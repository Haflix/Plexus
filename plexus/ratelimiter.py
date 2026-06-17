"""Token-bucket rate-limiter primitives for Plexus.

The pure, framework-agnostic core: ``Bucket`` + ``RateLimiter``. Deliberately
self-contained, with no asyncio dependency, so the token-bucket logic is
unit-testable in isolation from the rest of the framework.

Model: a ``Bucket`` is a token bucket with lazy continuous refill on a
monotonic clock, configured as ``max`` + ``window`` (so ``rate = max / window``
tokens per second). ``RateLimiter.admit()`` runs a lock-free,
all-or-nothing check-all-then-commit over a list of buckets (the "charge-set"):
it is atomic when called on a single thread with no ``await`` between the peek
and the commit, which is how the framework will use it (loop-side dispatch).
Overflow never queues; ``admit`` returns the first dry bucket so the caller can
reject loudly and name the binding dimension.
"""
from __future__ import annotations

import math
import time
from typing import Dict, List, Optional, Sequence, Tuple

from .exceptions import ConfigException


# ── Bucket dimensions + key conventions (Section 3) ───────────────────────
#
# Seven bucket namespaces. Each (dimension, key) pair names one bucket in the
# RateLimiter registry. The charge sites build the keys with the helpers below
# so the configure-time key and the lookup-time key are formatted identically.
DIM_FRAMEWORK_IN = "framework_in"   # one global bucket, key FRAMEWORK_IN_KEY
DIM_NODES_IN = "nodes_in"           # per remote peer, key = peer hostname
DIM_PLUGIN_IN = "plugin_in"         # per plugin (target), key = plugin name
DIM_PLUGIN_OUT = "plugin_out"       # per plugin (caller/asserted), key = name
DIM_EVENT_OUT = "event_out"         # per (plugin, event_id)
DIM_ENDPOINT_IN = "endpoint_in"     # per (plugin, access_name)
DIM_SUB_IN = "sub_in"               # per subscription, key = sub_uuid

# The single global-intake bucket's key (Framework-IN is one bucket).
FRAMEWORK_IN_KEY = "global"

# Composite-key separator. Plugin / endpoint / event identifiers are validated
# identifiers (letters, digits, underscore -- see _validate_identifier_name), so
# ":" can never appear inside a part and the joined key is unambiguous.
_KEY_SEP = ":"


def endpoint_key(plugin: str, access_name: str) -> str:
    return f"{plugin}{_KEY_SEP}{access_name}"


def event_key(plugin: str, event_id: str) -> str:
    return f"{plugin}{_KEY_SEP}{event_id}"


def _validate(max_tokens, window, where: str) -> None:
    """Reject non-numeric / non-positive ``max`` or ``window`` BEFORE a Bucket
    exists. "No limit on a dimension" is expressed by OMITTING it, never by
    ``max: 0`` (which would silently block all traffic)."""
    for name, val in (("max", max_tokens), ("window", window)):
        # bool is an int subclass, so float(True)==1.0 would slip through as a
        # silent 1-token bucket. Reject it BEFORE the float() coercion.
        if isinstance(val, bool):
            raise ConfigException(
                f"rate limit {where}: {name}={val!r} is a bool, not a number"
            )
        try:
            fval = float(val)
        except (TypeError, ValueError):
            raise ConfigException(
                f"rate limit {where}: {name}={val!r} is not numeric"
            )
        # Reject inf/nan too: max=inf -> always-admit bucket; window=inf ->
        # rate 0 -> always-block; nan -> NaN comparisons are always False ->
        # silently admits without draining. All three are silent misbehavior.
        if not math.isfinite(fval) or fval <= 0:
            raise ConfigException(
                f"rate limit {where}: {name} must be a finite number > 0 "
                f"(got {fval}); omit the dimension to disable it, never use 0"
            )


class Bucket:
    """One token bucket: lazy refill, fractional tokens, charged/rejected
    counters.

    ``max_stream_weight`` is the largest stream cost registered against this
    bucket (a stream may cost more than one token at open). It starts at 0.0
    (NOT 1.0): a non-stream bucket has no stream weight and must stay
    reconfigurable to any ``max > 0``, including fractional values.
    """

    __slots__ = (
        "max", "rate", "tokens", "last",
        "max_stream_weight", "charged", "rejected",
    )

    def __init__(self, max_tokens, window, now: float) -> None:
        # Caller validates via _validate() before construction.
        self.max = float(max_tokens)
        self.rate = float(max_tokens) / float(window)   # tokens per second
        self.tokens = float(max_tokens)                 # start full
        self.last = now
        self.max_stream_weight = 0.0
        self.charged = 0
        self.rejected = 0

    def refill(self, now: float) -> None:
        # Production ``now`` is process-monotonic (>= last). Defensively clamp a
        # backward delta to a no-op: a stale/non-monotonic ``now`` must never
        # DRAIN tokens (a negative delta would drive tokens deeply negative and
        # falsely reject). The min() clamp caps accumulation at ``max`` (and
        # bounds float drift); ``last`` never moves backward.
        elapsed = now - self.last
        if elapsed > 0:
            self.tokens = min(self.max, self.tokens + elapsed * self.rate)
            self.last = now

    def reconfigure(self, max_tokens, window) -> None:
        _validate(max_tokens, window, "reconfigure")
        if float(max_tokens) < self.max_stream_weight:
            raise ConfigException(
                f"rate limit reconfigure: max {max_tokens} < registered "
                f"stream_weight {self.max_stream_weight}; the bucket could "
                f"never admit that stream"
            )
        self.max = float(max_tokens)
        self.rate = float(max_tokens) / float(window)
        self.tokens = min(self.tokens, self.max)        # clamp down on shrink

    def register_stream_weight(self, weight) -> None:
        """Record a stream endpoint's cost against this bucket. Rejects a weight
        the bucket's ``max`` can never admit (a permanent silent block,
        diagnosed at registration instead of at call time)."""
        # Same numeric discipline as _validate (bool/non-finite rejected), so a
        # malformed weight fails loud here instead of silently leaving
        # max_stream_weight unchanged (nan slips a bare <=0 / >max check).
        if isinstance(weight, bool):
            raise ConfigException(
                f"rate limit: stream_weight={weight!r} is a bool, not a number"
            )
        try:
            w = float(weight)
        except (TypeError, ValueError):
            raise ConfigException(
                f"rate limit: stream_weight={weight!r} is not numeric"
            )
        if not math.isfinite(w) or w <= 0:
            raise ConfigException(
                f"rate limit: stream_weight must be a finite number > 0 (got {w})"
            )
        if w > self.max:
            raise ConfigException(
                f"rate limit: stream_weight {w} > bucket max {self.max}; this "
                f"endpoint could never open"
            )
        if w > self.max_stream_weight:
            self.max_stream_weight = w


class RateLimiter:
    """Owns bucket namespaces keyed by ``(dimension, key)`` and runs admission.

    A caller registers buckets with ``configure`` and hands ``admit()`` an
    explicit list of buckets to charge (the "charge-set").

    Threading: NOT internally synchronized. Every method (admit AND the registry
    mutators configure/remove) must be called from the single event-loop thread;
    there is no lock by design, so concurrent mutation from another thread would
    race ``self._buckets``.
    """

    __slots__ = ("_buckets",)

    def __init__(self) -> None:
        self._buckets: Dict[Tuple[str, str], Bucket] = {}

    def configure(self, dimension: str, key: str, max_tokens, window,
                  now: Optional[float] = None) -> Bucket:
        """Create the bucket for ``(dimension, key)``, or reconfigure it live."""
        _validate(max_tokens, window, f"{dimension}:{key}")
        if now is None:
            now = time.monotonic()
        existing = self._buckets.get((dimension, key))
        if existing is None:
            b = Bucket(max_tokens, window, now)
            self._buckets[(dimension, key)] = b
            return b
        existing.reconfigure(max_tokens, window)
        return existing

    def get(self, dimension: str, key: str) -> Optional[Bucket]:
        return self._buckets.get((dimension, key))

    def __len__(self) -> int:
        """Number of configured buckets. Drives the framework's
        ``_rate_limits_active`` master switch (zero-overhead-off): a limiter with
        no buckets means nothing is configured, so the charge path short-circuits
        before any work."""
        return len(self._buckets)

    def keys(self) -> List[Tuple[str, str]]:
        """A snapshot list of every configured ``(dimension, key)``. Used by the
        framework's charge-set rebuild to prune orphan buckets left by removed
        plugins (``configure`` only adds, so a shrink is driven from here)."""
        return list(self._buckets.keys())

    def remove(self, dimension: str, key: str) -> None:
        """Tear a bucket down (unsubscribe / plugin hot-swap).

        Caller contract: discard any precomputed charge-set that referenced this
        bucket. A stale reference kept after remove (+ a later configure that
        creates a NEW object for the same key) would charge a dead, unregistered
        bucket forever. The framework rebuilds charge-sets at re-registration;
        callers must not cache a charge-set across a remove.
        """
        self._buckets.pop((dimension, key), None)

    def admit(self, buckets: Sequence[Bucket], cost: float = 1.0,
              now: Optional[float] = None) -> Optional[Bucket]:
        """All-or-nothing check-then-commit over the charge-set ``buckets``.

        Returns ``None`` on admit (every bucket committed ``-cost``), or the
        FIRST dry bucket on reject (NOTHING committed -> no leak). Atomic only
        when called with no ``await`` between the peek and the commit
        (single-thread / loop-side). ``buckets`` must be a re-iterable sequence
        already in the caller's pinned order; ``admit`` honors list order so the
        reported dry bucket is deterministic. An empty
        charge-set admits (nothing to charge). ``cost`` must be > 0.
        """
        if cost <= 0:
            # cost <= 0 would always pass the peek and (for cost < 0) MINT
            # tokens past max in the commit. cost is the per-call weight (1, or
            # a stream_weight > 0); a non-positive cost is a wiring bug.
            raise ConfigException(
                f"rate limit admit: cost must be > 0 (got {cost})"
            )
        if not isinstance(buckets, (list, tuple)):
            # admit iterates buckets TWICE (peek, then commit). A generator
            # would be exhausted by the peek, so the commit charges nothing and
            # admit silently returns "admitted" without deducting a token -- the
            # worst possible failure mode for a limiter. The charge-set is a
            # precomputed list; enforce that here.
            raise ConfigException(
                "rate limit admit: buckets must be a list/tuple (re-iterable); "
                f"got {type(buckets).__name__}"
            )
        if now is None:
            now = time.monotonic()
        # phase 1: refill + peek (no token commit)
        for b in buckets:
            b.refill(now)
            if b.tokens < cost:
                b.rejected += 1
                return b
        # phase 2: commit (every bucket passed)
        for b in buckets:
            b.tokens -= cost
            b.charged += 1
        return None


def charge_set(limiter: RateLimiter,
               specs: Sequence[Tuple[str, str]]) -> List[Bucket]:
    """Assemble a precomputed charge-set from ordered ``(dimension, key)`` specs.

    Returns the configured buckets for ``specs`` IN THE SAME ORDER, skipping any
    dimension that has no bucket configured (no limit on that axis). ``specs`` is
    the caller's pinned admit order (Section 5: OUT dims, then Framework-IN, then
    IN dims) so ``admit`` reports the first dry bucket deterministically. A spec
    list whose dimensions are all unconfigured yields an empty list -> ``admit``
    no-ops (zero-overhead-off). The result is a plain ``list`` (re-iterable, as
    ``admit`` requires) of direct bucket references, so the hot path does no key
    formatting or dict lookups per call -- only this one-time assembly at
    registration / rebuild.
    """
    out: List[Bucket] = []
    for dim, key in specs:
        b = limiter.get(dim, key)
        if b is not None:
            out.append(b)
    return out
