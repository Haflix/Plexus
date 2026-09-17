# Capabilities and Caller Identity

*Last updated for Plexus 0.81.1*

Every call in Plexus carries a **caller identity**: the framework knows which
plugin initiated each operation and the chain of plugins it passed through.
Normally a plugin acts as itself. The **capabilities** system is the operator's
opt-in grant that lets a specific plugin act under a *different* identity, either
to impersonate another plugin or to act as the privileged `system` caller.

This is off by default. With no `capabilities:` configured, the
gate is inert, every plugin is simply itself, and there is zero per-dispatch
overhead. The rate limiter uses the same caller-identity machinery to decide who
a call is charged to, see [rate_limiting.md](./rate_limiting.md).

---

## Why impersonation

Sometimes a plugin legitimately needs to act on behalf of someone else. An
orchestrator running a task "as" a particular user wants the downstream rate
limits, permissions, and audit trail to attribute to the user, not to the
orchestrator. That is impersonation: the orchestrator asserts a different
`author` for the operation.

Letting any plugin claim any identity would be a security hole, so impersonation
requires an explicit operator grant. A plugin that asserts an identity it was not
granted is **denied** (the call raises `CapabilityException`), and the denied
attempt is audited.

---

## Configuration

Grants live in the main `config.yml` under a top-level `capabilities:` section,
keyed by plugin name:

```yaml
capabilities:
  SomeOrchestrator:
    system_caller: true              # may act as the privileged "system" identity
    impersonation_allowed: ancestor  # may assert an identity from its caller chain

  AnotherPlugin:
    impersonation_allowed: [UserProxy, SessionManager]   # may assert these names
```

### The two grants

- **`system_caller`** (boolean) — the plugin may act as `system`, a privileged
  framework-level identity. A `system_caller: false` (or omitted) entry grants
  nothing.
- **`impersonation_allowed`** — which identities the plugin may assert:
  - `caller` — only its *immediate* caller's identity.
  - `ancestor` — any identity already present in its genuine caller chain.
  - a non-empty list of plugin names — those specific identities.

An entry that confers nothing (for example `system_caller: false` with no
impersonation) is treated as no grant at all. The moment any real grant exists,
the gate becomes active node-wide and caller-identity stamping turns on so the
gate can read the true caller.

---

## How a plugin asserts an identity

`Plugin.execute()` (and its `execute_sync` / `execute_stream` /
`execute_stream_sync` variants) take optional `author` and `author_id` arguments.
Passing them is how a plugin claims an identity for the operation:

```python
# Act as the user this orchestrator is serving:
await self.execute(
    "MemoryStore", "save",
    args={...},
    author="UserProxy", author_id=user_proxy_uuid,
)
```

When the gate is active, the framework evaluates the claim against the caller's
grant:

- If the plugin is allowed to assert that identity, the operation proceeds under
  the asserted identity (downstream charges and identity reads see the asserted
  identity, not the real caller), and an audit event is emitted.
- If it is not allowed, the call raises `CapabilityException` and a denied-claim
  audit event is emitted.
- A plain self-call (a plugin acting as itself) is not an assertion and is never
  gated.

When the gate is inert (no grants configured), `author` / `author_id` are just
routing labels with no privilege attached, the historical behavior.

The event methods (`publish_event` / `request_event` / `request_event_stream`) do
NOT take `author` / `author_id` — an event cannot itself assert an identity. They
always fire under the publisher's own identity, but they INHERIT any assertion
already active up the call chain: an event fired while an `execute` impersonation
is in scope is charged and attributed to the asserted identity (including across
the sync bridge).

---

## Rules the gate enforces

- **Default deny, when a caller frame is present.** An assertion evaluated
  against a grant that does not permit it is denied, and the gate fails closed.
- **Known gap (B-105).** The gate is a pass-through when the caller chain is
  empty, on the assumption that an empty chain means framework origin. A thread a
  plugin starts itself inherits neither the `ContextVar` nor the thread-local that
  carry the chain, so an assertion made from such a thread — the ordinary shape
  for a tier-1 plugin wrapping a blocking driver — is never evaluated. The
  cross-node leg is hardened separately and is not affected. Until this is closed,
  treat the gate as constraining calls that originate from a plugin's own task,
  not as an unconditional guarantee.
- **No chaining.** An identity that was itself asserted cannot be used as the
  basis for a further assertion. You cannot launder a claim through a second hop:
  the gate reasons about the *real* caller chain, not a previously-asserted label.
  This holds uniformly on the async and sync paths: an assertion that lands on a
  synchronous endpoint which re-enters the bus (`execute_sync`, ...) carries the
  asserted identity across the sync bridge, so the second hop is gated exactly as
  it would be async.
- **Ancestry is genuine.** The `ancestor` scope checks the real call chain that
  led to this operation, which the framework stamps at every plugin-to-plugin
  dispatch. A plugin cannot fabricate an ancestor it was not actually called
  through.
- **Cross-node identity is filtering-only.** For a peer-originated call, the
  wire `author` / `author_id` are labels the receiver uses only for author/host
  subscription filtering; they confer no capability. The right to act as
  `author="system"` is granted SOLELY from the callee's own authenticated
  `system_caller` record for that SPKI-pinned peer, never from the wire (a
  spoofed `system` claim is downgraded before the registry sees it, in
  `Dispatch._effective_caller`). Cross-node impersonation is a non-goal: the
  impersonation ancestry chain is empty for peer-originated calls (impersonation
  is a same-node grant, not transitive across nodes), and a vouched (discovered)
  peer is always `system_caller=false`. See [networking](./networking.md).

The pure decision logic is small and deterministic; the framework wiring stamps
the caller chain, reads the real caller, applies the grant, and either scopes the
asserted identity over the operation or raises.

---

## Security audit trail

Every allowed assertion and every denied attempt emits a
`_core/security/identity_asserted` event on the framework's internal observer bus.
The payload records the real caller, the asserted identity, whether it was denied,
the reason, and the caller chain. Subscribe to it with
`Plugin.internal_observe("_core/security/identity_asserted", callback)` to feed a
security log or alerting.

To keep a hot impersonation or a probing flood of denied attempts from spamming
the trail, these events are **window-suppressed** the same way rate-limit reject
logs are: the first event per suppression key per ~10s window fires immediately,
in-window repeats only increment a counter, and the next event after the window
carries a `suppressed` count. The suppression key is
`(real caller, asserted identity, denied)` on the ALLOW path, but on the DENY path
the asserted name is dropped from the key (it becomes `(real caller, denied)`): a
denied claim's asserted name is caller-supplied and unbounded, so an attacker
varying it every call would otherwise mint a fresh key per attempt and escape
suppression. Collapsing all of one caller's denied attempts into a single stream
preserves the useful signal (this caller keeps attempting assertions it cannot
make); the emitted payload still carries the actual asserted name and reason in
every case, so only the dedup key changed. An alerting consumer always sees the
onset of a burst; the true volume is preserved across the active window.

---

## Interaction with rate limiting

Capabilities and the rate limiter share the caller-identity machinery. The
limiter **charges the asserted identity**: if `A` is granted and asserts `X`, the
`plugin_out` rate-limit charge lands on `X`'s bucket, not `A`'s. This is why the
two subsystems turn on together (an active grant or an active limit both enable
identity stamping) and why operations originating from the framework itself carry
no plugin frame and are exempt from per-plugin charges. See
[rate_limiting.md](./rate_limiting.md).

---

## Quick reference

- Off by default; opt in with `capabilities:`. Fail-closed for calls that carry a
  caller frame — see the B-105 gap above for calls made from a plugin-created
  thread.
- `system_caller: true` grants the privileged `system` identity.
- `impersonation_allowed: caller | ancestor | [names]` grants impersonation scope.
- A plugin asserts via `execute(..., author=, author_id=)`; an ungranted
  assertion raises `CapabilityException` (a `RequestException`).
- No-chaining: an asserted identity cannot be re-asserted.
- Allowed and denied assertions are audited on
  `_core/security/identity_asserted` (window-suppressed).
- The rate limiter charges the asserted identity.
