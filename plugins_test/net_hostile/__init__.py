"""net_hostile — the Type-X hostile-peer test harness for the networking rewrite.

A raw TLS + frame client (NOT a cooperative Plexus node) that opens a real mTLS
connection to a rewrite node's listener and sends/omits/oversizes hand-crafted
wire frames per SPEC §5. It is the fixture the §D adversarial cells (TP-70..81)
+ the Type-X gap-hunt cells (TG-05b/09/17/18/20) drive.

Three modules:
  * ``wire`` — the §5 frame codec (kind table, length convention, cid high-bit
    dial-role, msgpack control fields / opaque CHUNK payload) + encode/decode.
  * ``hostile_client`` — DIALER mode: ``HostileClient`` (connect presenting an
    arbitrary cert, send/recv primitives, crafted-frame helpers) + ``StallListener``
    (a passive victim listener that counts inbound connect attempts, for the
    redial-rate / reflected-connect-storm cells TP-50/TG-19). Covers the cells where
    the HOSTILE dials the NODE (the node's inbound path): TP-70-inbound, TP-71/72/73/
    75/76/79/80/81, TG-05b/09/20.
  * ``hostile_server`` — ACCEPTOR / PONG-server mode: ``HostilePongServer`` (accept
    the node's dial, present a chosen cert, answer PING with a crafted PONG +
    optional crafted DirectorySnapshot). Covers the cells where the NODE dials the
    HOSTILE and pulls a crafted snapshot: TP-74, TP-77/78, TG-17, TP-70-outbound/
    vouched.

CANNOT RUN YET: needs a swapped rewrite node (the §5 wire is rewrite-only) and
the parent to run it (subagents cannot run python). Structured so the parent
wires it into the wave-2 socket suite once a branch lands.

See README.md for the wire-layout ASSUMPTION this scaffold pins (SPEC §5 does
not fix the byte layout of ``[cid + fields]`` to the byte — flagged in
WAVE2_TEST_MAP.md as the top open item).
"""
