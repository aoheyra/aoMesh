# ADR-0006: public channels (MSH-23)

## Decision

Channels are public, signed plaintext Broadcast messages. A channel id is the
first 16 bytes of BLAKE3 derive-key hash with context
`aoheyra/mesh/v1/channel-name` over the exact UTF-8 name. Names are case-sensitive;
no whitespace trimming or Unicode normalization occurs. Applications choose
and display names; the mesh only handles the identifier and opaque bytes.
Subscriptions affect local delivery only. Unsubscribed capable peers still relay.

Use `MeshInput::SubmitChannel` for publication and
`engine.channels_mut().subscribe(ChannelId::from_name(name))` for subscription.
`ChannelMessage` is distinct from sealed Direct `Deliver` and must be displayed
as public plaintext. The adapter forwards it to the host without interpretation.
Generic `Submit` rejects the reserved channel marker to prevent a second origin
admission path. Publication does not subscribe the sender or emit a local echo.

## Version and compatibility

MeshHello capability bit 5 (`CAP_CHANNEL_V1`) negotiates this new payload format.
The existing packet header, protocol version and packet signature domain stay
unchanged. Send and relay only to verified peers advertising this bit. Older
peers retain ordinary Broadcast support but do not participate in channel floods;
a path consisting only of legacy peers cannot carry a channel message.

The reserved Broadcast body marker is the three ASCII bytes `AOC`, followed by
version 1. Unknown versions and malformed channel frames are rejected and
penalized, rather than interpreted as ordinary Broadcasts. The v1 body is:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | AOC, version 1 |
| 4 | 16 | Channel id |
| 20 | 32 | Ed25519 public key |
| 52 | 32 | X25519 public key |
| 84 | 64 | Agreement binding |
| 148 | remaining | Unencrypted application bytes |

The origin signs the existing immutable header, whose content address commits
to this entire body. Every hop checks the aoIdents agreement binding, derives
NodeId from the two keys, and verifies both content address and packet signature.
No key lookup or prior presence gossip is required. TTL and hops remain mutable.
No new crypto primitive or dependency is introduced. Bounds are checked before
allocation of received application bytes.

## Alternatives

| Choice | Delivery and latency | CPU, memory, overhead and battery | Determinism and maintenance |
| --- | --- | --- | --- |
| Carry public identity in every message (selected) | Works before identity discovery; immediate authentication | Adds 128 public-identity bytes; verification per admitted hop; no key-fetch queue | Existing aoIdents verification, no asynchronous dependency |
| Resolve origin through presence/card cache | Missing cards delay or prevent delivery | Smaller frames; bounded cache plus fetch traffic and pending-message state | Adds card-fetch ordering and cache-expiry cases |

BTreeMap/BTreeSet provide deterministic ordering and bounded O(log n) lookup.
Hash tables offer expected O(1) lookup but no delivery, latency or radio benefit
for these small bounds, and require extra care for deterministic traversal.

## Limits

The MSH-10 Broadcast origin/link byte budgets remain authoritative. Additional
fixed local windows permit 30 messages/channel/minute and 10 messages/origin/minute
across all channels. Full tables reject new keys instead of evicting live rate
history, so rotating a channel cannot reset an origin's allowance. At most 64
subscriptions, 512 channel windows, 512 origin windows and 4096 recent accepted
ids are retained. Recent ids expire after the sender lifetime capped at 6 hours;
these records also prevent duplicate local delivery while suppression is pending.
Remote created_ms never drives rate windows or recent-id deadlines. A backward
local clock cannot reset a live rate window. There is no persistent membership.

Relaying uses the existing Broadcast TTL (6), timer and bounded suppression queue.
The channel threshold has a floor of two distinct ingress links, matching Presence:
a single incoming copy cannot suppress the only onward path on a line. Local
subscriber delivery happens before the TTL relay decision, including the last hop.

## Reproducible evidence

Run `cargo test --all-features --test sim_channels -- --nocapture`.
Even-indexed non-origin nodes subscribe; odd-indexed nodes are unsubscribed relays.
The 20-node topology connects offsets 1 and 5 on a ring (four radio neighbours).
Both rows use aoNetwork SimWorld and the real engine/adapter, with no radio errors.

| Nodes | Seed | Suppression | Subscribers reached | Mesh sends | Mesh bytes | Maximum latency ms |
| --- | --- | --- | --- | --- | --- | --- |
| 5 line | 1297303587 | off | 2/2 | 4 | 1080 | 400 |
| 5 line | 1297303587 | on | 2/2 | 4 | 1080 | 1750 |
| 20 graph | 1297303593 | off | 9/9 | 32 | 8640 | 600 |
| 20 graph | 1297303593 | on | 9/9 | 25 | 6750 | 1700 |

These count channel packet enqueue actions and mesh bytes, not BLE framing,
retransmissions, battery consumption or physical-device results. Suppression
saves seven sends (21.875%) on this graph at the measured latency cost. One
message remains far below the 512 KiB/hour Broadcast budget at every node.
This is scenario evidence, not a universal delivery guarantee under mobility,
loss, capability partitions, TTL exhaustion or deliberately exhausted budgets.
