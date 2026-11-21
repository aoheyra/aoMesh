# Changelog

Notable changes to `ao_mesh` are recorded here. The crate is
pre-alpha: there are no tagged releases yet, the public API may
change without notice until v0.1.0, and consumers pin by git tag
(AGENTS.md, section 8).

## Unreleased

The MSH-27 baseline fixture was regenerated against aoNetwork `492e148c`
(Net 25 flow control). The refreshed sibling changed simulated link formation:
waypoint and community delivery improved, waypoint overhead fell, community
overhead rose from 328.5541 to 328.7067, and the exact link counts moved from
182/424 to 180/412. Radio-byte accounting now accumulates per-tick `tx_bytes`
deltas per link instead of subtracting two snapshots of only live links, so
traffic on links that close during mobility is counted; the higher radio-byte
figures are a measurement fix, not a routing regression. Repeated debug and
release runs produced identical metrics. No aoMesh routing code changed.

MSH-10 adds per-origin and per-(sending link, origin) token buckets with the
ADR-0001 class rates and a ten-minute burst. Relays debit both buckets before
sending copies;
local delivery is unaffected. Invalid, unverified and link-saturated traffic
adds a decaying penalty, and a link crossing the threshold is released once with
`DisconnectReason::AbuseDetected`. An exhausted origin is dropped without
blaming the neighbour that carried it, because disconnecting that link would
also drop honest traffic. `BudgetOutcome` makes the distinction explicit.
`MeshConfig` gains a `budgets: BudgetConfig`
field, `MeshEngine::budgets` exposes read-only state, and `PacketClass::all`
lists classes in priority order. The simulator gains `Traffic::Flood`,
per-origin delivery metrics, `flood_scenarios` and an `enforce` ablation
switch. On the refreshed aoNetwork baseline the fixed flood case shows the
origin's delivery falling from 0.8133 to 0.3400 while honest delivery rises
from 0.6833 to 0.7533 and stays near the 0.7825 no-flood control; details and
seeds are in the README and ADR-0001. The flood scenarios are additive; the
four refreshed baseline scenarios are not changed by this feature.

MSH-11 adds counter-based suppression for Broadcast and Presence. A fresh
content id waits a seeded, degree-scaled assessment window while distinct
neighbour copies are counted; enough copies cancel the relay and the timer
otherwise sends one copy with the class TTL. Pending state is bounded and
evicted by deadline. `MeshConfig` gains a `suppression: SuppressionConfig`
field, the simulator gains `Traffic::MixedBroadcast`, per-node reception
metrics, `suppression_scenarios` and an `enforce_suppression` ablation switch.
No wire field changes. Suppression only sees packets admitted by MSH-10, so a
budget denial cannot start a timer or blame its carrier. On the seeded 50-node
mixed case transmissions fall from 5801 to 3316 (42.84%) with the Direct
delivery ratio unchanged at 0.2000; the Broadcast-reception diagnostic and
seeds are in the README and ADR-0001.

MSH-13 adds a canonical store summary and a debounced four-byte beacon digest.
`StoreSummary` ignores input order and duplicates, exposes eight-byte id
prefixes and hashes every full id. `MeshInput::StoreSummary` lets the host
supply live store ids without giving the engine a store; `MeshConfig` gains a
`summary: SummaryConfig` field and the engine emits `SetBeacon` after a 200 ms
change debounce. Tests show equal digests for identical stores and a different
digest after one message changes. No wire format changes.

MSH-27 adds a deterministic SimWorld harness behind feature `sim`. It drives
signed hellos, link events and the engine through the adapter across a 20-node
line, a 50-node random waypoint network, a 100-node community network and a
200-node chain with scripted contacts. `examples/sim_report` prints CSV or
writes it to a path; `tests/sim_baseline.rs` and `.github/workflows/sim.yml`
enforce directional regression bounds on delivery ratio, overhead, latency,
duplicates, radio bytes and peak queue occupancy. The adapter gains
`engine_mut` and `network_mut` so the harness can count outputs before they
are applied. Published seeds and numbers are in the README.

MSH-09 authenticates local delivery. A Direct packet addressed to this node
must carry an aoIdents sealed payload bound to the immutable header content
address; the engine opens it against a borrowed local identity, requires the
seal's sender to equal `origin`, verifies the origin signature and content
`msg_id`, and accepts the message through a bounded replay guard before
emitting `Deliver` with the opened plaintext. Tampered, misdirected, forged
and replayed candidates produce nothing and are counted on the sending link,
as are forged content addresses; policy drops are not penalised. Decision
record: ADR-0005. Tests cover every pipeline step at unit level and
authenticated delivery, duplicates, tampering and penalties at engine level;
the simulator forwarding cases now deliver through this pipeline.

Breaking unreleased API change: `MeshEngine::new` and `with_config` no longer
take a local `NodeId`; `MeshInput::Data` takes a borrowed `identity`;
`NetworkAdapter::poll_event` and `next_event` take a borrowed `identity` per
pump; `Neighbor` gained `rejected_packets`; `MeshConfig` gained `replay`.
`MeshOutput::Deliver.payload` is now the opened plaintext, not opaque bytes.

MSH-08 adds the baseline forwarding path for Direct. A received packet
must re-derive its content-bound `msg_id` before any state changes, is
recorded once in the seen-cache, is delivered when `dst` matches the
engine's `NodeId`, and otherwise relays to every verified neighbour
except the sending link with `ttl` decremented (the hop limit: a
submission with `ttl` N reaches N hops) and `hops` incremented,
saturating at 255. Submissions are recorded too, so no node re-relays
its own message; other classes, unverified senders and duplicates are
counted and dropped (ADR-0004, and MSH-11/19/22 own the other
classes). Delivery was structural until MSH-09; see the entry above. Tests
pin delivery without loops on a line, a ring and a seeded random graph.

MSH-07 adds the signed MeshHello: the `hello` module builds, encodes,
verifies and negotiates a 161-byte fixed layout covering `node_id`,
`card_hash`, `proto`, `caps`, `store_digest` and both public keys under
`aoheyra/mesh/v1/hello`. Link-up decodes, verifies and negotiates the
peer's introduction before recording anything: a valid hello yields the
derived `NodeId` on the neighbour, an invalid, oversize or
version-incompatible one is dropped without an identity (the entry
keeps counting traffic; only a full table releases the link).
Breaking unreleased API change: `Neighbor` gained the public
`node_id: Option<NodeId>` field, and `NeighborTable::insert` is
engine-internal with new `contains`/`has_room` admission checks.

MSH-32 threads the host's monotonic network clock through the adapter:
`NetworkAdapter::handle` and `apply` take `network_now: Duration` and pass it
to every facade command that needs time (`send`, `broadcast`, `disconnect`).
Breaking unreleased API change: those two methods gained the leading
`network_now` parameter.

MSH-06 adds bounded per-link state, signed Submit commands, typed submission
errors and the optional NetworkAdapter. No runtime dependency is added.

Breaking unreleased API change: MeshInput now borrows submission identity and
payload; MeshEngine::handle returns Result<Vec<MeshOutput>, MeshError>.
Data is structurally counted, not authenticated or delivered. MSH-07/08/09
remain separate work.


Initial implementation through `MSH-05`: the sans-IO engine
interface (`MSH-01`), configuration (`MSH-02`), the v1 packet codec
(`MSH-03`), origin signatures with content-derived `msg_id` (`MSH-04`),
and the bounded forwarding seen-cache (`MSH-05`, ADR-0003).

Breaking API changes within the unreleased window: `Packet::new`
takes the origin signature, and `Header.msg_id` is a `MessageId`
rather than a raw byte array.
