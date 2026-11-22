# Changelog

Notable changes to `ao_mesh` are recorded here. The crate is
pre-alpha: there are no tagged releases yet, the public API may
change without notice until v0.1.0, and sibling git sources must
match exactly (AGENTS.md, section 8).

## Unreleased

Document the pre-release sibling seam. `ao_mesh` stays at version `0.1.0` and
consumes `ao_network` and `ao_idents` as untagged git sources. A consumer that
depends on those siblings directly must use the same untagged URLs (no tag,
`branch` or `rev`) until release tags start at `v0.1.0`; mixing a tagged source
with aoMesh's untagged source duplicates `Identity`, `LinkId` and `NodeId`
types across the seam. No routing, packet, sync or store behaviour changes.

FIX 38 scopes the two-link suppression floor to where it proves coverage:
chain relays with at most one other link and every Presence announcement.
Dense Broadcast and channel floods use the calibrated degree-scaled threshold
again. The seeded 50-node mixed case (seed `1297304013`) drops from 5801 to
3277 transmissions (43.51%) with Direct delivery unchanged at 0.2000; the
line-20 channel row and the MSH-19 presence report are unchanged. The
suppression threshold now comes from `SuppressionConfig::copy_threshold_for`,
which is covered by unit, engine-pipeline and simulator regressions. The
mixed observability counters move to 321 duplicates, 166 suppressed relays and
547 seen records because different relays cancel; no MSH-27 threshold changed.

MSH-29 gains an explicit TimedSnapshot wrapper for process/device restarts with
changed clock epochs. It binds state to the local owner, stores remaining
lifetimes, rebases with host-supplied elapsed time and clears transport LinkIds.
Restore is atomic and fresh-engine-only. Duplicate observations cannot refill
spent spray tickets or extend their expiry; zero-capacity spray stores no state.
Legacy Snapshot format and tests remain supported for same-epoch restoration.

MSH-34 changes `MessageStore::get` from `Option<&StoredMessage>` to
`Option<StoredMessage>`. This is a breaking unreleased host-seam API change:
disk-backed stores can decode a row into an owned value without keeping a second
authoritative in-memory copy, and hosts should keep the returned value alive
while building borrowed `SyncOffer`s. In-memory lookup now clones one bounded
entry; routing, quotas, eviction order and all wire formats are unchanged. The
exported conformance suite checks that a fetched value survives store mutation
and is also run against a row-backed test store. A new tag is still required
before aoheyra APP-05 can consume this seam.

MSH-25 adds bounded advisory neighbour link hints. `MeshInput::ObserveLinkHint`
carries an opaque `PeerKey`, its associated `NodeId` and a contact flag; the
engine emits `MeshOutput::SetLinkHint` / `ClearLinkHint`, which the adapter maps
to aoNetwork's real `set_link_hint` / `clear_link_hint`. Contacts and directory
diversity are preferred, penalties deprioritise, and eviction matches
aoNetwork's deterministic rule. aoNetwork alone forms links and enforces the
degree cap; no wire format changes. `MeshConfig` gains a `link_hints:
LinkHintConfig` field and `MeshEngine::link_hints()` exposes read-only state.
New host seams are `MeshInput::ObserveLinkHint`, `MeshOutput::SetLinkHint` and
`MeshOutput::ClearLinkHint`. Four paired fixed-seed runs (1297303701 through
1297303704) link 12 of 12 recognised contacts within one second against 0 of 12
with hints off, with identical delivery, latency, transmissions and overhead.
`tests/linkhint.rs`, `tests/adapter.rs` and `tests/sim_linkhint.rs` cover the
policy, the real facade and the measured rows.
MSH-26 adds opt-in per-link hop encryption over the real aoIdents pinned-hash
handshake. A host sets `MeshConfig::hop_enabled` and signs its hello with
`MeshHello::sign_with_hop`; `CAP_HOP_V1` is deliberately absent from the default
`CAPS`, so hosts that do not drive handshakes keep cleartext links. The signed
hello's card hash and bounded negotiation state stay in the engine; cards,
handshakes and `HopSessions` remain host-owned and are borrowed only through
`NetworkAdapter::*_with_hop`. Control frames carry a one-byte Noise tag;
Data frames on an active link seal the whole encoded packet per neighbour, so
a passive observer sees no mesh header. Post-link-up sync and receipts are
deferred until `MeshInput::HopReady` to avoid cleartext leakage and preserve
frame order. Failed seal/open emits typed `HopFailed` events and no cleartext
retry. The SimWorld capture test with seed `0x2601` verifies `1 / 1` parsed
packets with no header visible on the radio when both sides opt in, and `1 / 1`
cleartext packets when only one side does. Breaking unreleased API additions:
`MeshConfig::hop_enabled`, `MeshInput::{HopControl, HopReady}`,
`MeshError::Hop`, `AdapterEvent::{HopStart, HopControl, HopFrameInvalid,
HopFailed, HopEnded}`, the `*_with_hop` adapter methods, and the `hop` and
`SUPPORTED_CAPS` exports. `MeshHello::sign` is unchanged and remains cleartext.

MSH-19 adds bounded presence announcements. An ordinary signed `Presence`
packet carries a fixed 150-byte body with the origin's card hash, capabilities,
sequence and existing public identity, so every relay can verify the binding
and signature without storing keys or consulting a directory. `MeshHello`
advertises `CAP_PRESENCE_V1` (`1 << 4`); legacy peers keep the previous Presence
relay path. Trickle timing, latest-wins ordering, bounded learned entries and
one-shot `CardFetch` host events are implemented in the new `presence` module.
The fixed 50-node report on seed `1297304021` learns 49 of 49 peers in 50 ms,
emits no card fetches, and uses 15,480 B/h per source at steady state against
the 64 KiB/h budget. The one-copy cancellation in MSH-11 suppression is also
fixed at the algorithm level: a degree-one path needs two distinct sending
links, with a unit regression. FIX 38 later scopes that floor to chain relays
and Presence so dense Broadcast floods keep their calibrated saving. The
MSH-17 enabled 200-node report consequently sends 27,926 instead of 27,958
packets on seed `1297303752`; delivery, receipts, purges and purge latency are
unchanged.

Breaking unreleased API change: `MeshInput::Tick` now takes a borrowed
`Identity` and an eight-byte card hash. New host seams are
`MeshInput::KnownCards` and `MeshOutput::CardFetch` (surfaced by the adapter as
`AdapterEvent::CardFetch`); `poll_event` and `next_event` signatures are
unchanged. `MeshConfig` gains a `presence: PresenceConfig` field and
`MeshEngine::presence()` exposes read-only learned state.
MSH-20 adds a bounded, ephemeral `NodeDirectory` fed by a typed presence
observation seam. Entries carry the last seen time, local expiry, hop
distance, via-node, caps, sequence, card hash and opaque bounded location
bytes. Capacity evicts least-recently-seen nodes, relative-time expiry ignores
backwards and skewed clocks, and queries by id, vicinity and recency are
bounded and deterministic. UI changes arrive as coalesced
`DirectoryChanged` events with one pending entry per node. The engine remains
sans-IO and no wire format changes. Verified MSH-19 announcements now feed the
directory with their origin, card hash, caps, sequence, hop count and
ingress neighbour. The fixed seed `1297304021` scenario peaks at
the four-entry cap, expires all 24 timed-out entries and ends with zero live
entries.

MSH-21 adds bounded reverse-path route hints for Direct traffic, derived from
MSH-20 directory observations: verified presence announcements feed them
automatically and host facts use `MeshInput::ObserveNode`. No peer time is
accepted, a backwards local clock is clamped to the table's floor, and
observations whose via-node has no verified link are ignored. The bounded table
ranks by hops, presence sequence and link id, expires on `Tick` and drops
entries on `LinkDown`. The measured default `SubstituteCopy` makes a fresh hint
one of the existing spray copies instead of adding a send; `AdditiveUnicast` is
retained as a rejected option and `Off` keeps every published row unchanged. No
packet, hello or sync wire field changes. On the paired random-20 case
(seed `1297303632`) substitution cuts fresh-path mean latency from 356 ms to
337 ms and overall mean latency from 360 ms to 345 ms with transmissions
unchanged at 230 and overhead at 23.0000, while additive uses 231
transmissions and 23.1000. The line-20 control (seed `1297303584`) is identical
in all modes.

MSH-22 adds bounded latest-wins Telemetry. `SubmitTelemetry` frames an opaque
payload with an application-owned kind and a monotonic sequence under the
existing Telemetry class; the frame prefix is version, kind, `u64` sequence,
then opaque bytes. `TelemetrySend`/`TelemetryBroadcast` carry a typed advisory
whose stable `(origin, kind)` coalescing key and local deadline the adapter
passes to aoNetwork's `SendOpts` and `Network::send_opts`. Relays check the
frame and apply 30 s freshness, a one-per-origin/10 s cap and a three-hop limit
before spending a relay budget; malformed frames alone are penalised. Telemetry
is never stored or synced, and its bounded tracker uses local time only. The
fixed slow-line seed `1297304023` shows eight bursts reduced to one in-flight
frame plus one pending replacement at each receiver (six receptions, at most
two sequences per node, sequence 8, 12 transmissions); the chatty seed
`1297304029` accepts one of twelve attempts and emits no telemetry frame.

MSH-23 adds bounded public channels over signed Broadcast packets. A channel is
an 18-byte envelope (magic `0xC4`, version `1`, a 16-byte BLAKE3-128 id derived
from a local name, then opaque app bytes) inside the existing payload; no
header, class or signature domain changes. Subscriptions are local-only
`MeshInput::ChannelSubscribe`/`ChannelUnsubscribe` state, so relays keep no
subscription table. Channel traffic reuses MSH-10's bounded origin-bucket table
through a domain-separated synthetic key and MSH-11's Broadcast suppression.
A direct copy is authenticated with the key from the sender's signed hello and
emitted as `MeshOutput::ChannelDeliver` / `AdapterEvent::ChannelDeliver` after
the replay guard accepts it; relayed copies forward without local delivery.
The fixed line-20 case with seed `1297304023` delivers one message to both
in-range subscribers in twelve transmissions (3,048 bytes) inside the
43,690-byte Broadcast burst. The row was remeasured after rebasing onto MSH-22:
MSH-19's two-link suppression floor makes each line relay forward once,
replacing the old two-transmission expectation from the pre-MSH-19 tree. No
published MSH-27 threshold was lowered. Bounds, typed errors and the exact
simulator row are in the README, ADR-0001 and `docs/protocol.md`.

Breaking unreleased API additions: `MeshConfig` gained `channels`, `Neighbor`
gained `signing_pk`, `NeighborTable::insert` takes that key, and the input,
output, adapter-event and error enums gained channel variants. Exhaustive
matches in `tests/forwarding.rs` and `tests/sim_budgets.rs` were updated.
MSH-28 adds deterministic resource bounds and fuzz targets for hostile input.
Packet decoding remains allocation-free; sync frame bodies are capped at 8198
bytes before copying, summary construction and `SyncItems` handling read at
most 1024 entries, and a reachable delivery-path debug assertion was removed.
`SyncFrame::decode`, `SyncFrameV2::decode`, `SyncError` and `SyncV2Error` are
public with typed `FrameTooLarge(usize)` rejections. New `fuzz/` targets cover
packet decoding, engine input streams and sync frames; nightly CI runs each for
one hour with a 16 KiB input cap, 2048 MiB RSS limit and 10-second timeout.
`tests/resource_bounds.rs` pins allocation and CPU-proxy ceilings with a
counting allocator. The separate fuzz crate uses dev-only `libfuzzer-sys` and
`rand`; core dependencies and the sans-IO boundary are unchanged.
MSH-29 adds versioned restart snapshots through the `Snapshot` trait on
`MeshEngine`. A host stores the bytes and restores them into a fresh engine with
the same config and RNG seed; seen-cache entries and eviction order, receipt
immunity and spray copy counters survive, while store content, clock, config and
link capabilities stay host-owned. The format is bounded at 4 MiB, typed errors
reject malformed or version-mismatched bytes atomically, and the fixed-seed
line-20 report shows 14 post-restart re-relays without restore against zero with
restore, with delivery unchanged at 20/20.
MSH-30 adds bounded observability. `MeshSnapshot` exposes saturating counters
for duplicate packets, suppressed relays, encoded sync bytes and neighbour
penalty events, plus gauges derived from existing bounded state for store ids,
current penalties, seen records and pending suppression windows. The snapshot
is versioned plain integer data with no packet content, ids, keys or personal
data, and `MeshEngine::observability_snapshot` / `NetworkAdapter::snapshot` read it without
allocation, I/O or a second source of truth. `MeshConfig` gains a `seen` field
so the seen-record gauge has the same documented 4096-entry bound as the cache.
The fixed mixed 20-node scenario with seed `1297304021` reports 323 duplicates,
120 suppressed relays, 88 store ids, 820 sync bytes in each direction and four
penalty events from injected malformed frames. These values were remeasured on
the accumulated MSH-19 stack after the two-distinct-link suppression floor
changed which relays cancel a flood; no wire format or MSH-27 threshold
changed. The host maps this snapshot into aoheyra's APP-15 bundle.

MSH-17 adds signed delivery receipts and bounded store immunity. An
authenticated delivery emits a cap-gated receipt envelope carrying a signed
Direct acknowledgement, the destination's public identity and the original
header/hash, so any relay can prove the acker without a directory. Accepted
receipts purge host-store copies, stop spray and sync of the id, and report
`Delivered` to the origin. The fixed-seed report purges all 206 line-20 copies
in 1,550 ms and all 1,341 scripted-200 copies in 1,750 ms, with the ablations
retaining their copies.

MSH-16 adds binary spray-and-wait for Direct traffic. Packets keep their signed
header; a six-byte capability-negotiated envelope carries a remaining-copy
ticket on the Message channel. Peers without `CAP_SPRAY_V1` receive the raw
packet. Each message starts with 255 tickets, hands half to a non-destination
contact, gives one to the destination and otherwise waits with its last copy;
tickets also travel through MSH-14/15 sync and are bounded by a 4096-id tracker.
The paired `spray_report` uses the fixed MSH-27 seeds: scripted-200 delivers
99/100 with 1,786 transmissions against relay-only 100/100 with 3,455, and
line-20 keeps 20/20 with 186 transmissions against 193. The published
MSH-27 baselines remain relay-only and unchanged.

MSH-15 adds range-based reconciliation for links that advertise both sync
capability bits. Each side hashes binary ranges of the canonical id space,
splits only differing ranges and exchanges full ids in small leaves. The
existing `SyncNeed` / `SyncItems` transfer then moves the actual packets, so
the host still owns the store and peers with only `CAP_SYNC_V1` keep the
MSH-14 summary path. Version-2 sync frames use the same magic and five-byte
header with tags for Root, Ranges, Request, Ids and Ready; after both sides
send Ready the contact uses the existing `Item` and `Done` frames. The
`sync_v2_report` example measures 2,018 bytes for v2 against 16,188 bytes for
v1 on stores of 1000 and 1001 messages with seed `0x515f_2026`.

MSH-14 adds bounded anti-entropy sync for links that advertise `CAP_SYNC_V1`.
The engine compares store digests, exchanges eight-byte id prefixes and asks
the host for the encoded packets it owes through `SyncNeed`/`SyncItems`.
Incoming `SyncItem` packets are bounds- and content-address-checked before the
host inserts them; final authenticity stays with the store owner. A two-phase
`Done` handshake releases the opportunistic link only after both directions
have finished, and a 20-second deadline releases a stalled contact. The sync
frames use magic `0x53`, version `1` and a five-byte header on aoNetwork's Bulk
channel; peers without the capability bit keep the MSH-13 beacon path. A
SimWorld acceptance case with seed `0x5147_2026` converges two stores on the
same four ids after a 20-second meeting and observes the link release.

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
mixed case transmissions fall from 5801 to 3277 (43.51%) with the Direct
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
