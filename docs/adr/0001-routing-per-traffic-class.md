# ADR-0001: Routing per traffic class

- **Status:** accepted
- **Date:** 2026-11-05
- **Related:** MSH-08..MSH-11 implement the mechanisms; MSH-27 sweeps these defaults; IDN-19 records the metadata consequence.

## Decision

Units: TTL = hop limit; Copies = copies in the network; Lifetime = how long a copy may be stored; Relay budget = node-wide KiB/hour a node spends relaying that class for others; Priority = scheduling order, 1 = highest.

| Class | Mechanism | TTL | Copies | Lifetime | Relay budget | Priority |
|---|---|---|---|---|---|---|
| Direct | spray-and-wait with reverse-path hints | 8 | 255 | 24 h | 1 MiB/h | 1 |
| Broadcast and channels | counter-based suppression | 6 | 1 per node (forward once) | 6 h | 256 KiB/h | 2 |
| Presence | trickle-timed gossip | 3 | 1 per node | 30 min | 64 KiB/h | 3 |
| Telemetry (location) | announce, latest-wins, no storage | 3 | 1 per node | 5 min | 32 KiB/h | 4 |

## Reasons

**Direct — TTL 8, 255 copies, 24 h, 1 MiB/h.** Room and building diameters stay well under 8 hops at a degree cap of 8; binary splitting halves the ticket, so 255 is the smallest bounded value that still leaves a copy after eight splits and approaches flooding delivery in the scripted-200 sweep (8 copies delivered 0.09, 64 delivered 0.28, 255 delivered 0.45 in the older community case, and 255 delivers 0.99 in the paired scripted-200 case at 48 percent fewer transmissions); 24 h covers an overnight-offline recipient inside a bounded store; the budget lets a relay carry roughly 500 messages of 2 KiB per hour for neighbours before shedding, so one busy conversation cannot evict everything else.

**Broadcast and channels — TTL 6, forward once, 6 h, 256 KiB/h.** Each node forwards at most once and the counter suppresses re-floods, so the copy count is bounded by topology rather than by the sender; six hours outlives a suppressed flood (the origin re-announces newer content anyway); the budget is a quarter of Direct's because every duplicate is re-relayed by many nodes.

**Presence — TTL 3, 30 min, 64 KiB/h.** A 150-byte signed announcement carries the origin's card hash, capabilities, sequence and existing public identity. Trickle refreshes from 1 minute to a 15-minute steady bound, so a packet only has to outlive one missed period; three hops cover the immediate neighbourhood where presence is useful; the budget bounds Sybil spam to a few dozen announcements per hour. With the measured 258-byte average wire frame, one source's steady refresh is 15,480 B/h against the 64 KiB/h allowance.

**Telemetry — TTL 3, 5 min, 32 KiB/h.** Location is worthless when stale, so nothing is stored and the newest wins; three hops is the bound for "who is near me"; being the lowest budget, telemetry is the first class shed under pressure.

**Priority order.** User-visible content (Direct, Broadcast) before ambient state (Presence); presence self-refreshes through trickle and telemetry through latest-wins, so neither loses anything to a short delay. Nothing above can be starved by anything below, mirroring aoNetwork's control-over-bulk rule.

## Metadata trade-off

Relays see the origin and destination of every packet in MVP, which lets them rate-limit spam and detect loops. Accepted for MVP: it exposes the contact graph to observers, which IDN-19 lists as explicitly not protected. Hop encryption (MSH-26) protects content, not this header; hiding it needs rendezvous or cover traffic and is out of M0 scope.

## Sweeping

Each default becomes an engine config field with exactly these values; MSH-27 sweeps TTL, copies and budgets against delivery and overhead thresholds in CI. Changing a default here is a routing change and needs simulator numbers (README, Contributing).

## MSH-10 implementation

The relay budget is implemented as two token buckets per admitted packet: one
keyed by the claimed origin and one by the (sending link, claimed origin) pair.
The per-link map is capped at 64 origins by `max_origins_per_neighbor` and
evicts least-recently-used entries. Both use the hourly
rates above with a ten-minute full bucket, so an honest node can spend its
allowance in a burst without accumulating an unlimited credit. Telemetry's
32 KiB/hour is about 9 fixed-point units per millisecond, so integer refill
does not round ordinary ticks down to zero. Refill is driven only by the
caller's `now`; a backwards clock never mints tokens. Buckets are per class and
do not borrow, which is how "Direct first, Telemetry last" becomes observable
under pressure.

Options considered for the burst were one minute (too little slack for a
phone that just came back into range) and one hour (lets a flooder dump the
whole allowance instantaneously). Ten minutes bounds a first burst while
keeping the 2 KiB Direct budget around 174 KiB. The full hour is still the
sustained rate, so the ADR table above is unchanged.

Origin state is capped at 1024 entries and evicted least-recently-used first,
with `NodeId` order as the tie-break; neighbour state follows the neighbour
table exactly. Invalid packets add 3 penalty, packets from a link whose hello
failed verification add 2, and packets the sending link's own bucket cannot
admit add 1. `BudgetTracker::admit` returns which bucket refused so the engine
can drop an origin-limited packet without penalising the neighbour that carried
it. Four options were measured after aoNetwork's NET-25 credit flow control
changed link dynamics, always comparing honest delivery against the 0.6833
unbounded-flood run. Blaming the sender for every refusal gave 0.3200 because
releasing flooder-facing links partitioned the graph. Typing the refusal but
keeping a shared link bucket improved that only to 0.4967, because the flooder
still consumed the allowance honest origins needed on the same link. Splitting
the link bucket per origin without typing the refusal gave 0.3367, because the
link was still released. The combination of per-origin link buckets and no
blame for an origin denial gives 0.7533 while still throttling the flooder.
Penalty decays by 1 per minute;
reaching 12 emits one `Release` with `DisconnectReason::AbuseDetected`, and a
later `LinkDown` forgets the score.
aoNetwork owns reconnection and any future blacklist decision, so no new wire
field or sibling API is needed. MSH-09 authenticates local delivery, but a
relay still keys the origin bucket from the claimed header value; the per-link
bucket limits any sender regardless of what it claims, and relay-side origin
signatures for flooded classes are a separate concern.

Measured on the MSH-27 simulator with the fixed flood case (seed `1297304003`,
20-node random graph, 300 oversized messages from one origin and 300 from
honest nodes, aoNetwork `492e148c`): the flooder delivered 102 of 300 with
budgets and 244 of 300 with budgets disabled, while honest deliveries were 226
of 300 with budgets and 205 of 300 without. A no-flood control delivered 223
of 285 honest messages. The flood is cut to 41.8 percent of its unbounded
delivery; honest delivery improves by 7 points over the unbounded flood and
stays within 2.9 points of the no-flood control. The four refreshed MSH-27
scenarios stayed inside their existing directional bounds. No rate default in
the table changed; `max_origins_per_neighbor` was added as a bounded memory
parameter, not a routing-rate change.

## MSH-11 implementation

Broadcast and Presence packets are held in a bounded pending table keyed by
the content-bound `msg_id`. A node counts **distinct links** that carry the
same id during a seeded assessment window; copies from one neighbour are one
copy. Reaching the copy threshold cancels the relay and records the id in the
seen-cache. Reaching the deadline first re-encodes one relay with the class
TTL from the table above, decrements `ttl`, increments `hops`, and sends to
every verified neighbour except those already counted. Direct and Telemetry
keep their existing paths; no wire field changes.

| Setting | Default | Reason |
|---|---|---|
| Pending entries | 1024 | Bounds memory while covering a contact's worth of distinct content |
| Reference degree / copies | 4 / 3 | Calibrated by the 50-node sweep: 45.20% fewer transmissions, Direct ratio unchanged |
| Copy bounds | 1 to 6 configured, 2 effective | Sparse graphs still forward; hostile or extreme degrees cannot mint unbounded work |
| Base delay | 60-140 ms, seeded | Long enough for neighbour copies, short enough for a contact |
| Final delay | 20-600 ms, shrinking with degree | Dense groups decide sooner without letting sparse groups relay blind |
| Class TTLs | 8, 6, 3, 3 | Same table as above; submission and relay both clamp |

Three threshold policies were considered. A fixed `k = 2` is simple but
leaves most of the flood's redundancy in dense graphs. A fixed `k = 1`
removes almost all transmissions but isolates nodes that only hear one copy;
the MSH-19 convergence work reproduced that failure on degree-one paths, where
one arrival cancelled the only relay and extinguished the flood at the first
hop. A degree-scaled `k` with fractional seeded rounding is the chosen option:
it spends relays where neighbours are scarce and cancels them where the mesh
already offered several chances. The effective threshold is now floored at two
distinct sending links for every flooded class, so `min_k = 1` can no longer
produce that isolation. This is a routing fix, not a scenario special case.
The delay shrinks with degree for the same reason. The reference degree is
four, calibrated by the 50-node sweep; bounds keep `k` and the delay finite
for hostile degree claims. State is bounded at 1024 pending messages and
evicted by earliest deadline. CI rechecks the fixed suppression scenario
without lowering its thresholds; the published Direct-only baselines carry no
flooded classes and are unaffected.

The simulator ablation sets `SuppressionConfig::enabled = false`, restoring
immediate flooding without changing topology, identities or traffic. Suppression
only observes packets that MSH-10 admitted, so a budget denial cannot start a
timer or blame the neighbour that carried it. On the fixed 50-node mixed case
(seed `1297304013`), transmissions fall from 5801 to 3316 (42.84%) and the
Direct delivery ratio stays at 0.2000. Unique Broadcast receptions fall from
2197 to 1456: cancelling relays is expected to reduce how far a flood travels,
so that diagnostic is reported alongside the acceptance numbers rather than
hidden. The four published MSH-27 baselines are unchanged because they carry no
flooded classes.

## MSH-19 implementation

Three designs were compared for announcing a card hash across the mesh. A new
`PresenceCard` packet class would give the smallest payload and a separate
budget, but it would change the header class table, seen-cache windows, relay
policy and every peer's decoder for no routing gain. Gossiping only the
eight-byte hash in an ordinary Presence payload would be cheaper still, but a
relay could not bind the hash to an origin: a hostile neighbour could inject or
rewrite directory facts that every other node accepted. The chosen design is a
fixed 150-byte body inside the existing signed `PacketClass::Presence` packet,
carrying the card hash, capabilities, sequence and the origin's existing
`PublicIdentity` and agreement binding. Every hop derives `origin` from the
carried keys, verifies the binding and checks the packet signature under the
already registered `aoheyra/mesh/v1/packet` domain. No new class, header field,
crypto domain, key storage or app schema is introduced.

On delivery ratio and latency, the hash-only option would converge at least as
fast but is unverifiable; the new-class option has the same reach with a larger
protocol surface. The signed body converges 49 of 49 peers in 50 ms on the
fixed diameter-three, 50-node circulant. On overhead, the measured wire frame
averages 258 bytes, so one source's 60-second refresh is 15,480 B/h (15.1
KiB/h), far below this table's 64 KiB/h Presence budget; the whole 50-node
mesh sends 6,036 announcement frames in the last 60 seconds. Relays remain
bounded by the MSH-10 per-origin buckets. On memory, the tracker keeps at most
1024 learned entries and 1024 host-declared hashes; on CPU, each accepted
announcement costs one binding check and one signature verification per hop,
with no key directory lookup. Timing, ordering, eviction and tie-breaks use
only caller-supplied time and injected randomness, so the result is
deterministic and testable; maintenance is limited to aoMesh's presence module
because the crypto types and domain already exist in aoIdents.

`MeshHello` advertises `CAP_PRESENCE_V1` (`1 << 4`) in its existing `caps`
field. A peer without the bit receives no announcement bytes and keeps the
pre-MSH-19 Presence suppression path, so the body is additive. The host borrows
its `Identity` and card hash on each `MeshInput::Tick`, supplies
`MeshInput::KnownCards`, and consumes `MeshOutput::CardFetch` for hashes it must
resolve; the engine retains no key and stops repeating an unanswered fetch for
the same node and hash. A sequence counter is monotonic across card and
capability changes; a higher value wins and the full body gives a deterministic
tie-break.

| Setting | Default | Reason |
|---|---|---|
| Enabled | `true` | Cap gating restricts exposure on each link |
| Learned entries | 1024 | Bounds memory independently of the directory |
| Known cards | 1024 | Bounds one host input |
| Quick delay | 1000 ms | Bounded convergence after a change |
| Base / steady interval | 60 s / 900 s | Doubling trickle inside the 30 min entry lifetime |
| Entry lifetime | 1800 s | ADR-0001 Presence lifetime, measured in local monotonic time |

The first implementation exposed a trickle bug: a quick deadline was stored as
a time only, so ticks while the host had not yet supplied identity data kept
pushing it forward. The deadline now carries the facts it was scheduled for;
the host's later ticks cannot postpone that first send. The convergence work
also exposed the MSH-11 one-copy cancellation described above; it is fixed in
the suppression algorithm, not in the presence scenario.

The fixed report uses seed `1297304021` with no application traffic:

| Scenario | Seed | Converged | Convergence | Fewest learned | Card fetches | Steady sends / bytes |
|---|---:|---|---:|---:|---:|---:|
| `presence-smallworld-50` | 1297304021 | true | 50 ms | 49/49 | 0 | 6036 / 1,557,288 |

`cargo run --release --features sim --example presence_report` prints the exact
CSV row and `tests/sim_presence.rs` locks the header, seed and row so a wire or
timer change cannot pass unnoticed.

## MSH-13 implementation

The store owner supplies live message ids to `MeshInput::StoreSummary`; the
engine never persists packets or interprets payloads. `StoreSummary` sorts and
deduplicates ids, exposes eight-byte prefixes for MSH-14's summary exchange,
and hashes the full ids plus the entry count with a domain separator into the
four-byte beacon digest. Canonical ordering makes the digest independent of
backend iteration order, and full-id hashing prevents a prefix collision from
hiding a change.

Three summary representations were considered. Full 16-byte ids are exact but
make every contact exchange large. A Bloom filter is compact but reports false
positives, which would make MSH-14 request unnecessary transfers. Sorted
eight-byte prefixes are deterministic, small enough for the bounded 1024-entry
store, and safe because MSH-14 confirms with full ids before transferring. The
digest itself is only a change detector; a four-byte collision cannot be ruled
out, so a matching digest ends the exchange and a differing one starts full
comparison.

The beacon waits 200 ms after a change is first observed. Zero delay publishes
every store write and wastes airtime on batches; one second delays a link-up
comparison enough to be noticeable. A change back to the published digest
cancels the pending beacon, so transient churn does not flap the advertisement.
A backwards clock is treated as time zero inside the debounce window and never
mints an early publication. No wire field changes: aoNetwork's beacon already
carries the opaque four-byte digest.

## MSH-14 implementation

A meeting link whose MeshHello negotiates `CAP_SYNC_V1` starts a bounded
anti-entropy exchange over aoNetwork's Bulk channel. The engine compares the
peer's four-byte digest with its cached `StoreSummary`, exchanges sorted
eight-byte prefixes, and asks the host to resolve missing prefixes through
`MeshOutput::SyncNeed` / `MeshInput::SyncItems`. Incoming `SyncItem` packets are
checked for bounded decode, a content address that matches the claimed id, and
a storable class; the store owner still verifies signatures and decides
insertion. Telemetry is never synced.

Three transfer designs were compared. An engine-owned store would unify the
API but duplicate aoheyra's SQLite backend and break the sans-IO boundary
MSH-12 established. A pure push of the whole store is simple but wastes
airtime when digests differ by one item. A summary-driven request/offer
exchange keeps the engine store-free and transfers only the symmetric
difference; its extra round trip is acceptable because a contact is already
open and the exchange is bounded. The host therefore supplies encoded items
through `SyncItems` and inserts received items itself.

The frame format was chosen over full-id vectors and Bloom filters for the
same reasons as MSH-13: full ids are exact but too large, Bloom filters create
false requests, and prefixes are deterministic and bounded. A five-byte header
(magic `0x53`, version `1`, tag, two-byte length) keeps the decoder small. The
wire limit is 15 KiB per frame so the default 16 KiB Bulk frame still fits, and
256 KiB per contact bounds the work a hostile or merely large peer can demand.
A summary with more than 1024 entries is rejected before allocation.

Release uses a two-phase `Done` handshake. An early design released as soon as
the local side had sent its items and received the ones it expected, but the
simulator showed the peer still had queued frames when aoNetwork closed the
link: two of three items were lost. Requiring `Done` from both sides before
`ReleaseOpportunistic` fixed the loss without adding retries or delays. An
equal digest ends the exchange with no release: a simulator run that released
those links cut waypoint delivery from 31/50 to 27/50 by closing links that
were still useful for ordinary forwarding. The 20-second deadline is a
fallback for a stalled peer; it releases once, and a
link drop clears the session so the next encounter restarts from a fresh
digest. Peers without the capability bit stay on the MSH-13 beacon path, so
this is an additive wire change: no packet or hello layout moved.

Acceptance uses aoNetwork `SimWorld` seed `0x5147_2026` with four stable filler
links before the target node appears. Over a 20-second meeting the two stores
converge on the same four live ids (3 seeded locally, 1 from the peer) and the
opportunistic contact is closed. `tests/sync_v1.rs` covers frame bounds, the
per-contact byte budget, link-drop recovery and the release handshake.

## MSH-15 implementation

MSH-15 replaces the MSH-14 summary vector with Negentropy-style binary range
reconciliation when both peers set `CAP_SYNC_V2`. A range is a leading prefix
of the canonical 128-bit id space. Each side hashes its sorted ids in a range
and sends only summaries for ranges the peer requests; differing ranges split
until they hold at most 32 ids, at which point the full ids are exchanged.
The engine then computes the missing prefixes and reuses MSH-14's
`SyncNeed` / `SyncItems` transfer, byte budget, deadline and two-phase release.
Caching canonical full ids in `StoreSummary` costs 16 KiB at the 1024-entry
store bound; no dependency is needed because BLAKE3 is already a dependency.

Two alternatives were considered. An IBLT gives a fixed one- or two-round
exchange but needs careful table sizing, has probabilistic failure modes and
would add a new decoder and dependency. A fixed 64-bucket vector is simpler
but its descriptor cost is constant while the ids sent per differing bucket
still grow with store size. Adaptive binary ranges have neither problem: only
differing branches cost bytes, so a 1000-id store with one missing message
exchanges a handful of summaries rather than 8000 bytes of prefixes. The
deterministic split also avoids false requests and is easy to test.

A canonicalisation bug found by the large-store harness zeroed the byte that
held a range's meaningful bit, collapsing both children into one and leaving
the contact stuck. `range_children_survive_encoding_as_distinct_ranges` now
reproduces that seed-independent failure. The `sync_v2_report` example with
seed `0x515f_2026` and stores of 1000 and 1001 messages measures 2,018 bytes
for v2 against 16,188 bytes for v1, an 87.5% reduction, with both stores
converging. The published MSH-27 baselines are unchanged because empty stores
have equal digests and open no sync contact.

## MSH-16 implementation

MSH-16 carries a copy ticket beside the packet instead of in the header. Three
designs were compared: extending the signed header would change signature
coverage and break every peer; a side-channel key would need a new frame type
and a separate store seam; an additive envelope before the packet on the same
Message channel leaves the header, signature and store key unchanged. The
envelope is six bytes with magic `0x54`, version `1`, Direct tag `1`, a one-byte
ticket and a bounded two-byte inner length. `CAP_SPRAY_V1` is negotiated in
MeshHello; a peer without it receives the raw packet. A stray envelope on a link
without the capability is attributable invalid traffic.

The split is binary: a non-destination contact gets `floor(copies_left / 2)`,
the destination gets one copy, and a node at one ticket waits for the
destination. Fixed fan-out was rejected because it cannot adapt to the number
of contacts and would either over-send in dense meetings or starve sparse ones.
Header-based tickets were rejected because hop-mutable fields must stay outside
the signature and the header is already at its fixed layout. The tracker holds
at most 4096 live ids, and tickets survive store/sync through
`StoreMetadata::copies_left` and `SyncFrame::SprayItem`, so a stored copy can
continue spraying after a later encounter.

Seeds and paired scenarios are fixed in `spray_scenarios()`. With seed
`1297303752` on scripted-200, flooding delivers 100/100 with 3,455
transmissions (34.5500 per delivery); spraying with 255 initial tickets
delivers 99/100 with 1,786 transmissions (18.0404 per delivery), a 48 percent
transmission reduction. With seed `1297303584` on line-20, both deliver 20/20
while spraying uses 186 transmissions against 193. Earlier sweeps with 8 and
64 tickets delivered far below flooding, so the default moved from the ADR's
original six-copy estimate to 255; the published MSH-27 rows remain the
relay-only reference.

## MSH-17 implementation

Three designs were compared for the delivery acknowledgement. A fifth packet
class would force changes to budgets, suppression, seen lifetimes, store class
indexes and relay verification policy for no routing benefit. An aoIdents
`SignedBlob` would reuse an IDN registry row whose documented purpose is
presence and channels, and would need a sibling ADR and tag change. Trusting a
receipt only from the directly connected neighbour cannot purge the rest of a
spray tree. We chose an additive control envelope carrying a normal signed
Direct packet, the acker's full `PublicIdentity`, the original header and the
original payload hash. This stays inside the registered packet signature domain,
lets every relay verify the signer is the true destination without a directory,
and leaves the packet header untouched. It is cap-gated with
`CAP_RECEIPT_V1` (`1 << 3`) and legacy peers receive no receipt bytes.

The immunity list is a bounded LRU-like map (512 ids, five minutes) rather than
an unbounded set or a replay-guard extension. Memory is bounded by configuration
and every entry is deterministic: expiry is relative to local receipt time, and
eviction chooses the earliest expiry then the id order. Hosts remain the store
owner: the engine emits `Purge` and `Delivered` outputs and never holds a store
or key. An immune id is also dropped from the spray relay and sync paths; without
that check, an old spray ticket can re-store a copy after its receipt was
accepted.

The paired report fixes seeds and uses spray in both rows so stores are
populated. With seed `1297303584` on line-20, receipts purge all 206 copies and
the slowest purge takes 1,550 ms; with seed `1297303752` on scripted-200,
receipts purge all 1,341 copies and the slowest purge takes 1,750 ms. Both
ablations retain their copies (`206` and `1,436`), so the purge is attributable
to MSH-17. The regression gate `tests/sim_receipts.rs` requires zero remaining
copies and a purge latency below ten seconds.
## MSH-20 implementation

The directory is a local, ephemeral view over presence facts, not a wire
protocol. Two storage designs were compared. An unbounded `BTreeMap<NodeId, _>`
is the simplest but a hostile announcement flood grows memory without limit;
a time-only map with periodic scanning bounds staleness but still lets memory
grow inside the window and makes cleanup linear in attacker-controlled size.
The chosen design keeps a `BTreeMap` keyed by `NodeId` plus an ordered LRU key
set `(local receipt time, sequence, node id)`. Inserts are `O(log n)`, eviction
is `O(log n)`, and both structures are bounded by the same configured
capacity. The id tie-break makes eviction reproducible with a fixed input
stream and seed. `std` collections suffice; no dependency is added.

The event stream had two realistic shapes: one UI event per observation, or a
bounded queue coalesced by node. The first is trivial but gives a hostile
neighbour an unbounded UI event stream; the second emits only the net effect.
`set` and `VecDeque` are both capped by `max_change_events`, and merging
`Added` with `Removed` drops the event entirely while `Removed` followed by
`Added` becomes `Updated` because the UI last knew the node as present. The UI
queries the entry by id rather than receiving location bytes in the stream.

| Setting | Default | Reason |
|---|---|---|
| Directory entries | 256 | Covers a contact's visible mesh in about 80 KiB including indexes |
| Stale after | 30 min | ADR-0001 Presence lifetime; one missed trickle refresh does not expire a node |
| Location bytes | 64 | Bounds hostile claims while leaving the telemetry schema to MSH-22 |
| UI events | 64 | Absorbs announcement bursts without unbounded app work |

Lifetime is relative to local receipt time with a high-water-mark clock: a
backwards `now` cannot mint a longer or shorter life. The observation time is
clamped for display ordering only and never sets `expires_at_ms`; this keeps
peer clock skew out of expiry, matching MSH-18's contract. A lower `seq` is
ignored, and equal-content refreshes produce no UI change, so repeated
announcements cannot churn the event stream.

The fixed `directory-line-6` case (seed `1297304021`, static line, capacity 4,
2,000 ms staleness, alternating 5,000 ms observation-time skew) peaks at four
entries, records 24 expirations and 24 evictions, removes the last entry at
4,000 ms and ends with zero live entries. The numbers are locked in
`tests/sim_directory.rs`; no MSH-27 routing threshold changed because the
directory path emits no radio traffic.

## Lifetime implementation (MSH-18)

`expiry::LifetimePolicy::default()` implements this table's lifetimes unchanged.
A store may set local ceilings at construction, but never extend the packet's
sender lifetime. Relative age and local elapsed time determine expiry; remote
`created_ms` does not. See [lifetime policy](lifetime-expiry.md) for the clock
contract, examples versus accepted defaults, and validation boundaries.
