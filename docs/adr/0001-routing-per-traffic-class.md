# ADR-0001: Routing per traffic class

- **Status:** accepted
- **Date:** 2026-11-05
- **Related:** MSH-08..MSH-11 implement the mechanisms; MSH-27 sweeps these defaults; IDN-19 records the metadata consequence.

## Decision

Units: TTL = hop limit; Copies = copies in the network; Lifetime = how long a copy may be stored; Relay budget = node-wide KiB/hour a node spends relaying that class for others; Priority = scheduling order, 1 = highest.

| Class | Mechanism | TTL | Copies | Lifetime | Relay budget | Priority |
|---|---|---|---|---|---|---|
| Direct | spray-and-wait with reverse-path hints | 8 | 6 | 24 h | 1 MiB/h | 1 |
| Broadcast and channels | counter-based suppression | 6 | 1 per node (forward once) | 6 h | 256 KiB/h | 2 |
| Presence | trickle-timed gossip | 3 | 1 per node | 30 min | 64 KiB/h | 3 |
| Telemetry (location) | announce, latest-wins, no storage | 3 | 1 per node | 5 min | 32 KiB/h | 4 |

## Reasons

**Direct — TTL 8, 6 copies, 24 h, 1 MiB/h.** Room and building diameters stay well under 8 hops at a degree cap of 8; six copies survive two relay failures without approaching flood cost (sweep 2–10 in MSH-27); 24 h covers an overnight-offline recipient inside a bounded store; the budget lets a relay carry roughly 500 messages of 2 KiB per hour for neighbours before shedding, so one busy conversation cannot evict everything else.

**Broadcast and channels — TTL 6, forward once, 6 h, 256 KiB/h.** Each node forwards at most once and the counter suppresses re-floods, so the copy count is bounded by topology rather than by the sender; six hours outlives a suppressed flood (the origin re-announces newer content anyway); the budget is a quarter of Direct's because every duplicate is re-relayed by many nodes.

**Presence — TTL 3, 30 min, 64 KiB/h.** Trickle refreshes every 10–15 minutes, so a packet only has to outlive one missed period; three hops cover the immediate neighbourhood where presence is useful; the budget bounds Sybil spam to a few dozen announcements per hour.

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
| Copy bounds | 1 to 6 | Sparse graphs still forward; hostile or extreme degrees cannot mint unbounded work |
| Base delay | 60-140 ms, seeded | Long enough for neighbour copies, short enough for a contact |
| Final delay | 20-600 ms, shrinking with degree | Dense groups decide sooner without letting sparse groups relay blind |
| Class TTLs | 8, 6, 3, 3 | Same table as above; submission and relay both clamp |

Three threshold policies were considered. A fixed `k = 2` is simple but
leaves most of the flood's redundancy in dense graphs. A fixed `k = 1`
removes almost all transmissions but isolates nodes that only hear one copy.
A degree-scaled `k` with fractional seeded rounding is the chosen option: it
spends relays where neighbours are scarce and cancels them where the mesh
already offered several chances. The delay shrinks with degree for the same
reason. The reference degree is four, calibrated by the 50-node sweep; bounds
keep `k` and the delay finite for hostile degree claims. State is bounded at
1024 pending messages and evicted by earliest deadline.

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
