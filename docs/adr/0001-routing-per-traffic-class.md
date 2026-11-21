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
keyed by the claimed origin and one by the sending link. Both use the hourly
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
failed verification add 2, and packets a bucket could not admit add 1. Penalty
decays by 1 per minute; reaching 12 emits one `Release` with
`DisconnectReason::AbuseDetected`, and a later `LinkDown` forgets the score.
aoNetwork owns reconnection and any future blacklist decision, so no new wire
field or sibling API is needed. MSH-09 authenticates local delivery, but a
relay still keys the origin bucket from the claimed header value; the per-link
bucket limits any sender regardless of what it claims, and relay-side origin
signatures for flooded classes are a separate concern.

Measured on the MSH-27 simulator with the fixed flood case (seed `1297304003`,
20-node random graph, 300 oversized messages from one origin and 300 from
honest nodes): the flooder delivered 92 of 300 with budgets and 236 of 300
with budgets disabled, while honest deliveries were 208 of 300 with budgets
and 199 of 300 without. A no-flood control delivered 217 of 285 honest
messages. The four published MSH-27 scenarios stayed inside their existing
directional bounds. No default in the table changed.
