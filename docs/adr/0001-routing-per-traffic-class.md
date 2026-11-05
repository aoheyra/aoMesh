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
