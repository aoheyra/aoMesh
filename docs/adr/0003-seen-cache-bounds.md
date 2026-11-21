# ADR-0003: Seen-cache bounds

- Status: accepted
- Date: 2026-11-16
- Related: MSH-05 implements it; ADR-0001 supplies the per-class
  lifetimes; MSH-08 wires the cache into forwarding; MSH-29 adds the
  optional restart snapshot.

## Decision

Forwarding dedupe is one cache keyed by `msg_id` (`MessageId`), bounded
in both size and time:

- **Size**: at most `capacity` recordings (default 4096). When full the
  oldest recording is evicted first, in original recording order.
- **Time**: a recording expires at record time plus its class's window
  from ADR-0001's Lifetime column (Direct 24 h, Broadcast 6 h, Presence
  30 min, Telemetry 5 min). An offer is a duplicate while
  `expires_at > now`, fresh at or after that instant; a duplicate does
  not extend the window.
- Capacity wins over time under pressure: eviction can end dedupe early
  for the oldest traffic, which is what keeps a flood of unique ids
  inside the memory budget. `capacity` 0 records nothing; a 0 lifetime
  never deduplicates. There are no error paths: every offer answers
  `Fresh` or `Duplicate`.

Both structures are strict functions of `capacity`:

- the recordings map is a `BTreeMap<MessageId, u64>` (key to expiry);
- the order deque is a `VecDeque<MessageId>` that reserves `capacity`
  slots at construction; a recording made while the deque is full holds
  no slot and is reclaimed at expiry instead of by eviction.

## Reasons

**Two bounds, not one.** Time alone lets a hostile peer pin memory by
flooding unique ids inside one window; size alone would shed dedupe for
old traffic at arbitrary moments. Together, pressure removes the oldest
recording first, and time removes everything eventually.

**`BTreeMap` over `HashMap`.** std's hashbrown keeps `capacity()` as
`items + growth_left`, and erasing leaves `DELETED` markers that do not
restore `growth_left`; under the erase/insert churn that eviction
produces, `growth_left` drains and forces a table rehash below the
configured size, doubling the table (measured: rehash at about 36k churn
inserts at 4096 live entries of a capacity-7168 table, with capacity
still eroding afterwards). Item counts stay bounded, but bytes then have
no hard configured bound. A `BTreeMap`'s nodes are a strict function of
item count, which never exceeds `capacity`, so the byte cap is
structural; measured through one million insertions
(`tests/seen_memory.rs`): 65,536 bytes reserved (the deque), 263,560
bytes peak, budgeted at 512 KiB. The cost is `O(log capacity)` lookups
instead of `O(1)`, negligible next to signature verification and radio
time at a few thousand entries.

**Oldest-first eviction with an order deque.** FIFO matches the
lifetime table: the oldest recording is the closest to expiring anyway.
The deque keys eviction order; it holds no expiry state, so a stale slot
left by an expired re-recording frees only itself when the sweep reaches
it, and evicting through a stale slot can drop a newer recording early.
Both are the documented approximation: dedupe for an id can end before
its window under capacity pressure, and eviction order is
oldest-first-by-original-recording in the common case.

**Expiry checked at lookup, reclaimed from the front.** Correctness
never depends on cleanup: every lookup compares the timestamp itself, so
an expired id answers `Fresh` even if its slot was never swept. The
front sweep runs in amortised `O(1)` because the front holds the oldest
recordings; with mixed class windows a live front entry can hide expired
ones behind it, which are then reclaimed at their own lookup or by
capacity. The size bound does not depend on the sweep at all.

## Consequences

- `MeshEngine` (MSH-08) calls `check_and_insert` once per received
  Direct packet whose content matches its claimed `msg_id` (dropping
  `Offer::Duplicate` before it can deliver or relay), and once per
  submission so an origin never re-relays its own message.
- A restart without a snapshot loses the cache and dedupe resets, which a
  delayed neighbour copy can turn into a re-relay. MSH-29 snapshots the entry
  map and the eviction order together, so restored nodes keep the same dedupe
  decisions and the same capacity-eviction point; omitting the order would
  change behaviour even when every live id survived.
- The byte ceiling is enforced by `tests/seen_memory.rs`; the capacity
  and window defaults are enumerated by a test in `seen.rs`.
