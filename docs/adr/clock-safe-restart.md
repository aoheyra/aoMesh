# Clock-safe process restart (MSH-29 follow-up)

The original `Snapshot` format preserves absolute `expires_at_ms` and raw LinkIds.
That is sufficient only when the host preserves the exact clock epoch and link
namespace. Android process/device restarts can change both. A high new clock can
expire every dedupe record immediately; a reset clock can retain immunity too
long; a reused link number can suppress gossip to an unrelated new peer.

## Host contract

Use `TimedSnapshot::snapshot_at(now_ms, identity.node_id())`, atomically persist
those bytes with MessageStore copy metadata, then create a fresh engine and call
`restore_at(new_now_ms, identity.node_id(), elapsed_ms, &bytes)` before feeding
any input. The host owns persistence, bounded deserialization where relevant,
local storage authentication/encryption, and measurement of elapsed time since
capture. The engine reads no clock and stores no keys or message payloads.

`elapsed_ms` includes time since capture and downtime. Never subtract two different
monotonic epochs. If downtime is unknown, zero conservatively retains the saved
guards; repeated restarts can then retain them longer than their nominal lifetime.
The host needs a trusted elapsed-time source to age records accurately across
launches. A snapshot is not durable or crash-exact unless the host commits it
consistently with MessageStore. Pending suppression timers are not persisted.

Restore is atomic and restricted to a fresh engine. It checks owner, format,
existing section/byte limits and receipt signatures, rebases remaining durations
using checked addition, discards expired entries, and clears every saved transport
LinkId. It preserves zero-copy tombstones and wait-phase one-copy tickets. Duplicate
observations do not replenish a live ticket or renew its deadline. Zero-capacity
spray stores no state. ReplayGuard remains separate from forwarding dedupe.

## Format and compatibility

`AMST`, version 1, wraps 16 bytes of owner NodeId and an existing bounded AMSH
snapshot payload whose deadline fields now carry remaining durations. The wrapper
is 21 bytes. It has a separate magic so legacy `Snapshot::restore` rejects it
rather than treating durations as absolute deadlines. All existing legacy tests
and the legacy byte format remain intact; existing applications can migrate
explicitly. There is no radio packet, capability or signature-domain change.

The complete wrapper remains bounded by `MAX_SNAPSHOT_LEN` (4 MiB). Existing
receiver configuration limits cap section counts before allocation. Remaining
seen/copy durations are at most the ADR-0001 Direct ceiling (24 hours); immunity
also respects the receiving engine's configured lifetime. A smaller receiver cap
rejects an incompatible snapshot instead of silently dropping guards. Overflow
and malformed state return typed errors and leave the engine untouched.

## Alternatives

| Approach | Delivery, latency and radio cost | Memory, CPU and battery | Determinism and maintenance |
| --- | --- | --- | --- |
| Explicit time-aware wrapper (chosen) | Retained ids do not re-relay after an epoch change; no extra radio message | Existing bounded metadata plus 21 bytes; reverify receipts at restore | Existing parser and legacy API retained, host downtime explicit |
| Require stable wall clock and LinkIds forever | Can forget guards or suppress the wrong session after restart | Smaller API but extra radio traffic when state is lost | Relies on platform assumptions the sans-IO engine cannot enforce |

Tests exercise a reset clock and a clock advanced to 1,000,000,000,000 ms,
relative expiry boundaries, owner/version/truncation rejection, overflow, atomic
failure, fresh-engine gating, authenticated immunity, gossip after LinkId reuse,
spent tickets and zero capacity. Existing restart tests continue to pass. These
are engine-seam tests, not proof that the application implements durable storage.
