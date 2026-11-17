# Lifetime and expiry policy (MSH-18)

Status: proposed implementation for issue #25.

## Decision

LifetimePolicy supplies configurable per-class local ceilings. Defaults preserve
ADR-0001: Direct 24 h, Broadcast 6 h, Presence 30 min, Telemetry freshness 5 min.
The values in issue #25 are examples, not a change to the accepted defaults.
Zero disables retention for a class. Telemetry remains non-storable regardless
of its freshness ceiling. No relay budgets or wire fields change.

Effective lifetime is min(sender lifetime, local class ceiling). Consumed age
is age at receipt plus elapsed local monotonic time. created_ms is never read
by the expiry calculation. Using a wide integer internally avoids premature
expiry from overflowing seconds-to-milliseconds conversions; remaining_ms
saturates only its public return value. Expiry occurs when remaining time is
zero, including the exact deadline.

MemoryStore freezes its policy at construction. Admission, duplicate lookup,
get, by_destination, summary and expire all use the same policy. StoredMessage
exposes is_expired_with for other MessageStore backends; is_expired uses the
ADR defaults. SQLite must apply its configured policy on every query as well
as during cleanup. Packet bytes are never rewritten to enforce a local limit.

## Alternatives and costs

Remote wall-clock deadlines are compact but expire early/late under peer clock
skew and couple delivery correctness to clock synchronization. Relative age
plus a local receipt epoch costs two existing u64 metadata fields, requires
constant CPU and no allocation, and is deterministic and easy to test. We use
relative age. A mutable store-wide policy would let an update revive or expire
entries mid-run; an immutable construction policy makes lifecycle decisions
stable. Caller reconstruction is needed to change it.

This is a retention correctness change, not a routing optimization. Delivery,
latency, radio overhead and phone battery improvements are not claimed. Existing
class defaults are preserved; no parameter sweep or changed routing baseline
is introduced. The deterministic skew tests cover 9 combinations of local and
remote epochs, including a remote u64::MAX wall clock.

## Caller contract and boundaries

now and received_at share a monotonic local epoch. A backward sample consumes
zero additional age; this is defensive arithmetic, not support for a system
wall clock that can jump. age_at returns consumed age to carry to the next
encounter. The next node uses that age with its own receipt epoch, not the
previous node's timestamp. Known transport delay must be added by the caller.
An untrusted peer can lie about age: relative-age arithmetic is not an
authenticated age protocol. Sync integration belongs to MSH-14 and restart
translation to MSH-29; neither silently resets age to zero. No new age field
is added to the packet wire format by this change.

## Validation

Public tests cover all defaults, configurable ceilings, a shorter sender
lifetime, zero retention, exact boundaries, remote and local clock offsets,
multiple encounters, integer extremes, unchanged packet bytes, and every
MemoryStore expiry path. Existing store conformance remains in place.
