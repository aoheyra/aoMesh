# ADR-0002: Packet wire format

- **Status:** accepted
- **Date:** 2026-11-15
- **Related:** MSH-03 implements it; MSH-04 signs the immutable prefix and derives `msg_id`; MSH-07 negotiates versions and features via `MeshHello.proto` and `caps`; ADR-0001 defines the class names this format carries.

## Decision

The v1 layout with class IDs 1 Direct, 2 Broadcast, 3 Presence, 4 Telemetry,
flags bit 0 for `dst`, canonical unsigned LEB128 integers, a 2048-byte
payload cap, a contiguous immutable prefix that ends just before `ttl`, a
64-byte Ed25519 origin signature between the hop fields and the payload,
and a `msg_id` derived from the immutable prefix and the payload hash.
The byte-level reference is `docs/protocol.md`; the `packet` and `sign`
modules' rustdoc document the same layout.

## Reasons

**Varints instead of fixed-width fields.** Fixed u64s for `created_ms`,
`lifetime_s` and `payload_len` would cost 24 bytes on every packet; the
LEB128 form of realistic values costs 4 to 9. Presence and telemetry packets
are small and frequent, so those bytes are air time. The cost is a slightly
more complex parser, bounded at 10 bytes per field.

**Immutable prefix first, hop fields after it.** Putting `ttl` and `hops` at
the front of the header, as a flat field list suggests, would split the
signed range into two slices or force a copy before signing. Keeping the
prefix contiguous lets MSH-04 sign `bytes[0..prefix_len]` directly: one
range, no copying, and a relay's `ttl` decrement cannot touch it.

**Reject, do not normalise, non-canonical encodings.** Two encodings of the
same integer would give one message two byte strings, and `msg_id` derives
from bytes: uniqueness of the encoding is uniqueness of the identity.

**Reject unknown classes, flags and versions.** Ignoring unknown flag bits
would accept two byte strings as the same packet; ignoring an unknown class
would route by fallback. Fail closed and introduce new behaviour through
`MeshHello.proto` and `caps` (MSH-07) instead.

**2048-byte payload cap.** ADR-0001 budgets assume 2 KiB messages ("500
messages of 2 KiB per hour"), aoNetwork's default frame is 16 KiB, and the
cap bounds what a hostile header can make a relay hold before the payload is
even read. Larger payloads are a future protocol change, not a tunable.

**Signature after the hop fields, payload last.** The signature
authenticates the header, so it sits with the header: after the mutable
hop bytes, before the opaque payload. A future payload-level protection
can then append after the payload without moving the signature. It covers
the immutable prefix only; the payload is bound through `msg_id`, which
hashes the payload, so signing the payload twice is not needed.

**`msg_id` as a content address.** The ID derives from the prefix with
its own field hashed as zeroes (it sits inside the prefix it derives
from) plus a domain-separated hash of the payload. Every other prefix
field participates, so different content cannot claim one dedup key, and
the hop fields do not, so a relay's `ttl` decrement never changes a
message's identity on its way to the seen-cache (MSH-05). Both domains,
`aoheyra/mesh/v1/packet` and `aoheyra/mesh/v1/msg-id`, were registered in
aoIdents ADR-0001 before use, as that registry requires.
