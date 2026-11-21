# ADR-0005: Authenticated local delivery (MSH-09)

- **Status:** accepted
- **Date:** 2026-11-21
- **Related:** MSH-09, IDN-09 (`SealedMessage`), IDN-14 (`ReplayGuard`), ADR-0002 (wire format), ADR-0003 (seen-cache bounds)

## Decision

A Direct packet whose `dst` names the receiving node is a *candidate*.
`MeshOutput::Deliver` is emitted only after all of these steps, in order:

1. `SealedMessage::decode` parses the bounded payload.
2. `SealedMessage::open(identity, aad)` authenticates the seal under
   associated data `aad = derive_msg_id(header, &[])` and yields the
   plaintext and the sender's `PublicIdentity`.
3. `compute_node_id(sender.signing_pk, sender.agreement_pk)` must equal
   `header.origin`.
4. `verify_origin(sender, header, payload, signature)` must accept the
   origin signature and the content-derived `msg_id`.
5. `ReplayGuard::accept(origin, msg_id, created_ms, now)` must accept.

The host receives the opened plaintext. The header is passed through as
received, so its `payload_len` is the length of the *sealed* wire payload,
not of the plaintext. A failure at any step produces nothing and increments
`Neighbor::rejected_packets`; a content address that fails to re-derive in
MSH-08 is counted the same way. Normal policy drops (duplicate, worn `ttl`,
class gate, unverified link) are not penalties.

The recipient borrows `&Identity` on each `MeshInput::Data` instead of
owning it. `MeshInput::Submit` already borrowed an identity for signing;
extending that rule to Data keeps keys in the host and lets one engine serve
one node without retaining secret material (AGENTS section 3). The adapter
passes each node's own identity when it pumps a network event.

## Why the seal is bound to the header content address, not to `msg_id`

`msg_id = H(header_prefix || H(payload))` (MSH-04). For a Direct packet the
payload *is* the seal, so binding the seal to `msg_id` is a cycle: the id
needs the ciphertext hash before the ciphertext exists.

| Option | Consequence |
|---|---|
| Bind to `msg_id` | Needs a two-pass seal/pad hack or a change to the MSH-04 id derivation; both are protocol changes and neither buys a stronger guarantee than the chosen binding. |
| Bind to `derive_msg_id(header, &[])` (chosen) | `derive_msg_id` hashes every immutable field with `msg_id` zeroed, including `dst`, `origin`, `created_ms` and `payload_len`. Step 4 binds `msg_id` itself to those same header bytes *and* the ciphertext under the origin signature. The composition is equivalent to binding the seal to the whole packet. |
| No header binding; rely on the origin signature alone | A seal made for another context (different recipient or header) could be spliced under a header the sender signed for a different purpose whenever the payload hash stayed equal. AEAD associated data is designed to prevent exactly this; using it costs nothing on the wire. |

Opening happens before signature verification because the packet carries no
verification key of its own: the only authenticated sender key available at
the recipient is the one inside the seal. The seal's own message signature
and key binding are already verified by `SealedMessage::open`; the origin
binding then prevents a sender from claiming another node's identity.

## Replay parameters

| Parameter | Value | Reason |
|---|---|---|
| sliding window | 1024 ids per sender | A busy day of one-to-one messages per active contact; aoIdents' maximum. |
| timestamp tolerance | 86,400,000 ms (24 h) | Matches ADR-0001's Direct lifetime and the seen-cache's Direct window. A stored message that arrives a day late still opens; after that both the seen-cache and the guard refuse it. |
| max senders | 64 | Well beyond the MVP's daily active contacts; bounds memory at 1024 x 64 x 24 bytes, about 1.5 MiB at the absolute ceiling. |

The seen-cache remains the first line of duplicate defence (forwarding
dedupe); the replay guard is the recipient's acceptance check and is not
merged with it. Because both cover the same 24-hour Direct lifetime, an id
that leaves one is still held or rejected by the other. A forged delivery
never records a seen-cache entry: forwarding records relays immediately,
but the engine records a delivery only after the pipeline accepts.

## Sender recipe (application side, e.g. APP-09)

The payload of a sealed Direct packet is built before submission:

1. Seal the plaintext to the recipient's `PublicIdentity`. The AAD is
   `derive_msg_id(header_with_zero_msg_id, &[])`; `header.dst` and
   `header.origin` must already be final. The encoded length does not depend
   on the AAD, so it can be measured with one probe seal or computed from
   the suite's fixed overhead.
2. Put the encoded seal in `header.payload_len`.
3. Call `sign_packet`, which stamps `origin` and derives `msg_id` from the
   header and the sealed bytes, then submit the header and sealed payload.

`tests/common/mod.rs` contains this recipe for tests only; production hosts
own their own CSPRNG and call `SealedMessage::seal` directly.

## Tests

Unit tests cover every failure step (malformed seal, flipped ciphertext,
wrong recipient, edited header, sender/origin mismatch, broken signature,
claimed `msg_id` mismatch, replay, timestamp outside tolerance, full
window), plus an honest delivery. Engine tests cover an honest delivery and
its duplicate, tampered signatures, a seal for another recipient, penalty
counters, and the multihop line/ring/random-graph paths in
`tests/forwarding.rs`, where the destination now emits an authenticated
delivery rather than a structural one.
