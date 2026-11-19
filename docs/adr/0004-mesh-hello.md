# ADR-0004: MeshHello layout and verification

- **Status:** accepted
- **Date:** 2026-11-19
- **Related:** MSH-07 implements it; aoIdents ADR-0001 registers the
  `aoheyra/mesh/v1/hello` domain and exposes the `verify_signing_pk` and
  `compute_node_id` seams this uses; ADR-0002's `ver` is negotiated
  through this hello; `docs/protocol.md` carries the byte table.

## Decision

One fixed 161-byte layout inside aoNetwork's 256-byte `app_hello`:

```
offset 0   node_id       16   claimed; must equal the derivation below
offset 16  card_hash      8   identity-card announcement hash, opaque
offset 24  proto          1   mesh format version the sender speaks
offset 25  caps           4   feature bits, big-endian
offset 29  store_digest   4   store summary digest, opaque
offset 33  signing_pk    32   Ed25519 verification key
offset 65  agreement_pk  32   X25519 key; with signing_pk derives node_id
offset 97  signature     64   over bytes 0..97 under the hello domain
```

The signature covers bytes 0..97, everything before it, under
`aoheyra/mesh/v1/hello`. Link-up admits a neighbour's identity only when
the hello decodes to exactly this length, the signature verifies under
`signing_pk`, `compute_node_id(signing_pk, agreement_pk)` reproduces the
claimed `node_id`, and negotiation succeeds: common `proto` is the lower
of the two sides and never below 1, common `caps` is the intersection. A
hello that fails any step is dropped - the neighbour entry counts
traffic with `node_id: None` and no policy may forward, deliver or
budget on its behalf - and the link itself is released only when the
neighbour table is full.

## Reasons

**Fixed width, not varints.** The hello is parsed once per link, never
in a hot loop, so the parsing cost is irrelevant while bounds checks
become trivial: one length decision, then fixed-offset reads. Any bit
pattern round-trips byte-identically (`decode(encode(h)) == h`), so
verification over the re-encoded body covers exactly the received bytes
and there is no canonicalisation to disagree about.

**Both public keys in the hello; the id is derived, never trusted.**
Link-up is first contact: there is no directory yet to look a key up
in, so the keys travel with the introduction. Verification proves
control of `signing_pk`, and the derived `node_id` is what the entry
records, so a sender cannot claim an identity it does not own.
Cross-pairing a foreign `agreement_pk` derives a third, different id -
a phantom that looks like nobody else, which is a sybil problem for
MSH-10's budgets, never an impersonation.

**`card_hash` is the 8-byte announcement hash.** It is the only card
hash aoIdents exposes publicly (`IdentityCard::announcement_hash`), and
it is a hint for the app layer, which binds names to ids later; no
mesh decision rests on it. It sits inside the signature, so it cannot
be swapped in transit.

**Dropped, not released, on failure.** The contract is that a failed
verification never records an identity while the entry keeps observing
the link: its counters are what MSH-10's penalties will read. Release
stays reserved for the table's own admission decision (it is full).
Entry count cannot be poisoned beyond what the radio's degree cap
already allows, so garbage hellos cost an attacker a held link, not
unbounded state.

**Negotiation computes from one exchange.** `min(proto)` and the `caps`
intersection are symmetric, so both ends reach the same result from the
single hello, with no extra round trip. The floor of 1 fails closed
when there is no common version, and a hello that cannot be parsed to
that length is rejected before any field is read.

## Consequences

- Changing the layout, the signature coverage or the negotiation rule
  is a protocol change: this ADR, a `PROTO` bump and a compatibility
  note.
- v1 receivers reject every length except 161 (`TrailingBytes`), so a
  future layout must either keep this core parseable or accept that
  older nodes drop the hello: the link stays up, unverified.
- `hello` works on bytes and aoIdents types only, so its codec is
  unit-tested against hostile input without the engine or the facade.
