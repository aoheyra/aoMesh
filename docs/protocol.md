# aoMesh packet wire format (v1)

Implemented by the `packet` module (MSH-03). Decision record:
[ADR-0002](adr/0002-packet-wire-format.md). Traffic classes come from
[ADR-0001](adr/0001-routing-per-traffic-class.md).

## Layout

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | `ver` | `1`; any other value is rejected |
| 1 | 1 | `class` | 1 Direct, 2 Broadcast, 3 Presence, 4 Telemetry; 0 and 5..255 rejected |
| 2 | 1 | `flags` | bit 0 = `dst` present; all other bits must be 0 |
| 3 | 16 | `msg_id` | derived from the immutable prefix and the payload hash (MSH-04) |
| 19 | 16 | `origin` | opaque node ID |
| 35 | 0 or 16 | `dst` | present iff flags bit 0 is set |
| .. | 1..10 | `created_ms` | unsigned LEB128 |
| .. | 1..10 | `lifetime_s` | unsigned LEB128 |
| .. | 1..10 | `payload_len` | unsigned LEB128, at most 2048 |
| .. | 1 | `ttl` | hop-mutable |
| .. | 1 | `hops` | hop-mutable |
| .. | 64 | `signature` | Ed25519 over the immutable prefix, domain `aoheyra/mesh/v1/packet` |
| .. | `payload_len` | `payload` | opaque bytes |

The bytes from `ver` up to (excluding) `ttl` form the **immutable prefix**:
one contiguous range. The origin signature covers exactly this range and
nothing else. `ttl` and `hops` sit after it, so a relay decrementing
`ttl` never breaks verification, while any change inside the prefix does.
The signature follows the hop fields: it is outside the range it covers,
so verification never depends on hop state. The payload is bound to the
signature through `msg_id`, which derives from the payload hash.

## Origin signature and `msg_id` (MSH-04)

The origin signs the immutable prefix under `aoheyra/mesh/v1/packet`,
using aoIdents' context-separated sign/verify (IDN-04); both domains are
registered in aoIdents ADR-0001. The policy: relays verify Broadcast and
Presence always, Direct only while their CPU budget allows, and never
Telemetry; the recipient always verifies a Direct packet addressed to it
(`sign::verify_for_relay`, `sign::verify_origin`). MSH-04 ships the calls;
MSH-09 runs the recipient's check for local delivery. Relay-side checks
follow with the issues that build those paths (MSH-10, MSH-11).

`msg_id` is a content address, in two domain-separated steps under
`aoheyra/mesh/v1/msg-id`:

```
payload_hash = BLAKE3(domain || 0x01 || payload)
msg_id       = BLAKE3(domain || 0x02 || prefix_with_msg_id_zeroed || payload_hash)[..16]
```

The field is hashed as zeroes because it lives inside the prefix it
derives from. Every other prefix field participates, so two different
messages cannot claim one dedup key; `ttl` and `hops` do not, so a relay's
hop decrement keeps a message's identity stable (MSH-05 keys its
seen-cache on this value).

Verification re-encodes the parsed header rather than slicing raw bytes:
parsing rejects non-canonical input, so a decoded header re-encodes to the
exact bytes that were received.

## Rules

- Integers use **canonical** unsigned LEB128: the shortest form only, at
  most 10 bytes, at most 64 bits. Non-canonical input is rejected rather
  than normalised, so one message has exactly one byte string, and therefore
  exactly one `msg_id`.
- `payload_len` is capped at **2048 bytes** (`MAX_PAYLOAD`). The cap is
  checked while the header is parsed, before any payload byte is read.
- Parsing is header-first and allocation-free: `Header::decode` never reads
  payload bytes, and `Packet::decode` borrows the payload in place instead
  of copying it.
- A packet must consume its input exactly; trailing bytes are rejected.
- Unknown versions, classes and flag bits are rejected: fail closed.

## MeshHello (MSH-07)

The signed link introduction lives in the `Hello` frame's opaque
`app_hello` (aoNetwork, NET-04), not in the packet above. Decision
record: [ADR-0004](adr/0004-mesh-hello.md). It is fixed-width and
exactly 161 bytes:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 16 | `node_id` | claimed; must equal the derivation below |
| 16 | 8 | `card_hash` | identity-card announcement hash, opaque to the mesh |
| 24 | 1 | `proto` | mesh format version the sender speaks |
| 25 | 4 | `caps` | feature bits the sender sets, big-endian |
| 29 | 4 | `store_digest` | store summary digest, opaque to the mesh |
| 33 | 32 | `signing_pk` | Ed25519 verification key |
| 65 | 32 | `agreement_pk` | X25519 key; with `signing_pk` it derives `node_id` |
| 97 | 64 | `signature` | Ed25519 over bytes 0..97, domain `aoheyra/mesh/v1/hello` |

The signature covers the contiguous prefix before it, under the domain
registered in aoIdents ADR-0001, so a signature made for any other
registered use never verifies as a hello. Verification is strict
Ed25519 against `signing_pk`, then `node_id` must reproduce
`compute_node_id(signing_pk, agreement_pk)`: the identity is derived
from the keys, never trusted from the bytes. Proof of key control is
not a real-world identity - cards and directories bind names later,
and the mesh budgets every neighbour as hostile regardless.

On link-up the engine decodes, verifies and negotiates: common `proto`
is the lower of the two sides, never below 1, and common `caps` is the
intersection, both computable from this one hello. An introduction
that fails any step - truncated, oversize, tampered, foreign domain,
mismatched id or no common version - is dropped: the neighbour entry
still counts traffic but records no `node_id`, and nothing may
forward, deliver or budget on its behalf. Every field is fixed-width,
so hostile bit patterns decode identically and
`decode(encode(h)) == h` holds with no normalisation.

## Versioning

`ver` selects the packet layout. Mesh format versions travel in
`MeshHello.proto` (MSH-07): both ends take the lower `proto` value,
never below the floor of 1, and intersect `MeshHello.caps`, so a node
never parses bytes of a version it does not know, and a hello with no
common version is dropped like an invalid one. Changing this layout or
the hello's is a protocol change: ADR, version bump and compatibility
note (AGENTS section 4).

## Errors

`PacketError` carries one variant per rejection: `Truncated`,
`UnsupportedVersion`, `UnknownClass`, `UnknownFlags`, `NonCanonicalVarint`,
`VarintOverflow`, `PayloadTooLarge`, `PayloadLengthMismatch`,
`TrailingBytes`. Each has a test that triggers it.

Origin verification reports `sign::VerifyError`: `BadSignature` (wrong key,
tampered prefix or foreign domain) and `MsgIdMismatch` (the header claims a
derivation the content does not produce). Each has a test that triggers it.

MeshHello rejections report `hello::HelloError`: `Truncated`,
`TrailingBytes`, `Verify` (tampered field, foreign domain or weak key, as
aoIdents reports it), `NodeIdMismatch`, `IncompatibleProto`. Each has a
test that triggers it.

## Engine integration (MSH-06, MSH-08)

The wire layout is unchanged. Submit validates the payload/header agreement,
stamps origin and content-derived ID, signs, then encodes. Selected-link
submission requires an admitted neighbour; broadcast uses every up link, and
every submission is recorded in the seen-cache so its own copy can never
loop back to be re-relayed.

Incoming bytes are parsed without copying and counted first. A packet from
an admitted link whose hello was verified then takes the MSH-08 rules: the
content-derived `msg_id` must re-derive before any state changes, a repeat
in the seen-cache is dropped, a Direct packet addressed to this node is
delivered, and otherwise it relays to every verified neighbour except the
sending link with `ttl` decremented (hop limit: submitted `ttl` N reaches N
hops, and the destination delivers regardless of a worn `ttl`) and `hops`
incremented, saturating at 255. Before producing relay copies, MSH-10 debits
the origin and sending-link buckets; a local delivery still happens when the
bucket is empty. Classes other than Direct, senders without a verified
`node_id` (ADR-0004) and content whose bytes no longer match its `msg_id` are
counted and dropped. A forged content address is additionally counted as a
rejection on the sending link. The relay path itself verifies no origin
signature; local delivery is authenticated by MSH-09 below. Link-up
authentication is MSH-07 (above).

## Authenticated local delivery (MSH-09)

A Direct packet whose `dst` names the receiving node is only a candidate.
Its payload must be an aoIdents `SealedMessage` (IDN-09) addressed to the
receiving node. The sender seals the plaintext to the recipient's public
identity under associated data `derive_msg_id(header, &[])` - the immutable
header content address with `msg_id` zeroed by the derivation. The seal's
encoded length does not depend on the associated data, so the sender sets
`header.payload_len` before the real seal and then signs with `sign_packet`,
which stamps `origin` and the ciphertext-derived `msg_id`. This binding is
not circular: `msg_id` is authenticated separately by the origin signature
over the header and the seal's hash. Decision record:
[ADR-0005](adr/0005-local-delivery-pipeline.md).

`MeshInput::Data` borrows the local `Identity` for this call; the engine
never retains a key. The recipient then:

1. decodes the bounded seal;
2. opens it under that content-address binding, which authenticates the
   plaintext and the sender's public identity;
3. derives the sender's `NodeId` from the seal and requires it to equal
   `header.origin`;
4. verifies the origin signature and re-derives `msg_id`;
5. accepts `(origin, msg_id, created_ms, now)` through aoIdents'
   `ReplayGuard` (IDN-14), configured with a 1024-id window per sender,
   a 24-hour timestamp tolerance and 64 senders.

Only then is `MeshOutput::Deliver` emitted, with the **opened plaintext**.
The header is unchanged, so its `payload_len` still counts sealed wire
bytes. A tampered seal, a seal for another recipient, a forged sender, a
broken signature, a claimed id the content does not produce or a replayed
or stale timestamp produces no delivery and increments
`Neighbor::rejected_packets` on the sending link. The seen-cache records a
delivery only after acceptance; relays are recorded before forwarding to
keep their loop invariant.

## Relay budgets and neighbour penalties (MSH-10)

No wire field changes: budgets are a local forwarding decision. For every
admitted packet the engine debits two token buckets, one keyed by the claimed
origin and one by the (sending link, claimed origin) pair, bounded per link by
`max_origins_per_neighbor`. Both refill from the caller-supplied `now`
at the ADR-0001 class rates (1 MiB/h Direct down to 32 KiB/h Telemetry) with a
ten-minute full bucket. Classes have separate buckets and never borrow from
each other, so a full Direct allowance cannot mask a Telemetry flood. A packet
that finds either bucket empty is still delivered locally when addressed to
this node, but its relay copies are withheld.

Malformed packets add 3 to the sending link's penalty, packets from a link with
no verified identity add 2, and packets the sending link's own bucket cannot
admit add 1. An exhausted origin is dropped with no link penalty: blaming the
neighbour that carried it would disconnect links used by honest traffic. The
score decays by 1 per minute; at 12 the engine emits `MeshOutput::Release` with
`DisconnectReason::AbuseDetected` once until `LinkDown`. aoNetwork owns any
blacklist and reconnection decision. The simulator's `enforce` switch disables
both buckets only for ablation runs; it is never a production tuning knob.

## Simulation evidence (MSH-27)

No wire format changes. Feature `sim` drives the codec and engine over aoNetwork's
paused `SimWorld` with fixed seeds, signed hellos, mobility and scripted
contacts. It reports delivery ratio, latency, overhead, duplicate ratio, radio
bytes and queue occupancy as CSV; the published seeds, numbers and regeneration
commands are in the README section "Simulator harness and baseline". The
nightly `sim` workflow fails on any directional regression against those
numbers, so protocol or routing changes must state their measured effect. See
[the simulator baseline decision](adr/simulator-baseline.md) for the scenario
and metric choices.

## Local storage metadata

MSH-12 stores encoded packets unchanged. Local copies_left, priority,
first_seen, received_at, consumed age, size and ingress node are not wire
fields. Expiry compares relative age against lifetime, never remote wall time.
See [MessageStore](adr/message-store.md) for quotas and deterministic eviction.
