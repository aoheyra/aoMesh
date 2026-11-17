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
registered in aoIdents ADR-0001. Relays verify Broadcast and Presence
always, Direct only while their CPU budget allows, and never Telemetry;
the recipient always verifies a Direct packet addressed to it
(`sign::verify_for_relay`, `sign::verify_origin`).

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

## Versioning

`ver` selects the layout. New versions are negotiated through
`MeshHello.caps` (MSH-07) with fallback; a node never parses bytes of a
version it does not know. Changing this layout is a protocol change: ADR,
version bump and compatibility note (AGENTS section 4).

## Errors

`PacketError` carries one variant per rejection: `Truncated`,
`UnsupportedVersion`, `UnknownClass`, `UnknownFlags`, `NonCanonicalVarint`,
`VarintOverflow`, `PayloadTooLarge`, `PayloadLengthMismatch`,
`TrailingBytes`. Each has a test that triggers it.

Origin verification reports `sign::VerifyError`: `BadSignature` (wrong key,
tampered prefix or foreign domain) and `MsgIdMismatch` (the header claims a
derivation the content does not produce). Each has a test that triggers it.

## Local storage metadata

MSH-12 stores encoded packets unchanged. Local copies_left, priority,
first_seen, received_at, consumed age, size and ingress node are not wire
fields. Expiry compares relative age against lifetime, never remote wall time.
See [MessageStore](adr/message-store.md) for quotas and deterministic eviction.
