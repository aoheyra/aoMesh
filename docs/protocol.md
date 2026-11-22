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
MSH-09 runs the recipient's check for local delivery, and MSH-11 checks the
content id of every flooded packet before adding it to suppression state.
MSH-19 verifies every Presence announcement at every hop; MSH-22 and MSH-23
own the remaining class-specific paths.

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

## Hop encryption frames (MSH-26)

Capability bit `1 << 5` (`CAP_HOP_V1`) is signed in `MeshHello.caps`. It is
**opt-in**: the default `MeshHello::sign` omits it because only the host can
drive the Noise handshake. A host sets `MeshConfig::hop_enabled` and signs with
`MeshHello::sign_with_hop`; the engine negotiates the bit only when both sides
advertise it. The hello layout and packet header are unchanged, so older peers
simply lack the bit and keep the cleartext path.

Handshake bytes travel in aoNetwork's `Channel::Control` with a one-byte mesh
tag before aoIdents' opaque Noise message:

```text
offset 0  1 byte   kind = 0x01 (Noise_XX_25519_ChaChaPoly_SHA256 v1)
offset 1  ..       Noise message: 32, 96 or 64 bytes for XX v1
```

The tag is a demultiplexer, not authenticated: the Noise state machine rejects
out-of-order, duplicate or payload-bearing messages. Empty bodies, unknown
kinds and messages over 128 bytes are dropped as `HopFrameInvalid`. A new Noise
suite needs a new kind byte, ADR entry and version bump.

On an active link every Data-channel body is the raw
`HopTransport::encrypt_msg` ciphertext of the **whole encoded mesh packet**:

```text
plaintext = Header || signature || opaque payload
wire body = plaintext || 16-byte ChaCha20-Poly1305 tag
```

Data frames carry no aoIdents header. The receiver opens with the host's
session before `Header::decode`, so a passive observer sees neither routing
metadata nor the original packet header. Sealing is per neighbour, so a
Broadcast is emitted as one sealed `Send` per verified link. Control frames are
never sealed because they establish the session.

A link that negotiated the capability but has no installed session emits
`HopFailed` and transmits nothing; a failed open emits `HopFailed` and passes
no plaintext to the engine. There is no automatic cleartext retry. Sync and
receipt frames that would normally start at link-up are deferred until
`HopReady`, preventing pre-session cleartext sends and preserving frame order.

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

Presence announcement work reports `presence::PresenceError`: `BadLength`,
`BadMagic`, `BadVersion`, `BadClass`, `MsgIdMismatch`, `BadBinding`,
`OriginMismatch`, `TooManyKnownCards`, `Signing` and `Packet`. Packet-driven
failures are dropped and attributed to the sending link, not returned as a
`MeshError`; only host-supplied state or local signing reaches the caller.

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

## Broadcast suppression (MSH-11)

No wire field changes: suppression is a local decision for `Broadcast` and
`Presence`. A received copy must first re-derive its content id; a mismatch is
rejected and charged to the sending link. A fresh id is held in a bounded
pending table keyed by that id, with at most
`SuppressionConfig::max_entries` entries (default 1024) evicted by earliest
deadline. The node counts **distinct sending links**, so retransmissions from
one neighbour are only one copy.

A seeded assessment delay shrinks as the verified neighbour degree grows.
Before the deadline the node sends nothing. The effective threshold is the
seeded degree-scaled value, except on a chain relay (at most one other link)
and on every Presence announcement, where it is floored at two distinct links:
one copy does not prove that a sparse path or a capability-gated peer's other
links learned the content. If the effective threshold is reached from different links,
the pending entry is cancelled and the seen-cache records the id: the mesh has
already given this node enough chances to hear the content, and this node adds
no duplicate. If the timer
wins, the node re-encodes the packet with `ttl` capped at the class value,
decrements `ttl` once, increments `hops`, records the id and sends one copy
to every verified neighbour except the links already counted. The configured
threshold is fractional for most degrees; the seeded rounding draw keeps its
expected value exact without making the engine non-deterministic.

`Direct` keeps the MSH-08 path unchanged, and locally submitted packets are
clamped to their ADR-0001 class TTL before signing. Telemetry has its own
latest-wins path below and never enters the suppression table.
`SuppressionConfig::enabled` is a simulator ablation switch only. The pending
table never holds payload bytes borrowed from a neighbour: the relay bytes are
encoded once when the first copy arrives.

## Telemetry latest-wins (MSH-22)

Telemetry reuses class 4 and the `aoheyra/mesh/v1/packet` signature domain; no
header field, class id or capability bit changes. Older nodes already dropped
this class, and a node that understands the frame accepts it without a new
negotiation. The payload begins with a fixed ten-byte prefix:

| Offset | Bytes | Field | Meaning |
|---|---|---|---|
| 0 | 1 | `version` | `1`; another value is an attributable malformed frame |
| 1 | 1 | `kind` | Opaque application stream tag; aoMesh does not interpret it |
| 2..10 | 8 | `seq` | Sender-monotonic big-endian sequence |
| 10.. | remainder | payload | Opaque bytes, unchanged by the mesh |

`MeshInput::SubmitTelemetry` frames and signs this payload and returns
`TelemetrySend` or `TelemetryBroadcast` with a typed `TelemetryAdvisory`. The
advisory's coalescing key is BLAKE3 over
`aoheyra/mesh/v1/telemetry/coalesce || origin(16) || kind(1)`, truncated to
16 bytes; `seq` is excluded so a newer value replaces an older waiting frame.
`NetworkAdapter` maps the advisory to aoNetwork's `SendOpts { coalesce_key,
expires_at }` using `Network::send_opts`. It never queues in the core and never
invents a network API.

Relays first check the content address and frame prefix. A malformed frame or
content mismatch is charged to the sending neighbour as invalid traffic.
Freshness and rate policy run before the relay budget: a sender declaring
zero lifetime, a sequence not newer than the last accepted one, an origin
inside its 10 s cap, or a packet with no relay hop left is a silent drop with
no budget debit, no penalty and no dedupe record. Remote `created_ms` is
ignored; only local monotonic `now` drives expiry, eviction and throttling, so
skewed device clocks cannot buy freshness. The effective window is
`min(sender lifetime, 30 s)`.

Telemetry is ambient state, not a message: it is never offered to `SyncItem`,
the store, or the receipt tracker. Per-`(origin, kind)` freshness and
per-origin rate state are bounded by `TelemetryConfig::max_entries` (default
512); full state evicts by earliest local expiry, then key order. The relay
caps `ttl` at the Telemetry class limit, decrements it and increments `hops`
outside the signed prefix, exactly like other classes, and refuses a packet
that has already spent the configured radius.

## Presence announcements (MSH-19)

No packet class, header field or signature domain changes. A presence
announcement is an ordinary signed `PacketClass::Presence` packet with no
`dst`, TTL clamped by `SuppressionConfig::presence_ttl` (3), and a fixed
150-byte payload:

| Offset | Size | Field | Notes |
|---|---:|---|---|
| 0 | 1 | Magic | `0x56` |
| 1 | 1 | Version | `1` |
| 2 | 8 | `card_hash` | Opaque eight-byte identity-card announcement hash |
| 10 | 4 | `caps` | Capability bits, big endian |
| 14 | 8 | `seq` | Monotonic per origin, big endian |
| 22 | 32 | `signing_pk` | Origin Ed25519 verification key |
| 54 | 32 | `agreement_pk` | Origin X25519 agreement key |
| 86 | 64 | `binding` | aoIdents agreement-key binding signature |

The decoder checks the exact length, magic and version before reading any
field. The two keys and binding are the origin's `PublicIdentity`, already
defined by aoIdents; the mesh carries them so every relay can authenticate the
body without a directory or key store. Verification re-derives `msg_id`, calls
`PublicIdentity::verify_binding`, derives `origin` with `compute_node_id`, and
checks the packet signature under the existing `aoheyra/mesh/v1/packet`
domain. A changed `ttl` or `hops` keeps the signature valid; a changed
immutable field, card hash, capability bit or sequence does not. A body that
fails any check is attributable invalid traffic and increments the sending
link's penalty.

`MeshHello` advertises `CAP_PRESENCE_V1` (`1 << 4`) in its existing `caps`
field. An announcement is emitted and accepted only on links whose negotiated
capabilities include the bit. A capability peer without it never receives
announcement bytes and follows the pre-MSH-19 Presence relay path; the new
body is an additive wire change, not a version bump.

The host supplies the borrowed `Identity` and an eight-byte card hash on each
`MeshInput::Tick`, and declares hashes it can resolve through
`MeshInput::KnownCards`. The engine keeps only a sequence number, a typed
trickle deadline and bounded learned entries; the host receives
`MeshOutput::CardFetch { node_id, card_hash }` once per unknown hash until it
declares that hash. Learned entries are latest-wins: a higher `seq` replaces
an older one, and equal sequences use the full carried body as a
deterministic tie-break. Entries expire after `PresenceConfig::lifetime_s`
using local monotonic time, never a remote clock. The tracker holds at most
`max_entries` learned nodes and `max_known_cards` declared hashes.

A change sets a quick deadline carrying the facts it was scheduled for, so
repeated ticks while it is pending cannot postpone the first announcement.
After emission, quiet refreshes double from `base_interval_ms` to
`steady_interval_ms`. Duplicate announcements are stopped by the MSH-05
seen-cache; fresh ones use MSH-11's suppression with Presence TTL 3 and are
sent only to capability links.

## Store summary and beacon digest (MSH-13)

Before anti-entropy starts, a node compares a four-byte summary digest with
neighbours. `StoreSummary` sorts and deduplicates the live `MessageId`s, exposes
eight-byte prefixes as the compact vector MSH-14 will exchange, and hashes the
full ids plus the count into the beacon digest. Identical live sets give equal
digests; one differing id changes it with overwhelming probability. The digest
is a change detector, not a proof of equality, so MSH-14 still compares full
summaries before transferring packets.

The engine does not own or open the store. The host submits
`MeshInput::StoreSummary` with ids from `MessageStore::summary(now)`. A changed
digest waits `SummaryConfig::debounce_ms` (200 ms by default) before one
`SetBeacon` output is emitted; a change back to the published value cancels the
pending beacon, and a backwards clock cannot shorten the wait. The hint bytes
are opaque to the mesh, and the four-byte digest uses the beacon field already
defined by aoNetwork, so no packet or hello layout changes.

## Anti-entropy sync v1 (MSH-14)

MSH-14 adds engine-to-engine control frames on aoNetwork's `Channel::Bulk`.
They are not mesh packets: they carry no origin signature. The items inside
them are complete encoded mesh packets, checked by the receiving engine for
bounded decode, a matching content address and a storable class before they
are handed to the host store. The store owner remains responsible for final
signature verification and insertion policy.

A `MeshHello` advertises `CAP_SYNC_V1` in its capability bits. The bit uses an
existing hello field, so the wire layout is unchanged. If the negotiated caps
do not include it, the engine sends no sync frames and both nodes continue to
use the MSH-13 beacon digest only. A peer speaking a different sync version is
rejected by the frame decoder and leaves the session to its deadline.

Every frame starts with a five-byte header:

| Offset | Length | Meaning |
|---|---|---|
| 0 | 1 | Magic `0x53` |
| 1 | 1 | Sync version (`1`) |
| 2 | 1 | Tag: `1` Digest, `2` Summary, `3` Item, `4` Done |
| 3..5 | 2 | Body length, big endian |

`Digest` carries the four-byte summary digest. `Summary` carries that digest,
a two-byte entry count and that many sorted eight-byte id prefixes; a count
above 1024 is rejected before any allocation. `Item` carries one complete
encoded mesh packet, bounded by the 15 KiB per-frame limit and the 256 KiB
per-contact budget. `Done` has an empty body.

The exchange is symmetric. Each side compares the peer's summary with its
cached local summary, computes the prefixes the peer lacks, and asks its host
for those packets with `MeshOutput::SyncNeed`. The host answers with
`MeshInput::SyncItems`. Equal digests end the exchange without a release,
because the link may still carry ordinary traffic. A node sends `Done` only
after it has sent everything it owes and received everything it expected; it
emits `MeshOutput::ReleaseOpportunistic` only after the peer's `Done`. The
adapter maps that output to aoNetwork's `Network::release`, which closes
opportunistic links and leaves stable links alone. A 20-second deadline
releases a stalled contact once, and a link drop removes the session so a
later meeting starts from a fresh digest.

## Range-based reconciliation (MSH-15)

`MeshHello` sets `CAP_SYNC_V2` in addition to `CAP_SYNC_V1`. The engine prefers
v2 when both peers advertise it; a peer with only bit 0 gets the MSH-14 summary
exchange, and a peer with neither gets no sync frames. The hello layout does
not change. Version-2 frames reuse magic `0x53` and the five-byte header, with
version `2` and tags `1` Root, `2` Ranges, `3` Request, `4` Ids and `5` Ready.

A range key is a 16-byte prefix plus one bit-count from 0 to 128; trailing bits
are zero so every range has one encoding. A `RangeSummary` adds a four-byte
count and a 16-byte BLAKE3 digest of the sorted full ids in that range. Both
sides send Root on link-up. When summaries differ and the range holds more
than 32 ids, each side sends Request for its two children and answers peer
Requests with Ranges. At 32 ids or fewer, each side sends every full id in the
leaf through Ids. Counts, entry lists and frame bytes are bounded by config and
the decoder rejects non-canonical keys and ids outside their range.

After both sides have exchanged every leaf, each sends Ready. The first peer
to see both Ready flags inserts an ordinary MSH-14 session with the missing
prefixes in each direction, emits `SyncNeed` if it owes any packets, and from
then on uses the version-1 `Item` and `Done` frames. The existing 256 KiB
per-contact budget, 20-second deadline and two-phase release therefore still
apply. A stalled v2 contact is released once; a link drop removes the session
so the next meeting starts from a fresh digest.

## Binary spray-and-wait (MSH-16)

`MeshHello` adds `CAP_SPRAY_V1` (`1 << 2`). The packet header and signature
layout do not change: a copy ticket travels in a six-byte envelope before the
ordinary encoded packet, on the same Message channel. The bytes are magic
`0x54`, version `1`, tag `1` for Direct, one byte of remaining copies (1 to 255)
and a little-endian two-byte inner length. The decoder checks the fixed header
before reading the inner packet, rejects bad versions, tags, tickets, lengths
and trailing bytes, and never allocates before those checks pass. A link that
did not negotiate the capability receives the raw packet from its peer and
rejects an unexpected envelope as attributable invalid traffic.

A local Direct submission or a received spray copy creates a bounded tracker
entry containing the destination, expiry and remaining tickets. For each
non-destination contact the engine hands over `floor(copies_left / 2)` and keeps
the rest; a destination contact receives one ticket and ends the spray. At one
ticket the node waits and only hands that copy to the destination. Sync frames
carry the same count in `SprayItem`, so a stored copy received through
MSH-14/15 can continue spraying on a later contact. The host persists the count
as `StoreMetadata::copies_left`; the engine keeps at most 4096 live tickets.

## Reverse-path route hints (MSH-21)

No packet, hello or sync wire field changes. A hint is local routing advice:
"the freshest observation for destination D arrived from verified neighbour N,
H hops away". It is not signed, is never sent to a peer and never authenticates
a packet. It is derived exclusively from MSH-20 directory observations:
verified MSH-19 announcements feed them, and host facts use
`MeshInput::ObserveNode`. A fact is retained as a hint only while its via-node
names a verified neighbour. The source accepts no peer-supplied timestamp:
expiry uses only local `now`, and a backwards local clock is clamped to the
table's clock floor so neither skew nor replay can extend freshness. The
simulator injects BFS-derived directory facts every five seconds, including in
the hint-off control rows.

Observations from links that are down or lack a verified identity are ignored,
as are zero-hop or over-ceiling hop counts. Hints rank by `(hops ascending,
seq descending, LinkId ascending)`; an equal-rank observation never refreshes
the winner's expiry. The table holds at most `RouteHintConfig::max_entries`
destinations, evicting the earliest expiry then the lowest `NodeId`. `Tick`
expires hints and `LinkDown` removes every hint that link supplied, so a stale
or vanished path cannot survive.

With `RouteHintMode::SubstituteCopy` (the measured default) a fresh hint takes
the place of one ordinary spray recipient: the engine sends one one-ticket
copy along the hint and omits one other recipient, so neither the transmission
count nor the remaining-ticket accounting grows. `AdditiveUnicast` sent one
extra send and was rejected by the paired report. `Off` records nothing and
leaves every forwarding decision unchanged. Config defaults are 1024 entries,
300,000 ms lifetime, an eight-hop ceiling and `SubstituteCopy`; the measured
rows and seeds are in the MSH-21 section of the README.

## Advisory neighbour link hints (MSH-25)

No packet, hello, sync or radio wire field changes. Link hints are host-to-engine
facts and engine-to-host advice, never peer protocol bytes. The host sends
`MeshInput::ObserveLinkHint` with an opaque aoNetwork `PeerKey`, the `NodeId` it
associates with that peer, and a contact-book flag. The engine emits
`MeshOutput::SetLinkHint` or `ClearLinkHint`; the adapter calls aoNetwork's
`set_link_hint` / `clear_link_hint`. Hints affect candidate ordering and the
initiation delay only. aoNetwork still decides whether to dial, admits the
link and enforces the degree cap.

A recognised contact is `Prefer`. An unlinked identity that is the `via`
neighbour of at least `min_diverse_nodes` live directory entries whose
destinations are not already reachable through linked neighbours is also
`Prefer`; a verified link to that identity removes the diversity claim. A
penalty at or above `penalty_threshold`, using the time-decayed value on a
`Tick`, overrides both with `Deprioritize`. Revocation or loss of support emits
`ClearLinkHint`. The table holds at most `max_peers` facts (64 by default) and
evicts lowest preference then greatest `PeerKey`, matching aoNetwork's own
table. Facts that yield no advice never take a slot. The paired report and
seeds are in the MSH-25 section of the README.

## Signed delivery receipts (MSH-17)

`MeshHello` adds `CAP_RECEIPT_V1` (`1 << 3`). The packet header, signature
coverage and class set do not change. A successful authenticated delivery emits
a control envelope on the Message channel with this fixed header:

| Bytes | Field |
|---|---|
| 1 | Magic `0x55` |
| 1 | Version `1` |
| 1 | Tag `1` (Ack) |
| 1 | Flags, currently zero |
| 2 | Little-endian encoded original-header length |
| 2 | Little-endian encoded acknowledgement-packet length |
| 32 | Destination signing public key |
| 32 | Destination agreement public key |
| 64 | Agreement-key binding signature |

The variable part is the original encoded header (including hop-mutable
`ttl`/`hops`), a 32-byte payload hash in the same domain as `msg_id`, and the
complete encoded acknowledgement packet. The acknowledgement is an ordinary
Direct packet addressed to the original origin whose payload is the original
`MessageId`, signed under the registered `aoheyra/mesh/v1/packet` domain. The
decoder reads both lengths before allocating, rejects unknown versions, tags,
non-zero flags, bad lengths and trailing bytes, and parses the original header
before any signature work.

Verification is self-contained: `verify_binding` and `compute_node_id` prove the
attached public identity owns the original destination; re-deriving the id from
the original header and payload hash proves the acknowledged id belongs to that
destination; `verify_origin` checks the acknowledgement under the existing
packet domain. No key directory and no new crypto domain are required. A stray
receipt on a link without the capability, or one that fails verification, is
attributable invalid traffic and feeds the neighbour penalty.

An accepted receipt produces `MeshOutput::Purge { id }` for the host store and
`MeshOutput::Delivered { id, origin, by }` at the origin. It also inserts a
bounded immunity entry (512 ids, 300 seconds, 16 frames per contact burst).
Immune ids are never relayed, re-stored or served from sync. This is distinct
from aoIdents' recipient-side replay guard and from the engine's forwarding
dedupe cache.

## NodeDirectory (MSH-20)

There is no new wire format. MSH-19's presence announcements will be verified
elsewhere and handed to the engine as a typed `NodeObservation`: node id,
card hash, caps, per-origin `seq`, estimated hop distance, via-node,
observation time and opaque bounded location bytes. The directory does not
fetch cards or interpret location. It is an ephemeral local view, not a
persisted store, and it emits no packets.

Each entry keeps the last observation time, local receipt time, expiry
instant, hop distance, via-node, caps, `seq`, card hash and optional location.
The default bounds are 256 entries, 30 minutes of relative freshness, 64
opaque location bytes and 64 pending UI events (ADR-0001). A full directory
evicts the least-recently-seen entry; expiry starts at local receipt time, and
a high-water-mark clock makes a backwards `now` inert. A peer-supplied
observation time is clamped to that clock for ordering only and cannot change
the expiry instant.

An observation with a lower `seq` than the stored entry is ignored. A repeat
at the same or a newer `seq` refreshes local freshness and LRU position, but
emits an `Updated` event only when a visible field changes. Queries by id,
hop-distance range and recency are deterministic, bounded and read-only.
Changes reach the host as `MeshOutput::DirectoryChanged` /
`AdapterEvent::DirectoryChanged` with at most one coalesced event per node;
the UI queries the directory for details instead of receiving payloads.

## Public channels (MSH-23)

A public channel is an envelope inside the opaque payload of a normal signed
`Broadcast` packet. The packet header, signature coverage, class set and
`msg_id` derivation are unchanged, and legacy peers can relay the bytes without
understanding them.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | Magic `0xC4` |
| 1 | 1 | Version `1` |
| 2 | 16 | Channel id |
| 18 | .. | Opaque application bytes |

The 18-byte header is parsed before any application bytes are read. The total
envelope must fit the existing 2048-byte packet payload cap. Magic `0xC4` is
reserved: a Broadcast payload that starts with it but cannot decode as a v1
envelope is attributable invalid traffic and feeds the neighbour penalty.
Payloads with any other first byte remain ordinary Broadcast data.

The channel id is derived locally from a bounded name:

```
id = BLAKE3("aoheyra/mesh/v1/channel-id" || len(name) || 0x01 || name)[..16]
```

The one-byte length and form tag avoid ambiguity between names and other
domain-separated hashes. The name is never encoded on the wire. A 128-bit digest
can collide in principle, so the local registry binds each id to the name that
claimed it and returns `ChannelError::IdCollision` if a different name claims
the same id. This is a local host-state check, not a wire field.

For the existing MSH-10 bucket table, the synthetic budget key is:

```
key = BLAKE3("aoheyra/mesh/v1/channel-budget" || 16 || id)[..16]
```

It is a bucket index, never a node identity. The extra domain prevents a real
`NodeId` and a channel id from being interchangeable. A submission or relay
debited for the Broadcast class pays both the claimed origin and this channel
key, in addition to the normal per-link bucket on receive. This reuses the same
bounded table and class rates; it is not a second limiter.

Verification is unchanged: the origin signature covers the immutable header,
and `msg_id` binds the envelope bytes, under `aoheyra/mesh/v1/packet` and
`aoheyra/mesh/v1/msg-id` respectively. A subscriber verifies a direct copy with
the `signing_pk` proved by the sending link's signed `MeshHello`, then runs the
recipient replay guard before `MeshOutput::ChannelDeliver` is emitted with the
opaque bytes after byte 18. A relayed copy is forwarded but not delivered
locally: the directory's typed observations do not carry a signing key proved
under the packet domain, so no signature check is relaxed. No new hello
capability bit is required because old peers already treat the payload as
opaque Broadcast bytes.
## Restart snapshot bytes (MSH-29)

MSH-29 defines a local host-owned snapshot, not a radio or peer protocol wire
format. `MeshEngine::snapshot()` writes magic `AMSH`, a one-byte version
(`SNAPSHOT_VERSION = 1`), four little-endian section counts, then
BTreeMap-ordered sections for seen entries, seen eviction order, receipt
immunity and spray tickets. Every integer is little-endian; receipt wires are
stored verbatim and revalidated with the frame decoder on restore.

The host stores the bytes, rebuilds the engine with the same config and RNG
seed, calls `restore`, and re-announces live links with `MeshInput::LinkUp`.
Link capabilities, config, clock and stored packets are deliberately not in the
snapshot. `MAX_SNAPSHOT_LEN` is 4 MiB; bad magic, wrong version, oversized or
truncated input, trailing bytes, count/bound mismatches, duplicate entries and
invalid receipt wires produce a typed `SnapshotError` before any state changes.
No packet header or sync frame changes, so this needs no hello capability bit.

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
`MessageStore::get` returns an owned `StoredMessage`; the host may build it from
its own row without lending internal storage. This is a host API change only and
does not alter packet or sync bytes.
See [MessageStore](adr/message-store.md) for quotas and deterministic eviction.

## Lifetime ceilings and relative age

MSH-18 computes effective lifetime as the smaller of the sender's lifetime_s
and the configured class ceiling. Local age at receipt and elapsed monotonic
time decide expiry; created_ms is never compared with a local clock. Store
policy does not modify encoded bytes or add a wire age field. Sync callers
must carry consumed age separately and account for known transfer delay.
See [lifetime policy](adr/lifetime-expiry.md).

## Resource bounds and typed rejections (MSH-28)

No wire field changes. Every decoder reads a fixed header or declared length
before allocating, and every host-supplied slice is bounded before it can grow
engine state:

| Input | Bound | Rejection before work |
|---|---:|---|
| Packet header | 10-byte canonical varints, `payload_len <= 2048` | `PacketError` while parsing the header; no payload is read |
| Store summary ids | 1024 entries | `StoreSummary::from_ids` reads only the cap; duplicates and order do not matter |
| Sync frame body | 8198 bytes (`6 + 1024 * 8`) | `SyncError::FrameTooLarge(usize)` / `SyncV2Error::FrameTooLarge(usize)` before a slice is copied |
| Sync summary count | 1024 entries | `TooManyEntries` before constructing the id vector; body length must match the count exactly |
| Sync offers per input | 1024 | `SyncTracker::on_offers` iterates only the cap |

v1 summaries keep their historical `TooManyEntries` rejection even when the
declared length exceeds the general body cap, so earlier behaviour and tests
are preserved. Every other v1 tag and every v2 tag rejects an oversized body
before copying it into an `Item`, `SprayItem`, range list or id list. The public
`SyncFrame::decode` and `SyncFrameV2::decode` return typed `SyncError` and
`SyncV2Error` values, both implementing `Display` and `std::error::Error`.

A delivery-path `debug_assert_eq!` that hostile input could reach in debug
builds was replaced by a checked outcome; a rejection is still recorded, but a
malformed packet cannot panic the process. `tests/resource_bounds.rs` pins
allocation and CPU-proxy ceilings for decoders, summary streams, hostile engine
Data streams and store quotas. The `fuzz/` crate adds `libFuzzer` targets for
packet decoding, engine input streams and sync frames; nightly CI runs each for
one hour with a 16 KiB maximum input, a 2048 MiB RSS limit and a 10-second
per-input timeout. No one-hour campaign is part of local verification.
## Diagnostics snapshot (MSH-30)

`MeshSnapshot` is host-local plain data, not a wire message. Its `version`
field selects the field layout; version 1 carries saturating `u64` counters for
duplicate forwarding verdicts, cancelled flood relays, encoded sync bytes sent
and received, and positive neighbour penalty applications. It also carries
`u32` gauges for live store ids, current penalty totals/maxima and counts,
seen-cache records and pending suppression windows. Store occupancy is the
count from the latest `MeshInput::StoreSummary`: the engine owns no store and
never invents a byte count.

The counters live in the module that makes the decision, so a snapshot cannot
disagree with routing state. Malformed or unverified frames are penalties, not
sync bytes; zero-amount decay probes are not penalty events. All values are
deterministic for a fixed input stream and hostile traffic can only saturate a
counter, never grow a map. No field contains packet content, message ids, keys,
identities or personal data. `MeshEngine::observability_snapshot` and
`NetworkAdapter::snapshot` expose the same value without I/O or allocation, so
aoheyra can map it directly into its APP-15 diagnostics bundle. Adding or
changing a field is a snapshot schema change and bumps `MESH_SNAPSHOT_VERSION`;
it does not change packet, sync or beacon bytes.
