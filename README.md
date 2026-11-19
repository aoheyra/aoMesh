# aoMesh

**The routing and store-and-forward engine of the aoheyra mesh.** A sans-IO Rust crate that decides what happens to a packet: forward it, hold it, suppress it, deliver it, or drop it, across a phone-to-phone mesh where links come and go.

> **Status: pre-alpha, through MSH-07.** Packet encoding, origin signatures, seen-cache bookkeeping, signed submissions, bounded neighbours, the signed MeshHello introduction with verified neighbour identities and the optional network adapter are implemented. Forwarding (MSH-08) and verified local delivery (MSH-09) are not implemented.

Cargo package name: `ao_mesh`.

---

## Where this crate sits

```
                aoheyra  (app: Rust core + Kotlin UI)
                   │  depends on all three
        ┌──────────┼───────────┐
        ▼          ▼           ▼
    aoMesh ───▶ aoNetwork    aoIdents
        │                       ▲
        └───────────────────────┘

aoNetwork and aoIdents never depend on each other.
```

aoMesh consumes **aoNetwork** (links and frames) and **aoIdents** (signatures, sealing, replay). It knows packet *classes* and opaque payload bytes; it never sees the app schema (text, location, profile). That is aoheyra's.

## What it does

- Defines the **packet format**: header, hop-mutable fields kept apart from the signed immutable part, `MessageId` derived from immutable content.
- Runs a **sans-IO engine**: `handle(now, input) -> Result<Vec<MeshOutput>, MeshError>`, injected RNG, no `tokio` inside. The same code runs in the simulator, in fuzzers and on the phone.
- **Routes per traffic class** (table below), including spray-and-wait for direct messages and counter-based suppression for floods.
- **Stores and forwards**: `MessageStore` trait with quotas and eviction, store summary and beacon digest, anti-entropy sync when two nodes meet.
- **Controls abuse mesh-wide**: per-origin and per-class relay budgets, neighbour penalty scores.
- Handles **delivery receipts and immunity** so copies are purged after delivery.
- Maintains **presence**, a mesh-wide **NodeDirectory**, reverse-path route hints and public channels.
- Ships a **simulator harness** with mobility models and metrics, so every routing parameter can be swept and every claim measured.

## What it deliberately does not do

| Not here | Lives in |
|---|---|
| Keys, signing primitives, sealing, tag generation, replay guard | `aoIdents` |
| Radio, links, fragmentation, per-link queues and rate limits, degree cap | `aoNetwork` |
| App payload schema, SQLite, UI, FFI | `aoheyra` (supplies the SQLite `MessageStore` and persists the directory cache) |

## Traffic classes (from the routing ADR, MSH-02)

| Class | Strategy | Storage | Notes |
|---|---|---|---|
| **Direct** (1:1) | Spray-and-wait (binary spray, default `L = 8` copies) plus reverse-path hints | Stored; default lifetime ~48 h | Highest relay priority; receipt and immunity purge copies |
| **Broadcast / channels** | Counter-based suppression, random assessment delay, per-class TTL | Short | Main flood-prevention mechanism |
| **Presence** | Trickle-timed gossip, short TTL, latest-wins by `seq` | Not stored long (~10 min) | Interval backs off when nothing changes |
| **Telemetry** (location) | Latest-wins, hop limit ~3, per-origin rate cap | **Never stored**; ~30 s | Coalesced in aoNetwork via `coalesce_key` |

Lifetimes, TTLs, copy counts and budgets are **defaults with documented reasons** and are all configurable. Expiry uses relative age (`received_at` plus age at receipt), so a wrong phone clock can neither extend nor kill messages.

**Metadata trade-off (MVP):** origin and destination are visible to relays so they can rate-limit spam. Sender anonymity is a later trade-off; see the threat model in aoIdents (IDN-19).

## Architecture

```
 aoheyra runtime
       │ Submit, Tick, events        Deliver, Send, Release, ...
       ▼                                   ▲
 ┌─────────────────────────────────────────────────────┐
 │ MeshEngine  (sans-IO: handle(now, input) -> outputs)│
 │  ├─ packet: header · codec · MessageId · signature  │
 │  ├─ seen-cache (forwarding dedupe)                  │
 │  ├─ forwarding: baseline · suppression · spray      │
 │  ├─ budgets: per-origin, per-neighbour, penalties   │
 │  ├─ store: MessageStore trait · quotas · expiry     │
 │  ├─ sync: summary · digest · anti-entropy v1 (v2)   │
 │  ├─ receipts and immunity                           │
 │  └─ presence · NodeDirectory · route hints · channels│
 └─────────────────────────────────────────────────────┘
       ▲  thin async adapter (feature `adapter`)
       ▼
   aoNetwork  (NetworkEvent in, actions out)      aoIdents (sign, open, replay)
```

**Engine inputs:** `LinkUp`, `LinkDown`, `Data`, `Tick`, `Submit`. **Outputs:** `Send`, `Broadcast`, `Release`, `Deliver`, `SetHello`, `SetBeacon`.

### Engine and adapter (MSH-06)

`MeshEngine::new(rng)` uses `MeshConfig::default()` (32 neighbour entries).
`with_config` accepts an explicit bound; zero refuses all new links. Excess
links emit `Release`, duplicate link-up events preserve counters, and link-down
removes the entry. These are bookkeeping limits, not radio topology policy.
Link-up verifies the peer's signed MeshHello, so each entry carries a verified
`NodeId` or none (below).

`Submit` borrows an `Identity`, header and opaque payload. The engine retains
no keys, validates lengths before signing, and emits `Send` to a selected
admitted link or `Broadcast` to all up links. Telemetry uses the Telemetry
channel; other packet classes use Message. Packet and signing failures return
typed `MeshError`s while the caller retains its payload. Incoming Data is
parsed without copying, counted and discarded; structural validity never
produces `Deliver` or implies successful authentication.

With feature `adapter`, `NetworkAdapter` owns the facade and engine in one
caller task. All seven output variants map to commands or host events;
`SendFailed` returns the link and original payload through `SendError`.
`poll_event` and its `next_event` future need no runtime dependency and work
in a Tokio-owned task. The host supplies separate monotonic network durations
and mesh milliseconds, arranges wakeups by `next_deadline()`, and recreates
`next_event` with fresh times after a timer wakeup. Tick is explicit; no mesh
timers are scheduled yet.

```bash
cargo run --features adapter --example mesh_adapter
```

This seeded three-node example checks structural reception through the full
adapter and transport path. It does not demonstrate multihop forwarding,
end-to-end encryption or application delivery. See the [I/O decision](docs/adr/engine-io-and-adapter.md).

### Packet format (MSH-03, MSH-04)

`Header { ver, class, flags, ttl, hops, msg_id(16), origin(16), dst(16 or none), created_ms, lifetime_s, payload_len }`, then a 64-byte Ed25519 origin signature, then the payload.

- Byte layout, class IDs (1 Direct, 2 Broadcast, 3 Presence, 4 Telemetry), canonical varints and the 2048-byte payload cap: [`docs/protocol.md`](docs/protocol.md), decision record ADR-0002.
- `ttl` and `hops` are **hop-mutable** and are *not* covered by the origin signature; everything else is. The signature sits after the hop fields, so verification survives relay hops.
- Header-only parsing allows fast reject without allocating the payload; there is a hard payload cap.
- `msg_id` derives from the immutable header and the payload hash (MSH-04): a content address, so one message has exactly one dedup key for MSH-05's seen-cache.
- Relays verify the origin signature for Broadcast and Presence; Direct packets are verified by the recipient, and by relays only within a CPU budget. Telemetry is not verified by relays.

### Seen-cache (MSH-05)

A bounded dedupe cache for forwarding: `check_and_insert(now, class, msg_id)` answers `Fresh` (forward) or `Duplicate` (drop), keyed by the MSH-04 content address.

- Bounded in **size and time**: at most 4096 recordings (oldest evicted first), each expiring at its class's window from ADR-0001 (Direct 24 h, Broadcast 6 h, Presence 30 min, Telemetry 5 min). A duplicate does not extend the window.
- No input can grow it past the bound: one million insertions peak at 263,560 bytes, asserted against the documented 512 KiB ceiling by `tests/seen_memory.rs`. Decision record ADR-0003.
- Capacity and windows are configurable through `SeenConfig`; capacity 0 records nothing, a zero window never deduplicates.

### MeshHello (MSH-07)

A signed `MeshHello {node_id, card_hash, proto, caps, store_digest, signing_pk, agreement_pk, signature}`:
161 fixed bytes inside aoNetwork's 256-byte `app_hello` limit. The signature
covers every other field under `aoheyra/mesh/v1/hello` (aoIdents ADR-0001),
and verification proves key control before deriving the **verified `NodeId`**
from the two keys, so the claimed id can never be borrowed.

On `LinkUp` the engine decodes, verifies and negotiates (the lower `proto`,
never below 1; the `caps` intersection). A valid introduction records the
`NodeId` in the neighbour table; an invalid, oversize or version-incompatible
hello is dropped - the entry keeps counting traffic but records no identity,
and only a full table releases the link. Byte layout and the negotiation
rule: [`docs/protocol.md`](docs/protocol.md), decision record
[ADR-0004](docs/adr/0004-mesh-hello.md).

## Targets and evidence

Performance claims are measured in the simulator harness (MSH-27), never asserted:

- Counter-based suppression: at least 40% fewer transmissions than naive flooding on 50-node graphs, delivery ratio within 2 points.
- Spray-and-wait: delivery close to epidemic routing at a fraction of the transmissions under mobility.
- Sync v2: bytes per contact drop measurably against v1 for stores of 1000+ messages.

Metrics: delivery ratio, latency, overhead (transmissions per delivery), duplicate ratio, buffer occupancy. Reports are CSV; nightly CI enforces thresholds and fails on regression.

## Features

| Feature | Meaning |
|---|---|
| *(default)* | The sans-IO core only. No `tokio`, no I/O |
| `adapter` | Runtime-neutral async glue usable by a Tokio-owned task; pumps `NetworkEvent` into the engine and actions out |

## Development

Requires Rust 1.85+ (edition 2024; the MSRV is pinned as `rust-version` in `Cargo.toml` and enforced by CI).

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check
cargo doc --no-deps --all-features

# Simulator scenarios and metrics (after MSH-27)
cargo run --release --example sim_report
```

Tests are `cargo test` only: no Miri or callgrind locally. CI runs fmt, clippy, tests on three operating systems, `cargo doc`, cargo-deny, an MSRV build and miri on every pull request.

### Sibling crates

`ao_network` and `ao_idents` are consumed **by git** (master until the `v0.1.0` tags exist, then tags). For local co-development use a `[patch]` override in your own, uncommitted Cargo config; the exact procedure is documented in `docs/local-development.md` (MSH-01) and in aoheyra's APP-01. `ao_network` with feature `sim` is a `dev-dependency` so the whole mesh can be built and tested before the BLE shim works.

## Roadmap

| Milestone | Issues | Outcome |
|---|---|---|
| **M0 Foundations** | MSH-01, 02 | Scaffold, engine skeleton; routing-per-class ADR |
| **M1 Wire and bookkeeping** | MSH-03..05 | Packet format, signature coverage, seen-cache |
| **M2 Neighbours** | MSH-06, 07 | Engine I/O and network adapter, `MeshHello` |
| **M3 Direct and flood control** | MSH-08..11, 27 | Baseline forwarding, local delivery pipeline, relay budgets, broadcast suppression, simulator harness |
| **M4 Store-and-forward** | MSH-12..14, 16..18 | Store, summary and digest, sync v1, spray-and-wait, receipts and immunity, expiry policy |
| **M5 Presence and location** | MSH-19..23 | Presence, `NodeDirectory`, route hints, telemetry class, public channels |
| **M6 Hardening** | MSH-15, 24..26, 28..30 | Sync v2, encounter-history utility, link hints, hop encryption, fuzzing, restart persistence, observability |
| **M7 Beta** | MSH-31 | Protocol docs and `v0.1.0` |

Titles carry the ID: `[MSH-11] Broadcast suppression`.

## Contributing

1. Read the issue's scope and "Done when" line, and the routing ADR (MSH-02).
2. Read the [rules](AGENTS.md).
3. Any routing change that affects delivery or overhead must come with simulator numbers.

Report vulnerabilities privately to the maintainers (contact in `SECURITY.md`), not in a public issue.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT licence](LICENSE-MIT) at your option. Decision: APP-01, applied to all four repos.

## Message storage (MSH-12)

`store::MessageStore` defines put/get, destination lookup, canonical summaries,
expiry and explicit eviction. `store::MemoryStore` implements bounded total,
per-origin and per-class storage with deterministic eviction. Telemetry is not
stored. Callers verify packet authenticity before insertion; this module keeps
opaque wire bytes and local metadata, never keys or application data models.
See [the storage decision](docs/adr/message-store.md) for limits and ordering.
The app's SQLite backend must run `store::conformance::check` against a fresh
backend factory. SQLite itself and engine integration are separate tasks.
