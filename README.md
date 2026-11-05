# aoMesh

**The routing and store-and-forward engine of the aoheyra mesh.** A sans-IO Rust crate that decides what happens to a packet: forward it, hold it, suppress it, deliver it, or drop it, across a phone-to-phone mesh where links come and go.

> **Status: pre-alpha, M0 (Foundations).** **MSH-01** (scaffold, engine skeleton, sibling git dependencies, CI) is implemented; everything below is design from the backlog (`MSH-xx`) and lands with its issue.

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
- Runs a **sans-IO engine**: `handle(now, input) -> outputs`, injected RNG, no `tokio` inside. The same code runs in the simulator, in fuzzers and on the phone.
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
       ▲  thin async adapter (feature `adapter`, tokio)
       ▼
   aoNetwork  (NetworkEvent in, actions out)      aoIdents (sign, open, replay)
```

**Engine inputs:** `LinkUp`, `LinkDown`, `Data`, `Tick`, `Submit`. **Outputs:** `Send`, `Broadcast`, `Release`, `Deliver`, `SetHello`, `SetBeacon`.

### Packet header (MSH-03)

`Header { ver, class, flags, ttl, hops, msg_id(16), origin(16), dst(16 or none), created_ms, lifetime_s, payload_len }`

- `ttl` and `hops` are **hop-mutable** and are *not* covered by the origin signature; everything else is.
- Header-only parsing allows fast reject without allocating the payload; there is a hard payload cap.
- `msg_id` derives from the immutable header and the payload hash.
- Relays verify the origin signature for Broadcast and Presence; Direct packets are verified by the recipient, and by relays only within a CPU budget.

### MeshHello (MSH-07)

A signed `MeshHello {node_id, card_hash, proto, caps, store digest}` fitting aoNetwork's 256-byte `app_hello` limit. It is verified on `LinkUp`, so the engine exposes a **verified `NodeId`** per neighbour. Invalid or oversize hellos are dropped.

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
| `adapter` | Thin tokio glue that pumps `NetworkEvent` into the engine and actions out |

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
2. Read [`AGENTS.md`](AGENTS.md). It applies to humans and AI agents equally.
3. Any routing change that affects delivery or overhead must come with simulator numbers.

Report vulnerabilities privately to the maintainers (contact in `SECURITY.md`), not in a public issue.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT licence](LICENSE-MIT) at your option. Decision: APP-01, applied to all four repos.
