# aoMesh

**The routing and store-and-forward engine of the aoheyra mesh.** A sans-IO Rust crate that decides what happens to a packet: forward it, hold it, suppress it, deliver it, or drop it, across a phone-to-phone mesh where links come and go.

> **Status: pre-alpha, through MSH-16.** Packet encoding, origin signatures, seen-cache bookkeeping, signed submissions, bounded neighbours, the signed MeshHello introduction with verified neighbour identities, the optional network adapter, baseline Direct forwarding (dedupe, TTL, relay to verified neighbours), authenticated local delivery (seal, origin binding, signature and replay guard), per-origin/per-neighbour relay budgets with neighbour penalties, counter-based Broadcast/Presence suppression with seeded assessment delays, bounded store summaries, the debounced beacon digest, bounded anti-entropy sync, range-based reconciliation on meeting links and binary spray-and-wait for Direct traffic are implemented.

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

**Engine inputs:** `LinkUp`, `LinkDown`, `Data`, `Tick`, `Submit`, `StoreSummary`, `SyncItems`. **Outputs:** `Send`, `Broadcast`, `Release`, `Deliver`, `SetHello`, `SetBeacon`, `SyncNeed`, `SyncItem`, `ReleaseOpportunistic`.

### Engine and adapter (MSH-06)

`MeshEngine::new(rng)` uses `MeshConfig::default()`: 32 neighbour entries, the
MSH-09 replay guard (1024 ids per sender, 24 h tolerance, 64 senders), the
budget fields below, the MSH-11 suppression fields, the MSH-13 summary
fields and the MSH-14/15 sync fields below. `with_config`
accepts explicit bounds; zero neighbours
refuses all new links. Excess links emit `Release`, duplicate link-up events
preserve counters, and link-down removes the entry. These are bookkeeping
limits, not radio topology policy.
Link-up verifies the peer's signed MeshHello, so each entry carries a verified
`NodeId` or none (below).

`Submit` borrows an `Identity`, header and opaque payload. The engine retains
no keys, validates lengths before signing, and emits `Send` to a selected
admitted link or `Broadcast` to all up links. Telemetry uses the Telemetry
channel; other packet classes use Message. Packet and signing failures return
typed `MeshError`s while the caller retains its payload. Incoming Data also
borrows the local `Identity`; the engine keeps no keys. It is parsed without
copying and counted: a fresh Direct packet whose `dst` is that identity's
node id becomes a delivery candidate, any other fresh Direct packet relays
to verified neighbours except the sender with `ttl` decremented, and
everything else (other classes, unverified senders, repeats, content that no
longer matches its `msg_id`) is dropped. A candidate only becomes
`Deliver` after its sealed payload opens against the local identity, the
seal's sender matches `origin`, the origin signature verifies and the replay
guard accepts. Refusals and forged content addresses are counted against the
sending neighbour.

With feature `adapter`, `NetworkAdapter` owns the facade and engine in one
caller task. All nine output variants map to network commands or host events;
`SyncNeed` asks the host to resolve store ids, `SyncItem` hands an incoming
packet to the host store, and `ReleaseOpportunistic` calls aoNetwork's
`Network::release`, which closes only opportunistic links. `SendFailed`
returns the link and original payload through `SendError`.
`poll_event` and its `next_event` future need no runtime dependency and work
in a Tokio-owned task. Each pump takes the local `Identity` by borrow so
MSH-09 can open deliveries; the engine retains no key. The host supplies
separate monotonic network durations and mesh milliseconds, arranges wakeups
by `next_deadline()`, and recreates
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
- Relays verify the origin signature for Broadcast and Presence; Direct packets are verified by the recipient, and by relays only within a CPU budget. Telemetry is not verified by relays. The verification calls shipped in MSH-04; MSH-09 runs the recipient's checks for local delivery. MSH-11 checks the content id of every flooded packet before suppression, and MSH-22/23 own the remaining class pipelines.

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

### Baseline forwarding (MSH-08)

A received Direct packet must re-derive its content-bound `msg_id` before it
touches any state. A forged id is rejected and counted against the link. A
relay copy is recorded once in the seen-cache, then forwarded to every
verified neighbour except the sending link with `ttl` decremented (TTL is the
hop limit: a submission with `ttl` N reaches N hops, and the destination
delivers even on a worn `ttl`) and `hops` incremented, saturating at 255.
Submissions are recorded too, so a node never re-relays its own message.
`Telemetry`, unverified senders and duplicates are counted and dropped.
Broadcast and Presence follow MSH-11's suppression path; MSH-19 and MSH-22
own their remaining pipelines (ADR-0004 forbids acting on an unverified link). The line, ring and seeded random-graph cases in
`tests/forwarding.rs` pin delivery and the absence of loops with sealed
payloads, so the destination's MSH-09 pipeline emits the delivery.

### Authenticated local delivery (MSH-09)

A Direct packet addressed to this node carries a sealed payload. The sender
seals the plaintext to the recipient under the header's content address,
sets `payload_len` to the encoded seal length and signs the packet. The
recipient opens the seal against the borrowed local identity, requires the
seal's authenticated sender to equal `origin`, verifies the origin signature
and content id, then runs the replay guard before emitting `Deliver` with the
opened plaintext. The header's `payload_len` stays the sealed wire length.
Failed checks and forged content addresses increment
`Neighbor::rejected_packets` and never produce a delivery; policy drops do
not. Decision record: [ADR-0005](docs/adr/0005-local-delivery-pipeline.md).

### Relay budgets and penalties (MSH-10)

Every admitted packet debits two token buckets: one keyed by the packet's
claimed origin and one keyed by the (sending link, claimed origin) pair. Both
refill continuously in caller-supplied milliseconds and use the ADR-0001 hourly
rates, so Direct has the largest allowance and Telemetry the smallest. The
per-link map is bounded by `BudgetConfig::max_origins_per_neighbor` (default 64)
and evicts least-recently-used origins. Buckets are per class and
never borrow from each other; a full Direct bucket cannot hide a Telemetry
flood. Local delivery is never suppressed: only the onward relay copies are
withheld when either bucket is empty. The refusal is typed: an exhausted
origin is that origin's fault and drops without blaming the neighbour that
carried it, while an exhausted sending link feeds that link's penalty.
Disconnecting a neighbour merely because an origin ran out of allowance would
also drop honest traffic crossing that link. Origin state is bounded by
`BudgetConfig::max_origins` (default 1024) and evicted least-recently-used
first; neighbour state follows the neighbour table and is removed on
`LinkDown`.

| Setting | Default | Why |
|---|---|---|
| Direct | 1 MiB/h, 10 min burst | About 500 2 KiB messages per hour, with a bounded first burst (ADR-0001) |
| Broadcast | 256 KiB/h, 10 min burst | Quarter of Direct; suppression already duplicates each flood |
| Presence | 64 KiB/h, 10 min burst | A few dozen announcements per hour bounds Sybil spam |
| Telemetry | 32 KiB/h, 10 min burst | Lowest class, shed first under pressure |
| Invalid packet | +3 penalty | Structural garbage is a clear abuse signal |
| Unverified sender | +2 penalty | The link may watch, but cannot act through this engine |
| Over-budget packet | +1 penalty | Only for a saturated sending link; an exhausted origin is dropped without blame |
| Release threshold | 12, decay 1 per 60 s | A sustained offender is disconnected once; short mistakes fade |

Crossing the threshold emits `MeshOutput::Release` with
`DisconnectReason::AbuseDetected`. The release is emitted once per link until
`LinkDown`; aoNetwork owns reconnection and any later blacklist decision.
`BudgetConfig::enforce` is an ablation switch for the simulator, not a
production tuning knob.

The fixed flood case in `tests/sim_budgets.rs` submits 300 oversized messages
from one origin and 300 from honest nodes on a seeded 20-node random graph
(seed `1297304003`) against aoNetwork `492e148c`. With budgets on, the flooder
delivers 102 of 300 messages (0.3400) against 244 of 300 (0.8133) with budgets
off, while honest origins deliver 226 of 300 (0.7533) against 205 of 300
(0.6833) with no budgets. A no-flood control run delivers 223 of 285 honest
messages (0.7825), so the remaining gap is first-transmission radio contention
from the flooder, not a budget applied to honest traffic. The refreshed
four-scenario baseline is unchanged by this feature.

### Broadcast suppression (MSH-11)

Broadcast and Presence do not relay on sight. A fresh content id waits a
seeded assessment window while distinct sending links are counted; if the
degree-scaled copy threshold is reached, the relay is cancelled and the id is
recorded. Otherwise one relay is sent when the timer fires, with `ttl` capped
at the ADR-0001 class value. State is bounded by
`SuppressionConfig::max_entries` (default 1024) and evicted by earliest
deadline. `Direct` and `Telemetry` keep their existing paths and no wire field
changes.

| Setting | Default | Why |
|---|---|---|
| Reference degree / copies | 4 / 3 | 50-node sweep: cancels 45% of transmissions without moving Direct delivery |
| Copy bounds | 1 to 6 | Keeps sparse graphs forwarding and dense graphs from over-relaying |
| Base delay | 60-140 ms, seeded | Long enough for neighbour copies, short enough for a contact |
| Final delay | 20-600 ms, shrinking with degree | Dense groups decide sooner |
| Class TTL | Direct 8, Broadcast 6, Presence 3, Telemetry 3 | ADR-0001 table, clamped on submission too |

The fixed mixed case in `tests/sim_suppression.rs` submits 100 messages on a
seeded 50-node random graph (seed `1297304013`), every tenth one a sealed
Direct canary and the rest Broadcast from one origin. With suppression,
transmissions fall from 5801 to 3316 (42.84%) while the Direct delivery ratio
stays at 0.2000 (2/10) in both runs. Unique Broadcast receptions fall from
2197 to 1456, which is reported as a diagnostic: cancelling relays does
shorten a flood's reach, and that cost is not counted as a delivery-ratio
improvement. MSH-10 admission gates suppression, so a denied packet starts no
timer. The four published MSH-27 baselines are unchanged because they carry no
flooded classes.

### Simulator harness and baseline (MSH-27)

Feature `sim` adds a deterministic host-side harness on aoNetwork's paused
`SimWorld`. It drives real signed hellos, link events and the engine through
the adapter, then reports delivery, latency, overhead, duplicates, radio
bytes and queue occupancy. Scenarios cover a 20-node line, a 50-node random
waypoint network, a 100-node four-community network and a 200-node chain with
scripted shortcut contacts. Seeds, positions, traffic and sealing streams are
fixed, so every row reproduces exactly.

```bash
cargo run --release --features sim --example sim_report
cargo run --release --features sim --example sim_report -- baselines.csv
cargo test --release --all-features --test sim_baseline
```

The first command prints the CSV; the second writes it to a file. The third
enforces the published thresholds and fails on a regression; the nightly
workflow in `.github/workflows/sim.yml` runs both. Bounds are directional:
higher delivery and lower overhead, latency, duplicates, radio bytes and peak
queue occupancy pass. `tests/sim_baseline.rs` records the exact gate values.

CSV columns: `scenario,seed,nodes,submitted,delivered,duplicate_deliveries,
transmissions,receptions,send_failures,radio_bytes,mean_latency_ms,
max_latency_ms,delivery_ratio,overhead,duplicate_ratio,peak_queued_bytes,
links_after_settle`. Ratios are fractions and print with four decimal places.

Published baseline (Rust stable, release profile, fixed seeds):

| Scenario | Nodes | Seed | Delivered / submitted | Delivery ratio | Overhead | Mean / max latency (ms) | Radio bytes | Peak queued bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `line-20` | 20 | 1297303584 | 20 / 20 | 1.0000 | 9.6500 | 730 / 1200 | 102065 | 550 |
| `waypoint-50` | 50 | 1297303632 | 31 / 50 | 0.6200 | 125.7742 | 551 / 1200 | 2080893 | 12375 |
| `community-100` | 100 | 1297303652 | 75 / 80 | 0.9375 | 328.7067 | 676 / 1200 | 13031341 | 33290 |
| `scripted-200` | 200 | 1297303752 | 100 / 100 | 1.0000 | 34.5500 | 561 / 1200 | 1850727 | 6600 |

`send_failures` and duplicate deliveries are zero in every scenario. The
mobile scenarios are deliberately lossy under TTL 8: random-waypoint contacts
leave some destinations farther than eight hops, which is the baseline later
spray-and-wait and sync work must beat. The topology and metric choices are
recorded in [the simulator baseline decision](docs/adr/simulator-baseline.md).

These values were regenerated against aoNetwork `492e148c` (Net 25 flow
control), which changed simulated link formation. Waypoint and community
delivery improved, waypoint overhead fell, and community overhead rose slightly
from 328.5541 to 328.7067 per delivery. The exact settled link counts moved
from 182/424 to 180/412. Radio-byte accounting was also fixed: the harness now
sums per-tick `tx_bytes` deltas per link instead of subtracting two snapshots
of only the currently up links, so bytes sent on links that close during
mobility are no longer lost. That is why the radio-byte figures are higher than
the previous fixture; it is not a routing regression. Repeated debug and
release runs produced identical metrics. No aoMesh routing code changed.

## Targets and evidence

Performance claims are measured in the simulator harness (MSH-27), never asserted:

- Counter-based suppression: 45.20% fewer transmissions than naive flooding on the seeded 50-node graph, Direct delivery ratio unchanged at 0.2000 (see above).
- Spray-and-wait: delivery close to epidemic routing at a fraction of the transmissions under mobility.
- Sync v2: bytes per contact drop measurably against v1 for stores of 1000+ messages.

Metrics: delivery ratio, latency, overhead (transmissions per delivery), duplicate ratio, buffer occupancy. Reports are CSV (see the [MSH-27 baseline](#simulator-harness-and-baseline-msh-27)); nightly CI enforces thresholds and fails on regression.

## Features

| Feature | Meaning |
|---|---|
| *(default)* | The sans-IO core only. No `tokio`, no I/O |
| `adapter` | Runtime-neutral async glue usable by a Tokio-owned task; pumps `NetworkEvent` into the engine and actions out |
| `sim` | Deterministic SimWorld scenarios, CSV metrics and baseline gates; implies `adapter` and never enters the sans-IO core |

## Development

Requires Rust 1.85+ (edition 2024; the MSRV is pinned as `rust-version` in `Cargo.toml` and enforced by CI).

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check
cargo doc --no-deps --all-features

# Simulator scenarios and metrics
cargo run --release --features sim --example sim_report
cargo test --release --all-features --test sim_baseline
```

MSH-16 adds a separate paired report; the four published rows above stay the
relay-only MSH-08 reference:

```bash
cargo run --release --all-features --example spray_report
cargo test --release --all-features --test sim_spray
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

## Store summary and beacon digest (MSH-13)

`sync::StoreSummary` canonicalises the store's live message ids: input order and
duplicates are ignored, the exposed vector holds eight-byte prefixes, and the
four-byte digest hashes every full id plus the entry count. Two stores with the
same live content therefore produce equal digests; adding, removing or replacing
one message changes it with overwhelming probability. The digest is a change
detector, not a set proof: MSH-14 confirms differences with a full summary
exchange.

| Setting | Default | Why |
|---|---|---|
| Short id bytes | 8 | Compact enough for a bounded store, low collision risk |
| Beacon debounce | 200 ms | Coalesces a write burst without delaying a link-up comparison |
| Beacon hint | `[0; 8]` | Opaque to the mesh; the app may replace it |

The host remains the store owner. It submits `MeshInput::StoreSummary` with the
ids returned by `MessageStore::summary(now)`. The engine debounces changes for
`SummaryConfig::debounce_ms` (default 200 ms) and emits one `MeshOutput::SetBeacon`
with the digest and the configured opaque hint. Reverting to the published value
cancels a pending change, and a backwards clock never shortens the window. No
wire format changes: aoNetwork's beacon already carries the four-byte digest.
`tests/sync_summary.rs` proves the equality/change property with two
`MemoryStore` instances and the beacon behaviour through the engine.

## Anti-entropy sync v1 (MSH-14)

When two nodes meet, a link whose MeshHello advertises `CAP_SYNC_V1` starts a
bounded anti-entropy exchange on aoNetwork's Bulk channel. The engine never
opens the host's store: it compares the peer's four-byte beacon digest with its
cached summary, exchanges sorted eight-byte id prefixes, and emits `SyncNeed`
for the missing prefixes. The host resolves each prefix through
`MessageStore::get` and submits the encoded packet with `MeshInput::SyncItems`.
Incoming `SyncItem` events carry complete encoded packets for the host to
insert; the engine verifies bounds, the content address and the storable class,
while final signature verification and insertion policy stay with the store
owner. Telemetry is never synced.

| Setting | Default | Why |
|---|---|---|
| Per-contact byte budget | 256 KiB | Bounds work and airtime for one meeting |
| Per-frame byte budget | 15 KiB | Fits inside aoNetwork's 16 KiB Bulk frame |
| Summary entries | 1024 | Matches the store bound; larger summaries are rejected |
| Contact deadline | 20 s | Long enough for a slow contact, bounded against a stalled peer |

`SyncFrame` uses a five-byte header: magic `0x53`, version `1`, a tag for
Digest/Summary/Item/Done and a two-byte body length. A peer without the sync
capability bit is ignored by the sync path and keeps the MSH-13 beacon path; no
sync frames are sent. Equal digests end the contact without a release, since
the link may still carry ordinary forwarding traffic. Each side sends only the
ids the other lacks and waits for the peer's `Done` before emitting
`ReleaseOpportunistic`, so the link is not closed while packets are still in
flight. The deadline releases a stalled
contact once, and a link drop clears its session so a later encounter restarts
cleanly.

`tests/sync_v1.rs` covers bounded frames, host seams, drop recovery and
both-direction release; `src/hello.rs` covers the capability bit and its
negotiated fallback. `tests/sync_convergence.rs` drives the
real adapter over aoNetwork `SimWorld` with seed `0x5147_2026`: after a 20-second
contact the two stores converge on the same four ids and the opportunistic link
is released.

## Range-based reconciliation (MSH-15)

A link whose MeshHello negotiates `CAP_SYNC_V2` uses Negentropy-style binary
range reconciliation instead of the MSH-14 summary vector. Both sides hash the
full ids in each range of the canonical 128-bit id space. Equal summaries end
the branch; differing summaries split into two child ranges until a leaf is
small enough to exchange as full ids. The engine then computes the same
`SyncNeed` / `SyncItems` transfer as MSH-14, so the host still owns the store
and v1 remains the fallback for peers without the new capability bit.

| Setting | Default | Why |
|---|---|---|
| Range leaf size | 32 ids | 512 bytes of ids per leaf frame, well inside the frame budget |
| Maximum range depth | 128 bits | A fully split range has at most one id |
| Range entries per frame | 8 | Bounds response frames without many tiny sends |

`SyncFrameV2` reuses the sync magic and five-byte header with version `2` and
tags for Root, Ranges, Request, Ids and Ready. Once both sides send Ready, the
contact switches to MSH-14 `Item` and `Done` frames, so the existing per-contact
byte budget, timeout and release rules still apply. `tests/sync_v2.rs` covers
convergence, codec bounds and the v1-only fallback. The simulator report
`cargo run --release --all-features --example sync_v2_report` uses seed
`0x515f_2026` with stores of 1000 and 1001 messages: v2 exchanges 2,018 bytes
against v1's 16,188 bytes, with both stores converging.

## Binary spray-and-wait (MSH-16)

Direct packets now carry a copy ticket in a small additive envelope on the same
Message channel as the packet. The envelope is six bytes: magic `0x54`, version
`1`, tag `1` for Direct, a one-byte remaining-copy count and a two-byte inner
length. The packet header and its signed immutable part are unchanged; relays
may lower the hop-mutable ticket without forging origin content. Both peers must
advertise `CAP_SPRAY_V1` (`1 << 2`); a peer without it receives the ordinary
packet bytes, so this is a negotiated wire addition, not a packet version bump.
Receiving a stray envelope on a link that did not negotiate the bit is an
attributable protocol error.

Each new Direct message starts with 255 tickets. On contact with a non-destination
peer the node hands over half of its remaining tickets and keeps the rest; a
destination always receives one copy and ends the spray. At one ticket a node
waits and only hands that copy to the destination, which is also how a stored
copy reaches a later contact through MSH-14/15 sync. The tracker is bounded to
4096 live ids, and tickets, store metadata and sync frames carry the count
without adding a header field.

| Setting | Default | Why |
|---|---|---|
| Initial copies | 255 | Halving across an eight-hop TTL still leaves a copy for the destination; measured below |
| Maximum tracked ids | 4096 | Bounds memory across overlapping contact windows |
| Envelope header | 6 bytes | Magic, version, tag, count and a bounded inner length |

The paired report keeps topology, mobility, traffic and budgets identical:

| Scenario | Seed | Delivered / submitted | Delivery ratio | Transmissions | Overhead |
|---|---:|---:|---:|---:|---:|
| `spray-relay-line-20` | 1297303584 | 20 / 20 | 1.0000 | 193 | 9.6500 |
| `spray-enabled-line-20` | 1297303584 | 20 / 20 | 1.0000 | 186 | 9.3000 |
| `spray-relay-scripted-200` | 1297303752 | 100 / 100 | 1.0000 | 3455 | 34.5500 |
| `spray-enabled-scripted-200` | 1297303752 | 99 / 100 | 0.9900 | 1786 | 18.0404 |

The scripted-200 case keeps 99 percent delivery while using 48 percent fewer
transmissions. `tests/spray.rs` covers envelope bounds, the binary split, the
destination shortcut, wait-phase delivery, tracker eviction and capability
fallback; `tests/sim_spray.rs` locks the fixed-seed numbers.
