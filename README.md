# aoMesh

**The routing and store-and-forward engine of the aoheyra mesh.** A sans-IO Rust crate that decides what happens to a packet: forward it, hold it, suppress it, deliver it, or drop it, across a phone-to-phone mesh where links come and go.

> **Status: pre-alpha, through MSH-30.** Packet encoding, origin signatures, seen-cache bookkeeping, signed submissions, bounded neighbours, the signed MeshHello introduction with verified neighbour identities, the optional network adapter, baseline Direct forwarding (dedupe, TTL, relay to verified neighbours), authenticated local delivery (seal, origin binding, signature and replay guard), per-origin/per-neighbour relay budgets with neighbour penalties, counter-based Broadcast/Presence suppression with seeded assessment delays, bounded store summaries, the debounced beacon digest, bounded anti-entropy sync, range-based reconciliation on meeting links, binary spray-and-wait for Direct traffic, signed delivery receipts with bounded store purging, relative-age lifetime ceilings, bounded presence announcements with trickle timing, a bounded ephemeral NodeDirectory with coalesced UI events, bounded reverse-path route hints derived from directory observations, bounded advisory neighbour link hints for aoNetwork, bounded latest-wins telemetry with typed advisory coalescing, local public-channel subscriptions over signed Broadcast envelopes, resource-bounded decoders with fuzz targets in [aoheyra-fuzz](https://github.com/aoheyra/aoheyra-fuzz), versioned restart snapshots for seen-cache, immunity and spray state, and a versioned content-free diagnostics snapshot are implemented.

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
- Maintains bounded **presence** announcements and a mesh-wide **NodeDirectory** from typed observations, with LRU eviction, relative-time expiry and coalesced UI changes; derives bounded **reverse-path route hints** from those facts.
- Emits bounded **advisory link hints** from contact, diversity and penalty facts. aoNetwork alone forms links and enforces the degree cap.
- Publishes **Telemetry** as latest-wins ambient state with NET-21 coalescing, and carries **public channels** as bounded envelopes inside signed Broadcast packets with local-only subscriptions.
- Exposes **bounded diagnostics counters** as a versioned, content-free snapshot for the host.
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
| **Direct** (1:1) | Spray-and-wait (binary spray, default `L = 255` copies) plus reverse-path hints | Stored; default lifetime ~48 h | Highest relay priority; signed receipt and immunity purge copies |
| **Broadcast / channels** | Counter-based suppression, random assessment delay, per-class TTL | Short | Main flood-prevention mechanism |
| **Presence** | Trickle-timed gossip of signed 150-byte announcements, short TTL, latest-wins by `seq` | Not stored long (~30 min) | Cap-gated; interval backs off when nothing changes |
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
 │  ├─ observability: bounded counters · snapshot      │
 │  └─ presence · NodeDirectory · route hints · channels│
 └─────────────────────────────────────────────────────┘
       ▲  thin async adapter (feature `adapter`)
       ▼
   aoNetwork  (NetworkEvent in, actions out)      aoIdents (sign, open, replay)
```

**Engine inputs:** `LinkUp`, `LinkDown`, `Data`, `Tick`, `Submit`, `SubmitTelemetry`, `KnownCards`, `ObserveNode`, `StoreSummary`, `SyncItems`, `ChannelSubscribe`, `ChannelUnsubscribe`. **Outputs:** `Send`, `Broadcast`, `TelemetrySend`, `TelemetryBroadcast`, `Release`, `Deliver`, `ChannelDeliver`, `SetHello`, `SetBeacon`, `SyncNeed`, `SyncItem`, `ReleaseOpportunistic`, `Purge`, `Delivered`, `CardFetch`, `DirectoryChanged`.

### Engine and adapter (MSH-06)

`MeshEngine::new(rng)` uses `MeshConfig::default()`: 32 neighbour entries,
4096 MSH-05 seen-cache recordings, the MSH-09 replay guard (1024 ids per
sender, 24 h tolerance, 64 senders), the budget fields below, the MSH-11
suppression fields, the MSH-13 summary fields, the MSH-14/15 sync fields and
the MSH-23 channel bounds below. `with_config` accepts explicit bounds; zero neighbours
refuses all new links. Excess links emit `Release`, duplicate link-up events
preserve counters, and link-down removes the entry. These are bookkeeping
limits, not radio topology policy.
Link-up verifies the peer's signed MeshHello, so each entry carries a verified
`NodeId` or none (below).

`Submit` borrows an `Identity`, header and opaque payload. The engine retains
no keys, validates lengths before signing, and emits `Send` to a selected
admitted link or `Broadcast` to all up links. Telemetry uses the Telemetry
channel; other packet classes use Message. A Broadcast payload carrying the
reserved channel magic is validated as a channel envelope and charged to both
the origin's Broadcast bucket and the channel's own bucket before signing.
`ChannelSubscribe` and `ChannelUnsubscribe` change only that node's bounded
local registry; relays never send either input. Packet, channel and signing
failures return typed `MeshError`s while the caller retains its payload.
Incoming Data also
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
caller task. Every output variant maps to a network command or host event;
`ChannelDeliver` reports a signed channel message to a local subscriber,
`SyncNeed` asks the host to resolve store ids, `SyncItem` hands an incoming
packet to the host store, `ReleaseOpportunistic` calls aoNetwork's
`Network::release`, which closes only opportunistic links, and `CardFetch`
asks the host to resolve an unknown identity-card hash. `SendFailed`
returns the link and original payload through `SendError`.
`poll_event` and its `next_event` future need no runtime dependency and work
in a Tokio-owned task. Each pump takes the local `Identity` by borrow so
MSH-09 can open deliveries; the engine retains no key. The host supplies
separate monotonic network durations and mesh milliseconds, arranges wakeups
by `next_deadline()`, and recreates
`next_event` with fresh times after a timer wakeup. `MeshInput::Tick` also
borrows the identity and an eight-byte card hash so MSH-19 can sign and emit a
due announcement; its state is only a sequence number and a deadline. Tick is
explicit; no mesh timers are scheduled yet.

`MeshEngine::observability_snapshot()` and `NetworkAdapter::snapshot()` return the same
versioned, content-free diagnostics view (MSH-30). The adapter adds no I/O,
clock read or second counter; see [Observability](#observability-msh-30).

```bash
cargo run --features adapter --example mesh_adapter
```

This seeded three-node example checks structural reception through the full
adapter and transport path. It does not demonstrate multihop forwarding,
end-to-end encryption or application delivery. See the [I/O decision](docs/adr/engine-io-and-adapter.md).

### Telemetry (MSH-22)

`SubmitTelemetry` frames an opaque payload with a one-byte application-owned
`kind` and a sender-monotonic `u64` sequence, signs it under the existing
Telemetry class, and emits `TelemetrySend` or `TelemetryBroadcast`. The mesh
never reads the payload as a location or any other app schema. The coalescing
key is BLAKE3 over a dedicated domain, the origin id and the kind byte; the
sequence is deliberately excluded so a newer update replaces an older one
waiting in aoNetwork's NET-21 queue. `NetworkAdapter` passes that key and a
local-deadline-derived `SendOpts.expires_at` to `Network::send_opts`; it does
not build a second radio queue.

Relays decode the frame after the header and content-address checks, then
apply freshness and throttling **before** relaying or spending a per-origin
budget token. Stale, expired, rate-limited and hop-limited updates are silent
policy drops; only malformed frames or a bad content address count against the
sender. Expiry and the one-per-origin/10 s cap use only the caller's monotonic
`now`, so a skewed `created_ms` cannot change them. Telemetry is never handed
to `SyncItem`, the store, or the receipt tracker. Engine state is bounded by
`TelemetryConfig::max_entries`, evicting by earliest local expiry then key.

The fixed-seed report is reproducible with:

```bash
cargo run --release --features sim --example telemetry_report
```

The regression gate in `tests/sim_telemetry.rs` locks both seeds and rows.

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
- MSH-29 snapshots preserve both the entry map and the eviction order, so an eviction after restart happens at the same point as without a restart.

### Restart persistence (MSH-29)

The host owns the bytes: `MeshEngine` implements `Snapshot`, whose `snapshot()`
returns `Result<Vec<u8>, SnapshotError>` and whose `restore(&[u8])` is atomic.
The format is local host state, not a radio wire format: magic `AMSH`, version
byte, four little-endian counts, then BTreeMap-ordered seen entries, seen order,
receipt-immunity entries and spray tickets. All integers are little-endian.
`SNAPSHOT_VERSION` is 1 and `MAX_SNAPSHOT_LEN` is 4 MiB, above the roughly
1.85 MiB worst case of the default bounds.

Malformed, truncated, trailing, oversized or version-mismatched bytes are
rejected with a typed `SnapshotError` before any engine state is changed.
Restore checks counts against the receiving engine's config bounds, revalidates
immunity receipt wires and rejects duplicate ids or links. Store content, RNG
seed, config, wall clock and live link capabilities stay host-owned: the host
rebuilds the engine with the same seed and config, calls `restore`, and
re-announces links with `MeshInput::LinkUp`.

`tests/restart.rs` covers no re-relay after restart, immunity and copy-counter
survival, store isolation and atomic rejection. `tests/sim_restart.rs` locks the
fixed-seed paired report from `examples/restart_report`: with seed
`1_297_303_584` on line-20, the lost-state row re-relays 14 post-restart sends
(723 transmissions) while the restored row re-relays none (566 transmissions);
both deliver 20/20 and snapshot 5,374 bytes.

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
Broadcast and Presence follow MSH-11's suppression path; MSH-19 adds signed
announcements over the existing Presence class and MSH-22 owns telemetry
(ADR-0004 forbids acting on an unverified link). The line, ring and seeded random-graph cases in
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
at the ADR-0001 class value. A chain relay with at most one other link keeps a
two-link floor, so one copy cannot extinguish a flood on a degree-one path;
dense Broadcast nodes use the calibrated degree-scaled threshold again.
Presence keeps the two-link floor at every degree because a signed
announcement on one capability-gated link does not prove the peer's other
links learned it. State is bounded by `SuppressionConfig::max_entries`
(default 1024) and evicted by earliest deadline. `Direct` and `Telemetry`
keep their existing paths and no wire field changes.

| Setting | Default | Why |
|---|---|---|
| Reference degree / copies | 4 / 3 | 50-node sweep (seed `1297304013`): 43.51% fewer transmissions, Direct ratio unchanged |
| Copy bounds | 1 to 6 configured; 2 on chains and Presence | Keeps degree-one paths forwarding; dense Broadcast floods keep the calibrated threshold |
| Base delay | 60-140 ms, seeded | Long enough for neighbour copies, short enough for a contact |
| Final delay | 20-600 ms, shrinking with degree | Dense groups decide sooner |
| Class TTL | Direct 8, Broadcast 6, Presence 3, Telemetry 3 | ADR-0001 table, clamped on submission too |
| Telemetry freshness | 30 s | Long enough for a moving contact, short enough that stale ambient state is dropped |
| Telemetry rate cap | One accepted update per origin per 10 s | A chatty origin cannot fill a slow link; measured with seed `1297304029` |
| Telemetry state bound | 512 `(origin, kind)` entries | Bounded relay memory; earliest expiry, then key order, is evicted |

The fixed mixed case in `tests/sim_suppression.rs` submits 100 messages on a
seeded 50-node random graph (seed `1297304013`), every tenth one a sealed
Direct canary and the rest Broadcast from one origin. With suppression,
transmissions fall from 5801 to 3277 (43.51%) while the Direct delivery ratio
stays at 0.2000 (2/10) in both runs. Unique Broadcast receptions fall from
2197 to 1479, which is reported as a diagnostic: cancelling relays does
shorten a flood's reach, and that cost is not counted as a delivery-ratio
improvement. MSH-10 admission gates suppression, so a denied packet starts no
timer. The four published MSH-27 baselines are unchanged because they carry no
flooded classes. The two-copy floor on chain relays and Presence is covered by
unit and pipeline regressions; CI rechecks the suppression scenario without
lowering its thresholds.

### Presence announcements (MSH-19)

Presence uses the existing signed `PacketClass::Presence` packet; no new class,
header field, crypto domain or key storage is added. The opaque payload is a
fixed 150-byte announcement:

| Offset | Size | Field | Notes |
|---|---:|---|---|
| 0 | 1 | magic | `0x56` |
| 1 | 1 | version | `1` |
| 2 | 8 | `card_hash` | Opaque aoIdents announcement hash |
| 10 | 4 | `caps` | Big endian capability bits |
| 14 | 8 | `seq` | Big endian, monotonic per origin |
| 22 | 32 | `signing_pk` | Origin Ed25519 key |
| 54 | 32 | `agreement_pk` | Origin X25519 key |
| 86 | 64 | `binding` | aoIdents agreement-key binding signature |

The two keys and their binding are the origin's existing `PublicIdentity`.
Every relay derives `origin` from those keys, verifies the binding and the
packet signature, and rejects a forged origin at every hop. The keys are
carried in the opaque payload only; the engine retains no key and never
interprets the card hash. Changing `card_hash` or `caps` raises `seq`, and a
higher sequence replaces an older entry; ties use the full carried facts as a
deterministic tie-break.

`MeshHello` advertises `CAP_PRESENCE_V1` (`1 << 4`). Announcements are sent and
accepted only on links that negotiated the bit; a legacy peer keeps the
pre-MSH-19 Presence relay path and learns no entries from announcement bodies.
The host borrows its `Identity` and card hash on each `MeshInput::Tick`,
declares known hashes through `MeshInput::KnownCards`, and receives
`MeshOutput::CardFetch { node_id, card_hash }` once per unknown hash until it
answers. The adapter exposes the last one as `AdapterEvent::CardFetch`;
`poll_event` and `next_event` keep their signatures.

| Setting | Default | Why |
|---|---|---|
| Enabled | `true` | Cap gating still restricts which links see announcements |
| Maximum learned nodes | 1024 | Bounds the entry map independently of the directory |
| Maximum known cards | 1024 | Bounds host-supplied hashes per input |
| Quick delay | 1000 ms | Fast first announcement after a change or capable link appears |
| Base quiet interval | 60 s | Doubles after each quiet refresh |
| Steady interval | 900 s | Fits the 30 min entry lifetime and 64 KiB/h class budget |
| Entry lifetime | 1800 s | ADR-0001's Presence lifetime, using relative local time |

Trickle state is one typed deadline with the facts it was scheduled for, so
ticks while a quick deadline is pending cannot push the first announcement
forever. Duplicate cards are suppressed by the seen-cache and fresh ones are
relayed through MSH-11 with Presence TTL 3, only to capability peers.

The fixed 50-node case is a static diameter-three circulant (steps 1, 8 and
12, seed `1297304021`) with no application traffic. Its one-second quick delay
and 60-second steady interval make convergence and overhead visible inside a
two-minute run. All card hashes are declared up front, so any `CardFetch`
would be a regression.

```bash
cargo run --release --features sim --example presence_report
cargo test --release --all-features --test sim_presence
```

| Scenario | Seed | Converged | Convergence | Fewest learned | Card fetches | Steady sends / bytes (last 60 s) |
|---|---:|---|---:|---:|---:|---:|
| `presence-smallworld-50` | 1297304021 | true | 50 ms | 49/49 | 0 | 6036 / 1,557,288 |

The average wire size is 258 bytes, so one source's 60-second refresh is
15,480 bytes per hour, well under ADR-0001's 64 KiB/h Presence budget. Relays
are separately capped by the MSH-10 buckets. `tests/sim_presence.rs` locks the
exact CSV header and row as well as the directional bounds.

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
links_after_settle,presence_converged,convergence_ms,learned_nodes_min,
card_fetches,announcement_sends,announcement_bytes,steady_announcement_sends,
steady_announcement_bytes`. Ratios are fractions and print with four decimal
places. The last eight columns are MSH-19 diagnostics; baseline rows with
presence disabled report `false`, zero and zero learned nodes.

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

- Counter-based suppression: 43.51% fewer transmissions than naive flooding on the seeded 50-node graph, Direct delivery ratio unchanged at 0.2000 (see above).
- Presence: all 49 peers learned within 50 ms on the seeded 50-node circulant, with a 15,480 B/h per-source steady refresh against a 64 KiB/h budget (see above).
- Spray-and-wait: delivery close to epidemic routing at a fraction of the transmissions under mobility.
- Reverse-path hints: fresh-path mean latency drops from 356 ms to 337 ms on the seeded random-20 case with transmissions unchanged at 230; the additive alternative used 231 (see above).
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

# MSH-19 presence convergence and announcement overhead
cargo run --release --features sim --example presence_report
cargo test --release --all-features --test sim_presence

# Fuzzing is centralised in aoheyra-fuzz; see its README for the target list and commands
# https://github.com/aoheyra/aoheyra-fuzz
```

MSH-16 adds a separate paired report; the four published rows above stay the
relay-only MSH-08 reference:

```bash
cargo run --release --all-features --example spray_report
cargo test --release --all-features --test sim_spray
```

MSH-21 adds another paired report; the published rows keep `RouteHintMode::Off`:

```bash
cargo run --release --features sim --example routehint_report
cargo test --release --all-features --test sim_routehint
```

MSH-25 adds a paired time-to-link report:

```bash
cargo run --release --features sim --example linkhint_report
cargo test --release --all-features --test sim_linkhint
```

Tests are `cargo test` only: no Miri, callgrind or fuzz campaigns locally.
CI runs fmt, clippy, tests on three operating systems, `cargo doc`,
cargo-deny, an MSRV build and miri on every pull request. The weekly 90-minute
fuzz campaign runs in [aoheyra-fuzz](https://github.com/aoheyra/aoheyra-fuzz).

### Sibling crates

`ao_network` and `ao_idents` are consumed **as untagged git sources on their default branches**. There are no release tags yet; the first release tags start at `v0.1.0` and all crates will move to them together when they are cut. Cargo treats a tagged source as a different identity from an untagged one, so a downstream crate that depends on these siblings directly must use the same untagged git URLs as aoMesh. Otherwise `Identity`, `LinkId` and `NodeId` become duplicate Rust types across the seam. For local co-development use a `[patch]` override in your own, uncommitted Cargo config; the exact procedure is documented in `docs/local-development.md` (MSH-01) and in aoheyra's APP-01. `ao_network` with feature `sim` is a `dev-dependency` so the whole mesh can be built and tested before the BLE shim works.

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
expiry and explicit eviction. `get` returns an owned `StoredMessage`, so a
disk-backed store can decode a row without keeping a second authoritative
in-memory copy; the value stays valid after later store mutations.
`store::MemoryStore` implements bounded total, per-origin and per-class storage
with deterministic eviction. Telemetry is not stored. Callers verify packet
authenticity before insertion; this module keeps opaque wire bytes and local
metadata, never keys or application data models.
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
`MessageStore::get`, which returns an owned `StoredMessage`, and submits the
encoded packet with `MeshInput::SyncItems`.
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

## Reverse-path route hints (MSH-21)

Direct traffic can use a bounded, local table of reverse-path hints derived
from MSH-20 directory observations: "destination D was last seen through
verified neighbour N, H hops away". Verified MSH-19 presence announcements feed
the directory automatically; host-supplied facts use `MeshInput::ObserveNode`.
A hint is never signed, never encoded on the wire and never used to authenticate
a packet. The hint source accepts no peer time: only local `now` sets expiry,
and a backwards local clock is clamped to the table's clock floor so clock skew
cannot keep a hint fresh. A fact whose via-node is not currently a verified
neighbour cannot steer traffic.

Hints rank by lowest hops, then highest `seq`, then lowest `LinkId`; an exact
tie never refreshes the winner. `Tick` expires entries and `LinkDown` removes
every hint supplied by that link. In the default `SubstituteCopy` mode a fresh
hint replaces one ordinary spray recipient with a one-ticket copy along the
hint, so the transmission count and `copies_left` accounting stay unchanged;
a node holding its last ticket waits and hands that copy to the destination.
`Off` records nothing and changes no decision. `AdditiveUnicast` was measured
as a rejected option because it lowers latency only by adding a transmission.

| Setting | Default | Why |
|---|---|---|
| Mode | `SubstituteCopy` | Lower fresh-path latency at unchanged transmissions per delivery |
| Maximum entries | 1024 | One per destination, bounded to the documented directory scale |
| Lifetime | 300,000 ms | Shorter than the 10-15 min presence refresh, so stale paths age out |
| Fresh hop ceiling | 8 | Matches Direct's TTL; longer paths are not trusted |

The paired report keeps topology, mobility, traffic, budgets, spray and
receipts identical and changes only the hint mode. The last three columns are
the fresh-path diagnostic: every row receives the same seeded observations,
so the `Off` row is the honest latency baseline.

| Scenario | Seed | Delivered / submitted | Transmissions | Mean latency (ms) | Fresh-path deliveries | Fresh-path latency (ms) | Overhead |
|---|---:|---:|---:|---:|---:|---:|---:|
| `hint-spray-line-20` | 1297303584 | 20 / 20 | 186 | 727 | 20 / 20 | 727 | 9.3000 |
| `hint-additive-line-20` | 1297303584 | 20 / 20 | 186 | 727 | 20 / 20 | 727 | 9.3000 |
| `hint-substitute-line-20` | 1297303584 | 20 / 20 | 186 | 727 | 20 / 20 | 727 | 9.3000 |
| `hint-spray-random-20` | 1297303632 | 10 / 20 | 230 | 360 | 8 / 8 | 356 | 23.0000 |
| `hint-additive-random-20` | 1297303632 | 10 / 20 | 231 | 345 | 8 / 8 | 337 | 23.1000 |
| `hint-substitute-random-20` | 1297303632 | 10 / 20 | 230 | 345 | 8 / 8 | 337 | 23.0000 |

On the random-20 case, substitution cuts fresh-path mean latency from 356 ms
to 337 ms and overall mean latency from 360 ms to 345 ms while transmissions
stay at 230 and overhead at 23.0000. Additive reaches the same 337 ms but uses
231 transmissions (23.1000), so it was rejected. The line-20 rows are an
unchanged-behaviour control: the hint already lies on the spray path. Unit and
integration tests cover freshest selection, tie-breaking, capacity eviction,
expiry fallback, backwards clocks, unknown or unverified links, `Off` mode and
a Direct packet delivered through a substituted hint; the fixed-seed gate
locks every row above.

```bash
cargo run --release --features sim --example routehint_report
cargo test --release --all-features --test sim_routehint
```

## Neighbour hints to aoNetwork (MSH-25)

aoMesh sees facts aoNetwork cannot: the host recognises a contact's rotating
tag, the directory says which nodes a neighbour can reach, and MSH-10 records
neighbour penalties. The engine turns those facts into advisory
`MeshOutput::SetLinkHint` / `ClearLinkHint` actions; the adapter calls aoNetwork's
real `set_link_hint` / `clear_link_hint`. A hint changes candidate ordering and
skips aoNetwork's four-second initiation delay. It never reserves a slot,
evicts a link, changes the admission floor or raises the degree cap: aoNetwork
remains the only component that forms links. No wire field changes.

The host supplies opaque facts through `MeshInput::ObserveLinkHint { observation }`:
a `PeerKey` reported by the radio, the `NodeId` the host associates with it, and
whether the contact book recognises it. The engine keeps both values opaque.
A recognized contact is preferred. An unlinked peer is also preferred when its
identity is the `via` neighbour of at least `min_diverse_nodes` live directory
entries whose destinations no currently linked neighbour reaches. A verified
link to that peer removes the diversity claim. A penalty at or above
`penalty_threshold` overrides both claims with `Deprioritize`; a `Tick`
re-evaluates the decision as penalties decay. Revoking a contact or losing all
support clears the advice.

| Setting | Default | Why |
|---|---|---|
| Maximum tracked peers | 64 | Mirrors aoNetwork's default `max_peers` (NET-16) |
| Penalty threshold | 3 | One invalid packet under MSH-10's default `penalty_invalid` |
| Minimum diverse nodes | 2 | One noisy announcement is not a diversity claim |
| Eviction | Lowest preference, then greatest `PeerKey` | Deterministic and identical to aoNetwork's hint table |

The paired report runs scripted contacts 2, 3 and 4 into range of node 0 at
run start. Both rows use the same seed, topology, traffic and engine
configuration; only the host-supplied hint plan changes. The one-second bound
is far below NET-16's unhinted initiation delay. Four fixed seeds are published
so the "more often" claim is measured, not inferred from one run.

| Scenario | Seed | Linked in bound | Mean link time (ms) | Delivered / submitted | Transmissions | Mean latency (ms) | Overhead |
|---|---:|---:|---:|---:|---:|---:|---:|
| `linkhint-off-scripted-20-a` | 1297303701 | 0 / 3 | 0 | 16 / 16 | 238 | 687 | 14.8750 |
| `linkhint-on-scripted-20-a` | 1297303701 | 3 / 3 | 383 | 16 / 16 | 238 | 687 | 14.8750 |
| `linkhint-off-scripted-20-b` | 1297303702 | 0 / 3 | 0 | 16 / 16 | 238 | 684 | 14.8750 |
| `linkhint-on-scripted-20-b` | 1297303702 | 3 / 3 | 350 | 16 / 16 | 238 | 684 | 14.8750 |
| `linkhint-off-scripted-20-c` | 1297303703 | 0 / 3 | 0 | 16 / 16 | 238 | 684 | 14.8750 |
| `linkhint-on-scripted-20-c` | 1297303703 | 3 / 3 | 366 | 16 / 16 | 238 | 684 | 14.8750 |
| `linkhint-off-scripted-20-d` | 1297303704 | 0 / 3 | 0 | 16 / 16 | 238 | 684 | 14.8750 |
| `linkhint-on-scripted-20-d` | 1297303704 | 3 / 3 | 383 | 16 / 16 | 238 | 684 | 14.8750 |

Hints link 12 of 12 seeded contacts within one second against 0 of 12 without
hints. Delivery, latency, transmissions and overhead are identical in every
pair, so the win is time-to-link rather than a routing shortcut. `tests/linkhint.rs`
covers contact, diversity, penalty and bounded-fact behaviour; `tests/adapter.rs`
asserts the real aoNetwork hint table; `tests/sim_linkhint.rs` locks every row.

```bash
cargo run --release --features sim --example linkhint_report
cargo test --release --all-features --test sim_linkhint
```

## Signed delivery receipts and immunity (MSH-17)

A successful authenticated delivery emits a signed receipt on the Message
channel. The receipt is a cap-gated control envelope, not a fifth packet class:
magic `0x55`, version `1`, tag `1`, flags `0`, two little-endian lengths, the
destination's 128-byte public identity, the original encoded header, the
original payload hash and a normal signed Direct packet whose payload is the
acknowledged `MessageId`. The ack uses the already registered
`aoheyra/mesh/v1/packet` domain, so no sibling crypto domain or key directory is
needed. Peers advertise `CAP_RECEIPT_V1` (`1 << 3`); a link without it receives
no receipt and never parses the envelope.

The engine verifies the binding signature, derives the signer's `NodeId`,
re-derives the acknowledged id from the original header and payload hash,
checks that the signer is the packet's destination and verifies the ack
signature. Accepted receipts enter a bounded immunity list (512 ids, five
minutes), suppress further spray or sync of that id, and produce a `Purge`
output for the host store. The sender receives one `Delivered` output, which is
the origin's sender-status transition. The host owns the bytes; the engine never
holds keys, payloads or a store handle.

A late spray copy is dropped rather than re-stored once its id is immune. This
was the root cause of residual copies in the first scripted-200 run: four nodes
had purged, then re-stored a copy from an older spray ticket.

| Setting | Default | Why |
|---|---|---|
| Immunity entries | 512 | Bounds receipt bytes and per-link sent sets |
| Immunity lifetime | 300 s | Outlives a contact and its later re-sync |
| Gossip per contact | 16 frames | Bounds a link-up burst; further entries follow later contacts |

The paired report uses spray in both rows so the stores are populated, and only
the receipt bit differs:

| Scenario | Seed | Delivered | Receipts at origin | Purges | Copies left | Slowest purge |
|---|---:|---:|---:|---:|---:|---:|
| `receipt-relay-line-20` | 1297303584 | 20 / 20 | 0 | 0 | 206 | n/a |
| `receipt-enabled-line-20` | 1297303584 | 20 / 20 | 20 | 206 | 0 | 1,550 ms |
| `receipt-relay-scripted-200` | 1297303752 | 100 / 100 | 0 | 0 | 1,436 | n/a |
| `receipt-enabled-scripted-200` | 1297303752 | 100 / 100 | 100 | 1,341 | 0 | 1,750 ms |

```bash
cargo run --release --all-features --example receipt_report
cargo test --release --all-features --test sim_receipts
```

`tests/receipts.rs` covers the two-node pipeline; `tests/sim_receipts.rs` locks
the fixed-seed numbers and requires zero delivered copies at every node.
## NodeDirectory (MSH-20)

`directory::NodeDirectory` is a bounded, ephemeral, mesh-wide view of known
nodes. A typed `NodeObservation` carries an opaque `NodeId`, a card hash,
capability bits, an announcement sequence, an estimated hop distance, the
via-neighbour, an observation time and opaque bounded location bytes. The mesh
never fetches a card, opens a payload or interprets an app schema; location is
stored as bytes until the telemetry work defines its meaning. Verified MSH-19
announcements feed the directory automatically with the origin, card hash,
capabilities, sequence, hop count and ingress neighbour from the signed packet.
`MeshInput::ObserveNode` remains available for host-supplied facts; no packet or
hello wire format changes here.

| Setting | Default | Why |
|---|---|---|
| Directory entries | 256 | Covers the mesh visible over several contacts in about 80 KiB |
| Stale after | 30 min | ADR-0001's Presence lifetime: a missed trickle refresh cannot make a node linger |
| Location bytes | 64 | Bounds hostile location claims while leaving telemetry schema open |
| UI events | 64 | Bounds the coalesced change stream handed to the app |

Capacity evicts the least-recently-seen node, with sequence and `NodeId` as
deterministic tie-breaks. Expiry is relative to the local receipt time: a
high-water-mark clock means a backwards `now` neither extends nor shortens a
lifetime, and a peer's observation time is clamped for display ordering only.
`Tick` reclaims stale entries and emits their removals on schedule; queries
also treat a stale entry as absent without mutating state. `get`, `nearby`
(hop-distance range, nearest first) and `recent` are deterministic and bounded
by an explicit result limit.

UI updates arrive as `MeshOutput::DirectoryChanged` /
`AdapterEvent::DirectoryChanged`, each holding only node ids and kinds. One
pending event per node is coalesced (`Added` plus `Removed` disappears;
`Removed` plus `Added` becomes `Updated`), so an announcement flood cannot
grow the event stream past the configured bound. Oversized locations return
the typed `DirectoryError::LocationTooLong` through `MeshError::Directory`.

The fixed simulator scenario injects bounded observations with alternating
future and past observation-time skew. It isolates the ceiling and expiry
schedule without adding announcement traffic or changing any routing metric:

| Scenario | Seed | Capacity | Peak entries | Expirations | Evictions | Last removal | Live at end |
|---|---:|---:|---:|---:|---:|---:|---:|
| `directory-line-6` | 1297304021 | 4 | 4 | 24 | 24 | 4,000 ms | 0 |

```bash
cargo run --all-features --example directory_report
cargo test --all-features --test sim_directory
```

`tests/directory.rs` covers the engine seam and typed errors;
`tests/sim_directory.rs` locks the fixed-seed numbers.

## Lifetime and expiry (MSH-18)

`expiry::LifetimePolicy` provides per-class ceilings using the ADR-0001 defaults.
`MemoryStore::with_lifetime_policy` applies a custom policy consistently to
admission, lookup, summaries and cleanup. The effective lifetime never exceeds
the sender's lifetime and signed wire bytes are unchanged. Age carried from
previous encounters plus local monotonic elapsed time determines expiry;
remote timestamps are ignored. `expiry::age_at` carries consumed age between
encounters with different local epochs. See [the expiry decision](docs/adr/lifetime-expiry.md)
for the caller contract and restart/sync boundaries.

## Public channels (MSH-23)

A public channel is a fixed envelope inside the opaque payload of an ordinary
signed `Broadcast` packet:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | Magic `0xC4` |
| 1 | 1 | Version `1` |
| 2 | 16 | Channel id |
| 18 | .. | Opaque application bytes |

There is no new packet class, header field or signature domain. The channel id
is BLAKE3-128 over `aoheyra/mesh/v1/channel-id`, a one-byte name length, tag
`0x01` and the name; the name itself is never sent. A separate
`aoheyra/mesh/v1/channel-budget` hash turns the id into a synthetic key for the
existing MSH-10 origin-bucket table. A hot channel is therefore limited without
a second budget table and without eating the origin's general Broadcast
allowance.

| Setting | Default | Hard cap | Why |
|---|---:|---:|---|
| Local subscriptions | 32 | 256 | Bounds local name state; relays keep zero |
| Channel name bytes | 64 | 64 | Fits one length byte and bounds hash input |
| Envelope header | 18 | - | Magic, version and a 16-byte id |
| Channel id bytes | 16 | - | 128-bit collision resistance with typed collision detection |

`MeshInput::ChannelSubscribe` and `ChannelUnsubscribe` mutate only the node's
bounded `ChannelRules` registry. Relays never receive them, so an uninvolved
relay keeps an empty registry and forwards channel packets like any other
Broadcast. A Broadcast payload starting with the reserved magic must be a
complete envelope; a truncated or wrong-version one is rejected and counted
against the sending link. Ordinary Broadcast payloads keep the MSH-11 path.

For a copy arriving directly from the origin, a subscriber verifies the origin
signature with the key proved by the sender's signed `MeshHello`, accepts the
content id in the replay guard, and receives `MeshOutput::ChannelDeliver` with
the envelope's opaque inner bytes. Relayed copies still forward under MSH-10
and MSH-11 but are not delivered locally: the MSH-20 directory carries typed
presence observations and no signed packet key, so a remote origin cannot be
authenticated for local delivery. Verification is not relaxed to make a
delivery happen. Extending the directory with a key proved under the packet
domain can extend delivery beyond direct neighbours without changing the
envelope.

Locally submitted envelopes are validated before signing, then debited from the
origin's Broadcast bucket and the channel bucket; the origin is refunded if the
channel bucket refuses. Relays pay the normal origin and link buckets plus the
channel bucket before suppression starts. All rejections are typed
`ChannelError` values exposed as `MeshError::Channel`; no packet-driven path
panics, and no payload is interpreted as text or an app schema.

The fixed 20-node line case puts subscribers 9 and 11 in origin 10's radio
range and leaves the other 17 nodes subscription-free. One signed message is
submitted with seed `1297304023`:

```bash
cargo run --release --all-features --example channel_report
cargo test --release --all-features --test sim_channels
```

The report CSV columns are `scenario,seed,nodes,submitted,subscribers,
channel_deliveries,channel_transmissions,channel_bytes,broadcast_burst_bytes,
within_broadcast_budget`. Its exact row is:

| Scenario | Seed | Nodes | Submitted | Subscribers | Deliveries | Transmissions | Envelope bytes | Burst bytes | Within budget |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `channel-line-20` | 1297304023 | 20 | 1 | 2 | 2 | 12 | 3048 | 43690 | yes |

Both in-range subscribers receive the message; no other node does. Twelve
one-link transmissions carry 3,048 bytes against the 43,690-byte Broadcast
burst allowance from ADR-0001. This row was remeasured after rebasing onto
MSH-22: the two-link suppression floor kept for chain relays makes each line relay forward once,
replacing the old two-transmission expectation from the pre-MSH-19 tree.
Reachability and the budget gate are unchanged, and no published MSH-27
threshold was lowered. The four published MSH-27 baselines are unchanged.
## Fuzzing and resource bounds (MSH-28)

Every neighbour byte stream and host-supplied slice has a hard bound before it
can grow engine state. The packet decoder stays allocation-free; sync decoders
reject a hostile body before copying it; summary construction and sync-offer
handling read at most the store's entry cap. A reachable `debug_assert` in the
delivery path was removed so hostile input cannot panic in debug builds.

| Bound | Limit | Why |
|---|---:|---|
| Packet payload | 2048 bytes | Existing `MAX_PAYLOAD`, checked in the header (MSH-03) |
| Varint field | 10 bytes | Canonical unsigned LEB128, checked before value use |
| Summary entries | 1024 | Matches the default store cap; longer host slices are ignored |
| Sync frame body | 8198 bytes | `6 + 1024 * 8`, the largest legitimate v1 summary |
| Offers per engine input | 1024 | Matches the summary cap; `SyncItems` cannot mint extra work |
| Fuzz input | 16 KiB | Larger than every decoder cap, small enough for fast campaigns |
| Fuzz RSS / timeout | 2048 MiB / 10 s | Detects runaway allocation or a per-input loop |

`SyncFrame::decode` and `SyncFrameV2::decode` are public and return typed
`SyncError` / `SyncV2Error` values, including `FrameTooLarge(usize)`. This keeps
fuzz diagnostics and host integration string-free without changing the wire
format. `tests/resource_bounds.rs` uses a counting allocator to pin allocation
and CPU-proxy ceilings for hostile packets, sync frames, summary streams,
engine Data streams and store quotas. It is a single-test binary so no other
test can pollute the counters.

The three `libFuzzer` targets (`packet_decode`, `engine_input` and
`sync_frames`) live in [aoheyra-fuzz](https://github.com/aoheyra/aoheyra-fuzz),
together with their seeds, pinned revisions and weekly schedule. They use
injected time and RNG, construct a verified neighbour without `unwrap`/`expect`,
and treat malicious bytes as the input rather than setup failure. No fuzz
crate or workflow is kept in this repository.
## Restart state (MSH-29)

A restart snapshot is local, versioned host state rather than a protocol
wire format: no capability negotiation or packet layout is involved. It
covers the forwarding seen-cache, receipt immunity and spray tickets;
stored packets, RNG state, config and radio sessions remain with the host.
See the engine `Snapshot` trait and the paired restart report described in
the seen-cache section above.
## Observability (MSH-30)

`MeshSnapshot` is a plain, versioned bundle of saturating counters and gauges.
The host can map it directly into aoheyra's APP-15 diagnostics bundle; this
crate performs no logging, file I/O or network export. `version` selects the
field layout, so a host must switch on `MESH_SNAPSHOT_VERSION` before reading
fields it does not recognise. Reading a snapshot is side-effect free: gauges
are derived from state the engine already holds for routing policy.

| Field | Meaning | Bound / owner |
|---|---|---|
| `duplicate_packets` | Duplicate verdicts from forwarding dedupe | Saturating `u64`; `SeenCache` |
| `suppressed_relays` | Flood relays cancelled by MSH-11 | Saturating `u64`; `SuppressionTable` |
| `store_entries` | Live ids from the last `MeshInput::StoreSummary` | `u32`; host-owned store |
| `sync_bytes_sent` | Encoded sync frame bytes emitted on Bulk | Saturating `u64`; `SyncTracker` |
| `sync_bytes_received` | Decoded sync frame bytes from verified neighbours | Saturating `u64`; `SyncTracker` |
| `neighbour_penalty_events` | Positive penalty applications, including decayed ones | Saturating `u64`; `BudgetTracker` |
| `neighbour_penalty_total`, `neighbour_penalty_max`, `penalised_neighbours` | Current decayable penalty scores | Existing neighbour table |
| `seen_records`, `suppression_pending` | Live bounded table entries | `SeenConfig::capacity`, `SuppressionConfig::max_entries` |

Counters are owned by the module that makes the decision, so there is no
second source of truth. Cumulative counters saturate instead of wrapping under
hostile traffic. Malformed or unverified frames add a neighbour penalty but are
not counted as sync bytes. No field carries packet content, `MessageId`, keys,
identities or personal data. The wire format and MSH-27 CSV schema are
unchanged.

```bash
cargo run --release --all-features --example observability_report
cargo test --release --all-features --test sim_observability
cargo test --release --all-features --test observability
```

The fixed 20-node mixed scenario has seed `1297304021`; four malformed frames
are injected from node 0 after traffic starts. The measured report row is:

| Scenario | Seed | Submitted / delivered | Duplicates | Suppressed | Store ids | Sync bytes sent / received | Penalty events | Seen / pending |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `observability-mixed-20` | 1297304021 | 40 / 6 | 321 | 166 | 88 | 820 / 820 | 4 | 547 / 0 |

The row was remeasured after FIX 38 scoped the two-link suppression floor to
chain relays and Presence, so it is comparable neither to the original
367/193/89/512/7 measurement nor to the intermediate 323/120/88/512/7 row.
No MSH-27 threshold was lowered.
Current penalties are zero at the end because scores decay after the four
events; `neighbour_penalty_events` is the durable evidence that the hostile
neighbour was accounted for. `tests/sim_observability.rs` locks every value,
and `tests/observability.rs` covers adapter mapping, stability, bounds and
absence of content leakage. The actual APP-15 bundle wiring belongs to
aoheyra and consumes this plain snapshot.

For a process/device restart with a new monotonic epoch, prefer `TimedSnapshot`:
call `snapshot_at(now, owner)` and restore a fresh engine using
`restore_at(new_now, owner, elapsed_ms, &bytes)`. This identity-bound format stores
remaining lifetimes and discards old transport LinkIds. Legacy `Snapshot` bytes
require the original clock epoch and link namespace. See
[the clock-safe restart contract](docs/adr/clock-safe-restart.md).
