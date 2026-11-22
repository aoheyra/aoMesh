# v0.1.0 release preparation

`v0.1.0` is the planned first release of `ao_mesh`. This document records the
unreleased state of the crate: the feature set intended for that version, the
public defaults that the ADRs and README must agree with, the MSH-27 baseline
evidence, and the two no-behavior documentation/test cleanups made during
MSH-31.

aoMesh remains pre-alpha and untagged. Sibling crates are consumed as untagged
git sources on their default branches. A consumer that depends on `ao_network`
or `ao_idents` directly must use the same untagged URLs as aoMesh; Cargo treats
a tagged source as a different identity and would duplicate `Identity`,
`LinkId` and `NodeId` across the seam. Local co-development overrides belong in
uncommitted Cargo config only. No tags are created or moved by MSH-31.

## Parameter reference in code

All defaults below come from `MeshConfig::default()` and the component
defaults. ADR-0001 gives the rationale and the measurement behind each value;
`docs/protocol.md` gives the wire fields they affect.

| Area | Code field | Default |
|---|---|---|
| Neighbours | `MeshConfig::max_neighbors` | 32 |
| Seen cache | `SeenConfig::capacity` | 4096 entries |
| Seen windows | `SeenConfig` per class | Direct 24 h, Broadcast 6 h, Presence 30 min, Telemetry 5 min |
| Replay guard | `MeshConfig::replay` | 1024 ids per sender, 86,400,000 ms tolerance, 64 senders |
| Relay rates | `BudgetConfig::rates` | 1 MiB/h, 256 KiB/h, 64 KiB/h, 32 KiB/h; 600 s burst |
| Relay state | `BudgetConfig` | 1024 origins, 32 neighbours, 64 origins per neighbour |
| Penalties | `BudgetConfig` | invalid 3, unverified 2, excess 1, release at 12, decay 1 per 60 s |
| Suppression | `SuppressionConfig` | 1024 entries, degree 4 / 3 copies, configured `min_k` 1 with an effective floor of 2, `max_k` 6 |
| Delays | `SuppressionConfig` | 60-140 ms base, 20-600 ms final |
| Class TTL | `SuppressionConfig` | Direct 8, Broadcast 6, Presence 3, Telemetry 3 |
| Store | `StoreLimits` | 1024 entries, 2 MiB total, 256 KiB per origin; Direct 2 MiB, Broadcast 512 KiB, Presence 64 KiB, Telemetry 0 |
| Lifetime | `LifetimePolicy` | Direct 24 h, Broadcast 6 h, Presence 30 min, Telemetry store ceiling 5 min |
| Telemetry | `TelemetryConfig` | 30 s freshness, 10 s per-origin cap, 3 hops, 512 entries |
| Summary / sync | `SummaryConfig`, `SyncConfig` | 8-byte prefixes, 200 ms debounce, 256 KiB/contact, 15 KiB/frame, 20 s deadline, 32-id leaves, depth 128, 8 range entries |
| Spray | `SprayConfig` | 255 initial tickets, 4096 live ids |
| Receipts | `ReceiptConfig` | 512 immune ids, 300 s, 16 frames per contact |
| Presence | `PresenceConfig` | 1024 learned, 1024 known cards, 1000 ms quick, 60 s base, 900 s steady, 1800 s lifetime |
| Directory | `DirectoryConfig` | 256 entries, 30 min, 64 location bytes, 64 UI events |
| Route hints | `RouteHintConfig` | `SubstituteCopy`, 1024 entries, 300,000 ms, 8 hops |
| Channels | `ChannelConfig` | 32 subscriptions, 64-byte names, 256 hard cap |
| Snapshot | `snapshot` module | version 1, 4 MiB maximum |
| Sync frames | `MAX_FRAME_BODY_BYTES` | 8198 bytes (`6 + 1024 * 8`) |

Telemetry has two distinct windows: the `LifetimePolicy` store ceiling is
5 min, while the `TelemetryConfig` relay freshness window is 30 s. Telemetry is
never stored, so the first value is a policy ceiling rather than retained
state. ADR-0001, the simulator ADR and these notes state both.

## MSH-27 benchmark evidence

Reproduced from the current source with:

```text
cargo run --release --features sim --example sim_report -- baselines.csv
cargo test --release --all-features --test sim_baseline
```

Release profile, toolchain `cargo +1.85`, fixed seeds from
`ao_mesh::sim::baseline_scenarios()`:

| Scenario | Seed | Delivered / submitted | Delivery ratio | Overhead | Mean / max latency (ms) | Radio bytes | Peak queued bytes |
|---|---:|---:|---:|---:|---:|---:|---:|
| `line-20` | 1297303584 | 20 / 20 | 1.0000 | 9.6500 | 727 / 1200 | 102065 | 550 |
| `waypoint-50` | 1297303632 | 31 / 50 | 0.6200 | 125.7742 | 551 / 1200 | 2080893 | 12375 |
| `community-100` | 1297303652 | 75 / 80 | 0.9375 | 328.7067 | 676 / 1200 | 13031341 | 33290 |
| `scripted-200` | 1297303752 | 100 / 100 | 1.0000 | 34.5500 | 561 / 1200 | 1850727 | 6600 |

All rows have zero send failures and zero duplicate deliveries. The measured
line-20 mean latency is 727 ms; the directional gate in `tests/sim_baseline.rs`
keeps its existing 730 ms ceiling and was not lowered to match the row. The
table is published in the README, `docs/adr/simulator-baseline.md` and here;
`tests/release_docs.rs` checks the three copies against the code defaults and
the same gate values.

## Documentation and test corrections

MSH-31 brings the written defaults in line with the code without changing any
packet, `MeshHello`, sync, snapshot or diagnostics layout. The Rust 1.85 gates
also required two no-behavior cleanups: `SyncTracker::on_frame` uses
`Entry::Vacant` instead of `contains_key` plus `insert`, and the route-hint
rustdoc no longer links to the private `expire`. Neither changes packet bytes,
routing decisions, public API or any value listed above.

`tests/release_docs.rs` now guards the README, ADRs and these notes against
drift. Fuzz targets live in
[aoheyra-fuzz](https://github.com/aoheyra/aoheyra-fuzz); there is no local
`fuzz/` crate in aoMesh.
