//! MSH-30 regression gate for the host-visible engine snapshot.
//!
//! Values come from `cargo run --release --all-features --example
//! observability_report`. The scenario and seed are fixed in
//! [`ao_mesh::sim::observability_scenarios`]. The extra metrics are outside
//! the MSH-27 CSV schema: they aggregate engine snapshots rather than radio
//! events, so no MSH-27 threshold is changed here.

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::{
    SeenConfig, SuppressionConfig,
    sim::{observability_scenarios, run_observability},
};

struct Expected {
    scenario: &'static str,
    seed: u64,
    nodes: usize,
    submitted: u64,
    delivered: u64,
    duplicate_packets: u64,
    suppressed_relays: u64,
    store_entries: u64,
    sync_bytes_sent: u64,
    sync_bytes_received: u64,
    neighbour_penalty_events: u64,
    neighbour_penalty_total: u64,
    neighbour_penalty_max: u32,
    penalised_neighbours: u64,
    seen_records: u64,
    suppression_pending: u64,
}

fn expected() -> Expected {
    Expected {
        scenario: "observability-mixed-20",
        seed: 1_297_304_021,
        nodes: 20,
        submitted: 40,
        delivered: 6,
        duplicate_packets: 321,
        suppressed_relays: 166,
        store_entries: 88,
        sync_bytes_sent: 820,
        sync_bytes_received: 820,
        neighbour_penalty_events: 4,
        neighbour_penalty_total: 0,
        neighbour_penalty_max: 0,
        penalised_neighbours: 0,
        seen_records: 547,
        suppression_pending: 0,
    }
}

#[test]
fn mixed_traffic_keeps_the_snapshot_counters_stable_and_bounded() {
    let experiments = observability_scenarios();
    assert_eq!(experiments.len(), 1);
    let invalid_frames = experiments[0].injection.invalid_frames;
    let got = run_observability(experiments.into_iter().next().unwrap());
    let want = expected();

    assert_eq!(got.scenario, want.scenario);
    assert_eq!(got.seed, want.seed);
    assert_eq!(got.nodes, want.nodes);
    assert_eq!(got.submitted, want.submitted);
    assert_eq!(got.delivered, want.delivered);
    assert_eq!(got.duplicate_packets, want.duplicate_packets);
    assert_eq!(got.suppressed_relays, want.suppressed_relays);
    assert_eq!(got.store_entries, want.store_entries);
    assert_eq!(got.sync_bytes_sent, want.sync_bytes_sent);
    assert_eq!(got.sync_bytes_received, want.sync_bytes_received);
    assert_eq!(got.neighbour_penalty_events, want.neighbour_penalty_events);
    assert_eq!(got.neighbour_penalty_total, want.neighbour_penalty_total);
    assert_eq!(got.neighbour_penalty_max, want.neighbour_penalty_max);
    assert_eq!(got.penalised_neighbours, want.penalised_neighbours);
    assert_eq!(got.seen_records, want.seen_records);
    assert_eq!(got.suppression_pending, want.suppression_pending);

    // Every injected malformed frame reaches the penalty counter. Current
    // scores decay to zero by design, so the cumulative count is the proof
    // that the hostile neighbour was accounted for.
    assert_eq!(got.neighbour_penalty_events, invalid_frames as u64);
    assert!(got.neighbour_penalty_total <= got.neighbour_penalty_events);

    // The live gauges never exceed the bounded tables that feed them.
    let nodes = got.nodes as u64;
    assert!(got.seen_records <= nodes * SeenConfig::default().capacity as u64);
    assert!(got.suppression_pending <= nodes * SuppressionConfig::default().max_entries as u64);
    assert!(got.penalised_neighbours <= nodes * 32);
}
