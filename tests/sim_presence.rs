//! MSH-19 simulation evidence: a 50-node mesh learns every other node and
//! stays inside ADR-0001's per-origin Presence allowance at steady state.
//!
//! The exact row is locked, not just the directional bounds, so a change to
//! the trickle timer, topology, capability gate or wire body must be reviewed
//! and republished. This is the same row printed by `presence_report`.

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::sim::{Metrics, presence_scenarios, run};

const HEADER: &str = "scenario,seed,nodes,submitted,delivered,duplicate_deliveries,transmissions,receptions,send_failures,radio_bytes,mean_latency_ms,max_latency_ms,delivery_ratio,overhead,duplicate_ratio,peak_queued_bytes,links_after_settle,presence_converged,convergence_ms,learned_nodes_min,card_fetches,announcement_sends,announcement_bytes,steady_announcement_sends,steady_announcement_bytes";

const SEED: u64 = 1_297_304_021;

const ROW: &str = "presence-smallworld-50,1297304021,50,0,0,0,17090,16487,0,2929308,0,0,0.0000,17090.0000,0.0000,714676,300,true,50,49,0,11007,2839806,6036,1557288";

#[test]
fn fifty_nodes_converge_within_the_presence_budget() {
    let scenario = presence_scenarios()
        .into_iter()
        .next()
        .expect("presence scenario is configured");
    assert_eq!(scenario.seed, SEED);
    let metrics = run(scenario.clone());

    assert_eq!(Metrics::csv_header(), HEADER);
    assert_eq!(metrics.csv_row(), ROW);
    assert!(metrics.presence_converged, "the mesh did not converge");
    assert_eq!(metrics.learned_nodes_min, scenario.nodes - 1);
    assert_eq!(metrics.card_fetches, 0, "all card hashes are declared");

    // One-second quick delay plus TTL 3 over a diameter-three graph, with the
    // 600 ms suppression ceiling at each hop, is bounded well below 5 s.
    assert!(
        metrics.convergence_ms <= 5_000,
        "convergence took {} ms",
        metrics.convergence_ms
    );

    // One source emits at most one announcement per steady interval. The
    // measured average wire size times that rate must fit ADR-0001's 64 KiB/h
    // Presence budget. Relays are separately bounded by the MSH-10 buckets.
    assert!(metrics.steady_announcement_sends > 0);
    let bytes_per_announcement =
        metrics.steady_announcement_bytes as f64 / metrics.steady_announcement_sends as f64;
    let hourly_source_bytes =
        bytes_per_announcement * (3_600_000.0 / scenario.presence_config.steady_interval_ms as f64);
    assert!(
        hourly_source_bytes <= 64.0 * 1024.0,
        "per-source steady rate {hourly_source_bytes:.1} B/h exceeds 64 KiB/h"
    );
}
