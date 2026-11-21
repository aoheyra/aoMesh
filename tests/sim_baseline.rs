//! Nightly regression gate for the published MSH-27 baseline.
//!
//! Values come from `cargo run --release --features sim --example sim_report`
//! with the fixed scenarios and seeds in [`ao_mesh::sim::baseline_scenarios`].
//! Bounds are directional: an improvement passes, a regression fails.

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::sim::{Metrics, baseline_scenarios, run};

const EPS: f64 = 1e-9;

struct Expected {
    scenario: &'static str,
    seed: u64,
    nodes: usize,
    submitted: u64,
    delivered: u64,
    radio_bytes: u64,
    mean_latency_ms: u64,
    max_latency_ms: u64,
    delivery_ratio: f64,
    overhead: f64,
    duplicate_ratio: f64,
    peak_queued_bytes: usize,
    links_after_settle: usize,
}

fn expected() -> Vec<Expected> {
    vec![
        Expected {
            scenario: "line-20",
            seed: 1_297_303_584,
            nodes: 20,
            submitted: 20,
            delivered: 20,
            radio_bytes: 102_065,
            mean_latency_ms: 730,
            max_latency_ms: 1_200,
            delivery_ratio: 1.0,
            overhead: 193.0 / 20.0,
            duplicate_ratio: 0.0,
            peak_queued_bytes: 550,
            links_after_settle: 38,
        },
        Expected {
            scenario: "waypoint-50",
            seed: 1_297_303_632,
            nodes: 50,
            submitted: 50,
            delivered: 31,
            radio_bytes: 2_080_893,
            mean_latency_ms: 551,
            max_latency_ms: 1_200,
            delivery_ratio: 0.62,
            overhead: 3_899.0 / 31.0,
            duplicate_ratio: 0.0,
            peak_queued_bytes: 12_375,
            links_after_settle: 180,
        },
        Expected {
            scenario: "community-100",
            seed: 1_297_303_652,
            nodes: 100,
            submitted: 80,
            delivered: 75,
            radio_bytes: 13_031_341,
            mean_latency_ms: 676,
            max_latency_ms: 1_200,
            delivery_ratio: 0.9375,
            overhead: 24_653.0 / 75.0,
            duplicate_ratio: 0.0,
            peak_queued_bytes: 33_290,
            links_after_settle: 412,
        },
        Expected {
            scenario: "scripted-200",
            seed: 1_297_303_752,
            nodes: 200,
            submitted: 100,
            delivered: 100,
            radio_bytes: 1_850_727,
            mean_latency_ms: 561,
            max_latency_ms: 1_200,
            delivery_ratio: 1.0,
            overhead: 34.5500,
            duplicate_ratio: 0.0,
            peak_queued_bytes: 6_600,
            links_after_settle: 398,
        },
    ]
}

fn check(got: &Metrics, want: &Expected) {
    assert_eq!(got.scenario, want.scenario);
    assert_eq!(got.seed, want.seed);
    assert_eq!(got.nodes, want.nodes);
    assert_eq!(got.submitted, want.submitted);
    assert_eq!(got.links_after_settle, want.links_after_settle);
    assert_eq!(got.send_failures, 0, "{} refused a send", got.scenario);
    assert_eq!(got.duplicate_deliveries, 0, "{} duplicated", got.scenario);

    assert!(
        got.delivered >= want.delivered,
        "{} delivery regressed: {} < {}",
        got.scenario,
        got.delivered,
        want.delivered
    );
    assert!(
        got.delivery_ratio + EPS >= want.delivery_ratio,
        "{} delivery ratio regressed: {:.4} < {:.4}",
        got.scenario,
        got.delivery_ratio,
        want.delivery_ratio
    );
    assert!(
        got.overhead <= want.overhead + EPS,
        "{} overhead regressed: {:.4} > {:.4}",
        got.scenario,
        got.overhead,
        want.overhead
    );
    assert!(
        got.duplicate_ratio <= want.duplicate_ratio + EPS,
        "{} duplicate ratio regressed: {:.4} > {:.4}",
        got.scenario,
        got.duplicate_ratio,
        want.duplicate_ratio
    );
    assert!(
        got.mean_latency_ms <= want.mean_latency_ms,
        "{} mean latency regressed: {} > {}",
        got.scenario,
        got.mean_latency_ms,
        want.mean_latency_ms
    );
    assert!(
        got.max_latency_ms <= want.max_latency_ms,
        "{} max latency regressed: {} > {}",
        got.scenario,
        got.max_latency_ms,
        want.max_latency_ms
    );
    assert!(
        got.radio_bytes <= want.radio_bytes,
        "{} radio bytes regressed: {} > {}",
        got.scenario,
        got.radio_bytes,
        want.radio_bytes
    );
    assert!(
        got.peak_queued_bytes <= want.peak_queued_bytes,
        "{} buffer occupancy regressed: {} > {}",
        got.scenario,
        got.peak_queued_bytes,
        want.peak_queued_bytes
    );
}

#[test]
fn published_baseline_holds() {
    let scenarios = baseline_scenarios();
    let expected = expected();
    assert_eq!(scenarios.len(), expected.len());
    for (scenario, want) in scenarios.into_iter().zip(expected) {
        check(&run(scenario), &want);
    }
}
