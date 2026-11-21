//! MSH-21 regression gate for the paired route-hint report.
//!
//! Values come from
//! `cargo run --release --features sim --example routehint_report` with the
//! fixed seeds in [`ao_mesh::sim::route_hint_scenarios`]. The paired rows
//! share topology, mobility, traffic, budgets, spray and receipts; only the
//! hint mode differs. Every row receives the same seeded presence
//! observations, so the fresh-path count in the hint-off row is the honest
//! baseline for the two hint-on rows.

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::sim::{route_hint_scenarios, run};

struct Expected {
    scenario: &'static str,
    seed: u64,
    nodes: usize,
    submitted: u64,
    delivered: u64,
    transmissions: u64,
    mean_latency_ms: u64,
    fresh_submissions: u64,
    fresh_deliveries: u64,
    fresh_mean_latency_ms: u64,
    overhead: f64,
}

fn expected() -> Vec<Expected> {
    vec![
        Expected {
            scenario: "hint-spray-line-20",
            seed: 1_297_303_584,
            nodes: 20,
            submitted: 20,
            delivered: 20,
            transmissions: 186,
            mean_latency_ms: 727,
            fresh_submissions: 20,
            fresh_deliveries: 20,
            fresh_mean_latency_ms: 727,
            overhead: 9.3000,
        },
        Expected {
            scenario: "hint-additive-line-20",
            seed: 1_297_303_584,
            nodes: 20,
            submitted: 20,
            delivered: 20,
            transmissions: 186,
            mean_latency_ms: 727,
            fresh_submissions: 20,
            fresh_deliveries: 20,
            fresh_mean_latency_ms: 727,
            overhead: 9.3000,
        },
        Expected {
            scenario: "hint-substitute-line-20",
            seed: 1_297_303_584,
            nodes: 20,
            submitted: 20,
            delivered: 20,
            transmissions: 186,
            mean_latency_ms: 727,
            fresh_submissions: 20,
            fresh_deliveries: 20,
            fresh_mean_latency_ms: 727,
            overhead: 9.3000,
        },
        Expected {
            scenario: "hint-spray-random-20",
            seed: 1_297_303_632,
            nodes: 20,
            submitted: 20,
            delivered: 10,
            transmissions: 230,
            mean_latency_ms: 360,
            fresh_submissions: 8,
            fresh_deliveries: 8,
            fresh_mean_latency_ms: 356,
            overhead: 23.0000,
        },
        Expected {
            scenario: "hint-additive-random-20",
            seed: 1_297_303_632,
            nodes: 20,
            submitted: 20,
            delivered: 10,
            transmissions: 231,
            mean_latency_ms: 345,
            fresh_submissions: 8,
            fresh_deliveries: 8,
            fresh_mean_latency_ms: 337,
            overhead: 23.1000,
        },
        Expected {
            scenario: "hint-substitute-random-20",
            seed: 1_297_303_632,
            nodes: 20,
            submitted: 20,
            delivered: 10,
            transmissions: 230,
            mean_latency_ms: 345,
            fresh_submissions: 8,
            fresh_deliveries: 8,
            fresh_mean_latency_ms: 337,
            overhead: 23.0000,
        },
    ]
}

#[test]
fn substitute_hint_lowers_fresh_path_latency_without_raising_overhead() {
    let got: Vec<_> = route_hint_scenarios().into_iter().map(run).collect();
    let want = expected();
    assert_eq!(got.len(), want.len());
    for (actual, expected) in got.iter().zip(&want) {
        assert_eq!(actual.scenario, expected.scenario);
        assert_eq!(actual.seed, expected.seed);
        assert_eq!(actual.nodes, expected.nodes);
        assert_eq!(actual.submitted, expected.submitted);
        assert_eq!(actual.delivered, expected.delivered);
        assert_eq!(actual.transmissions, expected.transmissions);
        assert_eq!(actual.mean_latency_ms, expected.mean_latency_ms);
        assert_eq!(actual.fresh_hint_submissions, expected.fresh_submissions);
        assert_eq!(actual.fresh_hint_deliveries, expected.fresh_deliveries);
        assert_eq!(
            actual.fresh_hint_mean_latency_ms,
            expected.fresh_mean_latency_ms
        );
        assert!((actual.overhead - expected.overhead).abs() < 5e-5);
        assert_eq!(
            actual.send_failures, 0,
            "{} refused a send",
            actual.scenario
        );
    }

    // The line is the unchanged-behaviour control: a hint that already lies
    // on the spray path must not add a transmission or change latency.
    assert_eq!(
        got[0].fresh_hint_mean_latency_ms,
        got[2].fresh_hint_mean_latency_ms
    );
    assert_eq!(got[0].transmissions, got[2].transmissions);

    // The measured winner is the substituted spray copy. Both hint-on modes
    // lower fresh-path latency, but only substitution leaves transmissions
    // per delivery unchanged; additive unicast pays one extra transmission.
    assert!(got[5].fresh_hint_mean_latency_ms < got[3].fresh_hint_mean_latency_ms);
    assert!(got[5].overhead <= got[3].overhead);
    assert_eq!(got[5].delivered, got[3].delivered);
    assert!(got[4].fresh_hint_mean_latency_ms < got[3].fresh_hint_mean_latency_ms);
    assert!(got[4].overhead > got[3].overhead);
}
