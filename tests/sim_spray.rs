//! MSH-16 regression gate for the paired spray report.
//!
//! Values come from `cargo run --release --features sim --example spray_report`
//! with the fixed seeds in [`ao_mesh::sim::spray_scenarios`]. The paired rows
//! share topology, mobility, traffic and budgets; only the spray bit differs.

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::sim::{Metrics, run, spray_scenarios};

struct Expected {
    scenario: &'static str,
    seed: u64,
    nodes: usize,
    submitted: u64,
    delivered: u64,
    transmissions: u64,
    delivery_ratio: f64,
    overhead: f64,
}

fn expected() -> Vec<Expected> {
    vec![
        Expected {
            scenario: "spray-relay-line-20",
            seed: 1_297_303_584,
            nodes: 20,
            submitted: 20,
            delivered: 20,
            transmissions: 193,
            delivery_ratio: 1.0,
            overhead: 9.6500,
        },
        Expected {
            scenario: "spray-enabled-line-20",
            seed: 1_297_303_584,
            nodes: 20,
            submitted: 20,
            delivered: 20,
            transmissions: 186,
            delivery_ratio: 1.0,
            overhead: 9.3000,
        },
        Expected {
            scenario: "spray-relay-scripted-200",
            seed: 1_297_303_752,
            nodes: 200,
            submitted: 100,
            delivered: 100,
            transmissions: 3_455,
            delivery_ratio: 1.0,
            overhead: 34.5500,
        },
        Expected {
            scenario: "spray-enabled-scripted-200",
            seed: 1_297_303_752,
            nodes: 200,
            submitted: 100,
            delivered: 99,
            transmissions: 1_786,
            delivery_ratio: 0.9900,
            overhead: 18.0404,
        },
    ]
}

#[test]
fn spray_is_close_to_flooding_at_a_fraction_of_the_transmissions() {
    let got: Vec<Metrics> = spray_scenarios().into_iter().map(run).collect();
    let want = expected();
    assert_eq!(got.len(), want.len());

    for (actual, expected) in got.iter().zip(&want) {
        assert_eq!(actual.scenario, expected.scenario);
        assert_eq!(actual.seed, expected.seed);
        assert_eq!(actual.nodes, expected.nodes);
        assert_eq!(actual.submitted, expected.submitted);
        assert_eq!(actual.delivered, expected.delivered);
        assert_eq!(actual.transmissions, expected.transmissions);
        assert_eq!(
            actual.send_failures, 0,
            "{} refused a send",
            actual.scenario
        );
        assert!((actual.delivery_ratio - expected.delivery_ratio).abs() < 1e-9);
        assert!((actual.overhead - expected.overhead).abs() < 5e-5);
    }

    let relay = &got[2];
    let spray = &got[3];
    assert!(
        spray.delivery_ratio >= 0.95,
        "spray delivery {:.4} is not close to flooding",
        spray.delivery_ratio
    );
    assert!(
        spray.transmissions * 100 <= relay.transmissions * 52,
        "spray used {} of {} transmissions",
        spray.transmissions,
        relay.transmissions
    );
}
