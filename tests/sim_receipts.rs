//! MSH-17 regression gate for bounded, network-wide store purging.
//!
//! Values come from `cargo run --release --all-features --example
//! receipt_report`. Both rows use spray so stores are populated; only the
//! receipt capability differs. Seeds are fixed in
//! [`ao_mesh::sim::receipt_scenarios`]. The enabled 200-node row dropped from
//! 27,958 to 27,926 transmissions when MSH-19 floored suppression at two
//! distinct sending links; delivery, receipts, purges and latency are unchanged.

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::sim::{receipt_scenarios, run};

struct Expected {
    scenario: &'static str,
    seed: u64,
    submitted: u64,
    delivered: u64,
    delivery_receipts: u64,
    purges: u64,
    remaining_copies: usize,
    max_purge_latency_ms: u64,
    transmissions: u64,
}

fn expected() -> Vec<Expected> {
    vec![
        Expected {
            scenario: "receipt-relay-line-20",
            seed: 1_297_303_584,
            submitted: 20,
            delivered: 20,
            delivery_receipts: 0,
            purges: 0,
            remaining_copies: 206,
            max_purge_latency_ms: 0,
            transmissions: 186,
        },
        Expected {
            scenario: "receipt-enabled-line-20",
            seed: 1_297_303_584,
            submitted: 20,
            delivered: 20,
            delivery_receipts: 20,
            purges: 206,
            remaining_copies: 0,
            max_purge_latency_ms: 1_550,
            transmissions: 566,
        },
        Expected {
            scenario: "receipt-relay-scripted-200",
            seed: 1_297_303_752,
            submitted: 100,
            delivered: 100,
            delivery_receipts: 0,
            purges: 0,
            remaining_copies: 1_436,
            max_purge_latency_ms: 0,
            transmissions: 1_568,
        },
        Expected {
            scenario: "receipt-enabled-scripted-200",
            seed: 1_297_303_752,
            submitted: 100,
            delivered: 100,
            delivery_receipts: 100,
            purges: 1_341,
            remaining_copies: 0,
            max_purge_latency_ms: 1_750,
            transmissions: 27_926,
        },
    ]
}

#[test]
fn receipts_purge_every_stored_copy_within_a_bounded_time() {
    let got: Vec<_> = receipt_scenarios().into_iter().map(run).collect();
    let want = expected();
    assert_eq!(got.len(), want.len());
    for (actual, expected) in got.iter().zip(&want) {
        assert_eq!(actual.scenario, expected.scenario);
        assert_eq!(actual.seed, expected.seed);
        assert_eq!(actual.submitted, expected.submitted);
        assert_eq!(actual.delivered, expected.delivered);
        assert_eq!(actual.delivery_receipts, expected.delivery_receipts);
        assert_eq!(actual.purges, expected.purges);
        assert_eq!(actual.remaining_copies, expected.remaining_copies);
        assert_eq!(
            actual.max_purge_latency_ms, expected.max_purge_latency_ms,
            "{} purge latency changed",
            actual.scenario
        );
        assert_eq!(actual.transmissions, expected.transmissions);
        assert_eq!(
            actual.remaining_delivered_copies, 0,
            "{} retained a delivered copy",
            actual.scenario
        );
        assert_eq!(
            actual.remaining_delivered_copies_immune, 0,
            "{} retained a copy at an immune node",
            actual.scenario
        );
        assert!(actual.max_purge_latency_ms <= 10_000);
    }

    let ablation = &got[2];
    let enabled = &got[3];
    assert!(
        ablation.remaining_copies > 0,
        "the ablation must populate stores or the purge proof is empty"
    );
    assert_eq!(enabled.remaining_copies, 0);
    assert_eq!(enabled.delivery_receipts, enabled.delivered);
}
