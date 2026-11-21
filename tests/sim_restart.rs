//! MSH-29 regression gate for restart state survival.
//!
//! Values come from `cargo run --features sim --example restart_report`.
//! Both rows use the same fixed seed and differ only in the `restore` bit, so
//! the replay delta is attributable to the snapshot rather than the topology.

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::sim::{restart_scenarios, run};

struct Expected {
    scenario: &'static str,
    seed: u64,
    submitted: u64,
    delivered: u64,
    transmissions: u64,
    snapshot_bytes: usize,
    replays: u64,
    sends_after: u64,
}

fn expected() -> Vec<Expected> {
    vec![
        Expected {
            scenario: "restart-lost-line-20",
            seed: 1_297_303_584,
            submitted: 20,
            delivered: 20,
            transmissions: 723,
            snapshot_bytes: 5_374,
            replays: 14,
            sends_after: 81,
        },
        Expected {
            scenario: "restart-restored-line-20",
            seed: 1_297_303_584,
            submitted: 20,
            delivered: 20,
            transmissions: 566,
            snapshot_bytes: 5_374,
            replays: 0,
            sends_after: 67,
        },
    ]
}

#[test]
fn a_restored_engine_does_not_re_relay_seen_packets() {
    let got: Vec<_> = restart_scenarios().into_iter().map(run).collect();
    let want = expected();
    assert_eq!(got.len(), want.len());
    for (actual, expected) in got.iter().zip(&want) {
        assert_eq!(actual.scenario, expected.scenario);
        assert_eq!(actual.seed, expected.seed);
        assert_eq!(actual.submitted, expected.submitted);
        assert_eq!(actual.delivered, expected.delivered);
        assert_eq!(actual.transmissions, expected.transmissions);
        assert_eq!(actual.restart_snapshot_bytes, expected.snapshot_bytes);
        assert_eq!(actual.restart_replays, expected.replays);
        assert_eq!(actual.restart_sends_after, expected.sends_after);
    }

    let lost = &got[0];
    let restored = &got[1];
    assert!(lost.restart_snapshot_bytes > 0);
    assert!(lost.restart_replays > 0, "the ablation must show re-relays");
    assert_eq!(restored.restart_replays, 0);
    assert!(
        restored.transmissions < lost.transmissions,
        "restoring state must remove the re-relay transmissions"
    );
    assert_eq!(restored.delivered, lost.delivered);
}
