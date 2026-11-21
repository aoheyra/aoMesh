//! MSH-20 regression gate for the bounded, ephemeral node directory.
//!
//! Values come from `cargo run --all-features --example directory_report`.
//! The seed and schedule are fixed in [`ao_mesh::sim::directory_scenarios`].
//! No MSH-27 threshold is lowered or changed here: the directory path is
//! additive and emits no radio traffic.

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::sim::{directory_scenarios, run};

#[test]
fn directory_capacity_is_never_exceeded_and_entries_expire_on_schedule() {
    let scenarios = directory_scenarios();
    let capacity = scenarios[0]
        .directory
        .as_ref()
        .map_or(0, |plan| plan.config.capacity);
    let stale_after_ms = scenarios[0]
        .directory
        .as_ref()
        .map_or(0, |plan| plan.config.stale_after_ms);
    let rows: Vec<_> = scenarios.into_iter().map(run).collect();

    assert_eq!(rows.len(), 1);
    let got = &rows[0];
    assert_eq!(got.scenario, "directory-line-6");
    assert_eq!(got.seed, 1_297_304_021);
    assert_eq!(got.nodes, 6);
    assert_eq!(capacity, 4);
    assert_eq!(stale_after_ms, 2_000);

    // Locked numbers from the fixed seed. A capacity or expiry regression
    // changes at least one of them.
    assert_eq!(got.directory_peak_entries, 4);
    assert_eq!(got.directory_expirations, 24);
    assert_eq!(got.directory_evictions, 24);
    assert_eq!(got.directory_last_removal_ms, 2_000);
    assert_eq!(got.directory_live_entries, 0);

    assert!(got.directory_peak_entries <= capacity);
    assert!(got.directory_expirations > 0);
    // The last observation round lands at 2,000 ms. Capacity is four nodes
    // on a six-node line, so later rounds evict the oldest entries before
    // their 2,000 ms relative lifetime; the last removal is therefore at the
    // end of the observation window, not two lifetimes later. Expirations
    // still occur, and no entry survives the run.
    assert!(got.directory_last_removal_ms >= stale_after_ms);
}
