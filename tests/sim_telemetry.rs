//! MSH-22 regression gate for latest-wins telemetry.
//!
//! Values come from `cargo run --example telemetry_report --features sim`.
//! The first row bursts eight updates into a slow send queue: each receiver
//! sees the first in-flight frame and the one newest pending frame, never
//! the six intermediate versions. The second row sends twelve updates from
//! one origin under the default throttle, so only the first is accepted.
//! Seeds are fixed in [`ao_mesh::sim::telemetry_scenarios`].

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::sim::{run, telemetry_scenarios};

#[test]
fn telemetry_coalesces_a_burst_and_throttles_a_chatty_origin() {
    let metrics: Vec<_> = telemetry_scenarios().into_iter().map(run).collect();
    let rows: Vec<_> = metrics.iter().map(|m| m.telemetry_csv_row()).collect();
    assert_eq!(
        rows,
        [
            "telemetry-slow-line-5,1297304023,5,8,8,0,6,6,2,8,12,1176",
            "telemetry-chatty-random-20,1297304029,20,12,1,11,0,0,0,0,0,360",
        ]
    );

    let slow = &metrics[0];
    assert_eq!(slow.telemetry_attempts, 8);
    assert_eq!(slow.telemetry_accepted, 8);
    assert_eq!(slow.telemetry_max_seq, 8);
    assert_eq!(
        slow.telemetry_max_seqs_per_node, 2,
        "a slow queue may hold one pending update beside the in-flight one"
    );
    assert_eq!(
        slow.remaining_copies, 0,
        "telemetry must never enter a store"
    );

    let chatty = &metrics[1];
    assert_eq!(chatty.telemetry_attempts, 12);
    assert_eq!(chatty.telemetry_accepted, 1);
    assert_eq!(chatty.telemetry_rejected, 11);
    assert_eq!(chatty.telemetry_receptions, 0);
    assert_eq!(chatty.transmissions, 0);
    assert_eq!(
        chatty.remaining_copies, 0,
        "telemetry must never enter a store"
    );
}
