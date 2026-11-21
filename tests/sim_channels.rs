//! MSH-23 simulation evidence: every in-range subscriber receives the signed
//! channel message, and the envelope traffic stays inside the Broadcast
//! allowance. The row is exact so CI detects any reachability regression.

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::sim::{Metrics, Traffic, channel_scenarios, run};

// MSH-19 raised suppression's effective floor to two distinct sending links,
// so every line relay forwards once. The pre-MSH-19 expectation was two sends.
const EXPECTED_ROW: &str = "channel-line-20,1297304023,20,1,2,2,12,3048,43690,true";

#[test]
fn signed_channel_message_reaches_every_in_range_subscriber_within_budget() {
    let scenarios = channel_scenarios();
    assert_eq!(scenarios.len(), 1);
    let scenario = scenarios
        .into_iter()
        .next()
        .expect("one channel scenario is configured");
    let (origin, subscribers) = match scenario.traffic {
        Traffic::Channel {
            origin,
            subscribers,
            ..
        } => (origin, subscribers),
        other => panic!("channel scenario expected, got {other:?}"),
    };
    assert_eq!(origin, 10);
    assert_eq!(subscribers, &[9, 11]);

    let metrics: Metrics = run(scenario);
    assert_eq!(metrics.channel_csv_row(), EXPECTED_ROW);
    assert_eq!(metrics.submitted, 1);
    assert_eq!(metrics.channel_subscribers, 2);
    assert_eq!(metrics.channel_deliveries, 2);
    assert_eq!(metrics.channel_delivered_ids[9].len(), 1);
    assert_eq!(metrics.channel_delivered_ids[11].len(), 1);
    for node in 0..metrics.nodes {
        if node != 9 && node != 11 {
            assert!(
                metrics.channel_delivered_ids[node].is_empty(),
                "node {node} is not a subscriber"
            );
        }
    }

    let burst = ao_mesh::BudgetConfig::default().rates
        [ao_mesh::PacketClass::Broadcast as usize - 1]
        .burst_bytes();
    assert_eq!(metrics.channel_bytes, 3_048);
    assert!(metrics.channel_bytes <= burst);
}
