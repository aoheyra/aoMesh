//! MSH-10 simulation evidence: a flooded origin is throttled while honest
//! origins keep their delivery.

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::sim::{flood_scenarios, run};

#[test]
fn flood_origin_is_throttled_without_hurting_honest_origins() {
    let scenario = flood_scenarios()
        .into_iter()
        .next()
        .expect("flood scenario is configured");
    let bounded = run(scenario.clone());
    let mut ablation = scenario.clone();
    ablation.enforce_budgets = false;
    let unbounded = run(ablation);
    let mut honest_only = scenario.clone();
    honest_only.traffic = ao_mesh::sim::Traffic::Balanced;
    honest_only.messages = scenario.messages / 2;
    let baseline = run(honest_only.clone());

    let (flood, weight) = match scenario.traffic {
        ao_mesh::sim::Traffic::Flood { origin, weight } => (origin, weight),
        ao_mesh::sim::Traffic::Balanced
        | ao_mesh::sim::Traffic::Broadcast { .. }
        | ao_mesh::sim::Traffic::MixedBroadcast { .. }
        | ao_mesh::sim::Traffic::Presence => panic!("flood scenario expected"),
    };
    let round = weight + 1;
    let flood_count = scenario.messages.div_ceil(round);
    let flood_submitted = flood_count as f64;
    let honest_submitted = (scenario.messages - flood_count) as f64;
    let honest_sum = |metrics: &ao_mesh::sim::Metrics| -> u64 {
        metrics
            .delivered_by_origin
            .iter()
            .enumerate()
            .map(|(i, n)| if i == flood { 0 } else { *n })
            .sum()
    };
    let honest_bounded = honest_sum(&bounded);
    let honest_unbounded = honest_sum(&unbounded);
    let honest_baseline = honest_sum(&baseline);
    let baseline_submitted = (0..honest_only.messages)
        .filter(|m| m % honest_only.nodes != flood)
        .count() as f64;

    println!("bounded flood: {:?}", bounded.delivered_by_origin);
    println!("unbounded flood: {:?}", unbounded.delivered_by_origin);
    println!("honest baseline: {:?}", baseline.delivered_by_origin);
    println!("baseline submitted: {baseline_submitted}");
    println!(
        "flood ratio bounded={:.4} unbounded={:.4}",
        bounded.delivered_by_origin[flood] as f64 / flood_submitted,
        unbounded.delivered_by_origin[flood] as f64 / flood_submitted
    );
    println!(
        "honest ratio bounded={:.4} unbounded={:.4} baseline={:.4}",
        honest_bounded as f64 / honest_submitted,
        honest_unbounded as f64 / honest_submitted,
        honest_baseline as f64 / baseline_submitted
    );

    assert!(unbounded.delivered_by_origin[flood] > bounded.delivered_by_origin[flood]);
    assert!(bounded.delivered_by_origin[flood] * 2 < unbounded.delivered_by_origin[flood]);
    // Throttling the flood cannot make honest origins worse than leaving it
    // unchecked, and keeps them near their no-flood delivery ratio. The
    // small remaining gap is radio contention from the flooder's own first
    // transmission, which no relay budget can prevent.
    assert!(honest_bounded >= honest_unbounded);
    assert!(
        honest_bounded as f64 / honest_submitted
            >= 0.9 * (honest_baseline as f64 / baseline_submitted)
    );
}
