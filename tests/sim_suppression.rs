//! MSH-11 simulation evidence: suppression cuts flood transmissions without
//! moving the MSH-27 delivery ratio.

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::sim::{run, suppression_scenarios};

#[test]
fn suppression_reduces_transmissions_without_hurting_delivery() {
    let scenario = suppression_scenarios()
        .into_iter()
        .next()
        .expect("suppression scenario is configured");
    let mut ablation = scenario.clone();
    ablation.enforce_suppression = false;
    let suppressed = run(scenario.clone());
    let flooded = run(ablation);

    let reduction = (flooded.transmissions - suppressed.transmissions) as f64
        / flooded.transmissions.max(1) as f64;
    let suppressed_ratio = suppressed.delivery_ratio;
    let flooded_ratio = flooded.delivery_ratio;

    println!("suppressed: {:?}", suppressed);
    println!("flooded: {:?}", flooded);
    println!("transmission reduction: {reduction:.4}");
    println!("delivery suppressed={suppressed_ratio:.4} flooded={flooded_ratio:.4}");

    assert!(
        reduction >= 0.40,
        "suppression only saved {:.1}% of transmissions",
        reduction * 100.0
    );
    assert!(
        suppressed_ratio + 0.02 >= flooded_ratio,
        "suppression hurt delivery: {suppressed_ratio:.4} < {flooded_ratio:.4}"
    );
    assert!(
        suppressed.send_failures <= flooded.send_failures,
        "suppression must not add radio contention"
    );
}
