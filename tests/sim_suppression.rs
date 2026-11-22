//! MSH-11 simulation evidence: suppression cuts flood transmissions without
//! moving the MSH-27 delivery ratio.

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::sim::{run, suppression_scenarios};

#[test]
fn suppression_seed_1297304013_cuts_flood_without_hurting_delivery() {
    // FIX 38 regression seed: the pre-fix two-link floor on every flooded
    // class capped this case at a 33.72% saving against the same 5801 flood.
    let scenario = suppression_scenarios()
        .into_iter()
        .next()
        .expect("suppression scenario is configured");
    assert_eq!(
        scenario.seed, 1_297_304_013,
        "FIX 38 regression seed changed"
    );
    assert_eq!(scenario.nodes, 50);
    assert_eq!(scenario.messages, 100);
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

    assert_eq!(suppressed.seed, 1_297_304_013, "suppression seed changed");
    assert_eq!(flooded.transmissions, 5801, "flood baseline changed");
    assert_eq!(
        suppressed.transmissions, 3277,
        "FIX 38 scoped-floor transmission count changed"
    );
    assert_eq!(suppressed.delivered, 2);
    assert_eq!(flooded.delivered, 2);
    assert_eq!(suppressed.unique_receptions, 1479);
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
