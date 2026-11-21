//! Temporary diagnostic (not for commit): sweep suppression parameters.
use ao_mesh::sim::{run, suppression_scenarios};
use ao_mesh::SuppressionConfig;

fn main() {
    let mut base = suppression_scenarios().remove(0);
    base.traffic = ao_mesh::sim::Traffic::Broadcast { origin: 0 };
    let ablation = {
        let mut s = base.clone();
        s.enforce_suppression = false;
        run(s)
    };
    println!(
        "ablation transmissions={} delivered={} unique={}",
        ablation.transmissions, ablation.delivered, ablation.unique_receptions
    );
    let mut variants: Vec<(&str, SuppressionConfig)> = Vec::new();
    for (name, lo, hi, cap) in [
        ("k2-d100", 100, 200, 600),
        ("k2-d250", 250, 500, 600),
        ("k2-d500", 500, 1000, 2000),
        ("k2-d1000", 1000, 2000, 4000),
        ("k2-d2000", 2000, 4000, 8000),
        ("k3-d250", 250, 500, 600),
        ("k3-d1000", 1000, 2000, 4000),
    ] {
        let k = if name.starts_with("k3") { 3 } else { 2 };
        let mut c = SuppressionConfig::default();
        c.k_at_degree_ref = k;
        c.max_k = k;
        c.min_base_delay_ms = lo;
        c.max_base_delay_ms = hi;
        c.max_delay_ms = cap;
        variants.push((name, c));
    }
    // Constant delay (no degree scaling), k=2.
    for (name, d) in [("k2-const100", 100), ("k2-const250", 250), ("k2-const500", 500)] {
        let mut c = SuppressionConfig::default();
        c.k_at_degree_ref = 2;
        c.max_k = 2;
        c.min_base_delay_ms = d;
        c.max_base_delay_ms = d;
        c.min_delay_ms = d;
        c.max_delay_ms = d;
        variants.push((name, c));
    }
    for (name, config) in variants {
        let mut s = base.clone();
        s.suppression = config;
        let m = run(s);
        let reduction = (ablation.transmissions - m.transmissions) as f64
            / ablation.transmissions.max(1) as f64;
        println!(
            "{name:16} tx={:5} reduction={:6.2}% delivered={:3} ratio={:.3} suppressed={:4} unique={:4} pending={}",
            m.transmissions,
            reduction * 100.0,
            m.delivered,
            m.delivery_ratio,
            m.suppressed_relays,
            m.unique_receptions,
            m.suppression_pending
        );
        if name == "k2-d500" || name == "k2-const250" {
            println!("  per-node: {:?}", m.unique_receptions_by_node);
        }
    }
}
