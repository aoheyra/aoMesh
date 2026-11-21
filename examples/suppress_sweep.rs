use ao_mesh::sim::{run, suppression_scenarios};
use ao_mesh::SuppressionConfig;

fn main() {
    let base = suppression_scenarios().remove(0);
    let ablation = {
        let mut s = base.clone();
        s.enforce_suppression = false;
        run(s)
    };
    println!(
        "ablation transmissions={} delivered={}",
        ablation.transmissions, ablation.delivered
    );
    let variants: Vec<(&str, SuppressionConfig)> = vec![
        ("default", SuppressionConfig::default()),
        ("k2-max3", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 3;
            c
        }),
        ("k2-max4", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 4;
            c
        }),
        ("k2-max6", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c
        }),
        ("delay200", {
            let mut c = SuppressionConfig::default();
            c.min_base_delay_ms = 200;
            c.max_base_delay_ms = 400;
            c
        }),
        ("k2-max3-delay200", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 3;
            c.min_base_delay_ms = 200;
            c.max_base_delay_ms = 400;
            c
        }),
        ("min2-max6", {
            let mut c = SuppressionConfig::default();
            c.min_k = 2;
            c
        }),
        ("always2", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 2;
            c
        }),
        ("always2-delay400", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 2;
            c.min_base_delay_ms = 400;
            c.max_base_delay_ms = 800;
            c
        }),
        ("k2-max3-delay400", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 3;
            c.min_base_delay_ms = 400;
            c.max_base_delay_ms = 800;
            c
        }),
        ("k3-max3-delay400", {
            let mut c = SuppressionConfig::default();
            c.max_k = 3;
            c.min_base_delay_ms = 400;
            c.max_base_delay_ms = 800;
            c
        }),
        ("degree8-delay400", {
            let mut c = SuppressionConfig::default();
            c.degree_ref = 8;
            c.min_base_delay_ms = 400;
            c.max_base_delay_ms = 800;
            c
        }),
        ("always2-delay100", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 2;
            c.min_base_delay_ms = 100;
            c.max_base_delay_ms = 200;
            c
        }),
        ("always2-delay150", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 2;
            c.min_base_delay_ms = 150;
            c.max_base_delay_ms = 300;
            c
        }),
        ("always2-delay250", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 2;
            c.min_base_delay_ms = 250;
            c.max_base_delay_ms = 500;
            c
        }),
        ("always2-delay300", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 2;
            c.min_base_delay_ms = 300;
            c.max_base_delay_ms = 600;
            c
        }),
        ("always2-delay250-ref6", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 2;
            c.degree_ref = 6;
            c.min_base_delay_ms = 250;
            c.max_base_delay_ms = 500;
            c
        }),
        ("always2-delay250-ref8", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 2;
            c.degree_ref = 8;
            c.min_base_delay_ms = 250;
            c.max_base_delay_ms = 500;
            c
        }),
        ("always2-delay250-cap300", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 2;
            c.min_base_delay_ms = 250;
            c.max_base_delay_ms = 500;
            c.max_delay_ms = 300;
            c
        }),
        ("always2-delay250-floor50", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 2;
            c.max_k = 2;
            c.min_base_delay_ms = 250;
            c.max_base_delay_ms = 500;
            c.min_delay_ms = 50;
            c
        }),
        ("always3-delay400", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 3;
            c.max_k = 3;
            c.min_base_delay_ms = 400;
            c.max_base_delay_ms = 800;
            c.max_delay_ms = 1500;
            c
        }),
        ("always3-delay600", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 3;
            c.max_k = 3;
            c.min_base_delay_ms = 600;
            c.max_base_delay_ms = 1000;
            c.max_delay_ms = 2000;
            c
        }),
        ("always3-delay1000", {
            let mut c = SuppressionConfig::default();
            c.k_at_degree_ref = 3;
            c.max_k = 3;
            c.min_base_delay_ms = 1000;
            c.max_base_delay_ms = 2000;
            c.max_delay_ms = 4000;
            c
        }),
        ("default-delay600", {
            let mut c = SuppressionConfig::default();
            c.min_base_delay_ms = 600;
            c.max_base_delay_ms = 1000;
            c.max_delay_ms = 2000;
            c
        }),
    ];
    for (name, config) in variants {
        let mut s = base.clone();
        s.suppression = config;
        let m = run(s);
        let reduction = (ablation.transmissions - m.transmissions) as f64
            / ablation.transmissions.max(1) as f64;
        println!(
            "{name:20} transmissions={:5} reduction={:6.2}% delivered={:3} ratio={:.3} suppressed={}",
            m.transmissions,
            reduction * 100.0,
            m.delivered,
            m.delivery_ratio,
            m.suppressed_relays
        );
    }
}
