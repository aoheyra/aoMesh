//! MSH-25 regression gate for the paired link-hint report.
//!
//! Values come from
//! `cargo run --release --features sim --example linkhint_report` with the
//! four fixed seeds in [`ao_mesh::sim::link_hint_scenarios`]. Each pair shares
//! topology, mobility, traffic, budgets and RNG; only the host-supplied hint
//! plan differs. Delivery, latency and overhead are unchanged, so the measured
//! effect is time-to-link in aoNetwork's real hint table.

#![cfg(all(feature = "sim", not(miri)))]

use ao_mesh::sim::{link_hint_scenarios, run};

struct Expected {
    scenario: &'static str,
    seed: u64,
    delivered: u64,
    transmissions: u64,
    mean_latency_ms: u64,
    targets: usize,
    linked: usize,
    mean_link_ms: u64,
    sets: u64,
    clears: u64,
}

fn expected() -> Vec<Expected> {
    let rows = [
        ("linkhint-off-scripted-20-a", 1_297_303_701, 0, 0, 0, 0, 0),
        ("linkhint-on-scripted-20-a", 1_297_303_701, 3, 3, 383, 3, 0),
        ("linkhint-off-scripted-20-b", 1_297_303_702, 0, 0, 0, 0, 0),
        ("linkhint-on-scripted-20-b", 1_297_303_702, 3, 3, 350, 3, 0),
        ("linkhint-off-scripted-20-c", 1_297_303_703, 0, 0, 0, 0, 0),
        ("linkhint-on-scripted-20-c", 1_297_303_703, 3, 3, 366, 3, 0),
        ("linkhint-off-scripted-20-d", 1_297_303_704, 0, 0, 0, 0, 0),
        ("linkhint-on-scripted-20-d", 1_297_303_704, 3, 3, 383, 3, 0),
    ];
    rows.into_iter()
        .map(
            |(scenario, seed, targets, linked, mean_link_ms, sets, clears)| Expected {
                scenario,
                seed,
                delivered: 16,
                transmissions: 238,
                mean_latency_ms: if seed == 1_297_303_701 { 687 } else { 684 },
                targets,
                linked,
                mean_link_ms,
                sets,
                clears,
            },
        )
        .collect()
}

#[test]
fn contact_hints_link_contacts_within_bound_without_changing_delivery() {
    let got: Vec<_> = link_hint_scenarios().into_iter().map(run).collect();
    let want = expected();
    assert_eq!(got.len(), want.len());
    for (actual, expected) in got.iter().zip(&want) {
        assert_eq!(actual.scenario, expected.scenario);
        assert_eq!(actual.seed, expected.seed);
        assert_eq!(actual.delivered, expected.delivered);
        assert_eq!(actual.transmissions, expected.transmissions);
        assert_eq!(actual.mean_latency_ms, expected.mean_latency_ms);
        assert_eq!(actual.link_hint_targets, expected.targets);
        assert_eq!(actual.link_hint_links_within_bound, expected.linked);
        assert_eq!(actual.link_hint_mean_link_ms, expected.mean_link_ms);
        assert_eq!(actual.link_hint_sets, expected.sets);
        assert_eq!(actual.link_hint_clears, expected.clears);
        assert_eq!(
            actual.send_failures, 0,
            "{} refused a send",
            actual.scenario
        );
    }

    let off_linked: usize = got
        .iter()
        .step_by(2)
        .map(|m| m.link_hint_links_within_bound)
        .sum();
    let on_linked: usize = got
        .iter()
        .skip(1)
        .step_by(2)
        .map(|m| m.link_hint_links_within_bound)
        .sum();
    assert_eq!(off_linked, 0);
    assert_eq!(on_linked, 12, "every seeded contact is linked in time");
    assert!(
        got.iter()
            .skip(1)
            .step_by(2)
            .all(|m| m.link_hint_mean_link_ms <= 1_000)
    );
}
