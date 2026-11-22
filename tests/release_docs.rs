//! Documentation guards for the v0.1.0 release preparation (MSH-31).
//!
//! The baseline and parameter tables are copied into several documents. This
//! test compares those copies with the public defaults and the fixed-seed
//! gate, so a stale table fails `cargo test` rather than shipping in docs.

use ao_mesh::expiry::LifetimePolicy;
use ao_mesh::store::StoreLimits;
use ao_mesh::{
    MAX_FRAME_BODY_BYTES, MAX_SNAPSHOT_LEN, MAX_SUMMARY_ENTRIES, MeshConfig, SNAPSHOT_VERSION,
};

const README: &str = include_str!("../README.md");
const CHANGELOG: &str = include_str!("../CHANGELOG.md");
const PROTOCOL: &str = include_str!("../docs/protocol.md");
const ROUTING_ADR: &str = include_str!("../docs/adr/0001-routing-per-traffic-class.md");
const BASELINE_ADR: &str = include_str!("../docs/adr/simulator-baseline.md");
const RELEASE_NOTES: &str = include_str!("../docs/release-notes.md");
const BASELINE_GATE: &str = include_str!("sim_baseline.rs");
const LIB_RS: &str = include_str!("../src/lib.rs");

const BASELINE_ROWS: [&str; 4] = [
    "| `line-20` | 1297303584 | 20 / 20 | 1.0000 | 9.6500 | 727 / 1200 | 102065 | 550 |",
    "| `waypoint-50` | 1297303632 | 31 / 50 | 0.6200 | 125.7742 | 551 / 1200 | 2080893 | 12375 |",
    "| `community-100` | 1297303652 | 75 / 80 | 0.9375 | 328.7067 | 676 / 1200 | 13031341 | 33290 |",
    "| `scripted-200` | 1297303752 | 100 / 100 | 1.0000 | 34.5500 | 561 / 1200 | 1850727 | 6600 |",
];

const README_BASELINE_ROWS: [&str; 4] = [
    "| `line-20` | 20 | 1297303584 | 20 / 20 | 1.0000 | 9.6500 | 727 / 1200 | 102065 | 550 |",
    "| `waypoint-50` | 50 | 1297303632 | 31 / 50 | 0.6200 | 125.7742 | 551 / 1200 | 2080893 | 12375 |",
    "| `community-100` | 100 | 1297303652 | 75 / 80 | 0.9375 | 328.7067 | 676 / 1200 | 13031341 | 33290 |",
    "| `scripted-200` | 200 | 1297303752 | 100 / 100 | 1.0000 | 34.5500 | 561 / 1200 | 1850727 | 6600 |",
];

const GATE_FACTS: [&str; 8] = [
    "seed: 1_297_303_584,",
    "seed: 1_297_303_632,",
    "seed: 1_297_303_652,",
    "seed: 1_297_303_752,",
    "delivered: 20,",
    "delivered: 31,",
    "delivered: 75,",
    "radio_bytes: 13_031_341,",
];

#[test]
fn published_baseline_matches_readme_and_adr() {
    for (row, readme_row) in BASELINE_ROWS.iter().zip(README_BASELINE_ROWS) {
        assert!(
            README.contains(readme_row),
            "README is missing `{readme_row}`"
        );
        assert!(
            BASELINE_ADR.contains(*row),
            "baseline ADR is missing `{row}`"
        );
        assert!(
            RELEASE_NOTES.contains(*row),
            "release notes are missing `{row}`"
        );
    }
    for fact in GATE_FACTS {
        assert!(
            BASELINE_GATE.contains(fact),
            "the MSH-27 gate is missing `{fact}`"
        );
    }
}

fn rate_label(bytes_per_hour: u64) -> String {
    if bytes_per_hour % (1024 * 1024) == 0 {
        format!("{} MiB/h", bytes_per_hour / (1024 * 1024))
    } else {
        format!("{} KiB/h", bytes_per_hour / 1024)
    }
}

fn duration(ms: u64) -> String {
    if ms % 3_600_000 == 0 {
        format!("{} h", ms / 3_600_000)
    } else if ms % 60_000 == 0 {
        format!("{} min", ms / 60_000)
    } else {
        format!("{} s", ms / 1_000)
    }
}

#[test]
fn routing_defaults_match_adr_table() {
    let config = MeshConfig::default();
    let lifetime = LifetimePolicy::default();
    let rates = &config.budgets.rates;

    let rows = [
        format!(
            "| Direct | spray-and-wait with reverse-path hints | {} | {} | {} | {} | 1 |",
            config.suppression.direct_ttl,
            config.spray.copies,
            duration(lifetime.direct_s * 1000),
            rate_label(rates[0].bytes_per_hour)
        ),
        format!(
            "| Broadcast and channels | counter-based suppression | {} | 1 per node (forward once) | {} | {} | 2 |",
            config.suppression.broadcast_ttl,
            duration(lifetime.broadcast_s * 1000),
            rate_label(rates[1].bytes_per_hour)
        ),
        format!(
            "| Presence | trickle-timed gossip | {} | 1 per node | {} | {} | 3 |",
            config.suppression.presence_ttl,
            duration(lifetime.presence_s * 1000),
            rate_label(rates[2].bytes_per_hour)
        ),
        format!(
            "| Telemetry (location) | announce, latest-wins, never stored | {} | 1 per node | store ceiling {}, relay freshness {} | {} | 4 |",
            config.suppression.telemetry_ttl,
            duration(lifetime.telemetry_s * 1000),
            duration(config.telemetry.expiry_ms),
            rate_label(rates[3].bytes_per_hour)
        ),
    ];
    for row in rows {
        assert!(ROUTING_ADR.contains(&row), "ADR-0001 is missing `{row}`");
    }
    assert!(RELEASE_NOTES.contains("store ceiling 5 min"));
    assert!(RELEASE_NOTES.contains("30 s freshness"));
    assert!(rates.iter().all(|rate| rate.burst_seconds == 600));
    assert!(RELEASE_NOTES.contains("600 s burst"));
    assert_eq!(config.telemetry.expiry_ms, 30_000);
    assert_eq!(lifetime.telemetry_s, 300);
}

#[test]
fn untagged_sibling_seam_and_fuzz_location_are_documented() {
    assert!(CHANGELOG.contains("no tagged releases yet"));
    assert!(README.contains("pre-alpha and untagged"));
    assert!(RELEASE_NOTES.contains("uncommitted Cargo config"));
    assert!(PROTOCOL.contains("release-notes.md"));

    for doc in [CHANGELOG, RELEASE_NOTES, README, PROTOCOL] {
        assert!(
            !doc.contains("d3087f6ba8fc9b72a7236595d177290e5ff10869")
                && !doc.contains("0e9c36a38938412d993e0eea57df9b8a0d76c92f")
                && !doc.contains("tag = \"v0.1.0\""),
            "a document still claims an existing release tag"
        );
    }

    for doc in [PROTOCOL, ROUTING_ADR, CHANGELOG, LIB_RS] {
        assert!(
            !doc.contains("The `fuzz/` crate") && !doc.contains("the `fuzz/` targets"),
            "a local fuzz crate is still claimed in a release document"
        );
    }
    assert!(PROTOCOL.contains("aoheyra-fuzz"));
    assert!(ROUTING_ADR.contains("aoheyra-fuzz"));
}

#[test]
fn release_parameter_reference_matches_public_constants() {
    let store = StoreLimits::default();
    let config = MeshConfig::default();

    assert_eq!(config.max_neighbors, 32);
    assert_eq!(config.seen.capacity, 4096);
    assert_eq!(config.suppression.max_entries, 1024);
    assert_eq!(config.sync.max_bytes_per_contact, 256 * 1024);
    assert_eq!(config.sync.max_frame_bytes, 15 * 1024);
    assert_eq!(config.sync.range_leaf_ids, 32);
    assert_eq!(config.presence.max_entries, 1024);
    assert_eq!(config.directory.capacity, 256);
    assert_eq!(config.route_hint.max_entries, 1024);
    assert_eq!(store.entries, 1024);
    assert_eq!(store.total_bytes, 2 * 1024 * 1024);
    assert_eq!(MAX_SUMMARY_ENTRIES, 1024);
    assert_eq!(MAX_FRAME_BODY_BYTES, 8198);
    assert_eq!(SNAPSHOT_VERSION, 1);
    assert_eq!(MAX_SNAPSHOT_LEN, 4 * 1024 * 1024);

    assert!(RELEASE_NOTES.contains("32 neighbours"));
    assert!(RELEASE_NOTES.contains("4096 entries"));
    assert!(RELEASE_NOTES.contains("1024 entries, 2 MiB total, 256 KiB per origin"));
    assert!(RELEASE_NOTES.contains("8198"));
    assert!(RELEASE_NOTES.contains("version 1, 4 MiB maximum"));
}
