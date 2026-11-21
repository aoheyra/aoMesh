//! Writes the MSH-30 snapshot metrics as CSV.
//!
//! The extra columns are deliberately outside the published MSH-27 CSV
//! schema: they aggregate host-visible engine snapshots, not radio events.
//! The seed is fixed in [`ao_mesh::sim::observability_scenarios`].

use ao_mesh::sim::{observability_scenarios, run_observability};
use std::env;
use std::fs::File;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out: Box<dyn Write> = match env::args().nth(1) {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout().lock()),
    };
    writeln!(
        out,
        "scenario,seed,nodes,submitted,delivered,duplicate_packets,suppressed_relays,store_entries,sync_bytes_sent,sync_bytes_received,neighbour_penalty_events,neighbour_penalty_total,neighbour_penalty_max,penalised_neighbours,seen_records,suppression_pending"
    )?;
    for experiment in observability_scenarios() {
        let m = run_observability(experiment);
        writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            m.scenario,
            m.seed,
            m.nodes,
            m.submitted,
            m.delivered,
            m.duplicate_packets,
            m.suppressed_relays,
            m.store_entries,
            m.sync_bytes_sent,
            m.sync_bytes_received,
            m.neighbour_penalty_events,
            m.neighbour_penalty_total,
            m.neighbour_penalty_max,
            m.penalised_neighbours,
            m.seen_records,
            m.suppression_pending,
        )?;
    }
    Ok(())
}
