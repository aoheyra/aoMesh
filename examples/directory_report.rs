//! Writes the MSH-20 bounded-directory scenario as CSV.
//!
//! The extra columns are deliberately outside the published MSH-27 CSV
//! schema: they measure ephemeral directory state, not radio behaviour.

use ao_mesh::sim::{directory_scenarios, run};
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
        "scenario,seed,nodes,capacity,peak_entries,expirations,evictions,last_removal_ms,live_entries"
    )?;
    for scenario in directory_scenarios() {
        let capacity = scenario
            .directory
            .as_ref()
            .map_or(0, |plan| plan.config.capacity);
        let m = run(scenario);
        writeln!(
            out,
            "{},{},{},{},{},{},{},{},{}",
            m.scenario,
            m.seed,
            m.nodes,
            capacity,
            m.directory_peak_entries,
            m.directory_expirations,
            m.directory_evictions,
            m.directory_last_removal_ms,
            m.directory_live_entries,
        )?;
    }
    Ok(())
}
