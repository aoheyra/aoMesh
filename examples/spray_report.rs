//! Writes the MSH-16 relay-versus-spray comparison as CSV.
//!
//! Both rows use the same MSH-27 waypoint seed; only the spray capability
//! differs, so delivery and transmission changes are attributable to MSH-16.

use ao_mesh::sim::{Metrics, run, spray_scenarios};
use std::env;
use std::fs::File;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out: Box<dyn Write> = match env::args().nth(1) {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout().lock()),
    };
    writeln!(out, "{}", Metrics::csv_header())?;
    for scenario in spray_scenarios() {
        writeln!(out, "{}", run(scenario).csv_row())?;
    }
    Ok(())
}
