//! Writes the MSH-22 telemetry scenarios as CSV.
//!
//! The columns are deliberately outside the published MSH-27 schema:
//! they measure latest-wins acceptance and the observable result of
//! NET-21 send-queue coalescing, not sealed-message delivery.

use ao_mesh::sim::{run, telemetry_scenarios};
use std::env;
use std::fs::File;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out: Box<dyn Write> = match env::args().nth(1) {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout().lock()),
    };
    writeln!(out, "{}", ao_mesh::sim::Metrics::telemetry_csv_header())?;
    for scenario in telemetry_scenarios() {
        writeln!(out, "{}", run(scenario).telemetry_csv_row())?;
    }
    Ok(())
}
