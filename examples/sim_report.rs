//! Writes the reproducible MSH-27 baseline report as CSV.
//!
//! With no argument the report goes to stdout. With a path argument it is
//! written there instead, so CI can archive the exact numbers it checked.

use ao_mesh::sim::{Metrics, baseline_scenarios, run};
use std::env;
use std::fs::File;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out: Box<dyn Write> = match env::args().nth(1) {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout().lock()),
    };
    writeln!(out, "{}", Metrics::csv_header())?;
    for scenario in baseline_scenarios() {
        writeln!(out, "{}", run(scenario).csv_row())?;
    }
    Ok(())
}
