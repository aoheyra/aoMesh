//! Writes the reproducible MSH-19 presence report as CSV.
//!
//! With no argument the report goes to stdout. With a path argument it is
//! written there instead, so CI can archive the exact convergence and
//! overhead numbers it checked.

use ao_mesh::sim::{Metrics, presence_scenarios, run};
use std::env;
use std::fs::File;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out: Box<dyn Write> = match env::args().nth(1) {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout().lock()),
    };
    writeln!(out, "{}", Metrics::csv_header())?;
    for scenario in presence_scenarios() {
        writeln!(out, "{}", run(scenario).csv_row())?;
    }
    Ok(())
}
