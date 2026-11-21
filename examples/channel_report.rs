//! Writes the MSH-23 public-channel reachability and budget row as CSV.
//!
//! The columns are outside the published MSH-27 radio schema because they
//! measure local channel delivery and the Broadcast allowance, not general
//! forwarding. Both the fixed seed and the exact row are asserted in
//! `tests/sim_channels.rs`.

use ao_mesh::sim::{channel_scenarios, run};
use std::env;
use std::fs::File;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out: Box<dyn Write> = match env::args().nth(1) {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout().lock()),
    };
    writeln!(out, "{}", ao_mesh::sim::Metrics::channel_csv_header())?;
    for scenario in channel_scenarios() {
        writeln!(out, "{}", run(scenario).channel_csv_row())?;
    }
    Ok(())
}
