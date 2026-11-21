//! Writes the MSH-15 v1-versus-v2 contact-cost report as CSV.
//!
//! With no argument the report goes to stdout. With a path argument it is
//! written there instead, so CI can archive the exact numbers it checked.

use ao_mesh::sim::{SyncComparison, run_sync_comparison};
use std::env;
use std::fs::File;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const SEED: u64 = 0x515f_2026;
    const LOCAL: usize = 1_000;
    const REMOTE: usize = 1_001;

    let mut out: Box<dyn Write> = match env::args().nth(1) {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout().lock()),
    };
    writeln!(out, "{}", SyncComparison::csv_header())?;
    for mode in ["v1", "v2"] {
        writeln!(
            out,
            "{}",
            run_sync_comparison(mode, SEED, LOCAL, REMOTE).csv_row()
        )?;
    }
    Ok(())
}
