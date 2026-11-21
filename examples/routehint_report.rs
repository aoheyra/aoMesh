//! Writes the MSH-21 hint-off / hint-on comparison as CSV.
//!
//! Every row uses the same seed, topology, traffic and spray settings; only
//! the hint mode changes. The last three columns are the fresh-path diagnostic
//! supplied by the harness's MSH-20 directory observation seam.

use ao_mesh::sim::{route_hint_scenarios, run};
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
        "scenario,seed,nodes,submitted,delivered,transmissions,mean_latency_ms,fresh_hint_submissions,fresh_hint_deliveries,fresh_hint_mean_latency_ms,overhead"
    )?;
    for scenario in route_hint_scenarios() {
        let m = run(scenario);
        writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{},{:.4}",
            m.scenario,
            m.seed,
            m.nodes,
            m.submitted,
            m.delivered,
            m.transmissions,
            m.mean_latency_ms,
            m.fresh_hint_submissions,
            m.fresh_hint_deliveries,
            m.fresh_hint_mean_latency_ms,
            m.overhead,
        )?;
    }
    Ok(())
}
