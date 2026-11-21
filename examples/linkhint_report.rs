//! Writes the MSH-25 hints-off / hints-on comparison as CSV.
//!
//! Both rows share the same seed, scripted radio contacts and traffic. The
//! extra columns report time-to-link for the owner's recognised contacts and
//! the bounded number of advisory outputs emitted through the real
//! aoNetwork link-hint API.

use ao_mesh::sim::{link_hint_scenarios, run};
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
        "scenario,seed,nodes,submitted,delivered,transmissions,mean_latency_ms,overhead,link_hint_targets,link_hint_links_within_bound,link_hint_mean_link_ms,link_hint_sets,link_hint_clears"
    )?;
    for scenario in link_hint_scenarios() {
        let m = run(scenario);
        writeln!(
            out,
            "{},{},{},{},{},{},{},{:.4},{},{},{},{},{}",
            m.scenario,
            m.seed,
            m.nodes,
            m.submitted,
            m.delivered,
            m.transmissions,
            m.mean_latency_ms,
            m.overhead,
            m.link_hint_targets,
            m.link_hint_links_within_bound,
            m.link_hint_mean_link_ms,
            m.link_hint_sets,
            m.link_hint_clears,
        )?;
    }
    Ok(())
}
