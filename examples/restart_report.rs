//! Writes the MSH-29 restart-versus-ablation comparison as CSV.
//!
//! Both rows differ only in whether the host restores the snapshot. The extra
//! columns are outside the published MSH-27 CSV schema because they measure
//! restart state, not radio behaviour.

use ao_mesh::sim::{restart_scenarios, run};
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
        "scenario,seed,nodes,submitted,delivered,transmissions,restart_snapshot_bytes,restart_replays,restart_sends_after"
    )?;
    for scenario in restart_scenarios() {
        let m = run(scenario);
        writeln!(
            out,
            "{},{},{},{},{},{},{},{},{}",
            m.scenario,
            m.seed,
            m.nodes,
            m.submitted,
            m.delivered,
            m.transmissions,
            m.restart_snapshot_bytes,
            m.restart_replays,
            m.restart_sends_after,
        )?;
    }
    Ok(())
}
