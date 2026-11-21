//! Writes the MSH-17 receipt-versus-ablation purge comparison as CSV.
//!
//! Both rows use spray so stores are populated; only the receipt capability
//! differs. The extra columns are deliberately outside the published MSH-27
//! CSV schema because they measure host-store state, not radio behaviour.

use ao_mesh::sim::{receipt_scenarios, run};
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
        "scenario,seed,nodes,submitted,delivered,delivery_receipts,purges,remaining_copies,remaining_delivered_copies,remaining_delivered_copies_immune,max_purge_latency_ms,transmissions"
    )?;
    for scenario in receipt_scenarios() {
        let m = run(scenario);
        writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            m.scenario,
            m.seed,
            m.nodes,
            m.submitted,
            m.delivered,
            m.delivery_receipts,
            m.purges,
            m.remaining_copies,
            m.remaining_delivered_copies,
            m.remaining_delivered_copies_immune,
            m.max_purge_latency_ms,
            m.transmissions,
        )?;
    }
    Ok(())
}
