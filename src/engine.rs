//! The sans-IO engine: `(now, input) -> outputs`, injected RNG, no I/O.

use rand_core::RngCore;

/// One input to [`MeshEngine::handle`].
///
/// Non-exhaustive: MSH-03 onward adds packet and neighbour inputs; callers
/// outside this crate match with a wildcard arm.
#[non_exhaustive]
pub enum MeshInput {
    /// Time-driven step. `now` (unix milliseconds) is carried by `handle`'s
    /// first parameter, not by this variant.
    Tick,
}

/// One output of [`MeshEngine::handle`].
///
/// Empty in M0: the engine produces no actions until packet parsing (MSH-03)
/// and the network adapter (MSH-06) exist. Non-exhaustive so outputs can be
/// added without breaking callers.
#[non_exhaustive]
pub enum MeshOutput {}

/// The mesh engine core.
///
/// Deterministic: the same RNG seed and the same input sequence produce the
/// same outputs, so the simulator (MSH-27) and the fuzzers (MSH-28) reproduce
/// runs exactly.
pub struct MeshEngine<R: RngCore> {
    // The injected RNG is part of the M0 interface contract (MSH-01); the
    // first read lands in MSH-03 onward (jitter, suppression). Silencing
    // dead_code here is justified until then — removing the field would
    // change the constructor's signature twice.
    #[allow(dead_code)]
    rng: R,
}

impl<R: RngCore> MeshEngine<R> {
    /// Creates an engine over an injected RNG.
    ///
    /// Seeding it (`StdRng::seed_from_u64`, for example) fixes the whole
    /// run's randomness; nothing in the engine creates its own.
    pub fn new(rng: R) -> Self {
        Self { rng }
    }

    /// Runs one engine step and returns the outputs to act on.
    ///
    /// `now` is unix milliseconds supplied by the caller's clock. The M0
    /// engine ignores it and emits nothing; MSH-03 onward schedules from it.
    pub fn handle(&mut self, _now: u64, input: MeshInput) -> Vec<MeshOutput> {
        match input {
            MeshInput::Tick => {}
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn no_op_loop_emits_nothing() {
        let mut engine = MeshEngine::new(StdRng::seed_from_u64(42));
        for now in 0..1_000u64 {
            let outputs = engine.handle(now, MeshInput::Tick);
            assert!(outputs.is_empty(), "M0 engine must be a no-op at {now}");
        }
    }
}
