//! Bounded counters and the versioned diagnostics snapshot (MSH-30).
//!
//! Debugging a mesh on a phone needs counters, not log archaeology. Every
//! counter here is a fixed-width saturating integer owned by the module that
//! makes the decision (the seen cache, suppression table, budget tracker or
//! sync tracker); the engine only reads them and derives gauges from its
//! existing bounded state. No new map, queue, key, payload or I/O is added.
//!
//! [`MeshSnapshot`] is plain data with integer fields only, so aoheyra can map
//! it straight into APP-15's diagnostics bundle without an aoMesh-specific
//! adapter type. The `version` field is the schema discriminator: a host that
//! does not know it must ignore the unfamiliar fields rather than guess.

/// Schema version of [`MeshSnapshot`]. Bump when a field's meaning changes or
/// a field is added or removed; hosts switch on this before reading fields.
pub const MESH_SNAPSHOT_VERSION: u8 = 1;

/// A plain-data view of bounded mesh counters and gauges.
///
/// All values are deterministic under a fixed input stream. Cumulative
/// counters saturate at `u64::MAX` instead of wrapping; gauges describe only
/// state that is already held by the engine and are bounded by `MeshConfig`.
/// No field carries packet content, message ids, keys or personal data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MeshSnapshot {
    /// Schema version, always [`MESH_SNAPSHOT_VERSION`].
    pub version: u8,
    /// Duplicate verdicts from the forwarding dedupe cache, saturating.
    ///
    /// Includes relay repeats and flooded-class copies already recorded by
    /// this node. A delivery replay drop is counted when the delivery path's
    /// peek is followed by the explicit duplicate note.
    pub duplicate_packets: u64,
    /// Flood relays cancelled by MSH-11's copy threshold, saturating.
    pub suppressed_relays: u64,
    /// Live store ids from the most recent `MeshInput::StoreSummary`.
    ///
    /// Zero until the host supplies a summary; the engine never opens the
    /// store, so this is occupancy as observed by the mesh, not a byte count.
    pub store_entries: u32,
    /// Encoded sync frame bytes emitted on the Bulk channel, saturating.
    ///
    /// Counted only when a bounded frame was actually encoded for a send.
    pub sync_bytes_sent: u64,
    /// Encoded sync frame bytes accepted from verified neighbours, saturating.
    ///
    /// Malformed or unverified frames are penalties, not sync bytes.
    pub sync_bytes_received: u64,
    /// Penalty applications to neighbours, saturating.
    ///
    /// Counted even when decay later removes the score: cumulative events and
    /// current score answer different diagnostic questions.
    pub neighbour_penalty_events: u64,
    /// Sum of current neighbour penalty scores, saturating.
    pub neighbour_penalty_total: u64,
    /// Largest current penalty score on any tracked neighbour.
    pub neighbour_penalty_max: u32,
    /// Tracked neighbours with a non-zero current penalty score.
    pub penalised_neighbours: u32,
    /// Current seen-cache recordings, bounded by `SeenConfig::capacity`.
    pub seen_records: u32,
    /// Current pending MSH-11 windows, bounded by `SuppressionConfig::max_entries`.
    pub suppression_pending: u32,
}

impl Default for MeshSnapshot {
    fn default() -> Self {
        Self {
            version: MESH_SNAPSHOT_VERSION,
            duplicate_packets: 0,
            suppressed_relays: 0,
            store_entries: 0,
            sync_bytes_sent: 0,
            sync_bytes_received: 0,
            neighbour_penalty_events: 0,
            neighbour_penalty_total: 0,
            neighbour_penalty_max: 0,
            penalised_neighbours: 0,
            seen_records: 0,
            suppression_pending: 0,
        }
    }
}

/// One saturating counter shared by every owning module.
#[derive(Debug, Default)]
pub(crate) struct Counter(u64);

impl Counter {
    pub(crate) const fn new() -> Self {
        Self(0)
    }

    pub(crate) fn add(&mut self, amount: u64) {
        self.0 = self.0.saturating_add(amount);
    }

    pub(crate) const fn get(&self) -> u64 {
        self.0
    }

    #[cfg(test)]
    pub(crate) fn set(&mut self, value: u64) {
        self.0 = value;
    }
}

/// Clamps a bounded `usize` gauge into the snapshot's fixed-width field.
pub(crate) fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn counter_saturates_instead_of_wrapping() {
        let mut counter = Counter::new();
        counter.set(u64::MAX - 1);
        counter.add(10);
        assert_eq!(counter.get(), u64::MAX);
        counter.add(u64::MAX);
        assert_eq!(counter.get(), u64::MAX);
    }

    #[test]
    fn snapshot_is_a_small_fixed_layout_with_a_version() {
        assert_eq!(MeshSnapshot::default().version, MESH_SNAPSHOT_VERSION);
        assert!(size_of::<MeshSnapshot>() <= 128);
        // A snapshot taken twice from unchanged state is identical data.
        let snapshot = MeshSnapshot::default();
        assert_eq!(snapshot, snapshot);
    }

    #[test]
    fn gauge_conversion_clamps_without_panicking() {
        assert_eq!(saturating_u32(7), 7);
        assert_eq!(saturating_u32(usize::MAX), u32::MAX);
    }
}
