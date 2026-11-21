//! Bounded, ephemeral mesh-wide node directory (MSH-20).
//!
//! Presence gossip (MSH-19) produces observations; this module turns them
//! into a bounded view for the UI, route hints (MSH-21) and the map. It holds
//! no keys, fetches no cards and interprets no app payload: the card hash and
//! location bytes are opaque. Location is stored as bounded opaque bytes so
//! telemetry work can decide its schema later.
//!
//! Two bounds always hold: at most [`DirectoryConfig::capacity`] entries and
//! at most [`DirectoryConfig::max_change_events`] pending UI events. Capacity
//! evicts the least-recently-seen node; staleness is relative to the local
//! monotonic clock with a high-water mark, so a backwards `now` neither
//! extends nor shortens a lifetime. Remote observation times are clamped for
//! display ordering only and never set an expiry instant.

use ao_idents::NodeId;
use core::fmt;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Bounds and lifetimes for a [`NodeDirectory`].
///
/// The defaults are the values recorded in ADR-0001 and the README's
/// directory table; they are covered by a test so documentation and code
/// cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryConfig {
    /// Maximum live entries. A full directory evicts the least-recently-seen
    /// node; zero stores nothing.
    pub capacity: usize,
    /// Relative lifetime of an entry from its local receipt time, in
    /// milliseconds. Matches ADR-0001's Presence lifetime.
    pub stale_after_ms: u64,
    /// Maximum length of the opaque location bytes carried by an observation.
    pub max_location_bytes: usize,
    /// Maximum number of queued UI change events. Zero suppresses events.
    pub max_change_events: usize,
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        Self {
            // About 80 KiB with populated location fields: 256 entries plus
            // their LRU keys and 64 events. Far below the phone memory budget
            // and enough for a mesh visible over several contacts.
            capacity: 256,
            stale_after_ms: 30 * 60 * 1_000,
            max_location_bytes: 64,
            max_change_events: 64,
        }
    }
}

/// One presence fact, as supplied by MSH-19 after the rebase.
///
/// The seam is deliberately narrow: an opaque node id and card hash, the
/// peer's capability bits and sequence number, an estimated hop distance,
/// the via-neighbour, the observation time and opaque bounded location bytes.
/// The directory does not fetch a card, open a payload or derive an id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeObservation<'a> {
    /// Opaque node identity derived by aoIdents elsewhere.
    pub node: NodeId,
    /// Opaque hash of the node's identity card.
    pub card_hash: [u8; 8],
    /// Capability bits advertised by the node.
    pub caps: u32,
    /// Per-origin announcement sequence; older values are ignored.
    pub seq: u64,
    /// Estimated hop distance to the node.
    pub hops: u8,
    /// Neighbour through which the fact was learned.
    pub via: NodeId,
    /// Observation time supplied by the caller. Future values are clamped to
    /// the local clock; it never sets the entry's expiry instant.
    pub observed_at_ms: u64,
    /// Opaque location bytes; the mesh never interprets them.
    pub location: &'a [u8],
}

/// A directory entry as exposed to queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// Opaque node identity.
    pub node: NodeId,
    /// Clamped observation time, used for deterministic display ordering.
    pub last_seen_ms: u64,
    /// Effective local receipt time, used for expiry and LRU ordering.
    pub local_seen_ms: u64,
    /// Local instant at which this entry becomes stale.
    pub expires_at_ms: u64,
    /// Estimated hop distance to the node.
    pub hops: u8,
    /// Neighbour through which the fact was learned.
    pub via: NodeId,
    /// Capability bits advertised by the node.
    pub caps: u32,
    /// Latest accepted announcement sequence.
    pub seq: u64,
    /// Opaque hash of the node's identity card.
    pub card_hash: [u8; 8],
    /// Opaque location bytes, absent until a caller supplies them.
    pub location: Option<Vec<u8>>,
}

/// A typed UI event. Only the id and kind travel; the UI queries the
/// directory for details, so an announcement flood cannot copy payloads into
/// the event stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryChange {
    /// The node was not in the directory before.
    Added {
        /// The node.
        node: NodeId,
    },
    /// A visible field of a known node changed.
    Updated {
        /// The node.
        node: NodeId,
    },
    /// The node expired or was evicted.
    Removed {
        /// The node.
        node: NodeId,
    },
}

impl DirectoryChange {
    /// The node this event refers to, used for coalescing.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        match self {
            Self::Added { node } | Self::Updated { node } | Self::Removed { node } => *node,
        }
    }
}

/// Why an observation was refused. Public errors stay typed; no packet or
/// neighbour input can make the directory panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryError {
    /// The opaque location bytes exceeded the configured cap.
    LocationTooLong {
        /// Offered length.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocationTooLong { len, max } => {
                write!(f, "directory location length {len} exceeds {max}")
            }
        }
    }
}

impl std::error::Error for DirectoryError {}

/// Counters for bounded state transitions, useful in tests and telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirectoryStats {
    /// Entries removed by relative-time expiry.
    pub expirations: u64,
    /// Entries removed by capacity pressure.
    pub evictions: u64,
    /// Observations refused by stale sequence or zero capacity.
    pub ignored_observations: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Removal {
    Expiry,
    Eviction,
}

/// The bounded, deterministic directory state owned by the sans-IO engine.
///
/// Entries are keyed by `NodeId`. A secondary ordered set ranks them by local
/// receipt time, then sequence, then id, so LRU eviction is deterministic
/// even when many observations carry the same timestamp. Queries never
/// mutate: stale entries read as absent until a `Tick` or an observation
/// reclaims them.
#[derive(Debug)]
pub struct NodeDirectory {
    config: DirectoryConfig,
    /// Monotonic high-water mark; a backwards `now` is treated as this value.
    clock_ms: u64,
    entries: BTreeMap<NodeId, DirectoryEntry>,
    /// `(local receipt time, sequence, id)`, oldest first.
    activity: BTreeSet<(u64, u64, NodeId)>,
    changes: VecDeque<DirectoryChange>,
    stats: DirectoryStats,
}

impl NodeDirectory {
    /// Creates an empty directory bounded by `config`.
    #[must_use]
    pub fn new(config: DirectoryConfig) -> Self {
        Self {
            config,
            clock_ms: 0,
            entries: BTreeMap::new(),
            activity: BTreeSet::new(),
            changes: VecDeque::with_capacity(config.max_change_events),
            stats: DirectoryStats::default(),
        }
    }

    /// The configured capacity, the hard bound on [`Self::len`].
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.config.capacity
    }

    /// Number of stored entries, including ones awaiting reclamation.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no entries are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of entries that are still live at `now`.
    #[must_use]
    pub fn live_len(&self, now: u64) -> usize {
        let effective = self.effective_now(now);
        self.entries
            .values()
            .filter(|entry| entry.expires_at_ms > effective)
            .count()
    }

    /// Bounded transition counters.
    #[must_use]
    pub const fn stats(&self) -> DirectoryStats {
        self.stats
    }

    /// Looks up one node. A stale entry reads as absent without being
    /// removed, so a pure query never changes state.
    #[must_use]
    pub fn get(&self, now: u64, node: NodeId) -> Option<DirectoryEntry> {
        let effective = self.effective_now(now);
        self.entries
            .get(&node)
            .filter(|entry| entry.expires_at_ms > effective)
            .cloned()
    }

    /// Live nodes within an inclusive hop-distance range, nearest first.
    ///
    /// Ties break on the clamped observation time (newest first), then
    /// sequence (newest first), then `NodeId` order. At most `limit` entries
    /// are returned; `min_hops > max_hops` yields an empty vector.
    #[must_use]
    pub fn nearby(
        &self,
        now: u64,
        min_hops: u8,
        max_hops: u8,
        limit: usize,
    ) -> Vec<DirectoryEntry> {
        if min_hops > max_hops || limit == 0 {
            return Vec::new();
        }
        let effective = self.effective_now(now);
        let mut found: Vec<&DirectoryEntry> = self
            .entries
            .values()
            .filter(|entry| {
                entry.expires_at_ms > effective && entry.hops >= min_hops && entry.hops <= max_hops
            })
            .collect();
        found.sort_unstable_by(|a, b| {
            a.hops
                .cmp(&b.hops)
                .then_with(|| b.last_seen_ms.cmp(&a.last_seen_ms))
                .then_with(|| b.seq.cmp(&a.seq))
                .then_with(|| a.node.cmp(&b.node))
        });
        found.into_iter().take(limit).cloned().collect()
    }

    /// The most recently observed live nodes, newest first.
    ///
    /// "Recent" uses the local receipt time, not a peer's clock. Ties break
    /// on sequence then `NodeId` order; at most `limit` entries are returned.
    #[must_use]
    pub fn recent(&self, now: u64, limit: usize) -> Vec<DirectoryEntry> {
        if limit == 0 {
            return Vec::new();
        }
        let effective = self.effective_now(now);
        let mut found: Vec<&DirectoryEntry> = self
            .entries
            .values()
            .filter(|entry| entry.expires_at_ms > effective)
            .collect();
        found.sort_unstable_by(|a, b| {
            b.local_seen_ms
                .cmp(&a.local_seen_ms)
                .then_with(|| b.seq.cmp(&a.seq))
                .then_with(|| a.node.cmp(&b.node))
        });
        found.into_iter().take(limit).cloned().collect()
    }

    /// Takes all pending UI changes, in insertion order after coalescing.
    ///
    /// The returned vector is bounded by [`DirectoryConfig::max_change_events`].
    #[must_use]
    pub fn drain_changes(&mut self) -> Vec<DirectoryChange> {
        self.changes.drain(..).collect()
    }

    /// Records one presence observation.
    ///
    /// An older `seq` for a known node is ignored. A repeated sighting
    /// refreshes the local expiry and LRU position but only emits an `Updated`
    /// event when a visible field (card hash, caps, hops, via or location)
    /// changed, so a hostile announcement stream cannot produce one UI event
    /// per packet. The observation time is clamped to the local clock and
    /// used for ordering only; expiry always starts at local receipt time.
    ///
    /// # Errors
    ///
    /// Returns [`DirectoryError::LocationTooLong`] before touching any state
    /// when `observation.location` exceeds the configured cap.
    pub fn observe(
        &mut self,
        now: u64,
        observation: NodeObservation<'_>,
    ) -> Result<(), DirectoryError> {
        if observation.location.len() > self.config.max_location_bytes {
            return Err(DirectoryError::LocationTooLong {
                len: observation.location.len(),
                max: self.config.max_location_bytes,
            });
        }
        let effective = self.advance_clock(now);
        self.expire_at(effective);

        if let Some(entry) = self.entries.get_mut(&observation.node) {
            if observation.seq < entry.seq {
                self.stats.ignored_observations = self.stats.ignored_observations.saturating_add(1);
                return Ok(());
            }
            self.activity
                .remove(&(entry.local_seen_ms, entry.seq, entry.node));
            let visible_change = entry.card_hash != observation.card_hash
                || entry.caps != observation.caps
                || entry.hops != observation.hops
                || entry.via != observation.via
                || entry.location.as_deref() != Some(observation.location);
            entry.last_seen_ms = observation.observed_at_ms.min(effective);
            entry.local_seen_ms = effective;
            entry.expires_at_ms = effective.saturating_add(self.config.stale_after_ms);
            entry.card_hash = observation.card_hash;
            entry.caps = observation.caps;
            entry.seq = observation.seq;
            entry.hops = observation.hops;
            entry.via = observation.via;
            entry.location =
                (!observation.location.is_empty()).then(|| observation.location.to_vec());
            self.activity
                .insert((effective, observation.seq, entry.node));
            if visible_change {
                self.push_change(DirectoryChange::Updated {
                    node: observation.node,
                });
            }
            return Ok(());
        }

        if self.config.capacity == 0 {
            self.stats.ignored_observations = self.stats.ignored_observations.saturating_add(1);
            return Ok(());
        }
        while self.entries.len() >= self.config.capacity && self.evict_oldest() {}
        let entry = DirectoryEntry {
            node: observation.node,
            last_seen_ms: observation.observed_at_ms.min(effective),
            local_seen_ms: effective,
            expires_at_ms: effective.saturating_add(self.config.stale_after_ms),
            hops: observation.hops,
            via: observation.via,
            caps: observation.caps,
            seq: observation.seq,
            card_hash: observation.card_hash,
            location: (!observation.location.is_empty()).then(|| observation.location.to_vec()),
        };
        self.activity
            .insert((effective, observation.seq, observation.node));
        self.entries.insert(observation.node, entry);
        self.push_change(DirectoryChange::Added {
            node: observation.node,
        });
        Ok(())
    }

    /// Reclaims entries whose relative lifetime ended at `now`.
    ///
    /// Called on `Tick` so removal events appear on schedule even when no
    /// new observation arrives. A backwards `now` cannot revive an entry.
    pub fn expire(&mut self, now: u64) {
        let effective = self.advance_clock(now);
        self.expire_at(effective);
    }

    /// Effective time for a query: the high-water mark, never a backwards
    /// sample. Queries do not mutate the mark, so a read cannot change later
    /// expiry behaviour.
    fn effective_now(&self, now: u64) -> u64 {
        self.clock_ms.max(now)
    }

    fn advance_clock(&mut self, now: u64) -> u64 {
        self.clock_ms = self.clock_ms.max(now);
        self.clock_ms
    }

    fn expire_at(&mut self, effective: u64) {
        let stale: Vec<NodeId> = self
            .entries
            .values()
            .filter(|entry| entry.expires_at_ms <= effective)
            .map(|entry| entry.node)
            .collect();
        for node in stale {
            self.remove(node, Removal::Expiry);
        }
    }

    fn evict_oldest(&mut self) -> bool {
        let oldest = self
            .activity
            .first()
            .map(|(_, _, node)| *node)
            .or_else(|| self.entries.keys().next().copied());
        let Some(node) = oldest else {
            return false;
        };
        self.remove(node, Removal::Eviction);
        true
    }

    fn remove(&mut self, node: NodeId, reason: Removal) {
        let Some(entry) = self.entries.remove(&node) else {
            return;
        };
        self.activity
            .remove(&(entry.local_seen_ms, entry.seq, entry.node));
        match reason {
            Removal::Expiry => {
                self.stats.expirations = self.stats.expirations.saturating_add(1);
            }
            Removal::Eviction => {
                self.stats.evictions = self.stats.evictions.saturating_add(1);
            }
        }
        self.push_change(DirectoryChange::Removed { node });
    }

    /// Queues one event, coalescing with a pending event for the same node.
    /// The queue never exceeds its configured bound; under a flood of new
    /// ids the oldest pending event gives way.
    fn push_change(&mut self, change: DirectoryChange) {
        if self.config.max_change_events == 0 {
            return;
        }
        let node = change.node();
        if let Some(position) = self
            .changes
            .iter()
            .position(|pending| pending.node() == node)
        {
            if let Some(pending) = self.changes.get(position).copied() {
                match merge(pending, change) {
                    Some(merged) => {
                        if let Some(slot) = self.changes.get_mut(position) {
                            *slot = merged;
                        }
                    }
                    None => {
                        self.changes.remove(position);
                    }
                }
            }
            return;
        }
        if self.changes.len() >= self.config.max_change_events {
            self.changes.pop_front();
        }
        self.changes.push_back(change);
    }
}

/// The net UI effect of two changes to one node, without exposing transient
/// churn. `Added` then `Removed` needs no event at all; `Removed` then
/// `Added` is an `Updated` because the UI last knew the node as present.
fn merge(old: DirectoryChange, new: DirectoryChange) -> Option<DirectoryChange> {
    use DirectoryChange::{Added, Removed, Updated};
    match (old, new) {
        (Added { node }, Added { .. } | Updated { .. }) => Some(Added { node }),
        (Added { .. }, Removed { .. }) => None,
        (Updated { node }, Added { .. } | Updated { .. }) => Some(Updated { node }),
        (Updated { node }, Removed { .. }) => Some(Removed { node }),
        (Removed { node }, Added { .. } | Updated { .. }) => Some(Updated { node }),
        (Removed { node }, Removed { .. }) => Some(Removed { node }),
    }
}

impl Default for NodeDirectory {
    fn default() -> Self {
        Self::new(DirectoryConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 16])
    }

    fn observation(
        id: NodeId,
        seq: u64,
        hops: u8,
        at: u64,
        location: &[u8],
    ) -> NodeObservation<'_> {
        NodeObservation {
            node: id,
            card_hash: [id.as_bytes()[0]; 8],
            caps: u32::from(id.as_bytes()[0]),
            seq,
            hops,
            via: node(200),
            observed_at_ms: at,
            location,
        }
    }

    fn config(capacity: usize, stale_after_ms: u64, max_change_events: usize) -> DirectoryConfig {
        DirectoryConfig {
            capacity,
            stale_after_ms,
            max_change_events,
            ..DirectoryConfig::default()
        }
    }

    #[test]
    fn defaults_match_the_documented_table() {
        let config = DirectoryConfig::default();
        assert_eq!(config.capacity, 256);
        assert_eq!(config.stale_after_ms, 30 * 60 * 1_000);
        assert_eq!(config.max_location_bytes, 64);
        assert_eq!(config.max_change_events, 64);
    }

    #[test]
    fn capacity_is_never_exceeded_and_eviction_is_least_recently_seen() {
        let mut directory = NodeDirectory::new(config(2, 100_000, 8));
        let a = node(1);
        let b = node(2);
        let c = node(3);
        directory
            .observe(0, observation(a, 1, 1, 0, &[]))
            .expect("valid observation");
        directory
            .observe(0, observation(b, 1, 1, 0, &[]))
            .expect("valid observation");
        // Touching A makes B the least recently seen, even though all three
        // observations carry the same local timestamp.
        directory
            .observe(0, observation(a, 2, 1, 0, &[]))
            .expect("valid observation");
        directory
            .observe(0, observation(c, 1, 1, 0, &[]))
            .expect("valid observation");
        assert_eq!(directory.len(), 2);
        assert!(directory.get(0, a).is_some());
        assert!(directory.get(0, b).is_none(), "B should have been evicted");
        assert!(directory.get(0, c).is_some());
        assert_eq!(directory.stats().evictions, 1);

        // A sustained hostile flood stays at the ceiling.
        for n in 4u16..1_000 {
            directory
                .observe(0, observation(node(n as u8), 1, 1, 0, &[]))
                .expect("valid observation");
            assert!(directory.len() <= 2, "capacity was exceeded");
        }
    }

    #[test]
    fn scheduled_expiry_ignores_skewed_and_backwards_clocks() {
        let mut directory = NodeDirectory::new(config(4, 1_000, 8));
        let a = node(1);
        let b = node(2);
        // A carries a far-past observation time, B a far-future one. Neither
        // peer clock changes the local expiry schedule.
        directory
            .observe(10_000, observation(a, 1, 1, 0, &[]))
            .expect("valid observation");
        directory
            .observe(10_000, observation(b, 1, 2, 99_999, &[]))
            .expect("valid observation");
        assert_eq!(directory.get(10_000, a).unwrap().last_seen_ms, 0);
        assert_eq!(directory.get(10_000, b).unwrap().last_seen_ms, 10_000);

        // A backwards tick neither expires early nor revives anything.
        directory.expire(9_000);
        assert_eq!(directory.stats().expirations, 0);
        assert!(directory.get(9_000, a).is_some());
        // A backwards observation is stamped with the high-water mark: its
        // lifetime is neither shortened nor extended by the backward sample.
        let c = node(3);
        directory
            .observe(9_500, observation(c, 1, 3, 9_500, &[]))
            .expect("valid observation");
        assert_eq!(directory.get(9_500, c).unwrap().expires_at_ms, 11_000);

        // Queries filter stale entries, but only Tick reclaims them.
        assert!(directory.get(10_999, a).is_some());
        assert!(directory.get(11_000, a).is_none());
        directory.expire(11_000);
        assert_eq!(directory.stats().expirations, 3);
        assert!(directory.is_empty());
        // A later backwards clock must not bring an expired node back.
        assert!(directory.get(1_000, a).is_none());
    }

    #[test]
    fn queries_are_ordered_and_bounded() {
        let mut directory = NodeDirectory::new(config(8, 100_000, 8));
        let a = node(1);
        let b = node(2);
        let c = node(3);
        let d = node(4);
        directory
            .observe(100, observation(a, 1, 2, 100, &[]))
            .expect("valid observation");
        directory
            .observe(200, observation(b, 1, 1, 200, &[]))
            .expect("valid observation");
        directory
            .observe(300, observation(c, 1, 2, 300, &[]))
            .expect("valid observation");
        directory
            .observe(300, observation(d, 1, 2, 300, &[]))
            .expect("valid observation");

        let near: Vec<NodeId> = directory
            .nearby(400, 1, 2, 3)
            .into_iter()
            .map(|entry| entry.node)
            .collect();
        assert_eq!(near, vec![b, c, d], "hops first, then newest sighting");
        let narrow: Vec<NodeId> = directory
            .nearby(400, 2, 2, 8)
            .into_iter()
            .map(|entry| entry.node)
            .collect();
        assert_eq!(narrow, vec![c, d, a]);
        assert!(directory.nearby(400, 3, 2, 8).is_empty());
        let recent: Vec<NodeId> = directory
            .recent(400, 2)
            .into_iter()
            .map(|entry| entry.node)
            .collect();
        assert_eq!(recent, vec![c, d], "equal local time breaks on id order");
        assert_eq!(directory.recent(400, 0).len(), 0);
    }

    #[test]
    fn change_events_are_bounded_and_coalesced_per_node() {
        let mut directory = NodeDirectory::new(config(8, 100_000, 2));
        let a = node(1);
        let b = node(2);
        let c = node(3);
        directory
            .observe(0, observation(a, 1, 1, 0, &[]))
            .expect("valid observation");
        for seq in 2..1_000u64 {
            let mut changed = observation(a, seq, 1, 0, &[]);
            changed.caps = seq as u32;
            directory.observe(0, changed).expect("valid observation");
        }
        assert_eq!(
            directory.drain_changes(),
            vec![DirectoryChange::Added { node: a }],
            "a flood about one node never produces more than one event"
        );

        directory
            .observe(0, observation(b, 1, 1, 0, &[]))
            .expect("valid observation");
        directory
            .observe(0, observation(c, 1, 1, 0, &[]))
            .expect("valid observation");
        directory
            .observe(0, observation(c, 2, 2, 0, &[]))
            .expect("valid observation");
        assert_eq!(
            directory.drain_changes(),
            vec![
                DirectoryChange::Added { node: b },
                DirectoryChange::Added { node: c },
            ],
            "the oldest event yields to a new node and repeats coalesce"
        );

        directory.expire(100_000);
        assert_eq!(
            directory.drain_changes(),
            vec![
                DirectoryChange::Removed { node: b },
                DirectoryChange::Removed { node: c },
            ]
        );
    }

    #[test]
    fn added_then_removed_needs_no_event_and_removed_then_added_is_updated() {
        let mut directory = NodeDirectory::new(config(2, 10, 4));
        let a = node(1);
        directory
            .observe(0, observation(a, 1, 1, 0, &[]))
            .expect("valid observation");
        directory.expire(10);
        assert!(directory.drain_changes().is_empty());

        directory
            .observe(20, observation(a, 1, 1, 20, &[]))
            .expect("valid observation");
        // Prime the UI with the current state, then churn the same node.
        assert_eq!(
            directory.drain_changes(),
            vec![DirectoryChange::Added { node: a }]
        );
        directory.expire(30);
        directory
            .observe(30, observation(a, 2, 1, 30, &[]))
            .expect("valid observation");
        assert_eq!(
            directory.drain_changes(),
            vec![DirectoryChange::Updated { node: a }]
        );
    }

    #[test]
    fn stale_sequences_are_ignored_and_oversized_locations_are_typed_errors() {
        let mut directory = NodeDirectory::new(DirectoryConfig {
            max_location_bytes: 4,
            ..config(4, 100_000, 8)
        });
        let a = node(1);
        directory
            .observe(0, observation(a, 7, 1, 0, &[1, 2]))
            .expect("valid observation");
        let _ = directory.drain_changes();
        directory
            .observe(10, observation(a, 6, 4, 10, &[9]))
            .expect("older sequence is ignored");
        let entry = directory.get(10, a).expect("entry survives");
        assert_eq!(entry.seq, 7);
        assert_eq!(entry.hops, 1);
        assert!(directory.drain_changes().is_empty());

        let error = directory
            .observe(10, observation(a, 8, 1, 10, &[0; 5]))
            .expect_err("location cap is enforced");
        assert_eq!(error, DirectoryError::LocationTooLong { len: 5, max: 4 });
        assert!(directory.get(10, a).is_some());
        assert!(directory.drain_changes().is_empty());
        assert_eq!(directory.stats().ignored_observations, 1);
    }
}
