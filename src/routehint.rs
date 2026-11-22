//! MSH-21 bounded reverse-path route hints (sans-IO).
//!
//! A hint is local, ephemeral routing advice: "the freshest presence
//! observation for destination D arrived from neighbour N, H hops away".
//! It is never signed, never sent on the wire and never used to authenticate
//! a packet. Hints are derived from MSH-20's directory observations: verified
//! presence announcements feed them automatically, and host-supplied
//! [`crate::MeshInput::ObserveNode`] facts use the same seam.
//!
//! Only local `now` is trusted. An observation deliberately has no timestamp
//! field: a peer-supplied time could otherwise extend a hint's lifetime, and
//! reading a remote wall clock would break the engine's relative-age rule.
//! A backwards local clock is clamped to the newest time this table has seen,
//! so neither replay nor clock skew keeps a hint fresh for longer.

use ao_idents::NodeId;
use ao_network::LinkId;
use core::cmp::Reverse;
use std::collections::BTreeMap;

/// How Direct traffic uses a fresh hint.
///
/// The two active modes were measured against the same fixed-seed spray
/// baseline (ADR-0001); see the MSH-21 section of the README.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteHintMode {
    /// Record nothing and change no forwarding decision.
    Off,
    /// Send one additional unicast copy along the hint, on top of spray.
    AdditiveUnicast,
    /// Make the hint one of the existing spray copies and drop one other
    /// recipient, so the number of transmissions does not grow.
    SubstituteCopy,
}

/// Bounded configuration for the route-hint table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteHintConfig {
    /// Forwarding mode. `Off` also stops observations being recorded.
    pub mode: RouteHintMode,
    /// Maximum number of destinations with a retained hint.
    pub max_entries: usize,
    /// Relative lifetime of a fresh hint, in local milliseconds.
    pub lifetime_ms: u64,
    /// Largest hop count still considered fresh.
    pub max_hops: u8,
}

impl Default for RouteHintConfig {
    /// 1024 destinations cover the documented node-directory bound with a
    /// small margin. A five-minute lifetime is shorter than one presence
    /// refresh interval (10-15 min in ADR-0001), so a stale path ages out
    /// before the next refresh; eight hops match Direct's TTL. The mode is
    /// the measured winner described in ADR-0001 and the README; it is set
    /// after the paired simulator sweep.
    fn default() -> Self {
        Self {
            mode: RouteHintMode::SubstituteCopy,
            max_entries: 1024,
            lifetime_ms: 300_000,
            max_hops: 8,
        }
    }
}

/// One directory-derived reverse-path observation, internal to the engine.
///
/// `neighbour` is the local link whose verified peer supplied the directory
/// fact; the engine accepts it only while that link is up and identity-verified.
/// `seq` is the destination's opaque presence sequence number: larger means
/// newer for the same hop count. No peer clock value is accepted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RouteHintObservation {
    /// Node whose reverse path this observation describes.
    pub destination: NodeId,
    /// Local link that carried the presence observation.
    pub neighbour: LinkId,
    /// Hop count from this node to the destination via `neighbour`.
    pub hops: u8,
    /// Opaque presence sequence number; higher wins at equal hop count.
    pub seq: u64,
}

/// The retained advice for one destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteHint {
    /// Verified neighbour that supplied the freshest observation.
    pub neighbour: LinkId,
    /// Hop count via that neighbour when the hint was recorded.
    pub hops: u8,
    /// Sequence number of the winning observation.
    pub seq: u64,
    /// Local time at which this hint stops being fresh.
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    hint: RouteHint,
    observed_at_ms: u64,
}

/// Bounded, deterministic table of reverse-path hints.
///
/// Ranking is `(hops ascending, seq descending, link id ascending)`, so a
/// lower hop count always wins, then a newer sequence, then link order breaks
/// an exact tie. Only a strictly fresher observation (lower hops or higher
/// seq) restarts the lifetime: a lower link id at equal hops and seq changes
/// the chosen neighbour but keeps the retained observation's age. A hint that
/// loses is ignored and never extends the winner's lifetime.
#[derive(Debug)]
pub struct RouteHintTable {
    config: RouteHintConfig,
    entries: BTreeMap<NodeId, Entry>,
    clock_floor_ms: u64,
}

impl RouteHintTable {
    /// Creates an empty table from bounded configuration.
    #[must_use]
    pub fn new(config: RouteHintConfig) -> Self {
        Self {
            config,
            entries: BTreeMap::new(),
            clock_floor_ms: 0,
        }
    }

    /// The active forwarding mode.
    #[must_use]
    pub fn mode(&self) -> RouteHintMode {
        self.config.mode
    }

    /// Number of destinations with a retained hint.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no hint is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The fresh hint for one destination, if any. A backwards `now` cannot
    /// revive an entry that has already expired.
    #[must_use]
    pub fn hint(&self, now: u64, destination: NodeId) -> Option<RouteHint> {
        let now = now.max(self.clock_floor_ms);
        let entry = self.entries.get(&destination)?;
        (now < entry.hint.expires_at_ms).then_some(entry.hint)
    }

    /// Drops hints whose local lifetime has passed.
    pub(crate) fn expire(&mut self, now: u64) {
        self.clock_floor_ms = self.clock_floor_ms.max(now);
        let floor = self.clock_floor_ms;
        self.entries
            .retain(|_, entry| floor < entry.hint.expires_at_ms);
    }

    /// Removes every hint supplied by a link that went down.
    pub(crate) fn link_down(&mut self, link: LinkId) {
        self.entries.retain(|_, entry| entry.hint.neighbour != link);
    }

    /// Records an observation if it is fresh and ranks above the retained
    /// one. `neighbour_verified` is the engine's admission check: observations
    /// from links without a verified identity are ignored.
    pub(crate) fn observe(
        &mut self,
        now: u64,
        observation: RouteHintObservation,
        neighbour_verified: bool,
    ) -> bool {
        if self.config.mode == RouteHintMode::Off
            || !neighbour_verified
            || observation.hops == 0
            || observation.hops > self.config.max_hops
        {
            return false;
        }
        self.expire(now);
        // A local clock moving backwards must not extend a hint. Clamping to
        // the table's clock floor keeps expiry relative to the newest local
        // time observed, never to peer time or to an earlier epoch.
        let effective_now = now.max(self.clock_floor_ms);
        let incoming = Self::freshness(observation.hops, observation.seq);
        if let Some(entry) = self.entries.get_mut(&observation.destination) {
            let retained = Self::freshness(entry.hint.hops, entry.hint.seq);
            if incoming > retained {
                // Worse hops or an older sequence: link order cannot rescue it.
                return false;
            }
            if incoming == retained {
                if observation.neighbour >= entry.hint.neighbour {
                    return false;
                }
                // The freshest fact is unchanged, so a better link id is only
                // a deterministic tie-break. Keep the original age: choosing
                // a neighbour is not new evidence and must not refresh expiry.
                entry.hint.neighbour = observation.neighbour;
                return true;
            }
            let expires_at_ms = if effective_now > entry.observed_at_ms {
                effective_now.saturating_add(self.config.lifetime_ms)
            } else {
                entry.hint.expires_at_ms
            };
            entry.hint = RouteHint {
                neighbour: observation.neighbour,
                hops: observation.hops,
                seq: observation.seq,
                expires_at_ms,
            };
            entry.observed_at_ms = effective_now;
            return true;
        }
        if self.entries.len() >= self.config.max_entries {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(destination, entry)| (entry.hint.expires_at_ms, **destination))
                .map(|(destination, _)| *destination);
            if let Some(destination) = oldest {
                self.entries.remove(&destination);
            }
        }
        if self.config.max_entries == 0 {
            return false;
        }
        self.entries.insert(
            observation.destination,
            Entry {
                hint: RouteHint {
                    neighbour: observation.neighbour,
                    hops: observation.hops,
                    seq: observation.seq,
                    expires_at_ms: effective_now.saturating_add(self.config.lifetime_ms),
                },
                observed_at_ms: effective_now,
            },
        );
        true
    }

    /// Lower is fresher. Link id is deliberately excluded: it breaks exact
    /// ties without making an observation newer.
    fn freshness(hops: u8, seq: u64) -> (u8, Reverse<u64>) {
        (hops, Reverse(seq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK_A: LinkId = LinkId::new(1);
    const LINK_B: LinkId = LinkId::new(2);
    const LINK_C: LinkId = LinkId::new(3);

    fn node(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 16])
    }

    fn observe(table: &mut RouteHintTable, now: u64, hops: u8, seq: u64, link: LinkId) -> bool {
        table.observe(
            now,
            RouteHintObservation {
                destination: node(9),
                neighbour: link,
                hops,
                seq,
            },
            true,
        )
    }

    fn config(mode: RouteHintMode, max_entries: usize, lifetime_ms: u64) -> RouteHintConfig {
        RouteHintConfig {
            mode,
            max_entries,
            lifetime_ms,
            max_hops: 8,
        }
    }

    #[test]
    fn lowest_hops_then_highest_seq_wins() {
        let mut table = RouteHintTable::new(config(RouteHintMode::SubstituteCopy, 4, 1_000));
        assert!(observe(&mut table, 0, 5, 100, LINK_A));
        assert!(observe(&mut table, 10, 3, 1, LINK_B));
        assert_eq!(
            table.hint(10, node(9)).map(|hint| hint.neighbour),
            Some(LINK_B)
        );
        assert!(observe(&mut table, 20, 3, 2, LINK_C));
        assert_eq!(table.hint(20, node(9)).map(|hint| hint.seq), Some(2));
        // More hops with a much newer sequence is not fresher.
        assert!(!observe(&mut table, 30, 4, 9_999, LINK_A));
        assert_eq!(
            table.hint(30, node(9)).map(|hint| hint.neighbour),
            Some(LINK_C)
        );
    }

    #[test]
    fn exact_ties_break_by_link_id_and_do_not_refresh() {
        let mut table = RouteHintTable::new(config(RouteHintMode::SubstituteCopy, 4, 1_000));
        assert!(observe(&mut table, 0, 2, 7, LINK_C));
        assert!(observe(&mut table, 10, 2, 7, LINK_A));
        let hint = table.hint(10, node(9)).expect("lower link wins a tie");
        assert_eq!(hint.neighbour, LINK_A);
        assert_eq!(hint.expires_at_ms, 1_000);
        // An equal fact from a higher link id loses the tie.
        assert!(!observe(&mut table, 200, 2, 7, LINK_B));
        // Same rank at a later time cannot extend the winner's lifetime.
        assert!(!observe(&mut table, 500, 2, 7, LINK_A));
        assert_eq!(
            table.hint(500, node(9)).map(|hint| hint.expires_at_ms),
            Some(1_000)
        );
        // A strictly fresher fact does restart the lifetime, whichever link
        // carried it.
        assert!(observe(&mut table, 600, 1, 7, LINK_C));
        assert_eq!(
            table
                .hint(600, node(9))
                .map(|hint| (hint.neighbour, hint.expires_at_ms)),
            Some((LINK_C, 1_600))
        );
    }

    #[test]
    fn capacity_evicts_earliest_expiry_then_node_order() {
        let mut table = RouteHintTable::new(config(RouteHintMode::SubstituteCopy, 2, 1_000));
        assert!(table.observe(
            0,
            RouteHintObservation {
                destination: node(1),
                neighbour: LINK_A,
                hops: 2,
                seq: 1,
            },
            true,
        ));
        assert!(table.observe(
            100,
            RouteHintObservation {
                destination: node(2),
                neighbour: LINK_B,
                hops: 2,
                seq: 1,
            },
            true,
        ));
        assert!(table.observe(
            200,
            RouteHintObservation {
                destination: node(3),
                neighbour: LINK_C,
                hops: 2,
                seq: 1,
            },
            true,
        ));
        assert_eq!(table.len(), 2);
        assert!(table.hint(200, node(1)).is_none());
        assert!(table.hint(200, node(2)).is_some());
        assert!(table.hint(200, node(3)).is_some());
    }

    #[test]
    fn expiry_falls_back_and_backwards_clock_does_not_revive() {
        let mut table = RouteHintTable::new(config(RouteHintMode::SubstituteCopy, 4, 1_000));
        assert!(observe(&mut table, 0, 2, 1, LINK_A));
        assert!(table.hint(999, node(9)).is_some());
        table.expire(1_000);
        assert!(table.hint(1_000, node(9)).is_none());
        assert!(table.hint(10, node(9)).is_none());
    }

    #[test]
    fn backwards_local_clock_does_not_extend_freshness() {
        let mut table = RouteHintTable::new(config(RouteHintMode::SubstituteCopy, 4, 1_000));
        assert!(observe(&mut table, 1_000, 3, 1, LINK_A));
        assert!(observe(&mut table, 1_100, 2, 2, LINK_B));
        let before = table.hint(1_100, node(9)).expect("fresh hint");
        assert!(observe(&mut table, 50, 1, 3, LINK_C));
        let after = table.hint(1_100, node(9)).expect("still fresh");
        assert_eq!(after.neighbour, LINK_C);
        assert_eq!(after.expires_at_ms, before.expires_at_ms);
    }

    #[test]
    fn zero_capacity_and_off_mode_record_nothing() {
        let mut empty = RouteHintTable::new(config(RouteHintMode::SubstituteCopy, 0, 1_000));
        assert!(!observe(&mut empty, 0, 1, 1, LINK_A));
        assert!(empty.is_empty());
        let mut off = RouteHintTable::new(config(RouteHintMode::Off, 4, 1_000));
        assert!(!observe(&mut off, 0, 1, 1, LINK_A));
        assert!(off.is_empty());
    }

    #[test]
    fn unverified_peer_and_out_of_range_hops_are_ignored() {
        let mut table = RouteHintTable::new(config(RouteHintMode::SubstituteCopy, 4, 1_000));
        let observation = RouteHintObservation {
            destination: node(9),
            neighbour: LINK_A,
            hops: 2,
            seq: 1,
        };
        assert!(!table.observe(0, observation, false));
        assert!(!table.observe(
            0,
            RouteHintObservation {
                hops: 0,
                ..observation
            },
            true,
        ));
        assert!(!table.observe(
            0,
            RouteHintObservation {
                hops: 9,
                ..observation
            },
            true,
        ));
        assert!(table.is_empty());
    }

    #[test]
    fn link_down_removes_its_hints() {
        let mut table = RouteHintTable::new(config(RouteHintMode::SubstituteCopy, 4, 1_000));
        assert!(observe(&mut table, 0, 2, 1, LINK_A));
        table.link_down(LINK_A);
        assert!(table.hint(0, node(9)).is_none());
    }
}
