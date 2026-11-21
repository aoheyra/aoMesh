//! Bounded advisory link hints for `aoNetwork` (MSH-25).
//!
//! `aoMesh` knows which radio peers would help the mesh: the host recognises
//! a contact's rotating tag, the directory says which nodes a neighbour can
//! reach, and MSH-10 records neighbour penalties. `aoNetwork` alone owns link
//! formation and the degree cap. This module turns those facts into the
//! advisory [`LinkHintPreference`] values that the adapter passes to
//! [`ao_network::Network::set_link_hint`] and
//! [`ao_network::Network::clear_link_hint`]. No hint reserves a slot, evicts
//! a link or changes a radio limit.
//!
//! A fact names the opaque `PeerKey` the radio reported and, when the host
//! knows it, the mesh identity behind it. The engine never derives a tag,
//! keeps a key or interprets either value: both stay opaque. Diversity is
//! computed locally from the bounded `NodeDirectory`: a peer is diverse when
//! it is the `via` neighbour of at least `min_diverse_nodes` live directory
//! entries that no currently linked neighbour reaches. A penalty at or above
//! `penalty_threshold` overrides contact and diversity, so a hostile peer is
//! never preferred while it is being penalised.
//!
//! Every bound is config-driven: at most `max_peers` facts are held, and one
//! input emits at most one output per tracked peer. Eviction at capacity uses
//! the same rule as aoNetwork's hint table (lowest preference, then greatest
//! `PeerKey`), so the two tables converge deterministically.

use ao_idents::NodeId;
use ao_network::{LinkHintPreference, LinkId, PeerKey};
use std::collections::{BTreeMap, BTreeSet};
// BTreeSet keeps multiple simultaneous links to one identity ordered and
// bounded by aoNetwork's link cap; no hint can grow this map from peer input.

use crate::budget::BudgetTracker;
use crate::directory::NodeDirectory;
use crate::neighbor::NeighborTable;

/// Default hint capacity: aoNetwork's default `max_peers` (NET-16).
pub const DEFAULT_MAX_PEERS: usize = 64;
/// Default penalty at which a neighbour is deprioritised: one invalid packet
/// under MSH-10's default `penalty_invalid` of three.
pub const DEFAULT_PENALTY_THRESHOLD: u32 = 3;
/// Default number of otherwise-unreachable directory nodes a peer must
/// reach before it counts as diverse. One is a single noisy announcement;
/// two is the smallest stable signal.
pub const DEFAULT_MIN_DIVERSE_NODES: usize = 2;

/// Bounds and decision thresholds for [`LinkHintTable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkHintConfig {
    /// Maximum number of advisory facts held at once. Zero disables all
    /// hints; the adapter then never sees an output from this module.
    pub max_peers: usize,
    /// Penalty at or above which a linked peer is deprioritised.
    pub penalty_threshold: u32,
    /// Minimum number of live directory nodes unique to a peer before it
    /// is preferred for diversity.
    pub min_diverse_nodes: usize,
}

impl Default for LinkHintConfig {
    fn default() -> Self {
        Self {
            max_peers: DEFAULT_MAX_PEERS,
            penalty_threshold: DEFAULT_PENALTY_THRESHOLD,
            min_diverse_nodes: DEFAULT_MIN_DIVERSE_NODES,
        }
    }
}

/// One host-supplied fact about an unlinked radio peer (MSH-25).
///
/// The `peer` is the opaque radio key, typically derived from a contact's
/// rotating tag by the host. `node` is the identity the host associates with
/// that tag; the engine treats it as opaque and uses it only to correlate
/// directory facts. Setting `contact` to `false` revokes a previous contact
/// claim: the engine clears its advice unless diversity still supports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkHintObservation {
    /// Radio peer to advise about.
    pub peer: PeerKey,
    /// Opaque mesh identity behind that peer, when the host knows it.
    pub node: NodeId,
    /// Whether the host's contact book recognises this peer's tag.
    pub contact: bool,
}

/// The advisory change an input produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HintChange {
    /// Install or replace the preference.
    Set(LinkHintPreference),
    /// Withdraw advice; aoNetwork falls back to its ordinary ordering.
    Clear,
    /// The decision did not change, so no output is emitted.
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    node: NodeId,
    contact: bool,
    link: Option<LinkId>,
    preference: LinkHintPreference,
}

/// Deterministic, bounded advisory state. No radio commands are issued here.
#[derive(Debug)]
pub struct LinkHintTable {
    config: LinkHintConfig,
    entries: BTreeMap<PeerKey, Entry>,
    /// Verified links by mesh identity. LinkUp can precede the host fact that
    /// names the same identity, so the association must survive until then.
    links: BTreeMap<NodeId, BTreeSet<LinkId>>,
    /// Number of SetLinkHint outputs emitted, for resource-bound tests and
    /// simulator diagnostics.
    sets: u64,
    /// Number of ClearLinkHint outputs emitted.
    clears: u64,
}

impl LinkHintTable {
    /// Creates an empty table with the supplied bounds.
    #[must_use]
    pub fn new(config: LinkHintConfig) -> Self {
        Self {
            config,
            entries: BTreeMap::new(),
            links: BTreeMap::new(),
            sets: 0,
            clears: 0,
        }
    }

    /// The configured cap on tracked peers.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.config.max_peers
    }

    /// Number of peers currently carrying advice.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no advice is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current advice for one peer, for tests and diagnostics.
    #[must_use]
    pub fn preference(&self, peer: PeerKey) -> LinkHintPreference {
        self.entries
            .get(&peer)
            .map_or(LinkHintPreference::Neutral, |entry| entry.preference)
    }

    /// Saturating output counters. A peer emitting advice twice counts twice;
    /// clearing a stale peer counts once.
    #[must_use]
    pub const fn counters(&self) -> (u64, u64) {
        (self.sets, self.clears)
    }

    /// Records a verified link for the peer whose identity matches `node`.
    pub(crate) fn link_up(&mut self, node: NodeId, link: LinkId) {
        self.links.entry(node).or_default().insert(link);
        for entry in self.entries.values_mut() {
            if entry.node == node && entry.link.is_none() {
                entry.link = Some(link);
            }
        }
    }

    /// Forgets the link associated with `link` without dropping the advice:
    /// a peer that goes out of range may come back and should keep its
    /// contact preference (NET-16 hints also survive range loss).
    pub(crate) fn link_down(&mut self, link: LinkId) {
        for links in self.links.values_mut() {
            links.remove(&link);
        }
        self.links.retain(|_, links| !links.is_empty());
        for entry in self.entries.values_mut() {
            if entry.link == Some(link) {
                entry.link = self
                    .links
                    .get(&entry.node)
                    .and_then(|links| links.iter().next().copied());
            }
        }
    }

    /// The verified link currently associated with `node`, if any.
    fn link_for(&self, node: NodeId) -> Option<LinkId> {
        self.links
            .get(&node)
            .and_then(|links| links.iter().next().copied())
    }

    /// Applies one host fact and returns the advice changes, in `PeerKey`
    /// order. A full table first clears the evicted peer, so aoNetwork never
    /// keeps advice this engine has forgotten.
    pub(crate) fn observe(
        &mut self,
        now: u64,
        observation: LinkHintObservation,
        directory: &NodeDirectory,
        neighbors: &NeighborTable,
        budgets: &BudgetTracker,
    ) -> Vec<(PeerKey, HintChange)> {
        if self.config.max_peers == 0 {
            return Vec::new();
        }
        let LinkHintObservation {
            peer,
            node,
            contact,
        } = observation;
        let link = self.link_for(node);
        let old = self
            .entries
            .get(&peer)
            .map_or(LinkHintPreference::Neutral, |entry| entry.preference);
        let mut entry = Entry {
            node,
            contact,
            link,
            preference: old,
        };
        let preference =
            Self::preference_for(now, &entry, &self.config, directory, neighbors, budgets);
        // Do not spend a slot on a fact that yields no advice: a host may
        // flood revocations for peers it never recognised.
        if preference == LinkHintPreference::Neutral && !self.entries.contains_key(&peer) {
            return Vec::new();
        }
        let evicted =
            if !self.entries.contains_key(&peer) && self.entries.len() >= self.config.max_peers {
                self.evict_one()
            } else {
                None
            };
        entry.preference = preference;
        self.entries.insert(peer, entry);
        let change = Self::classify(old, preference);
        self.record(change);
        let mut changes = Vec::with_capacity(2);
        if let Some(evicted) = evicted {
            changes.push((evicted, HintChange::Clear));
            self.clears = self.clears.saturating_add(1);
        }
        if change != HintChange::Unchanged {
            changes.push((peer, change));
        }
        changes.sort_by_key(|(peer, _)| *peer);
        changes
    }

    /// Re-evaluates every tracked peer after local state changed (a Tick).
    ///
    /// Returns at most `max_peers` changes in `PeerKey` order. A peer whose
    /// advice falls back to neutral is removed, which frees its slot for a
    /// future contact without a separate expiry timer.
    pub(crate) fn refresh(
        &mut self,
        now: u64,
        directory: &NodeDirectory,
        neighbors: &NeighborTable,
        budgets: &BudgetTracker,
    ) -> Vec<(PeerKey, HintChange)> {
        if self.entries.is_empty() {
            return Vec::new();
        }
        let mut changes = Vec::new();
        for (&peer, entry) in &mut self.entries {
            let preference =
                Self::preference_for(now, entry, &self.config, directory, neighbors, budgets);
            let old = entry.preference;
            entry.preference = preference;
            let change = Self::classify(old, preference);
            if change != HintChange::Unchanged {
                changes.push((peer, change));
            }
        }
        for (_, change) in &changes {
            self.record(*change);
        }
        // A peer whose advice fell back to neutral is removed so its slot is
        // free for a future contact; the clear event still goes to the host.
        self.entries
            .retain(|_, entry| entry.preference != LinkHintPreference::Neutral || entry.contact);
        changes
    }

    fn classify(old: LinkHintPreference, new: LinkHintPreference) -> HintChange {
        if old == new {
            HintChange::Unchanged
        } else if new == LinkHintPreference::Neutral {
            HintChange::Clear
        } else {
            HintChange::Set(new)
        }
    }

    fn record(&mut self, change: HintChange) {
        match change {
            HintChange::Set(_) => self.sets = self.sets.saturating_add(1),
            HintChange::Clear => self.clears = self.clears.saturating_add(1),
            HintChange::Unchanged => {}
        }
    }

    fn preference_for(
        now: u64,
        entry: &Entry,
        config: &LinkHintConfig,
        directory: &NodeDirectory,
        neighbors: &NeighborTable,
        budgets: &BudgetTracker,
    ) -> LinkHintPreference {
        if let Some(link) = entry.link {
            if budgets.penalty_at(now, link) >= config.penalty_threshold {
                return LinkHintPreference::Deprioritize;
            }
        }
        if entry.contact
            || Self::adds_diversity(
                now,
                entry.link.is_some(),
                entry.node,
                config,
                directory,
                neighbors,
            )
        {
            LinkHintPreference::Prefer
        } else {
            LinkHintPreference::Neutral
        }
    }

    /// True when `node` is the `via` neighbour of enough live directory
    /// entries that no current neighbour already reaches. A linked candidate
    /// cannot add diversity: the point of the hint is to choose the next dial.
    /// Both loops are bounded by the directory capacity and the neighbour
    /// table, never by peer input.
    fn adds_diversity(
        now: u64,
        linked_candidate: bool,
        node: NodeId,
        config: &LinkHintConfig,
        directory: &NodeDirectory,
        neighbors: &NeighborTable,
    ) -> bool {
        if directory.is_empty() || config.min_diverse_nodes == 0 || linked_candidate {
            return false;
        }
        let linked: BTreeSet<NodeId> = neighbors
            .iter()
            .filter_map(|neighbor| neighbor.node_id)
            .collect();
        if linked.contains(&node) {
            return false;
        }
        let facts = directory.recent(now, directory.capacity());
        let reachable: BTreeSet<NodeId> = facts
            .iter()
            .filter(|fact| linked.contains(&fact.via))
            .map(|fact| fact.node)
            .collect();
        let mut unique = 0usize;
        for fact in &facts {
            if fact.via != node || reachable.contains(&fact.node) {
                continue;
            }
            unique += 1;
            if unique >= config.min_diverse_nodes {
                return true;
            }
        }
        false
    }

    fn evict_one(&mut self) -> Option<PeerKey> {
        // Match aoNetwork's own hint table: lowest preference first, then the
        // greatest key. Ties therefore never depend on insertion order.
        let victim = self
            .entries
            .iter()
            .min_by(|(a, av), (b, bv)| av.preference.cmp(&bv.preference).then_with(|| b.cmp(a)))
            .map(|(&peer, _)| peer);
        let peer = victim?;
        let entry = self.entries.remove(&peer)?;
        (entry.preference != LinkHintPreference::Neutral).then_some(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::BudgetConfig;
    use crate::directory::{DirectoryConfig, NodeObservation};
    use ao_network::LinkHintPreference as Pref;

    fn table(max_peers: usize) -> LinkHintTable {
        LinkHintTable::new(LinkHintConfig {
            max_peers,
            min_diverse_nodes: 1,
            ..LinkHintConfig::default()
        })
    }

    fn directory() -> NodeDirectory {
        NodeDirectory::new(DirectoryConfig::default())
    }

    fn neighbors() -> NeighborTable {
        NeighborTable::new(4)
    }

    fn budgets() -> BudgetTracker {
        BudgetTracker::new(BudgetConfig::default())
    }

    fn fact(via: u8, node: u8) -> NodeObservation<'static> {
        NodeObservation {
            node: NodeId::from_bytes([node; 16]),
            card_hash: [0; 8],
            caps: 0,
            seq: 1,
            hops: 1,
            via: NodeId::from_bytes([via; 16]),
            observed_at_ms: 0,
            location: &[],
        }
    }

    #[test]
    fn a_contact_tag_is_preferred_and_a_revocation_clears_it() {
        let mut table = table(2);
        let peer = PeerKey::new([3; 16]);
        let node = NodeId::from_bytes([9; 16]);
        let advice = table.observe(
            0,
            LinkHintObservation {
                peer,
                node,
                contact: true,
            },
            &directory(),
            &neighbors(),
            &budgets(),
        );
        assert_eq!(advice, vec![(peer, HintChange::Set(Pref::Prefer))]);
        assert_eq!(table.preference(peer), Pref::Prefer);
        let cleared = table.observe(
            0,
            LinkHintObservation {
                peer,
                node,
                contact: false,
            },
            &directory(),
            &neighbors(),
            &budgets(),
        );
        assert_eq!(cleared, vec![(peer, HintChange::Clear)]);
        assert_eq!(table.preference(peer), Pref::Neutral);
    }

    #[test]
    fn diversity_uses_only_nodes_no_current_neighbour_reaches() {
        let mut dir = directory();
        dir.observe(0, fact(9, 1)).expect("bounded fact");
        dir.observe(0, fact(9, 2)).expect("bounded fact");
        let mut table = table(2);
        let peer = PeerKey::new([4; 16]);
        let advice = table.observe(
            0,
            LinkHintObservation {
                peer,
                node: NodeId::from_bytes([9; 16]),
                contact: false,
            },
            &dir,
            &neighbors(),
            &budgets(),
        );
        assert_eq!(advice, vec![(peer, HintChange::Set(Pref::Prefer))]);
    }

    #[test]
    fn a_penalty_overrides_contact_then_refresh_recovers() {
        let mut budget = budgets();
        let link = LinkId::new(1);
        let _ = budget.penalize(0, link, 3);
        let mut table = table(2);
        let peer = PeerKey::new([5; 16]);
        let _ = table.observe(
            0,
            LinkHintObservation {
                peer,
                node: NodeId::from_bytes([7; 16]),
                contact: true,
            },
            &directory(),
            &neighbors(),
            &budget,
        );
        table.link_up(NodeId::from_bytes([7; 16]), link);
        let changes = table.refresh(0, &directory(), &neighbors(), &budget);
        assert_eq!(changes, vec![(peer, HintChange::Set(Pref::Deprioritize))]);

        let clean = budgets();
        let changes = table.refresh(1, &directory(), &neighbors(), &clean);
        assert_eq!(changes, vec![(peer, HintChange::Set(Pref::Prefer))]);
    }

    #[test]
    fn a_linked_candidate_no_longer_claims_diversity() {
        let mut dir = directory();
        dir.observe(0, fact(9, 1)).expect("bounded fact");
        dir.observe(0, fact(9, 2)).expect("bounded fact");
        let mut table = table(2);
        let node = NodeId::from_bytes([9; 16]);
        let peer = PeerKey::new([4; 16]);
        table.link_up(node, LinkId::new(7));
        let advice = table.observe(
            0,
            LinkHintObservation {
                peer,
                node,
                contact: false,
            },
            &dir,
            &neighbors(),
            &budgets(),
        );
        assert!(advice.is_empty(), "an already linked peer adds no new path");
        assert_eq!(table.preference(peer), Pref::Neutral);
    }

    #[test]
    fn a_link_up_before_the_host_fact_still_applies_its_penalty() {
        let node = NodeId::from_bytes([7; 16]);
        let mut budget = budgets();
        let link = LinkId::new(11);
        let _ = budget.penalize(0, link, 3);
        let mut table = table(2);
        table.link_up(node, link);

        let advice = table.observe(
            0,
            LinkHintObservation {
                peer: PeerKey::new([5; 16]),
                node,
                contact: true,
            },
            &directory(),
            &neighbors(),
            &budget,
        );
        assert_eq!(
            advice,
            vec![(PeerKey::new([5; 16]), HintChange::Set(Pref::Deprioritize))]
        );
    }

    #[test]
    fn capacity_eviction_is_deterministic_and_bounded() {
        let mut table = table(3);
        let budgets = budgets();
        let mut last = Vec::new();
        for byte in 1..=5u8 {
            let node = NodeId::from_bytes([byte; 16]);
            let peer = PeerKey::new([byte; 16]);
            last = table.observe(
                0,
                LinkHintObservation {
                    peer,
                    node,
                    contact: true,
                },
                &directory(),
                &neighbors(),
                &budgets,
            );
        }
        // Evicting a peer withdraws its advice in aoNetwork too, so the
        // capacity path emits a clear before the new preference.
        assert_eq!(
            last,
            vec![
                (PeerKey::new([4; 16]), HintChange::Clear),
                (PeerKey::new([5; 16]), HintChange::Set(Pref::Prefer)),
            ]
        );
        assert_eq!(table.len(), 3);
        // Every entry is equally preferred, so the greatest key is evicted
        // first: 3, then 4. Insertion order never affects the result.
        assert_eq!(table.preference(PeerKey::new([1; 16])), Pref::Prefer);
        assert_eq!(table.preference(PeerKey::new([2; 16])), Pref::Prefer);
        assert_eq!(table.preference(PeerKey::new([3; 16])), Pref::Neutral);
        assert_eq!(table.preference(PeerKey::new([4; 16])), Pref::Neutral);
        assert_eq!(table.preference(PeerKey::new([5; 16])), Pref::Prefer);
    }
}
