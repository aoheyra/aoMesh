//! Bounded per-link bookkeeping, including the verified identity from
//! MSH-07's signed `MeshHello`.

use ao_idents::NodeId;
use ao_network::{Hello, LinkId};
use std::collections::BTreeMap;

/// Limits for engine-owned state. These do not enforce radio topology policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshConfig {
    /// Maximum neighbour entries; zero refuses every new link.
    pub max_neighbors: usize,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self { max_neighbors: 32 }
    }
}

/// One transport-ready neighbour, with the identity its introduction
/// proved (MSH-07).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    /// Local link identifier.
    pub link: LinkId,
    /// Untrusted link introduction, bounded by aoNetwork's AppHello type.
    pub remote_hello: Hello,
    /// The verified mesh identity, or `None` when the introduction did
    /// not decode, verify or negotiate: the link still counts traffic,
    /// but nothing may forward, deliver or budget on its behalf.
    pub node_id: Option<NodeId>,
    /// Caller-supplied connection time in milliseconds.
    pub connected_at_ms: u64,
    /// Caller-supplied time of the latest received packet, if any.
    pub last_rx_ms: Option<u64>,
    /// Bytes received, including malformed packets; saturates on overflow.
    pub received_bytes: u64,
    /// Structurally valid packets received, not authentication or delivery.
    pub received_packets: u64,
    /// Structurally invalid packets received.
    pub malformed_packets: u64,
}

/// Deterministically ordered entries, bounded by MeshConfig::max_neighbors.
#[derive(Debug)]
pub struct NeighborTable {
    limit: usize,
    entries: BTreeMap<LinkId, Neighbor>,
}

impl NeighborTable {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            entries: BTreeMap::new(),
        }
    }
    /// Number of tracked links.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether no links are tracked.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Looks up an entry without changing its counters or trust.
    pub fn get(&self, link: LinkId) -> Option<&Neighbor> {
        self.entries.get(&link)
    }
    /// Entries in link-id order, independent of platform hash seeds.
    pub fn iter(&self) -> impl Iterator<Item = &Neighbor> {
        self.entries.values()
    }
    /// Whether a link id is already tracked.
    pub(crate) fn contains(&self, link: LinkId) -> bool {
        self.entries.contains_key(&link)
    }
    /// Whether one more entry would fit the bound.
    pub(crate) fn has_room(&self) -> bool {
        self.entries.len() < self.limit
    }
    /// Records a transport-ready neighbour with the identity the engine
    /// verified, `None` for a rejected introduction. The caller has
    /// already checked [`Self::contains`] and [`Self::has_room`].
    pub(crate) fn insert(&mut self, now: u64, link: LinkId, hello: Hello, node_id: Option<NodeId>) {
        debug_assert!(self.has_room(), "insert past the neighbour bound");
        debug_assert!(!self.contains(link), "insert over a live link");
        self.entries.insert(
            link,
            Neighbor {
                link,
                remote_hello: hello,
                node_id,
                connected_at_ms: now,
                last_rx_ms: None,
                received_bytes: 0,
                received_packets: 0,
                malformed_packets: 0,
            },
        );
    }
    pub(crate) fn remove(&mut self, link: LinkId) {
        self.entries.remove(&link);
    }
    pub(crate) fn received(&mut self, now: u64, link: LinkId, bytes: usize, valid: bool) {
        if let Some(n) = self.entries.get_mut(&link) {
            n.last_rx_ms = Some(now);
            n.received_bytes = n.received_bytes.saturating_add(bytes as u64);
            if valid {
                n.received_packets = n.received_packets.saturating_add(1);
            } else {
                n.malformed_packets = n.malformed_packets.saturating_add(1);
            }
        }
    }
}
