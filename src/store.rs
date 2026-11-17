//! Bounded, deterministic storage policy for opaque mesh packets.
//!
//! Callers validate authenticity before insertion. This module parses only the
//! bounded header and never interprets application content or holds keys.
use crate::expiry::LifetimePolicy;
use crate::packet::{Header, MAX_PAYLOAD, PacketClass, PacketError};
use std::collections::BTreeMap;
use std::fmt;

/// Opaque message identifier.
pub type MessageId = [u8; 16];
/// Opaque node identifier.
pub type NodeId = [u8; 16];
/// Maximum stored envelope, including signature material and header.
pub const MAX_STORED_PACKET: usize = MAX_PAYLOAD + 512;

/// Resource limits. Bytes count the complete encoded packet; entries bound metadata.
#[derive(Debug, Clone, Copy)]
pub struct StoreLimits {
    /// Maximum number of entries.
    pub entries: usize,
    /// Total encoded bytes.
    pub total_bytes: usize,
    /// Encoded bytes belonging to one origin.
    pub per_origin_bytes: usize,
    /// Encoded bytes by class: Direct, Broadcast, Presence, Telemetry.
    pub per_class_bytes: [usize; 4],
}
impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            entries: 1024,
            total_bytes: 2 * 1024 * 1024,
            per_origin_bytes: 256 * 1024,
            per_class_bytes: [2 * 1024 * 1024, 512 * 1024, 64 * 1024, 0],
        }
    }
}

/// Local metadata, separate from the immutable wire packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreMetadata {
    /// Remaining spray copies, maintained by the caller.
    pub copies_left: u8,
    /// Local monotonic first encounter, in milliseconds.
    pub first_seen: u64,
    /// Local monotonic receipt time, in milliseconds.
    pub received_at: u64,
    /// Scheduling priority: smaller numbers are more important.
    pub priority: u8,
    /// Ingress neighbour, when known.
    pub received_from: Option<NodeId>,
    /// Relative age already consumed before this receipt, in milliseconds.
    pub age_ms: u64,
}

/// An owned, bounded wire packet and its local metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    header: Header,
    wire: Vec<u8>,
    metadata: StoreMetadata,
}
impl StoredMessage {
    /// Validate envelope bounds without allocating until the header passes.
    /// Signature verification remains the caller's responsibility.
    pub fn new(wire: &[u8], metadata: StoreMetadata) -> Result<Self, StoreError> {
        if wire.len() > MAX_STORED_PACKET {
            return Err(StoreError::TooLarge);
        }
        let header = Header::decode(wire).map_err(StoreError::Packet)?;
        let minimum = header.encode().len() + header.payload_len as usize;
        if wire.len() < minimum {
            return Err(StoreError::Truncated);
        }
        if header.class == PacketClass::Telemetry {
            return Err(StoreError::NotStorable);
        }
        if metadata.first_seen > metadata.received_at {
            return Err(StoreError::InvalidTime);
        }
        Ok(Self {
            header,
            wire: wire.to_vec(),
            metadata,
        })
    }
    /// Parsed immutable routing metadata.
    pub fn header(&self) -> &Header {
        &self.header
    }
    /// Complete encoded bytes, including any signature envelope.
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }
    /// Local store metadata.
    pub fn metadata(&self) -> &StoreMetadata {
        &self.metadata
    }
    /// Encoded storage cost in bytes.
    pub fn size(&self) -> usize {
        self.wire.len()
    }
    /// Expiry uses local elapsed time plus consumed age, never remote timestamps.
    pub fn is_expired(&self, now: u64) -> bool {
        self.is_expired_with(&LifetimePolicy::default(), now)
    }
    /// Apply a store's local lifetime ceilings without changing signed bytes.
    pub fn is_expired_with(&self, policy: &LifetimePolicy, now: u64) -> bool {
        policy.is_expired(
            &self.header,
            self.metadata.received_at,
            self.metadata.age_ms,
            now,
        )
    }
}

/// Typed storage failure; unsuccessful insertion leaves the store unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Header codec rejected the packet.
    Packet(PacketError),
    /// Envelope exceeds the hard bound.
    TooLarge,
    /// Encoded payload is incomplete.
    Truncated,
    /// Telemetry is latest-wins and is never persisted.
    NotStorable,
    /// Local timestamps are inconsistent or ahead of the supplied clock.
    InvalidTime,
    /// Message lifetime has elapsed.
    Expired,
    /// A live entry with this identifier already exists; duplicates cannot refresh it.
    Duplicate,
    /// Entry cannot fit even in an otherwise empty store.
    Quota,
}
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for StoreError {}

/// Storage seam implemented by the app's SQLite backend as well as memory.
///
/// Results and summaries are ordered lexicographically by message ID. Insertion
/// first removes expired entries, then evicts within violated quota scopes by
/// most replicated (fewest copies left), lowest priority, oldest first_seen,
/// and finally message ID. Duplicate insertion never changes existing metadata.
/// Backends must make insertion and its evictions atomic.
pub trait MessageStore {
    /// Insert and return removed message IDs in deterministic eviction order.
    fn put(&mut self, now: u64, entry: StoredMessage) -> Result<Vec<MessageId>, StoreError>;
    /// Fetch a live entry; expired entries are not exposed.
    fn get(&self, now: u64, id: &MessageId) -> Option<&StoredMessage>;
    /// Live message IDs addressed to a destination.
    fn by_destination(&self, now: u64, dst: &NodeId) -> Vec<MessageId>;
    /// Live message IDs in canonical order.
    fn summary(&self, now: u64) -> Vec<MessageId>;
    /// Remove expired entries and return their IDs in canonical order.
    fn expire(&mut self, now: u64) -> Vec<MessageId>;
    /// Explicitly remove an entry, including an expired one.
    fn evict(&mut self, id: &MessageId) -> Option<StoredMessage>;
}

/// In-memory reference implementation with bounded metadata and packet bytes.
#[derive(Debug)]
pub struct MemoryStore {
    limits: StoreLimits,
    lifetime_policy: LifetimePolicy,
    entries: BTreeMap<MessageId, StoredMessage>,
}
impl MemoryStore {
    /// Start an empty store with explicit quotas (zero disables that scope).
    pub fn new(limits: StoreLimits) -> Self {
        Self::with_lifetime_policy(limits, LifetimePolicy::default())
    }
    /// Start a store with immutable local lifetime ceilings.
    /// All admission, lookup, summary, expiry and eviction use this policy.
    pub fn with_lifetime_policy(limits: StoreLimits, lifetime_policy: LifetimePolicy) -> Self {
        Self {
            limits,
            lifetime_policy,
            entries: BTreeMap::new(),
        }
    }
    /// Bytes currently held, including entries not yet swept for expiry.
    pub fn used_bytes(&self) -> usize {
        self.entries.values().map(StoredMessage::size).sum()
    }
}
fn class_index(class: PacketClass) -> usize {
    class as usize - 1
}
impl MessageStore for MemoryStore {
    fn put(&mut self, now: u64, entry: StoredMessage) -> Result<Vec<MessageId>, StoreError> {
        if entry.metadata.received_at > now {
            return Err(StoreError::InvalidTime);
        }
        if entry.is_expired_with(&self.lifetime_policy, now) {
            return Err(StoreError::Expired);
        }
        let id = entry.header.msg_id;
        if self.get(now, &id).is_some() {
            return Err(StoreError::Duplicate);
        }
        let class = class_index(entry.header.class);
        if self.limits.entries == 0
            || entry.size() > self.limits.total_bytes
            || entry.size() > self.limits.per_origin_bytes
            || entry.size() > self.limits.per_class_bytes[class]
        {
            return Err(StoreError::Quota);
        }
        let mut removed = self.expire(now);
        loop {
            let total = self.used_bytes();
            let origin: usize = self
                .entries
                .values()
                .filter(|e| e.header.origin == entry.header.origin)
                .map(StoredMessage::size)
                .sum();
            let class_bytes: usize = self
                .entries
                .values()
                .filter(|e| e.header.class == entry.header.class)
                .map(StoredMessage::size)
                .sum();
            let origin_full = origin > self.limits.per_origin_bytes - entry.size();
            let class_full = class_bytes > self.limits.per_class_bytes[class] - entry.size();
            if !origin_full
                && !class_full
                && self.entries.len() < self.limits.entries
                && total <= self.limits.total_bytes - entry.size()
            {
                break;
            }
            // When a scoped quota is exceeded, evict only entries that relieve
            // that scope. Global pressure otherwise considers every entry.
            let victim = self
                .entries
                .iter()
                .filter(|(_, e)| {
                    if origin_full {
                        e.header.origin == entry.header.origin
                    } else if class_full {
                        e.header.class == entry.header.class
                    } else {
                        true
                    }
                })
                .min_by_key(|(id, e)| {
                    (
                        e.metadata.copies_left,
                        std::cmp::Reverse(e.metadata.priority),
                        e.metadata.first_seen,
                        **id,
                    )
                })
                .map(|(id, _)| *id);
            // A violated quota always has an existing entry: the incoming
            // entry was checked to fit alone. Each iteration removes one.
            if let Some(victim) = victim {
                self.entries.remove(&victim);
                removed.push(victim);
            } else {
                break;
            }
        }
        self.entries.insert(id, entry);
        Ok(removed)
    }
    fn get(&self, now: u64, id: &MessageId) -> Option<&StoredMessage> {
        self.entries
            .get(id)
            .filter(|e| !e.is_expired_with(&self.lifetime_policy, now))
    }
    fn by_destination(&self, now: u64, dst: &NodeId) -> Vec<MessageId> {
        self.entries
            .iter()
            .filter(|(_, e)| {
                e.header.dst.as_ref() == Some(dst) && !e.is_expired_with(&self.lifetime_policy, now)
            })
            .map(|(id, _)| *id)
            .collect()
    }
    fn summary(&self, now: u64) -> Vec<MessageId> {
        self.entries
            .iter()
            .filter(|(_, e)| !e.is_expired_with(&self.lifetime_policy, now))
            .map(|(id, _)| *id)
            .collect()
    }
    fn expire(&mut self, now: u64) -> Vec<MessageId> {
        let ids: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_expired_with(&self.lifetime_policy, now))
            .map(|(id, _)| *id)
            .collect();
        for id in &ids {
            self.entries.remove(id);
        }
        ids
    }
    fn evict(&mut self, id: &MessageId) -> Option<StoredMessage> {
        self.entries.remove(id)
    }
}

/// Reusable backend conformance checks. SQLite implementations should invoke
/// [`conformance::check`] with a factory that creates a fresh empty database.
pub mod conformance {
    use super::*;
    /// A reproducible small entry for backend tests; no cryptographic claim.
    pub fn entry(
        id: u8,
        origin: u8,
        class: PacketClass,
        copies: u8,
        priority: u8,
        received_at: u64,
    ) -> StoredMessage {
        let header = Header {
            class,
            dst: Some([9; 16]),
            msg_id: [id; 16],
            origin: [origin; 16],
            created_ms: u64::MAX,
            lifetime_s: 10,
            payload_len: 4,
            ttl: 8,
            hops: 0,
        };
        let mut wire = header.encode();
        wire.extend_from_slice(&[0; 4]);
        StoredMessage::new(
            &wire,
            StoreMetadata {
                copies_left: copies,
                priority,
                first_seen: received_at,
                received_at,
                received_from: None,
                age_ms: 0,
            },
        )
        .unwrap_or_else(|e| panic!("conformance fixture: {e}"))
    }
    /// Verify ordering, duplicate protection, expiry, quotas and eviction.
    /// Panics only on a backend contract violation; this is a test helper.
    pub fn check<S: MessageStore>(mut factory: impl FnMut(StoreLimits) -> S) {
        let sample = entry(1, 1, PacketClass::Direct, 6, 1, 0);
        let size = sample.size();
        let limits = StoreLimits {
            entries: 2,
            total_bytes: size * 2,
            per_origin_bytes: size * 2,
            per_class_bytes: [size * 2; 4],
        };
        let mut store = factory(limits);
        assert_eq!(store.put(0, sample.clone()), Ok(vec![]));
        assert_eq!(store.get(0, &[1; 16]), Some(&sample));
        assert_eq!(
            store.put(1, entry(1, 1, PacketClass::Direct, 6, 1, 1)),
            Err(StoreError::Duplicate)
        );
        assert_eq!(store.get(1, &[1; 16]), Some(&sample));
        assert_eq!(
            store.put(0, entry(2, 2, PacketClass::Direct, 1, 1, 0)),
            Ok(vec![])
        );
        assert_eq!(store.summary(0), vec![[1; 16], [2; 16]]);
        assert_eq!(store.by_destination(0, &[9; 16]), store.summary(0));
        assert!(store.by_destination(0, &[8; 16]).is_empty());
        assert_eq!(
            store.put(0, entry(3, 3, PacketClass::Direct, 6, 1, 0)),
            Ok(vec![[2; 16]])
        );
        assert!(store.summary(10_000).is_empty());
        assert_eq!(store.expire(10_000), vec![[1; 16], [3; 16]]);
        assert_eq!(store.put(10_000, sample), Err(StoreError::Expired));
        assert!(store.evict(&[1; 16]).is_none());

        let mut store = factory(StoreLimits {
            per_origin_bytes: size,
            ..limits
        });
        assert_eq!(
            store.put(0, entry(1, 1, PacketClass::Direct, 6, 1, 0)),
            Ok(vec![])
        );
        assert_eq!(
            store.put(0, entry(2, 2, PacketClass::Direct, 1, 4, 0)),
            Ok(vec![])
        );
        assert_eq!(
            store.put(0, entry(3, 1, PacketClass::Direct, 6, 1, 0)),
            Ok(vec![[1; 16]])
        );
        assert!(store.get(0, &[2; 16]).is_some());
        assert!(store.evict(&[3; 16]).is_some());
        let mut store = factory(StoreLimits {
            per_class_bytes: [size; 4],
            ..limits
        });
        assert_eq!(
            store.put(0, entry(1, 1, PacketClass::Broadcast, 6, 1, 0)),
            Ok(vec![])
        );
        assert_eq!(
            store.put(0, entry(2, 2, PacketClass::Direct, 1, 4, 0)),
            Ok(vec![])
        );
        assert_eq!(
            store.put(0, entry(3, 3, PacketClass::Broadcast, 6, 1, 0)),
            Ok(vec![[1; 16]])
        );
        assert!(store.get(0, &[2; 16]).is_some());
        let mut store = factory(StoreLimits {
            total_bytes: size - 1,
            ..limits
        });
        assert_eq!(
            store.put(0, entry(1, 1, PacketClass::Direct, 6, 1, 0)),
            Err(StoreError::Quota)
        );
        assert!(store.summary(0).is_empty());
    }
}
