//! Store summaries and the beacon digest used before anti-entropy sync.
//!
//! Two nodes that meet first compare a four-byte digest. This module builds a
//! canonical, compact view of a [`MessageStore`] and debounces beacon updates
//! so a burst of inserts produces one `SetBeacon` output. The full message ids
//! stay in the store; only an eight-byte prefix is exposed as the summary
//! vector MSH-14 will exchange. The digest is a change detector, not a proof
//! of set equality: MSH-14 confirms differences with a full summary exchange.

use crate::packet::{MSG_ID_LEN, MessageId};
use crate::store::MessageStore;
use blake3::Hasher;

/// Number of message-id bytes in one compact summary entry.
///
/// Eight bytes keep a 1024-entry store's summary under 8 KiB while making a
/// prefix collision vanishingly unlikely at the store's bounded size. Longer
/// prefixes do not fit the sync wire budget MSH-14 will define.
pub const SHORT_ID_BYTES: usize = 8;

/// Length of the store digest carried in a beacon.
pub const BEACON_DIGEST_LEN: usize = 4;

/// One compact, canonical view of a store's live messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSummary {
    short_ids: Vec<[u8; SHORT_ID_BYTES]>,
    digest: [u8; BEACON_DIGEST_LEN],
}

impl StoreSummary {
    /// Canonicalises `ids` and derives the beacon digest.
    ///
    /// Input order and duplicate ids do not affect the result. The digest
    /// covers every full message id, not just the exposed prefix, so adding
    /// or removing one message changes it with overwhelming probability.
    #[must_use]
    pub fn from_ids(ids: &[MessageId]) -> Self {
        let mut full: Vec<[u8; MSG_ID_LEN]> = ids.iter().map(|id| *id.as_bytes()).collect();
        full.sort_unstable();
        full.dedup();

        let short_ids = full
            .iter()
            .map(|id| {
                let mut short = [0u8; SHORT_ID_BYTES];
                short.copy_from_slice(&id[..SHORT_ID_BYTES]);
                short
            })
            .collect();

        let mut hasher = Hasher::new();
        hasher.update(b"aoheyra/mesh/v1/store-summary");
        hasher.update(&(full.len() as u64).to_le_bytes());
        for id in &full {
            hasher.update(id);
        }
        let hash = hasher.finalize();
        let mut digest = [0u8; BEACON_DIGEST_LEN];
        digest.copy_from_slice(&hash.as_bytes()[..BEACON_DIGEST_LEN]);

        Self { short_ids, digest }
    }

    /// Reads the live summary of `store` at `now`.
    #[must_use]
    pub fn from_store<S: MessageStore>(store: &S, now: u64) -> Self {
        Self::from_ids(&store.summary(now))
    }

    /// Sorted short ids, one per live message.
    #[must_use]
    pub fn short_ids(&self) -> &[[u8; SHORT_ID_BYTES]] {
        &self.short_ids
    }

    /// The four-byte digest advertised through the beacon.
    #[must_use]
    pub const fn digest(&self) -> [u8; BEACON_DIGEST_LEN] {
        self.digest
    }

    /// Number of distinct live message ids.
    #[must_use]
    pub fn len(&self) -> usize {
        self.short_ids.len()
    }

    /// Whether the store has no live messages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.short_ids.is_empty()
    }
}

/// Beacon publication policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SummaryConfig {
    /// Minimum time a changed digest waits before it is published.
    ///
    /// A zero value publishes immediately. The default coalesces a burst of
    /// store writes into one beacon without delaying a link-up exchange.
    pub debounce_ms: u64,
    /// Opaque eight-byte discovery hint sent with every beacon.
    pub beacon_hint: [u8; 8],
}

impl Default for SummaryConfig {
    fn default() -> Self {
        Self {
            debounce_ms: 200,
            beacon_hint: [0; 8],
        }
    }
}

/// Tracks the last published digest and debounces replacements.
///
/// The engine owns this state; the host owns the store and supplies ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconTracker {
    config: SummaryConfig,
    published: Option<[u8; BEACON_DIGEST_LEN]>,
    pending: Option<([u8; BEACON_DIGEST_LEN], u64)>,
}

impl BeaconTracker {
    /// Creates a tracker that has not published a beacon yet.
    #[must_use]
    pub const fn new(config: SummaryConfig) -> Self {
        Self {
            config,
            published: None,
            pending: None,
        }
    }

    /// Records a digest and returns it when it is time to publish.
    ///
    /// A change restarts the debounce window. A digest that returns to the
    /// published value cancels the pending change, so transient store churn
    /// does not make the beacon flap. A backwards clock never shortens the
    /// window.
    pub fn observe(
        &mut self,
        now: u64,
        digest: [u8; BEACON_DIGEST_LEN],
    ) -> Option<[u8; BEACON_DIGEST_LEN]> {
        if self.published == Some(digest) {
            self.pending = None;
            return None;
        }
        let since = match self.pending {
            Some((pending, since)) if pending == digest => since,
            _ => {
                self.pending = Some((digest, now));
                now
            }
        };
        if now.saturating_sub(since) >= self.config.debounce_ms {
            self.published = Some(digest);
            self.pending = None;
            return Some(digest);
        }
        None
    }

    /// The digest currently published in the beacon, if any.
    #[must_use]
    pub const fn published_digest(&self) -> Option<[u8; BEACON_DIGEST_LEN]> {
        self.published
    }

    /// The opaque hint paired with the digest.
    #[must_use]
    pub const fn beacon_hint(&self) -> [u8; 8] {
        self.config.beacon_hint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketClass;
    use crate::store::{MemoryStore, StoreLimits, StoreMetadata};

    fn id(byte: u8) -> MessageId {
        MessageId::from_bytes([byte; 16])
    }

    fn config(debounce_ms: u64) -> SummaryConfig {
        SummaryConfig {
            debounce_ms,
            beacon_hint: [3; 8],
        }
    }

    fn stored(byte: u8) -> crate::store::StoredMessage {
        let header = crate::Header {
            class: PacketClass::Direct,
            dst: Some([9; 16]),
            msg_id: id(byte),
            origin: [7; 16],
            created_ms: 1_000,
            lifetime_s: 60,
            payload_len: 4,
            ttl: 8,
            hops: 0,
        };
        let mut wire = header.encode();
        wire.extend_from_slice(&[byte; 4]);
        crate::store::StoredMessage::new(
            &wire,
            StoreMetadata {
                copies_left: 1,
                first_seen: 1_000,
                received_at: 1_000,
                priority: 1,
                received_from: None,
                age_ms: 0,
            },
        )
        .unwrap_or_else(|e| panic!("fixture: {e}"))
    }

    #[test]
    fn canonical_ids_produce_the_same_summary() {
        let a = StoreSummary::from_ids(&[id(1), id(2), id(3)]);
        let b = StoreSummary::from_ids(&[id(3), id(2), id(1), id(1)]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 3);
        assert_eq!(a.short_ids()[0], [1; SHORT_ID_BYTES]);
    }

    #[test]
    fn one_different_message_changes_the_digest() {
        let a = StoreSummary::from_ids(&[id(1), id(2)]);
        let b = StoreSummary::from_ids(&[id(1), id(3)]);
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn store_summaries_match_identical_content() {
        let mut first = MemoryStore::new(StoreLimits::default());
        let mut second = MemoryStore::new(StoreLimits::default());
        assert!(first.put(1_000, stored(1)).unwrap_or_default().is_empty());
        assert!(second.put(1_000, stored(1)).unwrap_or_default().is_empty());
        assert!(first.put(1_000, stored(2)).unwrap_or_default().is_empty());
        assert!(second.put(1_000, stored(2)).unwrap_or_default().is_empty());
        assert_eq!(
            StoreSummary::from_store(&first, 1_000).digest(),
            StoreSummary::from_store(&second, 1_000).digest()
        );
        assert!(second.put(1_000, stored(3)).unwrap_or_default().is_empty());
        assert_ne!(
            StoreSummary::from_store(&first, 1_000).digest(),
            StoreSummary::from_store(&second, 1_000).digest()
        );
    }

    #[test]
    fn debounce_publishes_once_and_cancels_churn() {
        let mut tracker = BeaconTracker::new(config(100));
        let a = StoreSummary::from_ids(&[id(1)]).digest();
        let b = StoreSummary::from_ids(&[id(2)]).digest();
        assert_eq!(tracker.observe(10, a), None);
        assert_eq!(tracker.observe(50, a), None);
        assert_eq!(tracker.observe(110, a), Some(a));
        assert_eq!(tracker.observe(120, a), None);
        assert_eq!(tracker.observe(150, b), None);
        assert_eq!(tracker.observe(200, a), None);
        assert_eq!(tracker.published_digest(), Some(a));
        assert_eq!(tracker.observe(300, b), None);
        assert_eq!(tracker.observe(400, b), Some(b));
    }

    #[test]
    fn a_backwards_clock_does_not_publish_early() {
        let mut tracker = BeaconTracker::new(config(100));
        let digest = StoreSummary::from_ids(&[id(1)]).digest();
        assert_eq!(tracker.observe(500, digest), None);
        assert_eq!(tracker.observe(100, digest), None);
        assert_eq!(tracker.observe(600, digest), Some(digest));
    }
}
