//! Store summaries and the beacon digest used before anti-entropy sync.
//!
//! Two nodes that meet first compare a four-byte digest. This module builds a
//! canonical, compact view of a [`MessageStore`] and debounces beacon updates
//! so a burst of inserts produces one `SetBeacon` output. The full message ids
//! stay in the store; only an eight-byte prefix is exposed as the summary
//! vector MSH-14 will exchange. The digest is a change detector, not a proof
//! of set equality: MSH-14 confirms differences with a full summary exchange.

use crate::packet::{MSG_ID_LEN, MessageId, Packet};
use crate::store::MessageStore;
use ao_network::LinkId;
use blake3::Hasher;
use std::collections::{BTreeMap, BTreeSet};

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

/// Magic byte that separates a sync frame from a v1 mesh packet.
///
/// Packets start with their version byte (`1`), so this cannot be confused
/// with an application packet even on the shared Bulk channel.
pub const SYNC_MAGIC: u8 = 0x53;
/// Version of the MSH-14 sync frame format.
pub const SYNC_VERSION: u8 = 1;
/// Hard cap on one exchanged summary, matching the default store's entries.
pub const MAX_SUMMARY_ENTRIES: usize = 1024;

const FRAME_HEADER_LEN: usize = 5;
const TAG_DIGEST: u8 = 1;
const TAG_SUMMARY: u8 = 2;
const TAG_ITEM: u8 = 3;
const TAG_DONE: u8 = 4;

/// One bounded anti-entropy frame (MSH-14).
///
/// This is engine-to-engine control traffic on aoNetwork's Bulk channel,
/// not a mesh packet: it carries no origin signature of its own. The items
/// inside it are complete mesh packets and are checked before delivery to
/// the host store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncFrame {
    /// Advertises the sender's current store digest.
    Digest([u8; BEACON_DIGEST_LEN]),
    /// The sender's canonical short ids and the digest they hash to.
    Summary {
        /// Digest of the sender's full store ids.
        digest: [u8; BEACON_DIGEST_LEN],
        /// Sorted, deduplicated eight-byte prefixes.
        short_ids: Vec<[u8; SHORT_ID_BYTES]>,
    },
    /// One complete encoded mesh packet the peer was missing.
    Item(Vec<u8>),
    /// This contact has finished; the peer may release an opportunistic link.
    Done,
}

impl SyncFrame {
    /// Encodes the frame, or `None` if it exceeds the two-byte length field.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        let payload = match self {
            Self::Digest(digest) => {
                let mut out = Vec::with_capacity(BEACON_DIGEST_LEN);
                out.extend_from_slice(digest);
                out
            }
            Self::Summary { digest, short_ids } => {
                let mut out = Vec::with_capacity(6 + short_ids.len() * SHORT_ID_BYTES);
                out.extend_from_slice(digest);
                out.extend_from_slice(&(short_ids.len() as u16).to_be_bytes());
                for id in short_ids {
                    out.extend_from_slice(id);
                }
                out
            }
            Self::Item(wire) => wire.clone(),
            Self::Done => Vec::new(),
        };
        let len = u16::try_from(payload.len()).ok()?;
        let tag = match self {
            Self::Digest(_) => TAG_DIGEST,
            Self::Summary { .. } => TAG_SUMMARY,
            Self::Item(_) => TAG_ITEM,
            Self::Done => TAG_DONE,
        };
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        out.extend_from_slice(&[SYNC_MAGIC, SYNC_VERSION, tag]);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&payload);
        Some(out)
    }

    /// Parses a frame. `None` means "not a sync frame"; an error means the
    /// bytes claimed the sync magic but violated the bounded format.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Option<Self>, SyncError> {
        if bytes.first() != Some(&SYNC_MAGIC) {
            return Ok(None);
        }
        if bytes.len() < FRAME_HEADER_LEN {
            return Err(SyncError::Truncated);
        }
        if bytes[1] != SYNC_VERSION {
            return Err(SyncError::UnsupportedVersion);
        }
        let len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        let body = bytes
            .get(FRAME_HEADER_LEN..FRAME_HEADER_LEN.saturating_add(len))
            .ok_or(SyncError::Truncated)?;
        if bytes.len() != FRAME_HEADER_LEN.saturating_add(len) {
            return Err(SyncError::TrailingBytes);
        }
        match bytes[2] {
            TAG_DIGEST => {
                let digest: [u8; BEACON_DIGEST_LEN] =
                    body.try_into().map_err(|_| SyncError::BadLength)?;
                Ok(Some(Self::Digest(digest)))
            }
            TAG_SUMMARY => {
                if body.len() < 6 {
                    return Err(SyncError::Truncated);
                }
                let digest: [u8; BEACON_DIGEST_LEN] =
                    body[..4].try_into().map_err(|_| SyncError::BadLength)?;
                let count = u16::from_be_bytes([body[4], body[5]]) as usize;
                if count > MAX_SUMMARY_ENTRIES {
                    return Err(SyncError::TooManyEntries);
                }
                let bytes_needed = count.saturating_mul(SHORT_ID_BYTES);
                let ids = body.get(6..6 + bytes_needed).ok_or(SyncError::Truncated)?;
                if ids.len() != bytes_needed {
                    return Err(SyncError::Truncated);
                }
                let short_ids = ids
                    .chunks_exact(SHORT_ID_BYTES)
                    .map(|chunk| {
                        let mut id = [0u8; SHORT_ID_BYTES];
                        id.copy_from_slice(chunk);
                        id
                    })
                    .collect();
                Ok(Some(Self::Summary { digest, short_ids }))
            }
            TAG_ITEM => {
                if body.is_empty() {
                    return Err(SyncError::BadLength);
                }
                Ok(Some(Self::Item(body.to_vec())))
            }
            TAG_DONE => {
                if !body.is_empty() {
                    return Err(SyncError::BadLength);
                }
                Ok(Some(Self::Done))
            }
            _ => Err(SyncError::BadTag),
        }
    }
}

/// Typed rejection of a claimed MSH-14 frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncError {
    /// The magic matched but the fixed header was incomplete.
    Truncated,
    /// The sender speaks another sync version.
    UnsupportedVersion,
    /// Unknown frame tag.
    BadTag,
    /// A field had the wrong length for its tag.
    BadLength,
    /// The summary advertised more ids than the store bound allows.
    TooManyEntries,
    /// The frame had bytes after its declared length.
    TrailingBytes,
}

/// Byte and time bounds for one anti-entropy contact.
///
/// Defaults are in ADR-0001: 256 KiB per contact, 15 KiB per frame so the
/// default 16 KiB aoNetwork frame still fits, and a 20 second dwell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncConfig {
    /// Whether MSH-14 frames are sent and accepted. The MSH-13 beacon
    /// path stays active either way.
    pub enabled: bool,
    /// Maximum encoded item bytes sent to one peer in one contact.
    pub max_bytes_per_contact: usize,
    /// Maximum encoded bytes in one frame, clamped to the wire field.
    pub max_frame_bytes: usize,
    /// Contact deadline in caller-supplied milliseconds.
    pub timeout_ms: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_bytes_per_contact: 256 * 1024,
            max_frame_bytes: 15 * 1024,
            timeout_ms: 20_000,
        }
    }
}

/// One host-provided item offered for a requested short id.
///
/// The host owns the store; it resolves each requested prefix to a live
/// encoded packet. The engine checks the prefix against the packet's full
/// content address before sending it, so a confused host cannot redirect a
/// transfer.
#[derive(Debug, Clone, Copy)]
pub struct SyncOffer<'a> {
    /// The prefix the peer asked for.
    pub prefix: [u8; SHORT_ID_BYTES],
    /// Complete encoded mesh packet, borrowed only for this call.
    pub wire: &'a [u8],
}

#[derive(Debug, Clone)]
struct SyncSession {
    /// Prefixes this node must send: local ids the peer did not advertise.
    target: BTreeSet<[u8; SHORT_ID_BYTES]>,
    /// Prefixes this node expects: peer ids absent from its local summary.
    incoming: BTreeSet<[u8; SHORT_ID_BYTES]>,
    received: BTreeSet<[u8; SHORT_ID_BYTES]>,
    sent: BTreeSet<[u8; SHORT_ID_BYTES]>,
    bytes_sent: usize,
    deadline_ms: u64,
    done_sent: bool,
    released: bool,
}

impl SyncSession {
    fn new(now: u64, timeout_ms: u64) -> Self {
        Self {
            target: BTreeSet::new(),
            incoming: BTreeSet::new(),
            received: BTreeSet::new(),
            sent: BTreeSet::new(),
            bytes_sent: 0,
            deadline_ms: now.saturating_add(timeout_ms),
            done_sent: false,
            released: false,
        }
    }

    fn sent_all(&self) -> bool {
        !self.target.is_empty() && self.target.iter().all(|id| self.sent.contains(id))
    }

    fn received_all(&self) -> bool {
        !self.incoming.is_empty() && self.incoming.iter().all(|id| self.received.contains(id))
    }
}

/// Engine-to-host consequences of one sync action, kept separate from
/// network sends so the host can service store reads and writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SyncAction {
    /// Queue one control frame on the Bulk channel.
    Send {
        /// Destination link.
        link: LinkId,
        /// Bounded frame.
        frame: SyncFrame,
    },
    /// Ask the host for encoded packets matching these short ids.
    Need {
        /// Destination link.
        link: LinkId,
        /// Prefixes the peer is missing.
        prefixes: Vec<[u8; SHORT_ID_BYTES]>,
    },
    /// Hand an authenticated-envelope item to the host store.
    Item {
        /// Full content address parsed from the wire packet.
        id: MessageId,
        /// Complete encoded packet.
        wire: Vec<u8>,
    },
    /// The contact is over; release it if aoNetwork made it opportunistic.
    Release {
        /// Destination link.
        link: LinkId,
    },
}

/// Bounded per-link anti-entropy sessions plus the host's current summary.
#[derive(Debug)]
pub struct SyncTracker {
    config: SyncConfig,
    local: StoreSummary,
    sessions: BTreeMap<LinkId, SyncSession>,
}

impl SyncTracker {
    /// Creates an empty tracker; the host supplies its summary before a
    /// contact so the first digest comparison is meaningful.
    #[must_use]
    pub fn new(config: SyncConfig) -> Self {
        let config = SyncConfig {
            max_frame_bytes: config
                .max_frame_bytes
                .min(usize::from(u16::MAX) - FRAME_HEADER_LEN),
            ..config
        };
        Self {
            config,
            local: StoreSummary::from_ids(&[]),
            sessions: BTreeMap::new(),
        }
    }

    /// Replaces the cached host summary; bounded by the store's own limit.
    pub(crate) fn set_local(&mut self, ids: &[MessageId]) {
        self.local = StoreSummary::from_ids(ids);
    }

    /// The digest advertised in the current local summary.
    pub(crate) fn local_digest(&self) -> [u8; BEACON_DIGEST_LEN] {
        self.local.digest()
    }

    /// Opens a contact when the peer's hello advertises a different digest.
    pub(crate) fn start(
        &mut self,
        now: u64,
        link: LinkId,
        remote_digest: [u8; BEACON_DIGEST_LEN],
    ) -> Vec<SyncAction> {
        if !self.config.enabled || self.sessions.contains_key(&link) {
            return Vec::new();
        }
        if remote_digest == self.local_digest() {
            // Nothing to reconcile. The link may still be useful for normal
            // forwarding, so only a contact that actually ran an exchange is
            // released at the end.
            return Vec::new();
        }
        self.sessions
            .insert(link, SyncSession::new(now, self.config.timeout_ms));
        vec![SyncAction::Send {
            link,
            frame: SyncFrame::Digest(self.local_digest()),
        }]
    }

    /// Applies one frame from a verified neighbour.
    pub(crate) fn on_frame(&mut self, now: u64, link: LinkId, frame: SyncFrame) -> Vec<SyncAction> {
        if !self.config.enabled {
            return Vec::new();
        }
        match frame {
            SyncFrame::Digest(digest) => {
                if !self.sessions.contains_key(&link) {
                    self.sessions
                        .insert(link, SyncSession::new(now, self.config.timeout_ms));
                }
                if digest == self.local_digest() {
                    return self.finish(link);
                }
                let short_ids = self.local.short_ids().to_vec();
                vec![SyncAction::Send {
                    link,
                    frame: SyncFrame::Summary {
                        digest: self.local_digest(),
                        short_ids,
                    },
                }]
            }
            SyncFrame::Summary { digest, short_ids } => {
                if short_ids.len() > MAX_SUMMARY_ENTRIES {
                    return Vec::new();
                }
                let local_digest = self.local.digest();
                let local_ids = self.local.short_ids();
                let same_digest = digest == local_digest;
                let remote: BTreeSet<[u8; SHORT_ID_BYTES]> = short_ids.into_iter().collect();
                let target: BTreeSet<[u8; SHORT_ID_BYTES]> = local_ids
                    .iter()
                    .copied()
                    .filter(|id| !remote.contains(id))
                    .collect();
                let incoming: BTreeSet<[u8; SHORT_ID_BYTES]> = remote
                    .iter()
                    .copied()
                    .filter(|id| !local_ids.contains(id))
                    .collect();
                let has_incoming = !incoming.is_empty();
                let prefixes: Vec<[u8; SHORT_ID_BYTES]> = {
                    let session = self
                        .sessions
                        .entry(link)
                        .or_insert_with(|| SyncSession::new(now, self.config.timeout_ms));
                    session.target = target;
                    session.incoming = incoming;
                    session
                        .target
                        .iter()
                        .copied()
                        .filter(|id| !session.sent.contains(id))
                        .collect()
                };
                if same_digest {
                    return self.finish(link);
                }
                if prefixes.is_empty() {
                    // Nothing to send. If we also expect nothing, the stores
                    // already agree; otherwise wait for the peer's items.
                    if !has_incoming {
                        return self.finish(link);
                    }
                    return Vec::new();
                }
                vec![SyncAction::Need { link, prefixes }]
            }
            SyncFrame::Item(wire) => {
                if !self.sessions.contains_key(&link) {
                    return Vec::new();
                }
                if wire.len() > self.config.max_frame_bytes
                    || wire.len() > crate::store::MAX_STORED_PACKET
                {
                    return Vec::new();
                }
                let Some((id, prefix)) = checked_item(&wire) else {
                    return Vec::new();
                };
                let complete = {
                    let Some(session) = self.sessions.get_mut(&link) else {
                        return Vec::new();
                    };
                    if !session.incoming.contains(&prefix) || session.received.contains(&prefix) {
                        return Vec::new();
                    }
                    session.received.insert(prefix);
                    session.received_all() && (session.target.is_empty() || session.sent_all())
                };
                let mut actions = vec![SyncAction::Item { id, wire }];
                if complete {
                    actions.extend(self.send_done(link));
                }
                actions
            }
            SyncFrame::Done => self.finish(link),
        }
    }

    /// Sends host-provided items within the contact's byte budget.
    pub(crate) fn on_offers<'a>(
        &mut self,
        link: LinkId,
        offers: &[SyncOffer<'a>],
    ) -> Vec<SyncAction> {
        if !self.config.enabled {
            return Vec::new();
        }
        let mut actions = Vec::new();
        let (complete, can_finish) = {
            let Some(session) = self.sessions.get_mut(&link) else {
                return actions;
            };
            for offer in offers {
                if offer.wire.len() > self.config.max_frame_bytes
                    || offer.wire.len() > crate::store::MAX_STORED_PACKET
                    || session.sent.contains(&offer.prefix)
                {
                    continue;
                }
                let Some((_id, prefix)) = checked_item(offer.wire) else {
                    continue;
                };
                if prefix != offer.prefix || !session.target.contains(&prefix) {
                    continue;
                }

                let bytes = session.bytes_sent.saturating_add(offer.wire.len());
                if bytes > self.config.max_bytes_per_contact {
                    break;
                }
                session.bytes_sent = bytes;
                session.sent.insert(prefix);
                actions.push(SyncAction::Send {
                    link,
                    frame: SyncFrame::Item(offer.wire.to_vec()),
                });
            }
            (
                session.sent_all(),
                session.incoming.is_empty() || session.received_all(),
            )
        };
        if complete && can_finish {
            actions.extend(self.send_done(link));
        }
        actions
    }

    /// Drops sessions whose deadline passed and asks to release their links.
    pub(crate) fn expire(&mut self, now: u64) -> Vec<SyncAction> {
        let due: Vec<LinkId> = self
            .sessions
            .iter()
            .filter(|(_, session)| now >= session.deadline_ms)
            .map(|(link, _)| *link)
            .collect();
        due.into_iter()
            .map(|link| {
                self.sessions.remove(&link);
                SyncAction::Release { link }
            })
            .collect()
    }

    /// Forgets a closed link; the host store keeps whatever arrived.
    pub(crate) fn link_down(&mut self, link: LinkId) {
        self.sessions.remove(&link);
    }

    fn send_done(&mut self, link: LinkId) -> Vec<SyncAction> {
        let Some(session) = self.sessions.get_mut(&link) else {
            return Vec::new();
        };
        if session.done_sent {
            return Vec::new();
        }
        session.done_sent = true;
        vec![SyncAction::Send {
            link,
            frame: SyncFrame::Done,
        }]
    }

    fn release(&mut self, link: LinkId) -> Vec<SyncAction> {
        let Some(session) = self.sessions.get_mut(&link) else {
            return Vec::new();
        };
        if session.released {
            return Vec::new();
        }
        session.released = true;
        session.deadline_ms = u64::MAX;
        vec![SyncAction::Release { link }]
    }

    fn finish(&mut self, link: LinkId) -> Vec<SyncAction> {
        let mut actions = self.send_done(link);
        actions.extend(self.release(link));
        actions
    }
}

/// Checks the only parts of an incoming item the engine can verify without
/// an origin key: bounded decode, canonical content address and a storable
/// class. Final authenticity remains the store owner's responsibility.
fn checked_item(wire: &[u8]) -> Option<(MessageId, [u8; SHORT_ID_BYTES])> {
    let packet = Packet::decode(wire).ok()?;
    if packet.header.class == crate::PacketClass::Telemetry
        || crate::sign::derive_msg_id(&packet.header, packet.payload) != packet.header.msg_id
    {
        return None;
    }
    let bytes = packet.header.msg_id.as_bytes();
    let mut prefix = [0u8; SHORT_ID_BYTES];
    prefix.copy_from_slice(&bytes[..SHORT_ID_BYTES]);
    Some((packet.header.msg_id, prefix))
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

    #[test]
    fn sync_frames_round_trip_and_reject_bad_wires() {
        let frames = [
            SyncFrame::Digest([7; BEACON_DIGEST_LEN]),
            SyncFrame::Summary {
                digest: [8; BEACON_DIGEST_LEN],
                short_ids: vec![[1; SHORT_ID_BYTES], [2; SHORT_ID_BYTES]],
            },
            SyncFrame::Item(vec![9; 32]),
            SyncFrame::Done,
        ];
        for frame in frames {
            let bytes = frame.encode().expect("fixture fits the length field");
            assert_eq!(SyncFrame::decode(&bytes).unwrap(), Some(frame));
        }
        assert_eq!(SyncFrame::decode(&[0x01, 0x00]), Ok(None));

        let mut wrong_version = SyncFrame::Done.encode().unwrap();
        wrong_version[1] = SYNC_VERSION + 1;
        assert_eq!(
            SyncFrame::decode(&wrong_version),
            Err(SyncError::UnsupportedVersion)
        );
        let truncated = &SyncFrame::Done.encode().unwrap()[..FRAME_HEADER_LEN - 1];
        assert_eq!(SyncFrame::decode(truncated), Err(SyncError::Truncated));
        let mut trailing = SyncFrame::Done.encode().unwrap();
        trailing.push(0);
        assert_eq!(SyncFrame::decode(&trailing), Err(SyncError::TrailingBytes));
    }

    #[test]
    fn summary_frames_reject_more_ids_than_the_store_bound() {
        let too_many = vec![[0; SHORT_ID_BYTES]; MAX_SUMMARY_ENTRIES + 1];
        let bytes = SyncFrame::Summary {
            digest: [0; BEACON_DIGEST_LEN],
            short_ids: too_many,
        }
        .encode()
        .expect("bound still fits the wire field");
        assert_eq!(SyncFrame::decode(&bytes), Err(SyncError::TooManyEntries));
    }

    fn signed_wire(identity: &ao_idents::Identity, tag: u8) -> Vec<u8> {
        let payload = vec![tag; 4];
        let mut header = crate::Header {
            class: PacketClass::Broadcast,
            dst: None,
            msg_id: [0; MSG_ID_LEN].into(),
            origin: [0; 16],
            created_ms: 1_000,
            lifetime_s: 60,
            payload_len: payload.len() as u64,
            ttl: 4,
            hops: 0,
        };
        let signature = crate::sign_packet(identity, &mut header, &payload)
            .expect("fixture signs with a local identity");
        crate::Packet::new(header, signature, &payload)
            .expect("fixture fields agree")
            .encode()
    }

    #[test]
    fn a_contact_sends_no_more_than_its_byte_budget() {
        let identity = ao_idents::Identity::from_seed([3; 32]);
        let first = signed_wire(&identity, 1);
        let second = signed_wire(&identity, 2);
        let first_id = Packet::decode(&first).unwrap().header.msg_id;
        let second_id = Packet::decode(&second).unwrap().header.msg_id;
        let config = SyncConfig {
            max_bytes_per_contact: first.len(),
            ..SyncConfig::default()
        };
        let mut tracker = SyncTracker::new(config);
        tracker.set_local(&[first_id, second_id]);
        let link = LinkId::new(1);
        let actions = tracker.on_frame(
            0,
            link,
            SyncFrame::Summary {
                digest: [9; BEACON_DIGEST_LEN],
                short_ids: Vec::new(),
            },
        );
        let SyncAction::Need { prefixes, .. } = &actions[0] else {
            panic!("an empty remote summary asks for every local id");
        };
        assert_eq!(prefixes.len(), 2);

        let offers = [
            SyncOffer {
                prefix: {
                    let mut prefix = [0; SHORT_ID_BYTES];
                    prefix.copy_from_slice(&first_id.as_bytes()[..SHORT_ID_BYTES]);
                    prefix
                },
                wire: &first,
            },
            SyncOffer {
                prefix: {
                    let mut prefix = [0; SHORT_ID_BYTES];
                    prefix.copy_from_slice(&second_id.as_bytes()[..SHORT_ID_BYTES]);
                    prefix
                },
                wire: &second,
            },
        ];
        let actions = tracker.on_offers(link, &offers);
        let sent = actions
            .iter()
            .filter(|action| matches!(action, SyncAction::Send { .. }))
            .count();
        assert_eq!(sent, 1, "the byte bound stops the second item");
    }
}
