//! Store summaries and the beacon digest used before anti-entropy sync.
//!
//! Two nodes that meet first compare a four-byte digest. This module builds a
//! canonical, compact view of a [`MessageStore`] and debounces beacon updates
//! so a burst of inserts produces one `SetBeacon` output. The full message ids
//! stay in the store; only an eight-byte prefix is exposed as the summary
//! vector MSH-14 will exchange. The digest is a change detector, not a proof
//! of set equality: MSH-14 confirms differences with a full summary exchange.

use crate::observability::Counter;
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
    /// Canonical full ids are cached so MSH-15 can hash id ranges without
    /// reading the host store. Bounded by the store's own 1024-entry cap.
    full_ids: Vec<[u8; MSG_ID_LEN]>,
    short_ids: Vec<[u8; SHORT_ID_BYTES]>,
    digest: [u8; BEACON_DIGEST_LEN],
}

impl StoreSummary {
    /// Canonicalises `ids` and derives the beacon digest.
    ///
    /// Input order and duplicate ids do not affect the result. The digest
    /// covers every full message id, not just the exposed prefix, so adding
    /// or removing one message changes it with overwhelming probability.
    ///
    /// At most [`MAX_SUMMARY_ENTRIES`] ids are read (MSH-28). The engine's
    /// own store is capped at that many live messages, so a longer slice
    /// can only be a host mistake or a hostile stream; ignoring its tail
    /// keeps the digest and the summary the same bounded view.
    #[must_use]
    pub fn from_ids(ids: &[MessageId]) -> Self {
        let mut full: Vec<[u8; MSG_ID_LEN]> = ids
            .iter()
            .take(MAX_SUMMARY_ENTRIES)
            .map(|id| *id.as_bytes())
            .collect();
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

        Self {
            full_ids: full,
            short_ids,
            digest,
        }
    }

    /// Reads the live summary of `store` at `now`.
    #[must_use]
    pub fn from_store<S: MessageStore>(store: &S, now: u64) -> Self {
        Self::from_ids(&store.summary(now))
    }

    /// Sorted full ids, one per live message (MSH-15 range hashing).
    #[must_use]
    pub(crate) fn full_ids(&self) -> &[[u8; MSG_ID_LEN]] {
        &self.full_ids
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

/// Hard cap on the body of one sync frame.
///
/// The largest legitimate body is a full 1024-entry MSH-14 summary
/// (6 + 1024 * 8 = 8198 bytes); every MSH-15 frame is smaller than that.
/// A claimed body longer than this is rejected before any slice is copied,
/// so a hostile `Item` or `SprayItem` cannot make the decoder allocate the
/// full 64 KiB the two-byte length field could express (MSH-28).
pub const MAX_FRAME_BODY_BYTES: usize = 6 + MAX_SUMMARY_ENTRIES * SHORT_ID_BYTES;

const FRAME_HEADER_LEN: usize = 5;
const TAG_DIGEST: u8 = 1;
const TAG_SUMMARY: u8 = 2;
const TAG_ITEM: u8 = 3;
const TAG_DONE: u8 = 4;
const TAG_SPRAY_ITEM: u8 = 5;

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
    /// One packet with its MSH-16 copy ticket, for spray-capable peers only.
    SprayItem {
        /// Remaining copies the receiving host should record.
        copies: u8,
        /// Complete encoded mesh packet.
        wire: Vec<u8>,
    },
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
            Self::SprayItem { copies, wire } => {
                let mut out = Vec::with_capacity(1 + wire.len());
                out.push(*copies);
                out.extend_from_slice(wire);
                out
            }
            Self::Done => Vec::new(),
        };
        let len = u16::try_from(payload.len()).ok()?;
        let tag = match self {
            Self::Digest(_) => TAG_DIGEST,
            Self::Summary { .. } => TAG_SUMMARY,
            Self::Item(_) => TAG_ITEM,
            Self::SprayItem { .. } => TAG_SPRAY_ITEM,
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
    ///
    /// Decoding is bounded before it allocates: a summary is capped by
    /// [`MAX_SUMMARY_ENTRIES`], every other tag by [`MAX_FRAME_BODY_BYTES`]
    /// (MSH-28).
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, SyncError> {
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
        // MSH-14 summaries carry their own count and an exact-length check
        // below, so they keep their historical `TooManyEntries` rejection
        // even when the declared length is over this general cap. Every
        // other tag is rejected here, before a slice of hostile size is
        // copied into an `Item` or `SprayItem` (MSH-28).
        if len > MAX_FRAME_BODY_BYTES && bytes[2] != TAG_SUMMARY {
            return Err(SyncError::FrameTooLarge(len));
        }
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
                if body.len() != 6 + bytes_needed {
                    // Extra bytes inside the declared body would be a
                    // second, unauthenticated encoding of the same summary.
                    return Err(SyncError::BadLength);
                }
                let ids = &body[6..];
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
            TAG_SPRAY_ITEM => {
                let Some((copies, wire)) = body.split_first() else {
                    return Err(SyncError::BadLength);
                };
                if *copies == 0 {
                    return Err(SyncError::BadCopies(*copies));
                }
                if wire.is_empty() {
                    return Err(SyncError::BadLength);
                }
                Ok(Some(Self::SprayItem {
                    copies: *copies,
                    wire: wire.to_vec(),
                }))
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
///
/// Public so fuzz targets and hosts can inspect a rejection without
/// stringly-typed errors (MSH-28).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncError {
    /// The magic matched but the fixed header was incomplete.
    Truncated,
    /// The sender speaks another sync version.
    UnsupportedVersion,
    /// Unknown frame tag.
    BadTag,
    /// A field had the wrong length for its tag.
    BadLength,
    /// A spray item advertised an out-of-range copy ticket.
    BadCopies(u8),
    /// The summary advertised more ids than the store bound allows.
    TooManyEntries,
    /// The frame had bytes after its declared length.
    TrailingBytes,
    /// The declared body exceeds [`MAX_FRAME_BODY_BYTES`] for a tag that
    /// has no count-based bound. Holds the declared length.
    FrameTooLarge(usize),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated sync frame"),
            Self::UnsupportedVersion => write!(f, "unsupported sync version"),
            Self::BadTag => write!(f, "unknown sync frame tag"),
            Self::BadLength => write!(f, "sync frame field has the wrong length"),
            Self::BadCopies(copies) => write!(f, "invalid spray copy ticket {copies}"),
            Self::TooManyEntries => write!(f, "sync summary exceeds the store bound"),
            Self::TrailingBytes => write!(f, "trailing bytes after the sync frame"),
            Self::FrameTooLarge(len) => {
                write!(f, "sync frame body {len} exceeds {MAX_FRAME_BODY_BYTES}")
            }
        }
    }
}

impl std::error::Error for SyncError {}

/// Version of the MSH-15 range-reconciliation frames.
pub const SYNC_V2_VERSION: u8 = 2;
const TAG_V2_ROOT: u8 = 1;
const TAG_V2_RANGES: u8 = 2;
const TAG_V2_REQUEST: u8 = 3;
const TAG_V2_IDS: u8 = 4;
const TAG_V2_READY: u8 = 5;
const RANGE_KEY_LEN: usize = MSG_ID_LEN + 1;
const RANGE_SUMMARY_LEN: usize = RANGE_KEY_LEN + 4 + 16;
const MAX_V2_RANGE_ENTRIES: usize = 16;
const MAX_V2_IDS: usize = 64;

/// A binary range of the canonical 128-bit message-id space (MSH-15).
///
/// `bits` is the number of leading id bits fixed by `prefix`; trailing bits
/// are always zero so a range has one wire representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RangeKey {
    /// Fixed leading id bits, zero-padded.
    pub prefix: [u8; MSG_ID_LEN],
    /// Number of leading bits that are meaningful.
    pub bits: u8,
}

impl RangeKey {
    /// The range containing every id.
    #[must_use]
    pub fn root() -> Self {
        Self {
            prefix: [0; MSG_ID_LEN],
            bits: 0,
        }
    }

    /// Selects one half at the next id bit.
    #[must_use]
    pub fn child(self, bit: u8) -> Self {
        let mut prefix = self.prefix;
        if self.bits < 128 {
            let byte = usize::from(self.bits / 8);
            let mask = 1 << (7 - (self.bits % 8));
            if bit & 1 == 0 {
                prefix[byte] &= !mask;
            } else {
                prefix[byte] |= mask;
            }
        }
        Self {
            prefix,
            bits: self.bits.saturating_add(1).min(128),
        }
    }

    /// Whether `id` lies in this range.
    #[must_use]
    pub fn contains(self, id: &[u8; MSG_ID_LEN]) -> bool {
        let whole = usize::from(self.bits / 8);
        if id[..whole] != self.prefix[..whole] {
            return false;
        }
        let rest = usize::from(self.bits % 8);
        rest == 0 || id[whole] >> (8 - rest) == self.prefix[whole] >> (8 - rest)
    }

    /// Clears bits outside the range so decoding can reject aliases.
    fn canonicalised(mut self) -> Option<Self> {
        if self.bits > 128 {
            return None;
        }
        let whole = usize::from(self.bits / 8);
        let rest = usize::from(self.bits % 8);
        if whole < MSG_ID_LEN {
            self.prefix[whole + 1..].fill(0);
        }
        if rest != 0 {
            let mask = 0xff << (8 - rest);
            self.prefix[whole] &= mask;
        }
        Some(self)
    }
}

/// Count and hash of the ids one peer holds in a range (MSH-15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeSummary {
    /// The range being summarised.
    pub key: RangeKey,
    /// Number of local ids in the range.
    pub count: u32,
    /// BLAKE3 digest of the sorted ids in the range.
    pub hash: [u8; 16],
}

/// One bounded MSH-15 reconciliation frame.
///
/// These frames only compare set membership. Once both sides know which
/// packets differ, the existing MSH-14 `Item` and `Done` frames carry the
/// transfer, so peers implementing only v1 remain fully compatible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncFrameV2 {
    /// The sender's root summary; both sides send one on link-up.
    Root(RangeSummary),
    /// Summaries requested by the peer.
    Ranges(Vec<RangeSummary>),
    /// Child ranges whose summaries the peer must supply.
    Request(Vec<RangeKey>),
    /// All local ids the sender holds in one leaf range.
    Ids {
        /// The leaf range.
        range: RangeKey,
        /// Sorted full ids, at most the configured leaf size.
        ids: Vec<[u8; MSG_ID_LEN]>,
    },
    /// Reconciliation is complete; both sides may start the item transfer.
    Ready,
}

impl SyncFrameV2 {
    /// Encodes the frame, or `None` if it exceeds the wire length field.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        let (tag, body) = match self {
            Self::Root(summary) => (TAG_V2_ROOT, encode_summary(summary).to_vec()),
            Self::Ranges(summaries) => {
                let mut body = Vec::with_capacity(2 + summaries.len() * RANGE_SUMMARY_LEN);
                body.extend_from_slice(&(summaries.len() as u16).to_be_bytes());
                for summary in summaries {
                    body.extend_from_slice(&encode_summary(summary));
                }
                (TAG_V2_RANGES, body)
            }
            Self::Request(keys) => {
                let mut body = Vec::with_capacity(2 + keys.len() * RANGE_KEY_LEN);
                body.extend_from_slice(&(keys.len() as u16).to_be_bytes());
                for key in keys {
                    body.extend_from_slice(&encode_key(*key));
                }
                (TAG_V2_REQUEST, body)
            }
            Self::Ids { range, ids } => {
                let mut body = Vec::with_capacity(RANGE_KEY_LEN + 2 + ids.len() * MSG_ID_LEN);
                body.extend_from_slice(&encode_key(*range));
                body.extend_from_slice(&(ids.len() as u16).to_be_bytes());
                for id in ids {
                    body.extend_from_slice(id);
                }
                (TAG_V2_IDS, body)
            }
            Self::Ready => (TAG_V2_READY, Vec::new()),
        };
        let len = u16::try_from(body.len()).ok()?;
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
        out.extend_from_slice(&[SYNC_MAGIC, SYNC_V2_VERSION, tag]);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
        Some(out)
    }

    /// Parses a v2 frame. `None` means it is not a sync frame.
    ///
    /// The body is capped by [`MAX_FRAME_BODY_BYTES`] before any slice is
    /// copied, and each tag has its own entry bound (MSH-28).
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, SyncV2Error> {
        if bytes.first() != Some(&SYNC_MAGIC) {
            return Ok(None);
        }
        if bytes.len() < FRAME_HEADER_LEN {
            return Err(SyncV2Error::Truncated);
        }
        if bytes[1] != SYNC_V2_VERSION {
            return Err(SyncV2Error::UnsupportedVersion);
        }
        let len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        if len > MAX_FRAME_BODY_BYTES {
            return Err(SyncV2Error::FrameTooLarge(len));
        }
        let body = bytes
            .get(FRAME_HEADER_LEN..FRAME_HEADER_LEN.saturating_add(len))
            .ok_or(SyncV2Error::Truncated)?;
        if bytes.len() != FRAME_HEADER_LEN.saturating_add(len) {
            return Err(SyncV2Error::TrailingBytes);
        }
        match bytes[2] {
            TAG_V2_ROOT => {
                let summary = take_summary(body, 0)?;
                if body.len() != RANGE_SUMMARY_LEN {
                    return Err(SyncV2Error::BadLength);
                }
                Ok(Some(Self::Root(summary)))
            }
            TAG_V2_RANGES => {
                let count = take_count(body, 0)?;
                if count > MAX_V2_RANGE_ENTRIES || body.len() != 2 + count * RANGE_SUMMARY_LEN {
                    return Err(SyncV2Error::TooManyEntries);
                }
                let summaries = (0..count)
                    .map(|i| take_summary(body, 2 + i * RANGE_SUMMARY_LEN))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Some(Self::Ranges(summaries)))
            }
            TAG_V2_REQUEST => {
                let count = take_count(body, 0)?;
                if count > MAX_V2_RANGE_ENTRIES || body.len() != 2 + count * RANGE_KEY_LEN {
                    return Err(SyncV2Error::TooManyEntries);
                }
                let keys = (0..count)
                    .map(|i| take_key(body, 2 + i * RANGE_KEY_LEN))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Some(Self::Request(keys)))
            }
            TAG_V2_IDS => {
                if body.len() < RANGE_KEY_LEN + 2 {
                    return Err(SyncV2Error::Truncated);
                }
                let range = take_key(body, 0)?;
                let count = take_count(body, RANGE_KEY_LEN)?;
                if count > MAX_V2_IDS || body.len() != RANGE_KEY_LEN + 2 + count * MSG_ID_LEN {
                    return Err(SyncV2Error::TooManyEntries);
                }
                let mut ids = Vec::with_capacity(count);
                for i in 0..count {
                    let start = RANGE_KEY_LEN + 2 + i * MSG_ID_LEN;
                    let id: [u8; MSG_ID_LEN] = body[start..start + MSG_ID_LEN]
                        .try_into()
                        .map_err(|_| SyncV2Error::BadLength)?;
                    if !range.contains(&id) {
                        return Err(SyncV2Error::BadRange);
                    }
                    ids.push(id);
                }
                Ok(Some(Self::Ids { range, ids }))
            }
            TAG_V2_READY => {
                if !body.is_empty() {
                    return Err(SyncV2Error::BadLength);
                }
                Ok(Some(Self::Ready))
            }
            _ => Err(SyncV2Error::BadTag),
        }
    }
}

fn encode_key(key: RangeKey) -> [u8; RANGE_KEY_LEN] {
    let mut out = [0u8; RANGE_KEY_LEN];
    out[..MSG_ID_LEN].copy_from_slice(&key.prefix);
    out[MSG_ID_LEN] = key.bits;
    out
}

fn take_key(body: &[u8], at: usize) -> Result<RangeKey, SyncV2Error> {
    let raw: [u8; RANGE_KEY_LEN] = body
        .get(at..at + RANGE_KEY_LEN)
        .ok_or(SyncV2Error::Truncated)?
        .try_into()
        .map_err(|_| SyncV2Error::BadLength)?;
    let mut prefix = [0u8; MSG_ID_LEN];
    prefix.copy_from_slice(&raw[..MSG_ID_LEN]);
    RangeKey {
        prefix,
        bits: raw[MSG_ID_LEN],
    }
    .canonicalised()
    .ok_or(SyncV2Error::BadRange)
}

fn encode_summary(summary: &RangeSummary) -> [u8; RANGE_SUMMARY_LEN] {
    let mut out = [0u8; RANGE_SUMMARY_LEN];
    out[..RANGE_KEY_LEN].copy_from_slice(&encode_key(summary.key));
    out[RANGE_KEY_LEN..RANGE_KEY_LEN + 4].copy_from_slice(&summary.count.to_be_bytes());
    out[RANGE_KEY_LEN + 4..].copy_from_slice(&summary.hash);
    out
}

fn take_summary(body: &[u8], at: usize) -> Result<RangeSummary, SyncV2Error> {
    let raw: [u8; RANGE_SUMMARY_LEN] = body
        .get(at..at + RANGE_SUMMARY_LEN)
        .ok_or(SyncV2Error::Truncated)?
        .try_into()
        .map_err(|_| SyncV2Error::BadLength)?;
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&raw[RANGE_KEY_LEN + 4..]);
    Ok(RangeSummary {
        key: take_key(body, at)?,
        count: u32::from_be_bytes([
            raw[RANGE_KEY_LEN],
            raw[RANGE_KEY_LEN + 1],
            raw[RANGE_KEY_LEN + 2],
            raw[RANGE_KEY_LEN + 3],
        ]),
        hash,
    })
}

fn take_count(body: &[u8], at: usize) -> Result<usize, SyncV2Error> {
    let bytes: [u8; 2] = body
        .get(at..at + 2)
        .ok_or(SyncV2Error::Truncated)?
        .try_into()
        .map_err(|_| SyncV2Error::BadLength)?;
    Ok(u16::from_be_bytes(bytes) as usize)
}

/// Typed rejection of a claimed MSH-15 frame.
///
/// Public so fuzz targets and hosts can inspect a rejection without
/// stringly-typed errors (MSH-28).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncV2Error {
    /// The magic matched but the fixed header was incomplete.
    Truncated,
    /// The sender speaks another sync version.
    UnsupportedVersion,
    /// Unknown frame tag.
    BadTag,
    /// A count exceeded the decoder's hard bound or disagreed with the body.
    TooManyEntries,
    /// A field had the wrong length for its tag.
    BadLength,
    /// A range key was non-canonical or an id lay outside its range.
    BadRange,
    /// The frame had bytes after its declared length.
    TrailingBytes,
    /// The declared body exceeds [`MAX_FRAME_BODY_BYTES`]. Holds the length.
    FrameTooLarge(usize),
}

impl std::fmt::Display for SyncV2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated sync v2 frame"),
            Self::UnsupportedVersion => write!(f, "unsupported sync v2 version"),
            Self::BadTag => write!(f, "unknown sync v2 frame tag"),
            Self::TooManyEntries => write!(f, "sync v2 frame exceeds its entry bound"),
            Self::BadLength => write!(f, "sync v2 frame field has the wrong length"),
            Self::BadRange => write!(f, "sync v2 range key or id is invalid"),
            Self::TrailingBytes => write!(f, "trailing bytes after the sync v2 frame"),
            Self::FrameTooLarge(len) => {
                write!(f, "sync v2 frame body {len} exceeds {MAX_FRAME_BODY_BYTES}")
            }
        }
    }
}

impl std::error::Error for SyncV2Error {}

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
    /// Largest range exchanged as full ids in MSH-15 reconciliation.
    pub range_leaf_ids: usize,
    /// Never split a range beyond this many id bits.
    pub range_max_depth: u8,
    /// Upper bound on range keys or summaries in one MSH-15 frame.
    pub range_frame_entries: usize,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_bytes_per_contact: 256 * 1024,
            max_frame_bytes: 15 * 1024,
            timeout_ms: 20_000,
            range_leaf_ids: 32,
            range_max_depth: 128,
            range_frame_entries: 8,
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
    /// Retained spray copies for Direct items; one for other classes.
    pub copies_left: u8,
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
    spray: bool,
    deadline_ms: u64,
    done_sent: bool,
    released: bool,
}

impl SyncSession {
    fn new(now: u64, timeout_ms: u64, spray: bool) -> Self {
        Self {
            target: BTreeSet::new(),
            incoming: BTreeSet::new(),
            received: BTreeSet::new(),
            sent: BTreeSet::new(),
            bytes_sent: 0,
            spray,
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

/// One MSH-15 reconciliation, replaced by an ordinary MSH-14 item session
/// once both sides have exchanged the ids in every differing leaf range.
#[derive(Debug)]
struct V2Session {
    deadline_ms: u64,
    /// Snapshot of the local store taken when the contact opened.
    ids: Vec<[u8; MSG_ID_LEN]>,
    /// Whether the contact may carry MSH-16 copy tickets.
    spray: bool,
    /// Ranges still waiting for the peer's summary.
    outstanding: BTreeSet<RangeKey>,
    /// Summaries already received, so duplicates and loops are ignored.
    received_summaries: BTreeSet<RangeKey>,
    /// Differing ranges narrow enough to exchange as full ids.
    leafs: BTreeSet<RangeKey>,
    /// Leaf ranges for which our ids have been sent.
    leaf_sent: BTreeSet<RangeKey>,
    /// Peer ids keyed by leaf range.
    leaf_ids: BTreeMap<RangeKey, Vec<[u8; MSG_ID_LEN]>>,
    /// Prefixes we owe the peer after reconciliation.
    target: BTreeSet<[u8; SHORT_ID_BYTES]>,
    /// Prefixes we expect from the peer after reconciliation.
    incoming: BTreeSet<[u8; SHORT_ID_BYTES]>,
    ready_sent: bool,
    peer_ready: bool,
    released: bool,
    bytes_sent: usize,
    bytes_received: usize,
}

impl V2Session {
    fn new(now: u64, timeout_ms: u64, ids: Vec<[u8; MSG_ID_LEN]>, spray: bool) -> Self {
        Self {
            deadline_ms: now.saturating_add(timeout_ms),
            ids,
            spray,
            outstanding: BTreeSet::new(),
            received_summaries: BTreeSet::new(),
            leafs: BTreeSet::new(),
            leaf_sent: BTreeSet::new(),
            leaf_ids: BTreeMap::new(),
            target: BTreeSet::new(),
            incoming: BTreeSet::new(),
            ready_sent: false,
            peer_ready: false,
            released: false,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    fn reconciliation_done(&self) -> bool {
        self.outstanding.is_empty()
            && self
                .leafs
                .iter()
                .all(|key| self.leaf_sent.contains(key) && self.leaf_ids.contains_key(key))
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
    /// Queue one MSH-15 reconciliation frame on the Bulk channel.
    SendV2 {
        /// Destination link.
        link: LinkId,
        /// Bounded frame.
        frame: SyncFrameV2,
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
        /// Link that supplied the item, excluded from further spray handoff.
        link: LinkId,
        /// Full content address parsed from the wire packet.
        id: MessageId,
        /// Complete encoded packet.
        wire: Vec<u8>,
        /// Spray copies from a negotiated frame, or one otherwise.
        copies_left: u8,
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
    /// Cumulative wire bytes (MSH-30). Per-contact budgets live on sessions;
    /// these counters survive contact teardown and cannot be derived from it.
    bytes_sent_total: Counter,
    bytes_received_total: Counter,
    sessions: BTreeMap<LinkId, SyncSession>,
    v2_sessions: BTreeMap<LinkId, V2Session>,
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
            range_leaf_ids: config.range_leaf_ids.clamp(1, 64),
            range_max_depth: config.range_max_depth.clamp(1, 128),
            range_frame_entries: config.range_frame_entries.clamp(1, 16),
            ..config
        };
        Self {
            config,
            local: StoreSummary::from_ids(&[]),
            bytes_sent_total: Counter::new(),
            bytes_received_total: Counter::new(),
            sessions: BTreeMap::new(),
            v2_sessions: BTreeMap::new(),
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

    /// Number of live store ids in the last host-supplied summary (MSH-30).
    pub(crate) fn local_len(&self) -> usize {
        self.local.len()
    }

    /// Adds actually encoded bytes of an emitted sync frame (MSH-30).
    pub(crate) fn note_sent_bytes(&mut self, bytes: usize) {
        self.bytes_sent_total
            .add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    /// Adds bytes of a valid sync frame accepted on a verified link (MSH-30).
    pub(crate) fn note_received_bytes(&mut self, bytes: usize) {
        self.bytes_received_total
            .add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    /// Saturating cumulative sync bytes sent and received (MSH-30).
    pub(crate) fn byte_totals(&self) -> (u64, u64) {
        (self.bytes_sent_total.get(), self.bytes_received_total.get())
    }

    /// Resolves a short id back to the full id in the current summary.
    pub(crate) fn local_id_for_prefix(&self, prefix: [u8; SHORT_ID_BYTES]) -> Option<MessageId> {
        self.local
            .full_ids()
            .iter()
            .copied()
            .find(|id| id[..SHORT_ID_BYTES] == prefix)
            .map(MessageId::from_bytes)
    }

    /// Opens a contact when the peer's hello advertises a different digest.
    pub(crate) fn start(
        &mut self,
        now: u64,
        link: LinkId,
        remote_digest: [u8; BEACON_DIGEST_LEN],
        spray: bool,
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
            .insert(link, SyncSession::new(now, self.config.timeout_ms, spray));
        vec![SyncAction::Send {
            link,
            frame: SyncFrame::Digest(self.local_digest()),
        }]
    }

    /// Opens an MSH-15 contact when both peers advertise the v2 capability.
    pub(crate) fn start_v2(
        &mut self,
        now: u64,
        link: LinkId,
        remote_digest: [u8; BEACON_DIGEST_LEN],
        spray: bool,
    ) -> Vec<SyncAction> {
        if !self.config.enabled
            || self.sessions.contains_key(&link)
            || self.v2_sessions.contains_key(&link)
        {
            return Vec::new();
        }
        if remote_digest == self.local_digest() {
            return Vec::new();
        }
        let root = RangeKey::root();
        let frame = SyncFrameV2::Root(range_summary(self.local.full_ids(), root));
        let Some(wire) = frame.encode() else {
            return Vec::new();
        };
        if wire.len() > self.config.max_frame_bytes {
            return Vec::new();
        }
        let mut session = V2Session::new(
            now,
            self.config.timeout_ms,
            self.local.full_ids().to_vec(),
            spray,
        );
        session.outstanding.insert(root);
        session.bytes_sent = wire.len();
        self.v2_sessions.insert(link, session);
        vec![SyncAction::SendV2 { link, frame }]
    }

    /// Applies one MSH-15 frame from a verified neighbour.
    pub(crate) fn on_v2_frame(
        &mut self,
        now: u64,
        link: LinkId,
        frame: SyncFrameV2,
        wire_len: usize,
    ) -> Vec<SyncAction> {
        if !self.config.enabled {
            return Vec::new();
        }
        let Some(mut session) = self.v2_sessions.remove(&link) else {
            return Vec::new();
        };
        if now >= session.deadline_ms {
            return vec![SyncAction::Release { link }];
        }
        if session.bytes_received.saturating_add(wire_len) > self.config.max_bytes_per_contact {
            return vec![SyncAction::Release { link }];
        }
        session.bytes_received = session.bytes_received.saturating_add(wire_len);

        let mut actions = Vec::new();
        match frame {
            SyncFrameV2::Root(summary) => {
                self.apply_v2_summary(link, &mut session, summary, &mut actions);
            }
            SyncFrameV2::Ranges(summaries) => {
                for summary in summaries.into_iter().take(self.config.range_frame_entries) {
                    self.apply_v2_summary(link, &mut session, summary, &mut actions);
                }
            }
            SyncFrameV2::Request(keys) => {
                let summaries: Vec<RangeSummary> = keys
                    .into_iter()
                    .take(self.config.range_frame_entries)
                    .map(|key| range_summary(&session.ids, key))
                    .collect();
                if !summaries.is_empty() {
                    actions.extend(self.v2_send(
                        link,
                        &mut session,
                        SyncFrameV2::Ranges(summaries),
                    ));
                }
            }
            SyncFrameV2::Ids { range, ids } => self.apply_v2_ids(&mut session, range, ids),
            SyncFrameV2::Ready => session.peer_ready = true,
        }

        if session.reconciliation_done() && !session.ready_sent {
            session.ready_sent = true;
            actions.extend(self.v2_send(link, &mut session, SyncFrameV2::Ready));
        }
        if session.ready_sent && session.peer_ready {
            let mut next = SyncSession::new(now, self.config.timeout_ms, session.spray);
            next.target = session.target.clone();
            next.incoming = session.incoming.clone();
            self.sessions.insert(link, next);
            let prefixes: Vec<[u8; SHORT_ID_BYTES]> = session.target.iter().copied().collect();
            if prefixes.is_empty() {
                if session.incoming.is_empty() {
                    actions.extend(self.send_done(link));
                }
            } else {
                actions.push(SyncAction::Need { link, prefixes });
            }
        } else {
            self.v2_sessions.insert(link, session);
        }
        actions
    }

    fn v2_send(
        &self,
        link: LinkId,
        session: &mut V2Session,
        frame: SyncFrameV2,
    ) -> Vec<SyncAction> {
        let Some(wire) = frame.encode() else {
            return vec![SyncAction::Release { link }];
        };
        if wire.len() > self.config.max_frame_bytes
            || session.bytes_sent.saturating_add(wire.len()) > self.config.max_bytes_per_contact
        {
            session.released = true;
            session.deadline_ms = u64::MAX;
            return vec![SyncAction::Release { link }];
        }
        session.bytes_sent = session.bytes_sent.saturating_add(wire.len());
        vec![SyncAction::SendV2 { link, frame }]
    }

    fn apply_v2_summary(
        &self,
        link: LinkId,
        session: &mut V2Session,
        summary: RangeSummary,
        actions: &mut Vec<SyncAction>,
    ) {
        let key = summary.key;
        if session.received_summaries.contains(&key) || !session.outstanding.contains(&key) {
            return;
        }
        session.received_summaries.insert(key);
        let local = range_summary(&session.ids, key);
        if local == summary {
            session.outstanding.remove(&key);
            return;
        }
        session.outstanding.remove(&key);
        let leaf = local.count as usize <= self.config.range_leaf_ids
            || summary.count as usize <= self.config.range_leaf_ids
            || key.bits >= self.config.range_max_depth;
        if leaf {
            let ids: Vec<[u8; MSG_ID_LEN]> = session
                .ids
                .iter()
                .copied()
                .filter(|id| key.contains(id))
                .collect();
            let sent = self.v2_send(link, session, SyncFrameV2::Ids { range: key, ids });
            if sent
                .iter()
                .any(|action| matches!(action, SyncAction::SendV2 { .. }))
            {
                session.leafs.insert(key);
                session.leaf_sent.insert(key);
            }
            actions.extend(sent);
        } else {
            let children = [key.child(0), key.child(1)];
            for child in children {
                session.outstanding.insert(child);
            }
            actions.extend(self.v2_send(link, session, SyncFrameV2::Request(children.to_vec())));
        }
    }

    fn apply_v2_ids(
        &self,
        session: &mut V2Session,
        range: RangeKey,
        mut ids: Vec<[u8; MSG_ID_LEN]>,
    ) {
        // The peer may send its ids before this side has processed the same
        // child summary, so an outstanding range is just as legitimate as a
        // leaf we already chose.
        if !(session.leafs.contains(&range) || session.outstanding.contains(&range))
            || session.leaf_ids.contains_key(&range)
            || ids.len() > self.config.range_leaf_ids
        {
            return;
        }
        ids.sort_unstable();
        ids.dedup();
        if ids.iter().any(|id| !range.contains(id)) {
            return;
        }
        for id in &ids {
            if session.ids.binary_search(id).is_err() {
                session.incoming.insert(short_of(id));
            }
        }
        for local in session.ids.iter().copied().filter(|id| range.contains(id)) {
            if ids.binary_search(&local).is_err() {
                session.target.insert(short_of(&local));
            }
        }
        session.leafs.insert(range);
        session.leaf_ids.insert(range, ids);
    }

    /// Applies one frame from a verified neighbour.
    pub(crate) fn on_frame(&mut self, now: u64, link: LinkId, frame: SyncFrame) -> Vec<SyncAction> {
        if !self.config.enabled {
            return Vec::new();
        }
        let incoming_copies = match &frame {
            SyncFrame::SprayItem { copies, .. } => *copies,
            _ => 1,
        };
        match frame {
            SyncFrame::Digest(digest) => {
                if !self.sessions.contains_key(&link) {
                    self.sessions
                        .insert(link, SyncSession::new(now, self.config.timeout_ms, false));
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
                        .or_insert_with(|| SyncSession::new(now, self.config.timeout_ms, false));
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
            SyncFrame::Item(wire) | SyncFrame::SprayItem { wire, .. } => {
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
                let mut actions = vec![SyncAction::Item {
                    link,
                    id,
                    wire,
                    copies_left: incoming_copies,
                }];
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
            // Host-supplied, but one input must not be able to demand
            // unbounded work even if a host is confused or compromised.
            for offer in offers.iter().take(MAX_SUMMARY_ENTRIES) {
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
                let frame = if session.spray && offer.copies_left > 1 {
                    SyncFrame::SprayItem {
                        copies: offer.copies_left,
                        wire: offer.wire.to_vec(),
                    }
                } else {
                    SyncFrame::Item(offer.wire.to_vec())
                };
                actions.push(SyncAction::Send { link, frame });
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
            .chain(
                self.v2_sessions
                    .iter()
                    .filter(|(_, session)| now >= session.deadline_ms && !session.released)
                    .map(|(link, _)| *link),
            )
            .collect();
        due.into_iter()
            .map(|link| {
                self.sessions.remove(&link);
                self.v2_sessions.remove(&link);
                SyncAction::Release { link }
            })
            .collect()
    }

    /// Forgets a closed link; the host store keeps whatever arrived.
    pub(crate) fn link_down(&mut self, link: LinkId) {
        self.sessions.remove(&link);
        self.v2_sessions.remove(&link);
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

/// BLAKE3 over a domain separator, canonical range key, count and sorted ids.
fn range_summary(ids: &[[u8; MSG_ID_LEN]], key: RangeKey) -> RangeSummary {
    let local: Vec<[u8; MSG_ID_LEN]> = ids.iter().copied().filter(|id| key.contains(id)).collect();
    let mut hasher = Hasher::new();
    hasher.update(b"aoheyra/mesh/range-v1");
    hasher.update(&encode_key(key));
    hasher.update(&(local.len() as u64).to_le_bytes());
    for id in &local {
        hasher.update(id);
    }
    let digest = hasher.finalize();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&digest.as_bytes()[..16]);
    RangeSummary {
        key,
        count: local.len() as u32,
        hash,
    }
}

fn short_of(id: &[u8; MSG_ID_LEN]) -> [u8; SHORT_ID_BYTES] {
    let mut short = [0u8; SHORT_ID_BYTES];
    short.copy_from_slice(&id[..SHORT_ID_BYTES]);
    short
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
                copies_left: 1,
            },
            SyncOffer {
                prefix: {
                    let mut prefix = [0; SHORT_ID_BYTES];
                    prefix.copy_from_slice(&second_id.as_bytes()[..SHORT_ID_BYTES]);
                    prefix
                },
                wire: &second,
                copies_left: 1,
            },
        ];
        let actions = tracker.on_offers(link, &offers);
        let sent = actions
            .iter()
            .filter(|action| matches!(action, SyncAction::Send { .. }))
            .count();
        assert_eq!(sent, 1, "the byte bound stops the second item");
    }

    #[test]
    fn range_children_survive_encoding_as_distinct_ranges() {
        let root = RangeKey::root();
        let zero = root.child(0);
        let one = root.child(1);
        assert_ne!(zero, one);
        assert_eq!(zero.prefix[0], 0);
        assert_eq!(one.prefix[0], 0x80);
        for key in [zero, one] {
            let wire = SyncFrameV2::Request(vec![key]).encode().expect("encodes");
            let Some(SyncFrameV2::Request(decoded)) = SyncFrameV2::decode(&wire).expect("decodes")
            else {
                panic!("a request frame must decode as a request");
            };
            assert_eq!(decoded, vec![key]);
        }
    }

    #[test]
    fn sync_v2_frames_round_trip_and_reject_bad_wires() {
        let key = RangeKey::root().child(1).child(0);
        let mut id = [0u8; MSG_ID_LEN];
        id[0] = 0x80;
        let summary = RangeSummary {
            key,
            count: 1,
            hash: [7; 16],
        };
        let frames = [
            SyncFrameV2::Root(summary),
            SyncFrameV2::Ranges(vec![summary]),
            SyncFrameV2::Request(vec![key]),
            SyncFrameV2::Ids {
                range: key,
                ids: vec![id],
            },
            SyncFrameV2::Ready,
        ];
        for frame in frames {
            let wire = frame.encode().expect("encodes");
            assert_eq!(SyncFrameV2::decode(&wire).expect("decodes"), Some(frame));
        }

        assert_eq!(
            SyncFrameV2::decode(&[SYNC_MAGIC, SYNC_VERSION, 1, 0, 0]),
            Err(SyncV2Error::UnsupportedVersion)
        );
        assert_eq!(
            SyncFrameV2::decode(&[SYNC_MAGIC, SYNC_V2_VERSION, 99, 0, 0]),
            Err(SyncV2Error::BadTag)
        );

        let mut trailing = SyncFrameV2::Ready.encode().expect("encodes");
        trailing.push(0);
        assert_eq!(
            SyncFrameV2::decode(&trailing),
            Err(SyncV2Error::TrailingBytes)
        );

        let out_of_range = SyncFrameV2::Ids {
            range: RangeKey::root().child(1),
            ids: vec![[0; MSG_ID_LEN]],
        }
        .encode()
        .expect("encodes");
        assert_eq!(
            SyncFrameV2::decode(&out_of_range),
            Err(SyncV2Error::BadRange)
        );

        let too_many = SyncFrameV2::Ranges(vec![summary; MAX_V2_RANGE_ENTRIES + 1])
            .encode()
            .expect("encodes");
        assert_eq!(
            SyncFrameV2::decode(&too_many),
            Err(SyncV2Error::TooManyEntries)
        );
    }

    #[test]
    fn oversized_frame_bodies_are_rejected_before_copying() {
        let mut item = SyncFrame::Item(vec![0; MAX_FRAME_BODY_BYTES + 1])
            .encode()
            .expect("the u16 length field still fits");
        assert_eq!(
            SyncFrame::decode(&item),
            Err(SyncError::FrameTooLarge(MAX_FRAME_BODY_BYTES + 1))
        );
        // The same cap applies to v2 frames.
        let mut v2 = vec![SYNC_MAGIC, SYNC_V2_VERSION, TAG_V2_READY];
        v2.extend_from_slice(&((MAX_FRAME_BODY_BYTES + 1) as u16).to_be_bytes());
        assert_eq!(
            SyncFrameV2::decode(&v2),
            Err(SyncV2Error::FrameTooLarge(MAX_FRAME_BODY_BYTES + 1))
        );

        // A summary keeps its count-based bound and error even when the
        // declared body is longer than the general cap. The count lives
        // after the four-byte digest inside the body.
        item[2] = TAG_SUMMARY;
        item[9] = 0x05;
        item[10] = 0x01;
        assert_eq!(SyncFrame::decode(&item), Err(SyncError::TooManyEntries));
    }

    #[test]
    fn summary_frames_reject_bytes_inside_the_declared_body() {
        let frame = SyncFrame::Summary {
            digest: [0; BEACON_DIGEST_LEN],
            short_ids: vec![[1; SHORT_ID_BYTES]],
        }
        .encode()
        .expect("encodes");
        let declared = u16::try_from(frame.len() - FRAME_HEADER_LEN).expect("fits");

        // Bytes after the declared frame are rejected as trailing bytes
        // before the tag is parsed.
        let mut with_extra = frame;
        with_extra.extend_from_slice(&[7; 16]);
        assert_eq!(
            SyncFrame::decode(&with_extra),
            Err(SyncError::TrailingBytes)
        );
        // Include them in the declared length so they sit inside the body:
        // the summary's exact-length check must reject them here.
        let inflated = declared + 16;
        with_extra[3..5].copy_from_slice(&inflated.to_be_bytes());
        assert_eq!(SyncFrame::decode(&with_extra), Err(SyncError::BadLength));
    }

    #[test]
    fn a_summary_never_holds_more_ids_than_the_store_bound() {
        // The ids must be distinct: `StoreSummary` deduplicates, so reusing
        // one of a handful of byte patterns would end the test with fewer
        // ids than the bound before the cap is ever reached.
        let distinct_id = |i: usize| {
            let mut bytes = [0u8; MSG_ID_LEN];
            let index = u16::try_from(i).expect("test range fits");
            bytes[..2].copy_from_slice(&index.to_be_bytes());
            MessageId::from_bytes(bytes)
        };
        let ids: Vec<MessageId> = (0..MAX_SUMMARY_ENTRIES + 256).map(distinct_id).collect();
        let summary = StoreSummary::from_ids(&ids);
        assert_eq!(summary.len(), MAX_SUMMARY_ENTRIES);
        assert_eq!(
            summary.digest(),
            StoreSummary::from_ids(&ids[..MAX_SUMMARY_ENTRIES]).digest()
        );
    }

    #[test]
    fn byte_totals_follow_encoded_frames_and_saturate() {
        let mut tracker = SyncTracker::new(SyncConfig::default());
        assert_eq!(tracker.byte_totals(), (0, 0));
        tracker.note_sent_bytes(12);
        tracker.note_received_bytes(30);
        assert_eq!(tracker.byte_totals(), (12, 30));
        tracker.bytes_sent_total.set(u64::MAX - 1);
        tracker.bytes_received_total.set(u64::MAX);
        tracker.note_sent_bytes(usize::try_from(u64::MAX).unwrap_or(usize::MAX));
        tracker.note_received_bytes(1);
        assert_eq!(tracker.byte_totals(), (u64::MAX, u64::MAX));
    }

    #[test]
    fn local_len_reports_the_host_supplied_summary() {
        let mut tracker = SyncTracker::new(SyncConfig::default());
        assert_eq!(tracker.local_len(), 0);
        tracker.set_local(&[id(1), id(2), id(2), id(3)]);
        assert_eq!(tracker.local_len(), 3);
    }
}
