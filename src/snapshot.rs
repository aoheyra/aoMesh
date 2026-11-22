//! Restart snapshots for engine-owned volatile state (MSH-29).
//!
//! A relaunched engine would otherwise start with an empty seen-cache,
//! immunity list and spray tickets: already-forwarded packets would be
//! relayed again and purged copies re-accepted. [`Snapshot`] serialises
//! exactly those three bounded state sets into bytes. The host stores the
//! bytes wherever it likes and hands them back to [`Snapshot::restore`];
//! the engine never opens the store, reads a clock or draws randomness,
//! and no message bytes are copied into the snapshot.
//!
//! # Local format (not a radio wire format)
//!
//! The snapshot is host-local persistent state, not a peer protocol, so it
//! is not negotiated through `MeshHello.caps`. Its version is checked on
//! every restore and must be bumped if the layout changes. All integers are
//! little-endian and every string of items is preceded by its count, so a
//! parser can reject oversized counts before allocating:
//!
//! ```text
//! 4   magic = "AMSH"
//! 1   version = SNAPSHOT_VERSION
//! 4   seen entry count
//! 4   seen order count
//! 4   immunity entry count
//! 4   spray entry count
//! repeated seen entry count times:
//!     16  MessageId
//!     8   expires_at_ms
//! repeated seen order count times:
//!     16  MessageId (recording order, oldest first; stale slots are kept)
//! repeated immunity entry count times:
//!     16  MessageId
//!     8   expires_at_ms
//!     4   receipt wire length
//!     N   receipt envelope bytes
//!     4   sent-to link count
//!     8 * count  raw LinkId values
//! repeated spray entry count times:
//!     16  MessageId
//!     1   copies_left
//!     16  destination node id
//!     8   expires_at_ms
//!     4   handed-to link count
//!     8 * count  raw LinkId values
//! ```
//!
//! Entries are written in `BTreeMap` key order, so the same state always
//! produces the same bytes. Restore decodes everything into temporary
//! structures before touching the engine: a malformed or oversized
//! snapshot leaves the live engine exactly as it was.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ao_network::LinkId;

use crate::MessageId;
use crate::receipt::{ImmunityState, MAX_RECEIPT_WIRE, decode_frame};
use crate::seen::SeenState;
use crate::spray::SprayState;

/// Magic prefix of an engine snapshot.
pub const SNAPSHOT_MAGIC: [u8; 4] = *b"AMSH";
/// Version of the layout documented in the module. Bump on any layout change.
pub const SNAPSHOT_VERSION: u8 = 1;
/// Hard cap on a snapshot a host may store or hand back to the engine.
///
/// The default configuration's worst case is about 1.85 MiB (4096 seen
/// recordings plus their order, 512 immunity entries with signed receipt
/// envelopes and 32-link sent sets, and 4096 spray tickets with 32-link
/// hand-off sets). 4 MiB leaves room for larger per-host neighbour tables;
/// [`Snapshot::snapshot`] still returns [`SnapshotError::TooLarge`] rather
/// than growing past this bound.
pub const MAX_SNAPSHOT_LEN: usize = 4 * 1024 * 1024;

/// Which bounded section of a snapshot failed its count check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotSection {
    /// Seen-cache recording map.
    Seen,
    /// Seen-cache recording order.
    SeenOrder,
    /// Receipt immunity list.
    Immunity,
    /// Spray copy tickets.
    Copies,
}

/// A typed snapshot failure. No variant can be produced by a live packet:
/// snapshots are host-supplied bytes and are treated as untrusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// Timed state belongs to a different local account.
    OwnerMismatch,
    /// Timed restore must precede all engine inputs and any earlier restore.
    AlreadyStarted,
    /// A remaining lifetime exceeds the configured policy ceiling.
    InvalidLifetime,
    /// The new local deadline cannot be represented.
    ClockOverflow,
    /// The magic prefix is not [`SNAPSHOT_MAGIC`].
    BadMagic,
    /// The layout version is not [`SNAPSHOT_VERSION`].
    UnsupportedVersion(u8),
    /// The snapshot ended before the field at `need` bytes.
    Truncated {
        /// Offset the parser tried to read up to.
        need: usize,
        /// Bytes actually present.
        have: usize,
    },
    /// The byte string is longer than [`MAX_SNAPSHOT_LEN`].
    TooLarge {
        /// Length supplied or produced.
        len: usize,
        /// Hard cap.
        max: usize,
    },
    /// An item count cannot be represented in the four-byte count field.
    CountTooLarge(usize),
    /// A count exceeds the receiving engine's configured bound.
    CountExceedsLimit {
        /// Section whose count is too large.
        section: SnapshotSection,
        /// Count in the snapshot.
        count: usize,
        /// Configured bound.
        limit: usize,
    },
    /// A receipt envelope in the snapshot is malformed or inconsistent with
    /// the id it is supposed to make immune.
    InvalidReceipt(crate::receipt::ReceiptError),
    /// An id appears twice in a section that keys by id.
    DuplicateId,
    /// A link appears twice in one entry's sent/handed-to set.
    DuplicateLink,
    /// Bytes remain after the last section.
    TrailingBytes(usize),
}

impl core::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OwnerMismatch => write!(f, "snapshot belongs to another identity"),
            Self::AlreadyStarted => write!(f, "timed restore requires a fresh engine"),
            Self::InvalidLifetime => write!(f, "invalid remaining snapshot lifetime"),
            Self::ClockOverflow => write!(f, "snapshot deadline overflows local time"),
            Self::BadMagic => write!(f, "not an aoMesh engine snapshot"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported snapshot version {v}"),
            Self::Truncated { need, have } => {
                write!(f, "snapshot needs {need} bytes, has {have}")
            }
            Self::TooLarge { len, max } => write!(f, "snapshot of {len} bytes exceeds {max}"),
            Self::CountTooLarge(n) => write!(f, "snapshot count {n} exceeds u32"),
            Self::CountExceedsLimit {
                section,
                count,
                limit,
            } => write!(f, "{section:?} count {count} exceeds bound {limit}"),
            Self::InvalidReceipt(e) => write!(f, "invalid receipt in snapshot: {e}"),
            Self::DuplicateId => write!(f, "duplicate message id in snapshot"),
            Self::DuplicateLink => write!(f, "duplicate link id in snapshot"),
            Self::TrailingBytes(n) => write!(f, "{n} trailing snapshot bytes"),
        }
    }
}

impl std::error::Error for SnapshotError {}

impl From<crate::receipt::ReceiptError> for SnapshotError {
    fn from(error: crate::receipt::ReceiptError) -> Self {
        Self::InvalidReceipt(error)
    }
}

/// Serialisation of the volatile state that survives an engine restart.
///
/// For a process/OS restart with a new local clock epoch, use [`TimedSnapshot`].
/// This legacy format preserves absolute deadlines and session LinkIds; it is
/// suitable only when that exact clock epoch and link namespace are preserved.
/// The host calls [`Snapshot::snapshot`] before dropping an engine and
/// [`Snapshot::restore`] on a freshly constructed engine with the same
/// configuration and RNG seed. The engine owns no storage and no scheduler;
/// storing, encrypting and versioning the bytes over time is the host's job
/// (MSH-29). Link-specific capability bits are intentionally not included:
/// the host re-announces live links with `MeshInput::LinkUp` after a restart.
pub trait Snapshot {
    /// Version written by [`Self::snapshot`] and required by
    /// [`Self::restore`].
    const VERSION: u8 = SNAPSHOT_VERSION;
    /// Maximum encoded length; hosts may size their storage from this.
    const MAX_LEN: usize = MAX_SNAPSHOT_LEN;

    /// Encodes this engine's bounded volatile state.
    ///
    /// Returns [`SnapshotError::TooLarge`] if a host configuration grew the
    /// state past [`Self::MAX_LEN`]; no partial bytes are returned.
    fn snapshot(&self) -> Result<Vec<u8>, SnapshotError>;

    /// Restores volatile state on this engine, atomically.
    ///
    /// The engine must have been constructed with the same configuration and
    /// RNG seed it had before the restart. Malformed, oversized or
    /// version-mismatched bytes are rejected without changing any live state.
    fn restore(&mut self, bytes: &[u8]) -> Result<(), SnapshotError>;
}

#[derive(Default)]
struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), SnapshotError> {
        let len = self.out.len().saturating_add(bytes.len());
        if len > MAX_SNAPSHOT_LEN {
            return Err(SnapshotError::TooLarge {
                len,
                max: MAX_SNAPSHOT_LEN,
            });
        }
        self.out.extend_from_slice(bytes);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), SnapshotError> {
        self.bytes(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), SnapshotError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), SnapshotError> {
        self.bytes(&value.to_le_bytes())
    }

    fn id(&mut self, id: MessageId) -> Result<(), SnapshotError> {
        self.bytes(id.as_bytes())
    }

    fn link(&mut self, link: LinkId) -> Result<(), SnapshotError> {
        self.u64(link.raw())
    }

    fn count(&mut self, count: usize) -> Result<(), SnapshotError> {
        let value = u32::try_from(count).map_err(|_| SnapshotError::CountTooLarge(count))?;
        self.u32(value)
    }

    fn links(&mut self, links: &BTreeSet<LinkId>) -> Result<(), SnapshotError> {
        self.count(links.len())?;
        for link in links {
            self.link(*link)?;
        }
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SnapshotError> {
        let need = self.pos.checked_add(n).ok_or(SnapshotError::Truncated {
            need: usize::MAX,
            have: self.bytes.len(),
        })?;
        if need > self.bytes.len() {
            return Err(SnapshotError::Truncated {
                need,
                have: self.bytes.len(),
            });
        }
        let out = &self.bytes[self.pos..need];
        self.pos = need;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, SnapshotError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, SnapshotError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| SnapshotError::Truncated {
                need: self.pos.saturating_add(4),
                have: self.bytes.len(),
            })?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, SnapshotError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| SnapshotError::Truncated {
                need: self.pos.saturating_add(8),
                have: self.bytes.len(),
            })?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn id(&mut self) -> Result<MessageId, SnapshotError> {
        let bytes: [u8; 16] = self
            .take(16)?
            .try_into()
            .map_err(|_| SnapshotError::Truncated {
                need: self.pos.saturating_add(16),
                have: self.bytes.len(),
            })?;
        Ok(MessageId::from_bytes(bytes))
    }

    fn link(&mut self) -> Result<LinkId, SnapshotError> {
        Ok(LinkId::new(self.u64()?))
    }

    fn count(&mut self, section: SnapshotSection, limit: usize) -> Result<usize, SnapshotError> {
        let count =
            usize::try_from(self.u32()?).map_err(|_| SnapshotError::CountTooLarge(limit))?;
        if count > limit {
            return Err(SnapshotError::CountExceedsLimit {
                section,
                count,
                limit,
            });
        }
        Ok(count)
    }

    fn links(
        &mut self,
        section: SnapshotSection,
        limit: usize,
    ) -> Result<BTreeSet<LinkId>, SnapshotError> {
        let count = self.count(section, limit)?;
        let mut links = BTreeSet::new();
        for _ in 0..count {
            if !links.insert(self.link()?) {
                return Err(SnapshotError::DuplicateLink);
            }
        }
        Ok(links)
    }

    fn finish(self) -> Result<(), SnapshotError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(SnapshotError::TrailingBytes(self.bytes.len() - self.pos))
        }
    }
}

pub(crate) fn encode_snapshot(
    seen: SeenState,
    immunity: ImmunityState,
    spray: SprayState,
) -> Result<Vec<u8>, SnapshotError> {
    let mut w = Writer::default();
    w.bytes(&SNAPSHOT_MAGIC)?;
    w.u8(SNAPSHOT_VERSION)?;
    w.count(seen.entries.len())?;
    w.count(seen.order.len())?;
    w.count(immunity.entries.len())?;
    w.count(spray.entries.len())?;

    for (id, expires_at) in seen.entries {
        w.id(id)?;
        w.u64(expires_at)?;
    }
    for id in seen.order {
        w.id(id)?;
    }
    for (id, entry) in immunity.entries {
        w.id(id)?;
        w.u64(entry.expires_at_ms)?;
        let len = u32::try_from(entry.wire.len())
            .map_err(|_| SnapshotError::CountTooLarge(entry.wire.len()))?;
        w.u32(len)?;
        w.bytes(&entry.wire)?;
        w.links(&entry.sent_to)?;
    }
    for (id, entry) in spray.entries {
        w.id(id)?;
        w.u8(entry.copies_left)?;
        w.bytes(&entry.destination)?;
        w.u64(entry.expires_at_ms)?;
        w.links(&entry.handed_to)?;
    }
    Ok(w.out)
}

/// Decodes all sections before the caller mutates any tracker.
pub(crate) fn decode_snapshot(
    bytes: &[u8],
    seen_limit: usize,
    immunity_limit: usize,
    spray_limit: usize,
    link_limit: usize,
) -> Result<(SeenState, ImmunityState, SprayState), SnapshotError> {
    if bytes.len() > MAX_SNAPSHOT_LEN {
        return Err(SnapshotError::TooLarge {
            len: bytes.len(),
            max: MAX_SNAPSHOT_LEN,
        });
    }
    let mut r = Reader::new(bytes);
    if r.take(4)? != SNAPSHOT_MAGIC {
        return Err(SnapshotError::BadMagic);
    }
    let version = r.u8()?;
    if version != SNAPSHOT_VERSION {
        return Err(SnapshotError::UnsupportedVersion(version));
    }
    let seen_entries = r.count(SnapshotSection::Seen, seen_limit)?;
    let seen_order = r.count(SnapshotSection::SeenOrder, seen_limit)?;
    let immunity_entries = r.count(SnapshotSection::Immunity, immunity_limit)?;
    let spray_entries = r.count(SnapshotSection::Copies, spray_limit)?;

    let mut seen = SeenState {
        entries: BTreeMap::new(),
        order: VecDeque::new(),
    };
    for _ in 0..seen_entries {
        let id = r.id()?;
        let expires_at = r.u64()?;
        if seen.entries.insert(id, expires_at).is_some() {
            return Err(SnapshotError::DuplicateId);
        }
    }
    for _ in 0..seen_order {
        seen.order.push_back(r.id()?);
    }

    let mut immunity = ImmunityState {
        entries: BTreeMap::new(),
    };
    for _ in 0..immunity_entries {
        let id = r.id()?;
        let expires_at_ms = r.u64()?;
        let wire_len = usize::try_from(r.u32()?)
            .map_err(|_| SnapshotError::CountTooLarge(MAX_RECEIPT_WIRE))?;
        if wire_len == 0 || wire_len > MAX_RECEIPT_WIRE {
            return Err(SnapshotError::InvalidReceipt(
                crate::receipt::ReceiptError::BadLength(wire_len),
            ));
        }
        let wire = r.take(wire_len)?.to_vec();
        let frame = decode_frame(&wire)?.ok_or(SnapshotError::InvalidReceipt(
            crate::receipt::ReceiptError::BadOriginal,
        ))?;
        if frame.msg_id != id {
            return Err(SnapshotError::InvalidReceipt(
                crate::receipt::ReceiptError::MsgIdMismatch,
            ));
        }
        let sent_to = r.links(SnapshotSection::Immunity, link_limit)?;
        let entry = crate::receipt::ImmunityEntry {
            wire,
            expires_at_ms,
            sent_to,
        };
        if immunity.entries.insert(id, entry).is_some() {
            return Err(SnapshotError::DuplicateId);
        }
    }

    let mut spray = SprayState {
        entries: BTreeMap::new(),
    };
    for _ in 0..spray_entries {
        let id = r.id()?;
        let copies_left = r.u8()?;
        let destination: [u8; 16] =
            r.take(16)?
                .try_into()
                .map_err(|_| SnapshotError::Truncated {
                    need: r.pos.saturating_add(16),
                    have: bytes.len(),
                })?;
        let expires_at_ms = r.u64()?;
        let handed_to = r.links(SnapshotSection::Copies, link_limit)?;
        let entry = crate::spray::SprayEntry {
            copies_left,
            destination,
            expires_at_ms,
            handed_to,
        };
        if spray.entries.insert(id, entry).is_some() {
            return Err(SnapshotError::DuplicateId);
        }
    }
    r.finish()?;
    Ok((seen, immunity, spray))
}

/// Clock-epoch-safe storage format, separate from the legacy AMSH v1 bytes.
pub const TIMED_SNAPSHOT_MAGIC: [u8; 4] = *b"AMST";
/// Version of the identity-bound, relative-lifetime snapshot wrapper.
pub const TIMED_SNAPSHOT_VERSION: u8 = 1;
const TIMED_HEADER_LEN: usize = 4 + 1 + 16;
const MAX_REMAINING_MS: u64 = 86_400_000;

/// Android/process restart seam with explicit local time and account binding.
///
/// The host atomically commits bytes with MessageStore copy metadata and
/// authenticates its local storage. Remaining lifetimes are rebased to `now`;
/// `elapsed_ms` is host-measured time since capture, never subtraction of two
/// different monotonic epochs. Zero conservatively retains guards when elapsed
/// time is unknown. No keys, clocks, databases or message payloads are retained.
pub trait TimedSnapshot {
    /// Capture live metadata with relative remaining lifetimes and no LinkIds.
    fn snapshot_at(&self, now: u64, owner: ao_idents::NodeId) -> Result<Vec<u8>, SnapshotError>;
    /// Atomically restore before the fresh engine receives its first input.
    fn restore_at(
        &mut self,
        now: u64,
        owner: ao_idents::NodeId,
        elapsed_ms: u64,
        bytes: &[u8],
    ) -> Result<(), SnapshotError>;
}

pub(crate) fn encode_timed_snapshot(
    now: u64,
    owner: ao_idents::NodeId,
    mut seen: SeenState,
    mut immunity: ImmunityState,
    mut spray: SprayState,
) -> Result<Vec<u8>, SnapshotError> {
    seen.entries.retain(|_, at| {
        *at = at.saturating_sub(now).min(MAX_REMAINING_MS);
        *at > 0
    });
    seen.order.retain(|id| seen.entries.contains_key(id));
    immunity.entries.retain(|_, e| {
        e.expires_at_ms = e.expires_at_ms.saturating_sub(now).min(MAX_REMAINING_MS);
        e.sent_to.clear();
        e.expires_at_ms > 0
    });
    spray.entries.retain(|_, e| {
        e.expires_at_ms = e.expires_at_ms.saturating_sub(now).min(MAX_REMAINING_MS);
        e.handed_to.clear();
        e.expires_at_ms > 0
    });
    let payload = encode_snapshot(seen, immunity, spray)?;
    let mut writer = Writer::default();
    writer.bytes(&TIMED_SNAPSHOT_MAGIC)?;
    writer.u8(TIMED_SNAPSHOT_VERSION)?;
    writer.bytes(owner.as_bytes())?;
    writer.bytes(&payload)?;
    Ok(writer.out)
}

pub(crate) struct TimedRestoreLimits {
    pub(crate) seen: usize,
    pub(crate) immunity: usize,
    pub(crate) spray: usize,
    pub(crate) links: usize,
    pub(crate) immunity_ms: u64,
}

pub(crate) fn decode_timed_snapshot(
    bytes: &[u8],
    now: u64,
    owner: ao_idents::NodeId,
    elapsed: u64,
    limits: TimedRestoreLimits,
) -> Result<(SeenState, ImmunityState, SprayState), SnapshotError> {
    if bytes.len() > MAX_SNAPSHOT_LEN {
        return Err(SnapshotError::TooLarge {
            len: bytes.len(),
            max: MAX_SNAPSHOT_LEN,
        });
    }
    let mut r = Reader::new(bytes);
    if r.take(4)? != TIMED_SNAPSHOT_MAGIC {
        return Err(SnapshotError::BadMagic);
    }
    let version = r.u8()?;
    if version != TIMED_SNAPSHOT_VERSION {
        return Err(SnapshotError::UnsupportedVersion(version));
    }
    if r.take(16)? != owner.as_bytes() {
        return Err(SnapshotError::OwnerMismatch);
    }
    let (mut seen, mut immunity, mut spray) = decode_snapshot(
        &bytes[TIMED_HEADER_LEN..],
        limits.seen,
        limits.immunity,
        limits.spray,
        limits.links,
    )?;
    let rebase = |remaining: u64, ceiling: u64| -> Result<u64, SnapshotError> {
        if remaining > ceiling {
            return Err(SnapshotError::InvalidLifetime);
        }
        let remaining = remaining.saturating_sub(elapsed);
        if remaining == 0 {
            return Ok(0);
        }
        now.checked_add(remaining)
            .ok_or(SnapshotError::ClockOverflow)
    };
    for at in seen.entries.values_mut() {
        *at = rebase(*at, MAX_REMAINING_MS)?;
    }
    seen.entries.retain(|_, at| *at > 0);
    seen.order.retain(|id| seen.entries.contains_key(id));
    for e in immunity.entries.values_mut() {
        e.expires_at_ms = rebase(e.expires_at_ms, limits.immunity_ms.min(MAX_REMAINING_MS))?;
        e.sent_to.clear();
    }
    immunity.entries.retain(|_, e| e.expires_at_ms > 0);
    for e in spray.entries.values_mut() {
        e.expires_at_ms = rebase(e.expires_at_ms, MAX_REMAINING_MS)?;
        e.handed_to.clear();
    }
    spray.entries.retain(|_, e| e.expires_at_ms > 0);
    Ok((seen, immunity, spray))
}
