//! MSH-16 binary spray-and-wait policy and its bounded wire envelope.
//!
//! The packet header has no spray field: adding one would move the signed
//! immutable prefix and force a packet version bump. Instead a copy ticket
//! travels in a small additive envelope on the same transport channel as the
//! packet it describes. Both peers must advertise `CAP_SPRAY_V1`; a peer
//! without the bit receives the ordinary MSH-08 packet bytes.
//!
//! The envelope is hop-mutable and never signed. Authenticity still comes
//! from the inner packet's origin signature and sealed payload, so a relay
//! can lower a ticket without forging origin content.

use crate::store::MAX_STORED_PACKET;
use crate::{MessageId, PacketClass};
use ao_network::LinkId;
use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

/// Magic byte that distinguishes a spray envelope from a versioned packet.
pub const SPRAY_MAGIC: u8 = 0x54;
/// Version of the additive spray envelope.
pub const SPRAY_VERSION: u8 = 1;
/// Largest copy ticket accepted from a neighbour.
pub const MAX_COPIES: u8 = u8::MAX;

const TAG_DIRECT: u8 = 1;
const HEADER_LEN: usize = 4 + 2;

/// A malformed or out-of-policy spray envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SprayError {
    /// The envelope ended before the fixed header was complete.
    Truncated,
    /// The envelope carries an unknown version.
    BadVersion(u8),
    /// The envelope carries an unknown tag.
    BadTag(u8),
    /// The copy ticket is zero.
    BadCopies(u8),
    /// The declared inner packet length is zero or past the store cap.
    BadLength(usize),
    /// Bytes follow the declared inner packet.
    TrailingBytes(usize),
}

impl fmt::Display for SprayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated spray envelope"),
            Self::BadVersion(version) => write!(f, "unknown spray version {version}"),
            Self::BadTag(tag) => write!(f, "unknown spray tag {tag}"),
            Self::BadCopies(copies) => write!(f, "invalid spray copy count {copies}"),
            Self::BadLength(len) => write!(f, "invalid spray packet length {len}"),
            Self::TrailingBytes(n) => write!(f, "{n} trailing spray bytes"),
        }
    }
}

impl std::error::Error for SprayError {}

/// Parses the fixed envelope header without reading or allocating the inner
/// packet. `Ok(None)` means the bytes are not a spray envelope.
pub(crate) fn decode_frame(bytes: &[u8]) -> Result<Option<(u8, &[u8])>, SprayError> {
    if bytes.first() != Some(&SPRAY_MAGIC) {
        return Ok(None);
    }
    if bytes.len() < HEADER_LEN {
        return Err(SprayError::Truncated);
    }
    if bytes[1] != SPRAY_VERSION {
        return Err(SprayError::BadVersion(bytes[1]));
    }
    if bytes[2] != TAG_DIRECT {
        return Err(SprayError::BadTag(bytes[2]));
    }
    let copies = bytes[3];
    if copies == 0 {
        return Err(SprayError::BadCopies(copies));
    }
    let inner_len = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    if inner_len == 0 || inner_len > MAX_STORED_PACKET {
        return Err(SprayError::BadLength(inner_len));
    }
    let end = HEADER_LEN
        .checked_add(inner_len)
        .ok_or(SprayError::BadLength(inner_len))?;
    if bytes.len() < end {
        return Err(SprayError::Truncated);
    }
    if bytes.len() > end {
        return Err(SprayError::TrailingBytes(bytes.len() - end));
    }
    Ok(Some((copies, &bytes[HEADER_LEN..end])))
}

/// Wraps one encoded packet with a copy ticket. Returns `None` for values the
/// decoder would reject, so the engine never emits an envelope a peer cannot
/// parse.
pub(crate) fn encode_frame(copies: u8, wire: &[u8]) -> Option<Vec<u8>> {
    if copies == 0
        || wire.is_empty()
        || wire.len() > MAX_STORED_PACKET
        || wire.len() > u16::MAX as usize
    {
        return None;
    }
    let mut out = Vec::with_capacity(HEADER_LEN + wire.len());
    out.extend_from_slice(&[SPRAY_MAGIC, SPRAY_VERSION, TAG_DIRECT, copies]);
    out.extend_from_slice(&(wire.len() as u16).to_le_bytes());
    out.extend_from_slice(wire);
    Some(out)
}

/// Bounded policy for binary spray-and-wait (MSH-16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SprayConfig {
    /// Whether Direct traffic uses spray envelopes with capable peers.
    pub enabled: bool,
    /// Initial tickets for a locally submitted Direct packet.
    ///
    /// 255 is the measured setting: with 8 or 64 copies the binary split
    /// starves the eight-hop Direct TTL before a moving copy meets the
    /// destination. See the MSH-27 spray report and the MSH-02 table.
    pub copies: u8,
    /// Maximum number of live per-message spray entries.
    pub max_entries: usize,
}

impl Default for SprayConfig {
    /// 255 keeps one ticket for every hop of the eight-hop Direct TTL after
    /// repeated halving, which the scripted-200 run measures at 0.98 delivery
    /// with 48 percent fewer transmissions than relay-only flooding. 4096
    /// entries bound long-lived state at 1024 live store items across four
    /// overlapping contact windows.
    fn default() -> Self {
        Self {
            enabled: true,
            copies: 255,
            max_entries: 4096,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SprayEntry {
    pub(crate) copies_left: u8,
    pub(crate) destination: [u8; 16],
    pub(crate) expires_at_ms: u64,
    pub(crate) handed_to: BTreeSet<LinkId>,
}

/// The bounded state an MSH-29 snapshot carries. Link capabilities are not
/// included: the host re-announces live links after a restart.
#[derive(Debug, Clone)]
pub(crate) struct SprayState {
    pub(crate) entries: BTreeMap<MessageId, SprayEntry>,
}

/// Deterministic, bounded spray state owned by the sans-IO engine.
///
/// The host store still owns the packet bytes and their `copies_left`
/// metadata. This tracker only decides how many copies a contact may carry
/// and which links have already received one.
#[derive(Debug)]
pub struct SprayTracker {
    config: SprayConfig,
    caps: BTreeMap<LinkId, u32>,
    entries: BTreeMap<MessageId, SprayEntry>,
}

impl SprayTracker {
    /// Creates an empty tracker from bounded configuration.
    #[must_use]
    pub fn new(config: SprayConfig) -> Self {
        Self {
            config,
            caps: BTreeMap::new(),
            entries: BTreeMap::new(),
        }
    }

    /// Copies the bounded ticket set into an MSH-29 snapshot payload.
    pub(crate) fn export_state(&self) -> SprayState {
        SprayState {
            entries: self.entries.clone(),
        }
    }

    /// Installs a validated snapshot, leaving link capabilities untouched.
    pub(crate) fn import_state(&mut self, state: SprayState) {
        self.entries = state.entries;
    }

    /// Records the capability set a link advertised in its signed hello.
    pub(crate) fn set_caps(&mut self, link: LinkId, caps: u32) {
        if caps & crate::hello::CAP_SPRAY_V1 != 0 {
            self.caps.insert(link, caps);
        } else {
            self.caps.remove(&link);
        }
    }

    /// Removes a link from capability and hand-off bookkeeping.
    pub(crate) fn link_down(&mut self, link: LinkId) {
        self.caps.remove(&link);
        for entry in self.entries.values_mut() {
            entry.handed_to.remove(&link);
        }
    }

    /// Whether a link may receive a copy ticket.
    #[must_use]
    pub(crate) fn supports(&self, link: LinkId) -> bool {
        self.config.enabled && self.caps.contains_key(&link)
    }

    /// Starts one local ticket; repeated observations cannot refill it.
    pub(crate) fn observe(
        &mut self,
        now: u64,
        id: MessageId,
        class: PacketClass,
        destination: [u8; 16],
        lifetime_s: u64,
        copies: u8,
    ) {
        if class != PacketClass::Direct || copies == 0 || self.config.max_entries == 0 {
            return;
        }
        self.expire(now);
        let copies = copies.clamp(1, MAX_COPIES);
        let expires_at_ms = now.saturating_add(lifetime_s.saturating_mul(1_000));
        // Includes restored zero-copy tombstones: stale host metadata or a
        // loop must never mint another allocation for the same live id.
        if self.entries.contains_key(&id) {
            return;
        }
        if self.entries.len() >= self.config.max_entries {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at_ms)
                .map(|(id, _)| *id);
            if let Some(id) = oldest {
                self.entries.remove(&id);
            }
        }
        self.entries.insert(
            id,
            SprayEntry {
                copies_left: copies,
                destination,
                expires_at_ms,
                handed_to: BTreeSet::new(),
            },
        );
    }

    /// Removes tickets whose encoded lifetime has passed.
    pub(crate) fn expire(&mut self, now: u64) {
        self.entries.retain(|_, entry| entry.expires_at_ms > now);
    }

    /// The retained ticket for host store metadata. Unknown ids use one copy.
    #[must_use]
    pub(crate) fn copies_left(&self, id: MessageId) -> u8 {
        self.entries.get(&id).map_or(1, |entry| entry.copies_left)
    }

    /// Stops spraying an id once a delivery receipt has purged it.
    pub(crate) fn forget(&mut self, id: MessageId) {
        self.entries.remove(&id);
    }

    /// Whether a contact may carry this id to `peer`. The destination always
    /// receives a copy; other peers only receive one while the spray phase
    /// is active.
    #[must_use]
    pub(crate) fn can_sync(&self, id: MessageId, peer: [u8; 16]) -> bool {
        let Some(entry) = self.entries.get(&id) else {
            return true;
        };
        entry.destination == peer || entry.copies_left > 1
    }

    /// Chooses contacts that receive the next half of a ticket.
    ///
    /// Candidates arrive in deterministic link order from the neighbour
    /// table. The sender and links already holding a copy are skipped. A
    /// destination gets one copy and ends the spray for that entry.
    pub(crate) fn plan(
        &mut self,
        now: u64,
        id: MessageId,
        sender: Option<LinkId>,
        candidates: impl IntoIterator<Item = (LinkId, [u8; 16])>,
    ) -> Vec<(LinkId, u8)> {
        self.plan_with_hint(now, id, sender, candidates, None)
    }

    /// Same as [`Self::plan`], with an optional MSH-21 reverse-path hint.
    ///
    /// A hint only changes the plan when it names a candidate that the binary
    /// split would not have chosen. In the spray phase it replaces the last
    /// (highest link id) recipient with a one-ticket copy; the number of
    /// transmissions and the ticket consumption stay exactly as planned, so
    /// using a hint cannot add traffic. In the wait phase, where there is no
    /// other recipient, the retained copy is sent once along the fresh path.
    pub(crate) fn plan_with_hint(
        &mut self,
        now: u64,
        id: MessageId,
        sender: Option<LinkId>,
        candidates: impl IntoIterator<Item = (LinkId, [u8; 16])>,
        hint: Option<LinkId>,
    ) -> Vec<(LinkId, u8)> {
        self.expire(now);
        let Some(entry) = self.entries.get_mut(&id) else {
            return Vec::new();
        };
        let candidates: Vec<_> = candidates.into_iter().collect();

        // A later destination must not be skipped because an earlier
        // non-destination arrived first in link order. The last copy exists
        // precisely to meet the recipient.
        if let Some((link, _)) = candidates.iter().find(|(link, node)| {
            Some(*link) != sender && !entry.handed_to.contains(link) && entry.destination == *node
        }) {
            entry.handed_to.insert(*link);
            entry.copies_left = 0;
            return vec![(*link, 1)];
        }

        let mut plan = Vec::new();
        for (link, _node) in &candidates {
            if Some(*link) == sender || entry.handed_to.contains(link) {
                continue;
            }
            if entry.copies_left <= 1 {
                break;
            }
            let give = entry.copies_left / 2;
            entry.handed_to.insert(*link);
            entry.copies_left -= give;
            plan.push((*link, give));
            if entry.copies_left <= 1 {
                break;
            }
        }
        if let Some(hint) = hint {
            let wanted = Some(hint) != sender
                && !plan.iter().any(|(link, _)| *link == hint)
                && candidates.iter().any(|(link, _)| *link == hint);
            if wanted {
                if let Some(last) = plan.last_mut() {
                    let replaced = last.0;
                    // The destination shortcut is already the best copy.
                    if candidates
                        .iter()
                        .any(|(link, node)| *link == replaced && *node == entry.destination)
                    {
                        return plan;
                    }
                    // Ticket accounting stays at `give` consumed: the wire
                    // copy carries one ticket, but the replaced recipient's
                    // share is not returned to the spray pool. That keeps
                    // the number of transmissions, and the later fan-out,
                    // identical to the unhinted plan.
                    entry.handed_to.remove(&replaced);
                    entry.handed_to.insert(hint);
                    last.0 = hint;
                    last.1 = 1;
                } else if entry.copies_left > 0 {
                    // Wait phase: there is no other recipient, so the
                    // retained copy goes once along the fresh path.
                    entry.handed_to.insert(hint);
                    entry.copies_left = 0;
                    plan.push((hint, 1));
                }
            }
        }
        plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK_A: LinkId = LinkId::new(1);
    const LINK_B: LinkId = LinkId::new(2);
    const LINK_C: LinkId = LinkId::new(3);

    fn tracker(copies: u8, max_entries: usize) -> SprayTracker {
        SprayTracker::new(SprayConfig {
            enabled: true,
            copies,
            max_entries,
        })
    }

    fn id(byte: u8) -> MessageId {
        MessageId::from_bytes([byte; 16])
    }

    #[test]
    fn envelope_round_trips_and_rejects_bad_wires() {
        let inner = b"signed packet";
        let frame = encode_frame(5, inner).expect("valid envelope");
        assert_eq!(decode_frame(&frame), Ok(Some((5, &inner[..]))));
        assert_eq!(decode_frame(b"not spray"), Ok(None));

        let cases: [&[u8]; 6] = [
            &[SPRAY_MAGIC],
            &[SPRAY_MAGIC, SPRAY_VERSION, TAG_DIRECT, 1, 1],
            &[SPRAY_MAGIC, SPRAY_VERSION, 9, 1, 1, 0, 7],
            &[SPRAY_MAGIC, SPRAY_VERSION, TAG_DIRECT, 0, 1, 0, 7],
            &[SPRAY_MAGIC, SPRAY_VERSION, TAG_DIRECT, 1, 0, 0],
            &[SPRAY_MAGIC, SPRAY_VERSION, TAG_DIRECT, 1, 1, 0, 7, 8],
        ];
        for case in cases {
            assert!(
                decode_frame(case).is_err(),
                "accepted bad envelope {case:?}"
            );
        }
    }

    #[test]
    fn oversized_inner_packet_is_never_emitted() {
        assert!(encode_frame(1, &[0; MAX_STORED_PACKET]).is_some());
        assert!(encode_frame(1, &[0; MAX_STORED_PACKET + 1]).is_none());
    }

    #[test]
    fn binary_split_hands_half_and_stops_in_wait_phase() {
        let mut tracker = tracker(8, 8);
        tracker.observe(0, id(1), PacketClass::Direct, [2; 16], 60, 8);
        assert_eq!(
            tracker.plan(0, id(1), None, [(LINK_A, [3; 16]), (LINK_B, [4; 16])]),
            vec![(LINK_A, 4), (LINK_B, 2)]
        );
        assert_eq!(tracker.copies_left(id(1)), 2);
        assert_eq!(
            tracker.plan(0, id(1), None, [(LINK_C, [5; 16])]),
            vec![(LINK_C, 1)]
        );
        assert_eq!(tracker.copies_left(id(1)), 1);
        assert!(tracker.plan(0, id(1), None, [(LINK_A, [3; 16])]).is_empty());
    }

    #[test]
    fn destination_gets_one_copy_and_ends_the_spray() {
        let mut tracker = tracker(8, 8);
        tracker.observe(0, id(1), PacketClass::Direct, [9; 16], 60, 8);
        assert_eq!(
            tracker.plan(0, id(1), None, [(LINK_A, [9; 16]), (LINK_B, [4; 16])]),
            vec![(LINK_A, 1)]
        );
        assert_eq!(tracker.copies_left(id(1)), 0);
        assert!(tracker.can_sync(id(1), [9; 16]));
        assert!(!tracker.can_sync(id(1), [4; 16]));
    }

    #[test]
    fn wait_phase_still_delivers_to_the_destination() {
        let mut tracker = tracker(8, 8);
        tracker.observe(0, id(1), PacketClass::Direct, [9; 16], 60, 1);
        assert_eq!(
            tracker.plan(0, id(1), None, [(LINK_A, [4; 16]), (LINK_B, [9; 16])]),
            vec![(LINK_B, 1)]
        );
        assert_eq!(tracker.copies_left(id(1)), 0);
    }

    #[test]
    fn hint_replaces_a_recipient_without_adding_a_transmission() {
        let candidates = [(LINK_A, [3; 16]), (LINK_B, [4; 16]), (LINK_C, [5; 16])];
        let mut baseline = tracker(8, 8);
        baseline.observe(0, id(1), PacketClass::Direct, [9; 16], 60, 8);
        let base = baseline.plan(0, id(1), None, candidates);
        assert_eq!(base, vec![(LINK_A, 4), (LINK_B, 2)]);
        let base_left = baseline.copies_left(id(1));

        let mut hinted = tracker(8, 8);
        hinted.observe(0, id(1), PacketClass::Direct, [9; 16], 60, 8);
        let plan = hinted.plan_with_hint(0, id(1), None, candidates, Some(LINK_C));
        assert_eq!(plan.len(), base.len());
        assert_eq!(plan.last(), Some(&(LINK_C, 1)));
        assert_eq!(hinted.copies_left(id(1)), base_left);
    }

    #[test]
    fn wait_phase_sends_its_only_copy_along_a_fresh_hint() {
        let mut tracker = tracker(8, 8);
        tracker.observe(0, id(1), PacketClass::Direct, [9; 16], 60, 1);
        assert!(
            tracker
                .plan(0, id(1), None, [(LINK_A, [3; 16]), (LINK_B, [4; 16])])
                .is_empty()
        );
        assert_eq!(
            tracker.plan_with_hint(
                0,
                id(1),
                None,
                [(LINK_A, [3; 16]), (LINK_B, [4; 16])],
                Some(LINK_B),
            ),
            vec![(LINK_B, 1)]
        );
        assert_eq!(tracker.copies_left(id(1)), 0);
    }

    #[test]
    fn max_entries_evicts_the_oldest_ticket() {
        let mut tracker = tracker(8, 2);
        for (n, byte) in [1u8, 2, 3].into_iter().enumerate() {
            tracker.observe(
                n as u64 * 1_000,
                id(byte),
                PacketClass::Direct,
                [7; 16],
                60,
                8,
            );
        }
        assert!(
            tracker
                .plan(3_000, id(1), None, [(LINK_A, [4; 16])])
                .is_empty()
        );
        assert!(
            !tracker
                .plan(3_000, id(3), None, [(LINK_A, [4; 16])])
                .is_empty()
        );
    }
}

#[cfg(test)]
mod restart_copy_regressions {
    use super::*;
    #[test]
    fn restored_zero_ticket_cannot_be_refilled_by_stale_metadata() {
        let id = MessageId::from_bytes([29; 16]);
        let config = SprayConfig {
            enabled: true,
            copies: 8,
            max_entries: 2,
        };
        let mut original = SprayTracker::new(config);
        original.observe(100, id, PacketClass::Direct, [9; 16], 60, 8);
        assert_eq!(
            original.plan(100, id, None, [(LinkId::new(1), [9; 16])]),
            vec![(LinkId::new(1), 1)]
        );
        let mut restored = SprayTracker::new(config);
        restored.import_state(original.export_state());
        restored.observe(200, id, PacketClass::Direct, [9; 16], 3600, 255);
        assert_eq!(restored.copies_left(id), 0);
        let state = restored.export_state();
        assert_eq!(state.entries[&id].expires_at_ms, 60_100);
        assert!(
            restored
                .plan(201, id, None, [(LinkId::new(2), [8; 16])])
                .is_empty()
        );
    }
    #[test]
    fn zero_capacity_survives_live_observations() {
        let mut tracker = SprayTracker::new(SprayConfig {
            enabled: true,
            copies: 8,
            max_entries: 0,
        });
        tracker.observe(
            0,
            MessageId::from_bytes([1; 16]),
            PacketClass::Direct,
            [9; 16],
            60,
            8,
        );
        assert!(tracker.export_state().entries.is_empty());
    }
}
