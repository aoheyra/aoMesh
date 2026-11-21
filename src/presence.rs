//! Bounded presence announcements and trickle timing (MSH-19).
//!
//! A presence announcement is an ordinary signed [`PacketClass::Presence`]
//! packet whose opaque payload is a small fixed-width body: a magic byte and
//! version, the origin's eight-byte identity-card hash, its capability bits
//! and a monotonically increasing sequence number. The packet signature uses
//! the already registered `aoheyra/mesh/v1/packet` domain, so this module
//! adds no crypto domain, no packet class and no header field.
//!
//! The wire body is fixed-width and still far smaller than a direct message:
//!
//! ```text
//! offset  size  field
//! 0       1     magic 0x56
//! 1       1     version 1
//! 2       8     identity card hash, opaque to the mesh
//! 10      4     capability bits, big endian
//! 14      8     sequence number, big endian
//! 22      32    Ed25519 signing public key
//! 54      32    X25519 agreement public key
//! 86      64    aoIdents bind-agreement signature
//! ```
//!
//! The extra 96 bytes are not directory state: they are the origin's existing
//! [`PublicIdentity`] and binding, so every relay can derive `origin` from the
//! keys and verify the signature end to end. A forged origin is rejected at
//! every hop, not only at ingress, and a relay cannot swap the body because
//! the signature covers the immutable prefix and the payload hash. The two
//! keys and their binding are exactly the fields aoIdents already defines;
//! this module adds no crypto domain, key storage or identity logic.
//!
//! Trickle state is one deadline per node, not a queue: a change asks the
//! engine to announce immediately, then each quiet refresh doubles the
//! interval until the configured steady-state bound. The host supplies the
//! borrowed identity on each [`crate::MeshInput::Tick`] and the engine never
//! retains a key.

use ao_idents::{IdentError, Identity, PublicIdentity, Signature, compute_node_id};
use ao_network::LinkId;
use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::hello::{CAP_PRESENCE_V1, CAPS};
use crate::packet::{MAX_PAYLOAD, MessageId, Packet, PacketClass};
use crate::sign::{derive_msg_id, sign_packet, verify_origin};

/// Magic byte that distinguishes an announcement from other Presence payloads.
pub const ANNOUNCE_MAGIC: u8 = 0x56;
/// Version of the announcement body.
pub const ANNOUNCE_VERSION: u8 = 1;
/// Fixed encoded length of an announcement body.
pub const ANNOUNCE_LEN: usize = 150;

/// Signed presence facts carried by one announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Announcement {
    /// The origin's identity-card hash, eight opaque bytes.
    pub card_hash: [u8; 8],
    /// Capability bits the origin advertises.
    pub caps: u32,
    /// Monotonically increasing origin sequence number.
    pub seq: u64,
    /// The origin's signing key, so every relay can authenticate it.
    pub signing_pk: [u8; 32],
    /// The origin's agreement key; with `signing_pk` it derives `origin`.
    pub agreement_pk: [u8; 32],
    /// aoIdents binding signature for `agreement_pk`.
    pub binding: [u8; 64],
}

impl Announcement {
    /// Encodes the fixed-width body.
    #[must_use]
    pub fn encode(&self) -> [u8; ANNOUNCE_LEN] {
        let mut out = [0u8; ANNOUNCE_LEN];
        out[0] = ANNOUNCE_MAGIC;
        out[1] = ANNOUNCE_VERSION;
        let mut i = 2;
        while i < 10 {
            out[i] = self.card_hash[i - 2];
            i += 1;
        }
        out[10..14].copy_from_slice(&self.caps.to_be_bytes());
        out[14..22].copy_from_slice(&self.seq.to_be_bytes());
        out[22..54].copy_from_slice(&self.signing_pk);
        out[54..86].copy_from_slice(&self.agreement_pk);
        out[86..150].copy_from_slice(&self.binding);
        out
    }

    /// Parses a body, rejecting any length, magic or version other than the
    /// fixed v1 layout.
    pub fn decode(bytes: &[u8]) -> Result<Self, PresenceError> {
        if bytes.len() != ANNOUNCE_LEN {
            return Err(PresenceError::BadLength(bytes.len()));
        }
        if bytes[0] != ANNOUNCE_MAGIC {
            return Err(PresenceError::BadMagic(bytes[0]));
        }
        if bytes[1] != ANNOUNCE_VERSION {
            return Err(PresenceError::BadVersion(bytes[1]));
        }
        let mut card_hash = [0u8; 8];
        card_hash.copy_from_slice(&bytes[2..10]);
        let caps = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
        let seq = u64::from_be_bytes([
            bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21],
        ]);
        let mut signing_pk = [0u8; 32];
        signing_pk.copy_from_slice(&bytes[22..54]);
        let mut agreement_pk = [0u8; 32];
        agreement_pk.copy_from_slice(&bytes[54..86]);
        let mut binding = [0u8; 64];
        binding.copy_from_slice(&bytes[86..150]);
        Ok(Self {
            card_hash,
            caps,
            seq,
            signing_pk,
            agreement_pk,
            binding,
        })
    }

    /// The aoIdents public identity carried by this body.
    fn public(&self) -> PublicIdentity {
        PublicIdentity::new(
            self.signing_pk,
            self.agreement_pk,
            Signature::from_bytes(self.binding),
        )
    }
}

/// Typed failures for host-supplied presence state and announcement codec work.
///
/// Packet-driven announcement failures are dropped and attributed to the
/// sending link by the engine; they never become a `MeshError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceError {
    /// A body did not have the fixed v1 length.
    BadLength(usize),
    /// A body did not start with the announcement magic.
    BadMagic(u8),
    /// A body carried an unknown version.
    BadVersion(u8),
    /// The announcement body was not a Presence packet payload.
    BadClass,
    /// The signed content address did not match the packet bytes.
    MsgIdMismatch,
    /// The carried agreement-key binding did not verify.
    BadBinding(IdentError),
    /// The carried keys derive a node id other than `header.origin`.
    OriginMismatch,
    /// The host supplied more known card hashes than the bound allows.
    TooManyKnownCards {
        /// Hashes supplied by the host.
        len: usize,
        /// Configured bound.
        max: usize,
    },
    /// The identity layer refused to sign.
    Signing(IdentError),
    /// The signed packet could not be constructed.
    Packet(crate::PacketError),
}

impl fmt::Display for PresenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength(len) => write!(f, "announcement body has invalid length {len}"),
            Self::BadMagic(byte) => write!(f, "unknown announcement magic {byte:#04x}"),
            Self::BadVersion(version) => write!(f, "unknown announcement version {version}"),
            Self::BadClass => write!(f, "announcement is not a Presence packet"),
            Self::MsgIdMismatch => write!(f, "announcement content address does not match"),
            Self::BadBinding(error) => write!(f, "announcement identity binding failed: {error}"),
            Self::OriginMismatch => write!(f, "announcement keys do not derive its origin"),
            Self::TooManyKnownCards { len, max } => {
                write!(f, "{len} known card hashes exceed the bound {max}")
            }
            Self::Signing(error) => write!(f, "announcement signing failed: {error}"),
            Self::Packet(error) => write!(f, "announcement packet is invalid: {error}"),
        }
    }
}
impl std::error::Error for PresenceError {}

/// Bounded state, trickle timers and entry lifetime (MSH-19).
///
/// Defaults follow ADR-0001: the 30-minute entry lifetime and the 64 KiB/h
/// Presence relay budget are met by a 15-minute steady-state refresh. A change
/// goes out on the next tick, then quiet refreshes double from one minute to
/// that bound. No queue or timer thread is used: the engine owns one deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresenceConfig {
    /// Whether announcements are emitted and consumed.
    pub enabled: bool,
    /// Maximum simultaneous learned nodes.
    pub max_entries: usize,
    /// Maximum host-declared known card hashes.
    pub max_known_cards: usize,
    /// Delay before an announcement caused by a change.
    pub quick_ms: u64,
    /// First quiet refresh interval; doubles on each quiet announcement.
    pub base_interval_ms: u64,
    /// Upper bound for the quiet refresh interval (15 minutes by default).
    pub steady_interval_ms: u64,
    /// How long a learned announcement remains useful (ADR-0001).
    pub lifetime_s: u64,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 1_024,
            max_known_cards: 1_024,
            quick_ms: 1_000,
            base_interval_ms: 60_000,
            steady_interval_ms: 900_000,
            lifetime_s: 1_800,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    card_hash: [u8; 8],
    caps: u32,
    seq: u64,
    signing_pk: [u8; 32],
    agreement_pk: [u8; 32],
    binding: [u8; 64],
    expires_at_ms: u64,
    /// Last hash for which this node emitted a `CardFetch`, so a refresh with
    /// the same unknown hash cannot produce a second host event.
    fetched_hash: Option<[u8; 8]>,
}

/// Builds one signed Presence packet for `announcement`.
///
/// The caller supplies `ttl` from the class policy and `lifetime_s` from
/// [`PresenceConfig`]; both are in the signed immutable prefix except the
/// hop-mutable `ttl`. The returned content address lets the engine record the
/// sighting before it sends, so a copy that loops back is never re-relayed.
pub fn encode_announcement(
    now: u64,
    identity: &Identity,
    mut announcement: Announcement,
    ttl: u8,
    lifetime_s: u64,
) -> Result<(MessageId, Vec<u8>), PresenceError> {
    let public = identity.public();
    announcement.signing_pk = *public.signing_pk();
    announcement.agreement_pk = *public.agreement_pk();
    announcement.binding = *public.agreement_binding().as_bytes();
    let payload = announcement.encode();
    let mut header = crate::Header {
        class: PacketClass::Presence,
        dst: None,
        msg_id: [0; 16].into(),
        origin: [0; 16],
        created_ms: now,
        lifetime_s,
        payload_len: ANNOUNCE_LEN as u64,
        ttl,
        hops: 0,
    };
    let signature = sign_packet(identity, &mut header, &payload).map_err(PresenceError::Signing)?;
    let packet = Packet::new(header, signature, &payload).map_err(PresenceError::Packet)?;
    let id = packet.header.msg_id;
    Ok((id, packet.encode()))
}

/// Verifies an announcement end to end against the packet that carries it.
///
/// Every hop derives `origin` from the carried keys, checks aoIdents' binding
/// and verifies the packet signature. A relay can change only `ttl` and
/// `hops`; any other immutable field or body byte breaks one of these checks.
pub fn verify_announcement(packet: &Packet<'_>) -> Result<Announcement, PresenceError> {
    if packet.header.class != PacketClass::Presence || packet.header.dst.is_some() {
        return Err(PresenceError::BadClass);
    }
    if packet.payload.len() != ANNOUNCE_LEN || packet.header.payload_len > MAX_PAYLOAD as u64 {
        return Err(PresenceError::BadLength(packet.payload.len()));
    }
    let announcement = Announcement::decode(packet.payload)?;
    let derived = derive_msg_id(&packet.header, packet.payload);
    if derived != packet.header.msg_id {
        return Err(PresenceError::MsgIdMismatch);
    }
    let public = announcement.public();
    public.verify_binding().map_err(PresenceError::BadBinding)?;
    if compute_node_id(&announcement.signing_pk, &announcement.agreement_pk)
        != ao_idents::NodeId::from_bytes(packet.header.origin)
    {
        return Err(PresenceError::OriginMismatch);
    }
    verify_origin(&public, &packet.header, packet.payload, &packet.signature)
        .map_err(|_| PresenceError::Signing(IdentError::InvalidSignature))?;
    Ok(announcement)
}

/// When this node next emits an announcement and why.
///
/// A quick deadline carries the facts it was scheduled for, so repeated ticks
/// while the deadline is pending cannot push it forward forever. A quiet
/// deadline is the current trickle back-off after the last emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trickle {
    /// No capable link has asked for an announcement.
    Idle,
    /// A change was noticed; the quick deadline is set on the next tick.
    Pending,
    /// A change is waiting for its quick deadline.
    Quick {
        at_ms: u64,
        card_hash: [u8; 8],
        caps: u32,
    },
    /// The next quiet refresh.
    Quiet { at_ms: u64 },
}

/// Deterministic, bounded presence and trickle state.
#[derive(Debug)]
pub struct PresenceTracker {
    config: PresenceConfig,
    caps: BTreeMap<LinkId, u32>,
    entries: BTreeMap<[u8; 16], Entry>,
    known_cards: BTreeSet<[u8; 8]>,
    local: Option<(Announcement, u64, u64)>,
    interval_ms: u64,
    trickle: Trickle,
}

impl PresenceTracker {
    /// Creates an empty tracker. Intervals are clamped to positive values so
    /// a caller cannot construct a timer that fires continuously; a zero
    /// bound simply records nothing.
    #[must_use]
    pub fn new(config: PresenceConfig) -> Self {
        let config = PresenceConfig {
            base_interval_ms: config.base_interval_ms.max(1),
            steady_interval_ms: config.steady_interval_ms.max(1),
            quick_ms: config.quick_ms.max(1),
            ..config
        };
        Self {
            config,
            caps: BTreeMap::new(),
            entries: BTreeMap::new(),
            known_cards: BTreeSet::new(),
            local: None,
            interval_ms: config.base_interval_ms,
            trickle: Trickle::Idle,
        }
    }

    /// Records the caps a link negotiated in its signed hello. A peer without
    /// [`CAP_PRESENCE_V1`] is excluded from announcements and learns nothing
    /// through this module; it keeps the pre-MSH-19 Presence relay path.
    pub(crate) fn set_caps(&mut self, link: LinkId, caps: u32) {
        if self.config.enabled && caps & CAP_PRESENCE_V1 != 0 {
            self.caps.insert(link, caps);
            // A newly capable link must hear the current state without
            // waiting for a long quiet interval. The deadline is set on the
            // next tick so the host's current card hash is used.
            self.trickle = Trickle::Pending;
        } else {
            self.caps.remove(&link);
            if self.caps.is_empty() {
                self.trickle = Trickle::Idle;
            }
        }
    }

    /// Removes per-link bookkeeping when a link ends.
    pub(crate) fn link_down(&mut self, link: LinkId) {
        self.caps.remove(&link);
        if self.caps.is_empty() {
            self.trickle = Trickle::Idle;
        }
    }

    /// Whether a link negotiated the announcement capability.
    #[must_use]
    pub(crate) fn supports(&self, link: LinkId) -> bool {
        self.caps.contains_key(&link)
    }

    /// Whether any link can receive an announcement.
    #[must_use]
    pub(crate) fn has_capable_links(&self) -> bool {
        !self.caps.is_empty()
    }

    /// Replaces the host's known card hashes. The whole input is rejected if
    /// it exceeds the bound, so no partial or silently truncated set can be
    /// mistaken for what the host declared.
    pub(crate) fn set_known_cards(&mut self, hashes: &[[u8; 8]]) -> Result<(), PresenceError> {
        if hashes.len() > self.config.max_known_cards {
            return Err(PresenceError::TooManyKnownCards {
                len: hashes.len(),
                max: self.config.max_known_cards,
            });
        }
        self.known_cards.clear();
        self.known_cards.extend(hashes.iter().copied());
        Ok(())
    }

    /// Advances trickle timing and returns the announcement due now, if any.
    ///
    /// A changed card hash or cap set resets the interval and announces at
    /// once. A quiet refresh doubles the interval up to the steady bound.
    pub(crate) fn on_tick(
        &mut self,
        now: u64,
        card_hash: [u8; 8],
        caps: u32,
    ) -> Option<Announcement> {
        if !self.config.enabled || !self.has_capable_links() {
            return None;
        }
        self.expire(now);
        let caps = caps & CAPS;
        let changed = self
            .local
            .is_none_or(|(local, _, _)| local.card_hash != card_hash || local.caps != caps);
        let base = self
            .config
            .base_interval_ms
            .min(self.config.steady_interval_ms);
        let steady = self.config.steady_interval_ms.max(base);

        // A quick deadline carries the facts it was scheduled for. Without
        // that, `changed` stays true while `local` is empty and every tick
        // would push the deadline out again, so the first announcement would
        // never be emitted.
        match self.trickle {
            Trickle::Idle | Trickle::Pending => {
                self.interval_ms = base;
                self.trickle = Trickle::Quick {
                    at_ms: now.saturating_add(self.config.quick_ms),
                    card_hash,
                    caps,
                };
            }
            Trickle::Quick {
                card_hash: scheduled_hash,
                caps: scheduled_caps,
                ..
            } if scheduled_hash != card_hash || scheduled_caps != caps => {
                self.interval_ms = base;
                self.trickle = Trickle::Quick {
                    at_ms: now.saturating_add(self.config.quick_ms),
                    card_hash,
                    caps,
                };
            }
            Trickle::Quiet { .. } if changed => {
                self.interval_ms = base;
                self.trickle = Trickle::Quick {
                    at_ms: now.saturating_add(self.config.quick_ms),
                    card_hash,
                    caps,
                };
            }
            _ => {}
        }
        let due = match self.trickle {
            Trickle::Quick { at_ms, .. } | Trickle::Quiet { at_ms } => at_ms,
            Trickle::Idle | Trickle::Pending => return None,
        };
        if now < due {
            return None;
        }

        // The sequence is monotonic per origin. Resetting it when the card
        // changes would make the newer state lose `observe`'s latest-wins
        // comparison to an older announcement with a higher sequence.
        let seq = self
            .local
            .map_or(1, |(local, _, _)| local.seq.saturating_add(1));
        // The signing keys are stamped by `encode_announcement`; the tracker
        // itself stores only the facts it compares for changes and ordering.
        let announcement = Announcement {
            card_hash,
            caps,
            seq,
            signing_pk: [0; 32],
            agreement_pk: [0; 32],
            binding: [0; 64],
        };
        self.local = Some((announcement, now, self.interval_ms));
        if changed {
            // The change went out now; the next quiet refresh starts from
            // the base interval.
            self.trickle = Trickle::Quiet {
                at_ms: now.saturating_add(self.interval_ms),
            };
        } else {
            let doubled = self.interval_ms.saturating_mul(2);
            self.interval_ms = doubled.min(steady);
            self.trickle = Trickle::Quiet {
                at_ms: now.saturating_add(self.interval_ms),
            };
        }
        Some(announcement)
    }

    /// Applies a received announcement. The first value is a card hash the
    /// host must fetch when one was seen for the first time; the second says
    /// whether this announcement replaced the previous one and should update
    /// derived state such as the node directory.
    ///
    /// Latest wins by `seq`. Equal sequences are tied deterministically by
    /// the smaller `(card_hash, caps)` pair, so two peers that receive the
    /// same conflicting pair converge on one entry without a coin flip.
    pub(crate) fn observe(
        &mut self,
        now: u64,
        origin: [u8; 16],
        announcement: Announcement,
    ) -> (Option<[u8; 8]>, bool) {
        if !self.config.enabled || self.config.max_entries == 0 {
            return (None, false);
        }
        self.expire(now);
        let expires_at_ms = now.saturating_add(self.config.lifetime_s.saturating_mul(1_000));
        let replace = match self.entries.get(&origin) {
            None => true,
            Some(current) => {
                announcement.seq > current.seq
                    || (announcement.seq == current.seq
                        && Self::tie_key(&announcement) < Self::entry_tie_key(current))
            }
        };
        if !replace {
            return (None, false);
        }
        if !self.entries.contains_key(&origin) && self.entries.len() >= self.config.max_entries {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(node, entry)| (entry.expires_at_ms, *node))
                .map(|(node, _)| *node);
            if let Some(node) = oldest {
                self.entries.remove(&node);
            }
        }
        let already_fetched = self
            .entries
            .get(&origin)
            .and_then(|current| current.fetched_hash)
            == Some(announcement.card_hash);
        let fetch = (!self.known_cards.contains(&announcement.card_hash) && !already_fetched)
            .then_some(announcement.card_hash);
        self.entries.insert(
            origin,
            Entry {
                card_hash: announcement.card_hash,
                caps: announcement.caps,
                seq: announcement.seq,
                signing_pk: announcement.signing_pk,
                agreement_pk: announcement.agreement_pk,
                binding: announcement.binding,
                expires_at_ms,
                fetched_hash: fetch.or(already_fetched.then_some(announcement.card_hash)),
            },
        );
        (fetch, true)
    }

    /// Deterministic equal-sequence tie break: every authenticated field is
    /// part of the order, so conflicting valid announcements converge without
    /// a random draw or arrival-order dependence.
    fn tie_key(value: &Announcement) -> ([u8; 8], u32, [u8; 32], [u8; 32], [u8; 64]) {
        (
            value.card_hash,
            value.caps,
            value.signing_pk,
            value.agreement_pk,
            value.binding,
        )
    }

    fn entry_tie_key(value: &Entry) -> ([u8; 8], u32, [u8; 32], [u8; 32], [u8; 64]) {
        (
            value.card_hash,
            value.caps,
            value.signing_pk,
            value.agreement_pk,
            value.binding,
        )
    }

    /// Removes entries whose relative lifetime elapsed.
    pub(crate) fn expire(&mut self, now: u64) {
        self.entries.retain(|_, entry| entry.expires_at_ms > now);
    }

    /// Number of learned nodes, for diagnostics and bounded-memory tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no nodes have been learned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Read-only view of one learned node's announcement, for host diagnostics.
    #[must_use]
    pub fn get(&self, origin: &[u8; 16]) -> Option<Announcement> {
        self.entries.get(origin).map(|entry| Announcement {
            card_hash: entry.card_hash,
            caps: entry.caps,
            seq: entry.seq,
            signing_pk: entry.signing_pk,
            agreement_pk: entry.agreement_pk,
            binding: entry.binding,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ann(seq: u64, card: u8) -> Announcement {
        Announcement {
            card_hash: [card; 8],
            caps: CAP_PRESENCE_V1,
            seq,
            signing_pk: [card; 32],
            agreement_pk: [card.wrapping_add(1); 32],
            binding: [card.wrapping_add(2); 64],
        }
    }

    fn local_ann(seq: u64, card: u8, caps: u32) -> Announcement {
        Announcement {
            card_hash: [card; 8],
            caps,
            seq,
            signing_pk: [0; 32],
            agreement_pk: [0; 32],
            binding: [0; 64],
        }
    }

    fn signed_ann(identity: &Identity, seq: u64, card: u8, caps: u32) -> Announcement {
        let public = identity.public();
        Announcement {
            card_hash: [card; 8],
            caps,
            seq,
            signing_pk: *public.signing_pk(),
            agreement_pk: *public.agreement_pk(),
            binding: *public.agreement_binding().as_bytes(),
        }
    }

    #[test]
    fn body_round_trips_every_field() {
        let a = Announcement {
            card_hash: [0xAB; 8],
            caps: 0xDEAD_BEEF,
            seq: 0x0102_0304_0506_0708,
            signing_pk: [0x11; 32],
            agreement_pk: [0x22; 32],
            binding: [0x33; 64],
        };
        let bytes = a.encode();
        assert_eq!(bytes.len(), ANNOUNCE_LEN);
        assert_eq!(bytes[0], ANNOUNCE_MAGIC);
        assert_eq!(bytes[1], ANNOUNCE_VERSION);
        assert_eq!(Announcement::decode(&bytes), Ok(a));
    }

    #[test]
    fn codec_rejects_bad_length_magic_and_version() {
        let bytes = ann(1, 1).encode();
        assert_eq!(
            Announcement::decode(&bytes[..ANNOUNCE_LEN - 1]),
            Err(PresenceError::BadLength(ANNOUNCE_LEN - 1))
        );
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert_eq!(
            Announcement::decode(&extra),
            Err(PresenceError::BadLength(ANNOUNCE_LEN + 1))
        );
        let mut bad_magic = bytes;
        bad_magic[0] = 0x00;
        assert_eq!(
            Announcement::decode(&bad_magic),
            Err(PresenceError::BadMagic(0))
        );
        let mut bad_version = bad_magic;
        bad_version[0] = ANNOUNCE_MAGIC;
        bad_version[1] = 2;
        assert_eq!(
            Announcement::decode(&bad_version),
            Err(PresenceError::BadVersion(2))
        );
    }

    #[test]
    fn a_signed_announcement_verifies_at_every_hop_including_after_relay() {
        let origin = Identity::from_seed([31; 32]);
        let facts = signed_ann(&origin, 7, 0xA5, CAPS);
        let (id, wire) =
            encode_announcement(1_000, &origin, facts, 3, 1_800).expect("identity signs");
        let mut packet = Packet::decode(&wire).expect("announcement decodes");
        assert_eq!(packet.header.origin, *origin.node_id().as_bytes());
        assert_eq!(packet.header.msg_id, id);
        assert_eq!(verify_announcement(&packet), Ok(facts));
        // A relay changes only hop-mutable fields; verification still passes.
        packet.header.ttl -= 1;
        packet.header.hops += 1;
        assert_eq!(verify_announcement(&packet), Ok(facts));
    }

    #[test]
    fn tampering_with_the_body_or_origin_is_rejected() {
        let origin = Identity::from_seed([32; 32]);
        let facts = ann(1, 4);
        let (_, wire) = encode_announcement(1_000, &origin, facts, 3, 1_800).expect("signs");
        let mut tampered = wire;
        let at = tampered.len() - ANNOUNCE_LEN + 2;
        tampered[at] ^= 0x01;
        let packet = Packet::decode(&tampered).expect("decodes");
        assert_eq!(
            verify_announcement(&packet),
            Err(PresenceError::MsgIdMismatch)
        );

        let (_, wire) = encode_announcement(1_000, &origin, facts, 3, 1_800).expect("signs");
        let mut packet = Packet::decode(&wire).expect("decodes");
        packet.header.origin = [0x77; 16];
        packet.header.msg_id = derive_msg_id(&packet.header, packet.payload);
        assert_eq!(
            verify_announcement(&packet),
            Err(PresenceError::OriginMismatch)
        );
    }

    fn tracker() -> PresenceTracker {
        PresenceTracker::new(PresenceConfig::default())
    }

    #[test]
    fn latest_wins_by_seq_with_a_deterministic_tie() {
        let mut t = tracker();
        let origin = [7; 16];
        assert_eq!(t.observe(1_000, origin, ann(1, 1)).0, Some([1; 8]));
        assert_eq!(t.get(&origin), Some(ann(1, 1)));
        assert_eq!(t.observe(1_001, origin, ann(3, 3)).0, Some([3; 8]));
        assert_eq!(t.get(&origin), Some(ann(3, 3)));
        // Older sequences cannot roll state back.
        assert_eq!(t.observe(1_002, origin, ann(2, 2)).0, None);
        assert_eq!(t.get(&origin), Some(ann(3, 3)));
        // Equal seq: smaller card hash wins, independent of arrival order.
        assert_eq!(t.observe(1_003, origin, ann(3, 9)).0, None);
        assert_eq!(t.observe(1_004, origin, ann(3, 2)).0, Some([2; 8]));
        assert_eq!(t.get(&origin), Some(ann(3, 2)));
    }

    #[test]
    fn entries_expire_by_relative_age() {
        let mut t = tracker();
        let origin = [9; 16];
        let _ = t.observe(10_000, origin, ann(1, 1));
        let _ = t.observe(10_000 + 1_800_000, origin, ann(2, 2));
        t.expire(10_000 + 3_600_000);
        assert!(t.is_empty());
    }

    #[test]
    fn unknown_cards_are_reported_once_per_node_and_hash() {
        let mut t = tracker();
        let origin = [4; 16];
        assert_eq!(t.observe(100, origin, ann(1, 8)).0, Some([8; 8]));
        assert_eq!(t.observe(101, origin, ann(2, 8)).0, None);
        assert_eq!(t.observe(102, origin, ann(3, 9)).0, Some([9; 8]));
        assert!(t.set_known_cards(&[[9; 8], [8; 8]]).is_ok());
        assert_eq!(t.observe(103, origin, ann(4, 8)).0, None);
    }

    #[test]
    fn known_card_input_is_bounded() {
        let mut t = PresenceTracker::new(PresenceConfig {
            max_known_cards: 2,
            ..PresenceConfig::default()
        });
        assert_eq!(
            t.set_known_cards(&[[1; 8], [2; 8], [3; 8]]),
            Err(PresenceError::TooManyKnownCards { len: 3, max: 2 })
        );
        assert!(t.set_known_cards(&[[1; 8], [2; 8]]).is_ok());
    }

    #[test]
    fn entry_table_is_bounded() {
        let mut t = PresenceTracker::new(PresenceConfig {
            max_entries: 2,
            ..PresenceConfig::default()
        });
        for i in 0..64u8 {
            let _ = t.observe(1_000 + i as u64, [i; 16], ann(1, i));
            assert!(t.len() <= 2);
        }
    }

    #[test]
    fn trickle_backs_off_to_the_steady_bound_and_resets_on_change() {
        let mut t = PresenceTracker::new(PresenceConfig {
            base_interval_ms: 100,
            steady_interval_ms: 400,
            quick_ms: 10,
            ..PresenceConfig::default()
        });
        t.set_caps(LinkId::new(1), CAP_PRESENCE_V1);
        // A new identity waits only the quick delay, then backs off.
        assert_eq!(t.on_tick(0, [1; 8], CAPS), None);
        assert_eq!(t.on_tick(10, [1; 8], CAPS), Some(local_ann(1, 1, CAPS)));
        assert_eq!(t.on_tick(50, [1; 8], CAPS), None);
        assert_eq!(t.on_tick(110, [1; 8], CAPS), Some(local_ann(2, 1, CAPS)));
        assert_eq!(t.on_tick(200, [1; 8], CAPS), None);
        assert_eq!(t.on_tick(310, [1; 8], CAPS), Some(local_ann(3, 1, CAPS)));
        assert_eq!(t.on_tick(500, [1; 8], CAPS), None);
        assert_eq!(t.on_tick(710, [1; 8], CAPS), Some(local_ann(4, 1, CAPS)));
        assert_eq!(t.on_tick(1_110, [1; 8], CAPS), Some(local_ann(5, 1, CAPS)));
        // A card change is quick too and resets the interval.
        assert_eq!(t.on_tick(1_111, [2; 8], CAPS), None);
        // The sequence keeps increasing so the changed card wins latest-wins.
        assert_eq!(t.on_tick(1_121, [2; 8], CAPS), Some(local_ann(6, 2, CAPS)));
        assert_eq!(t.on_tick(1_150, [2; 8], CAPS), None);
    }

    #[test]
    fn capability_gate_controls_links_and_announcements() {
        let mut t = PresenceTracker::new(PresenceConfig::default());
        t.set_caps(LinkId::new(1), CAPS & !CAP_PRESENCE_V1);
        assert!(!t.supports(LinkId::new(1)));
        assert_eq!(t.on_tick(0, [1; 8], CAPS), None);
        t.set_caps(LinkId::new(2), CAP_PRESENCE_V1);
        assert_eq!(t.on_tick(0, [1; 8], CAPS), None);
        assert_eq!(t.on_tick(1_000, [1; 8], CAPS), Some(local_ann(1, 1, CAPS)));
        t.link_down(LinkId::new(2));
        assert!(!t.has_capable_links());
    }

    #[test]
    fn error_display_is_informative_for_every_variant() {
        let errors = [
            PresenceError::BadLength(3),
            PresenceError::BadMagic(0),
            PresenceError::BadVersion(2),
            PresenceError::BadClass,
            PresenceError::MsgIdMismatch,
            PresenceError::BadBinding(IdentError::InvalidSignature),
            PresenceError::OriginMismatch,
            PresenceError::TooManyKnownCards { len: 5, max: 4 },
            PresenceError::Signing(IdentError::InvalidSignature),
            PresenceError::Packet(crate::PacketError::PayloadTooLarge { len: 3, max: 2 }),
        ];
        for error in errors {
            assert!(!error.to_string().is_empty());
        }
    }
}
