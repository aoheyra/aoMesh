//! Key-free hop framing and per-link negotiation state (MSH-26).
//!
//! aoIdents owns the Noise XX handshake and the session keys (IDN-13/14).
//! This module owns only the two things that belong to the mesh: the signed
//! capability bit that lets both ends agree to encrypt, and the one-byte
//! Control-body tag that lets a receiver demultiplex a handshake frame before
//! any crypto runs. It never holds a card, a handshake, a key or an RNG.
//!
//! ```text
//! Control body: offset 0  1 byte  kind = 0x01 (Noise XX v1)
//!               offset 1  ..     Noise handshake message (32/96/64 bytes)
//! ```
//!
//! The kind byte is a demultiplexing tag, not a cryptographic field; the Noise
//! state machine rejects out-of-order messages and payloads by itself. Data
//! frames carry no header here: the host seals the complete encoded mesh
//! packet and puts only the resulting ciphertext on the radio, so a passive
//! observer sees no packet header.

use ao_idents::NodeId;
use ao_network::LinkId;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

/// Control-body tag for the `Noise_XX_25519_ChaChaPoly_SHA256` handshake.
///
/// A different Noise suite needs a new byte, an ADR entry and a version bump.
pub const HOP_KIND_NOISE_XX_V1: u8 = 0x01;
/// Largest handshake message this framing accepts. The XX messages are 32,
/// 96 and 64 bytes; 128 leaves room for a minor variant without a second tag.
pub const MAX_HOP_CONTROL_MSG: usize = 128;

/// Why a Control frame could not be framed or demultiplexed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopFrameError {
    /// The body had no kind byte.
    Empty,
    /// The tag names a suite this build does not implement.
    UnknownKind(u8),
    /// The handshake message exceeded [`MAX_HOP_CONTROL_MSG`].
    TooLong {
        /// Bytes supplied.
        len: usize,
        /// Largest accepted message.
        max: usize,
    },
}

impl fmt::Display for HopFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty hop Control frame"),
            Self::UnknownKind(kind) => write!(f, "unknown hop Control kind {kind:#04x}"),
            Self::TooLong { len, max } => {
                write!(f, "hop Control message of {len} bytes exceeds {max}")
            }
        }
    }
}

impl std::error::Error for HopFrameError {}

/// Prepends the kind byte to a host-produced handshake message.
///
/// # Errors
///
/// [`HopFrameError::TooLong`] when `message` exceeds the bound; nothing is
/// copied in that case. An empty message is allowed here but the Noise state
/// machine will reject it, so framing stays a pure length check.
pub fn encode_control(message: &[u8]) -> Result<Vec<u8>, HopFrameError> {
    if message.len() > MAX_HOP_CONTROL_MSG {
        return Err(HopFrameError::TooLong {
            len: message.len(),
            max: MAX_HOP_CONTROL_MSG,
        });
    }
    let mut body = Vec::with_capacity(message.len().saturating_add(1));
    body.push(HOP_KIND_NOISE_XX_V1);
    body.extend_from_slice(message);
    Ok(body)
}

/// Returns the handshake message inside an inbound Control body.
///
/// # Errors
///
/// [`HopFrameError::Empty`] for a zero-length body, [`HopFrameError::UnknownKind`]
/// for an unrecognised tag and [`HopFrameError::TooLong`] for an oversized
/// message. The body is borrowed; no ciphertext is copied before it passes.
pub fn decode_control(body: &[u8]) -> Result<&[u8], HopFrameError> {
    let (&kind, message) = body.split_first().ok_or(HopFrameError::Empty)?;
    if kind != HOP_KIND_NOISE_XX_V1 {
        return Err(HopFrameError::UnknownKind(kind));
    }
    if message.len() > MAX_HOP_CONTROL_MSG {
        return Err(HopFrameError::TooLong {
            len: message.len(),
            max: MAX_HOP_CONTROL_MSG,
        });
    }
    Ok(message)
}

/// Bounded per-link negotiation state. No keys and no handshake state live
/// here: the host installs a session in its own `HopSessions` and then calls
/// [`crate::MeshInput::HopReady`].
#[derive(Debug)]
pub struct HopTracker {
    limit: usize,
    negotiated: BTreeSet<LinkId>,
    /// The signed hello's identity and card-hash pin. The hash is public
    /// mesh state, not a key; the host uses it to select its out-of-band
    /// card before starting a handshake.
    pinned: BTreeMap<LinkId, (NodeId, [u8; 8])>,
    /// Post-link-up outputs that must wait for the host's session. Sending
    /// them earlier would put sync and receipt frames in cleartext on a link
    /// that already negotiated encryption.
    pending: BTreeMap<LinkId, (u32, [u8; 4])>,
    active: BTreeSet<LinkId>,
}

impl HopTracker {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            negotiated: BTreeSet::new(),
            pinned: BTreeMap::new(),
            pending: BTreeMap::new(),
            active: BTreeSet::new(),
        }
    }

    /// Records that both ends advertised the hop capability on `link` and
    /// remembers the card hash the signed hello pinned. Beyond the bound the
    /// link stays cleartext: encryption is optional and no live link is
    /// evicted to make room for policy state.
    pub(crate) fn negotiate(
        &mut self,
        link: LinkId,
        peer: NodeId,
        card_hash: [u8; 8],
        caps: u32,
        remote_digest: [u8; 4],
    ) {
        if self.negotiated.len() < self.limit {
            self.negotiated.insert(link);
            self.pinned.insert(link, (peer, card_hash));
            self.pending.insert(link, (caps, remote_digest));
        }
    }

    /// The verified neighbour and card-hash pin for a negotiated link.
    #[must_use]
    pub fn peer(&self, link: LinkId) -> Option<(NodeId, [u8; 8])> {
        self.pinned.get(&link).copied()
    }

    /// Marks a link active after the host installed its session and returns
    /// the post-link-up policy that was held back (MSH-26).
    pub(crate) fn activate(&mut self, link: LinkId) -> Option<(u32, [u8; 4])> {
        if self.negotiated.contains(&link) {
            self.active.insert(link);
            self.pending.remove(&link)
        } else {
            None
        }
    }

    /// Drops both sets on link-down; a later rekey must negotiate again.
    pub(crate) fn link_down(&mut self, link: LinkId) {
        self.negotiated.remove(&link);
        self.pinned.remove(&link);
        self.pending.remove(&link);
        self.active.remove(&link);
    }

    /// Whether both ends advertised the cap on `link`.
    #[must_use]
    pub fn is_negotiated(&self, link: LinkId) -> bool {
        self.negotiated.contains(&link)
    }

    /// Whether the host installed a session and the adapter must seal Data.
    #[must_use]
    pub fn is_active(&self, link: LinkId) -> bool {
        self.active.contains(&link)
    }

    /// Number of links with a negotiated capability, at most the bound.
    #[must_use]
    pub fn len(&self) -> usize {
        self.negotiated.len()
    }

    /// Whether no link negotiated hop encryption.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.negotiated.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_framing_round_trips_and_rejects_bad_bodies() {
        let body = encode_control(&[0xAB; 96]).expect("a real XX message fits");
        assert_eq!(body[0], HOP_KIND_NOISE_XX_V1);
        assert_eq!(decode_control(&body), Ok(&[0xAB; 96][..]));
        assert_eq!(decode_control(&[]), Err(HopFrameError::Empty));
        assert_eq!(
            decode_control(&[0x02, 1]),
            Err(HopFrameError::UnknownKind(0x02))
        );
        assert!(encode_control(&[0; MAX_HOP_CONTROL_MSG + 1]).is_err());
        assert!(decode_control(&[HOP_KIND_NOISE_XX_V1; MAX_HOP_CONTROL_MSG + 2]).is_err());
    }

    #[test]
    fn tracker_is_bounded_and_only_activates_negotiated_links() {
        let mut tracker = HopTracker::new(1);
        let first = LinkId::new(1);
        let second = LinkId::new(2);
        let peer = NodeId::from_bytes([3; 16]);
        assert!(
            tracker.activate(first).is_none(),
            "no negotiation, no session"
        );
        tracker.negotiate(first, peer, [4; 8], 1, [6; 4]);
        tracker.negotiate(second, peer, [5; 8], 1, [7; 4]);
        assert_eq!(tracker.peer(first), Some((peer, [4; 8])));
        assert_eq!(tracker.len(), 1);
        assert!(tracker.is_negotiated(first));
        assert!(!tracker.is_negotiated(second));
        assert_eq!(tracker.activate(first), Some((1, [6; 4])));
        assert!(tracker.is_active(first));
        tracker.link_down(first);
        assert!(!tracker.is_active(first));
        assert!(
            tracker.activate(first).is_none(),
            "a rekey needs a new hello"
        );
    }
}
