//! Signed delivery receipts and bounded immunity policy (MSH-17).
//!
//! A receipt is routed as a small control envelope on the same Message
//! channel as packets. It is not a fifth packet class and it does not change
//! the signed packet header. The envelope carries the recipient's full
//! [`PublicIdentity`], the original packet header and payload hash, and a
//! normal signed Direct packet whose payload is the acknowledged `MessageId`.
//! That makes the receipt self-contained: any relay can prove that the
//! signer owns the original destination without a directory, then re-derive
//! the acknowledged id from the header and payload hash.

use ao_idents::{IdentError, Identity, PublicIdentity, Signature, compute_node_id};
use ao_network::LinkId;
use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::hello::CAP_RECEIPT_V1;
use crate::packet::{Header, MAX_IMMUTABLE_LEN, MessageId, Packet, PacketClass, PacketError};
use crate::sign::{derive_msg_id_from_hash, sign_packet, verify_origin};

/// Magic byte that distinguishes a receipt from a versioned packet.
pub const RECEIPT_MAGIC: u8 = 0x55;
/// Version of the receipt envelope.
pub const RECEIPT_VERSION: u8 = 1;

const TAG_ACK: u8 = 1;
const HEADER_LEN: usize = 8;
const PUBLIC_IDENTITY_LEN: usize = 32 + 32 + 64;
const PAYLOAD_HASH_LEN: usize = 32;
const SIGNER_OFFSET: usize = HEADER_LEN;
const MAX_ORIGINAL_HEADER: usize = MAX_IMMUTABLE_LEN + 2;
const MAX_ACK_PACKET: usize = 512;
const MAX_GOSSIP_PER_CONTACT: usize = 16;
const ACK_LIFETIME_S: u64 = 300;

/// Why a receipt envelope was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    /// The envelope ended before its fixed header was complete.
    Truncated,
    /// The envelope carries an unknown version.
    BadVersion(u8),
    /// The envelope carries an unknown tag.
    BadTag(u8),
    /// Reserved header bits are set.
    BadFlags(u8),
    /// A bounded length field is invalid.
    BadLength(usize),
    /// The acknowledged header is not a Direct packet with a destination.
    BadOriginal,
    /// The original header and hash do not derive its claimed message id.
    MsgIdMismatch,
    /// The acknowledgement packet is not the expected Direct packet.
    BadAck,
    /// The attached identity is inconsistent or its signature is invalid.
    BadSigner,
    /// The identity layer refused a signature operation.
    Signing(IdentError),
    /// The acknowledgement packet could not be constructed.
    Packet(PacketError),
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated receipt envelope"),
            Self::BadVersion(version) => write!(f, "unknown receipt version {version}"),
            Self::BadTag(tag) => write!(f, "unknown receipt tag {tag}"),
            Self::BadFlags(flags) => write!(f, "invalid receipt flags {flags}"),
            Self::BadLength(len) => write!(f, "invalid receipt length {len}"),
            Self::BadOriginal => write!(f, "receipt does not name a Direct destination"),
            Self::MsgIdMismatch => write!(f, "receipt message id does not match its header"),
            Self::BadAck => write!(f, "receipt acknowledgement packet is invalid"),
            Self::BadSigner => write!(f, "receipt signer is not the acknowledged destination"),
            Self::Signing(error) => write!(f, "receipt signing failed: {error}"),
            Self::Packet(error) => write!(f, "receipt packet is invalid: {error}"),
        }
    }
}

impl std::error::Error for ReceiptError {}

/// A decoded and authenticated receipt. `wire` is the complete envelope and
/// is kept verbatim so immunity gossip never rewrites signed bytes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReceiptFrame<'a> {
    /// The message whose copies may be purged.
    pub msg_id: MessageId,
    /// The original sender, which receives sender-status delivery.
    pub origin: [u8; 16],
    /// The authenticated destination that issued the receipt.
    pub signer: [u8; 16],
    /// Complete encoded envelope.
    pub wire: &'a [u8],
}

/// Builds a signed acknowledgement for a successfully delivered packet.
pub(crate) fn encode_ack(
    now: u64,
    identity: &Identity,
    original: &Header,
    plaintext_hash: &[u8; PAYLOAD_HASH_LEN],
) -> Result<Vec<u8>, ReceiptError> {
    if original.class != PacketClass::Direct || original.dst.is_none() {
        return Err(ReceiptError::BadOriginal);
    }
    let ack_payload = original.msg_id.as_bytes();
    let mut ack_header = Header {
        class: PacketClass::Direct,
        dst: Some(original.origin),
        msg_id: MessageId::from_bytes([0; 16]),
        origin: [0; 16],
        created_ms: now,
        lifetime_s: ACK_LIFETIME_S,
        payload_len: ack_payload.len() as u64,
        ttl: 0,
        hops: 0,
    };
    let signature =
        sign_packet(identity, &mut ack_header, ack_payload).map_err(ReceiptError::Signing)?;
    let ack = Packet::new(ack_header, signature, ack_payload).map_err(ReceiptError::Packet)?;
    let ack_wire = ack.encode();
    if ack_wire.len() > MAX_ACK_PACKET {
        return Err(ReceiptError::BadLength(ack_wire.len()));
    }

    let original_wire = original.encode();
    if original_wire.len() > MAX_ORIGINAL_HEADER {
        return Err(ReceiptError::BadLength(original_wire.len()));
    }
    let public = identity.public();
    let total = HEADER_LEN
        .checked_add(PUBLIC_IDENTITY_LEN)
        .and_then(|n| n.checked_add(original_wire.len()))
        .and_then(|n| n.checked_add(PAYLOAD_HASH_LEN))
        .and_then(|n| n.checked_add(ack_wire.len()))
        .ok_or(ReceiptError::BadLength(usize::MAX))?;

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&[
        RECEIPT_MAGIC,
        RECEIPT_VERSION,
        TAG_ACK,
        0,
        (original_wire.len() as u16).to_le_bytes()[0],
        (original_wire.len() as u16).to_le_bytes()[1],
        (ack_wire.len() as u16).to_le_bytes()[0],
        (ack_wire.len() as u16).to_le_bytes()[1],
    ]);
    out.extend_from_slice(public.signing_pk());
    out.extend_from_slice(public.agreement_pk());
    out.extend_from_slice(public.agreement_binding().as_bytes());
    out.extend_from_slice(&original_wire);
    out.extend_from_slice(plaintext_hash);
    out.extend_from_slice(&ack_wire);
    debug_assert_eq!(out.len(), total);
    Ok(out)
}

/// Parses and authenticates a receipt envelope without allocating its inner
/// buffers. `Ok(None)` means the bytes are not a receipt envelope.
pub(crate) fn decode_frame(bytes: &[u8]) -> Result<Option<ReceiptFrame<'_>>, ReceiptError> {
    if bytes.first() != Some(&RECEIPT_MAGIC) {
        return Ok(None);
    }
    if bytes.len() < HEADER_LEN {
        return Err(ReceiptError::Truncated);
    }
    if bytes[1] != RECEIPT_VERSION {
        return Err(ReceiptError::BadVersion(bytes[1]));
    }
    if bytes[2] != TAG_ACK {
        return Err(ReceiptError::BadTag(bytes[2]));
    }
    if bytes[3] != 0 {
        return Err(ReceiptError::BadFlags(bytes[3]));
    }
    let original_len = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    let ack_len = u16::from_le_bytes([bytes[6], bytes[7]]) as usize;
    if original_len == 0 || original_len > MAX_ORIGINAL_HEADER || ack_len > MAX_ACK_PACKET {
        return Err(ReceiptError::BadLength(original_len.max(ack_len)));
    }
    let identity_end = SIGNER_OFFSET + PUBLIC_IDENTITY_LEN;
    let original_end = identity_end
        .checked_add(original_len)
        .ok_or(ReceiptError::BadLength(original_len))?;
    let hash_end = original_end
        .checked_add(PAYLOAD_HASH_LEN)
        .ok_or(ReceiptError::BadLength(original_len))?;
    let total = hash_end
        .checked_add(ack_len)
        .ok_or(ReceiptError::BadLength(ack_len))?;
    if bytes.len() < total {
        return Err(ReceiptError::Truncated);
    }
    if bytes.len() > total {
        return Err(ReceiptError::BadLength(bytes.len() - total));
    }

    let mut signing_pk = [0; 32];
    let mut agreement_pk = [0; 32];
    let mut binding = [0; 64];
    signing_pk.copy_from_slice(&bytes[SIGNER_OFFSET..SIGNER_OFFSET + 32]);
    agreement_pk.copy_from_slice(&bytes[SIGNER_OFFSET + 32..SIGNER_OFFSET + 64]);
    binding.copy_from_slice(&bytes[SIGNER_OFFSET + 64..identity_end]);
    let public = PublicIdentity::new(signing_pk, agreement_pk, Signature::from_bytes(binding));
    public
        .verify_binding()
        .map_err(|_| ReceiptError::BadSigner)?;
    let signer = compute_node_id(&signing_pk, &agreement_pk);

    let original = Header::decode(&bytes[identity_end..original_end])
        .map_err(|_| ReceiptError::BadOriginal)?;
    let Some(destination) = original.dst else {
        return Err(ReceiptError::BadOriginal);
    };
    if original.class != PacketClass::Direct || *signer.as_bytes() != destination {
        return Err(ReceiptError::BadSigner);
    }
    let hash: &[u8; PAYLOAD_HASH_LEN] = bytes[original_end..hash_end]
        .try_into()
        .map_err(|_| ReceiptError::Truncated)?;
    let msg_id = derive_msg_id_from_hash(&original, hash);
    if msg_id != original.msg_id {
        return Err(ReceiptError::MsgIdMismatch);
    }

    let ack = Packet::decode(&bytes[hash_end..total]).map_err(|_| ReceiptError::BadAck)?;
    if ack.header.class != PacketClass::Direct
        || ack.header.dst != Some(original.origin)
        || ack.payload != msg_id.as_bytes()
    {
        return Err(ReceiptError::BadAck);
    }
    verify_origin(&public, &ack.header, ack.payload, &ack.signature)
        .map_err(|_| ReceiptError::BadSigner)?;

    Ok(Some(ReceiptFrame {
        msg_id,
        origin: original.origin,
        signer: *signer.as_bytes(),
        wire: bytes,
    }))
}

/// Bounded configuration for receipts and the immunity list (MSH-17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptConfig {
    /// Whether receipts are emitted, accepted and gossiped.
    pub enabled: bool,
    /// Maximum live immunity entries.
    pub max_entries: usize,
    /// How long an immunity entry suppresses re-sync of its id.
    pub lifetime_s: u64,
    /// Maximum receipt frames sent to one link per contact event.
    pub max_gossip_per_contact: usize,
}

impl Default for ReceiptConfig {
    /// 512 receipts at a bounded envelope size keep immunity memory under
    /// 256 KiB; five minutes outlives a contact and its later re-sync.
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 512,
            lifetime_s: 300,
            max_gossip_per_contact: MAX_GOSSIP_PER_CONTACT,
        }
    }
}

#[derive(Debug, Clone)]
struct Immunity {
    wire: Vec<u8>,
    expires_at_ms: u64,
    sent_to: BTreeSet<LinkId>,
}

/// Deterministic, bounded immunity state owned by the sans-IO engine.
#[derive(Debug)]
pub struct ReceiptTracker {
    config: ReceiptConfig,
    caps: BTreeMap<LinkId, u32>,
    entries: BTreeMap<MessageId, Immunity>,
}

impl ReceiptTracker {
    /// Creates an empty tracker from bounded configuration.
    #[must_use]
    pub fn new(config: ReceiptConfig) -> Self {
        Self {
            config,
            caps: BTreeMap::new(),
            entries: BTreeMap::new(),
        }
    }

    /// Records the capability set a link advertised in its signed hello.
    pub(crate) fn set_caps(&mut self, link: LinkId, caps: u32) {
        if caps & CAP_RECEIPT_V1 != 0 {
            self.caps.insert(link, caps);
        } else {
            self.caps.remove(&link);
        }
    }

    /// Removes link-specific bookkeeping without dropping immunity entries.
    pub(crate) fn link_down(&mut self, link: LinkId) {
        self.caps.remove(&link);
        for entry in self.entries.values_mut() {
            entry.sent_to.remove(&link);
        }
    }

    /// Whether a link negotiated the receipt envelope.
    #[must_use]
    pub(crate) fn supports(&self, link: LinkId) -> bool {
        self.config.enabled && self.caps.contains_key(&link)
    }

    /// Whether an id is currently immune from store re-sync.
    #[must_use]
    pub(crate) fn is_immune(&self, id: MessageId) -> bool {
        self.entries.contains_key(&id)
    }

    /// Records an authenticated receipt. The sending link is marked served so
    /// the receipt is not echoed straight back to its source.
    pub(crate) fn accept(
        &mut self,
        now: u64,
        frame: &ReceiptFrame<'_>,
        sender: Option<LinkId>,
    ) -> bool {
        self.expire(now);
        if self.entries.contains_key(&frame.msg_id) {
            return false;
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
        if self.config.max_entries == 0 {
            return false;
        }
        let mut sent_to = BTreeSet::new();
        if let Some(link) = sender {
            sent_to.insert(link);
        }
        self.entries.insert(
            frame.msg_id,
            Immunity {
                wire: frame.wire.to_vec(),
                expires_at_ms: now.saturating_add(self.config.lifetime_s.saturating_mul(1_000)),
                sent_to,
            },
        );
        true
    }

    /// Returns bounded receipt frames that `link` has not received yet.
    pub(crate) fn pending_for(&mut self, link: LinkId) -> Vec<Vec<u8>> {
        if !self.supports(link) {
            return Vec::new();
        }
        self.entries
            .iter_mut()
            .filter(|(_, entry)| !entry.sent_to.contains(&link))
            .take(self.config.max_gossip_per_contact)
            .map(|(_, entry)| {
                entry.sent_to.insert(link);
                entry.wire.clone()
            })
            .collect()
    }

    /// Drops expired immunity entries.
    pub(crate) fn expire(&mut self, now: u64) {
        self.entries.retain(|_, entry| entry.expires_at_ms > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ao_idents::Identity;

    use crate::sign::payload_hash;

    const LINK_A: LinkId = LinkId::new(1);
    const LINK_B: LinkId = LinkId::new(2);

    fn identity(seed: u8) -> Identity {
        Identity::from_seed([seed; 32])
    }

    fn original(sender: &Identity, recipient: &Identity) -> (Header, [u8; 32]) {
        let payload: &[u8] = b"original packet bytes";
        let mut header = Header {
            class: PacketClass::Direct,
            dst: Some(*recipient.node_id().as_bytes()),
            msg_id: MessageId::from_bytes([0; 16]),
            origin: [0; 16],
            created_ms: 100,
            lifetime_s: 60,
            payload_len: payload.len() as u64,
            ttl: 8,
            hops: 0,
        };
        let signature = sign_packet(sender, &mut header, payload).expect("fixed packet signs");
        let _ = Packet::new(header, signature, payload).expect("lengths agree");
        (header, payload_hash(payload))
    }

    #[test]
    fn an_ack_is_self_authenticating_and_binds_the_original_id() {
        let sender = identity(1);
        let recipient = identity(2);
        let (header, hash) = original(&sender, &recipient);
        let wire = encode_ack(1_000, &recipient, &header, &hash).expect("ack encodes");
        let frame = decode_frame(&wire)
            .expect("ack decodes")
            .expect("is a receipt");
        assert_eq!(frame.msg_id, header.msg_id);
        assert_eq!(frame.origin, *sender.node_id().as_bytes());
        assert_eq!(frame.signer, *recipient.node_id().as_bytes());
        assert_eq!(frame.wire, wire.as_slice());
    }

    #[test]
    fn a_wrong_signer_or_tampered_header_is_rejected() {
        let sender = identity(1);
        let recipient = identity(2);
        let forger = identity(3);
        let (header, hash) = original(&sender, &recipient);

        let forged = encode_ack(1_000, &forger, &header, &hash).expect("forgery encodes");
        assert_eq!(
            decode_frame(&forged).err(),
            Some(ReceiptError::BadSigner),
            "only the destination may ack"
        );

        let wire = encode_ack(1_000, &recipient, &header, &hash).expect("ack encodes");
        let mut tampered = wire.clone();
        tampered[HEADER_LEN + 32] ^= 1;
        assert!(decode_frame(&tampered).is_err());
        assert!(decode_frame(&wire).is_ok());
    }

    #[test]
    fn malformed_lengths_are_rejected_before_inner_parsing() {
        let short = [RECEIPT_MAGIC, RECEIPT_VERSION, TAG_ACK, 0];
        assert_eq!(decode_frame(&short).err(), Some(ReceiptError::Truncated));

        let mut bad = vec![RECEIPT_MAGIC, RECEIPT_VERSION, TAG_ACK, 0, 0, 0, 0, 0];
        bad.extend_from_slice(&[0; PUBLIC_IDENTITY_LEN]);
        assert_eq!(decode_frame(&bad).err(), Some(ReceiptError::BadLength(0)));
    }

    #[test]
    fn immunity_is_bounded_and_gossiped_once_per_link() {
        let sender = identity(1);
        let recipient = identity(2);
        let (header, hash) = original(&sender, &recipient);
        let wire = encode_ack(1_000, &recipient, &header, &hash).expect("ack encodes");
        let frame = decode_frame(&wire).expect("decodes").expect("receipt");
        let mut tracker = ReceiptTracker::new(ReceiptConfig {
            max_entries: 1,
            ..ReceiptConfig::default()
        });
        tracker.set_caps(LINK_A, CAP_RECEIPT_V1);
        tracker.set_caps(LINK_B, CAP_RECEIPT_V1);
        assert!(tracker.accept(1_000, &frame, Some(LINK_A)));
        assert!(!tracker.accept(1_001, &frame, Some(LINK_B)));
        assert!(tracker.is_immune(frame.msg_id));
        assert!(tracker.pending_for(LINK_A).is_empty());
        assert_eq!(tracker.pending_for(LINK_B), vec![wire]);
        assert!(tracker.pending_for(LINK_B).is_empty());
    }
}
