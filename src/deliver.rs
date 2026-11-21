//! The authenticated local delivery pipeline (MSH-09).
//!
//! A packet whose `dst` is this node (MSH-08) is a delivery candidate
//! only; this module decides whether it becomes a delivery. The checks
//! run cheapest-first over what the packet already proved
//! structurally, then the sealed payload authenticates itself:
//!
//! 1. `SealedMessage::decode` parses the bounded seal;
//! 2. `SealedMessage::open` verifies the AEAD tag under associated
//!    data binding this node's identity and the header's content
//!    address, returning the authenticated sender;
//! 3. that sender's `NodeId` must equal `header.origin`;
//! 4. `verify_origin` checks the origin signature over the immutable
//!    prefix, under which `msg_id` and the timestamps are signed;
//! 5. `ReplayGuard::accept` enforces the per-sender message-id window
//!    and the timestamp tolerance around `now`.
//!
//! Opening runs before the signature check because the packet carries
//! no key of its own: the only sender key available at the recipient
//! is the one the seal itself authenticates.
//!
//! The seal binds `derive_msg_id(header, &[])` - the header's content
//! address with an empty payload - not the packet's `msg_id`, which
//! hashes the payload: the payload *is* the seal, so binding under
//! `msg_id` would need the hash of bytes the seal has not produced
//! yet. The sender-side recipe is documented in `docs/protocol.md`,
//! the decision in `docs/adr/0005-local-delivery-pipeline.md`.

use ao_idents::{
    IdentError, Identity, NodeId, ReplayGuard, SealedMessage, Signature, compute_node_id,
};

use crate::Header;
use crate::sign::{VerifyError, derive_msg_id, verify_origin};

/// Why a packet addressed to this node produced no delivery.
///
/// The engine maps every variant to one counted rejection on the link
/// the packet arrived on (`Neighbor::rejected_packets`); no variant
/// reaches the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeliverError {
    /// The payload is not a decodable, openable seal bound to this
    /// header: malformed, tampered, sealed to another recipient, or
    /// carrying a header edit the associated data refuses.
    Seal(IdentError),
    /// The seal opened, but its authenticated sender is not
    /// `header.origin`: the packet claims a sender it cannot prove.
    OriginMismatch,
    /// The origin signature failed, or the claimed `msg_id` is not
    /// what the header and payload derive.
    Verify(VerifyError),
    /// The replay guard refused the message: a replay, a timestamp
    /// outside its tolerance, or a full per-sender window.
    Replay(IdentError),
}

impl core::fmt::Display for DeliverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Seal(e) => write!(f, "seal refused the delivery: {e}"),
            Self::OriginMismatch => write!(f, "seal sender is not the claimed origin"),
            Self::Verify(e) => write!(f, "origin verification failed: {e}"),
            Self::Replay(e) => write!(f, "replay guard refused the message: {e}"),
        }
    }
}
impl std::error::Error for DeliverError {}

/// Opens and accepts one delivery candidate, or says why it is none.
///
/// Returns the opened plaintext. `header` stays as received, so its
/// `payload_len` counts the sealed wire payload rather than this
/// plaintext's length. `now` is unix milliseconds, as in
/// [`crate::MeshEngine::handle`].
pub(crate) fn open_delivery(
    identity: &Identity,
    guard: &mut ReplayGuard,
    now: u64,
    header: &Header,
    signature: &Signature,
    payload: &[u8],
) -> Result<Vec<u8>, DeliverError> {
    let sealed = SealedMessage::decode(payload).map_err(DeliverError::Seal)?;
    // The header's content address with an empty payload: both sides
    // derive it from the header alone, before any seal exists.
    let binding = derive_msg_id(header, &[]);
    let opened = sealed
        .open(identity, binding.as_bytes())
        .map_err(DeliverError::Seal)?;
    let origin = NodeId::from_bytes(header.origin);
    // The seal authenticates two public keys; the mesh id is derived
    // from them (the same derivation MSH-07's hello proves).
    let sender_id = compute_node_id(opened.sender().signing_pk(), opened.sender().agreement_pk());
    if sender_id != origin {
        return Err(DeliverError::OriginMismatch);
    }
    verify_origin(opened.sender(), header, payload, signature).map_err(DeliverError::Verify)?;
    guard
        .accept(origin, header.msg_id.as_bytes(), header.created_ms, now)
        .map_err(DeliverError::Replay)?;
    Ok(opened.plaintext().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MessageId;
    use crate::packet::PacketClass;
    use crate::sign::sign_packet;
    use ao_idents::ReplayConfig;
    use rand08::{SeedableRng, rngs::StdRng};

    const NOW: u64 = 100_000;

    /// The MSH-09 sender recipe as one call: a probe seal measures the
    /// sealed length (it does not depend on the associated data), the
    /// header claims that length, the real seal binds the header's
    /// content address, and signing stamps origin and `msg_id`.
    fn candidate(
        sender: &Identity,
        recipient: &Identity,
        dst: [u8; 16],
        created_ms: u64,
        plaintext: &[u8],
    ) -> (Header, Signature, Vec<u8>) {
        let mut rng = StdRng::seed_from_u64(0x5e_a1);
        let probe = SealedMessage::seal(sender, recipient.public(), &[0; 16], plaintext, &mut rng)
            .expect("fixed keys seal");
        let payload_len = probe.encode().len();
        let mut header = Header {
            class: PacketClass::Direct,
            dst: Some(dst),
            msg_id: [0; 16].into(),
            origin: *sender.node_id().as_bytes(),
            created_ms,
            lifetime_s: 600,
            payload_len: payload_len as u64,
            ttl: 8,
            hops: 0,
        };
        let binding = derive_msg_id(&header, &[]);
        let sealed = SealedMessage::seal(
            sender,
            recipient.public(),
            binding.as_bytes(),
            plaintext,
            &mut rng,
        )
        .expect("fixed keys seal");
        let payload = sealed.encode();
        debug_assert_eq!(payload.len(), payload_len);
        let signature = sign_packet(sender, &mut header, &payload).expect("fixed key signs");
        (header, signature, payload)
    }

    fn guard() -> ReplayGuard {
        ReplayGuard::new(ReplayConfig::new(8, 60_000, 4).expect("valid config"))
    }

    fn open(
        identity: &Identity,
        guard: &mut ReplayGuard,
        header: &Header,
        signature: &Signature,
        payload: &[u8],
    ) -> Result<Vec<u8>, DeliverError> {
        open_delivery(identity, guard, NOW, header, signature, payload)
    }

    fn identities() -> (Identity, Identity) {
        (Identity::from_seed([1; 32]), Identity::from_seed([3; 32]))
    }

    #[test]
    fn opens_an_honest_delivery_to_its_plaintext() {
        let (sender, me) = identities();
        let (header, signature, payload) =
            candidate(&sender, &me, *me.node_id().as_bytes(), NOW, b"hello");
        let mut guard = guard();
        assert_eq!(
            open(&me, &mut guard, &header, &signature, &payload).expect("honest packet opens"),
            b"hello"
        );
    }

    #[test]
    fn a_flipped_payload_byte_never_delivers() {
        let (sender, me) = identities();
        let (header, signature, mut payload) =
            candidate(&sender, &me, *me.node_id().as_bytes(), NOW, b"hello");
        let last = payload.len() - 1;
        payload[last] ^= 1;
        let mut guard = guard();
        let err = open(&me, &mut guard, &header, &signature, &payload)
            .expect_err("a flipped ciphertext byte cannot open");
        assert!(matches!(err, DeliverError::Seal(_)), "{err:?}");
    }

    #[test]
    fn a_seal_for_another_recipient_never_delivers() {
        // Misdirected: addressed here, but sealed to another node's
        // key, so the recipient binding in the associated data fails
        // even though the header's content address still matches.
        let (sender, me) = identities();
        let bob = Identity::from_seed([4; 32]);
        let (header, signature, payload) =
            candidate(&sender, &bob, *me.node_id().as_bytes(), NOW, b"hello");
        let mut guard = guard();
        let err = open(&me, &mut guard, &header, &signature, &payload)
            .expect_err("sealed to another recipient");
        assert!(matches!(err, DeliverError::Seal(_)), "{err:?}");
    }

    #[test]
    fn an_edited_header_never_delivers() {
        // The seal's associated data binds the header's content
        // address, so an edit made after sealing is refused before
        // any signature check runs.
        let (sender, me) = identities();
        let (mut header, signature, payload) =
            candidate(&sender, &me, *me.node_id().as_bytes(), NOW, b"hello");
        header.created_ms += 1;
        let mut guard = guard();
        let err = open(&me, &mut guard, &header, &signature, &payload)
            .expect_err("an edited header cannot open");
        assert!(matches!(err, DeliverError::Seal(_)), "{err:?}");
    }

    #[test]
    fn a_seal_whose_sender_is_not_the_claimed_origin_never_delivers() {
        // The forgery: Alice's honest header and signature, with the
        // payload swapped for a seal Mallory made under that header's
        // content address. The seal opens, then fails the origin
        // binding before Alice's signature is even consulted.
        let alice = Identity::from_seed([1; 32]);
        let mallory = Identity::from_seed([9; 32]);
        let me = Identity::from_seed([3; 32]);
        let (header, signature, _) = candidate(&alice, &me, *me.node_id().as_bytes(), NOW, b"real");
        let mut rng = StdRng::seed_from_u64(0x5e_a2);
        let binding = derive_msg_id(&header, &[]);
        let swapped =
            SealedMessage::seal(&mallory, me.public(), binding.as_bytes(), b"fake", &mut rng)
                .expect("fixed keys seal");
        let payload = swapped.encode();
        let mut guard = guard();
        let err = open(&me, &mut guard, &header, &signature, &payload)
            .expect_err("the authenticated sender must be the origin");
        assert_eq!(err, DeliverError::OriginMismatch);
    }

    #[test]
    fn a_broken_signature_never_delivers() {
        let (sender, me) = identities();
        let (header, signature, payload) =
            candidate(&sender, &me, *me.node_id().as_bytes(), NOW, b"hello");
        let mut bytes = *signature.as_bytes();
        bytes[0] ^= 1;
        let signature = Signature::from_bytes(bytes);
        let mut guard = guard();
        let err = open(&me, &mut guard, &header, &signature, &payload)
            .expect_err("a flipped signature byte cannot verify");
        assert_eq!(err, DeliverError::Verify(VerifyError::BadSignature));
    }

    #[test]
    fn a_claimed_msg_id_the_content_does_not_produce_never_delivers() {
        // Only `msg_id` changes: it sits inside the signed prefix but
        // is zeroed in the seal's binding, so the seal still opens
        // and the origin verification then refuses the claim.
        let (sender, me) = identities();
        let (mut header, signature, payload) =
            candidate(&sender, &me, *me.node_id().as_bytes(), NOW, b"hello");
        header.msg_id = MessageId::from_bytes([0xEE; 16]);
        let mut guard = guard();
        let err = open(&me, &mut guard, &header, &signature, &payload)
            .expect_err("a forged claim cannot verify");
        assert!(
            matches!(err, DeliverError::Verify(VerifyError::MsgIdMismatch { .. })),
            "{err:?}"
        );
    }

    #[test]
    fn a_replayed_message_is_refused_by_the_guard() {
        let (sender, me) = identities();
        let (header, signature, payload) =
            candidate(&sender, &me, *me.node_id().as_bytes(), NOW, b"hello");
        let mut guard = guard();
        open(&me, &mut guard, &header, &signature, &payload).expect("first acceptance");
        let err = open(&me, &mut guard, &header, &signature, &payload)
            .expect_err("the second acceptance is a replay");
        assert_eq!(err, DeliverError::Replay(IdentError::Replay));
    }

    #[test]
    fn a_message_outside_the_timestamp_tolerance_is_refused() {
        let (sender, me) = identities();
        let (header, signature, payload) =
            candidate(&sender, &me, *me.node_id().as_bytes(), NOW, b"hello");
        // The guard built here tolerates 60 s, in both directions.
        for now in [NOW - 60_001, NOW + 60_001] {
            let mut guard = guard();
            let err = open_delivery(&me, &mut guard, now, &header, &signature, &payload)
                .expect_err("outside the tolerance");
            assert_eq!(
                err,
                DeliverError::Replay(IdentError::StaleTimestamp),
                "now {now}"
            );
        }
    }

    #[test]
    fn a_full_per_sender_window_is_refused() {
        let (sender, me) = identities();
        let config = ReplayConfig::new(1, 60_000, 4).expect("valid config");
        let mut guard = ReplayGuard::new(config);
        let (first_h, first_s, first_p) =
            candidate(&sender, &me, *me.node_id().as_bytes(), NOW, b"one");
        open_delivery(&me, &mut guard, NOW, &first_h, &first_s, &first_p).expect("first message");
        let (second_h, second_s, second_p) =
            candidate(&sender, &me, *me.node_id().as_bytes(), NOW, b"two");
        let err = open_delivery(&me, &mut guard, NOW, &second_h, &second_s, &second_p)
            .expect_err("the window holds one message");
        assert_eq!(err, DeliverError::Replay(IdentError::GuardFull));
    }
}
