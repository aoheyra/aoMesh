//! Origin signatures and `msg_id` derivation (MSH-04).
//!
//! The origin signs the **immutable prefix** — the exact bytes
//! [`crate::packet`] documents — under a domain registered in aoIdents
//! ADR-0001, so a relay authenticates the header without touching `ttl`,
//! `hops` or the payload. `msg_id` derives from the same prefix (with its
//! own field hashed as zeroes) plus the payload hash: a content address, so
//! two different messages can never collide on one dedup key (MSH-05).
//!
//! Verification re-encodes the parsed header instead of slicing raw bytes:
//! [`crate::packet`] rejects non-canonical input, so a decoded header
//! re-encodes to the exact bytes that were received.

use ao_idents::{IdentError, Identity, PublicIdentity, Signature, verify_signing_pk};

use crate::packet::{Header, MAX_IMMUTABLE_LEN, MSG_ID_LEN, MSG_ID_OFFSET, MessageId, PacketClass};

/// Signature domain for the origin signature over the immutable prefix.
/// Registered in aoIdents ADR-0001; a signature made under any other
/// string fails verification here.
const SIGN_DOMAIN: &str = "aoheyra/mesh/v1/packet";

/// Domain for every hash that feeds `msg_id`. Registered in aoIdents
/// ADR-0001; the tag byte below separates its two uses.
const MSG_ID_DOMAIN: &str = "aoheyra/mesh/v1/msg-id";

/// Tag byte: the hash is of the payload alone.
const PAYLOAD_HASH_TAG: u8 = 0x01;
/// Tag byte: the hash is of the prefix plus the payload hash.
const MSG_ID_TAG: u8 = 0x02;

/// Derives the message ID from the immutable header and the payload hash.
///
/// The `msg_id` field is inside the prefix, so it cannot be its own input:
/// it is hashed as zeroes. Every other prefix field participates, and
/// `ttl`/`hops` do not (they sit outside the prefix), so a relay's hop
/// decrement never changes a message's identity. `payload` is hashed as
/// given; [`crate::packet::Packet::new`] enforces that it matches
/// `header.payload_len`, so a packet that cannot be built cannot derive an
/// ID either.
pub fn derive_msg_id(header: &Header, payload: &[u8]) -> MessageId {
    derive_msg_id_from_hash(header, &payload_hash(payload))
}

/// Hashes a payload with the one domain/tag pair used by [`derive_msg_id`].
pub(crate) fn payload_hash(payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MSG_ID_DOMAIN.as_bytes());
    hasher.update(&[PAYLOAD_HASH_TAG]);
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut out = [0; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

/// Derives a `MessageId` when the payload hash is already known.
///
/// Receipts carry the original header and payload hash instead of the whole
/// payload, so relays can re-derive the acknowledged id without retaining
/// application bytes. This is the same single derivation as
/// [`derive_msg_id`], not a second hashing policy.
pub(crate) fn derive_msg_id_from_hash(header: &Header, payload_hash: &[u8]) -> MessageId {
    debug_assert_eq!(payload_hash.len(), blake3::OUT_LEN);
    let mut prefix = [0u8; MAX_IMMUTABLE_LEN];
    let n = header.encode_immutable_into(&mut prefix);
    prefix[MSG_ID_OFFSET..MSG_ID_OFFSET + MSG_ID_LEN].fill(0);

    let mut hasher = blake3::Hasher::new();
    hasher.update(MSG_ID_DOMAIN.as_bytes());
    hasher.update(&[MSG_ID_TAG]);
    hasher.update(&prefix[..n]);
    hasher.update(payload_hash);
    let hash = hasher.finalize();
    let mut id = [0u8; MSG_ID_LEN];
    id.copy_from_slice(&hash.as_bytes()[..MSG_ID_LEN]);
    MessageId::from_bytes(id)
}

/// Sets `header.origin` to the identity's `NodeId`, derives `header.msg_id`,
/// and signs the resulting immutable prefix under `aoheyra/mesh/v1/packet`.
///
/// The caller then builds the packet with [`crate::packet::Packet::new`],
/// which enforces the payload-length agreement. Order matters: derivation
/// hashes the prefix with `msg_id` as zeroes, the signature covers it
/// populated, so the signature binds the very ID the content derives to.
pub fn sign_packet(
    identity: &Identity,
    header: &mut Header,
    payload: &[u8],
) -> Result<Signature, IdentError> {
    // The origin is this identity's own NodeId: a relay resolves `origin`
    // to a key before verifying, so any other value would fail there
    // anyway. Set it here rather than trust the caller.
    header.origin = *identity.node_id().as_bytes();
    header.msg_id = derive_msg_id(header, payload);
    let mut prefix = [0u8; MAX_IMMUTABLE_LEN];
    let n = header.encode_immutable_into(&mut prefix);
    identity.sign(SIGN_DOMAIN, &prefix[..n])
}

/// Why a packet failed origin verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// aoIdents rejected the signature: a different key, a tampered
    /// prefix, or a signature made under another domain. With the
    /// registered domain the identity layer reports only
    /// `InvalidSignature` or `InvalidPublicKey`; both mean this packet
    /// cannot be authenticated under the key its origin resolved to, so
    /// both map here and the packet is dropped.
    BadSignature,
    /// `header.msg_id` is not the derivation for this header and payload:
    /// the sender claimed a dedup key the content does not produce.
    MsgIdMismatch {
        /// What the header and payload derive to.
        expected: MessageId,
        /// What the header claims.
        found: MessageId,
    },
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadSignature => write!(f, "origin signature does not verify"),
            Self::MsgIdMismatch { expected, found } => {
                write!(f, "msg_id {found} does not match derived {expected}")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verifies the `msg_id` derivation and the origin signature.
///
/// `origin_pk` must be the key belonging to `header.origin`: resolving a
/// `NodeId` to a key is the engine's peer table, and aoMesh never derives
/// identity material itself (AGENTS section 3).
///
/// The derivation check runs first: a hash is cheaper than Ed25519, and a
/// mismatch is a rejected packet either way.
pub fn verify_origin(
    origin_pk: &PublicIdentity,
    header: &Header,
    payload: &[u8],
    signature: &Signature,
) -> Result<(), VerifyError> {
    check_msg_id(header, payload)?;
    let mut prefix = [0u8; MAX_IMMUTABLE_LEN];
    let n = header.encode_immutable_into(&mut prefix);
    origin_pk
        .verify(SIGN_DOMAIN, &prefix[..n], signature)
        .map_err(|_| VerifyError::BadSignature)
}

/// Verifies a packet when only the origin's signing key is available.
///
/// MSH-07's signed `MeshHello` carries that key, so a recipient can
/// authenticate a signed Broadcast such as an MSH-23 public-channel message
/// without the agreement key or an identity-card lookup. The derivation and
/// domain are byte-for-byte the ones [`verify_origin`] uses; only the key
/// representation differs. This is not a new signature scheme.
pub fn verify_origin_with_signing_pk(
    signing_pk: &[u8; 32],
    header: &Header,
    payload: &[u8],
    signature: &Signature,
) -> Result<(), VerifyError> {
    check_msg_id(header, payload)?;
    let mut prefix = [0u8; MAX_IMMUTABLE_LEN];
    let n = header.encode_immutable_into(&mut prefix);
    verify_signing_pk(signing_pk, SIGN_DOMAIN, &prefix[..n], signature)
        .map_err(|_| VerifyError::BadSignature)
}

fn check_msg_id(header: &Header, payload: &[u8]) -> Result<(), VerifyError> {
    let expected = derive_msg_id(header, payload);
    if header.msg_id != expected {
        return Err(VerifyError::MsgIdMismatch {
            expected,
            found: header.msg_id,
        });
    }
    Ok(())
}

/// What a relay does with a packet's signature check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayOutcome {
    /// The `msg_id` derivation and the signature were checked and are
    /// valid; forward.
    Verified,
    /// Not checked, under the class policy or an exhausted Direct budget;
    /// forward as received. The recipient still verifies.
    Skipped,
}

/// Verifies a packet a relay is about to forward, under the class policy:
/// Broadcast and Presence always, Direct only while `direct_budget_left`
/// allows it, Telemetry never (MSH-04's scope names Broadcast, Presence
/// and Direct; telemetry is latest-wins and its recipient verifies).
///
/// An error means the relay drops the packet; [`RelayOutcome::Skipped`]
/// does not. A caller that forwards Direct packets under budget decrements
/// its own counter once per `Verified` result.
pub fn verify_for_relay(
    class: PacketClass,
    direct_budget_left: u32,
    origin_pk: &PublicIdentity,
    header: &Header,
    payload: &[u8],
    signature: &Signature,
) -> Result<RelayOutcome, VerifyError> {
    let check = match class {
        PacketClass::Broadcast | PacketClass::Presence => true,
        PacketClass::Direct => direct_budget_left > 0,
        PacketClass::Telemetry => false,
    };
    if !check {
        return Ok(RelayOutcome::Skipped);
    }
    verify_origin(origin_pk, header, payload, signature)?;
    Ok(RelayOutcome::Verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{NODE_ID_LEN, Packet, SIGNATURE_LEN};

    fn identity(seed: u8) -> Identity {
        Identity::from_seed([seed; 32])
    }

    fn header_for(class: PacketClass, origin: [u8; NODE_ID_LEN]) -> Header {
        Header {
            class,
            dst: None,
            msg_id: [0u8; MSG_ID_LEN].into(),
            origin,
            created_ms: 1_700_000_000_000,
            lifetime_s: 3_600,
            payload_len: 4,
            ttl: 8,
            hops: 0,
        }
    }

    /// Signs `header` under `origin_id`, as an honest sender would, and
    /// returns the wire bytes.
    fn signed_bytes(origin_id: &Identity, class: PacketClass, payload: &[u8]) -> Vec<u8> {
        let mut header = header_for(class, [0; NODE_ID_LEN]);
        // `header_for` defaults to a four-byte "ping". An honest sender
        // declares the length of the payload it actually signs and sends;
        // some callers here use longer payloads.
        header.payload_len = u64::try_from(payload.len()).expect("test payload fits");
        let signature = sign_packet(origin_id, &mut header, payload).expect("sign");
        Packet::new(header, signature, payload)
            .expect("lengths agree")
            .encode()
    }

    #[test]
    fn sign_packet_sets_origin_and_derives_msg_id() {
        let id = identity(1);
        let mut header = header_for(PacketClass::Broadcast, [9; NODE_ID_LEN]);
        let signature = sign_packet(&id, &mut header, b"ping").expect("sign");
        assert_eq!(header.origin, *id.node_id().as_bytes());
        assert_eq!(header.msg_id, derive_msg_id(&header, b"ping"));
        // The signature verifies under this identity's public key.
        let mut prefix = [0u8; MAX_IMMUTABLE_LEN];
        let n = header.encode_immutable_into(&mut prefix);
        id.public()
            .verify(SIGN_DOMAIN, &prefix[..n], &signature)
            .expect("valid signature");
    }

    #[test]
    fn wire_round_trip_verifies() {
        let id = identity(2);
        let bytes = signed_bytes(&id, PacketClass::Broadcast, b"ping");
        let packet = Packet::decode(&bytes).expect("decodes");
        verify_origin(
            id.public(),
            &packet.header,
            packet.payload,
            &packet.signature,
        )
        .expect("honest packet verifies");
    }

    #[test]
    fn signing_key_only_verification_uses_the_same_domain() {
        let id = identity(11);
        let bytes = signed_bytes(&id, PacketClass::Broadcast, b"channel");
        let packet = Packet::decode(&bytes).expect("decodes");
        verify_origin_with_signing_pk(
            id.public().signing_pk(),
            &packet.header,
            packet.payload,
            &packet.signature,
        )
        .expect("hello-carried key verifies");
        let other = identity(12);
        assert_eq!(
            verify_origin_with_signing_pk(
                other.public().signing_pk(),
                &packet.header,
                packet.payload,
                &packet.signature,
            ),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn changed_ttl_does_not_break_verification() {
        let id = identity(3);
        let bytes = signed_bytes(&id, PacketClass::Broadcast, b"ping");
        let mut packet = Packet::decode(&bytes).expect("decodes");
        // What a relay does before forwarding.
        packet.header.ttl -= 1;
        packet.header.hops += 1;
        verify_origin(
            id.public(),
            &packet.header,
            packet.payload,
            &packet.signature,
        )
        .expect("hop fields are outside the signed prefix");
        // And the msg_id survives the hop unchanged: same derivation.
        assert_eq!(packet.header.msg_id, derive_msg_id(&packet.header, b"ping"));
    }

    #[test]
    fn forged_origin_is_dropped_by_relay_for_broadcast() {
        let victim = identity(4);
        let attacker = identity(5);
        // The attacker claims the victim's origin but can only sign under
        // their own key: sign_packet stamps its own NodeId, so forge the
        // way an off-API attacker would — sign the prefix manually.
        let mut header = header_for(PacketClass::Broadcast, *victim.node_id().as_bytes());
        header.msg_id = derive_msg_id(&header, b"ping");
        let mut prefix = [0u8; MAX_IMMUTABLE_LEN];
        let n = header.encode_immutable_into(&mut prefix);
        let forged = attacker.sign(SIGN_DOMAIN, &prefix[..n]).expect("sign");

        let outcome = verify_for_relay(
            PacketClass::Broadcast,
            5,
            victim.public(),
            &header,
            b"ping",
            &forged,
        );
        assert_eq!(outcome, Err(VerifyError::BadSignature));
        // The victim's own signature verifies, for contrast.
        let honest = sign_packet(&victim, &mut header, b"ping").expect("sign");
        assert_eq!(
            verify_for_relay(
                PacketClass::Broadcast,
                5,
                victim.public(),
                &header,
                b"ping",
                &honest,
            ),
            Ok(RelayOutcome::Verified)
        );
    }

    #[test]
    fn relay_class_policy_is_exercised() {
        let id = identity(6);
        let mut header = header_for(PacketClass::Direct, [0; NODE_ID_LEN]);
        let signature = sign_packet(&id, &mut header, b"ping").expect("sign");
        let mut forged_header = header;
        forged_header.origin = [7; NODE_ID_LEN];
        // The forger re-derives the ID for the stolen origin; only the
        // signature can stop them now.
        forged_header.msg_id = derive_msg_id(&forged_header, b"ping");
        let forged = Signature::from_bytes([0xEE; SIGNATURE_LEN]);

        // Direct with an exhausted budget: skipped, even a forged packet,
        // because the check does not run at all.
        assert_eq!(
            verify_for_relay(
                PacketClass::Direct,
                0,
                id.public(),
                &forged_header,
                b"ping",
                &forged
            ),
            Ok(RelayOutcome::Skipped)
        );
        // Direct with budget: checked, forgery dropped.
        assert_eq!(
            verify_for_relay(
                PacketClass::Direct,
                1,
                id.public(),
                &forged_header,
                b"ping",
                &forged
            ),
            Err(VerifyError::BadSignature)
        );
        // Direct with budget, honest: verified.
        assert_eq!(
            verify_for_relay(
                PacketClass::Direct,
                1,
                id.public(),
                &header,
                b"ping",
                &signature
            ),
            Ok(RelayOutcome::Verified)
        );
        // Presence is always checked; a forged Presence packet is dropped.
        let mut presence = header;
        presence.class = PacketClass::Presence;
        let mut presence_forged = presence;
        presence_forged.origin = [7; NODE_ID_LEN];
        presence_forged.msg_id = derive_msg_id(&presence_forged, b"ping");
        assert_eq!(
            verify_for_relay(
                PacketClass::Presence,
                0,
                id.public(),
                &presence_forged,
                b"ping",
                &forged
            ),
            Err(VerifyError::BadSignature)
        );
        // Telemetry is outside the relay-verification set: skipped.
        let mut telemetry = header;
        telemetry.class = PacketClass::Telemetry;
        assert_eq!(
            verify_for_relay(
                PacketClass::Telemetry,
                9,
                id.public(),
                &telemetry,
                b"ping",
                &forged
            ),
            Ok(RelayOutcome::Skipped)
        );
    }

    #[test]
    fn msg_id_mismatch_is_rejected_before_the_signature() {
        let id = identity(7);
        let mut header = header_for(PacketClass::Broadcast, [0; NODE_ID_LEN]);
        let signature = sign_packet(&id, &mut header, b"ping").expect("sign");
        let claimed = MessageId::from_bytes([0xEE; MSG_ID_LEN]);
        header.msg_id = claimed;
        let err = verify_origin(id.public(), &header, b"ping", &signature)
            .expect_err("claimed id is not the derivation");
        assert_eq!(
            err,
            VerifyError::MsgIdMismatch {
                expected: derive_msg_id(&header, b"ping"),
                found: claimed,
            }
        );
        // The claimed ID is preserved in the error for logging.
        match err {
            VerifyError::MsgIdMismatch { found, .. } => assert_eq!(found, claimed),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn signature_under_another_domain_is_rejected() {
        let id = identity(8);
        let mut header = header_for(PacketClass::Broadcast, [0; NODE_ID_LEN]);
        header.msg_id = derive_msg_id(&header, b"ping");
        let mut prefix = [0u8; MAX_IMMUTABLE_LEN];
        let n = header.encode_immutable_into(&mut prefix);
        // Same key, different context: IDN-04's separation must bite.
        let wrong_domain = id
            .sign("aoheyra/idn/v1/example", &prefix[..n])
            .expect("sign");
        assert_eq!(
            verify_origin(id.public(), &header, b"ping", &wrong_domain),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn tampered_prefix_is_rejected() {
        let id = identity(9);
        let mut header = header_for(PacketClass::Broadcast, [0; NODE_ID_LEN]);
        let signature = sign_packet(&id, &mut header, b"ping").expect("sign");
        header.created_ms += 1;
        // The forger re-derives the ID for the altered header; only the
        // signature can stop them now.
        header.msg_id = derive_msg_id(&header, b"ping");
        assert_eq!(
            verify_origin(id.public(), &header, b"ping", &signature),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn msg_id_is_a_content_address() {
        let base = header_for(PacketClass::Broadcast, [1; NODE_ID_LEN]);
        let id_of_base = derive_msg_id(&base, b"ping");
        // Deterministic.
        assert_eq!(derive_msg_id(&base, b"ping"), id_of_base);
        // The payload participates.
        assert_ne!(derive_msg_id(&base, b"pong"), id_of_base);
        // Every immutable field participates.
        let mut other = base;
        other.created_ms += 1;
        assert_ne!(derive_msg_id(&other, b"ping"), id_of_base);
        let mut other = base;
        other.origin = [2; NODE_ID_LEN];
        assert_ne!(derive_msg_id(&other, b"ping"), id_of_base);
        let mut other = base;
        other.dst = Some([3; NODE_ID_LEN]);
        assert_ne!(derive_msg_id(&other, b"ping"), id_of_base);
        // The hop fields do not: relays must not change a message's ID.
        let mut other = base;
        other.ttl -= 1;
        other.hops += 1;
        assert_eq!(derive_msg_id(&other, b"ping"), id_of_base);
        // Neither does the msg_id field itself: it is hashed as zeroes.
        let mut other = base;
        other.msg_id = MessageId::from_bytes([0xAB; MSG_ID_LEN]);
        assert_eq!(derive_msg_id(&other, b"ping"), id_of_base);
    }

    #[test]
    fn verify_error_display_is_informative() {
        let errors = [
            VerifyError::BadSignature,
            VerifyError::MsgIdMismatch {
                expected: MessageId::from_bytes([1; MSG_ID_LEN]),
                found: MessageId::from_bytes([2; MSG_ID_LEN]),
            },
        ];
        for err in errors {
            assert!(!format!("{err}").is_empty());
        }
    }
}
