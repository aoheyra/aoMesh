//! Integration tests for origin signatures and `msg_id` derivation
//! (MSH-04): the done-when scenarios through the public API only.

use ao_idents::{Identity, Signature};
use ao_mesh::packet::{Header, MSG_ID_LEN, MessageId, NODE_ID_LEN, Packet, PacketClass};
use ao_mesh::sign::{
    RelayOutcome, VerifyError, derive_msg_id, sign_packet, verify_for_relay, verify_origin,
};

fn identity(seed: u8) -> Identity {
    Identity::from_seed([seed; 32])
}

fn header_for(class: PacketClass) -> Header {
    Header {
        class,
        dst: None,
        msg_id: [0u8; MSG_ID_LEN].into(),
        origin: [0u8; NODE_ID_LEN],
        created_ms: 1_700_000_000_000,
        lifetime_s: 3_600,
        payload_len: 4,
        ttl: 8,
        hops: 0,
    }
}

/// Signs and encodes an honest packet, as a sender would.
fn signed_packet(id: &Identity, class: PacketClass, payload: &[u8]) -> Vec<u8> {
    let mut header = header_for(class);
    let signature = sign_packet(id, &mut header, payload).expect("sign");
    Packet::new(header, signature, payload)
        .expect("lengths agree")
        .encode()
}

#[test]
fn honest_packet_verifies_at_the_recipient() {
    let id = identity(1);
    let bytes = signed_packet(&id, PacketClass::Direct, b"ping");
    let packet = Packet::decode(&bytes).expect("decodes");
    assert_eq!(packet.header.origin, *id.node_id().as_bytes());
    verify_origin(
        id.public(),
        &packet.header,
        packet.payload,
        &packet.signature,
    )
    .expect("recipient accepts its own send");
}

#[test]
fn forged_origin_is_dropped_by_relays_for_broadcast() {
    let victim = identity(2);
    let attacker = identity(3);
    // The attacker sends a packet claiming the victim's origin, signed
    // under the attacker's own key: decode an honest attacker packet and
    // swap the origin, the way a modified client would.
    let attacker_bytes = signed_packet(&attacker, PacketClass::Broadcast, b"ping");
    let mut packet = Packet::decode(&attacker_bytes).expect("decodes");
    packet.header.origin = *victim.node_id().as_bytes();

    // Without touching msg_id, the swap already fails: the derivation
    // covers the origin.
    assert!(matches!(
        verify_for_relay(
            PacketClass::Broadcast,
            3,
            victim.public(),
            &packet.header,
            packet.payload,
            &packet.signature,
        ),
        Err(VerifyError::MsgIdMismatch { .. })
    ));

    // The forger's best effort: derive_msg_id is public, so re-derive the
    // ID for the stolen origin. The derivation now passes and only the
    // signature stands between the forgery and the relay.
    packet.header.msg_id = derive_msg_id(&packet.header, packet.payload);
    let outcome = verify_for_relay(
        PacketClass::Broadcast,
        3,
        victim.public(),
        &packet.header,
        packet.payload,
        &packet.signature,
    );
    assert_eq!(outcome, Err(VerifyError::BadSignature));

    // The honest packet from the same identity passes the same relay.
    let honest_bytes = signed_packet(&victim, PacketClass::Broadcast, b"ping");
    let honest = Packet::decode(&honest_bytes).expect("decodes");
    assert_eq!(
        verify_for_relay(
            PacketClass::Broadcast,
            3,
            victim.public(),
            &honest.header,
            honest.payload,
            &honest.signature,
        ),
        Ok(RelayOutcome::Verified)
    );
}

#[test]
fn changed_ttl_does_not_break_verification() {
    let id = identity(4);
    let bytes = signed_packet(&id, PacketClass::Broadcast, b"ping");
    let mut packet = Packet::decode(&bytes).expect("decodes");
    let signed_id = packet.header.msg_id;

    // Relay-style hop: ttl down, hops up, then verify as the next relay
    // would with the same key material.
    packet.header.ttl -= 1;
    packet.header.hops += 1;
    verify_origin(
        id.public(),
        &packet.header,
        packet.payload,
        &packet.signature,
    )
    .expect("hop fields are outside the signed prefix");
    // The message keeps its identity across the hop.
    assert_eq!(packet.header.msg_id, signed_id);
    assert_eq!(
        packet.header.msg_id,
        derive_msg_id(&packet.header, packet.payload)
    );
}

#[test]
fn changed_prefix_field_breaks_verification() {
    let id = identity(5);
    let bytes = signed_packet(&id, PacketClass::Broadcast, b"ping");
    let mut packet = Packet::decode(&bytes).expect("decodes");
    // Inside the signed range: any change must fail. The forger can
    // re-derive msg_id for the altered header (derive_msg_id is public),
    // so the rejection below is the signature's, not the derivation's.
    packet.header.created_ms += 1;
    packet.header.msg_id = derive_msg_id(&packet.header, packet.payload);
    assert_eq!(
        verify_origin(
            id.public(),
            &packet.header,
            packet.payload,
            &packet.signature,
        ),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn relay_policy_follows_the_class_and_the_budget() {
    let id = identity(6);
    let honest_bytes = signed_packet(&id, PacketClass::Broadcast, b"ping");
    let honest = Packet::decode(&honest_bytes).expect("decodes");
    let attacker_bytes = signed_packet(&identity(7), PacketClass::Broadcast, b"ping");
    let forged = {
        let mut packet = Packet::decode(&attacker_bytes).expect("decodes");
        packet.header.origin = *id.node_id().as_bytes();
        // Re-derive for the stolen origin, so the signature is what the
        // relay's rejection sees.
        packet.header.msg_id = derive_msg_id(&packet.header, packet.payload);
        packet
    };

    // Broadcast: always checked, forged dropped, honest verified.
    assert_eq!(
        verify_for_relay(
            PacketClass::Broadcast,
            0,
            id.public(),
            &forged.header,
            forged.payload,
            &forged.signature,
        ),
        Err(VerifyError::BadSignature)
    );
    assert_eq!(
        verify_for_relay(
            PacketClass::Broadcast,
            0,
            id.public(),
            &honest.header,
            honest.payload,
            &honest.signature,
        ),
        Ok(RelayOutcome::Verified)
    );

    // Presence: same, regardless of budget.
    assert_eq!(
        verify_for_relay(
            PacketClass::Presence,
            0,
            id.public(),
            &forged.header,
            forged.payload,
            &forged.signature,
        ),
        Err(VerifyError::BadSignature)
    );

    // Direct: skipped while the budget is exhausted (even a forged packet
    // is forwarded, unverified, because the check does not run), checked
    // and dropped once budget exists.
    assert_eq!(
        verify_for_relay(
            PacketClass::Direct,
            0,
            id.public(),
            &forged.header,
            forged.payload,
            &forged.signature,
        ),
        Ok(RelayOutcome::Skipped)
    );
    assert_eq!(
        verify_for_relay(
            PacketClass::Direct,
            1,
            id.public(),
            &forged.header,
            forged.payload,
            &forged.signature,
        ),
        Err(VerifyError::BadSignature)
    );

    // Telemetry: outside the relay-verification set.
    assert_eq!(
        verify_for_relay(
            PacketClass::Telemetry,
            9,
            id.public(),
            &forged.header,
            forged.payload,
            &forged.signature,
        ),
        Ok(RelayOutcome::Skipped)
    );
}

#[test]
fn msg_id_is_stable_and_content_addressed() {
    let id = identity(8);
    let bytes = signed_packet(&id, PacketClass::Broadcast, b"ping");
    let packet = Packet::decode(&bytes).expect("decodes");

    // What the sender derived is what anyone re-derives.
    assert_eq!(
        packet.header.msg_id,
        derive_msg_id(&packet.header, packet.payload)
    );
    // A different payload is a different message.
    assert_ne!(packet.header.msg_id, derive_msg_id(&packet.header, b"pong"));
    // And the newtype keeps it from being mistaken for the origin field.
    let id_bytes: [u8; MSG_ID_LEN] = *packet.header.msg_id.as_bytes();
    assert_ne!(id_bytes[..], packet.header.origin[..]);
}

#[test]
fn tampered_msg_id_is_rejected() {
    let id = identity(9);
    let bytes = signed_packet(&id, PacketClass::Broadcast, b"ping");
    let mut packet = Packet::decode(&bytes).expect("decodes");
    let honest: [u8; MSG_ID_LEN] = *packet.header.msg_id.as_bytes();
    let mut forged_id = honest;
    forged_id[0] ^= 0xFF;
    packet.header.msg_id = MessageId::from_bytes(forged_id);

    let err = verify_origin(
        id.public(),
        &packet.header,
        packet.payload,
        &packet.signature,
    )
    .expect_err("claimed id is not the derivation");
    assert!(matches!(err, VerifyError::MsgIdMismatch { .. }));
}

#[test]
fn signature_bytes_survive_the_wire() {
    let id = identity(10);
    let mut header = header_for(PacketClass::Direct);
    let signature = sign_packet(&id, &mut header, b"ping").expect("sign");
    let packet = Packet::new(header, signature, b"ping")
        .expect("lengths agree")
        .encode();
    let decoded = Packet::decode(&packet).expect("decodes");
    assert_eq!(decoded.signature, signature);
    // Signature bytes are the raw Ed25519 encoding,64 of them.
    assert_eq!(decoded.signature.as_bytes().len(), 64);
    let _round_trip = Signature::from_bytes(*decoded.signature.as_bytes());
}
