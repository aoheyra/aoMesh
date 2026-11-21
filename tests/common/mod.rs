//! The MSH-09 sender recipe shared by the integration tests: a packet
//! whose payload is the plaintext sealed to its recipient, bound to the
//! header's content address before signing.
//!
//! Only deterministic test scaffolding lives here - never production
//! randomness. Each `tests/*.rs` file opts in with `mod common;`.
#![allow(dead_code)] // every test binary uses a different subset

use ao_idents::{Identity, SealedMessage};
use ao_mesh::{Header, Packet, PacketClass, derive_msg_id, sign_packet};
use rand08::{SeedableRng, rngs::StdRng};

/// The header and sealed payload of one delivery candidate, before
/// signing: exactly what `MeshInput::Submit` needs, and what [`sealed`]
/// signs into a wire packet.
///
/// The probe seal measures the sealed length (it does not depend on
/// the associated data), the header claims that length with the
/// sender's origin already in place, the real seal binds
/// `derive_msg_id(&header, &[])`, and the caller's signing stamps
/// origin and `msg_id` over those same values.
pub fn seal_for(
    sender: &Identity,
    recipient: &Identity,
    created_ms: u64,
    class: PacketClass,
    mutate: impl FnOnce(&mut Header),
    plaintext: &[u8],
) -> (Header, Vec<u8>) {
    let mut rng = StdRng::seed_from_u64(0x5e_a1);
    let probe = SealedMessage::seal(sender, recipient.public(), &[0; 16], plaintext, &mut rng)
        .expect("fixed keys seal");
    let payload_len = probe.encode().len();
    let mut header = Header {
        class,
        dst: Some(*recipient.node_id().as_bytes()),
        msg_id: [0; 16].into(),
        origin: *sender.node_id().as_bytes(),
        created_ms,
        lifetime_s: 3_600,
        payload_len: payload_len as u64,
        ttl: 8,
        hops: 0,
    };
    mutate(&mut header);
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
    (header, payload)
}

/// One encoded packet addressed to `recipient`: [`seal_for`] plus the
/// origin signature, byte for byte what a signed submission puts on
/// the wire.
pub fn sealed(
    sender: &Identity,
    recipient: &Identity,
    created_ms: u64,
    class: PacketClass,
    mutate: impl FnOnce(&mut Header),
    plaintext: &[u8],
) -> Vec<u8> {
    let (mut header, payload) = seal_for(sender, recipient, created_ms, class, mutate, plaintext);
    let signature = sign_packet(sender, &mut header, &payload).expect("fixed key signs");
    Packet::new(header, signature, &payload)
        .expect("lengths agree")
        .encode()
}
