#![no_main]

//! MSH-28 packet codec target: arbitrary bytes must never panic or allocate
//! on the header-first, borrow-only decode path.

use std::hint::black_box;

use ao_mesh::{Header, Packet, derive_msg_id};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // No unwrap/expect: malformed input is the input, not a setup error.
    let _ = black_box(Header::decode(data));

    if let Ok(packet) = Packet::decode(data) {
        // A decoded packet is canonical: re-encoding and content-id derivation
        // exercise the paths that would turn a codec invariant break into a
        // crash. No assertion is needed for a panic to reach libFuzzer.
        let _ = black_box(packet.encode());
        let _ = black_box(derive_msg_id(&packet.header, packet.payload));
        let _ = black_box(Packet::new(packet.header, packet.signature, packet.payload).is_ok());
    }
});
