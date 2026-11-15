//! Property tests for the packet codec (MSH-03): round-trips, truncation
//! and never-panic on hostile bytes.

use ao_mesh::packet::{Header, MAX_PAYLOAD, MSG_ID_LEN, NODE_ID_LEN, Packet, PacketClass};
use proptest::collection::vec;
use proptest::prelude::*;

fn arb_class() -> impl Strategy<Value = PacketClass> {
    prop_oneof![
        Just(PacketClass::Direct),
        Just(PacketClass::Broadcast),
        Just(PacketClass::Presence),
        Just(PacketClass::Telemetry),
    ]
}

fn arb_header(payload_len: u64) -> impl Strategy<Value = Header> {
    (
        arb_class(),
        any::<[u8; MSG_ID_LEN]>(),
        any::<[u8; NODE_ID_LEN]>(),
        prop::option::of(any::<[u8; NODE_ID_LEN]>()),
        any::<u64>(),
        any::<u64>(),
        any::<u8>(),
        any::<u8>(),
    )
        .prop_map(
            move |(class, msg_id, origin, dst, created_ms, lifetime_s, ttl, hops)| Header {
                class,
                dst,
                msg_id,
                origin,
                created_ms,
                lifetime_s,
                payload_len,
                ttl,
                hops,
            },
        )
}

fn arb_any_header() -> impl Strategy<Value = Header> {
    (0u64..=MAX_PAYLOAD as u64).prop_flat_map(arb_header)
}

fn arb_packet() -> impl Strategy<Value = (Header, Vec<u8>)> {
    (0usize..=MAX_PAYLOAD).prop_flat_map(|len| (arb_header(len as u64), vec(any::<u8>(), len)))
}

proptest! {
    #[test]
    fn headers_round_trip(header in arb_any_header()) {
        let bytes = header.encode();
        let parsed = Header::decode(&bytes).expect("an encoded header always parses");
        prop_assert_eq!(parsed, header);
    }

    #[test]
    fn packets_round_trip((header, payload) in arb_packet()) {
        let packet = Packet::new(header, &payload).expect("payload_len matches by construction");
        let bytes = packet.encode();
        let decoded = Packet::decode(&bytes).expect("an encoded packet always parses");
        prop_assert_eq!(decoded.header, header);
        prop_assert_eq!(decoded.payload, payload.as_slice());
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in vec(any::<u8>(), 0..4096)) {
        let _header = Header::decode(&bytes);
        let _packet = Packet::decode(&bytes);
    }

    #[test]
    fn truncated_packets_are_rejected((header, payload) in arb_packet()) {
        let bytes = Packet::new(header, &payload).expect("payload_len matches by construction")
            .encode();
        for cut in 0..bytes.len() {
            prop_assert!(
                Packet::decode(&bytes[..cut]).is_err(),
                "prefix of {cut} of {} bytes parsed",
                bytes.len()
            );
        }
    }

    #[test]
    fn header_only_view_matches_the_packets_header((header, payload) in arb_packet()) {
        let bytes = Packet::new(header, &payload).expect("payload_len matches by construction")
            .encode();
        let view = Header::decode(&bytes).expect("the header parses first");
        prop_assert_eq!(view, header);
    }
}
