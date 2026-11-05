use ao_mesh::packet::{
    Header, HopHeader, ImmutableHeader, MAX_HEADER_LEN, PacketClass, PacketView, encode,
    parse_header,
};
use proptest::{
    prelude::*,
    test_runner::{Config, MapFailurePersistence, RngSeed},
};

fn config() -> Config {
    let mut config = Config::with_cases(256);
    config.rng_seed = RngSeed::Fixed(0xA003_0001);
    // In-memory persistence keeps these same deterministic cases usable in Miri.
    config.failure_persistence = Some(Box::new(MapFailurePersistence::default()));
    config
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn supported_headers_and_opaque_payloads_round_trip(
        class in 0u8..4, msg_id in any::<[u8;16]>(), origin in any::<[u8;16]>(),
        dst in proptest::option::of(any::<[u8;16]>()), created_ms in any::<u64>(),
        lifetime_s in any::<u32>(), ttl in any::<u8>(), hops in any::<u8>(),
        payload in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let header = Header {
            immutable: ImmutableHeader {
                class: PacketClass::try_from(class).unwrap(), flags: 0,
                msg_id, origin, dst, created_ms, lifetime_s, payload_len: payload.len() as u32,
            },
            hop: HopHeader { ttl, hops },
        };
        let mut bytes = vec![0; MAX_HEADER_LEN + payload.len()];
        let len = encode(&header, &payload, &mut bytes).unwrap();
        bytes.truncate(len);
        let packet = PacketView::parse(&bytes).unwrap();
        prop_assert_eq!(packet.parsed_header().header(), &header);
        prop_assert_eq!(packet.payload(), payload.as_slice());
        let offset = packet.parsed_header().payload_offset();
        prop_assert_eq!(packet.payload().as_ptr(), bytes[offset..].as_ptr());
        let immutable = packet.parsed_header().immutable_bytes().to_vec();
        bytes[offset-2] ^= 0xff;
        bytes[offset-1] ^= 0xff;
        prop_assert_eq!(parse_header(&bytes).unwrap().immutable_bytes(), immutable);
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_accepted_packets_are_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _header_result = parse_header(&bytes);
        if let Ok(packet) = PacketView::parse(&bytes) {
            let mut encoded = vec![0; bytes.len()];
            let len = encode(packet.parsed_header().header(), packet.payload(), &mut encoded).unwrap();
            prop_assert_eq!(len, bytes.len());
            prop_assert_eq!(encoded, bytes);
        }
    }
}
