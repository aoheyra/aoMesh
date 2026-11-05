use ao_mesh::packet::{
    Header, HopHeader, ImmutableHeader, MAX_HEADER_LEN, MAX_PAYLOAD_LEN, PacketClass, PacketError,
    PacketView, encode, parse_header,
};

fn header(payload_len: u32) -> Header {
    Header {
        immutable: ImmutableHeader {
            class: PacketClass::Direct,
            flags: 0,
            msg_id: [0x11; 16],
            origin: [0x22; 16],
            dst: None,
            created_ms: 300,
            lifetime_s: 60,
            payload_len,
        },
        hop: HopHeader { ttl: 8, hops: 0 },
    }
}

fn fixture() -> Vec<u8> {
    let mut bytes = vec![1, 0, 0];
    bytes.extend_from_slice(&[0x11; 16]);
    bytes.extend_from_slice(&[0x22; 16]);
    bytes.extend_from_slice(&[0, 0xac, 2, 60, 3, 8, 0, 0xaa, 0xbb, 0xcc]);
    bytes
}

#[test]
fn independent_wire_fixture_encodes_and_decodes() {
    let fixture = fixture();
    let mut out = [0xee; 128];
    let written = encode(&header(3), &[0xaa, 0xbb, 0xcc], &mut out).unwrap();
    assert_eq!(&out[..written], fixture);
    assert!(out[written..].iter().all(|&b| b == 0xee));
    let view = PacketView::parse(&fixture).unwrap();
    assert_eq!(view.parsed_header().header(), &header(3));
    assert_eq!(view.payload(), [0xaa, 0xbb, 0xcc]);
    assert_eq!(view.parsed_header().payload_offset(), 42);
    assert_eq!(view.parsed_header().immutable_bytes(), &fixture[..40]);
}

#[test]
fn header_only_admission_needs_no_body_but_full_parse_does() {
    let bytes = fixture();
    let parsed = parse_header(&bytes[..42]).unwrap();
    assert_eq!(parsed.packet_len(), bytes.len());
    assert!(matches!(
        PacketView::parse(&bytes[..42]),
        Err(PacketError::LengthMismatch { .. })
    ));
    for end in 0..42 {
        assert_eq!(parse_header(&bytes[..end]), Err(PacketError::Truncated));
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(matches!(
        PacketView::parse(&extra),
        Err(PacketError::LengthMismatch { .. })
    ));
}

#[test]
fn optional_destination_and_all_classes_have_fixed_discriminants() {
    for (byte, class) in [
        PacketClass::Direct,
        PacketClass::Broadcast,
        PacketClass::Presence,
        PacketClass::Telemetry,
    ]
    .into_iter()
    .enumerate()
    {
        let mut h = header(0);
        h.immutable.class = class;
        h.immutable.dst = Some([0x33; 16]);
        let mut out = [0; MAX_HEADER_LEN];
        let len = encode(&h, &[], &mut out).unwrap();
        assert_eq!(out[1], byte as u8);
        assert_eq!(out[35], 1);
        assert_eq!(&out[36..52], &[0x33; 16]);
        assert_eq!(
            PacketView::parse(&out[..len])
                .unwrap()
                .parsed_header()
                .header(),
            &h
        );
        for end in 36..52 {
            assert_eq!(parse_header(&out[..end]), Err(PacketError::Truncated));
        }
    }
}

#[test]
fn unknown_version_class_flags_and_destination_are_rejected() {
    for value in 0..=255u8 {
        let mut bytes = fixture();
        if value != 1 {
            bytes[0] = value;
            assert_eq!(
                parse_header(&bytes),
                Err(PacketError::UnsupportedVersion(value))
            );
        }
        bytes = fixture();
        if value > 3 {
            bytes[1] = value;
            assert_eq!(parse_header(&bytes), Err(PacketError::UnknownClass(value)));
        }
        bytes = fixture();
        if value != 0 {
            bytes[2] = value;
            assert_eq!(
                parse_header(&bytes),
                Err(PacketError::UnsupportedFlags(value))
            );
        }
        bytes = fixture();
        if value > 1 {
            bytes[35] = value;
            assert_eq!(
                parse_header(&bytes),
                Err(PacketError::InvalidDestination(value))
            );
        }
    }
}

#[test]
fn every_varint_field_rejects_overflow_and_redundant_encodings() {
    let bytes = fixture();
    // Independent offsets in the fixture: created_ms, lifetime_s, payload_len.
    for (start, end, width) in [(36, 38, 64), (38, 39, 32), (39, 40, 32)] {
        for bad in [vec![0x80, 0], vec![0x81, 0]] {
            let mut input = bytes.clone();
            input.splice(start..end, bad);
            assert_eq!(parse_header(&input), Err(PacketError::NonCanonicalVarint));
        }
        let mut overflow = vec![0xff; if width == 64 { 10 } else { 5 }];
        overflow.push(0);
        let mut input = bytes.clone();
        input.splice(start..end, overflow);
        assert_eq!(parse_header(&input), Err(PacketError::VarintOverflow));
        // Even a zero final group with excessive continuation bits must fail.
        let mut input = bytes.clone();
        input.splice(start..end, vec![0x80; if width == 64 { 10 } else { 5 }]);
        assert_eq!(parse_header(&input), Err(PacketError::VarintOverflow));
    }
}

#[test]
fn payload_cap_is_checked_before_waiting_for_the_body_or_hop_fields() {
    let bytes = fixture();
    let mut oversized = bytes[..39].to_vec();
    // 1 MiB + 1, canonical unsigned LEB128; no payload or hop fields supplied.
    oversized.extend_from_slice(&[0x81, 0x80, 0x40]);
    assert_eq!(
        parse_header(&oversized),
        Err(PacketError::PayloadTooLarge(MAX_PAYLOAD_LEN as u32 + 1))
    );
    let mut output = [0xee; 100];
    assert_eq!(
        encode(&header(MAX_PAYLOAD_LEN as u32 + 1), &[], &mut output),
        Err(PacketError::PayloadTooLarge(MAX_PAYLOAD_LEN as u32 + 1))
    );
    assert_eq!(output, [0xee; 100]);
}

#[test]
fn maximum_fields_fit_the_documented_header_bound() {
    let payload = vec![0xa5; MAX_PAYLOAD_LEN];
    let mut h = header(MAX_PAYLOAD_LEN as u32);
    h.immutable.created_ms = u64::MAX;
    h.immutable.lifetime_s = u32::MAX;
    h.immutable.dst = Some([0xff; 16]);
    h.hop = HopHeader {
        ttl: 255,
        hops: 255,
    };
    let mut output = vec![0; MAX_HEADER_LEN + payload.len()];
    let len = encode(&h, &payload, &mut output).unwrap();
    assert_eq!(len, output.len());
    let view = PacketView::parse(&output).unwrap();
    assert_eq!(view.parsed_header().payload_offset(), MAX_HEADER_LEN);
    assert_eq!(view.parsed_header().header(), &h);
    assert_eq!(view.payload().as_ptr(), output[MAX_HEADER_LEN..].as_ptr());
    assert_eq!(view.payload(), payload);
}

#[test]
fn hop_edits_preserve_immutable_bytes_and_origin_edits_change_them() {
    let mut bytes = fixture();
    let immutable = parse_header(&bytes).unwrap().immutable_bytes().to_vec();
    bytes[40] = 7;
    bytes[41] = 1;
    assert_eq!(parse_header(&bytes).unwrap().immutable_bytes(), immutable);
    bytes[19] ^= 1;
    assert_ne!(parse_header(&bytes).unwrap().immutable_bytes(), immutable);
}

#[test]
fn invalid_encode_never_changes_the_output() {
    let mut out = [0xee; 44];
    assert!(matches!(
        encode(&header(3), &[1, 2], &mut out),
        Err(PacketError::LengthMismatch {
            expected: 3,
            actual: 2
        })
    ));
    assert_eq!(out, [0xee; 44]);
    assert_eq!(
        encode(&header(3), &[1, 2, 3], &mut out),
        Err(PacketError::BufferTooSmall {
            required: 45,
            actual: 44
        })
    );
    assert_eq!(out, [0xee; 44]);
    let mut invalid = header(3);
    invalid.immutable.flags = 1;
    assert_eq!(
        encode(&invalid, &[1, 2, 3], &mut out),
        Err(PacketError::UnsupportedFlags(1))
    );
    assert_eq!(out, [0xee; 44]);
}
