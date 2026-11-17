use ao_mesh::{
    MessageId,
    packet::PacketClass,
    store::{conformance::entry, *},
};

fn id(value: u8) -> MessageId {
    MessageId::from_bytes([value; 16])
}

#[test]
fn memory_backend_conformance() {
    conformance::check(MemoryStore::new);
}

#[test]
fn eviction_priority_age_and_id_are_deterministic() {
    let mut s = MemoryStore::new(StoreLimits {
        entries: 2,
        ..StoreLimits::default()
    });
    s.put(20, entry(1, 1, PacketClass::Direct, 2, 1, 0))
        .unwrap();
    s.put(20, entry(2, 2, PacketClass::Direct, 2, 4, 20))
        .unwrap();
    assert_eq!(
        s.put(20, entry(3, 3, PacketClass::Direct, 2, 1, 20))
            .unwrap(),
        vec![id(2)]
    );
    assert_eq!(
        s.put(20, entry(4, 4, PacketClass::Direct, 2, 1, 20))
            .unwrap(),
        vec![id(1)]
    );
    assert_eq!(
        s.put(20, entry(5, 5, PacketClass::Direct, 2, 1, 20))
            .unwrap(),
        vec![id(3)]
    );
}

#[test]
fn relative_expiry_and_rejections_preserve_entries() {
    let original = entry(1, 1, PacketClass::Direct, 6, 1, 100);
    let mut meta = *original.metadata();
    meta.age_ms = 9_900;
    let aged = StoredMessage::new(original.wire(), meta).unwrap();
    assert!(!aged.is_expired(199));
    assert!(aged.is_expired(200));
    let mut s = MemoryStore::new(StoreLimits::default());
    s.put(100, original.clone()).unwrap();
    assert_eq!(
        s.put(99, entry(2, 1, PacketClass::Direct, 6, 1, 100)),
        Err(StoreError::InvalidTime)
    );
    assert_eq!(s.get(100, &id(1)), Some(&original));
    assert!(matches!(
        StoredMessage::new(&vec![0; MAX_STORED_PACKET + 1], meta),
        Err(StoreError::TooLarge)
    ));
    assert!(matches!(
        StoredMessage::new(&[], meta),
        Err(StoreError::Packet(_))
    ));
    assert!(matches!(
        StoredMessage::new(&original.wire()[..original.wire().len() - 1], meta),
        Err(StoreError::Truncated)
    ));
    let mut wire = original.wire().to_vec();
    wire[1] = PacketClass::Telemetry as u8;
    assert_eq!(
        StoredMessage::new(&wire, meta),
        Err(StoreError::NotStorable)
    );
}

#[test]
fn stress_caps_and_expiry_before_live_eviction() {
    let size = entry(1, 1, PacketClass::Direct, 6, 1, 0).size();
    let mut s = MemoryStore::new(StoreLimits {
        entries: 3,
        total_bytes: size * 3,
        per_origin_bytes: size * 2,
        per_class_bytes: [size * 3; 4],
    });
    for id in 0..100u8 {
        s.put(0, entry(id, id % 3, PacketClass::Direct, 6, 1, 0))
            .unwrap();
        assert!(s.used_bytes() <= size * 3);
        assert!(s.summary(0).len() <= 3);
    }
    assert_eq!(
        s.put(10_000, entry(101, 1, PacketClass::Direct, 6, 1, 10_000))
            .unwrap()
            .len(),
        3
    );
    assert_eq!(s.summary(10_000), vec![id(101)]);
}

#[test]
fn zero_limits_and_simultaneous_scoped_pressure() {
    let size = entry(1, 1, PacketClass::Direct, 6, 1, 0).size();
    for limits in [
        StoreLimits {
            entries: 0,
            ..StoreLimits::default()
        },
        StoreLimits {
            total_bytes: 0,
            ..StoreLimits::default()
        },
        StoreLimits {
            per_origin_bytes: 0,
            ..StoreLimits::default()
        },
        StoreLimits {
            per_class_bytes: [0; 4],
            ..StoreLimits::default()
        },
    ] {
        let mut s = MemoryStore::new(limits);
        assert_eq!(
            s.put(0, entry(1, 1, PacketClass::Direct, 6, 1, 0)),
            Err(StoreError::Quota)
        );
        assert_eq!(s.used_bytes(), 0);
    }
    let mut s = MemoryStore::new(StoreLimits {
        entries: 8,
        total_bytes: size * 8,
        per_origin_bytes: size,
        per_class_bytes: [size; 4],
    });
    s.put(0, entry(1, 1, PacketClass::Broadcast, 6, 1, 0))
        .unwrap();
    s.put(0, entry(2, 2, PacketClass::Direct, 6, 1, 0)).unwrap();
    // The origin and class pressure require two disjoint evictions.
    assert_eq!(
        s.put(0, entry(3, 1, PacketClass::Direct, 6, 1, 0)).unwrap(),
        vec![id(1), id(2)]
    );
    assert_eq!(s.summary(0), vec![id(3)]);
}

#[test]
fn maximum_clock_values_and_signature_envelope_remain_bounded() {
    let base = entry(1, 1, PacketClass::Direct, 6, 1, 0);
    let mut wire = base.wire().to_vec();
    wire.extend_from_slice(&[3; 64]);
    let signed = StoredMessage::new(&wire, *base.metadata()).unwrap();
    assert_eq!(signed.wire(), wire);
    assert_eq!(signed.size(), wire.len());
    let mut meta = *base.metadata();
    meta.age_ms = u64::MAX;
    let expired = StoredMessage::new(base.wire(), meta).unwrap();
    assert!(expired.is_expired(u64::MAX));
    meta.first_seen = 1;
    assert_eq!(
        StoredMessage::new(base.wire(), meta),
        Err(StoreError::InvalidTime)
    );
}
