use ao_mesh::{
    expiry::{LifetimePolicy, age_at},
    packet::{Header, MessageId, PacketClass},
    store::{MemoryStore, MessageStore, StoreError, StoreLimits, conformance::entry},
};

#[test]
fn defaults_match_routing_adr_and_sender_can_shorten() {
    let p = LifetimePolicy::default();
    for (class, seconds) in [
        (PacketClass::Direct, 86400),
        (PacketClass::Broadcast, 21600),
        (PacketClass::Presence, 1800),
        (PacketClass::Telemetry, 300),
    ] {
        let mut h = entry(1, 1, PacketClass::Direct, 6, 1, 0)
            .header()
            .to_owned();
        h.class = class;
        h.lifetime_s = u64::MAX;
        assert_eq!(p.lifetime_s(class), seconds);
        assert_eq!(p.remaining_ms(&h, 0, 0, 0), seconds * 1000);
        assert!(!p.is_expired(&h, 0, 0, seconds * 1000 - 1));
        assert!(p.is_expired(&h, 0, 0, seconds * 1000));
        h.lifetime_s = 1;
        assert_eq!(p.remaining_ms(&h, 0, 0, 0), 1000);
    }
}

#[test]
fn hours_of_clock_skew_do_not_change_relative_expiry() {
    let p = LifetimePolicy::default();
    for local_epoch in [0, 3_600_000, 86_400_000] {
        for remote_wall_clock in [0, 86_400_000, u64::MAX] {
            let mut h = entry(1, 1, PacketClass::Direct, 6, 1, 0)
                .header()
                .to_owned();
            h.created_ms = remote_wall_clock;
            h.lifetime_s = 10;
            assert_eq!(
                p.remaining_ms(&h, local_epoch, 2500, local_epoch + 5000),
                2500
            );
            assert!(!p.is_expired(&h, local_epoch, 2500, local_epoch + 7499));
            assert!(p.is_expired(&h, local_epoch, 2500, local_epoch + 7500));
        }
    }
}

#[test]
fn custom_policy_is_enforced_on_every_store_path() {
    let p = LifetimePolicy {
        direct_s: 2,
        broadcast_s: 3,
        presence_s: 0,
        telemetry_s: 1,
    };
    let mut s = MemoryStore::with_lifetime_policy(StoreLimits::default(), p);
    let direct = entry(1, 1, PacketClass::Direct, 6, 1, 100);
    let wire = direct.wire().to_vec();
    s.put(100, direct).unwrap();
    s.put(100, entry(2, 2, PacketClass::Broadcast, 6, 1, 100))
        .unwrap();
    assert_eq!(
        s.get(2099, &MessageId::from_bytes([1; 16])).unwrap().wire(),
        wire
    );
    assert!(s.get(2100, &MessageId::from_bytes([1; 16])).is_none());
    assert_eq!(s.summary(2100), vec![MessageId::from_bytes([2; 16])]);
    assert_eq!(
        s.by_destination(2100, &[9; 16]),
        vec![MessageId::from_bytes([2; 16])]
    );
    assert_eq!(
        s.put(2100, entry(3, 3, PacketClass::Direct, 6, 1, 100)),
        Err(StoreError::Expired)
    );
    assert_eq!(
        s.put(100, entry(4, 4, PacketClass::Presence, 1, 3, 100)),
        Err(StoreError::Expired)
    );
    assert_eq!(s.expire(2100), vec![MessageId::from_bytes([1; 16])]);
    assert_eq!(s.expire(3100), vec![MessageId::from_bytes([2; 16])]);
    assert_eq!(s.used_bytes(), 0);
}

#[test]
fn zero_and_extreme_values_have_defined_boundaries() {
    let mut h: Header = *entry(1, 1, PacketClass::Direct, 6, 1, 0).header();
    let p = LifetimePolicy {
        direct_s: u64::MAX,
        ..LifetimePolicy::default()
    };
    h.lifetime_s = u64::MAX;
    assert!(!p.is_expired(&h, 0, u64::MAX, u64::MAX));
    assert_eq!(p.remaining_ms(&h, 0, 0, 0), u64::MAX);
    h.lifetime_s = 0;
    assert!(p.is_expired(&h, 0, 0, 0));
    h.lifetime_s = 10;
    assert_eq!(p.remaining_ms(&h, 100, 2000, 99), 8000);
    assert_eq!(age_at(100, u64::MAX, 200), u64::MAX);
}

#[test]
fn multiple_encounters_preserve_consumed_age() {
    let h = *entry(1, 1, PacketClass::Direct, 6, 1, 0).header();
    let p = LifetimePolicy::default();
    let age = age_at(1000, 1000, 4000);
    assert_eq!(age, 4000);
    // Receiver's clock is hours ahead; only its own elapsed 6 seconds count.
    assert_eq!(p.remaining_ms(&h, 36_000_000, age, 36_005_999), 1);
    assert!(p.is_expired(&h, 36_000_000, age, 36_006_000));
}

#[test]
fn default_store_ceiling_expires_long_sender_lifetime_without_rewriting() {
    use ao_mesh::store::StoredMessage;
    let base = entry(1, 1, PacketClass::Direct, 6, 1, 0);
    let mut h = *base.header();
    h.lifetime_s = 7 * 24 * 60 * 60;
    let mut wire = h.encode();
    wire.extend_from_slice(&[0; 4]);
    let long = StoredMessage::new(&wire, *base.metadata()).unwrap();
    let mut s = MemoryStore::new(StoreLimits::default());
    s.put(0, long).unwrap();
    assert_eq!(
        s.get(86_399_999, &MessageId::from_bytes([1; 16]))
            .unwrap()
            .wire(),
        wire
    );
    assert!(s.get(86_400_000, &MessageId::from_bytes([1; 16])).is_none());
    // Expired duplicate is replaceable under the same policy used for queries.
    assert_eq!(
        s.put(
            86_400_000,
            entry(1, 1, PacketClass::Direct, 6, 1, 86_400_000)
        )
        .unwrap(),
        vec![MessageId::from_bytes([1; 16])]
    );
    assert!(s.get(86_400_000, &MessageId::from_bytes([1; 16])).is_some());
}
