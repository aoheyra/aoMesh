use ao_idents::Identity;
use ao_mesh::{
    ChannelConfig, ChannelError, ChannelFrame, ChannelId, ChannelTracker, MeshConfig, MeshEngine,
    MeshHello, MeshInput, MeshOutput, Packet, channel,
};
use ao_network::{AppHello, Channel, Hello, LinkId, LocalTag};
use rand::{SeedableRng, rngs::StdRng};

fn hello(id: &Identity, caps: u32) -> Hello {
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps,
        max_frame: 16384,
        tag: LocalTag::new([1; 16]),
        app_hello: AppHello::new(
            MeshHello::sign_with_caps(id, [0; 8], [0; 4], caps)
                .unwrap()
                .encode()
                .to_vec(),
        )
        .unwrap(),
    }
}
fn engine() -> MeshEngine<StdRng> {
    MeshEngine::new(StdRng::seed_from_u64(0x23))
}
fn link(e: &mut MeshEngine<StdRng>, n: u64, id: &Identity, caps: u32) {
    e.handle(
        0,
        MeshInput::LinkUp {
            link: LinkId::new(n),
            remote_hello: hello(id, caps),
        },
    )
    .unwrap();
}
fn data(e: &mut MeshEngine<StdRng>, id: &Identity, wire: &[u8], now: u64) -> Vec<MeshOutput> {
    e.handle(
        now,
        MeshInput::Data {
            link: LinkId::new(1),
            channel: Channel::Message,
            payload: wire,
            identity: id,
        },
    )
    .unwrap()
}
#[test]
fn exact_names_and_authenticated_plaintext_roundtrip() {
    let a = ChannelId::from_name("campus");
    assert_eq!(a, ChannelId::from_name("campus"));
    assert_ne!(a, ChannelId::from_name("Campus"));
    assert_ne!(a, ChannelId::from_name("campus "));
    let id = Identity::from_seed([1; 32]);
    let wire = channel::encode(&id, 999, a, b"hello", 6).unwrap();
    let mut packet = Packet::decode(&wire).unwrap();
    packet.header.ttl -= 1;
    packet.header.hops += 1;
    let frame = ChannelFrame::verify(&packet).unwrap();
    assert_eq!(frame.channel, a);
    assert_eq!(frame.payload, b"hello");
    packet.header.origin[0] ^= 1;
    assert!(ChannelFrame::verify(&packet).is_err());
    for cut in 0..wire.len() {
        assert!(Packet::decode(&wire[..cut]).is_err());
    }
    let mut forged = wire.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(ChannelFrame::verify(&Packet::decode(&forged).unwrap()).is_err());
    assert!(channel::encode(&id, 0, a, &vec![0; ao_mesh::packet::MAX_PAYLOAD], 6).is_err());
}
#[test]
fn subscriptions_are_local_and_delivery_is_once_even_while_relay_pending() {
    let sender = Identity::from_seed([2; 32]);
    let receiver = Identity::from_seed([3; 32]);
    let target = ChannelId::from_name("campus");
    let other = ChannelId::from_name("other");
    let mut e = engine();
    link(&mut e, 1, &sender, ao_mesh::hello::CAPS);
    e.channels_mut().subscribe(other).unwrap();
    let wire = channel::encode(&sender, u64::MAX, target, b"first", 6).unwrap();
    assert!(
        data(&mut e, &receiver, &wire, 1)
            .iter()
            .all(|o| !matches!(o, MeshOutput::ChannelMessage { .. }))
    );
    e.channels_mut().subscribe(target).unwrap();
    assert!(
        data(&mut e, &receiver, &wire, 2)
            .iter()
            .all(|o| !matches!(o, MeshOutput::ChannelMessage { .. }))
    );
    let wire = channel::encode(&sender, 0, target, b"second", 6).unwrap();
    let out = data(&mut e, &receiver, &wire, 3);
    assert_eq!(
        out.iter()
            .filter(|o| matches!(o,MeshOutput::ChannelMessage{payload,..} if payload==b"second"))
            .count(),
        1
    );
    assert!(
        data(&mut e, &receiver, &wire, 4)
            .iter()
            .all(|o| !matches!(o, MeshOutput::ChannelMessage { .. }))
    );
    e.channels_mut().unsubscribe(target);
    assert!(!e.channels().subscribed(target));
}
#[test]
fn limits_are_shared_across_channels_and_origins_with_no_eviction_bypass() {
    let a = ChannelId::from_name("a");
    let b = ChannelId::from_name("b");
    let mut t = ChannelTracker::new(ChannelConfig {
        max_subscriptions: 1,
        max_entries: 2,
        max_recent: 4,
        window_ms: 100,
        per_channel: 2,
        per_origin: 1,
    });
    t.subscribe(a).unwrap();
    t.subscribe(a).unwrap();
    assert_eq!(t.subscribe(b), Err(ChannelError::Capacity));
    t.admit(100, a, [1; 16], [1; 16].into(), 1).unwrap();
    assert_eq!(
        t.admit(101, b, [1; 16], [2; 16].into(), 1),
        Err(ChannelError::RateLimited)
    );
    t.admit(101, a, [2; 16], [2; 16].into(), 1).unwrap();
    assert_eq!(
        t.admit(102, a, [3; 16], [3; 16].into(), 1),
        Err(ChannelError::RateLimited)
    );
    assert_eq!(
        t.admit(102, b, [3; 16], [3; 16].into(), 1),
        Err(ChannelError::Capacity)
    );
    assert_eq!(
        t.admit(50, b, [1; 16], [4; 16].into(), 1),
        Err(ChannelError::RateLimited)
    );
    t.admit(201, b, [3; 16], [3; 16].into(), 1).unwrap();
    assert_eq!(t.lengths(), (1, 1, 1, 3));
    assert_eq!(
        t.admit(202, b, [3; 16], [3; 16].into(), 1),
        Err(ChannelError::Duplicate)
    );
}
#[test]
fn forged_frames_are_penalized_and_legacy_peers_receive_no_channel_wire() {
    let sender = Identity::from_seed([4; 32]);
    let receiver = Identity::from_seed([5; 32]);
    let mut e = engine();
    link(&mut e, 1, &sender, ao_mesh::hello::CAPS);
    let target = ChannelId::from_name("campus");
    e.channels_mut().subscribe(target).unwrap();
    let mut wire = channel::encode(&sender, 0, target, b"signed", 6).unwrap();
    *wire.last_mut().unwrap() ^= 1;
    assert!(
        !data(&mut e, &receiver, &wire, 1)
            .iter()
            .any(|o| matches!(o, MeshOutput::ChannelMessage { .. }))
    );
    assert_eq!(
        e.neighbors().get(LinkId::new(1)).unwrap().rejected_packets,
        1
    );
    let mut old = engine();
    link(&mut old, 1, &sender, 0);
    let out = old
        .handle(
            1,
            MeshInput::SubmitChannel {
                identity: &receiver,
                channel: target,
                payload: b"new",
            },
        )
        .unwrap();
    assert!(out.is_empty());
}
#[test]
fn unsubscribed_relay_forwards_and_ttl_one_still_delivers_locally() {
    let sender = Identity::from_seed([6; 32]);
    let receiver = Identity::from_seed([7; 32]);
    let next = Identity::from_seed([8; 32]);
    let target = ChannelId::from_name("campus");
    let mut config = MeshConfig::default();
    config.suppression.enabled = false;
    let mut e = MeshEngine::with_config(StdRng::seed_from_u64(23), config);
    link(&mut e, 1, &sender, ao_mesh::hello::CAPS);
    link(&mut e, 2, &next, ao_mesh::hello::CAPS);
    let wire = channel::encode(&sender, 0, target, b"relay", 6).unwrap();
    let out = data(&mut e, &receiver, &wire, 1);
    assert_eq!(
        out.iter()
            .filter(|o| matches!(o,MeshOutput::Send{link,..} if *link==LinkId::new(2)))
            .count(),
        1
    );
    assert!(
        !out.iter()
            .any(|o| matches!(o, MeshOutput::ChannelMessage { .. }))
    );
    e.channels_mut().subscribe(target).unwrap();
    let wire = channel::encode(&sender, 0, target, b"last hop", 1).unwrap();
    let out = data(&mut e, &receiver, &wire, 2);
    assert_eq!(
        out.iter()
            .filter(|o| matches!(o, MeshOutput::ChannelMessage { .. }))
            .count(),
        1
    );
    assert!(!out.iter().any(|o| matches!(o, MeshOutput::Send { .. })));
}

proptest::proptest! {
    #[test]
    fn arbitrary_plaintext_roundtrips(payload in proptest::collection::vec(proptest::num::u8::ANY,0..512)) {
        let id=Identity::from_seed([23;32]);
        let channel=ChannelId::from_name("property");
        let wire=channel::encode(&id,0,channel,&payload,6).unwrap();
        let packet=Packet::decode(&wire).unwrap();
        let frame=ChannelFrame::verify(&packet).unwrap();
        proptest::prop_assert_eq!(frame.payload,payload.as_slice());
    }
}
#[test]
fn zero_capacity_and_recent_bound_fail_closed() {
    let channel = ChannelId::from_name("bounded");
    for config in [
        ChannelConfig {
            max_entries: 0,
            ..Default::default()
        },
        ChannelConfig {
            max_recent: 0,
            ..Default::default()
        },
    ] {
        let mut tracker = ChannelTracker::new(config);
        assert_eq!(
            tracker.admit(0, channel, [1; 16], [1; 16].into(), 1),
            Err(ChannelError::Capacity)
        );
        assert_eq!(tracker.lengths(), (0, 0, 0, 0));
    }
    let mut tracker = ChannelTracker::new(ChannelConfig {
        max_recent: 1,
        ..Default::default()
    });
    tracker
        .admit(0, channel, [1; 16], [1; 16].into(), 1)
        .unwrap();
    assert_eq!(
        tracker.admit(1, channel, [2; 16], [2; 16].into(), 1),
        Err(ChannelError::Capacity)
    );
    tracker
        .admit(1000, channel, [2; 16], [2; 16].into(), 1)
        .unwrap();
    assert_eq!(tracker.lengths().3, 1);
}
#[test]
fn generic_submit_cannot_bypass_channel_admission_and_unknown_version_is_rejected() {
    let sender = Identity::from_seed([11; 32]);
    let receiver = Identity::from_seed([12; 32]);
    let target = ChannelId::from_name("campus");
    let wire = channel::encode(&sender, 0, target, b"signed", 6).unwrap();
    let packet = Packet::decode(&wire).unwrap();
    let mut e = engine();
    link(&mut e, 1, &sender, ao_mesh::hello::CAPS);
    assert!(
        e.handle(
            0,
            MeshInput::Submit {
                identity: &sender,
                header: packet.header,
                payload: packet.payload,
                via: None
            }
        )
        .is_err()
    );
    let mut body = packet.payload.to_vec();
    body[3] = 2;
    let mut header = packet.header;
    let signature = ao_mesh::sign_packet(&sender, &mut header, &body).unwrap();
    let future = Packet::new(header, signature, &body).unwrap().encode();
    assert!(data(&mut e, &receiver, &future, 1).is_empty());
    assert_eq!(
        e.neighbors().get(LinkId::new(1)).unwrap().rejected_packets,
        1
    );
}
