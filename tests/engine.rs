//! Engine dispatch through the public API, including untrusted input bounds.
use ao_idents::Identity;
use ao_mesh::{
    Header, MeshConfig, MeshEngine, MeshError, MeshInput, MeshOutput, Packet, PacketClass,
    verify_origin,
};
use ao_network::{AppHello, Channel, DisconnectReason, Hello, LinkId, LocalTag};
use rand::{SeedableRng, rngs::StdRng};

fn engine(limit: usize) -> MeshEngine<StdRng> {
    MeshEngine::with_config(
        StdRng::seed_from_u64(0x6006),
        MeshConfig {
            max_neighbors: limit,
        },
    )
}
fn hello() -> Hello {
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps: 0,
        max_frame: 16384,
        tag: LocalTag::new([1; 16]),
        app_hello: AppHello::new(vec![1; 8]).unwrap(),
    }
}
fn header(class: PacketClass, len: usize) -> Header {
    Header {
        class,
        dst: Some([9; 16]),
        msg_id: [0; 16].into(),
        origin: [0; 16],
        created_ms: 100,
        lifetime_s: 600,
        payload_len: len as u64,
        ttl: 8,
        hops: 0,
    }
}
fn signed(class: PacketClass, payload: &[u8]) -> Vec<u8> {
    let mut e = engine(1);
    let identity = Identity::from_seed([1; 32]);
    let outputs = e
        .handle(
            100,
            MeshInput::Submit {
                identity: &identity,
                header: header(class, payload.len()),
                payload,
                via: None,
            },
        )
        .unwrap();
    match outputs.into_iter().next().unwrap() {
        MeshOutput::Broadcast { payload, .. } => payload,
        other => panic!("unexpected {other:?}"),
    }
}
#[test]
fn default_bound_and_every_input_change_only_their_owned_state() {
    assert_eq!(MeshConfig::default().max_neighbors, 32);
    let mut e = engine(2);
    let link = LinkId::new(1);
    assert!(
        e.handle(
            10,
            MeshInput::LinkUp {
                link,
                remote_hello: hello()
            }
        )
        .unwrap()
        .is_empty()
    );
    let n = e.neighbors().get(link).unwrap();
    assert_eq!(n.connected_at_ms, 10);
    assert_eq!(n.remote_hello, hello());
    let packet = signed(PacketClass::Direct, b"opaque");
    assert!(
        e.handle(
            20,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &packet
            }
        )
        .unwrap()
        .is_empty()
    );
    let n = e.neighbors().get(link).unwrap();
    assert_eq!((n.received_packets, n.malformed_packets), (1, 0));
    assert_eq!(n.received_bytes, packet.len() as u64);
    assert_eq!(n.last_rx_ms, Some(20));
    assert!(e.handle(30, MeshInput::Tick).unwrap().is_empty());
    assert_eq!(e.neighbors().get(link).unwrap().last_rx_ms, Some(20));
    assert!(
        e.handle(
            40,
            MeshInput::LinkDown {
                link,
                reason: DisconnectReason::TransportLost
            }
        )
        .unwrap()
        .is_empty()
    );
    assert!(e.neighbors().is_empty());
}
#[test]
fn signed_submission_passes_origin_verification_for_every_class() {
    let identity = Identity::from_seed([1; 32]);
    for class in [
        PacketClass::Direct,
        PacketClass::Broadcast,
        PacketClass::Presence,
        PacketClass::Telemetry,
    ] {
        let wire = signed(class, b"payload");
        let packet = Packet::decode(&wire).unwrap();
        assert_eq!(packet.header.origin, *identity.node_id().as_bytes());
        verify_origin(
            identity.public(),
            &packet.header,
            packet.payload,
            &packet.signature,
        )
        .unwrap();
        assert_eq!(packet.payload, b"payload");
    }
}
#[test]
fn submission_targets_a_known_link_and_telemetry_uses_its_own_channel() {
    let mut e = engine(1);
    let link = LinkId::new(7);
    let identity = Identity::from_seed([2; 32]);
    e.handle(
        0,
        MeshInput::LinkUp {
            link,
            remote_hello: hello(),
        },
    )
    .unwrap();
    let outputs = e
        .handle(
            1,
            MeshInput::Submit {
                identity: &identity,
                header: header(PacketClass::Telemetry, 1),
                payload: b"x",
                via: Some(link),
            },
        )
        .unwrap();
    let [
        MeshOutput::Send {
            link: actual,
            channel,
            payload,
        },
    ] = outputs.as_slice()
    else {
        panic!("expected send")
    };
    assert_eq!((*actual, *channel), (link, Channel::Telemetry));
    let p = Packet::decode(payload).unwrap();
    verify_origin(identity.public(), &p.header, p.payload, &p.signature).unwrap();
}
#[test]
fn bad_submissions_return_typed_errors_and_leave_state_untouched() {
    let mut e = engine(1);
    let identity = Identity::from_seed([3; 32]);
    let input = || MeshInput::Submit {
        identity: &identity,
        header: header(PacketClass::Direct, 1),
        payload: b"x",
        via: Some(LinkId::new(4)),
    };
    assert!(matches!(
        e.handle(0, input()),
        Err(MeshError::UnknownLink(_))
    ));
    assert!(matches!(
        e.handle(
            0,
            MeshInput::Submit {
                identity: &identity,
                header: header(PacketClass::Direct, 2),
                payload: b"x",
                via: None
            }
        ),
        Err(MeshError::Packet(_))
    ));
    assert!(matches!(
        e.handle(
            0,
            MeshInput::Submit {
                identity: &identity,
                header: header(PacketClass::Direct, 2049),
                payload: &[0; 2049],
                via: None
            }
        ),
        Err(MeshError::Packet(_))
    ));
    assert!(e.neighbors().is_empty());
}
#[test]
fn neighbour_flood_is_bounded_and_refused_links_are_released() {
    let mut e = engine(3);
    for id in 0..10_000 {
        let link = LinkId::new(id);
        let out = e
            .handle(
                id,
                MeshInput::LinkUp {
                    link,
                    remote_hello: hello(),
                },
            )
            .unwrap();
        assert!(e.neighbors().len() <= 3);
        if id >= 3 {
            assert_eq!(
                out,
                [MeshOutput::Release {
                    link,
                    reason: DisconnectReason::Closed
                }]
            );
        }
    }
    assert_eq!(
        e.neighbors().iter().map(|n| n.link).collect::<Vec<_>>(),
        [LinkId::new(0), LinkId::new(1), LinkId::new(2)]
    );
    // A repeated LinkUp cannot reset the original counters or consume a slot.
    assert!(
        e.handle(
            99999,
            MeshInput::LinkUp {
                link: LinkId::new(0),
                remote_hello: hello()
            }
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        e.neighbors().get(LinkId::new(0)).unwrap().connected_at_ms,
        0
    );
    e.handle(
        100000,
        MeshInput::LinkDown {
            link: LinkId::new(0),
            reason: DisconnectReason::Closed,
        },
    )
    .unwrap();
    assert!(
        e.handle(
            100001,
            MeshInput::LinkUp {
                link: LinkId::new(10001),
                remote_hello: hello()
            }
        )
        .unwrap()
        .is_empty()
    );
    let mut none = engine(0);
    assert_eq!(
        none.handle(
            0,
            MeshInput::LinkUp {
                link: LinkId::new(0),
                remote_hello: hello()
            }
        )
        .unwrap()
        .len(),
        1
    );
    assert!(none.neighbors().is_empty());
}
#[test]
fn malformed_and_oversized_data_are_counted_without_delivery_or_forwarding() {
    let mut e = engine(1);
    let link = LinkId::new(1);
    e.handle(
        0,
        MeshInput::LinkUp {
            link,
            remote_hello: hello(),
        },
    )
    .unwrap();
    let wire = signed(PacketClass::Direct, b"hello");
    for end in 0..wire.len() {
        assert!(
            e.handle(
                1,
                MeshInput::Data {
                    link,
                    channel: Channel::Message,
                    payload: &wire[..end]
                }
            )
            .unwrap()
            .is_empty()
        );
    }
    assert!(
        e.handle(
            2,
            MeshInput::Data {
                link,
                channel: Channel::Bulk,
                payload: &[0; 16384]
            }
        )
        .unwrap()
        .is_empty()
    );
    let n = e.neighbors().get(link).unwrap();
    assert_eq!(n.received_packets, 0);
    assert_eq!(n.malformed_packets, wire.len() as u64 + 1);
    // Untracked senders cannot create state by injecting data.
    assert!(
        e.handle(
            3,
            MeshInput::Data {
                link: LinkId::new(99),
                channel: Channel::Message,
                payload: &wire
            }
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(e.neighbors().len(), 1);
}
#[test]
fn structural_validity_never_means_authenticated_delivery() {
    let mut e = engine(1);
    let link = LinkId::new(1);
    e.handle(
        0,
        MeshInput::LinkUp {
            link,
            remote_hello: hello(),
        },
    )
    .unwrap();
    let mut wire = signed(PacketClass::Direct, b"tamper");
    *wire.last_mut().unwrap() ^= 1;
    assert!(Packet::decode(&wire).is_ok());
    assert!(
        e.handle(
            1,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &wire
            }
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(e.neighbors().get(link).unwrap().received_packets, 1);
}
