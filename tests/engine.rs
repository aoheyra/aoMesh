//! Engine dispatch through the public API, including untrusted input bounds.
use ao_idents::{Identity, NodeId};
use ao_mesh::{
    Header, MeshConfig, MeshEngine, MeshError, MeshHello, MeshInput, MeshOutput, Packet,
    PacketClass, verify_origin,
};
use ao_network::{AppHello, Channel, DisconnectReason, Hello, LinkId, LocalTag};
use rand::{SeedableRng, rngs::StdRng};

/// The node every test engine delivers to; deliberately not `[9; 16]`,
/// the destination `header()` stamps.
const LOCAL: NodeId = NodeId::from_bytes([3; 16]);
fn engine(limit: usize) -> MeshEngine<StdRng> {
    MeshEngine::with_config(
        StdRng::seed_from_u64(0x6006),
        LOCAL,
        MeshConfig {
            max_neighbors: limit,
        },
    )
}
fn hello() -> Hello {
    hello_of(&Identity::from_seed([7; 32]))
}
/// A link-level Hello carrying a signed MeshHello, as every honest
/// host now builds it (MSH-07).
fn hello_of(identity: &Identity) -> Hello {
    let signed = MeshHello::sign(identity, [0; 8], [0; 4]).unwrap();
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps: 0,
        max_frame: 16384,
        tag: LocalTag::new([1; 16]),
        app_hello: AppHello::new(signed.encode().to_vec()).unwrap(),
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
/// One submission from a fixed demonstration identity, encoded as it
/// hits the wire; `mutate` adjusts the header before signing so tests
/// can build destined, exhausted or hostile variants.
fn signed_with(class: PacketClass, mutate: impl FnOnce(&mut Header), payload: &[u8]) -> Vec<u8> {
    let mut e = engine(1);
    let identity = Identity::from_seed([1; 32]);
    let mut header = header(class, payload.len());
    mutate(&mut header);
    let outputs = e
        .handle(
            100,
            MeshInput::Submit {
                identity: &identity,
                header,
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
fn signed(class: PacketClass, payload: &[u8]) -> Vec<u8> {
    signed_with(class, |_| {}, payload)
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
#[test]
fn link_up_records_the_verified_node_id_from_the_hello() {
    let mut e = engine(2);
    let identity = Identity::from_seed([0x77; 32]);
    let link = LinkId::new(5);
    assert!(
        e.handle(
            10,
            MeshInput::LinkUp {
                link,
                remote_hello: hello_of(&identity)
            }
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        e.neighbors().get(link).unwrap().node_id,
        Some(identity.node_id())
    );
}
#[test]
fn link_up_with_an_invalid_hello_leaves_no_verified_node_id() {
    let mut e = engine(3);
    // A pre-MSH-07 garbage blob, and an oversize blob: aoNetwork
    // allows up to 256 bytes, the v1 layout defines exactly 161.
    let rejected = [
        AppHello::new(vec![1; 8]).unwrap(),
        AppHello::new(vec![0; 200]).unwrap(),
    ];
    for (case, app_hello) in rejected.into_iter().enumerate() {
        let link = LinkId::new(case as u64 + 20);
        let outputs = e
            .handle(
                case as u64,
                MeshInput::LinkUp {
                    link,
                    remote_hello: Hello {
                        proto_min: 1,
                        proto_max: 1,
                        caps: 0,
                        max_frame: 16384,
                        tag: LocalTag::new([1; 16]),
                        app_hello,
                    },
                },
            )
            .unwrap();
        // A failed introduction is dropped, not released: the entry
        // keeps counting what the link delivers (ADR-0004).
        assert!(outputs.is_empty(), "case {case}: {outputs:?}");
        let neighbor = e.neighbors().get(link).unwrap();
        assert_eq!(neighbor.node_id, None, "case {case}");
        assert_eq!(neighbor.received_packets, 0);
    }
    // The reject does not poison later admissions: a valid hello on
    // another link still records its identity.
    let identity = Identity::from_seed([0x78; 32]);
    let link = LinkId::new(99);
    e.handle(
        50,
        MeshInput::LinkUp {
            link,
            remote_hello: hello_of(&identity),
        },
    )
    .unwrap();
    assert_eq!(
        e.neighbors().get(link).unwrap().node_id,
        Some(identity.node_id())
    );
}
#[test]
fn fresh_direct_for_the_local_node_delivers_exactly_once() {
    let mut e = engine(2);
    let link = LinkId::new(1);
    e.handle(
        0,
        MeshInput::LinkUp {
            link,
            remote_hello: hello(),
        },
    )
    .unwrap();
    let wire = signed_with(
        PacketClass::Direct,
        |h| h.dst = Some(*LOCAL.as_bytes()),
        b"hello",
    );
    let out = e
        .handle(
            20,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &wire,
            },
        )
        .unwrap();
    let [MeshOutput::Deliver { header, payload }] = out.as_slice() else {
        panic!("expected exactly one delivery, {out:?}")
    };
    assert_eq!(payload.as_slice(), b"hello");
    assert_eq!(header.class, PacketClass::Direct);
    assert_eq!(header.dst, Some(*LOCAL.as_bytes()));
    // The same message arriving again is a duplicate, not a delivery.
    assert!(
        e.handle(
            30,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &wire,
            },
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(e.neighbors().get(link).unwrap().received_packets, 2);
}
#[test]
fn relay_skips_the_sending_link_and_decrements_ttl() {
    let mut e = engine(3);
    for id in 1..=3u64 {
        e.handle(
            id,
            MeshInput::LinkUp {
                link: LinkId::new(id),
                remote_hello: hello(),
            },
        )
        .unwrap();
    }
    let wire = signed(PacketClass::Direct, b"hop");
    let original = Packet::decode(&wire).unwrap();
    let sent = e
        .handle(
            20,
            MeshInput::Data {
                link: LinkId::new(1),
                channel: Channel::Message,
                payload: &wire,
            },
        )
        .unwrap();
    assert_eq!(sent.len(), 2, "{sent:?}");
    let mut links = Vec::new();
    for output in &sent {
        let MeshOutput::Send {
            link,
            channel,
            payload,
        } = output
        else {
            panic!("expected sends only, {output:?}")
        };
        assert_eq!(*channel, Channel::Message);
        let relayed = Packet::decode(payload).unwrap();
        assert_eq!(relayed.header.ttl, 7);
        assert_eq!(relayed.header.hops, 1);
        assert_eq!(relayed.payload, original.payload);
        // The re-encode leaves the immutable prefix alone, so the next
        // hop verifies the same origin signature and content id.
        assert_eq!(relayed.header.msg_id, original.header.msg_id);
        assert_eq!(relayed.signature, original.signature);
        verify_origin(
            Identity::from_seed([1; 32]).public(),
            &relayed.header,
            relayed.payload,
            &relayed.signature,
        )
        .unwrap();
        links.push(*link);
    }
    links.sort();
    assert_eq!(links, [LinkId::new(2), LinkId::new(3)]);
}
#[test]
fn exhausted_ttl_stops_relaying_but_the_local_destination_still_delivers() {
    let mut e = engine(2);
    // Two links, so an empty result proves the ttl floor refused the
    // relay rather than the neighbour table having no target.
    for id in 1..=2u64 {
        e.handle(
            id,
            MeshInput::LinkUp {
                link: LinkId::new(id),
                remote_hello: hello(),
            },
        )
        .unwrap();
    }
    let link = LinkId::new(1);
    // Not for this node and no hop left: dropped, never relayed.
    for (ttl, payload) in [(0, &b"zero"[..]), (1, &b"one"[..])] {
        let wire = signed_with(PacketClass::Direct, |h| h.ttl = ttl, payload);
        assert!(
            e.handle(
                1,
                MeshInput::Data {
                    link,
                    channel: Channel::Message,
                    payload: &wire,
                },
            )
            .unwrap()
            .is_empty(),
            "ttl {ttl} must not relay"
        );
    }
    // A worn ttl never blocks delivery at the destination itself.
    let wire = signed_with(
        PacketClass::Direct,
        |h| {
            h.dst = Some(*LOCAL.as_bytes());
            h.ttl = 0;
        },
        b"last hop",
    );
    let out = e
        .handle(
            2,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &wire,
            },
        )
        .unwrap();
    assert!(
        matches!(out.as_slice(), [MeshOutput::Deliver { .. }]),
        "{out:?}"
    );
}
#[test]
fn hostile_hops_saturate_instead_of_panicking() {
    let mut e = engine(2);
    for id in 1..=2u64 {
        e.handle(
            id,
            MeshInput::LinkUp {
                link: LinkId::new(id),
                remote_hello: hello(),
            },
        )
        .unwrap();
    }
    let wire = signed_with(PacketClass::Direct, |h| h.hops = 255, b"many");
    let sent = e
        .handle(
            1,
            MeshInput::Data {
                link: LinkId::new(1),
                channel: Channel::Message,
                payload: &wire,
            },
        )
        .unwrap();
    let [MeshOutput::Send { payload, .. }] = sent.as_slice() else {
        panic!("expected one relay, {sent:?}")
    };
    assert_eq!(Packet::decode(payload).unwrap().header.hops, 255);
}
#[test]
fn non_direct_classes_are_neither_delivered_nor_relayed() {
    let mut e = engine(2);
    for id in 1..=2u64 {
        e.handle(
            id,
            MeshInput::LinkUp {
                link: LinkId::new(id),
                remote_hello: hello(),
            },
        )
        .unwrap();
    }
    for class in [
        PacketClass::Broadcast,
        PacketClass::Presence,
        PacketClass::Telemetry,
    ] {
        // Hostile: a flooded class claiming this node as its
        // destination, arriving where a relay target exists.
        let wire = signed_with(class, |h| h.dst = Some(*LOCAL.as_bytes()), b"flooded");
        assert!(
            e.handle(
                1,
                MeshInput::Data {
                    link: LinkId::new(1),
                    channel: Channel::Message,
                    payload: &wire,
                },
            )
            .unwrap()
            .is_empty(),
            "{class:?} must not forward"
        );
    }
}
#[test]
fn content_tampering_never_reaches_delivery() {
    let mut e = engine(2);
    let link = LinkId::new(1);
    e.handle(
        0,
        MeshInput::LinkUp {
            link,
            remote_hello: hello(),
        },
    )
    .unwrap();
    let mut wire = signed_with(
        PacketClass::Direct,
        |h| h.dst = Some(*LOCAL.as_bytes()),
        b"secret",
    );
    *wire.last_mut().unwrap() ^= 1;
    assert!(Packet::decode(&wire).is_ok());
    assert!(
        e.handle(
            1,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &wire,
            },
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(e.neighbors().get(link).unwrap().received_packets, 1);
    // The forgery touched no dedupe record, so the intact copy of the
    // same content still delivers.
    let intact = signed_with(
        PacketClass::Direct,
        |h| h.dst = Some(*LOCAL.as_bytes()),
        b"secret",
    );
    assert!(matches!(
        e.handle(
            2,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &intact,
            },
        )
        .unwrap()
        .as_slice(),
        [MeshOutput::Deliver { .. }]
    ));
}
#[test]
fn unverified_senders_neither_forward_nor_receive() {
    let mut e = engine(3);
    // Link 1 carries a pre-MSH-07 garbage blob; links 2 and 3 are
    // verified through signed hellos.
    e.handle(
        0,
        MeshInput::LinkUp {
            link: LinkId::new(1),
            remote_hello: Hello {
                proto_min: 1,
                proto_max: 1,
                caps: 0,
                max_frame: 16384,
                tag: LocalTag::new([1; 16]),
                app_hello: AppHello::new(vec![1; 8]).unwrap(),
            },
        },
    )
    .unwrap();
    for id in 2..=3u64 {
        e.handle(
            id,
            MeshInput::LinkUp {
                link: LinkId::new(id),
                remote_hello: hello(),
            },
        )
        .unwrap();
    }
    assert_eq!(e.neighbors().get(LinkId::new(1)).unwrap().node_id, None);
    // Addressed to this node but arriving on the unverified link:
    // counted, never delivered (ADR-0004).
    let for_us = signed_with(
        PacketClass::Direct,
        |h| h.dst = Some(*LOCAL.as_bytes()),
        b"hostile",
    );
    assert!(
        e.handle(
            3,
            MeshInput::Data {
                link: LinkId::new(1),
                channel: Channel::Message,
                payload: &for_us,
            },
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        e.neighbors().get(LinkId::new(1)).unwrap().received_packets,
        1
    );
    // For another node on the unverified link: never relayed either.
    let elsewhere = signed(PacketClass::Direct, b"pass-through");
    assert!(
        e.handle(
            4,
            MeshInput::Data {
                link: LinkId::new(1),
                channel: Channel::Message,
                payload: &elsewhere,
            },
        )
        .unwrap()
        .is_empty()
    );
    // A verified sender's copy relays only to the other verified link:
    // the sending link is excluded and the unverified entry is not a
    // relay target.
    let sent = e
        .handle(
            5,
            MeshInput::Data {
                link: LinkId::new(2),
                channel: Channel::Message,
                payload: &elsewhere,
            },
        )
        .unwrap();
    let [MeshOutput::Send { link, .. }] = sent.as_slice() else {
        panic!("expected exactly one relay, {sent:?}")
    };
    assert_eq!(*link, LinkId::new(3));
}
#[test]
fn the_origin_never_rerelays_a_copy_of_its_own_submission() {
    let mut e = engine(2);
    for id in 1..=2u64 {
        e.handle(
            id,
            MeshInput::LinkUp {
                link: LinkId::new(id),
                remote_hello: hello(),
            },
        )
        .unwrap();
    }
    let identity = Identity::from_seed([1; 32]);
    let outputs = e
        .handle(
            100,
            MeshInput::Submit {
                identity: &identity,
                header: header(PacketClass::Direct, 4),
                payload: b"ping",
                via: Some(LinkId::new(1)),
            },
        )
        .unwrap();
    let [MeshOutput::Send { link, payload, .. }] = outputs.as_slice() else {
        panic!("expected one send, {outputs:?}")
    };
    assert_eq!(*link, LinkId::new(1));
    // The same bytes coming back over the other link must not be
    // re-relayed: without the origin's own dedupe record that would
    // target link 1 again and close a loop.
    assert!(
        e.handle(
            200,
            MeshInput::Data {
                link: LinkId::new(2),
                channel: Channel::Message,
                payload: payload.as_slice(),
            },
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        e.neighbors().get(LinkId::new(2)).unwrap().received_packets,
        1
    );
}
