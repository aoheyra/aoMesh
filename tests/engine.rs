//! Engine dispatch through the public API, including untrusted input bounds.
mod common;

use ao_idents::{Identity, ReplayConfig};
use ao_mesh::{
    BudgetConfig, ClassRate, Header, MeshConfig, MeshEngine, MeshError, MeshHello, MeshInput,
    MeshOutput, Packet, PacketClass, SuppressionConfig, sign_packet, verify_origin,
};
use ao_network::{AppHello, Channel, DisconnectReason, Hello, LinkId, LocalTag};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::LazyLock;

/// The node every test engine delivers to: a real identity, so the
/// sealed delivery tests address and open against the same key pair.
/// Seed `[3; 32]`, deliberately neither the `[9; 16]` destination
/// `header()` stamps nor the `[1; 32]` sender the helpers build.
static LOCAL: LazyLock<Identity> = LazyLock::new(|| Identity::from_seed([3; 32]));

fn engine(limit: usize) -> MeshEngine<StdRng> {
    MeshEngine::with_config(
        StdRng::seed_from_u64(0x6006),
        MeshConfig {
            max_neighbors: limit,
            ..MeshConfig::default()
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
/// A link-up with no store items starts MSH-14 and sends one digest frame.
fn assert_sync_digest(outputs: Vec<MeshOutput>, link: LinkId) {
    match outputs.as_slice() {
        [
            MeshOutput::Send {
                link: actual,
                channel: Channel::Bulk,
                payload,
            },
        ] => {
            assert_eq!(*actual, link);
            assert_eq!(payload.first(), Some(&0x53), "sync magic");
        }
        _ => panic!("expected one sync digest frame, got {outputs:?}"),
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
/// A relay-valid packet signed by an explicit identity, for budget tests
/// that need distinct claimed origins on the same sender link.
fn signed_by(identity: &Identity, class: PacketClass, payload: &[u8]) -> Vec<u8> {
    let mut header = header(class, payload.len());
    let signature = sign_packet(identity, &mut header, payload).unwrap();
    Packet::new(header, signature, payload)
        .unwrap()
        .encode()
        .to_vec()
}
/// One encoded packet whose payload is the plaintext sealed to this
/// node, built with the MSH-09 recipe; `mutate` adjusts the header
/// before the seal binds it.
fn sealed_with(class: PacketClass, mutate: impl FnOnce(&mut Header), plaintext: &[u8]) -> Vec<u8> {
    common::sealed(
        &Identity::from_seed([1; 32]),
        &LOCAL,
        100,
        class,
        mutate,
        plaintext,
    )
}
/// Where in the wire the 64-byte origin signature starts: after the
/// header, before the payload.
fn signature_offset(wire: &[u8], payload_len: usize) -> usize {
    wire.len() - payload_len - ao_mesh::SIGNATURE_LEN
}
/// Breaks the origin signature without changing either the sealed
/// payload or its content address: the seal and `msg_id` still decode,
/// so the packet reaches MSH-09's verification step.
fn tamper_signature(wire: &mut [u8], payload_len: usize) {
    let at = signature_offset(wire, payload_len);
    wire[at] ^= 1;
}
#[test]
fn default_bound_and_every_input_change_only_their_owned_state() {
    assert_eq!(MeshConfig::default().max_neighbors, 32);
    // The replay defaults are the documented bounds: 1024 ids per
    // sender for 24 h (ADR-0001's Direct lifetime) across 64 senders.
    assert_eq!(
        MeshConfig::default().replay,
        ReplayConfig::new(1_024, 86_400_000, 64).expect("documented bounds are valid")
    );
    let mut e = engine(2);
    let link = LinkId::new(1);
    assert_sync_digest(
        e.handle(
            10,
            MeshInput::LinkUp {
                link,
                remote_hello: hello(),
            },
        )
        .unwrap(),
        link,
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
                payload: &packet,
                identity: &LOCAL,
            }
        )
        .unwrap()
        .is_empty()
    );
    let n = e.neighbors().get(link).unwrap();
    assert_eq!((n.received_packets, n.malformed_packets), (1, 0));
    assert_eq!(n.rejected_packets, 0);
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
    assert_sync_digest(
        e.handle(
            100001,
            MeshInput::LinkUp {
                link: LinkId::new(10001),
                remote_hello: hello(),
            },
        )
        .unwrap(),
        LinkId::new(10001),
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
        let outputs = e
            .handle(
                1,
                MeshInput::Data {
                    link,
                    channel: Channel::Message,
                    payload: &wire[..end],
                    identity: &LOCAL,
                },
            )
            .unwrap();
        // Malformed traffic never delivers or forwards; once the penalty
        // crosses its threshold the only extra output is the link release.
        assert!(
            outputs
                .iter()
                .all(|output| matches!(output, MeshOutput::Release { .. }))
        );
    }
    let outputs = e
        .handle(
            2,
            MeshInput::Data {
                link,
                channel: Channel::Bulk,
                payload: &[0; 16384],
                identity: &LOCAL,
            },
        )
        .unwrap();
    assert!(
        outputs
            .iter()
            .all(|output| matches!(output, MeshOutput::Release { .. }))
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
                payload: &wire,
                identity: &LOCAL,
            }
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(e.neighbors().len(), 1);
    assert_eq!(e.budgets().origins(), 0);
}

#[test]
fn an_excessive_origin_is_denied_without_blaming_its_sender() {
    let mut budgets = BudgetConfig::default();
    budgets.rates[0] = ClassRate {
        bytes_per_hour: 9_600,
        burst_seconds: 600,
    };
    budgets.penalty_excess = 2;
    budgets.penalty_release_at = 2;
    let config = MeshConfig {
        max_neighbors: 2,
        budgets,
        ..MeshConfig::default()
    };
    let mut e = MeshEngine::with_config(StdRng::seed_from_u64(7), config);
    let sender = LinkId::new(1);
    let other = LinkId::new(2);
    e.handle(
        0,
        MeshInput::LinkUp {
            link: sender,
            remote_hello: hello(),
        },
    )
    .unwrap();
    e.handle(
        0,
        MeshInput::LinkUp {
            link: other,
            remote_hello: hello_of(&Identity::from_seed([8; 32])),
        },
    )
    .unwrap();
    let first = signed(PacketClass::Direct, &vec![1; 700]);
    let second = signed(PacketClass::Direct, &vec![2; 700]);
    let first_outputs = e
        .handle(
            0,
            MeshInput::Data {
                link: sender,
                channel: Channel::Message,
                payload: &first,
                identity: &LOCAL,
            },
        )
        .unwrap();
    assert!(
        first_outputs
            .iter()
            .any(|output| matches!(output, MeshOutput::Send { link, .. } if *link == other))
    );
    let second_outputs = e
        .handle(
            0,
            MeshInput::Data {
                link: sender,
                channel: Channel::Message,
                payload: &second,
                identity: &LOCAL,
            },
        )
        .unwrap();
    // The flooder is throttled, but the neighbour that carried its packets
    // stays connected: disconnecting it would also drop honest traffic.
    assert!(second_outputs.is_empty());
    assert_eq!(e.budgets().penalty(sender), 0);
}

#[test]
fn a_neighbor_limit_denial_is_still_penalised() {
    let budgets = BudgetConfig {
        max_origins_per_neighbor: 0,
        penalty_excess: 1,
        penalty_release_at: 1,
        ..BudgetConfig::default()
    };
    let config = MeshConfig {
        max_neighbors: 2,
        budgets,
        ..MeshConfig::default()
    };
    let mut e = MeshEngine::with_config(StdRng::seed_from_u64(9), config);
    let sender = LinkId::new(1);
    let other = LinkId::new(2);
    e.handle(
        0,
        MeshInput::LinkUp {
            link: sender,
            remote_hello: hello(),
        },
    )
    .unwrap();
    e.handle(
        0,
        MeshInput::LinkUp {
            link: other,
            remote_hello: hello_of(&Identity::from_seed([8; 32])),
        },
    )
    .unwrap();
    let packet = signed_by(&Identity::from_seed([1; 32]), PacketClass::Direct, &[1; 64]);
    let outputs = e
        .handle(
            0,
            MeshInput::Data {
                link: sender,
                channel: Channel::Message,
                payload: &packet,
                identity: &LOCAL,
            },
        )
        .unwrap();
    assert_eq!(
        outputs,
        vec![MeshOutput::Release {
            link: sender,
            reason: DisconnectReason::AbuseDetected,
        }]
    );
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
    let plaintext = b"tamper";
    let mut wire = sealed_with(
        PacketClass::Direct,
        |h| h.dst = Some(*LOCAL.node_id().as_bytes()),
        plaintext,
    );
    let sealed_len = Packet::decode(&wire).unwrap().header.payload_len as usize;
    tamper_signature(&mut wire, sealed_len);
    assert!(Packet::decode(&wire).is_ok());
    assert!(
        e.handle(
            1,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &wire,
                identity: &LOCAL,
            }
        )
        .unwrap()
        .is_empty()
    );
    let neighbor = e.neighbors().get(link).unwrap();
    assert_eq!(neighbor.received_packets, 1);
    assert_eq!(neighbor.rejected_packets, 1, "the sender is penalised");
}

#[test]
fn a_seal_for_another_recipient_is_not_delivered_and_is_counted() {
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
    // Addressed to us, but encrypted for a different node. The header's
    // content address is intact, so only the seal can refuse it.
    let other = Identity::from_seed([4; 32]);
    let wire = common::sealed(
        &Identity::from_seed([1; 32]),
        &other,
        100,
        PacketClass::Direct,
        |h| h.dst = Some(*LOCAL.node_id().as_bytes()),
        b"not for you",
    );
    assert!(
        e.handle(
            1,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &wire,
                identity: &LOCAL,
            }
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(e.neighbors().get(link).unwrap().rejected_packets, 1);
    // A subsequent honest delivery on the same link still works: the
    // refusal left no state that could block it.
    let honest = sealed_with(
        PacketClass::Direct,
        |h| h.dst = Some(*LOCAL.node_id().as_bytes()),
        b"not for you",
    );
    let out = e
        .handle(
            2,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &honest,
                identity: &LOCAL,
            },
        )
        .unwrap();
    assert!(
        matches!(out.as_slice(), [MeshOutput::Deliver { .. }]),
        "{out:?}"
    );
}
#[test]
fn link_up_records_the_verified_node_id_from_the_hello() {
    let mut e = engine(2);
    let identity = Identity::from_seed([0x77; 32]);
    let link = LinkId::new(5);
    assert_sync_digest(
        e.handle(
            10,
            MeshInput::LinkUp {
                link,
                remote_hello: hello_of(&identity),
            },
        )
        .unwrap(),
        link,
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
    let wire = sealed_with(
        PacketClass::Direct,
        |h| h.dst = Some(*LOCAL.node_id().as_bytes()),
        b"hello",
    );
    let out = e
        .handle(
            20,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &wire,
                identity: &LOCAL,
            },
        )
        .unwrap();
    let [MeshOutput::Deliver { header, payload }] = out.as_slice() else {
        panic!("expected exactly one delivery, {out:?}")
    };
    assert_eq!(payload.as_slice(), b"hello");
    assert_eq!(header.class, PacketClass::Direct);
    assert_eq!(header.dst, Some(*LOCAL.node_id().as_bytes()));
    // The same message arriving again is a duplicate, not a delivery.
    assert!(
        e.handle(
            30,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &wire,
                identity: &LOCAL,
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
                identity: &LOCAL,
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
                    identity: &LOCAL,
                },
            )
            .unwrap()
            .is_empty(),
            "ttl {ttl} must not relay"
        );
    }
    // A worn ttl never blocks delivery at the destination itself.
    let wire = sealed_with(
        PacketClass::Direct,
        |h| {
            h.dst = Some(*LOCAL.node_id().as_bytes());
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
                identity: &LOCAL,
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
                identity: &LOCAL,
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
        let wire = signed_with(
            class,
            |h| h.dst = Some(*LOCAL.node_id().as_bytes()),
            b"flooded",
        );
        assert!(
            e.handle(
                1,
                MeshInput::Data {
                    link: LinkId::new(1),
                    channel: Channel::Message,
                    payload: &wire,
                    identity: &LOCAL,
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
    let mut wire = sealed_with(
        PacketClass::Direct,
        |h| h.dst = Some(*LOCAL.node_id().as_bytes()),
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
                identity: &LOCAL,
            },
        )
        .unwrap()
        .is_empty()
    );
    let neighbor = e.neighbors().get(link).unwrap();
    assert_eq!(neighbor.received_packets, 1);
    assert_eq!(neighbor.rejected_packets, 1, "forged content address");
    // The forgery touched no dedupe record, so the intact copy of the
    // same content still delivers.
    let intact = sealed_with(
        PacketClass::Direct,
        |h| h.dst = Some(*LOCAL.node_id().as_bytes()),
        b"secret",
    );
    assert!(matches!(
        e.handle(
            2,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &intact,
                identity: &LOCAL,
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
        |h| h.dst = Some(*LOCAL.node_id().as_bytes()),
        b"hostile",
    );
    assert!(
        e.handle(
            3,
            MeshInput::Data {
                link: LinkId::new(1),
                channel: Channel::Message,
                payload: &for_us,
                identity: &LOCAL,
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
                identity: &LOCAL,
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
                identity: &LOCAL,
            },
        )
        .unwrap();
    let [MeshOutput::Send { link, .. }] = sent.as_slice() else {
        panic!("expected exactly one relay, {sent:?}")
    };
    assert_eq!(*link, LinkId::new(3));
}
fn fast_suppression_engine(neighbors: usize, enabled: bool) -> MeshEngine<StdRng> {
    MeshEngine::with_config(
        StdRng::seed_from_u64(0xB11C),
        MeshConfig {
            max_neighbors: neighbors,
            suppression: SuppressionConfig {
                enabled,
                min_k: 2,
                k_at_degree_ref: 3,
                degree_ref: 8,
                min_base_delay_ms: 10,
                max_base_delay_ms: 10,
                min_delay_ms: 10,
                max_delay_ms: 10,
                ..SuppressionConfig::default()
            },
            ..MeshConfig::default()
        },
    )
}

#[test]
fn submission_clamps_each_class_to_its_adr_ttl() {
    let wire = signed_with(PacketClass::Broadcast, |h| h.ttl = 255, b"caps");
    assert_eq!(Packet::decode(&wire).unwrap().header.ttl, 6);
    let direct = signed_with(PacketClass::Direct, |h| h.ttl = 255, b"caps");
    assert_eq!(Packet::decode(&direct).unwrap().header.ttl, 8);
    let presence = signed_with(PacketClass::Presence, |h| h.ttl = 255, b"caps");
    assert_eq!(Packet::decode(&presence).unwrap().header.ttl, 3);
}

#[test]
fn broadcast_waits_for_its_timer_before_relaying_once() {
    let mut e = fast_suppression_engine(2, true);
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
    let wire = signed(PacketClass::Broadcast, b"timer");
    assert!(
        e.handle(
            100,
            MeshInput::Data {
                link: LinkId::new(1),
                channel: Channel::Message,
                payload: &wire,
                identity: &LOCAL,
            },
        )
        .unwrap()
        .is_empty(),
        "the first copy must wait"
    );
    assert!(e.handle(109, MeshInput::Tick).unwrap().is_empty());
    let due = e.handle(110, MeshInput::Tick).unwrap();
    let [MeshOutput::Send { link, payload, .. }] = due.as_slice() else {
        panic!("expected one timed relay, {due:?}")
    };
    assert_eq!(*link, LinkId::new(2));
    let decoded = Packet::decode(payload).unwrap();
    assert_eq!(decoded.header.ttl, 5);
    assert_eq!(decoded.header.hops, 1);
    assert!(
        e.handle(111, MeshInput::Tick).unwrap().is_empty(),
        "a timer fires once"
    );
}

#[test]
fn distinct_neighbour_copies_cancel_a_broadcast_relay() {
    let mut e = fast_suppression_engine(3, true);
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
    let wire = signed(PacketClass::Broadcast, b"three");
    for (at, link) in [(100, 1), (101, 1), (102, 2), (103, 3)] {
        let out = e
            .handle(
                at,
                MeshInput::Data {
                    link: LinkId::new(link),
                    channel: Channel::Message,
                    payload: &wire,
                    identity: &LOCAL,
                },
            )
            .unwrap();
        assert!(
            out.is_empty(),
            "link {link} should not trigger a send: {out:?}"
        );
    }
    assert!(
        e.handle(1_000, MeshInput::Tick).unwrap().is_empty(),
        "enough copies cancel the pending relay"
    );
}

#[test]
fn disabled_suppression_restores_immediate_flooding() {
    let mut e = fast_suppression_engine(2, false);
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
    let wire = signed(PacketClass::Broadcast, b"ablation");
    let sent = e
        .handle(
            100,
            MeshInput::Data {
                link: LinkId::new(1),
                channel: Channel::Message,
                payload: &wire,
                identity: &LOCAL,
            },
        )
        .unwrap();
    assert_eq!(sent.len(), 1);
    assert!(e.handle(101, MeshInput::Tick).unwrap().is_empty());
}

#[test]
fn budget_denied_broadcast_and_presence_never_enter_suppression() {
    for class in [PacketClass::Broadcast, PacketClass::Presence] {
        let wire = signed(class, b"throttled");
        let index = match class {
            PacketClass::Broadcast => 1,
            PacketClass::Presence => 2,
            other => panic!("unexpected class {other:?}"),
        };
        let mut budgets = BudgetConfig::default();
        // One byte short of the encoded packet with a one-hour bucket: even
        // the first copy must be denied, so nothing may be scheduled.
        budgets.rates[index] = ClassRate {
            bytes_per_hour: (wire.len() - 1) as u64,
            burst_seconds: 3600,
        };
        budgets.penalty_excess = 1;
        budgets.penalty_release_at = 1;
        let config = MeshConfig {
            max_neighbors: 2,
            budgets,
            suppression: SuppressionConfig {
                enabled: true,
                min_base_delay_ms: 10,
                max_base_delay_ms: 10,
                min_delay_ms: 10,
                max_delay_ms: 10,
                ..SuppressionConfig::default()
            },
            ..MeshConfig::default()
        };
        let mut e = MeshEngine::with_config(StdRng::seed_from_u64(0xB11C), config);
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
        let out = e
            .handle(
                100,
                MeshInput::Data {
                    link: LinkId::new(1),
                    channel: Channel::Message,
                    payload: &wire,
                    identity: &LOCAL,
                },
            )
            .unwrap();
        assert!(out.is_empty(), "{class:?} denial must not relay: {out:?}");
        assert!(
            e.handle(1_000, MeshInput::Tick).unwrap().is_empty(),
            "{class:?} denial must not start a suppression timer"
        );
        assert_eq!(
            e.budgets().penalty(LinkId::new(1)),
            0,
            "{class:?} origin denial must not blame the carrier"
        );
    }
}

#[test]
fn tampered_broadcast_is_not_counted_as_a_suppression_copy() {
    let mut e = fast_suppression_engine(3, true);
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
    let mut wire = signed(PacketClass::Broadcast, b"clean");
    // Change content, not just the signature: the content address is what
    // suppression keys on, so a forged address must never enter a timer.
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    let out = e
        .handle(
            100,
            MeshInput::Data {
                link: LinkId::new(1),
                channel: Channel::Message,
                payload: &wire,
                identity: &LOCAL,
            },
        )
        .unwrap();
    assert!(
        out.is_empty(),
        "a forged packet cannot suppress or relay: {out:?}"
    );
    assert!(e.handle(1_000, MeshInput::Tick).unwrap().is_empty());
    assert_eq!(
        e.neighbors().get(LinkId::new(1)).unwrap().rejected_packets,
        1
    );
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
                identity: &LOCAL,
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
