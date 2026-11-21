//! MSH-19 public-API evidence: announcement codec, end-to-end verification,
//! latest-wins order, bounded state and capability fallback.

use ao_idents::Identity;
use ao_mesh::{
    Announcement, CAP_PRESENCE_V1, MeshConfig, MeshEngine, MeshError, MeshHello, MeshInput,
    MeshOutput, Packet, PacketClass, PresenceConfig, PresenceError, PresenceTracker, derive_msg_id,
    encode_announcement, verify_announcement,
};
use ao_network::{AppHello, Channel, Hello, LinkId, LocalTag};
use proptest::prelude::*;
use rand::{SeedableRng, rngs::StdRng};

const LOCAL_SEED: [u8; 32] = [3; 32];
const REMOTE_SEED: [u8; 32] = [17; 32];

fn local_identity() -> Identity {
    Identity::from_seed(LOCAL_SEED)
}

fn remote_identity() -> Identity {
    Identity::from_seed(REMOTE_SEED)
}

fn config() -> MeshConfig {
    MeshConfig {
        presence: PresenceConfig {
            quick_ms: 1,
            base_interval_ms: 10,
            steady_interval_ms: 40,
            ..PresenceConfig::default()
        },
        ..MeshConfig::default()
    }
}

fn engine(config: MeshConfig) -> MeshEngine<StdRng> {
    MeshEngine::with_config(StdRng::seed_from_u64(0x19), config)
}

fn hello(identity: &Identity, caps: u32) -> Hello {
    let signed = MeshHello::sign_with_caps(identity, [0; 8], [0; 4], caps)
        .expect("fixed test identity signs");
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps,
        max_frame: 16384,
        tag: LocalTag::new([1; 16]),
        app_hello: AppHello::new(signed.encode().to_vec()).expect("hello fits"),
    }
}

fn link_up(engine: &mut MeshEngine<StdRng>, link: LinkId, identity: &Identity, caps: u32) {
    let outputs = engine
        .handle(
            0,
            MeshInput::LinkUp {
                link,
                remote_hello: hello(identity, caps),
            },
        )
        .expect("signed hello is valid");
    assert!(
        outputs
            .iter()
            .all(|output| !matches!(output, MeshOutput::CardFetch { .. })),
        "link setup cannot fetch cards"
    );
}

fn facts(seq: u64, card_hash: [u8; 8]) -> Announcement {
    Announcement {
        card_hash,
        caps: CAP_PRESENCE_V1,
        seq,
        signing_pk: [0; 32],
        agreement_pk: [0; 32],
        binding: [0; 64],
    }
}

fn wire(identity: &Identity, now: u64, facts: Announcement) -> Vec<u8> {
    encode_announcement(now, identity, facts, 3, 1_800)
        .expect("fixed identity signs")
        .1
}

fn sends(outputs: &[MeshOutput]) -> Vec<&[u8]> {
    outputs
        .iter()
        .filter_map(|output| match output {
            MeshOutput::Send { payload, .. } => Some(payload.as_slice()),
            _ => None,
        })
        .collect()
}

fn card_fetches(outputs: &[MeshOutput]) -> Vec<([u8; 16], [u8; 8])> {
    outputs
        .iter()
        .filter_map(|output| match output {
            MeshOutput::CardFetch { node_id, card_hash } => Some((*node_id, *card_hash)),
            _ => None,
        })
        .collect()
}

proptest! {
    #[test]
    fn body_round_trips_any_field_bytes(bytes in prop::collection::vec(any::<u8>(), 150)) {
        let mut card_hash = [0u8; 8];
        card_hash.copy_from_slice(&bytes[2..10]);
        let mut signing_pk = [0u8; 32];
        signing_pk.copy_from_slice(&bytes[22..54]);
        let mut agreement_pk = [0u8; 32];
        agreement_pk.copy_from_slice(&bytes[54..86]);
        let mut binding = [0u8; 64];
        binding.copy_from_slice(&bytes[86..150]);
        let announcement = Announcement {
            card_hash,
            caps: u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]),
            seq: u64::from_be_bytes([
                bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19], bytes[20],
                bytes[21],
            ]),
            signing_pk,
            agreement_pk,
            binding,
        };
        prop_assert_eq!(Announcement::decode(&announcement.encode()), Ok(announcement));
    }

    #[test]
    fn arbitrary_bodies_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = Announcement::decode(&bytes);
    }
}

#[test]
fn signed_announcement_verifies_end_to_end_after_hop_mutable_changes() {
    let origin = remote_identity();
    let body = facts(7, [0xA5; 8]);
    let (id, bytes) = encode_announcement(1_000, &origin, body, 3, 1_800).expect("signs");
    let mut packet = Packet::decode(&bytes).expect("decodes");
    assert_eq!(packet.header.class, PacketClass::Presence);
    assert_eq!(packet.header.origin, *origin.node_id().as_bytes());
    assert_eq!(packet.header.msg_id, id);
    assert_eq!(packet.payload.len(), 150);
    assert_eq!(verify_announcement(&packet), Ok(body));

    packet.header.ttl -= 1;
    packet.header.hops += 1;
    assert_eq!(verify_announcement(&packet), Ok(body));

    let mut tampered = bytes.clone();
    let at = tampered.len() - 150 + 2;
    tampered[at] ^= 1;
    let packet = Packet::decode(&tampered).expect("still a packet");
    assert_eq!(
        verify_announcement(&packet),
        Err(PresenceError::MsgIdMismatch)
    );
}

#[test]
fn a_capable_link_receives_the_trickled_announcement() {
    let mut e = engine(config());
    let link = LinkId::new(1);
    link_up(&mut e, link, &remote_identity(), CAP_PRESENCE_V1);

    let local = local_identity();
    let none = e
        .handle(
            0,
            MeshInput::Tick {
                identity: &local,
                card_hash: [0x11; 8],
            },
        )
        .expect("tick is valid");
    assert!(sends(&none).is_empty());
    let outputs = e
        .handle(
            1,
            MeshInput::Tick {
                identity: &local,
                card_hash: [0x11; 8],
            },
        )
        .expect("tick is valid");
    let sent = sends(&outputs);
    assert_eq!(sent.len(), 1, "one announcement per capable link");
    let packet = Packet::decode(sent[0]).expect("announcement is a packet");
    assert_eq!(packet.header.origin, *local.node_id().as_bytes());
    assert_eq!(
        verify_announcement(&packet).map(|body| body.card_hash),
        Ok([0x11; 8])
    );
}

#[test]
fn unknown_cards_are_reported_once_per_node_and_hash() {
    let mut e = engine(config());
    let link = LinkId::new(1);
    let remote = remote_identity();
    link_up(&mut e, link, &remote, CAP_PRESENCE_V1);

    let local = local_identity();
    let first = e
        .handle(
            1_000,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &wire(&remote, 1_000, facts(1, [0x42; 8])),
                identity: &local,
            },
        )
        .expect("valid announcement");
    assert_eq!(
        card_fetches(&first),
        vec![(*remote.node_id().as_bytes(), [0x42; 8])]
    );
    assert_eq!(e.presence().len(), 1);

    let refresh = e
        .handle(
            1_001,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &wire(&remote, 1_001, facts(2, [0x42; 8])),
                identity: &local,
            },
        )
        .expect("valid refresh");
    assert!(
        card_fetches(&refresh).is_empty(),
        "same hash is not fetched twice"
    );
    assert_eq!(
        e.presence()
            .get(remote.node_id().as_bytes())
            .map(|body| body.seq),
        Some(2)
    );
}

#[test]
fn latest_wins_by_seq_then_by_signed_tie_break() {
    let mut e = engine(config());
    let link = LinkId::new(1);
    let remote = remote_identity();
    link_up(&mut e, link, &remote, CAP_PRESENCE_V1);
    let node = *remote.node_id().as_bytes();
    let local = local_identity();

    let send = |e: &mut MeshEngine<StdRng>, now: u64, body: Announcement| {
        let bytes = wire(&remote, now, body);
        e.handle(
            now,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &bytes,
                identity: &local,
            },
        )
        .expect("valid announcement");
    };
    send(&mut e, 1_000, facts(3, [9; 8]));
    send(&mut e, 1_001, facts(1, [1; 8]));
    assert_eq!(e.presence().get(&node).map(|body| body.seq), Some(3));
    // Equal sequence: the smaller card hash wins regardless of arrival order.
    send(&mut e, 1_002, facts(3, [2; 8]));
    assert_eq!(
        e.presence().get(&node).map(|body| body.card_hash),
        Some([2; 8])
    );
}

#[test]
fn forged_origin_is_dropped_and_counted_against_the_sender() {
    let mut e = engine(config());
    let link = LinkId::new(1);
    link_up(&mut e, link, &remote_identity(), CAP_PRESENCE_V1);
    let local = local_identity();

    // The forger signs a valid announcement, then rewrites only the signed
    // origin and content address. Its keys still derive the real origin.
    let forger = Identity::from_seed([41; 32]);
    let victim = Identity::from_seed([42; 32]);
    let (_, bytes) = encode_announcement(1_000, &forger, facts(1, [7; 8]), 3, 1_800)
        .expect("forger signs its own body");
    let mut packet = Packet::decode(&bytes).expect("valid packet");
    packet.header.origin = *victim.node_id().as_bytes();
    packet.header.msg_id = derive_msg_id(&packet.header, packet.payload);
    let forged = packet.encode();
    let outputs = e
        .handle(
            1_000,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &forged,
                identity: &local,
            },
        )
        .expect("malformed packet is handled, not fatal");

    assert!(e.presence().is_empty());
    assert!(card_fetches(&outputs).is_empty());
    assert!(sends(&outputs).is_empty());
    assert_eq!(e.neighbors().get(link).map(|n| n.rejected_packets), Some(1));
}

#[test]
fn bound_inputs_are_rejected_and_learning_stays_bounded() {
    let mut config = config();
    config.presence.max_known_cards = 2;
    config.presence.max_entries = 2;
    let mut e = engine(config);
    let link = LinkId::new(1);
    link_up(&mut e, link, &remote_identity(), CAP_PRESENCE_V1);

    let error = e
        .handle(
            0,
            MeshInput::KnownCards {
                hashes: &[[1; 8], [2; 8], [3; 8]],
            },
        )
        .expect_err("over-bound host input fails");
    assert!(matches!(
        error,
        MeshError::Presence(PresenceError::TooManyKnownCards { len: 3, max: 2 })
    ));
    e.handle(
        0,
        MeshInput::KnownCards {
            hashes: &[[1; 8], [2; 8]],
        },
    )
    .expect("in-bound host input succeeds");

    let local = local_identity();
    for i in 0..8u8 {
        let identity = Identity::from_seed([i; 32]);
        let bytes = wire(&identity, 1_000 + i as u64, facts(1, [i; 8]));
        e.handle(
            1_000 + i as u64,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &bytes,
                identity: &local,
            },
        )
        .expect("valid announcement");
        assert!(e.presence().len() <= 2);
    }
}

#[test]
fn a_peer_without_the_capability_gets_pre_msh19_fallback() {
    let mut e = engine(config());
    let link = LinkId::new(1);
    let remote = remote_identity();
    link_up(&mut e, link, &remote, 0);

    let local = local_identity();
    let tick = e
        .handle(
            10_000,
            MeshInput::Tick {
                identity: &local,
                card_hash: [0x33; 8],
            },
        )
        .expect("tick is valid");
    assert!(sends(&tick).is_empty(), "no announcement to a legacy peer");

    let bytes = wire(&remote, 10_000, facts(1, [0x44; 8]));
    let outputs = e
        .handle(
            10_000,
            MeshInput::Data {
                link,
                channel: Channel::Message,
                payload: &bytes,
                identity: &local,
            },
        )
        .expect("legacy Presence packet is still handled");
    assert!(card_fetches(&outputs).is_empty());
    assert!(e.presence().is_empty(), "legacy peer is not learned");
}

#[test]
fn tracker_reports_emptiness_and_public_getters() {
    let tracker = PresenceTracker::new(PresenceConfig::default());
    assert!(tracker.is_empty());
    assert_eq!(tracker.get(&[0; 16]), None);
}
