//! MSH-23 public channels: deterministic ids, signed Broadcast envelopes,
//! local-only subscriptions, bounded rules and typed budget failures.

use ao_idents::Identity;
use ao_mesh::{
    BudgetConfig, ChannelBudgetScope, ChannelConfig, ChannelEnvelope, ChannelError, ChannelId,
    ClassRate, Header, MeshConfig, MeshEngine, MeshError, MeshHello, MeshInput, MeshOutput, Packet,
    PacketClass, derive_channel_id, sign_packet, verify_origin_with_signing_pk,
};
use ao_network::{AppHello, Channel, Hello, LinkId, LocalTag};
use rand::{SeedableRng, rngs::StdRng};

const NOW: u64 = 1_700_000_000_000;
const CHANNEL_NAME: &[u8] = b"town-square";

fn channel_id() -> ChannelId {
    derive_channel_id(CHANNEL_NAME).expect("name is within the bound")
}

fn engine(config: MeshConfig) -> MeshEngine<StdRng> {
    MeshEngine::with_config(StdRng::seed_from_u64(0x2323), config)
}

fn hello_of(identity: &Identity) -> Hello {
    let signed = MeshHello::sign(identity, [0; 8], [0; 4]).expect("fixed key signs hello");
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps: 0,
        max_frame: 16_384,
        tag: LocalTag::new([1; 16]),
        app_hello: AppHello::new(signed.encode().to_vec()).expect("hello fits"),
    }
}

fn link_up(e: &mut MeshEngine<StdRng>, link: LinkId, identity: &Identity) {
    let _ = e
        .handle(
            NOW,
            MeshInput::LinkUp {
                link,
                remote_hello: hello_of(identity),
            },
        )
        .expect("signed hello is valid");
}

fn signed_channel(origin: &Identity, inner: &[u8]) -> Vec<u8> {
    let payload = ChannelEnvelope::new(channel_id(), inner)
        .expect("test payload fits")
        .encode();
    let mut header = Header {
        class: PacketClass::Broadcast,
        dst: None,
        msg_id: [0; 16].into(),
        origin: [0; 16],
        created_ms: NOW,
        lifetime_s: 600,
        payload_len: payload.len() as u64,
        ttl: 255,
        hops: 0,
    };
    let signature = sign_packet(origin, &mut header, &payload).expect("fixed key signs");
    Packet::new(header, signature, &payload)
        .expect("lengths agree")
        .encode()
}

#[test]
fn channel_id_is_a_stable_hash_and_envelope_errors_are_typed() {
    assert_eq!(
        channel_id(),
        derive_channel_id(CHANNEL_NAME).expect("stable")
    );
    assert_ne!(
        channel_id(),
        derive_channel_id(b"town-square ").expect("stable")
    );
    assert_eq!(derive_channel_id(b""), Err(ChannelError::EmptyName));

    let envelope = ChannelEnvelope::new(channel_id(), b"opaque").expect("fits");
    let wire = envelope.encode();
    assert_eq!(wire.len(), ao_mesh::CHANNEL_HEADER_LEN + 6);
    assert_eq!(ChannelEnvelope::decode(&wire), Ok(envelope));
    assert_eq!(
        ChannelEnvelope::decode(&wire[..ao_mesh::CHANNEL_HEADER_LEN - 1]),
        Err(ChannelError::EnvelopeTooShort {
            need: ao_mesh::CHANNEL_HEADER_LEN,
            have: ao_mesh::CHANNEL_HEADER_LEN - 1,
        })
    );
    let mut bad_version = wire.clone();
    bad_version[1] = 2;
    assert_eq!(
        ChannelEnvelope::decode(&bad_version),
        Err(ChannelError::UnsupportedVersion(2))
    );
    let mut bad_magic = wire;
    bad_magic[0] = 0;
    assert_eq!(
        ChannelEnvelope::decode(&bad_magic),
        Err(ChannelError::WrongMagic(0))
    );
    assert_eq!(ChannelConfig::new(0, 64), Err(ChannelError::InvalidConfig));
}

#[test]
fn channel_signature_uses_the_unchanged_domain_and_ignores_hop_fields() {
    let origin = Identity::from_seed([7; 32]);
    let wire = signed_channel(&origin, b"opaque");
    let packet = Packet::decode(&wire).expect("decodes");
    let key = origin.public().signing_pk();
    verify_origin_with_signing_pk(key, &packet.header, packet.payload, &packet.signature)
        .expect("hello-carried key verifies");

    // A relay's hop-mutable fields are outside the signed prefix.
    let mut header = packet.header;
    header.ttl -= 1;
    header.hops += 1;
    verify_origin_with_signing_pk(key, &header, packet.payload, &packet.signature)
        .expect("ttl and hops do not break the signature");

    // Changing an immutable field or the payload must break it.
    header.origin = [9; 16];
    assert!(
        verify_origin_with_signing_pk(key, &header, packet.payload, &packet.signature).is_err()
    );
    let mut payload = packet.payload.to_vec();
    payload[ao_mesh::CHANNEL_HEADER_LEN] ^= 1;
    assert!(
        verify_origin_with_signing_pk(key, &packet.header, &payload, &packet.signature).is_err()
    );
}

#[test]
fn only_a_local_subscriber_receives_a_verified_channel_message() {
    let origin = Identity::from_seed([7; 32]);
    let host = Identity::from_seed([3; 32]);
    let sender = LinkId::new(1);
    let downstream = LinkId::new(2);
    let wire = signed_channel(&origin, b"opaque");

    let mut subscriber = engine(MeshConfig {
        suppression: ao_mesh::SuppressionConfig {
            enabled: false,
            ..ao_mesh::SuppressionConfig::default()
        },
        ..MeshConfig::default()
    });
    link_up(&mut subscriber, sender, &origin);
    link_up(&mut subscriber, downstream, &Identity::from_seed([8; 32]));
    subscriber
        .handle(NOW, MeshInput::ChannelSubscribe { name: CHANNEL_NAME })
        .expect("subscription is valid");
    assert!(subscriber.channels().contains(channel_id()));

    let outputs = subscriber
        .handle(
            NOW,
            MeshInput::Data {
                link: sender,
                channel: Channel::Message,
                payload: &wire,
                identity: &host,
            },
        )
        .expect("channel packet is valid");
    let deliver = outputs
        .iter()
        .find_map(|output| match output {
            MeshOutput::ChannelDeliver {
                channel_id: id,
                payload,
                ..
            } => Some((*id, payload.as_slice())),
            _ => None,
        })
        .expect("subscriber receives the opaque body");
    assert_eq!(deliver, (channel_id(), b"opaque".as_slice()));
    assert_eq!(subscriber.channels().len(), 1);

    // The same subscribed engine rejects a forged signature and blames the
    // link instead of delivering another copy.
    let mut forged = wire.clone();
    let signature_at = forged.len() - packet_payload_len(&wire) - ao_mesh::SIGNATURE_LEN;
    forged[signature_at] ^= 1;
    let before = subscriber
        .neighbors()
        .get(sender)
        .expect("link")
        .rejected_packets;
    let outputs = subscriber
        .handle(
            NOW + 1,
            MeshInput::Data {
                link: sender,
                channel: Channel::Message,
                payload: &forged,
                identity: &host,
            },
        )
        .expect("forgery is dropped without an error");
    assert!(
        !outputs
            .iter()
            .any(|output| matches!(output, MeshOutput::ChannelDeliver { .. }))
    );
    assert_eq!(
        subscriber
            .neighbors()
            .get(sender)
            .expect("link")
            .rejected_packets,
        before + 1
    );

    // A relay with no subscription forwards on the normal Broadcast path and
    // keeps its local registry empty.
    let mut relay = engine(MeshConfig {
        suppression: ao_mesh::SuppressionConfig {
            enabled: false,
            ..ao_mesh::SuppressionConfig::default()
        },
        ..MeshConfig::default()
    });
    link_up(&mut relay, sender, &origin);
    link_up(&mut relay, downstream, &Identity::from_seed([8; 32]));
    let outputs = relay
        .handle(
            NOW,
            MeshInput::Data {
                link: sender,
                channel: Channel::Message,
                payload: &wire,
                identity: &host,
            },
        )
        .expect("relay accepts the packet");
    assert!(relay.channels().is_empty());
    assert!(
        !outputs
            .iter()
            .any(|output| matches!(output, MeshOutput::ChannelDeliver { .. }))
    );
    assert!(
        outputs
            .iter()
            .any(|output| matches!(output, MeshOutput::Send { link, .. } if *link == downstream)),
        "relay sends to the other neighbour"
    );
}

#[test]
fn local_submission_enforces_both_origin_and_channel_budgets() {
    let config = small_broadcast_budget();
    let mut e = engine(config);
    let identity = Identity::from_seed([1; 32]);
    let payload = ChannelEnvelope::new(channel_id(), &[0; 500])
        .expect("test payload fits")
        .encode();
    let mut header = header_for(payload.len());

    // 518 envelope bytes fit the 600-byte burst; a second 518-byte message
    // from another origin exhausts the shared channel bucket while that
    // origin's own bucket is still full.
    assert!(
        e.handle(
            NOW,
            MeshInput::Submit {
                identity: &identity,
                header,
                payload: &payload,
                via: None,
            },
        )
        .is_ok()
    );
    let other = Identity::from_seed([2; 32]);
    header = header_for(payload.len());
    assert_channel_error(
        e.handle(
            NOW,
            MeshInput::Submit {
                identity: &other,
                header,
                payload: &payload,
                via: None,
            },
        )
        .unwrap_err(),
        ChannelError::BudgetDenied {
            scope: ChannelBudgetScope::Channel,
        },
    );

    // A fresh channel still refuses an origin that spent its own allowance.
    let mut e = engine(small_broadcast_budget());
    let big = ChannelEnvelope::new(channel_id(), &[0; 600])
        .expect("test payload fits")
        .encode();
    assert_channel_error(
        e.handle(
            NOW,
            MeshInput::Submit {
                identity: &identity,
                header: header_for(big.len()),
                payload: &big,
                via: None,
            },
        )
        .unwrap_err(),
        ChannelError::BudgetDenied {
            scope: ChannelBudgetScope::Origin,
        },
    );
}

#[test]
fn subscriptions_are_bounded_and_unsubscribe_acts_locally() {
    let config = MeshConfig {
        channels: ChannelConfig::new(1, 64).expect("valid test config"),
        ..MeshConfig::default()
    };
    let mut e = engine(config);
    e.handle(NOW, MeshInput::ChannelSubscribe { name: b"alpha" })
        .expect("one subscription fits");
    assert_channel_error(
        e.handle(NOW, MeshInput::ChannelSubscribe { name: b"bravo" })
            .unwrap_err(),
        ChannelError::SubscriptionsFull { limit: 1 },
    );
    e.handle(NOW, MeshInput::ChannelUnsubscribe { name: b"alpha" })
        .expect("unsubscribing is valid");
    assert!(e.channels().is_empty());
    e.handle(NOW, MeshInput::ChannelSubscribe { name: b"bravo" })
        .expect("the slot was freed");
    assert_eq!(e.channels().len(), 1);
}

fn assert_channel_error(actual: MeshError, expected: ChannelError) {
    match actual {
        MeshError::Channel(error) => assert_eq!(error, expected),
        other => panic!("expected a typed channel error, got {other:?}"),
    }
}

fn packet_payload_len(wire: &[u8]) -> usize {
    Packet::decode(wire)
        .expect("test wire decodes")
        .payload
        .len()
}

fn header_for(payload_len: usize) -> Header {
    Header {
        class: PacketClass::Broadcast,
        dst: None,
        msg_id: [0; 16].into(),
        origin: [0; 16],
        created_ms: NOW,
        lifetime_s: 600,
        payload_len: payload_len as u64,
        ttl: 6,
        hops: 0,
    }
}

fn small_broadcast_budget() -> MeshConfig {
    MeshConfig {
        budgets: BudgetConfig {
            rates: [ClassRate {
                bytes_per_hour: 3_600,
                burst_seconds: 600,
            }; 4],
            ..BudgetConfig::default()
        },
        ..MeshConfig::default()
    }
}
