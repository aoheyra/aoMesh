//! MSH-22 engine policy through the public API.
//!
//! The tracker's arithmetic and bounds have their own unit tests. These
//! tests prove the engine wires that policy before budget admission, keeps
//! Telemetry out of store/sync, and turns only malformed frames into a
//! penalty.

use ao_idents::Identity;
use ao_mesh::{
    DEFAULT_EXPIRY_MS, DEFAULT_RATE_LIMIT_MS, Header, MeshConfig, MeshEngine, MeshError, MeshHello,
    MeshInput, MeshOutput, Packet, PacketClass, TelemetryConfig, TelemetryError, TelemetryFrame,
    TelemetryKind, sign_packet, verify_origin,
};
use ao_network::{AppHello, Channel, Hello, LinkId, LocalTag};
use rand::{SeedableRng, rngs::StdRng};

fn config(rate_limit_ms: u64) -> MeshConfig {
    let mut config = MeshConfig::default();
    config.spray.enabled = false;
    config.receipt.enabled = false;
    config.telemetry = TelemetryConfig {
        rate_limit_ms,
        ..TelemetryConfig::default()
    };
    config
}

fn engine(rate_limit_ms: u64) -> MeshEngine<StdRng> {
    MeshEngine::with_config(StdRng::seed_from_u64(0x22), config(rate_limit_ms))
}

fn hello() -> Hello {
    let signed = MeshHello::sign(&Identity::from_seed([7; 32]), [0; 8], [0; 4]).unwrap();
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps: 0,
        max_frame: 16_384,
        tag: LocalTag::new([1; 16]),
        app_hello: AppHello::new(signed.encode().to_vec()).unwrap(),
    }
}

fn link_up(engine: &mut MeshEngine<StdRng>, link: LinkId) {
    let _ = engine
        .handle(
            0,
            MeshInput::LinkUp {
                link,
                remote_hello: hello(),
            },
        )
        .unwrap();
}

#[derive(Clone, Copy)]
struct Wire {
    seq: u64,
    ttl: u8,
    hops: u8,
    lifetime_s: u64,
    created_ms: u64,
}

fn framed_packet(identity: &Identity, kind: u8, wire: Wire, payload: &[u8]) -> Vec<u8> {
    let framed = TelemetryFrame::encode(TelemetryKind::new(kind), wire.seq, payload).unwrap();
    let mut header = Header {
        class: PacketClass::Telemetry,
        dst: None,
        msg_id: [0; 16].into(),
        origin: *identity.node_id().as_bytes(),
        created_ms: wire.created_ms,
        lifetime_s: wire.lifetime_s,
        payload_len: framed.len() as u64,
        ttl: wire.ttl,
        hops: wire.hops,
    };
    let signature = sign_packet(identity, &mut header, &framed).unwrap();
    Packet::new(header, signature, &framed).unwrap().encode()
}

fn relay_data(
    engine: &mut MeshEngine<StdRng>,
    now: u64,
    sender: LinkId,
    wire: &[u8],
) -> Vec<MeshOutput> {
    let identity = Identity::from_seed([3; 32]);
    engine
        .handle(
            now,
            MeshInput::Data {
                link: sender,
                channel: Channel::Telemetry,
                payload: wire,
                identity: &identity,
            },
        )
        .unwrap()
}

#[test]
fn typed_submission_keeps_one_key_for_a_stream_and_never_stores_it() {
    let mut engine = engine(0);
    link_up(&mut engine, LinkId::new(1));
    let identity = Identity::from_seed([1; 32]);
    let mut advisories = Vec::new();
    for seq in 1..=2 {
        let outputs = engine
            .handle(
                1_000,
                MeshInput::SubmitTelemetry {
                    identity: &identity,
                    kind: TelemetryKind::new(7),
                    seq,
                    payload: b"opaque location bytes",
                    via: Some(LinkId::new(1)),
                },
            )
            .unwrap();
        let [
            MeshOutput::TelemetrySend {
                link,
                channel,
                payload,
                advisory,
            },
        ] = outputs.as_slice()
        else {
            panic!("expected one telemetry send, got {outputs:?}")
        };
        assert_eq!(*link, LinkId::new(1));
        assert_eq!(*channel, Channel::Telemetry);
        assert_eq!(advisory.seq, seq);
        assert_eq!(advisory.expires_in_ms, DEFAULT_EXPIRY_MS);
        assert_eq!(advisory.hop_limit, 3);
        advisories.push(*advisory);
        let packet = Packet::decode(payload).unwrap();
        assert_eq!(packet.header.class, PacketClass::Telemetry);
        verify_origin(
            identity.public(),
            &packet.header,
            packet.payload,
            &packet.signature,
        )
        .unwrap();
    }
    assert_eq!(advisories[0].coalesce_key, advisories[1].coalesce_key);
    assert_ne!(advisories[0].seq, advisories[1].seq);
    assert!(
        !engine.telemetry().is_empty(),
        "the origin tracks its own accepted update"
    );
}

#[test]
fn chatty_origin_is_throttled_and_a_backward_clock_grants_nothing() {
    let mut engine = engine(DEFAULT_RATE_LIMIT_MS);
    let identity = Identity::from_seed([1; 32]);
    let submit = |engine: &mut MeshEngine<StdRng>, now: u64, seq: u64| {
        engine.handle(
            now,
            MeshInput::SubmitTelemetry {
                identity: &identity,
                kind: TelemetryKind::new(7),
                seq,
                payload: b"x",
                via: None,
            },
        )
    };
    assert!(submit(&mut engine, 1_000_000, 1).unwrap().len() == 1);
    assert!(matches!(
        submit(&mut engine, 1_000_001, 2),
        Err(MeshError::Telemetry(TelemetryError::RateLimited { .. }))
    ));
    assert!(matches!(
        submit(&mut engine, 999_999, 2),
        Err(MeshError::Telemetry(TelemetryError::RateLimited { .. }))
    ));
    let outputs = submit(&mut engine, 1_000_000 + DEFAULT_RATE_LIMIT_MS, 2).unwrap();
    assert!(matches!(
        outputs.as_slice(),
        [MeshOutput::TelemetryBroadcast { .. }]
    ));
}

#[test]
fn relay_drops_stale_expired_and_hop_limited_updates_without_penalty_or_sync() {
    let mut engine = engine(0);
    link_up(&mut engine, LinkId::new(1));
    link_up(&mut engine, LinkId::new(2));
    let origin = Identity::from_seed([1; 32]);
    let sender = LinkId::new(1);
    // A wildly skewed remote created_ms must not change the local window.
    let fresh = framed_packet(
        &origin,
        7,
        Wire {
            seq: 5,
            ttl: 3,
            hops: 0,
            lifetime_s: 30,
            created_ms: u64::MAX,
        },
        b"location",
    );
    let outputs = relay_data(&mut engine, 500_000, sender, &fresh);
    assert!(matches!(
        outputs.as_slice(),
        [MeshOutput::TelemetrySend {
            link: actual,
            channel: Channel::Telemetry,
            ..
        }] if *actual == LinkId::new(2)
    ));
    assert_eq!(engine.telemetry().len(), 1);

    let packet = |seq, ttl, hops, lifetime_s| {
        framed_packet(
            &origin,
            7,
            Wire {
                seq,
                ttl,
                hops,
                lifetime_s,
                created_ms: 0,
            },
            b"location",
        )
    };
    let stale = packet(5, 3, 0, 30);
    assert!(relay_data(&mut engine, 500_001, sender, &stale).is_empty());
    let older = packet(4, 3, 0, 30);
    assert!(relay_data(&mut engine, 500_002, sender, &older).is_empty());

    let expired = packet(6, 3, 0, 0);
    assert!(relay_data(&mut engine, 500_003, sender, &expired).is_empty());
    let short_ttl = packet(7, 1, 0, 30);
    assert!(relay_data(&mut engine, 500_004, sender, &short_ttl).is_empty());
    let worn_hops = packet(8, 255, 3, 30);
    assert!(relay_data(&mut engine, 500_005, sender, &worn_hops).is_empty());
    assert_eq!(engine.telemetry().len(), 1, "drops left no freshness entry");
    assert_eq!(
        engine.budgets().penalty(sender),
        0,
        "policy drops are benign"
    );
}

#[test]
fn malformed_telemetry_is_attributable_but_never_relayed() {
    let mut engine = engine(0);
    link_up(&mut engine, LinkId::new(1));
    link_up(&mut engine, LinkId::new(2));
    let sender = LinkId::new(1);
    let identity = Identity::from_seed([3; 32]);
    let wire = framed_packet(
        &Identity::from_seed([1; 32]),
        7,
        Wire {
            seq: 1,
            ttl: 3,
            hops: 0,
            lifetime_s: 30,
            created_ms: 0,
        },
        b"too short",
    );
    let mut frame = Packet::decode(&wire).unwrap().payload.to_vec();
    frame.truncate(
        TelemetryFrame::encode(TelemetryKind::new(7), 1, b"")
            .unwrap()
            .len()
            - 1,
    );
    let mut header = Packet::decode(&wire).unwrap().header;
    header.payload_len = frame.len() as u64;
    let signer = Identity::from_seed([1; 32]);
    let signature = sign_packet(&signer, &mut header, &frame).unwrap();
    let malformed = Packet::new(header, signature, &frame).unwrap().encode();
    let outputs = engine
        .handle(
            10_000,
            MeshInput::Data {
                link: sender,
                channel: Channel::Telemetry,
                payload: &malformed,
                identity: &identity,
            },
        )
        .unwrap();
    assert!(outputs.is_empty());
    assert_eq!(engine.budgets().penalty(sender), 3);
    assert!(engine.telemetry().is_empty());
}
