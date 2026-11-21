//! MSH-16 acceptance: capability-negotiated copy envelopes and tickets.
mod common;

use ao_idents::Identity;
use ao_mesh::{
    CAP_SPRAY_V1, CAPS, MeshEngine, MeshHello, MeshInput, MeshOutput, SPRAY_MAGIC, sign_packet,
};
use ao_network::{AppHello, Channel, Hello, LinkId, LocalTag};
use rand::{SeedableRng, rngs::StdRng};

const LINK: LinkId = LinkId::new(1);
fn engine() -> MeshEngine<StdRng> {
    MeshEngine::new(StdRng::seed_from_u64(0x16))
}

fn hello(identity: &Identity, caps: u32) -> Hello {
    let signed = MeshHello::sign_with_caps(identity, [0; 8], [0; 4], caps)
        .expect("fixed identity signs hello");
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps: signed.caps,
        max_frame: 16384,
        tag: LocalTag::new([1; 16]),
        app_hello: AppHello::new(signed.encode().to_vec()).expect("hello fits"),
    }
}

fn link_up(engine: &mut MeshEngine<StdRng>, identity: &Identity, caps: u32) {
    let _ = engine
        .handle(
            10,
            MeshInput::LinkUp {
                link: LINK,
                remote_hello: hello(identity, caps),
            },
        )
        .expect("verified hello");
}

fn submit(engine: &mut MeshEngine<StdRng>, from: &Identity, to: &Identity) -> Vec<u8> {
    let (mut header, payload) = common::seal_for(
        from,
        to,
        100,
        ao_mesh::PacketClass::Direct,
        |_| {},
        b"spray",
    );
    let signature = sign_packet(from, &mut header, &payload).expect("fixed key signs");
    let packet = ao_mesh::Packet::new(header, signature, &payload).expect("lengths agree");
    let wire = packet.encode();
    let outputs = engine
        .handle(
            100,
            MeshInput::Submit {
                identity: from,
                header: packet.header,
                payload: &payload,
                via: Some(LINK),
            },
        )
        .expect("valid submission");
    assert_eq!(outputs.len(), 1, "one link, one copy");
    let MeshOutput::Send { payload, .. } = &outputs[0] else {
        panic!("expected a send, got {outputs:?}");
    };
    assert!(payload.starts_with(&[SPRAY_MAGIC, 1, 1]), "spray envelope");
    assert!(
        payload.ends_with(&wire),
        "inner packet is authenticated unchanged"
    );
    payload.clone()
}

#[test]
fn capable_peer_receives_a_copy_envelope() {
    let mut engine = engine();
    let remote = Identity::from_seed([7; 32]);
    link_up(&mut engine, &remote, CAPS);
    submit(&mut engine, &Identity::from_seed([1; 32]), &remote);
}

#[test]
fn legacy_peer_gets_the_raw_packet() {
    let mut engine = engine();
    let remote = Identity::from_seed([7; 32]);
    link_up(&mut engine, &remote, 0);
    let (mut header, payload) = common::seal_for(
        &Identity::from_seed([1; 32]),
        &remote,
        100,
        ao_mesh::PacketClass::Direct,
        |_| {},
        b"legacy",
    );
    let signature =
        sign_packet(&Identity::from_seed([1; 32]), &mut header, &payload).expect("fixed key signs");
    let packet = ao_mesh::Packet::new(header, signature, &payload).expect("lengths agree");
    let outputs = engine
        .handle(
            100,
            MeshInput::Submit {
                identity: &Identity::from_seed([1; 32]),
                header: packet.header,
                payload: &payload,
                via: Some(LINK),
            },
        )
        .expect("valid submission");
    let [MeshOutput::Send { payload: sent, .. }] = outputs.as_slice() else {
        panic!("expected a send, got {outputs:?}");
    };
    assert_eq!(sent.first(), Some(&1), "ordinary packet version, not spray");
}

#[test]
fn a_capable_link_delivers_an_enveloped_packet_with_its_ticket() {
    let local = Identity::from_seed([3; 32]);
    let remote = Identity::from_seed([7; 32]);
    let mut engine = engine();
    link_up(&mut engine, &remote, CAP_SPRAY_V1);
    let wire = common::sealed(
        &Identity::from_seed([1; 32]),
        &local,
        100,
        ao_mesh::PacketClass::Direct,
        |_| {},
        b"hello",
    );
    let mut envelope = vec![SPRAY_MAGIC, 1, 1, 3];
    envelope.extend_from_slice(&(wire.len() as u16).to_le_bytes());
    envelope.extend_from_slice(&wire);
    let outputs = engine
        .handle(
            110,
            MeshInput::Data {
                link: LINK,
                channel: Channel::Message,
                payload: &envelope,
                identity: &local,
            },
        )
        .expect("valid enveloped data");
    assert!(
        outputs
            .iter()
            .any(|output| matches!(output, MeshOutput::Deliver { .. }))
    );
    assert!(
        outputs
            .iter()
            .any(|output| matches!(output, MeshOutput::SyncItem { copies_left: 3, .. }))
    );
}

#[test]
fn a_stray_envelope_from_a_legacy_peer_is_not_delivered() {
    let local = Identity::from_seed([3; 32]);
    let remote = Identity::from_seed([7; 32]);
    let mut engine = engine();
    link_up(&mut engine, &remote, 0);
    let wire = common::sealed(
        &Identity::from_seed([1; 32]),
        &local,
        100,
        ao_mesh::PacketClass::Direct,
        |_| {},
        b"hello",
    );
    let mut envelope = vec![SPRAY_MAGIC, 1, 1, 3];
    envelope.extend_from_slice(&(wire.len() as u16).to_le_bytes());
    envelope.extend_from_slice(&wire);
    let outputs = engine
        .handle(
            110,
            MeshInput::Data {
                link: LINK,
                channel: Channel::Message,
                payload: &envelope,
                identity: &local,
            },
        )
        .expect("input is bounded even when rejected");
    assert!(
        !outputs
            .iter()
            .any(|output| matches!(output, MeshOutput::Deliver { .. }))
    );
}

#[test]
fn a_relay_splits_a_ticket_towards_the_destination() {
    let relay = Identity::from_seed([3; 32]);
    let source = Identity::from_seed([1; 32]);
    let destination = Identity::from_seed([4; 32]);
    let link_a = LinkId::new(1);
    let link_b = LinkId::new(2);
    let mut engine = engine();
    for (link, peer) in [(link_a, &source), (link_b, &destination)] {
        let _ = engine
            .handle(
                10,
                MeshInput::LinkUp {
                    link,
                    remote_hello: hello(peer, CAPS),
                },
            )
            .expect("verified hello");
    }
    let wire = common::sealed(
        &source,
        &destination,
        100,
        ao_mesh::PacketClass::Direct,
        |_| {},
        b"relay",
    );
    let mut envelope = vec![SPRAY_MAGIC, 1, 1, 4];
    envelope.extend_from_slice(&(wire.len() as u16).to_le_bytes());
    envelope.extend_from_slice(&wire);
    let outputs = engine
        .handle(
            110,
            MeshInput::Data {
                link: link_a,
                channel: Channel::Message,
                payload: &envelope,
                identity: &relay,
            },
        )
        .expect("valid enveloped data");
    let sends: Vec<_> = outputs
        .iter()
        .filter_map(|output| match output {
            MeshOutput::Send { link, payload, .. } => Some((*link, payload.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        sends.len(),
        1,
        "only the destination gets a copy: {outputs:?}"
    );
    let (link, payload) = &sends[0];
    assert_eq!(*link, link_b);
    assert_eq!(payload[3], 1, "destination shortcut sends one copy");
}
