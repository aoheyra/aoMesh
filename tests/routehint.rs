//! MSH-21 acceptance after the MSH-20 rebase: hints derive from directory
//! observations, Off behaviour is identical, and a Direct packet is delivered
//! along a substituted hint.
mod common;

use ao_idents::Identity;
use ao_mesh::{
    CAP_SPRAY_V1, Header, MeshConfig, MeshEngine, MeshHello, MeshInput, MeshOutput,
    NodeObservation, Packet, PacketClass, RouteHintConfig, RouteHintMode, SPRAY_MAGIC, sign_packet,
};
use ao_network::{AppHello, Channel, Hello, LinkId, LocalTag};
use rand::{SeedableRng, rngs::StdRng};

const SOURCE_LINK: LinkId = LinkId::new(1);
const OTHER_LINK: LinkId = LinkId::new(2);
const HINT_LINK: LinkId = LinkId::new(3);

fn engine(mode: RouteHintMode) -> MeshEngine<StdRng> {
    MeshEngine::with_config(
        StdRng::seed_from_u64(0x21),
        MeshConfig {
            route_hint: RouteHintConfig {
                mode,
                ..RouteHintConfig::default()
            },
            ..MeshConfig::default()
        },
    )
}

fn hello(identity: &Identity) -> Hello {
    let signed = MeshHello::sign_with_caps(identity, [0; 8], [0; 4], CAP_SPRAY_V1)
        .expect("fixed identity signs hello");
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps: signed.caps,
        max_frame: 16_384,
        tag: LocalTag::new([1; 16]),
        app_hello: AppHello::new(signed.encode().to_vec()).expect("hello fits"),
    }
}

fn link_up(engine: &mut MeshEngine<StdRng>, link: LinkId, identity: &Identity) {
    let _ = engine
        .handle(
            10,
            MeshInput::LinkUp {
                link,
                remote_hello: hello(identity),
            },
        )
        .expect("verified hello");
}

fn observation(
    destination: &Identity,
    via: &Identity,
    hops: u8,
    seq: u64,
) -> NodeObservation<'static> {
    NodeObservation {
        node: destination.node_id(),
        card_hash: [0; 8],
        caps: 0,
        seq,
        hops,
        via: via.node_id(),
        observed_at_ms: 20,
        location: &[],
    }
}

fn observe(engine: &mut MeshEngine<StdRng>, now: u64, observation: NodeObservation<'static>) {
    let _ = engine
        .handle(now, MeshInput::ObserveNode { observation })
        .expect("bounded directory input");
}

fn tick(engine: &mut MeshEngine<StdRng>, now: u64, identity: &Identity) {
    let _ = engine
        .handle(
            now,
            MeshInput::Tick {
                identity,
                card_hash: [0; 8],
            },
        )
        .expect("valid tick");
}

fn sealed_wire(sender: &Identity, recipient: &Identity) -> Vec<u8> {
    let (mut header, payload) = common::seal_for(
        sender,
        recipient,
        100,
        PacketClass::Direct,
        |_: &mut Header| {},
        b"route hint",
    );
    let signature = sign_packet(sender, &mut header, &payload).expect("fixed key signs");
    Packet::new(header, signature, &payload)
        .expect("lengths agree")
        .encode()
}

fn spray_envelope(copies: u8, wire: &[u8]) -> Vec<u8> {
    let mut envelope = vec![SPRAY_MAGIC, 1, 1, copies];
    envelope.extend_from_slice(&(wire.len() as u16).to_le_bytes());
    envelope.extend_from_slice(wire);
    envelope
}

fn sends(outputs: &[MeshOutput]) -> Vec<(LinkId, Vec<u8>)> {
    outputs
        .iter()
        .filter_map(|output| match output {
            MeshOutput::Send { link, payload, .. } => Some((*link, payload.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn observations_from_unknown_or_unverified_links_are_ignored() {
    let destination = Identity::from_seed([9; 32]);
    let peer = Identity::from_seed([7; 32]);
    let mut engine = engine(RouteHintMode::SubstituteCopy);
    observe(&mut engine, 20, observation(&destination, &peer, 2, 1));
    assert!(
        engine.route_hints().is_empty(),
        "unknown via-node has no verified link"
    );

    // A link admitted with a failed hello is verified by neither table.
    let _ = engine
        .handle(
            10,
            MeshInput::LinkUp {
                link: SOURCE_LINK,
                remote_hello: Hello {
                    app_hello: AppHello::new(vec![0; 8]).expect("bounded hello blob"),
                    ..hello(&peer)
                },
            },
        )
        .expect("rejected hello is still counted");
    observe(&mut engine, 20, observation(&destination, &peer, 2, 1));
    assert!(engine.route_hints().is_empty());
}

#[test]
fn off_mode_leaves_submission_outputs_identical() {
    let sender = Identity::from_seed([1; 32]);
    let peer = Identity::from_seed([7; 32]);
    let destination = Identity::from_seed([9; 32]);
    let mut baseline = engine(RouteHintMode::Off);
    let mut hinted = engine(RouteHintMode::SubstituteCopy);
    for engine in [&mut baseline, &mut hinted] {
        link_up(engine, SOURCE_LINK, &peer);
        observe(engine, 20, observation(&destination, &peer, 2, 1));
    }
    assert!(baseline.route_hints().is_empty());
    assert_eq!(hinted.route_hints().len(), 1);

    let (header, payload) = common::seal_for(
        &sender,
        &destination,
        100,
        PacketClass::Direct,
        |_: &mut Header| {},
        b"route hint",
    );
    let mut outputs = Vec::new();
    for engine in [&mut baseline, &mut hinted] {
        outputs.push(
            engine
                .handle(
                    100,
                    MeshInput::Submit {
                        identity: &sender,
                        header,
                        payload: &payload,
                        via: None,
                    },
                )
                .expect("valid submission"),
        );
    }
    assert_eq!(outputs[0], outputs[1]);
}

#[test]
fn a_substituted_hint_carries_a_direct_packet_to_its_destination() {
    let sender = Identity::from_seed([1; 32]);
    let other = Identity::from_seed([5; 32]);
    let intermediate = Identity::from_seed([7; 32]);
    let destination = Identity::from_seed([9; 32]);

    // The relay has three links. A two-ticket spray copy would go to the
    // lower-id non-sender link; the hint points at the other one.
    let mut relay = engine(RouteHintMode::SubstituteCopy);
    link_up(&mut relay, SOURCE_LINK, &sender);
    link_up(&mut relay, OTHER_LINK, &other);
    link_up(&mut relay, HINT_LINK, &intermediate);
    observe(
        &mut relay,
        20,
        observation(&destination, &intermediate, 2, 1),
    );
    let wire = sealed_wire(&sender, &destination);
    let envelope = spray_envelope(2, &wire);
    let outputs = relay
        .handle(
            110,
            MeshInput::Data {
                link: SOURCE_LINK,
                channel: Channel::Message,
                payload: &envelope,
                identity: &intermediate,
            },
        )
        .expect("valid enveloped data");
    let forwarded = sends(&outputs);
    assert_eq!(forwarded.len(), 1, "substitution does not add a send");
    assert_eq!(forwarded[0].0, HINT_LINK, "the fresh path is chosen");

    // The next hop forwards its copy to the directly connected destination.
    let mut next_hop = engine(RouteHintMode::Off);
    link_up(&mut next_hop, SOURCE_LINK, &sender);
    link_up(&mut next_hop, HINT_LINK, &destination);
    let outputs = next_hop
        .handle(
            120,
            MeshInput::Data {
                link: SOURCE_LINK,
                channel: Channel::Message,
                payload: &forwarded[0].1,
                identity: &intermediate,
            },
        )
        .expect("valid enveloped data");
    let forwarded = sends(&outputs);
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].0, HINT_LINK);

    // The destination's MSH-09 pipeline opens the sealed payload.
    let mut recipient = engine(RouteHintMode::Off);
    link_up(&mut recipient, HINT_LINK, &intermediate);
    let outputs = recipient
        .handle(
            130,
            MeshInput::Data {
                link: HINT_LINK,
                channel: Channel::Message,
                payload: &forwarded[0].1,
                identity: &destination,
            },
        )
        .expect("valid enveloped data");
    assert!(
        outputs
            .iter()
            .any(|output| matches!(output, MeshOutput::Deliver { payload, .. } if payload == b"route hint")),
        "packet delivered via the hint: {outputs:?}"
    );
}

#[test]
fn expired_hint_falls_back_to_the_ordinary_spray_plan() {
    let sender = Identity::from_seed([1; 32]);
    let other = Identity::from_seed([5; 32]);
    let intermediate = Identity::from_seed([7; 32]);
    let destination = Identity::from_seed([9; 32]);
    let mut relay = engine(RouteHintMode::SubstituteCopy);
    link_up(&mut relay, SOURCE_LINK, &sender);
    link_up(&mut relay, OTHER_LINK, &other);
    link_up(&mut relay, HINT_LINK, &intermediate);
    observe(
        &mut relay,
        20,
        observation(&destination, &intermediate, 2, 1),
    );
    let expiry = 20 + RouteHintConfig::default().lifetime_ms;
    tick(&mut relay, expiry, &sender);
    assert!(relay.route_hints().is_empty());

    let wire = sealed_wire(&sender, &destination);
    let envelope = spray_envelope(2, &wire);
    let outputs = relay
        .handle(
            expiry + 1,
            MeshInput::Data {
                link: SOURCE_LINK,
                channel: Channel::Message,
                payload: &envelope,
                identity: &intermediate,
            },
        )
        .expect("valid enveloped data");
    let forwarded = sends(&outputs);
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].0, OTHER_LINK, "unhinted spray plan restored");
}
