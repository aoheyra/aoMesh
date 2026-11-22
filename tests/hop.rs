//! MSH-26 hop encryption against the real aoIdents handshake and the real
//! SimWorld transport. The engine keeps no card, handshake or key; the host
//! structures in this file own all of them.
#![cfg(feature = "adapter")]

use ao_idents::{HopHandshake, HopSessions, Identity, IdentityCard, NodeId, Signature};
use ao_mesh::{
    AdapterEvent, CAPS, Header, MeshConfig, MeshEngine, MeshError, MeshHello, MeshInput,
    MeshOutput, NetworkAdapter, Packet, PacketClass, SUPPORTED_CAPS, SprayConfig,
};
use ao_network::{
    AdvProfile, AppHello, BeaconFlags, LinkId, LocalTag, Network, NetworkConfig,
    NodeId as SimNodeId, PeerKey, ScanProfile, SimConfig, SimNode, SimTransport, SimWorld,
    Transport, TransportCaps, TransportEvent,
};
use rand::{SeedableRng, rngs::StdRng};
use rand08::{SeedableRng as SeedableRng08, rngs::StdRng as StdRng08};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

type Adapter = NetworkAdapter<StdRng, CaptureTransport>;

/// Records exactly what a passive radio observer sees, then forwards the
/// chunk unchanged to the deterministic SimWorld transport.
#[derive(Clone, Default)]
struct Capture {
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Capture {
    fn clear(&self) {
        self.frames.lock().expect("capture lock").clear();
    }

    fn frames(&self) -> Vec<Vec<u8>> {
        self.frames.lock().expect("capture lock").clone()
    }
}

struct CaptureTransport {
    inner: SimTransport,
    capture: Capture,
}

impl Transport for CaptureTransport {
    fn caps(&self) -> TransportCaps {
        self.inner.caps()
    }

    fn start(&mut self) {
        self.inner.start();
    }

    fn stop(&mut self) {
        self.inner.stop();
    }

    fn set_advertising(&mut self, profile: Option<AdvProfile>) {
        self.inner.set_advertising(profile);
    }

    fn set_scanning(&mut self, profile: Option<ScanProfile>) {
        self.inner.set_scanning(profile);
    }

    fn connect(&mut self, peer: PeerKey) -> LinkId {
        self.inner.connect(peer)
    }

    fn disconnect(&mut self, link: LinkId) {
        self.inner.disconnect(link);
    }

    fn write(&mut self, link: LinkId, chunk: Vec<u8>) {
        self.frames_lock().push(chunk.clone());
        self.inner.write(link, chunk);
    }

    fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<TransportEvent> {
        self.inner.poll_event(cx)
    }
}

impl CaptureTransport {
    fn node(&self) -> SimNodeId {
        self.inner.node()
    }

    fn frames_lock(&self) -> std::sync::MutexGuard<'_, Vec<Vec<u8>>> {
        self.capture.frames.lock().expect("capture lock")
    }
}

/// Everything the host, not the mesh engine, owns for one link set.
struct TestHost {
    handshakes: HashMap<LinkId, HopHandshake>,
    sessions: HopSessions,
    rng: StdRng08,
}

impl TestHost {
    fn new(seed: u64) -> Self {
        Self {
            handshakes: HashMap::new(),
            sessions: HopSessions::new(),
            rng: StdRng08::seed_from_u64(seed),
        }
    }
}

fn engine(hop_enabled: bool) -> MeshEngine<StdRng> {
    MeshEngine::with_config(
        StdRng::seed_from_u64(0x2600),
        MeshConfig {
            hop_enabled,
            spray: SprayConfig {
                enabled: false,
                ..SprayConfig::default()
            },
            ..MeshConfig::default()
        },
    )
}

/// Builds a two-node world with the given hello capability sets. Node 0 is
/// the radio-link initiator. Both nodes use the hop-capable adapter API, so
/// the only variable is the signed capability and the engine opt-in.
fn pair(
    caps: [u32; 2],
    hop_enabled: [bool; 2],
) -> (
    SimWorld,
    Vec<Adapter>,
    Vec<Identity>,
    Vec<IdentityCard>,
    Vec<Capture>,
) {
    let world = SimWorld::new(SimConfig {
        seed: 0x2601,
        ..SimConfig::default()
    });
    let identities: Vec<Identity> = (1..=2u8)
        .map(|seed| Identity::from_seed([seed; 32]))
        .collect();
    let cards: Vec<IdentityCard> = identities
        .iter()
        .map(|id| id.card(b"hop-test", 1_700_000_000).expect("card signs"))
        .collect();
    let captures = vec![Capture::default(), Capture::default()];
    let mut nodes = Vec::new();
    for i in 0..2 {
        let radio = world.add_node(SimNode::default()).expect("sim node is new");
        let transport = CaptureTransport {
            inner: radio,
            capture: captures[i].clone(),
        };
        let mut adapter = NetworkAdapter::new(
            engine(hop_enabled[i]),
            Network::new(NetworkConfig::default(), transport),
        );
        let signed = MeshHello::sign_with_caps(
            &identities[i],
            cards[i].announcement_hash(),
            [0; 4],
            caps[i],
        )
        .expect("fixed identity signs");
        let outputs = adapter.apply(
            world.now(),
            vec![
                MeshOutput::SetHello {
                    tag: LocalTag::new([(i + 1) as u8; 16]),
                    app_hello: AppHello::new(signed.encode().to_vec()).expect("hello fits"),
                },
                MeshOutput::SetBeacon {
                    hint: [(i + 1) as u8; 8],
                    digest: [0; 4],
                    flags: BeaconFlags {
                        accepting: true,
                        ..BeaconFlags::default()
                    },
                },
            ],
        );
        assert!(outputs.is_empty(), "setup emits no sends");
        nodes.push(adapter);
    }
    world.set_in_range(
        nodes[0].network().transport().node(),
        nodes[1].network().transport().node(),
        true,
    );
    (world, nodes, identities, cards, captures)
}

fn now_ms(world: &SimWorld) -> u64 {
    world.now().as_millis() as u64
}

/// Drives the host's handshake one step. `incoming` is the Noise message just
/// received, or `None` when this side starts the exchange. The final step
/// installs the transport in the host's table and tells the adapter that
/// Data frames may now be sealed.
fn advance_handshake(
    host: &mut TestHost,
    adapter: &mut Adapter,
    world: &SimWorld,
    link: LinkId,
    peer: NodeId,
    mut handshake: HopHandshake,
    incoming: Option<&[u8]>,
) -> Vec<AdapterEvent> {
    let mut events = Vec::new();
    if let Some(message) = incoming {
        handshake
            .read_message(message)
            .expect("honest Noise message");
    }
    if !handshake.is_complete() {
        let message = handshake
            .write_message()
            .unwrap_or_else(|error| panic!("next Noise message failed: {error:?}"));
        events.extend(
            adapter
                .handle_with_hop(
                    world.now(),
                    now_ms(world),
                    MeshInput::HopControl {
                        link,
                        message: &message,
                    },
                    &mut host.sessions,
                )
                .expect("control send succeeds"),
        );
        if !handshake.is_complete() {
            host.handshakes.insert(link, handshake);
            return events;
        }
    }
    let transport = handshake.into_transport().expect("pinned card matches");
    host.sessions
        .install(peer, transport)
        .expect("session table has room");
    events.extend(
        adapter
            .handle_with_hop(
                world.now(),
                now_ms(world),
                MeshInput::HopReady { link },
                &mut host.sessions,
            )
            .expect("activation succeeds"),
    );
    events
}

fn process_events(
    events: Vec<AdapterEvent>,
    index: usize,
    adapters: &mut [Adapter],
    hosts: &mut [TestHost],
    world: &SimWorld,
    identities: &[Identity],
    cards: &[IdentityCard],
) {
    for event in events {
        match event {
            AdapterEvent::HopStart {
                link,
                peer,
                card_hash,
                initiator,
            } => {
                assert_eq!(peer, identities[1 - index].node_id());
                assert_eq!(card_hash, cards[1 - index].announcement_hash());
                let handshake = if initiator {
                    HopHandshake::initiator_pinned_by_hash(
                        &identities[index],
                        &card_hash,
                        &cards[1 - index],
                        &mut hosts[index].rng,
                    )
                } else {
                    HopHandshake::responder_pinned_by_hash(
                        &identities[index],
                        &card_hash,
                        &cards[1 - index],
                        &mut hosts[index].rng,
                    )
                }
                .expect("host card matches the signed pin");
                let more = if initiator {
                    advance_handshake(
                        &mut hosts[index],
                        &mut adapters[index],
                        world,
                        link,
                        peer,
                        handshake,
                        None,
                    )
                } else {
                    // XX responder writes only after message 1 arrives.
                    hosts[index].handshakes.insert(link, handshake);
                    Vec::new()
                };
                process_events(more, index, adapters, hosts, world, identities, cards);
            }
            AdapterEvent::HopControl {
                link,
                peer,
                card_hash,
                message,
                ..
            } => {
                assert_eq!(peer, identities[1 - index].node_id());
                assert_eq!(card_hash, cards[1 - index].announcement_hash());
                let handshake = hosts[index]
                    .handshakes
                    .remove(&link)
                    .expect("a responder or mid-handshake peer exists");
                let more = advance_handshake(
                    &mut hosts[index],
                    &mut adapters[index],
                    world,
                    link,
                    peer,
                    handshake,
                    Some(&message),
                );
                process_events(more, index, adapters, hosts, world, identities, cards);
            }
            AdapterEvent::HopFrameInvalid { link, error } => {
                panic!("link {link:?} sent an invalid hop frame: {error}")
            }
            AdapterEvent::HopFailed { link, error } => {
                panic!("link {link:?} failed hop crypto: {error:?}")
            }
            _ => {}
        }
    }
}

fn poll_node(
    adapter: &mut Adapter,
    cx: &mut Context<'_>,
    world: &SimWorld,
    identity: &Identity,
    sessions: &mut HopSessions,
) -> Poll<Result<Vec<AdapterEvent>, MeshError>> {
    adapter.poll_event_with_hop(cx, world.now(), now_ms(world), identity, sessions)
}

fn drive_handshakes(
    world: &SimWorld,
    adapters: &mut [Adapter],
    hosts: &mut [TestHost],
    identities: &[Identity],
    cards: &[IdentityCard],
) {
    let mut cx = Context::from_waker(Waker::noop());
    let mut links = Vec::new();
    for _ in 0..100 {
        world.advance(Duration::from_millis(10));
        for index in 0..2 {
            loop {
                match poll_node(
                    &mut adapters[index],
                    &mut cx,
                    world,
                    &identities[index],
                    &mut hosts[index].sessions,
                ) {
                    Poll::Pending => break,
                    Poll::Ready(result) => process_events(
                        result.expect("poll succeeds"),
                        index,
                        adapters,
                        hosts,
                        world,
                        identities,
                        cards,
                    ),
                }
            }
        }
        if links.is_empty()
            && adapters
                .iter()
                .all(|node| node.network().links().len() == 1)
        {
            links = adapters
                .iter()
                .map(|node| node.network().links()[0].link)
                .collect();
        }
        if !links.is_empty()
            && adapters
                .iter()
                .zip(&links)
                .all(|(node, link)| node.engine().hop_active(*link))
        {
            return;
        }
    }
    panic!("hop handshakes did not complete");
}

fn header(dst: NodeId) -> Header {
    Header {
        class: PacketClass::Direct,
        dst: Some(*dst.as_bytes()),
        msg_id: [0xAB; 16].into(),
        origin: [0; 16],
        created_ms: 2_000,
        lifetime_s: 3_600,
        payload_len: 4,
        ttl: 8,
        hops: 0,
    }
}

fn clear_wire(identity: &Identity, dst: NodeId) -> Vec<u8> {
    let mut head = header(dst);
    let signature: Signature =
        ao_mesh::sign_packet(identity, &mut head, b"ping").expect("origin signs");
    Packet::new(head, signature, b"ping")
        .expect("packet is valid")
        .encode()
}

#[test]
fn a_passive_observer_sees_ciphertext_and_the_peer_still_parses_the_packet() {
    let (world, mut nodes, identities, cards, captures) =
        pair([SUPPORTED_CAPS, SUPPORTED_CAPS], [true, true]);
    let mut hosts = [TestHost::new(0x1101), TestHost::new(0x1102)];
    drive_handshakes(&world, &mut nodes, &mut hosts, &identities, &cards);

    let link = nodes[0].network().links()[0].link;
    let back = nodes[1].network().links()[0].link;
    assert!(nodes[0].engine().hop_negotiated(link));
    assert!(nodes[1].engine().hop_negotiated(back));
    assert_eq!(hosts[0].sessions.len(), 1);
    assert_eq!(hosts[1].sessions.len(), 1);

    let wire = clear_wire(&identities[0], identities[1].node_id());
    captures[0].clear();
    let events = nodes[0]
        .handle_with_hop(
            world.now(),
            now_ms(&world),
            MeshInput::Submit {
                identity: &identities[0],
                header: header(identities[1].node_id()),
                payload: b"ping",
                via: Some(link),
            },
            &mut hosts[0].sessions,
        )
        .expect("submit succeeds");
    assert!(
        events
            .iter()
            .all(|event| !matches!(event, AdapterEvent::HopFailed { .. }))
    );

    let mut cx = Context::from_waker(Waker::noop());
    let mut delivered = false;
    for _ in 0..30 {
        world.advance(Duration::from_millis(10));
        for index in 0..2 {
            loop {
                match poll_node(
                    &mut nodes[index],
                    &mut cx,
                    &world,
                    &identities[index],
                    &mut hosts[index].sessions,
                ) {
                    Poll::Pending => break,
                    Poll::Ready(result) => {
                        for event in result.expect("poll succeeds") {
                            assert!(
                                !matches!(
                                    event,
                                    AdapterEvent::HopFailed { .. }
                                        | AdapterEvent::HopFrameInvalid { .. }
                                ),
                                "an honest sealed frame must not fail: {event:?}"
                            );
                        }
                    }
                }
            }
        }
        if nodes[1]
            .engine()
            .neighbors()
            .get(back)
            .unwrap()
            .received_packets
            == 1
        {
            delivered = true;
            break;
        }
    }

    let frames = captures[0].frames();
    assert!(!frames.is_empty(), "the sender put a frame on the radio");
    assert!(
        frames.iter().all(|frame| !frame
            .windows(wire.len())
            .any(|window| window == wire.as_slice())),
        "a passive observer must not see the encoded packet header"
    );
    assert!(delivered, "the peer never parsed the opened packet");
}

#[test]
fn a_link_without_the_cap_stays_cleartext_and_still_forwards() {
    let (world, mut nodes, identities, _cards, captures) = pair([CAPS, CAPS], [true, false]);
    let mut hosts = [TestHost::new(0x2201), TestHost::new(0x2202)];
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..100 {
        world.advance(Duration::from_millis(10));
        for index in 0..2 {
            loop {
                match poll_node(
                    &mut nodes[index],
                    &mut cx,
                    &world,
                    &identities[index],
                    &mut hosts[index].sessions,
                ) {
                    Poll::Pending => break,
                    Poll::Ready(result) => {
                        for event in result.expect("poll succeeds") {
                            assert!(
                                !matches!(
                                    event,
                                    AdapterEvent::HopStart { .. }
                                        | AdapterEvent::HopControl { .. }
                                        | AdapterEvent::HopFailed { .. }
                                        | AdapterEvent::HopFrameInvalid { .. }
                                ),
                                "cleartext links must not run hop events: {event:?}"
                            );
                        }
                    }
                }
            }
        }
        if nodes
            .iter()
            .all(|node| !node.engine().neighbors().is_empty())
        {
            break;
        }
    }
    let link = nodes[0].network().links()[0].link;
    assert!(!nodes[0].engine().hop_negotiated(link));

    captures[0].clear();
    nodes[0]
        .handle_with_hop(
            world.now(),
            now_ms(&world),
            MeshInput::Submit {
                identity: &identities[0],
                header: header(identities[1].node_id()),
                payload: b"ping",
                via: Some(link),
            },
            &mut hosts[0].sessions,
        )
        .expect("submit succeeds");
    for _ in 0..30 {
        world.advance(Duration::from_millis(10));
        for index in 0..2 {
            loop {
                match poll_node(
                    &mut nodes[index],
                    &mut cx,
                    &world,
                    &identities[index],
                    &mut hosts[index].sessions,
                ) {
                    Poll::Pending => break,
                    Poll::Ready(result) => {
                        result.expect("poll succeeds");
                    }
                }
            }
        }
    }
    let back = nodes[1].network().links()[0].link;
    assert_eq!(
        nodes[1]
            .engine()
            .neighbors()
            .get(back)
            .unwrap()
            .received_packets,
        1
    );
    assert!(
        captures[0]
            .frames()
            .iter()
            .any(|frame| frame.windows(4).any(|window| window == b"ping")),
        "a cleartext link must carry the packet body unchanged"
    );
}
