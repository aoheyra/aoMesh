#![cfg(all(feature = "sim", not(miri)))]
use ao_idents::Identity;
use ao_mesh::{
    AdapterEvent, ChannelId, MeshConfig, MeshEngine, MeshHello, MeshInput, MeshOutput,
    NetworkAdapter,
};
use ao_network::{
    AppHello, BeaconFlags, LocalTag, Network, NetworkConfig, NetworkEvent, SimConfig, SimNode,
    SimTransport, SimWorld,
};
use rand::{SeedableRng, rngs::StdRng};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
type Host = NetworkAdapter<StdRng, SimTransport>;
struct Node {
    host: Host,
    identity: Identity,
    deliveries: usize,
    sends: usize,
    bytes: usize,
    latency: u64,
}
impl Node {
    fn apply(&mut self, world: &SimWorld, outputs: Vec<MeshOutput>, now: u64) {
        for output in &outputs {
            if let MeshOutput::Send { payload, .. } = output {
                if ao_mesh::Packet::decode(payload)
                    .is_ok_and(|p| p.payload.starts_with(&ao_mesh::channel::CHANNEL_MAGIC))
                {
                    self.sends += 1;
                    self.bytes += payload.len();
                }
            }
        }
        let events = self.host.apply(world.now(), outputs);
        self.events(events, now);
    }
    fn events(&mut self, events: Vec<AdapterEvent>, now: u64) {
        for event in events {
            match event {
                AdapterEvent::ChannelMessage { payload, .. } => {
                    assert_eq!(payload, b"campus update");
                    self.deliveries += 1;
                    self.latency = now - 20_000;
                }
                AdapterEvent::SendFailed { error, .. } => panic!("sim send failed: {error:?}"),
                _ => {}
            }
        }
    }
}
fn scenario(n: usize, seed: u64, suppress: bool) -> (usize, usize, usize, u64) {
    let world = SimWorld::new(SimConfig {
        seed,
        ..SimConfig::default()
    });
    let channel = ChannelId::from_name("campus");
    let mut nodes: Vec<Node> = (0..n)
        .map(|i| {
            let radio = world.add_node(SimNode::default()).unwrap();
            let identity = Identity::from_seed([i as u8 + 1; 32]);
            let mut config = MeshConfig::default();
            config.presence.enabled = false;
            config.suppression.enabled = suppress;
            let engine = MeshEngine::with_config(StdRng::seed_from_u64(seed + i as u64), config);
            let mut host =
                NetworkAdapter::new(engine, Network::new(NetworkConfig::default(), radio));
            if i > 0 && i % 2 == 0 {
                host.engine_mut().channels_mut().subscribe(channel).unwrap();
            }
            let intro = MeshHello::sign(&identity, [0; 8], [0; 4]).unwrap();
            let setup = vec![
                MeshOutput::SetHello {
                    tag: LocalTag::new([i as u8 + 1; 16]),
                    app_hello: AppHello::new(intro.encode().to_vec()).unwrap(),
                },
                MeshOutput::SetBeacon {
                    hint: [0; 8],
                    digest: [0; 4],
                    flags: BeaconFlags {
                        accepting: true,
                        relay_willing: true,
                        low_battery: false,
                    },
                },
            ];
            assert!(host.apply(world.now(), setup).is_empty());
            Node {
                host,
                identity,
                deliveries: 0,
                sends: 0,
                bytes: 0,
                latency: 0,
            }
        })
        .collect();
    for a in 0..n {
        for b in a + 1..n {
            let distance = b - a;
            let connected = if n == 5 {
                distance == 1
            } else {
                distance == 1 || distance == n - 1 || distance == 5 || distance == n - 5
            };
            world.set_in_range(
                nodes[a].host.network().transport().node(),
                nodes[b].host.network().transport().node(),
                connected,
            );
        }
    }
    let mut cx = Context::from_waker(Waker::noop());
    for step in 0..800 {
        let now = step * 50;
        if now == 20_000 {
            let node = &mut nodes[0];
            let out = node
                .host
                .engine_mut()
                .handle(
                    now,
                    MeshInput::SubmitChannel {
                        identity: &node.identity,
                        channel,
                        payload: b"campus update",
                    },
                )
                .unwrap();
            node.apply(&world, out, now);
        }
        for node in &mut nodes {
            loop {
                let event = match node.host.network_mut().poll_event(&mut cx, world.now()) {
                    Poll::Pending => break,
                    Poll::Ready(event) => event,
                };
                let input = match event {
                    NetworkEvent::LinkUp { link, remote_hello } => {
                        MeshInput::LinkUp { link, remote_hello }
                    }
                    NetworkEvent::LinkDown { link, reason } => MeshInput::LinkDown { link, reason },
                    NetworkEvent::Data {
                        link,
                        channel,
                        ref payload,
                    } => MeshInput::Data {
                        link,
                        channel,
                        payload,
                        identity: &node.identity,
                    },
                    _ => continue,
                };
                let out = node.host.engine_mut().handle(now, input).unwrap();
                node.apply(&world, out, now);
            }

            let out = node
                .host
                .engine_mut()
                .handle(
                    now,
                    MeshInput::Tick {
                        identity: &node.identity,
                        card_hash: [0; 8],
                    },
                )
                .unwrap();
            node.apply(&world, out, now);
        }
        world.advance(Duration::from_millis(50));
    }
    for (i, node) in nodes.iter().enumerate() {
        assert!(
            node.bytes < 512 * 1024,
            "node {i} exceeded Broadcast budget"
        );
        assert_eq!(
            node.deliveries,
            usize::from(i > 0 && i % 2 == 0),
            "node {i}, n={n}, suppress={suppress}"
        );
    }
    (
        nodes.iter().map(|n| n.deliveries).sum(),
        nodes.iter().map(|n| n.sends).sum(),
        nodes.iter().map(|n| n.bytes).sum(),
        nodes.iter().map(|n| n.latency).max().unwrap(),
    )
}
#[test]
fn subscribers_receive_across_unsubscribed_relays_inside_broadcast_budget() {
    for (n, seed) in [(5, 0x4d534823), (20, 0x4d534829)] {
        for suppress in [false, true] {
            let (delivered, sends, bytes, latency) = scenario(n, seed, suppress);
            println!(
                "channels,n={n},seed={seed},suppression={suppress},delivered={delivered},sends={sends},bytes={bytes},max_latency_ms={latency}"
            );
            // A single small message remains well below ADR-0001's 512 KiB/h Broadcast budget at every node.
            assert!(bytes < n * 512 * 1024);
        }
    }
}
