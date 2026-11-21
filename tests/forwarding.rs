//! MSH-08 baseline forwarding on aoNetwork's SimWorld: a line, a ring
//! and a seeded random graph, each checked for delivery and for the
//! absence of loops. Payloads are sealed with the MSH-09 recipe so the
//! destination's authenticated pipeline emits the delivery.
#![cfg(feature = "adapter")]
mod common;
use ao_idents::Identity;
use ao_mesh::{
    AdapterEvent, MeshConfig, MeshEngine, MeshHello, MeshInput, MeshOutput, NetworkAdapter,
    PacketClass, ReceiptConfig, SprayConfig,
};
use ao_network::{
    AppHello, BeaconFlags, LocalTag, Network, NetworkConfig, SimConfig, SimNode, SimTransport,
    SimWorld,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::collections::BTreeSet;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

type Adapter = NetworkAdapter<StdRng, SimTransport>;
const SEED: u64 = 0x0B08_2026;
const PAYLOAD: &[u8] = b"baseline forwarding";

/// The fixed demonstration identity for node `index`.
fn identity(index: usize) -> Identity {
    Identity::from_seed([(index as u8 + 1); 32])
}

/// One simulated node with a signed MeshHello and an accepting beacon.
fn node(world: &SimWorld, index: usize) -> Adapter {
    let own = identity(index);
    let radio = world.add_node(SimNode::default()).unwrap();
    let network = Network::new(NetworkConfig::default(), radio);
    let engine = MeshEngine::with_config(
        StdRng::seed_from_u64(SEED),
        MeshConfig {
            spray: SprayConfig {
                enabled: false,
                ..SprayConfig::default()
            },
            receipt: ReceiptConfig {
                enabled: false,
                ..ReceiptConfig::default()
            },
            ..MeshConfig::default()
        },
    );
    let mut adapter = NetworkAdapter::new(engine, network);
    let signed = MeshHello::sign(&own, [0; 8], [0; 4]).unwrap();
    let applied = adapter.apply(
        world.now(),
        vec![
            MeshOutput::SetHello {
                tag: LocalTag::new([(index as u8 + 1); 16]),
                app_hello: AppHello::new(signed.encode().to_vec()).unwrap(),
            },
            MeshOutput::SetBeacon {
                hint: [(index as u8 + 1); 8],
                digest: [0; 4],
                flags: BeaconFlags {
                    accepting: true,
                    ..BeaconFlags::default()
                },
            },
        ],
    );
    assert!(applied.is_empty(), "setup emits no host events");
    adapter
}

/// Advances the world one step per ten mesh milliseconds, collecting
/// host events so the assertions decide what may appear.
fn pump(
    world: &SimWorld,
    nodes: &mut [Adapter],
    steps: usize,
    events: &mut Vec<(usize, AdapterEvent)>,
) {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..steps {
        world.advance(Duration::from_millis(10));
        for (i, node) in nodes.iter_mut().enumerate() {
            let own = identity(i);
            while let Poll::Ready(result) =
                node.poll_event(&mut cx, world.now(), world.now().as_millis() as u64, &own)
            {
                for event in result.unwrap() {
                    events.push((i, event));
                }
            }
        }
    }
}

/// Nodes, their in-range edges and the degree each must end up with.
struct Graph {
    world: SimWorld,
    nodes: Vec<Adapter>,
    degree: Vec<usize>,
}

/// Builds the nodes and marks only `edges` in range, so the radio
/// topology cannot gain or lose a link behind the test's back.
fn graph(seeds: usize, edges: &[(usize, usize)]) -> Graph {
    let world = SimWorld::new(SimConfig {
        seed: SEED,
        ..SimConfig::default()
    });
    let nodes: Vec<Adapter> = (0..seeds).map(|i| node(&world, i)).collect();
    let mut degree = vec![0usize; seeds];
    for &(a, b) in edges {
        world.set_in_range(
            nodes[a].network().transport().node(),
            nodes[b].network().transport().node(),
            true,
        );
        degree[a] += 1;
        degree[b] += 1;
    }
    Graph {
        world,
        nodes,
        degree,
    }
}

impl Graph {
    /// Drives discovery until every node holds exactly its graph degree.
    fn form_links(&mut self, events: &mut Vec<(usize, AdapterEvent)>) {
        for _ in 0..1_000 {
            pump(&self.world, &mut self.nodes, 10, events);
            if self
                .nodes
                .iter()
                .zip(&self.degree)
                .all(|(node, &want)| node.engine().neighbors().len() == want)
            {
                return;
            }
        }
        let actual: Vec<usize> = self
            .nodes
            .iter()
            .map(|node| node.engine().neighbors().len())
            .collect();
        panic!("links did not form: got {actual:?}, want {:?}", self.degree);
    }
}

/// Node zero originates `PAYLOAD` as Direct for node `dst`, with the
/// ADR-0001 Direct hop limit of 8.
fn submit(g: &mut Graph, dst: usize) {
    let origin = identity(0);
    let now_ms = g.world.now().as_millis() as u64;
    let (header, payload) = common::seal_for(
        &origin,
        &identity(dst),
        now_ms,
        PacketClass::Direct,
        |h| h.ttl = 8,
        PAYLOAD,
    );
    let events = g
        .nodes
        .get_mut(0)
        .expect("graph is not empty")
        .handle(
            g.world.now(),
            now_ms,
            MeshInput::Submit {
                identity: &origin,
                header,
                payload: &payload,
                via: None,
            },
        )
        .unwrap();
    assert!(
        events.is_empty(),
        "submission emits no host events: {events:?}"
    );
}

/// Exactly one delivery, at `dst`, carrying the origin's payload; no
/// send ever failed along the way.
fn assert_delivered_once(events: &[(usize, AdapterEvent)], dst: usize) {
    let mut delivered = Vec::new();
    for &(i, ref event) in events {
        match event {
            AdapterEvent::Deliver { header, payload } => {
                assert_eq!(header.class, PacketClass::Direct);
                assert_eq!(
                    header.dst,
                    Some(*identity(dst).node_id().as_bytes()),
                    "delivery must be addressed to the destination"
                );
                delivered.push((i, payload.as_slice()));
            }
            AdapterEvent::SendFailed { link, error } => {
                panic!("send failed on {link:?}: {error:?}")
            }
            AdapterEvent::SyncNeed { .. } | AdapterEvent::SyncItem { .. } => {
                panic!("unexpected sync event in a forwarding test: {event:?}")
            }
            AdapterEvent::Purge { .. }
            | AdapterEvent::Delivered { .. }
            | AdapterEvent::CardFetch { .. } => {
                panic!("unexpected receipt or presence event in a forwarding test: {event:?}")
            }
            AdapterEvent::DirectoryChanged { .. } => {
                panic!("unexpected directory event in a forwarding test: {event:?}")
            }
        }
    }
    assert_eq!(delivered, [(dst, PAYLOAD)], "one delivery, at dst");
}

/// Every neighbour link carried this message at most once. A node that
/// relayed twice, or an origin re-relaying its own submission, would
/// show a second reception at some neighbour, which is exactly how a
/// loop pays for itself on a cyclic topology.
fn assert_no_loops(nodes: &[Adapter]) {
    for (i, node) in nodes.iter().enumerate() {
        for neighbor in node.engine().neighbors().iter() {
            assert!(
                neighbor.received_packets <= 1,
                "node {i} received {} copies over link {:?}",
                neighbor.received_packets,
                neighbor.link
            );
        }
    }
}

/// Total structurally valid receptions per node.
fn receptions(nodes: &[Adapter]) -> Vec<u64> {
    nodes
        .iter()
        .map(|node| {
            node.engine()
                .neighbors()
                .iter()
                .map(|neighbor| neighbor.received_packets)
                .sum()
        })
        .collect()
}

/// A connected random graph on `n` nodes: a spanning tree plus extra
/// edges, every degree at or under aoNetwork's default cap of 5.
fn random_graph(n: usize, extra_target: usize, rng: &mut StdRng) -> Vec<(usize, usize)> {
    const DEGREE_CAP: usize = 5;
    let mut edges = Vec::new();
    let mut degree = vec![0usize; n];
    let mut seen = BTreeSet::new();
    for i in 1..n {
        let j = rng.random_range(0..i);
        edges.push((i, j));
        degree[i] += 1;
        degree[j] += 1;
        seen.insert((j, i));
    }
    let mut extra = 0;
    let mut attempts = 0;
    while extra < extra_target && attempts < 10_000 {
        attempts += 1;
        let a = rng.random_range(0..n);
        let b = rng.random_range(0..n);
        if a == b
            || degree[a] >= DEGREE_CAP
            || degree[b] >= DEGREE_CAP
            || !seen.insert((a.min(b), a.max(b)))
        {
            continue;
        }
        edges.push((a, b));
        degree[a] += 1;
        degree[b] += 1;
        extra += 1;
    }
    assert_eq!(extra, extra_target, "extra edge generation stalled");
    edges
}

/// Breadth-first hop distance from `from`; panics if `edges` leave any
/// node unreachable, so a broken generator cannot pass silently.
fn distances(n: usize, edges: &[(usize, usize)], from: usize) -> Vec<usize> {
    let mut adjacent = vec![Vec::new(); n];
    for &(a, b) in edges {
        adjacent[a].push(b);
        adjacent[b].push(a);
    }
    let mut dist = vec![usize::MAX; n];
    dist[from] = 0;
    let mut queue = vec![from];
    let mut head = 0;
    while head < queue.len() {
        let u = queue[head];
        head += 1;
        for &v in &adjacent[u] {
            if dist[v] == usize::MAX {
                dist[v] = dist[u] + 1;
                queue.push(v);
            }
        }
    }
    assert!(
        dist.iter().all(|&d| d != usize::MAX),
        "graph is disconnected"
    );
    dist
}

#[test]
fn five_node_line_delivers_once_with_one_reception_per_link() {
    let edges = [(0, 1), (1, 2), (2, 3), (3, 4)];
    let mut g = graph(5, &edges);
    let mut events = Vec::new();
    g.form_links(&mut events);
    assert_eq!(g.degree, [1, 2, 2, 2, 1]);
    submit(&mut g, 4);
    pump(&g.world, &mut g.nodes, 300, &mut events);
    assert_delivered_once(&events, 4);
    assert_no_loops(&g.nodes);
    // Exactly one copy per link along the chain, and nothing ever
    // travels back toward the origin.
    assert_eq!(receptions(&g.nodes), [0, 1, 1, 1, 1]);
}

#[test]
fn six_node_ring_dedupes_the_second_arrival_without_extra_receptions() {
    let edges = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 0)];
    let mut g = graph(6, &edges);
    let mut events = Vec::new();
    g.form_links(&mut events);
    assert!(g.degree.iter().all(|&d| d == 2));
    submit(&mut g, 3);
    pump(&g.world, &mut g.nodes, 300, &mut events);
    // Both directions flood toward the destination; the second copy is
    // dropped by dedupe instead of delivering or turning around.
    assert_delivered_once(&events, 3);
    assert_no_loops(&g.nodes);
    assert_eq!(receptions(&g.nodes), [0, 1, 1, 2, 1, 1]);
}

#[test]
fn seeded_random_graph_delivers_once_within_the_default_ttl_without_loops() {
    let mut rng = StdRng::seed_from_u64(SEED);
    let edges = random_graph(20, 15, &mut rng);
    let dist = distances(20, &edges, 0);
    let farthest = dist.iter().copied().max().expect("graph is not empty");
    // The ADR-0001 Direct hop limit must reach every node even when a
    // longer path's copy arrives first and spends more of its ttl.
    assert!(
        farthest <= 6,
        "TTL 8 needs slack for detours: farthest node is {farthest} hops away"
    );
    let dst = dist
        .iter()
        .position(|&d| d == farthest)
        .expect("a farthest node exists");
    let mut g = graph(20, &edges);
    let mut events = Vec::new();
    g.form_links(&mut events);
    submit(&mut g, dst);
    pump(&g.world, &mut g.nodes, 300, &mut events);
    assert_delivered_once(&events, dst);
    assert_no_loops(&g.nodes);
    // The loop invariant in its total form: two receptions per
    // undirected edge at most.
    let total: u64 = receptions(&g.nodes).iter().sum();
    assert!(
        total <= 2 * edges.len() as u64,
        "{total} receptions over {} edges",
        edges.len()
    );
}
