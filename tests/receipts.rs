//! MSH-17 engine pipeline: a delivered Direct packet produces a signed
//! receipt, the recipient and origin purge, and the origin sees Delivered.

#![cfg(feature = "adapter")]
mod common;

use ao_idents::Identity;
use ao_mesh::{
    AdapterEvent, MeshConfig, MeshEngine, MeshHello, MeshInput, MeshOutput, NetworkAdapter,
    PacketClass, sign_packet,
};
use ao_network::{
    AppHello, BeaconFlags, LocalTag, Network, NetworkConfig, SimConfig, SimNode, SimTransport,
    SimWorld,
};
use rand::{SeedableRng, rngs::StdRng};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

const SEED: u64 = 1_297_304_001;
type Adapter = NetworkAdapter<StdRng, SimTransport>;

fn identity(index: usize) -> Identity {
    if index == 0 {
        Identity::from_seed([1; 32])
    } else {
        Identity::from_seed([2; 32])
    }
}

fn node(world: &SimWorld, index: usize) -> Adapter {
    let own = identity(index);
    let radio = world.add_node(SimNode::default()).unwrap();
    let network = Network::new(NetworkConfig::default(), radio);
    let engine = MeshEngine::with_config(
        StdRng::seed_from_u64(SEED ^ (index as u64 + 1)),
        MeshConfig::default(),
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

#[test]
fn delivery_purges_both_copies_and_reports_delivered_to_the_origin() {
    let world = SimWorld::new(SimConfig {
        seed: SEED,
        ..SimConfig::default()
    });
    let mut nodes = vec![node(&world, 0), node(&world, 1)];
    world.set_in_range(
        nodes[0].network().transport().node(),
        nodes[1].network().transport().node(),
        true,
    );
    let mut events = Vec::new();
    pump(&world, &mut nodes, 1_000, &mut events);
    assert_eq!(nodes[0].engine().neighbors().len(), 1);
    assert_eq!(nodes[1].engine().neighbors().len(), 1);

    let now_ms = world.now().as_millis() as u64;
    let (mut header, payload) = common::seal_for(
        &identity(0),
        &identity(1),
        now_ms,
        PacketClass::Direct,
        |h| h.ttl = 8,
        b"receipt pipeline",
    );
    let signature = sign_packet(&identity(0), &mut header, &payload).unwrap();
    let packet = ao_mesh::Packet::new(header, signature, &payload).unwrap();
    let id = packet.header.msg_id;
    let applied = nodes[0]
        .handle(
            world.now(),
            now_ms,
            MeshInput::Submit {
                identity: &identity(0),
                header: packet.header,
                payload: &payload,
                via: None,
            },
        )
        .unwrap();
    assert!(
        applied.is_empty(),
        "submission has no host events: {applied:?}"
    );

    events.clear();
    pump(&world, &mut nodes, 2_000, &mut events);

    let delivered = events
        .iter()
        .filter(|(_, event)| matches!(event, AdapterEvent::Deliver { .. }))
        .count();
    assert_eq!(delivered, 1, "exactly one local delivery");
    let purged_origin = events.iter().any(|(node, event)| {
        matches!(event, AdapterEvent::Purge { id: got } if *got == id && *node == 0)
    });
    let purged_destination = events.iter().any(|(node, event)| {
        matches!(event, AdapterEvent::Purge { id: got } if *got == id && *node == 1)
    });
    assert!(purged_origin, "origin purges its copy after the receipt");
    assert!(purged_destination, "recipient purges its copy");
    let receipts = events
        .iter()
        .filter(|(node, event)| {
            matches!(event, AdapterEvent::Delivered { id: got, .. } if *got == id && *node == 0)
        })
        .count();
    assert_eq!(receipts, 1, "origin learns Delivered exactly once");
}
