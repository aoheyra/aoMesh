//! Three simulated neighbours exchanging an originated mesh packet.
//! Counts structural reception only; verified delivery belongs to MSH-09.
use ao_idents::Identity;
use ao_mesh::{Header, MeshEngine, MeshInput, MeshOutput, NetworkAdapter, PacketClass};
use ao_network::{
    AppHello, BeaconFlags, LocalTag, Network, NetworkConfig, SimConfig, SimNode, SimTransport,
    SimWorld,
};
use rand::{SeedableRng, rngs::StdRng};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

type Adapter = NetworkAdapter<StdRng, SimTransport>;
fn pump(world: &SimWorld, nodes: &mut [Adapter]) -> Result<(), Box<dyn std::error::Error>> {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..200 {
        world.advance(Duration::from_millis(10));
        for node in nodes.iter_mut() {
            while let Poll::Ready(result) =
                node.poll_event(&mut cx, world.now(), world.now().as_millis() as u64)
            {
                if !result?.is_empty() {
                    return Err("unexpected adapter event".into());
                }
            }
        }
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    const SEED: u64 = 0x6006;
    let world = SimWorld::new(SimConfig {
        seed: SEED,
        ..SimConfig::default()
    });
    let mut nodes = Vec::new();
    for i in 1..=3u8 {
        let radio = world.add_node(SimNode::default())?;
        let mut node = NetworkAdapter::new(
            MeshEngine::new(StdRng::seed_from_u64(SEED)),
            Network::new(NetworkConfig::default(), radio),
        );
        let events = node.apply(vec![
            MeshOutput::SetHello {
                tag: LocalTag::new([i; 16]),
                app_hello: AppHello::new(Vec::new())?,
            },
            MeshOutput::SetBeacon {
                hint: [i; 8],
                digest: [0; 4],
                flags: BeaconFlags {
                    accepting: true,
                    ..BeaconFlags::default()
                },
            },
        ]);
        if !events.is_empty() {
            return Err("unexpected setup event".into());
        }
        nodes.push(node);
    }
    for a in 0..nodes.len() {
        for b in a + 1..nodes.len() {
            world.set_in_range(
                nodes[a].network().transport().node(),
                nodes[b].network().transport().node(),
                true,
            );
        }
    }
    pump(&world, &mut nodes)?;
    // Public, fixed demonstration identity only; never use this seed on a phone.
    let identity = Identity::from_seed([1; 32]);
    let header = Header {
        class: PacketClass::Broadcast,
        dst: None,
        origin: [0; 16],
        msg_id: [0; 16].into(),
        created_ms: 2000,
        lifetime_s: 600,
        payload_len: 4,
        ttl: 6,
        hops: 0,
    };
    let events = nodes[0].handle(
        2000,
        MeshInput::Submit {
            identity: &identity,
            header,
            payload: b"demo",
            via: None,
        },
    )?;
    if !events.is_empty() {
        return Err("submission was not admitted".into());
    }
    pump(&world, &mut nodes)?;
    for (i, node) in nodes.iter().enumerate() {
        let received: u64 = node
            .engine()
            .neighbors()
            .iter()
            .map(|n| n.received_packets)
            .sum();
        let expected = u64::from(i != 0);
        if received != expected {
            return Err("unexpected structural packet count".into());
        }
        println!(
            "node {}: {} neighbours, {} structurally valid packets",
            i + 1,
            node.engine().neighbors().len(),
            received
        );
    }
    println!("seed {SEED:#x}; no application delivery or multihop routing claimed");
    Ok(())
}
