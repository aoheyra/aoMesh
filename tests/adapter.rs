//! Facade-to-engine integration on the real SimWorld, with no radio mocks.
#![cfg(feature = "adapter")]
use ao_idents::Identity;
use ao_mesh::{
    AdapterEvent, Header, MeshConfig, MeshEngine, MeshHello, MeshInput, MeshOutput, NetworkAdapter,
    PacketClass,
};
use ao_network::{
    AppHello, BeaconFlags, Channel, DisconnectReason, LinkId, LocalTag, Network, NetworkConfig,
    SendError, SimConfig, SimNode, SimTransport, SimWorld,
};
use rand::{SeedableRng, rngs::StdRng};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

type Adapter = NetworkAdapter<StdRng, SimTransport>;
const SEED: u64 = 0x6006;
fn pair() -> (SimWorld, Vec<Adapter>) {
    let world = SimWorld::new(SimConfig {
        seed: SEED,
        ..SimConfig::default()
    });
    let mut nodes: Vec<Adapter> = (1..=2u8)
        .map(|i| {
            let radio = world.add_node(SimNode::default()).unwrap();
            let network = Network::new(NetworkConfig::default(), radio);
            let identity = Identity::from_seed([i; 32]);
            let engine = MeshEngine::new(StdRng::seed_from_u64(SEED));
            let mut adapter = NetworkAdapter::new(engine, network);
            let signed = MeshHello::sign(&identity, [0; 8], [0; 4]).unwrap();
            assert!(
                adapter
                    .apply(
                        world.now(),
                        vec![
                            MeshOutput::SetHello {
                                tag: LocalTag::new([i; 16]),
                                app_hello: AppHello::new(signed.encode().to_vec()).unwrap()
                            },
                            MeshOutput::SetBeacon {
                                hint: [i; 8],
                                digest: [0; 4],
                                flags: BeaconFlags {
                                    accepting: true,
                                    ..BeaconFlags::default()
                                }
                            },
                        ]
                    )
                    .is_empty()
            );
            adapter
        })
        .collect();
    world.set_in_range(
        nodes[0].network().transport().node(),
        nodes[1].network().transport().node(),
        true,
    );
    drive(&world, &mut nodes, 200);
    // Each neighbour recorded the identity its peer's signed hello
    // proved, verified through the full facade and transport path.
    let expected = [
        Identity::from_seed([1; 32]).node_id(),
        Identity::from_seed([2; 32]).node_id(),
    ];
    for (i, n) in nodes.iter().enumerate() {
        assert_eq!(n.engine().neighbors().len(), 1);
        let neighbor = n.engine().neighbors().iter().next().unwrap();
        assert_eq!(neighbor.node_id, Some(expected[1 - i]));
    }
    (world, nodes)
}
fn drive(world: &SimWorld, nodes: &mut [Adapter], steps: usize) {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..steps {
        world.advance(Duration::from_millis(10));
        for (i, n) in nodes.iter_mut().enumerate() {
            // Each adapter must be pumped with its own identity: MSH-09
            // opens a delivered seal against the node the packet names.
            let identity = Identity::from_seed([(i + 1) as u8; 32]);
            while let Poll::Ready(result) = n.poll_event(
                &mut cx,
                world.now(),
                world.now().as_millis() as u64,
                &identity,
            ) {
                assert!(
                    result.unwrap().is_empty(),
                    "no unverified data may be delivered"
                );
            }
        }
    }
}
fn header() -> Header {
    Header {
        class: PacketClass::Direct,
        dst: Some([8; 16]),
        msg_id: [0; 16].into(),
        origin: [0; 16],
        created_ms: 2000,
        lifetime_s: 3600,
        payload_len: 4,
        ttl: 8,
        hops: 0,
    }
}
#[test]
fn link_up_data_and_link_down_run_through_the_facade_and_engine() {
    let (world, mut nodes) = pair();
    let link = nodes[0].network().links()[0].link;
    let back = nodes[1].network().links()[0].link;
    let identity = Identity::from_seed([1; 32]);
    assert!(
        nodes[0]
            .handle(
                world.now(),
                2000,
                MeshInput::Submit {
                    identity: &identity,
                    header: header(),
                    payload: b"ping",
                    via: Some(link)
                }
            )
            .unwrap()
            .is_empty()
    );
    drive(&world, &mut nodes, 100);
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
        nodes[0]
            .apply(
                world.now(),
                vec![MeshOutput::Send {
                    link,
                    channel: Channel::Message,
                    payload: vec![0xff]
                }]
            )
            .is_empty()
    );
    drive(&world, &mut nodes, 100);
    assert_eq!(
        nodes[1]
            .engine()
            .neighbors()
            .get(back)
            .unwrap()
            .malformed_packets,
        1
    );
    for (i, n) in nodes.iter_mut().enumerate() {
        n.apply(
            world.now(),
            vec![MeshOutput::SetBeacon {
                hint: [(i + 1) as u8; 8],
                digest: [0; 4],
                flags: BeaconFlags::default(),
            }],
        );
    }
    assert!(
        nodes[0]
            .apply(
                world.now(),
                vec![MeshOutput::Release {
                    link,
                    reason: DisconnectReason::Closed
                }]
            )
            .is_empty()
    );
    drive(&world, &mut nodes, 100);
    assert!(
        nodes
            .iter()
            .all(|n| n.network().links().is_empty() && n.engine().neighbors().is_empty())
    );
    assert!(
        nodes[0]
            .handle(world.now(), 5000, MeshInput::Tick)
            .unwrap()
            .is_empty()
    );
}
#[test]
fn broadcast_is_submitted_and_network_errors_retain_payloads() {
    let (world, mut nodes) = pair();
    let identity = Identity::from_seed([2; 32]);
    assert!(
        nodes[0]
            .handle(
                world.now(),
                2000,
                MeshInput::Submit {
                    identity: &identity,
                    header: header(),
                    payload: b"ping",
                    via: None
                }
            )
            .unwrap()
            .is_empty()
    );
    drive(&world, &mut nodes, 100);
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
    let unknown = LinkId::new(u64::MAX);
    let events = nodes[0].apply(
        world.now(),
        vec![MeshOutput::Send {
            link: unknown,
            channel: Channel::Bulk,
            payload: vec![1, 2, 3],
        }],
    );
    let [AdapterEvent::SendFailed { link, error }] = events.as_slice() else {
        panic!("expected send failure")
    };
    assert_eq!(*link, unknown);
    assert_eq!(error, &SendError::LinkClosed(vec![1, 2, 3]));
}
#[test]
fn rejected_link_is_released_through_the_network_without_retaining_it() {
    let world = SimWorld::new(SimConfig::default());
    let mut nodes: Vec<Adapter> = [0usize, 1]
        .into_iter()
        .enumerate()
        .map(|(i, limit)| {
            let radio = world.add_node(SimNode::default()).unwrap();
            let identity = Identity::from_seed([i as u8; 32]);
            let engine = MeshEngine::with_config(
                StdRng::seed_from_u64(SEED),
                MeshConfig {
                    max_neighbors: limit,
                    ..MeshConfig::default()
                },
            );
            let mut n = NetworkAdapter::new(engine, Network::new(NetworkConfig::default(), radio));
            let signed = MeshHello::sign(&identity, [0; 8], [0; 4]).unwrap();
            n.apply(
                world.now(),
                vec![
                    MeshOutput::SetHello {
                        tag: LocalTag::new([i as u8; 16]),
                        app_hello: AppHello::new(signed.encode().to_vec()).unwrap(),
                    },
                    MeshOutput::SetBeacon {
                        hint: [i as u8; 8],
                        digest: [0; 4],
                        flags: BeaconFlags {
                            accepting: true,
                            ..BeaconFlags::default()
                        },
                    },
                ],
            );
            n
        })
        .collect();
    world.set_in_range(
        nodes[0].network().transport().node(),
        nodes[1].network().transport().node(),
        true,
    );
    drive(&world, &mut nodes, 200);
    assert!(nodes[0].engine().neighbors().is_empty());
    for (i, n) in nodes.iter_mut().enumerate() {
        n.apply(
            world.now(),
            vec![MeshOutput::SetBeacon {
                hint: [i as u8; 8],
                digest: [0; 4],
                flags: BeaconFlags::default(),
            }],
        );
    }
    drive(&world, &mut nodes, 100);
    assert!(
        nodes
            .iter()
            .all(|n| n.network().links().is_empty() && n.engine().neighbors().is_empty())
    );
}
#[test]
fn async_wrapper_is_pending_without_network_events() {
    let world = SimWorld::new(SimConfig::default());
    let radio = world.add_node(SimNode::default()).unwrap();
    let mut n = NetworkAdapter::new(
        MeshEngine::new(StdRng::seed_from_u64(SEED)),
        Network::new(NetworkConfig::default(), radio),
    );
    let mut cx = Context::from_waker(Waker::noop());
    let identity = Identity::from_seed([1; 32]);
    let mut future = std::pin::pin!(n.next_event(Duration::ZERO, 0, &identity));
    assert!(std::future::Future::poll(future.as_mut(), &mut cx).is_pending());
}
