//! MSH-20 engine seam: typed presence observations produce bounded UI
//! events, answer directory queries and expire on a Tick's local schedule.

#![cfg(feature = "adapter")]

use ao_idents::{Identity, NodeId};
use ao_mesh::{
    AdapterEvent, DirectoryChange, DirectoryConfig, DirectoryError, MeshConfig, MeshEngine,
    MeshError, MeshInput, MeshOutput, NetworkAdapter, NodeObservation,
};
use ao_network::{Network, NetworkConfig, SimNode, SimWorld};
use rand::{SeedableRng, rngs::StdRng};

const SEED: u64 = 1_297_304_021;

fn directory_config(capacity: usize, stale_after_ms: u64) -> DirectoryConfig {
    DirectoryConfig {
        capacity,
        stale_after_ms,
        max_change_events: 4,
        ..DirectoryConfig::default()
    }
}

fn engine(capacity: usize, stale_after_ms: u64) -> MeshEngine<StdRng> {
    let config = MeshConfig {
        directory: directory_config(capacity, stale_after_ms),
        ..MeshConfig::default()
    };
    MeshEngine::with_config(StdRng::seed_from_u64(SEED), config)
}

fn tick(mesh: &mut MeshEngine<StdRng>, now: u64) -> Vec<MeshOutput> {
    let identity = Identity::from_seed([7; 32]);
    mesh.handle(
        now,
        MeshInput::Tick {
            identity: &identity,
            card_hash: [7; 8],
        },
    )
    .expect("tick is valid")
}

fn observation(id: u8, seq: u64, hops: u8, at: u64, location: &[u8]) -> NodeObservation<'_> {
    NodeObservation {
        node: NodeId::from_bytes([id; 16]),
        card_hash: [id; 8],
        caps: u32::from(id),
        seq,
        hops,
        via: NodeId::from_bytes([9; 16]),
        observed_at_ms: at,
        location,
    }
}

fn only_directory_changes(outputs: Vec<MeshOutput>) -> Vec<DirectoryChange> {
    match outputs.as_slice() {
        [MeshOutput::DirectoryChanged { changes }] => changes.clone(),
        other => panic!("expected one directory event, got {other:?}"),
    }
}

#[test]
fn default_config_matches_the_documented_directory_bounds() {
    let config = MeshConfig::default().directory;
    assert_eq!(config.capacity, 256);
    assert_eq!(config.stale_after_ms, 30 * 60 * 1_000);
    assert_eq!(config.max_location_bytes, 64);
    assert_eq!(config.max_change_events, 64);
}

#[test]
fn observations_drive_queries_and_coalesced_ui_events() {
    let mut mesh = engine(2, 100_000);
    let a = NodeId::from_bytes([1; 16]);
    let b = NodeId::from_bytes([2; 16]);

    let first = mesh
        .handle(
            1_000,
            MeshInput::ObserveNode {
                observation: observation(1, 1, 3, 900, b"loc"),
            },
        )
        .expect("first observation is valid");
    assert_eq!(
        only_directory_changes(first),
        vec![DirectoryChange::Added { node: a }]
    );

    let mut repeat = observation(1, 2, 2, 1_000, b"loc");
    repeat.caps = 7;
    let second = mesh
        .handle(
            1_000,
            MeshInput::ObserveNode {
                observation: repeat,
            },
        )
        .expect("repeat observation is valid");
    assert_eq!(
        only_directory_changes(second),
        vec![DirectoryChange::Added { node: a }],
        "one pending event per node even when fields change"
    );

    mesh.handle(
        1_000,
        MeshInput::ObserveNode {
            observation: observation(2, 1, 1, 1_000, &[]),
        },
    )
    .expect("second node is valid");
    let entry = mesh.directory().get(1_000, a).expect("A is live");
    assert_eq!(entry.card_hash, [1; 8]);
    assert_eq!(entry.caps, 7);
    assert_eq!(entry.seq, 2);
    assert_eq!(entry.hops, 2);
    assert_eq!(entry.via, NodeId::from_bytes([9; 16]));
    assert_eq!(entry.location.as_deref(), Some(&b"loc"[..]));
    assert_eq!(entry.last_seen_ms, 1_000, "a future observation is clamped");
    assert_eq!(
        mesh.directory()
            .nearby(1_000, 1, 2, 4)
            .into_iter()
            .map(|entry| entry.node)
            .collect::<Vec<_>>(),
        vec![b, a]
    );
    assert_eq!(mesh.directory().len(), 2);
}

#[test]
fn adapter_forwards_directory_events_to_the_host() {
    let world = SimWorld::new(ao_network::SimConfig {
        seed: SEED,
        ..ao_network::SimConfig::default()
    });
    let radio = world.add_node(SimNode::default()).expect("valid sim node");
    let engine = engine(2, 100_000);
    let mut adapter = NetworkAdapter::new(engine, Network::new(NetworkConfig::default(), radio));
    // The adapter needs no local identity for an observation: the engine
    // keeps no key on this path.
    let events = adapter
        .handle(
            world.now(),
            500,
            MeshInput::ObserveNode {
                observation: observation(4, 1, 2, 500, &[]),
            },
        )
        .expect("observation is valid");
    match events.as_slice() {
        [AdapterEvent::DirectoryChanged { changes }] => assert_eq!(
            changes,
            &[DirectoryChange::Added {
                node: NodeId::from_bytes([4; 16]),
            }]
        ),
        other => panic!("expected one directory event, got {other:?}"),
    }
}

#[test]
fn tick_expires_on_schedule_and_a_backwards_clock_changes_nothing() {
    let mut mesh = engine(4, 1_000);
    let a = NodeId::from_bytes([1; 16]);
    mesh.handle(
        10_000,
        MeshInput::ObserveNode {
            observation: observation(1, 1, 1, 0, &[]),
        },
    )
    .expect("observation is valid");
    assert!(tick(&mut mesh, 10_999).is_empty());
    assert!(mesh.directory().get(10_999, a).is_some());

    let removed = tick(&mut mesh, 11_000);
    assert_eq!(
        only_directory_changes(removed),
        vec![DirectoryChange::Removed { node: a }]
    );
    assert!(mesh.directory().get(11_000, a).is_none());
    assert_eq!(mesh.directory().stats().expirations, 1);

    // A late backward tick cannot revive or delay the already-scheduled
    // expiry, and emits no duplicate UI event.
    assert!(tick(&mut mesh, 9_000).is_empty());
    assert_eq!(mesh.directory().stats().expirations, 1);
}

#[test]
fn oversized_locations_are_rejected_with_a_typed_error() {
    let mut mesh = engine(4, 100_000);
    let error = mesh
        .handle(
            0,
            MeshInput::ObserveNode {
                observation: observation(1, 1, 1, 0, &[0; 65]),
            },
        )
        .expect_err("the default 64-byte location cap is enforced");
    assert!(matches!(
        error,
        MeshError::Directory(DirectoryError::LocationTooLong { len: 65, max: 64 })
    ));
    assert!(mesh.directory().is_empty());
}
