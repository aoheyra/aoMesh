//! MSH-30 integration coverage for the host-facing snapshot.
//!
//! The engine owns every counter; this suite only checks that the adapter
//! exposes the same plain data, that repeated reads are stable and bounded,
//! and that no packet content or id reaches the snapshot.

#![cfg(feature = "adapter")]

use ao_idents::Identity;
use ao_mesh::{
    Header, MESH_SNAPSHOT_VERSION, MeshConfig, MeshEngine, MeshInput, MeshSnapshot, MessageId,
    NetworkAdapter, PacketClass,
};
use ao_network::{Network, NetworkConfig, SimConfig, SimNode, SimTransport, SimWorld};
use rand::{SeedableRng, rngs::StdRng};
use std::mem::size_of;

type Adapter = NetworkAdapter<StdRng, SimTransport>;

const SEED: u64 = 0x30_2026;

fn adapter() -> (SimWorld, Adapter) {
    let world = SimWorld::new(SimConfig {
        seed: SEED,
        ..SimConfig::default()
    });
    let radio = world.add_node(SimNode::default()).unwrap();
    let engine = MeshEngine::with_config(StdRng::seed_from_u64(SEED), MeshConfig::default());
    let adapter = NetworkAdapter::new(engine, Network::new(NetworkConfig::default(), radio));
    (world, adapter)
}

fn assert_copy<T: Copy>() {}

#[test]
fn adapter_snapshot_matches_the_engine_and_is_stable() {
    let (_world, mut adapter) = adapter();
    let ids = [
        MessageId::from_bytes([1; 16]),
        MessageId::from_bytes([2; 16]),
    ];
    adapter
        .handle(
            std::time::Duration::ZERO,
            1_000,
            MeshInput::StoreSummary { ids: &ids },
        )
        .unwrap();

    let from_engine = adapter.engine().observability_snapshot();
    let from_adapter = adapter.snapshot();
    assert_eq!(from_engine, from_adapter);
    assert_eq!(from_adapter.version, MESH_SNAPSHOT_VERSION);
    assert_eq!(from_adapter.store_entries, 2);
    assert_eq!(from_adapter, adapter.snapshot());

    assert_copy::<MeshSnapshot>();
    assert!(size_of::<MeshSnapshot>() <= 128);
}

#[test]
fn snapshot_never_carries_packet_content_or_message_ids() {
    let (world, mut adapter) = adapter();
    let identity = Identity::from_seed([9; 32]);
    let secret = b"MSH30-DO-NOT-LOG";
    let id = MessageId::from_bytes([0xab; 16]);
    let header = Header {
        class: PacketClass::Broadcast,
        dst: None,
        msg_id: id,
        origin: *identity.node_id().as_bytes(),
        created_ms: 1_000,
        lifetime_s: 3_600,
        payload_len: secret.len() as u64,
        ttl: 8,
        hops: 0,
    };

    adapter
        .handle(
            world.now(),
            1_000,
            MeshInput::Submit {
                identity: &identity,
                header,
                payload: secret,
                via: None,
            },
        )
        .unwrap();
    adapter
        .handle(world.now(), 1_001, MeshInput::StoreSummary { ids: &[id] })
        .unwrap();

    let debug = format!("{:?}", adapter.snapshot());
    assert!(!debug.contains(std::str::from_utf8(secret).unwrap()));
    let id_hex: String = (0..16).map(|_| "ab").collect();
    assert!(!debug.contains(&id_hex), "snapshot exposed a message id");
}
