//! MSH-29 restart hooks: the engine snapshots its bounded volatile state,
//! the host stores the bytes, and a restarted engine neither re-relays seen
//! packets nor forgets immunity or spray tickets.

#![cfg(feature = "adapter")]

mod common;

use ao_idents::Identity;
use ao_mesh::{
    MAX_SNAPSHOT_LEN, MeshConfig, MeshEngine, MeshHello, MeshInput, MeshOutput, MessageId, Packet,
    PacketClass, Snapshot, SnapshotError, SnapshotSection,
    store::{MemoryStore, MessageStore, StoreLimits, conformance},
};
use ao_network::{AppHello, Channel, Hello, LinkId, LocalTag};
use rand::{SeedableRng, rngs::StdRng};

const SEED: u64 = 0x5f5f_2901;
const LINK_A: LinkId = LinkId::new(1);
const LINK_B: LinkId = LinkId::new(2);

type Engine = MeshEngine<StdRng>;

fn identity(index: usize) -> Identity {
    Identity::from_seed([index as u8 + 1; 32])
}

fn engine(index: usize) -> Engine {
    MeshEngine::with_config(
        StdRng::seed_from_u64(SEED ^ index as u64),
        MeshConfig::default(),
    )
}

fn hello(index: usize) -> Hello {
    let signed = MeshHello::sign(&identity(index), [0; 8], [0; 4]).expect("fixed key signs");
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps: 0,
        max_frame: 16_384,
        tag: LocalTag::new([index as u8 + 1; 16]),
        app_hello: AppHello::new(signed.encode().to_vec()).expect("hello fits"),
    }
}

fn link_up(engine: &mut Engine, now: u64, link: LinkId, peer: usize) {
    let _ = engine
        .handle(
            now,
            MeshInput::LinkUp {
                link,
                remote_hello: hello(peer),
            },
        )
        .expect("link up is valid");
}

/// Message-channel sends decoded back to their content address; sync frames
/// and other control traffic are not relays of a mesh packet.
fn relay_ids(outputs: &[MeshOutput]) -> Vec<MessageId> {
    outputs
        .iter()
        .filter_map(|output| match output {
            MeshOutput::Send { payload, .. } | MeshOutput::Broadcast { payload, .. } => {
                let bytes = if payload.first() == Some(&ao_mesh::SPRAY_MAGIC) && payload.len() >= 6
                {
                    let len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
                    payload.get(6..6 + len).unwrap_or(payload.as_slice())
                } else {
                    payload.as_slice()
                };
                Packet::decode(bytes)
                    .ok()
                    .map(|packet| packet.header.msg_id)
            }
            _ => None,
        })
        .collect()
}

fn signed_wire(now: u64, from: usize, to: usize, tag: &[u8], ttl: u8) -> (Vec<u8>, MessageId) {
    let (mut header, payload) = common::seal_for(
        &identity(from),
        &identity(to),
        now,
        PacketClass::Direct,
        |h| h.ttl = ttl,
        tag,
    );
    let signature =
        ao_mesh::sign_packet(&identity(from), &mut header, &payload).expect("fixed key signs");
    let packet = Packet::new(header, signature, &payload).expect("lengths agree");
    let id = packet.header.msg_id;
    (packet.encode(), id)
}

#[test]
fn a_restart_does_not_re_relay_an_already_seen_packet() {
    let mut origin = engine(0);
    let mut relay = engine(1);
    let mut destination = engine(2);
    link_up(&mut origin, 100, LINK_A, 1);
    link_up(&mut destination, 100, LINK_B, 1);
    link_up(&mut relay, 100, LINK_A, 0);
    link_up(&mut relay, 100, LINK_B, 2);

    let (mut header, payload) = common::seal_for(
        &identity(0),
        &identity(2),
        1_000,
        PacketClass::Direct,
        |h| h.ttl = 8,
        b"restart dedupe",
    );
    let signature =
        ao_mesh::sign_packet(&identity(0), &mut header, &payload).expect("fixed key signs");
    let packet = Packet::new(header, signature, &payload).expect("lengths agree");
    let id = packet.header.msg_id;
    let wire = packet.encode();

    let outputs = relay
        .handle(
            1_100,
            MeshInput::Data {
                link: LINK_A,
                channel: Channel::Message,
                identity: &identity(1),
                payload: &wire,
            },
        )
        .expect("well-formed packet");
    assert!(relay_ids(&outputs).contains(&id), "first copy relays");

    let bytes = relay
        .snapshot()
        .expect("default state fits the snapshot cap");
    assert!(bytes.len() > 21, "a seen recording and tickets are encoded");

    // Same seed and config, restored state, links re-announced by the host.
    let mut restored = engine(1);
    restored.restore(&bytes).expect("valid snapshot");
    link_up(&mut restored, 1_200, LINK_A, 0);
    link_up(&mut restored, 1_200, LINK_B, 2);
    let outputs = restored
        .handle(
            1_250,
            MeshInput::Data {
                link: LINK_A,
                channel: Channel::Message,
                identity: &identity(1),
                payload: &wire,
            },
        )
        .expect("well-formed packet");
    assert!(
        !relay_ids(&outputs).contains(&id),
        "a restored engine must drop a packet it already forwarded"
    );

    // The same restart without the snapshot is the regression this locks:
    // the identical delayed copy is relayed again.
    let mut forgotten = engine(1);
    link_up(&mut forgotten, 1_200, LINK_A, 0);
    link_up(&mut forgotten, 1_200, LINK_B, 2);
    let outputs = forgotten
        .handle(
            1_250,
            MeshInput::Data {
                link: LINK_A,
                channel: Channel::Message,
                identity: &identity(1),
                payload: &wire,
            },
        )
        .expect("well-formed packet");
    assert!(
        relay_ids(&outputs).contains(&id),
        "the unsnapshotted ablation must re-relay, or the test proves nothing"
    );
}

#[test]
fn immunity_and_copy_counters_survive_a_restart() {
    let mut relay = engine(1);
    link_up(&mut relay, 100, LINK_A, 0);
    link_up(&mut relay, 100, LINK_B, 2);

    // A delivery at this engine creates an immunity entry; a local
    // submission creates a spray ticket.
    let (mut header, payload) = common::seal_for(
        &identity(0),
        &identity(1),
        1_000,
        PacketClass::Direct,
        |h| h.ttl = 8,
        b"immunity survives",
    );
    let signature =
        ao_mesh::sign_packet(&identity(0), &mut header, &payload).expect("fixed key signs");
    let packet = Packet::new(header, signature, &payload).expect("lengths agree");
    let delivered_id = packet.header.msg_id;
    let outputs = relay
        .handle(
            1_100,
            MeshInput::Data {
                link: LINK_A,
                channel: Channel::Message,
                identity: &identity(1),
                payload: &packet.encode(),
            },
        )
        .expect("well-formed packet");
    assert!(
        outputs
            .iter()
            .any(|output| matches!(output, MeshOutput::Deliver { .. })),
        "the packet must deliver for immunity to be created"
    );
    assert!(relay.is_immune(delivered_id), "receipt accepted locally");

    let (mut header, payload) = common::seal_for(
        &identity(1),
        &identity(9),
        1_200,
        PacketClass::Direct,
        |h| h.ttl = 8,
        b"ticket survives",
    );
    let signature =
        ao_mesh::sign_packet(&identity(1), &mut header, &payload).expect("fixed key signs");
    let packet = Packet::new(header, signature, &payload).expect("lengths agree");
    let ticket_id = packet.header.msg_id;
    let _ = relay
        .handle(
            1_200,
            MeshInput::Submit {
                identity: &identity(1),
                header: packet.header,
                payload: &payload,
                via: None,
            },
        )
        .expect("fixed submission");
    let copies = relay.spray_copies_left(ticket_id);
    assert!(
        copies > 1,
        "a spray ticket is live before the restart: {copies}"
    );

    let bytes = relay
        .snapshot()
        .expect("default state fits the snapshot cap");
    let mut restored = engine(1);
    restored.restore(&bytes).expect("valid snapshot");
    assert!(restored.is_immune(delivered_id));
    assert_eq!(restored.spray_copies_left(ticket_id), copies);
    assert_eq!(
        restored.snapshot().expect("round trip"),
        bytes,
        "the same state serialises to the same bytes"
    );

    let forgotten = engine(1);
    assert!(!forgotten.is_immune(delivered_id));
    assert_ne!(forgotten.spray_copies_left(ticket_id), copies);
}

#[test]
fn a_snapshot_leaves_the_host_store_untouched() {
    let mut store = MemoryStore::new(StoreLimits::default());
    let item = conformance::entry(1, 7, PacketClass::Direct, 2, 1, 0);
    store.put(0, item.clone()).expect("fixed store item");
    let before = store.summary(0);

    let mut engine = engine(1);
    link_up(&mut engine, 100, LINK_A, 0);
    let bytes = engine.snapshot().expect("snapshot encodes");
    engine.restore(&bytes).expect("snapshot restores");

    assert_eq!(store.summary(0), before);
    assert_eq!(store.get(0, &before[0]), Some(&item));
    assert!(
        !bytes
            .windows(item.wire().len())
            .any(|window| window == item.wire()),
        "message bytes are not copied into the snapshot"
    );
}

#[test]
fn malformed_oversized_and_mismatched_snapshots_are_rejected_atomically() {
    let mut engine = engine(1);
    link_up(&mut engine, 100, LINK_A, 0);
    let (mut header, payload) = common::seal_for(
        &identity(0),
        &identity(2),
        1_000,
        PacketClass::Direct,
        |h| h.ttl = 8,
        b"snapshot validation",
    );
    let signature =
        ao_mesh::sign_packet(&identity(0), &mut header, &payload).expect("fixed key signs");
    let packet = Packet::new(header, signature, &payload).expect("lengths agree");
    let wire = packet.encode();
    let _ = engine
        .handle(
            1_100,
            MeshInput::Data {
                link: LINK_A,
                channel: Channel::Message,
                identity: &identity(1),
                payload: &wire,
            },
        )
        .expect("well-formed packet");
    let good = engine.snapshot().expect("valid snapshot");

    // Every truncation fails, and none of them changes the live engine.
    for len in 0..good.len() {
        let error = engine
            .restore(&good[..len])
            .expect_err("truncated snapshot");
        assert!(
            matches!(
                error,
                SnapshotError::Truncated { .. } | SnapshotError::BadMagic
            ),
            "unexpected error for prefix {len}: {error}"
        );
    }
    assert_eq!(engine.snapshot().expect("state intact"), good);

    let mut wrong_version = good.clone();
    wrong_version[4] = 2;
    assert_eq!(
        engine.restore(&wrong_version),
        Err(SnapshotError::UnsupportedVersion(2))
    );

    let mut wrong_magic = good.clone();
    wrong_magic[0] ^= 1;
    assert_eq!(engine.restore(&wrong_magic), Err(SnapshotError::BadMagic));

    let mut huge_count = good.clone();
    huge_count[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        engine.restore(&huge_count),
        Err(SnapshotError::CountExceedsLimit {
            section: SnapshotSection::Seen,
            count: u32::MAX as usize,
            limit: 4_096,
        })
    );

    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        engine.restore(&trailing),
        Err(SnapshotError::TrailingBytes(1))
    );

    let oversized = vec![0u8; MAX_SNAPSHOT_LEN + 1];
    assert!(matches!(
        engine.restore(&oversized),
        Err(SnapshotError::TooLarge { .. })
    ));
    assert_eq!(engine.snapshot().expect("state intact"), good);
}

#[test]
fn restored_state_feeds_the_same_decisions_as_an_uninterrupted_engine() {
    let now = 1_000;
    let (wire, _) = signed_wire(now, 0, 1, b"deterministic restart", 8);
    let mut live = engine(1);
    link_up(&mut live, 100, LINK_A, 0);
    link_up(&mut live, 100, LINK_B, 2);
    let first = live
        .handle(
            1_100,
            MeshInput::Data {
                link: LINK_A,
                channel: Channel::Message,
                identity: &identity(1),
                payload: &wire,
            },
        )
        .expect("well-formed packet");

    let bytes = live.snapshot().expect("snapshot encodes");
    let mut restored = engine(1);
    restored.restore(&bytes).expect("snapshot restores");
    link_up(&mut restored, 1_200, LINK_A, 0);
    link_up(&mut restored, 1_200, LINK_B, 2);

    let next = wire.clone();
    let a = live
        .handle(
            1_300,
            MeshInput::Data {
                link: LINK_B,
                channel: Channel::Message,
                identity: &identity(1),
                payload: &next,
            },
        )
        .expect("well-formed packet");
    let b = restored
        .handle(
            1_300,
            MeshInput::Data {
                link: LINK_B,
                channel: Channel::Message,
                identity: &identity(1),
                payload: &next,
            },
        )
        .expect("well-formed packet");
    assert!(!first.is_empty(), "the first sighting relays");
    assert_eq!(a, b, "restored and live engines make the same decision");
}
