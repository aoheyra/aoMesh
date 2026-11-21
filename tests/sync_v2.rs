//! MSH-15 engine-level range reconciliation and v1 fallback.

use ao_idents::Identity;
use ao_mesh::store::{MemoryStore, MessageStore, StoreMetadata, StoredMessage};
use ao_mesh::{
    CAP_SYNC_V1, CAPS, Header, MeshConfig, MeshEngine, MeshHello, MeshInput, MeshOutput, Packet,
    PacketClass, SHORT_ID_BYTES, SYNC_MAGIC, SYNC_V2_VERSION, StoreSummary as MeshStoreSummary,
    SyncOffer, sign_packet,
};
use ao_network::{AppHello, Channel, Hello, LinkId, LocalTag};
use rand::{SeedableRng, rngs::StdRng};

type Engine = MeshEngine<StdRng>;

const LINK_A: LinkId = LinkId::new(11);
const LINK_B: LinkId = LinkId::new(12);

fn hello(identity: &Identity, digest: [u8; 4], caps: u32) -> Hello {
    let signed = MeshHello::sign_with_caps(identity, [0; 8], digest, caps).expect("identity signs");
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps: 0,
        max_frame: 16_384,
        tag: LocalTag::new([1; 16]),
        app_hello: AppHello::new(signed.encode().to_vec()).expect("hello fits"),
    }
}

fn wire(identity: &Identity, tag: u16) -> Vec<u8> {
    let payload = format!("range-message-{tag}").into_bytes();
    let mut header = Header {
        class: PacketClass::Broadcast,
        dst: None,
        msg_id: [0; 16].into(),
        origin: [0; 16],
        created_ms: 100,
        lifetime_s: 3_600,
        payload_len: payload.len() as u64,
        ttl: 6,
        hops: 0,
    };
    let signature = sign_packet(identity, &mut header, &payload).expect("signs");
    Packet::new(header, signature, &payload)
        .expect("packet fields agree")
        .encode()
}

fn put(store: &mut MemoryStore, now: u64, bytes: &[u8]) {
    let metadata = StoreMetadata {
        copies_left: 1,
        first_seen: now,
        received_at: now,
        priority: 0,
        received_from: None,
        age_ms: 0,
    };
    let message = StoredMessage::new(bytes, metadata).expect("bounded storable item");
    store.put(now, message).expect("store has room");
}

fn digest(store: &MemoryStore, now: u64) -> [u8; 4] {
    MeshStoreSummary::from_store(store, now).digest()
}

#[derive(Default)]
struct Serviced {
    frames: Vec<Vec<u8>>,
    items: Vec<Vec<u8>>,
    releases: usize,
    v2_frames: usize,
    v2_bytes: usize,
}

fn service(
    engine: &mut Engine,
    store: &MemoryStore,
    now: u64,
    outputs: Vec<MeshOutput>,
) -> Serviced {
    let mut result = Serviced::default();
    for output in outputs {
        match output {
            MeshOutput::Send {
                channel: Channel::Bulk,
                payload,
                ..
            } => {
                if payload.first() == Some(&SYNC_MAGIC) && payload.get(1) == Some(&SYNC_V2_VERSION)
                {
                    result.v2_frames += 1;
                    result.v2_bytes += payload.len();
                }
                result.frames.push(payload);
            }
            MeshOutput::SyncItem { wire, .. } => result.items.push(wire),
            MeshOutput::ReleaseOpportunistic { .. } => result.releases += 1,
            MeshOutput::SyncNeed { link, prefixes } => {
                let ids = store.summary(now);
                let offers: Vec<SyncOffer<'_>> = prefixes
                    .iter()
                    .filter_map(|prefix| {
                        let id = ids
                            .iter()
                            .find(|id| id.as_bytes()[..SHORT_ID_BYTES] == prefix[..])?;
                        let message = store.get(now, id)?;
                        Some(SyncOffer {
                            prefix: *prefix,
                            wire: message.wire(),
                        })
                    })
                    .collect();
                let extra = engine
                    .handle(
                        now,
                        MeshInput::SyncItems {
                            link,
                            items: &offers,
                        },
                    )
                    .expect("host offers are valid");
                let nested = service(engine, store, now, extra);
                result.frames.extend(nested.frames);
                result.items.extend(nested.items);
                result.releases += nested.releases;
                result.v2_frames += nested.v2_frames;
                result.v2_bytes += nested.v2_bytes;
            }
            _ => {}
        }
    }
    result
}

#[test]
fn two_stores_converge_through_range_reconciliation() {
    let owner = Identity::from_seed([21; 32]);
    let peer = Identity::from_seed([22; 32]);
    let mut a_store = MemoryStore::new(Default::default());
    let mut b_store = MemoryStore::new(Default::default());
    let wires: Vec<Vec<u8>> = (0..6).map(|tag| wire(&owner, tag)).collect();
    for wire in &wires {
        put(&mut a_store, 100, wire);
    }
    for wire in &wires[..4] {
        put(&mut b_store, 100, wire);
    }
    put(&mut b_store, 100, &wire(&owner, 99));
    let a_ids = a_store.summary(100);
    let b_ids = b_store.summary(100);

    let config = MeshConfig {
        max_neighbors: 4,
        ..MeshConfig::default()
    };
    let mut a = MeshEngine::with_config(StdRng::seed_from_u64(1), config);
    let mut b = MeshEngine::with_config(StdRng::seed_from_u64(2), config);
    a.handle(100, MeshInput::StoreSummary { ids: &a_ids })
        .expect("summary");
    b.handle(100, MeshInput::StoreSummary { ids: &b_ids })
        .expect("summary");

    let mut a_frames = Vec::new();
    let mut b_frames = Vec::new();
    let mut a_releases = 0;
    let mut b_releases = 0;
    let mut a_v2 = 0;
    let mut b_v2 = 0;

    let out = a
        .handle(
            100,
            MeshInput::LinkUp {
                link: LINK_A,
                remote_hello: hello(&peer, digest(&b_store, 100), CAPS),
            },
        )
        .expect("link up");
    let serviced = service(&mut a, &a_store, 100, out);
    a_frames.extend(serviced.frames);
    a_releases += serviced.releases;
    a_v2 += serviced.v2_frames;

    let out = b
        .handle(
            100,
            MeshInput::LinkUp {
                link: LINK_B,
                remote_hello: hello(&owner, digest(&a_store, 100), CAPS),
            },
        )
        .expect("link up");
    let serviced = service(&mut b, &b_store, 100, out);
    b_frames.extend(serviced.frames);
    b_releases += serviced.releases;
    b_v2 += serviced.v2_frames;

    for round in 0..100 {
        let outgoing = std::mem::take(&mut a_frames);
        for payload in outgoing {
            let outputs = b
                .handle(
                    101 + round,
                    MeshInput::Data {
                        link: LINK_B,
                        channel: Channel::Bulk,
                        payload: &payload,
                        identity: &peer,
                    },
                )
                .expect("sync frame");
            let serviced = service(&mut b, &b_store, 101 + round, outputs);
            b_frames.extend(serviced.frames);
            for item in serviced.items {
                put(&mut b_store, 102 + round, &item);
            }
            b_releases += serviced.releases;
            b_v2 += serviced.v2_frames;
        }
        let outgoing = std::mem::take(&mut b_frames);
        for payload in outgoing {
            let outputs = a
                .handle(
                    102 + round,
                    MeshInput::Data {
                        link: LINK_A,
                        channel: Channel::Bulk,
                        payload: &payload,
                        identity: &owner,
                    },
                )
                .expect("sync frame");
            let serviced = service(&mut a, &a_store, 102 + round, outputs);
            a_frames.extend(serviced.frames);
            for item in serviced.items {
                put(&mut a_store, 103 + round, &item);
            }
            a_releases += serviced.releases;
            a_v2 += serviced.v2_frames;
        }
        if a_frames.is_empty() && b_frames.is_empty() && a_releases >= 1 && b_releases >= 1 {
            break;
        }
    }

    assert!(a_v2 > 0 && b_v2 > 0, "both sides must send v2 frames");
    assert!(
        a_releases >= 1 && b_releases >= 1,
        "both contacts must release"
    );
    assert_eq!(
        a_store.summary(200),
        b_store.summary(200),
        "stores must converge"
    );
}

#[test]
fn a_v1_only_peer_keeps_the_msh14_summary_path() {
    let owner = Identity::from_seed([23; 32]);
    let peer = Identity::from_seed([24; 32]);
    let mut store = MemoryStore::new(Default::default());
    let wire = wire(&owner, 1);
    put(&mut store, 100, &wire);
    let ids = store.summary(110);
    let mut engine = MeshEngine::with_config(StdRng::seed_from_u64(3), MeshConfig::default());
    engine
        .handle(100, MeshInput::StoreSummary { ids: &ids })
        .expect("summary");
    let outputs = engine
        .handle(
            100,
            MeshInput::LinkUp {
                link: LINK_A,
                remote_hello: hello(&peer, [9; 4], CAP_SYNC_V1),
            },
        )
        .expect("link up");
    let has_v1 = outputs.iter().any(|output| {
        matches!(output, MeshOutput::Send { payload, .. } if payload.first() == Some(&SYNC_MAGIC))
    });
    let has_v2 = outputs.iter().any(|output| {
        matches!(output, MeshOutput::Send { payload, .. } if payload.get(1) == Some(&SYNC_V2_VERSION))
    });
    assert!(has_v1, "v1-only peers get the MSH-14 digest frame");
    assert!(!has_v2, "v1-only peers never get v2 frames");
}
