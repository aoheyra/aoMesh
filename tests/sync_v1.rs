//! MSH-14 engine-level sync: bounded frames, host seams and link-drop resume.

use ao_idents::Identity;
use ao_mesh::store::{MemoryStore, MessageStore, StoreMetadata, StoredMessage};
use ao_mesh::{
    Header, MeshConfig, MeshEngine, MeshHello, MeshInput, MeshOutput, Packet, PacketClass,
    SHORT_ID_BYTES, SyncOffer, sign_packet,
};
use ao_network::{AppHello, Channel, DisconnectReason, Hello, LinkId, LocalTag};
use rand::{SeedableRng, rngs::StdRng};

type Engine = MeshEngine<StdRng>;

const LINK_A: LinkId = LinkId::new(1);
const LINK_B: LinkId = LinkId::new(2);

fn hello(identity: &Identity, digest: [u8; 4]) -> Hello {
    let signed = MeshHello::sign(identity, [0; 8], digest).expect("identity signs");
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps: 0,
        max_frame: 16_384,
        tag: LocalTag::new([1; 16]),
        app_hello: AppHello::new(signed.encode().to_vec()).expect("hello fits"),
    }
}

fn wire(identity: &Identity, tag: u8) -> Vec<u8> {
    let payload = format!("message-{tag}").into_bytes();
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

fn engine() -> Engine {
    MeshEngine::with_config(StdRng::seed_from_u64(0x51AC), MeshConfig::default())
}

#[derive(Default)]
struct Serviced {
    frames: Vec<Vec<u8>>,
    items: Vec<Vec<u8>>,
    releases: usize,
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
            } => result.frames.push(payload),
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
                            copies_left: 1,
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
            }
            _ => {}
        }
    }
    result
}

fn digest(store: &MemoryStore, now: u64) -> [u8; 4] {
    ao_mesh::StoreSummary::from_store(store, now).digest()
}

#[test]
fn two_stores_converge_and_release_the_contact() {
    let owner = Identity::from_seed([1; 32]);
    let peer = Identity::from_seed([2; 32]);
    let mut a_store = MemoryStore::new(Default::default());
    let mut b_store = MemoryStore::new(Default::default());
    put(&mut a_store, 100, &wire(&owner, 1));
    put(&mut a_store, 100, &wire(&owner, 2));
    put(&mut b_store, 100, &wire(&peer, 3));
    let a_ids = a_store.summary(100);
    let b_ids = b_store.summary(100);

    let mut a = engine();
    let mut b = engine();
    a.handle(100, MeshInput::StoreSummary { ids: &a_ids })
        .expect("summary");
    b.handle(100, MeshInput::StoreSummary { ids: &b_ids })
        .expect("summary");

    let mut a_frames = Vec::new();
    let mut b_frames = Vec::new();
    let mut a_items = Vec::new();
    let mut b_items = Vec::new();
    let mut a_releases = 0;
    let mut b_releases = 0;

    let a_out = a
        .handle(
            100,
            MeshInput::LinkUp {
                link: LINK_A,
                remote_hello: hello(&peer, digest(&b_store, 100)),
            },
        )
        .expect("link up");
    let serviced = service(&mut a, &a_store, 100, a_out);
    a_frames.extend(serviced.frames);
    a_releases += serviced.releases;

    let b_out = b
        .handle(
            100,
            MeshInput::LinkUp {
                link: LINK_B,
                remote_hello: hello(&owner, digest(&a_store, 100)),
            },
        )
        .expect("link up");
    let serviced = service(&mut b, &b_store, 100, b_out);
    b_frames.extend(serviced.frames);
    b_releases += serviced.releases;

    for _ in 0..8 {
        let outgoing = std::mem::take(&mut a_frames);
        for payload in outgoing {
            let outputs = b
                .handle(
                    101,
                    MeshInput::Data {
                        link: LINK_B,
                        channel: Channel::Bulk,
                        payload: &payload,
                        identity: &peer,
                    },
                )
                .expect("sync frame");
            let serviced = service(&mut b, &b_store, 101, outputs);
            b_frames.extend(serviced.frames);
            b_items.extend(serviced.items);
            b_releases += serviced.releases;
        }
        let outgoing = std::mem::take(&mut b_frames);
        for payload in outgoing {
            let outputs = a
                .handle(
                    102,
                    MeshInput::Data {
                        link: LINK_A,
                        channel: Channel::Bulk,
                        payload: &payload,
                        identity: &owner,
                    },
                )
                .expect("sync frame");
            let serviced = service(&mut a, &a_store, 102, outputs);
            a_frames.extend(serviced.frames);
            a_items.extend(serviced.items);
            a_releases += serviced.releases;
        }
        if a_frames.is_empty() && b_frames.is_empty() {
            break;
        }
    }

    assert!(a_frames.is_empty(), "sync must settle, not loop");
    assert!(b_frames.is_empty(), "sync must settle, not loop");
    for item in a_items {
        put(&mut a_store, 110, &item);
    }
    for item in b_items {
        put(&mut b_store, 110, &item);
    }
    let expected: Vec<_> = a_ids.iter().chain(b_ids.iter()).collect();
    assert_eq!(a_store.summary(110).len(), expected.len());
    assert_eq!(b_store.summary(110).len(), expected.len());
    assert!(
        a_releases >= 1 && b_releases >= 1,
        "both contacts must release"
    );
}

#[test]
fn equal_digests_skip_the_exchange_and_keep_the_link() {
    let owner = Identity::from_seed([4; 32]);
    let peer = Identity::from_seed([5; 32]);
    let mut store = MemoryStore::new(Default::default());
    put(&mut store, 100, &wire(&owner, 9));
    let ids = store.summary(100);
    let digest = digest(&store, 100);
    let mut a = engine();
    let mut b = engine();
    a.handle(100, MeshInput::StoreSummary { ids: &ids })
        .unwrap();
    b.handle(100, MeshInput::StoreSummary { ids: &ids })
        .unwrap();
    let out = a
        .handle(
            100,
            MeshInput::LinkUp {
                link: LINK_A,
                remote_hello: hello(&peer, digest),
            },
        )
        .unwrap();
    let serviced = service(&mut a, &store, 100, out);
    assert!(serviced.frames.is_empty(), "equal digests send no frames");
    assert_eq!(serviced.releases, 0, "no exchange means no release");
}

#[test]
fn a_drop_mid_transfer_discards_state_and_restarts() {
    let owner = Identity::from_seed([6; 32]);
    let peer = Identity::from_seed([7; 32]);
    let mut store = MemoryStore::new(Default::default());
    put(&mut store, 100, &wire(&owner, 11));
    let ids = store.summary(100);
    let mut a = engine();
    a.handle(100, MeshInput::StoreSummary { ids: &ids })
        .unwrap();
    let out = a
        .handle(
            100,
            MeshInput::LinkUp {
                link: LINK_A,
                remote_hello: hello(&peer, [9; 4]),
            },
        )
        .unwrap();
    let first = service(&mut a, &store, 100, out);
    assert_eq!(first.frames.len(), 1, "starts with one digest");

    let down = a
        .handle(
            101,
            MeshInput::LinkDown {
                link: LINK_A,
                reason: DisconnectReason::Closed,
            },
        )
        .unwrap();
    assert!(down.is_empty());
    let offers: Vec<SyncOffer<'_>> = Vec::new();
    let after_drop = a
        .handle(
            102,
            MeshInput::SyncItems {
                link: LINK_A,
                items: &offers,
            },
        )
        .unwrap();
    assert!(after_drop.is_empty(), "a closed contact offers no items");

    let restarted = a
        .handle(
            103,
            MeshInput::LinkUp {
                link: LINK_A,
                remote_hello: hello(&peer, [9; 4]),
            },
        )
        .unwrap();
    let second = service(&mut a, &store, 103, restarted);
    assert_eq!(second.frames.len(), 1, "recontact sends a fresh digest");
}

#[test]
fn an_expired_contact_is_released() {
    let owner = Identity::from_seed([8; 32]);
    let peer = Identity::from_seed([9; 32]);
    let mut store = MemoryStore::new(Default::default());
    put(&mut store, 100, &wire(&owner, 12));
    let ids = store.summary(100);
    let mut a = engine();
    a.handle(100, MeshInput::StoreSummary { ids: &ids })
        .unwrap();
    let out = a
        .handle(
            100,
            MeshInput::LinkUp {
                link: LINK_A,
                remote_hello: hello(&peer, [7; 4]),
            },
        )
        .unwrap();
    let _ = service(&mut a, &store, 100, out);
    let out = a.handle(20_100, MeshInput::Tick).unwrap();
    let serviced = service(&mut a, &store, 20_100, out);
    assert_eq!(serviced.releases, 1, "the 20 second deadline releases once");
    let out = a.handle(20_101, MeshInput::Tick).unwrap();
    let serviced = service(&mut a, &store, 20_101, out);
    assert_eq!(serviced.releases, 0, "release is not repeated");
}
