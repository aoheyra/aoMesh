//! MSH-14 acceptance: two nodes meeting on aoNetwork's SimWorld converge
//! on the union of their stores and the opportunistic contact is released.

use ao_idents::Identity;
use ao_mesh::store::{MemoryStore, MessageStore, StoreMetadata, StoredMessage};
use ao_mesh::{
    Header, MeshHello, MeshInput, MeshOutput, NetworkAdapter, Packet, PacketClass, SHORT_ID_BYTES,
    StoreSummary, SyncOffer, sign_packet,
};
use ao_network::{
    AppHello, BeaconFlags, LinkId, LocalTag, Network, NetworkConfig, NetworkEvent, SimConfig,
    SimNode, SimTransport, SimWorld,
};
use rand::{SeedableRng, rngs::StdRng};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

type Host = NetworkAdapter<StdRng, SimTransport>;

fn signed_packet(identity: &Identity, tag: u8) -> Vec<u8> {
    let payload = format!("stored-{tag}").into_bytes();
    let mut header = Header {
        class: PacketClass::Broadcast,
        dst: None,
        msg_id: [0; 16].into(),
        origin: [0; 16],
        created_ms: 0,
        lifetime_s: 3_600,
        payload_len: payload.len() as u64,
        ttl: 6,
        hops: 0,
    };
    let signature = sign_packet(identity, &mut header, &payload).expect("signs");
    Packet::new(header, signature, &payload)
        .expect("fields agree")
        .encode()
}

fn insert(store: &mut MemoryStore, now: u64, wire: &[u8]) -> bool {
    let metadata = StoreMetadata {
        copies_left: 1,
        first_seen: now,
        received_at: now,
        priority: 0,
        received_from: None,
        age_ms: 0,
    };
    let Ok(message) = StoredMessage::new(wire, metadata) else {
        return false;
    };
    store.put(now, message).is_ok()
}

struct Node {
    host: Host,
    identity: Identity,
    store: MemoryStore,
    dirty: bool,
    next_summary_at: u64,
    contact_link: Option<LinkId>,
    contact_peer: Option<[u8; 16]>,
    releases: usize,
}

impl Node {
    fn new(
        world: &SimWorld,
        seed: u64,
        hint: [u8; 8],
        messages: Vec<Vec<u8>>,
        contact_peer: Option<[u8; 16]>,
    ) -> Self {
        let radio = world
            .add_node(SimNode::default())
            .expect("sim node is valid");
        let identity = Identity::from_seed([seed as u8; 32]);
        let network = Network::new(
            NetworkConfig::default()
                .with_max_links(5)
                .expect("five slots fit"),
            radio,
        );
        let engine = ao_mesh::MeshEngine::new(StdRng::seed_from_u64(seed));
        let mut host = NetworkAdapter::new(engine, network);
        let mut store = MemoryStore::new(Default::default());
        for wire in &messages {
            assert!(insert(&mut store, 0, wire), "seed item fits");
        }
        let ids = store.summary(0);
        let digest = StoreSummary::from_store(&store, 0).digest();
        let signed = MeshHello::sign(&identity, hint, digest).expect("identity signs");
        let tag_bytes = seed.to_be_bytes().repeat(2);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_bytes[..16]);
        let applied = host.apply(
            world.now(),
            vec![
                MeshOutput::SetHello {
                    tag: LocalTag::new(tag),
                    app_hello: AppHello::new(signed.encode().to_vec()).expect("hello fits"),
                },
                MeshOutput::SetBeacon {
                    hint,
                    digest,
                    flags: BeaconFlags {
                        accepting: true,
                        relay_willing: true,
                        low_battery: false,
                    },
                },
            ],
        );
        assert!(
            applied.is_empty(),
            "setup emits no host events: {applied:?}"
        );
        let outputs = host
            .engine_mut()
            .handle(0, MeshInput::StoreSummary { ids: &ids })
            .expect("initial summary");
        assert!(outputs.is_empty(), "the first beacon is debounced");

        Self {
            host,
            identity,
            store,
            dirty: false,
            next_summary_at: 200,
            contact_link: None,
            contact_peer,
            releases: 0,
        }
    }

    fn service(&mut self, now: Duration, now_ms: u64, outputs: Vec<MeshOutput>) {
        for output in outputs {
            match output {
                MeshOutput::SyncNeed { link, prefixes } => {
                    let ids = self.store.summary(now_ms);
                    let offers: Vec<SyncOffer<'_>> = prefixes
                        .iter()
                        .filter_map(|prefix| {
                            let id = ids
                                .iter()
                                .find(|id| id.as_bytes()[..SHORT_ID_BYTES] == prefix[..])?;
                            let message = self.store.get(now_ms, id)?;
                            Some(SyncOffer {
                                prefix: *prefix,
                                wire: message.wire(),
                            })
                        })
                        .collect();
                    let extra = self
                        .host
                        .engine_mut()
                        .handle(
                            now_ms,
                            MeshInput::SyncItems {
                                link,
                                items: &offers,
                            },
                        )
                        .expect("host offers are valid");
                    self.service(now, now_ms, extra);
                }
                MeshOutput::SyncItem { wire, .. } => {
                    if insert(&mut self.store, now_ms, &wire) {
                        self.dirty = true;
                    }
                }
                MeshOutput::ReleaseOpportunistic { link } => {
                    let _ = self
                        .host
                        .apply(now, vec![MeshOutput::ReleaseOpportunistic { link }]);
                    self.releases += 1;
                }
                other => {
                    let _ = self.host.apply(now, vec![other]);
                }
            }
        }
    }

    fn poll(&mut self, now: Duration, now_ms: u64, cx: &mut Context<'_>, contact_start: u64) {
        loop {
            let event = match self.host.network_mut().poll_event(cx, now) {
                Poll::Pending => break,
                Poll::Ready(event) => event,
            };
            let input = match &event {
                NetworkEvent::LinkUp { link, remote_hello } => {
                    if now_ms >= contact_start && self.contact_link.is_none() {
                        let peer_matches = self.contact_peer.is_some_and(|peer| {
                            ao_mesh::hello::verified_hello(remote_hello.app_hello.as_bytes())
                                .is_ok_and(|hello| hello.node_id.as_bytes() == &peer)
                        });
                        if peer_matches {
                            self.contact_link = Some(*link);
                        }
                    }
                    MeshInput::LinkUp {
                        link: *link,
                        remote_hello: remote_hello.clone(),
                    }
                }
                NetworkEvent::LinkDown { link, reason } => MeshInput::LinkDown {
                    link: *link,
                    reason: *reason,
                },
                NetworkEvent::Data {
                    link,
                    channel,
                    payload,
                } => MeshInput::Data {
                    link: *link,
                    channel: *channel,
                    payload,
                    identity: &self.identity,
                },
                _ => continue,
            };
            let outputs = self
                .host
                .engine_mut()
                .handle(now_ms, input)
                .expect("simulator input is well formed");
            self.service(now, now_ms, outputs);
        }
    }

    fn refresh_summary(&mut self, now: Duration, now_ms: u64) {
        if !self.dirty || now_ms < self.next_summary_at {
            return;
        }
        let ids = self.store.summary(now_ms);
        let outputs = self
            .host
            .engine_mut()
            .handle(now_ms, MeshInput::StoreSummary { ids: &ids })
            .expect("refreshed summary");
        self.dirty = false;
        self.next_summary_at = now_ms + 200;
        self.service(now, now_ms, outputs);
    }
}

#[test]
fn two_nodes_meeting_for_twenty_seconds_converge_and_release() {
    let world = SimWorld::new(SimConfig {
        seed: 0x5147_2026,
        ..SimConfig::default()
    });
    let owner = Identity::from_seed([1; 32]);
    let peer = Identity::from_seed([2; 32]);
    let mut messages_a = Vec::new();
    let mut messages_b = Vec::new();
    for tag in 0..3 {
        messages_a.push(signed_packet(&owner, tag));
    }
    messages_b.push(signed_packet(&peer, 9));

    // The filler nodes let aoNetwork fill its stable slots so the contact
    // between `a` and `b` is admitted as opportunistic (NET-22).
    // The fillers carry the same digest as `a`, so their meetings admit only
    // stable links and leave the opportunistic slot free for `b`.
    let filler_messages = messages_a.clone();
    let mut a = Node::new(&world, 10, [1; 8], messages_a, None);
    let mut filler1 = Node::new(&world, 11, [2; 8], filler_messages.clone(), None);
    let mut filler2 = Node::new(&world, 12, [3; 8], filler_messages.clone(), None);
    let mut filler3 = Node::new(&world, 14, [4; 8], filler_messages, None);
    let mut b = Node::new(&world, 13, [9; 8], messages_b, None);
    a.contact_peer = Some(*b.identity.node_id().as_bytes());

    let fillers = [
        a.host.network().transport().node(),
        filler1.host.network().transport().node(),
        filler2.host.network().transport().node(),
        filler3.host.network().transport().node(),
    ];
    for (x, y) in [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)] {
        world.set_in_range(fillers[x], fillers[y], true);
    }

    let mut cx = Context::from_waker(Waker::noop());
    let contact_start = 12_000;
    for _ in 0..1_600 {
        world.advance(Duration::from_millis(20));
        let now = world.now();
        let now_ms = now.as_millis() as u64;
        if now_ms == contact_start {
            world.set_in_range(
                a.host.network().transport().node(),
                b.host.network().transport().node(),
                true,
            );
        }
        filler1.poll(now, now_ms, &mut cx, contact_start);
        filler2.poll(now, now_ms, &mut cx, contact_start);
        filler3.poll(now, now_ms, &mut cx, contact_start);
        a.poll(now, now_ms, &mut cx, contact_start);
        b.poll(now, now_ms, &mut cx, contact_start);
        a.refresh_summary(now, now_ms);
        b.refresh_summary(now, now_ms);
    }

    let expected = a.store.summary(32_000);
    assert_eq!(expected.len(), 4, "the union holds every seeded item");
    assert_eq!(
        b.store.summary(32_000),
        expected,
        "the two stores converged on the same ids"
    );
    let link = a
        .contact_link
        .expect("an opportunistic contact was established");
    assert!(
        !a.host
            .network()
            .links()
            .iter()
            .any(|info| info.link == link),
        "the opportunistic contact was released after sync"
    );
    assert!(a.releases >= 1 && b.releases >= 1, "both sides finished");
}
