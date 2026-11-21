//! MSH-25 acceptance: advisory link hints are deterministic, bounded and
//! driven by contact, diversity and penalty facts. aoNetwork remains the
//! only component that forms links; these tests inspect the engine seam.

use ao_idents::{Identity, NodeId};
use ao_mesh::{
    CAP_SPRAY_V1, LinkHintConfig, LinkHintObservation, MeshConfig, MeshEngine, MeshHello,
    MeshInput, MeshOutput, NodeObservation,
};
use ao_network::{AppHello, Channel, Hello, LinkHintPreference, LinkId, LocalTag, PeerKey};
use rand::{SeedableRng, rngs::StdRng};

const LINK: LinkId = LinkId::new(1);

fn engine(max_peers: usize) -> MeshEngine<StdRng> {
    MeshEngine::with_config(
        StdRng::seed_from_u64(0x25),
        MeshConfig {
            link_hints: LinkHintConfig {
                max_peers,
                ..LinkHintConfig::default()
            },
            ..MeshConfig::default()
        },
    )
}

fn hello(identity: &Identity, tag: u8) -> Hello {
    let signed = MeshHello::sign_with_caps(identity, [0; 8], [0; 4], CAP_SPRAY_V1)
        .expect("fixed identity signs hello");
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps: signed.caps,
        max_frame: 16_384,
        tag: LocalTag::new([tag; 16]),
        app_hello: AppHello::new(signed.encode().to_vec()).expect("hello fits"),
    }
}

fn hint_changes(outputs: &[MeshOutput]) -> Vec<MeshOutput> {
    outputs
        .iter()
        .filter(|output| {
            matches!(
                output,
                MeshOutput::SetLinkHint { .. } | MeshOutput::ClearLinkHint { .. }
            )
        })
        .cloned()
        .collect()
}

fn observe_hint(
    engine: &mut MeshEngine<StdRng>,
    now: u64,
    observation: LinkHintObservation,
) -> Vec<MeshOutput> {
    engine
        .handle(now, MeshInput::ObserveLinkHint { observation })
        .expect("bounded host fact")
}

#[test]
fn contact_advice_is_set_and_a_revocation_clears_it() {
    let peer = PeerKey::new([3; 16]);
    let node = NodeId::from_bytes([9; 16]);
    let mut engine = engine(4);
    assert_eq!(
        observe_hint(
            &mut engine,
            10,
            LinkHintObservation {
                peer,
                node,
                contact: true,
            }
        ),
        vec![MeshOutput::SetLinkHint {
            peer,
            preference: LinkHintPreference::Prefer,
        }]
    );
    assert_eq!(engine.link_hints().len(), 1);
    assert_eq!(
        engine.link_hints().preference(peer),
        LinkHintPreference::Prefer
    );

    assert_eq!(
        observe_hint(
            &mut engine,
            20,
            LinkHintObservation {
                peer,
                node,
                contact: false,
            }
        ),
        vec![MeshOutput::ClearLinkHint { peer }]
    );
    assert_eq!(
        engine.link_hints().preference(peer),
        LinkHintPreference::Neutral
    );
}

#[test]
fn penalty_from_a_linked_neighbour_overrides_contact_then_recovers_on_tick() {
    let peer = Identity::from_seed([7; 32]);
    let node = peer.node_id();
    let key = PeerKey::new([5; 16]);
    let mut engine = engine(4);
    engine
        .handle(
            10,
            MeshInput::LinkUp {
                link: LINK,
                remote_hello: hello(&peer, 7),
            },
        )
        .expect("verified hello");
    // A malformed packet is attributable to the sending neighbour under
    // MSH-10; one invalid packet reaches MSH-25's penalty threshold.
    let _ = engine
        .handle(
            20,
            MeshInput::Data {
                link: LINK,
                channel: Channel::Message,
                identity: &peer,
                payload: &[0xff],
            },
        )
        .expect("bounded invalid packet");

    assert_eq!(
        observe_hint(
            &mut engine,
            30,
            LinkHintObservation {
                peer: key,
                node,
                contact: true,
            }
        ),
        vec![MeshOutput::SetLinkHint {
            peer: key,
            preference: LinkHintPreference::Deprioritize,
        }]
    );

    // Penalty decays on a Tick, so the preference must be recomputed even
    // when the host supplies no new fact.
    let identity = Identity::from_seed([1; 32]);
    let outputs = engine
        .handle(
            130_000,
            MeshInput::Tick {
                identity: &identity,
                card_hash: [0; 8],
            },
        )
        .expect("valid tick");
    assert_eq!(
        hint_changes(&outputs),
        vec![MeshOutput::SetLinkHint {
            peer: key,
            preference: LinkHintPreference::Prefer,
        }]
    );
}

#[test]
fn diversity_prefers_unlinked_paths_and_stops_when_the_peer_is_linked() {
    let candidate = Identity::from_seed([9; 32]);
    let linked = Identity::from_seed([8; 32]);
    let key = PeerKey::new([9; 16]);
    let mut engine = engine(4);

    for (index, destination) in [1u8, 2].into_iter().enumerate() {
        engine
            .handle(
                20,
                MeshInput::ObserveNode {
                    observation: NodeObservation {
                        node: NodeId::from_bytes([destination; 16]),
                        card_hash: [0; 8],
                        caps: 0,
                        seq: 1,
                        hops: 1,
                        via: candidate.node_id(),
                        observed_at_ms: 20,
                        location: &[],
                    },
                },
            )
            .expect("bounded directory fact");
        let _ = index;
    }
    assert_eq!(
        observe_hint(
            &mut engine,
            30,
            LinkHintObservation {
                peer: key,
                node: candidate.node_id(),
                contact: false,
            }
        ),
        vec![MeshOutput::SetLinkHint {
            peer: key,
            preference: LinkHintPreference::Prefer,
        }]
    );

    engine
        .handle(
            40,
            MeshInput::LinkUp {
                link: LINK,
                remote_hello: hello(&candidate, 9),
            },
        )
        .expect("verified hello");
    let identity = Identity::from_seed([1; 32]);
    let outputs = engine
        .handle(
            50,
            MeshInput::Tick {
                identity: &identity,
                card_hash: [0; 8],
            },
        )
        .expect("valid tick");
    assert_eq!(
        hint_changes(&outputs),
        vec![MeshOutput::ClearLinkHint { peer: key }],
        "a linked peer no longer adds a new path"
    );

    // A different linked neighbour does not suppress an unlinked candidate.
    engine
        .handle(
            60,
            MeshInput::LinkUp {
                link: LinkId::new(2),
                remote_hello: hello(&linked, 8),
            },
        )
        .expect("verified hello");
    for destination in [3u8, 4] {
        engine
            .handle(
                70,
                MeshInput::ObserveNode {
                    observation: NodeObservation {
                        node: NodeId::from_bytes([destination; 16]),
                        card_hash: [0; 8],
                        caps: 0,
                        seq: 1,
                        hops: 1,
                        via: linked.node_id(),
                        observed_at_ms: 70,
                        location: &[],
                    },
                },
            )
            .expect("bounded directory fact");
    }
    let other = PeerKey::new([8; 16]);
    assert_eq!(
        observe_hint(
            &mut engine,
            80,
            LinkHintObservation {
                peer: other,
                node: linked.node_id(),
                contact: false,
            }
        ),
        Vec::<MeshOutput>::new(),
        "an already linked peer is not a dial candidate"
    );
    assert!(engine.link_hints().is_empty());
}

#[test]
fn a_flood_of_host_facts_stays_bounded_and_deterministic() {
    let run = |limit: usize| {
        let mut engine = engine(limit);
        let mut all = Vec::new();
        for i in 0..256u16 {
            let mut bytes = [0u8; 16];
            bytes[..2].copy_from_slice(&i.to_le_bytes());
            let outputs = observe_hint(
                &mut engine,
                i.into(),
                LinkHintObservation {
                    peer: PeerKey::new(bytes),
                    node: NodeId::from_bytes(bytes),
                    contact: true,
                },
            );
            assert!(outputs.len() <= 2, "at most one eviction and one set");
            all.extend(outputs);
            assert!(engine.link_hints().len() <= limit);
        }
        (all, engine.link_hints().counters())
    };
    let (first, counters) = run(4);
    let (second, counters_again) = run(4);
    assert_eq!(first, second);
    assert_eq!(counters, counters_again);
    assert!(run(0).0.is_empty(), "a zero cap disables all advice");
}
