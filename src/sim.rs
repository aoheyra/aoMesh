//! Seeded SimWorld scenarios and metrics for the mesh engine (MSH-27).
//!
//! This module is host-side test tooling behind feature `sim`; the sans-IO
//! core never sees a simulator. It drives real `Network` facades, signed
//! `MeshHello`s, transport events and the engine on aoNetwork's paused
//! `SimWorld`. Everything is seeded: the same scenario and seed reproduce
//! the same positions, connect jitter, traffic and numbers.
//!
//! One scenario runs in three phases:
//!
//! 1. settle until links have formed at the seeded radio topology;
//! 2. submit sealed Direct messages from spread-out origins, one flooding
//!    origin in MSH-10's ablation case, or plain Broadcast messages in
//!    MSH-11's suppression case, staggered so mobility and scripted contacts
//!    can affect them;
//! 3. advance the world, applying optional mobility, and record deliveries,
//!    unique Broadcast receptions, transmissions, queue occupancy and radio
//!    bytes.
//!
//! The report is one CSV row per scenario. `examples/sim_report` writes it
//! and `tests/sim_baseline.rs` enforces the published numbers. Per-origin
//! delivery counts are kept off the CSV for the MSH-10 flood test.

use crate::{
    Header, MeshConfig, MeshEngine, MeshHello, MeshInput, MeshOutput, MessageId, NetworkAdapter,
    PacketClass, SuppressionConfig, derive_msg_id, sign_packet,
};
use ao_idents::{Identity, SealedMessage};
use ao_network::{
    AppHello, BeaconFlags, LinkId, LinkInfo, LocalTag, Network, NetworkConfig, NetworkEvent,
    SimConfig as WorldConfig, SimNode, SimTransport, SimWorld,
};
use rand::{SeedableRng as SeedableRng09, rngs::StdRng as EngineRng};
use rand08::{SeedableRng as SeedableRng08, rngs::StdRng as SealRng};
use std::collections::{BTreeMap, BTreeSet};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// Poll step: the world runs scheduled events exactly, so this only bounds
/// how late a node reacts to them.
const TICK: Duration = Duration::from_millis(50);
/// Radio range in the position units used by random and community layouts.
const RADIUS: i64 = 100;

/// Where nodes start and which pairs are in radio range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Topology {
    /// Uniform random positions in a square sized for about six neighbours.
    Random,
    /// A chain of `n` nodes, each in range of its immediate neighbours.
    Line,
    /// A cycle of `n` nodes, each in range of its two neighbours.
    Ring,
    /// `groups` clusters with seeded centres, for community mobility.
    Communities {
        /// Number of equally sized communities.
        groups: usize,
    },
    /// A permanent chain plus extra contacts that toggle at a given time.
    Scripted(Vec<Contact>),
}

/// One scripted radio-range change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contact {
    /// Milliseconds from the start of the run phase.
    pub at_ms: u64,
    /// First node.
    pub a: usize,
    /// Second node.
    pub b: usize,
    /// Whether the pair becomes in range or out of range.
    pub up: bool,
}

/// How node positions change during the run phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mobility {
    /// Nobody moves.
    Static,
    /// Move one seeded node to a seeded new position at each interval.
    RandomWaypoint {
        /// How often one node jumps to a new position.
        every: Duration,
    },
    /// Move one node within its community at each interval.
    Community {
        /// How often one node drifts.
        every: Duration,
    },
    /// Contacts come from [`Topology::Scripted`] instead of positions.
    Scripted,
}

/// How submitted messages are shared between origins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Traffic {
    /// Rotate evenly across every node, as the published baselines do.
    Balanced,
    /// Give one origin `weight` messages per round and spread the rest.
    ///
    /// This is how MSH-10 exercises a flooding origin without changing
    /// packet size or the honest nodes' allowance.
    Flood {
        /// Node index of the abusive origin.
        origin: usize,
        /// Number of flood messages per honest message.
        weight: usize,
    },
    /// Submit plain Broadcast messages from one origin (MSH-11).
    ///
    /// Broadcast has no sealed `Deliver` until later issues, so this case
    /// measures unique content receptions per node instead.
    Broadcast {
        /// Node index of the flooding origin.
        origin: usize,
    },
    /// Mostly Broadcast from one origin, with sealed Direct canaries.
    ///
    /// The canaries keep the MSH-27 delivery ratio meaningful while the
    /// flooded class supplies the transmission count MSH-11 measures.
    MixedBroadcast {
        /// Node index of the flooding origin.
        origin: usize,
        /// Submit one Direct canary every `direct_every` messages.
        direct_every: usize,
    },
}

/// One reproducible experiment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scenario {
    /// Name printed in the CSV report.
    pub name: &'static str,
    /// Seeds connect jitter, positions, identities and sealed payloads.
    pub seed: u64,
    /// Number of simulated nodes.
    pub nodes: usize,
    /// Starting radio topology.
    pub topology: Topology,
    /// Mobility during the run phase.
    pub mobility: Mobility,
    /// Time to let links form before any message is submitted.
    pub settle: Duration,
    /// Time messages have to propagate.
    pub run: Duration,
    /// Number of sealed Direct messages to submit.
    pub messages: usize,
    /// Plaintext bytes per message.
    pub payload_len: usize,
    /// Origin pattern used for submissions.
    pub traffic: Traffic,
    /// Whether engines enforce MSH-10 budgets and penalties.
    ///
    /// Ablation runs set this to false to measure an unbounded flood.
    pub enforce_budgets: bool,
    /// Whether engines enforce MSH-11 suppression for flooded classes.
    ///
    /// Ablation runs set this to false to measure immediate flooding.
    pub enforce_suppression: bool,
    /// Suppression bounds and timer parameters under test.
    pub suppression: SuppressionConfig,
}

/// Everything one run measured. Ratios are fractions, not percentages.
#[derive(Clone, Debug, PartialEq)]
pub struct Metrics {
    /// Scenario name.
    pub scenario: &'static str,
    /// Reproduction seed.
    pub seed: u64,
    /// Simulated node count.
    pub nodes: usize,
    /// Messages submitted to the mesh, of every class.
    pub submitted: u64,
    /// Sealed Direct submissions, the denominator of `delivery_ratio`.
    ///
    /// Equals `submitted` for the published Direct-only baselines.
    pub direct_submitted: u64,
    /// Authenticated deliveries emitted at destinations.
    pub delivered: u64,
    /// Deliveries of a message id already delivered at that node.
    pub duplicate_deliveries: u64,
    /// Mesh-level packet sends, including one per link of a broadcast.
    pub transmissions: u64,
    /// Structurally valid receptions counted by neighbour tables.
    pub receptions: u64,
    /// Sends the network refused (queue full or closed link).
    pub send_failures: u64,
    /// Simulator radio bytes written, settlement excluded.
    pub radio_bytes: u64,
    /// Mean delivery latency in milliseconds, from `created_ms`.
    pub mean_latency_ms: u64,
    /// Slowest delivery latency in milliseconds.
    pub max_latency_ms: u64,
    /// Deliveries per submitted message.
    pub delivery_ratio: f64,
    /// Transmissions per delivery.
    pub overhead: f64,
    /// Duplicate deliveries per delivery.
    pub duplicate_ratio: f64,
    /// Peak sum of bytes waiting in all send queues.
    pub peak_queued_bytes: usize,
    /// Up links once settlement finished.
    pub links_after_settle: usize,
    /// Unique deliveries attributed to each submitting node index.
    ///
    /// Not part of the CSV report; MSH-10 uses it to check that a flood
    /// is throttled without hurting honest origins.
    pub delivered_by_origin: Vec<u64>,
    /// Unique Broadcast content addresses observed at each node index.
    ///
    /// Not part of the CSV report. Broadcast has no `Deliver` event yet, so
    /// MSH-11 uses these receptions as its reachability measure.
    pub unique_receptions_by_node: Vec<u64>,
    /// Sum of unique receptions across all nodes.
    ///
    /// Not part of the CSV report.
    pub unique_receptions: u64,
}

impl Metrics {
    /// CSV column names, in the same order as [`Self::csv_row`].
    pub fn csv_header() -> &'static str {
        "scenario,seed,nodes,submitted,delivered,duplicate_deliveries,transmissions,receptions,send_failures,radio_bytes,mean_latency_ms,max_latency_ms,delivery_ratio,overhead,duplicate_ratio,peak_queued_bytes,links_after_settle"
    }
    /// One CSV line with four decimal places on every ratio.
    pub fn csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{:.4},{:.4},{:.4},{},{}",
            self.scenario,
            self.seed,
            self.nodes,
            self.submitted,
            self.delivered,
            self.duplicate_deliveries,
            self.transmissions,
            self.receptions,
            self.send_failures,
            self.radio_bytes,
            self.mean_latency_ms,
            self.max_latency_ms,
            self.delivery_ratio,
            self.overhead,
            self.duplicate_ratio,
            self.peak_queued_bytes,
            self.links_after_settle,
        )
    }
}

/// The fixed cases CI runs. Sizes span 20 to 200 nodes and cover static,
/// random-waypoint, community and scripted-contact models.
pub fn baseline_scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "line-20",
            seed: 1_297_303_584,
            nodes: 20,
            topology: Topology::Line,
            mobility: Mobility::Static,
            settle: Duration::from_secs(30),
            run: Duration::from_secs(30),
            messages: 20,
            payload_len: 128,
            traffic: Traffic::Balanced,
            enforce_budgets: true,
            enforce_suppression: true,
            suppression: SuppressionConfig::default(),
        },
        Scenario {
            name: "waypoint-50",
            seed: 1_297_303_632,
            nodes: 50,
            topology: Topology::Random,
            mobility: Mobility::RandomWaypoint {
                every: Duration::from_secs(5),
            },
            settle: Duration::from_secs(60),
            run: Duration::from_secs(60),
            messages: 50,
            payload_len: 128,
            traffic: Traffic::Balanced,
            enforce_budgets: true,
            enforce_suppression: true,
            suppression: SuppressionConfig::default(),
        },
        Scenario {
            name: "community-100",
            seed: 1_297_303_652,
            nodes: 100,
            topology: Topology::Communities { groups: 4 },
            mobility: Mobility::Community {
                every: Duration::from_secs(5),
            },
            settle: Duration::from_secs(90),
            run: Duration::from_secs(90),
            messages: 80,
            payload_len: 128,
            traffic: Traffic::Balanced,
            enforce_budgets: true,
            enforce_suppression: true,
            suppression: SuppressionConfig::default(),
        },
        Scenario {
            name: "scripted-200",
            seed: 1_297_303_752,
            nodes: 200,
            topology: Topology::Scripted(scripted_contacts(200)),
            mobility: Mobility::Scripted,
            settle: Duration::from_secs(60),
            run: Duration::from_secs(60),
            messages: 100,
            payload_len: 128,
            traffic: Traffic::Balanced,
            enforce_budgets: true,
            enforce_suppression: true,
            suppression: SuppressionConfig::default(),
        },
    ]
}

/// MSH-10's fixed flood case: one origin sends as many oversized messages
/// as all honest nodes together on a static 20-node random graph.
///
/// The origin's 300 messages carry 850 plaintext bytes each (1117 sealed),
/// well past what the 1 MiB/h Direct bucket can refill during the run, while
/// honest origins stay far below their own allowances. The fixed seed keeps
/// the flooder connected to several disjoint routes, so releasing its link
/// does not decide the outcome by partitioning the graph.
pub fn flood_scenarios() -> Vec<Scenario> {
    vec![Scenario {
        name: "flood-random-20",
        seed: 1_297_304_003,
        nodes: 20,
        topology: Topology::Random,
        mobility: Mobility::Static,
        settle: Duration::from_secs(30),
        run: Duration::from_secs(120),
        messages: 600,
        payload_len: 850,
        traffic: Traffic::Flood {
            origin: 0,
            weight: 1,
        },
        enforce_budgets: true,
        enforce_suppression: true,
        suppression: SuppressionConfig::default(),
    }]
}

/// MSH-11's fixed 50-node suppression case.
///
/// One origin submits plain Broadcast packets into a static random graph;
/// every tenth message is instead a sealed Direct canary so the MSH-27
/// delivery ratio remains meaningful. The paired ablation sets
/// `enforce_suppression = false`, which is exactly the old immediate-flooding
/// behaviour, so the comparison isolates the counter-based relay decision
/// from topology and radio contention.
pub fn suppression_scenarios() -> Vec<Scenario> {
    vec![Scenario {
        name: "suppression-random-50",
        seed: 1_297_304_013,
        nodes: 50,
        topology: Topology::Random,
        mobility: Mobility::Static,
        settle: Duration::from_secs(30),
        run: Duration::from_secs(60),
        messages: 100,
        payload_len: 128,
        traffic: Traffic::MixedBroadcast {
            origin: 0,
            direct_every: 10,
        },
        enforce_budgets: true,
        enforce_suppression: true,
        suppression: SuppressionConfig::default(),
    }]
}

/// A permanent chain plus short-lived shortcuts on a 200-node chain.
fn scripted_contacts(n: usize) -> Vec<Contact> {
    let mut contacts = Vec::new();
    for i in 0..n.saturating_sub(4) {
        if i % 4 == 0 {
            contacts.push(Contact {
                at_ms: 10_000 + (i as u64 % 20) * 1_000,
                a: i,
                b: i + 4,
                up: true,
            });
            contacts.push(Contact {
                at_ms: 40_000 + (i as u64 % 20) * 1_000,
                a: i,
                b: i + 4,
                up: false,
            });
        }
    }
    contacts
}

/// SplitMix64, the harness's only source of topology randomness.
fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

struct Node {
    adapter: NetworkAdapter<EngineRng, SimTransport>,
    pos: (i64, i64),
    group: usize,
}

/// Owns the simulated world and the metrics accumulated while driving it.
pub struct Simulation {
    scenario: Scenario,
    world: SimWorld,
    nodes: Vec<Node>,
    identities: Vec<Identity>,
    ranges: Vec<Vec<bool>>,
    applied: Vec<Vec<bool>>,
    contacts: Vec<Contact>,
    contact_cursor: usize,
    run_start_ms: u64,
    run_started: bool,
    side: i64,
    rng: u64,
    submitted: u64,
    direct_submitted: u64,
    delivered: u64,
    duplicate_deliveries: u64,
    transmissions: u64,
    send_failures: u64,
    radio_bytes_run: u64,
    peak_queued_bytes: usize,
    pending: Vec<BTreeMap<LinkId, u64>>,
    tx_last: Vec<BTreeMap<LinkId, u64>>,
    radio_tx_last: Vec<BTreeMap<LinkId, u64>>,
    latencies: Vec<u64>,
    delivered_ids: Vec<BTreeSet<MessageId>>,
    delivered_by_origin: Vec<u64>,
    received_ids: Vec<BTreeSet<MessageId>>,
    origin_index: BTreeMap<[u8; 16], usize>,
    links_after_settle: usize,
}

impl Simulation {
    /// Builds a paused world with `scenario.nodes` signed, accepting nodes.
    ///
    /// # Panics
    ///
    /// On invalid scenario input (zero nodes, no messages) or a failure to
    /// set up the fixed signed hello. Both are caller configuration errors,
    /// never packet-driven paths.
    pub fn new(scenario: Scenario) -> Self {
        assert!(scenario.nodes > 0, "a scenario needs nodes");
        assert!(scenario.messages > 0, "a scenario needs messages");
        let world = SimWorld::new(WorldConfig {
            seed: scenario.seed,
            ..WorldConfig::default()
        });
        let n = scenario.nodes;
        let radius = RADIUS;
        let side = ((n as f64 * std::f64::consts::PI / 6.0).sqrt() * radius as f64) as i64;
        let side = side.max(radius * 4);
        let mut rng = scenario.seed;
        let mut nodes = Vec::with_capacity(n);
        let mut identities = Vec::with_capacity(n);
        for i in 0..n {
            let radio = world
                .add_node(SimNode::default())
                .expect("sim node is valid");
            let mut seed_input = [0u8; 16];
            seed_input[..8].copy_from_slice(&scenario.seed.to_be_bytes());
            seed_input[8..].copy_from_slice(&(i as u64).to_be_bytes());
            let mut seed = [0u8; 32];
            seed.copy_from_slice(blake3::hash(&seed_input).as_bytes());
            let identity = Identity::from_seed(seed);
            let engine_rng = EngineRng::seed_from_u64(scenario.seed ^ (i as u64 + 1));
            let mut engine_config = MeshConfig::default();
            engine_config.budgets.enforce = scenario.enforce_budgets;
            engine_config.suppression = SuppressionConfig {
                enabled: scenario.enforce_suppression,
                ..scenario.suppression
            };
            let engine = MeshEngine::with_config(engine_rng, engine_config);
            // Baseline nodes have empty stores. The hello and beacon must
            // advertise the engine's actual digest, otherwise every link
            // looks different and MSH-14 starts a needless sync contact.
            let store_digest = engine.sync().local_digest();
            let mut adapter =
                NetworkAdapter::new(engine, Network::new(NetworkConfig::default(), radio));
            let tag = {
                let mut t = next(&mut rng).to_be_bytes().repeat(2);
                t[0] = i as u8;
                let mut out = [0u8; 16];
                out.copy_from_slice(&t[..16]);
                LocalTag::new(out)
            };
            let signed =
                MeshHello::sign(&identity, [0; 8], store_digest).expect("fixed identity signs");
            let applied = adapter.apply(
                world.now(),
                vec![
                    MeshOutput::SetHello {
                        tag,
                        app_hello: AppHello::new(signed.encode().to_vec()).expect("hello fits"),
                    },
                    MeshOutput::SetBeacon {
                        hint: next(&mut rng).to_be_bytes(),
                        digest: store_digest,
                        flags: BeaconFlags {
                            accepting: true,
                            ..BeaconFlags::default()
                        },
                    },
                ],
            );
            assert!(
                applied.is_empty(),
                "setup emits no host events: {applied:?}"
            );
            let pos = match scenario.topology {
                Topology::Line => ((i as i64) * radius, 0),
                Topology::Ring => ring_position(i, n, side),
                Topology::Random | Topology::Communities { .. } | Topology::Scripted(_) => {
                    let x = (next(&mut rng) % side as u64) as i64;
                    let y = (next(&mut rng) % side as u64) as i64;
                    (x, y)
                }
            };
            identities.push(identity);
            nodes.push(Node {
                adapter,
                pos,
                group: match scenario.topology {
                    Topology::Communities { groups } => i % groups.max(1),
                    _ => 0,
                },
            });
        }
        let mut ranges = vec![vec![false; n]; n];
        for a in 0..n {
            for b in a + 1..n {
                let on = match scenario.topology {
                    Topology::Line => b == a + 1,
                    Topology::Ring => b == a + 1 || (a == 0 && b == n - 1),
                    Topology::Random => near(nodes[a].pos, nodes[b].pos, radius),
                    Topology::Communities { .. } => {
                        near(nodes[a].pos, nodes[b].pos, radius)
                            || (nodes[a].group == nodes[b].group
                                && near(nodes[a].pos, nodes[b].pos, radius * 2))
                    }
                    Topology::Scripted(_) => b == a + 1,
                };
                ranges[a][b] = on;
                ranges[b][a] = on;
            }
        }
        let applied = vec![vec![false; n]; n];
        let delivered_ids = vec![BTreeSet::new(); n];
        let origin_index = identities
            .iter()
            .enumerate()
            .map(|(i, identity)| (*identity.node_id().as_bytes(), i))
            .collect();
        let mut contacts = match &scenario.topology {
            Topology::Scripted(contacts) => contacts.clone(),
            _ => Vec::new(),
        };
        contacts.sort_by_key(|contact| contact.at_ms);
        let mut sim = Self {
            scenario,
            world,
            nodes,
            identities,
            ranges,
            applied,
            contacts,
            contact_cursor: 0,
            run_start_ms: 0,
            run_started: false,
            side,
            rng,
            submitted: 0,
            direct_submitted: 0,
            delivered: 0,
            duplicate_deliveries: 0,
            transmissions: 0,
            send_failures: 0,
            radio_bytes_run: 0,
            peak_queued_bytes: 0,
            pending: vec![BTreeMap::new(); n],
            tx_last: vec![BTreeMap::new(); n],
            radio_tx_last: vec![BTreeMap::new(); n],
            latencies: Vec::new(),
            delivered_ids,
            delivered_by_origin: vec![0; n],
            received_ids: vec![BTreeSet::new(); n],
            origin_index,
            links_after_settle: 0,
        };
        sim.apply_ranges();
        sim
    }

    fn apply_ranges(&mut self) {
        let n = self.nodes.len();
        for a in 0..n {
            for b in a + 1..n {
                let on = self.ranges[a][b];
                if self.applied[a][b] == on {
                    continue;
                }
                let ra = self.nodes[a].adapter.network().transport().node();
                let rb = self.nodes[b].adapter.network().transport().node();
                self.world.set_in_range(ra, rb, on);
                self.applied[a][b] = on;
                self.applied[b][a] = on;
            }
        }
    }

    /// Bytes accepted by the network but not yet written to the radio.
    ///
    /// aoNetwork exposes per-link `tx_bytes` but not the queue itself, so the
    /// harness tracks enqueued bytes per link and retires them as the radio
    /// counter advances. A link that closes drops its remaining bytes.
    /// Radio bytes are accumulated per tick from every up link: subtracting
    /// two snapshots of only the currently up links would lose or invent
    /// bytes whenever mobility closes and opens links during the run.
    fn sample_queues(&mut self) {
        for i in 0..self.nodes.len() {
            let up: Vec<LinkInfo> = self.nodes[i].adapter.network().links();
            for link in &up {
                let tx = link.metrics.tx_bytes;
                let last = self.tx_last[i].insert(link.link, tx).unwrap_or(0);
                if let Some(pending) = self.pending[i].get_mut(&link.link) {
                    *pending = pending.saturating_sub(tx.saturating_sub(last));
                }
                if self.run_started {
                    let radio_last = self.radio_tx_last[i].insert(link.link, tx).unwrap_or(0);
                    self.radio_bytes_run = self
                        .radio_bytes_run
                        .saturating_add(tx.saturating_sub(radio_last));
                }
            }
            let up_ids: BTreeSet<LinkId> = up.iter().map(|link| link.link).collect();
            self.tx_last[i].retain(|link, _| up_ids.contains(link));
            self.pending[i].retain(|link, _| up_ids.contains(link));
        }
        let queued: usize = self
            .pending
            .iter()
            .flat_map(|links| links.values())
            .map(|bytes| *bytes as usize)
            .sum();
        self.peak_queued_bytes = self.peak_queued_bytes.max(queued);
    }

    fn reset_queue_baseline(&mut self) {
        for i in 0..self.nodes.len() {
            self.pending[i].clear();
            self.tx_last[i].clear();
            self.radio_tx_last[i].clear();
            for link in self.nodes[i].adapter.network().links() {
                self.tx_last[i].insert(link.link, link.metrics.tx_bytes);
                self.radio_tx_last[i].insert(link.link, link.metrics.tx_bytes);
            }
        }
        self.peak_queued_bytes = 0;
        self.radio_bytes_run = 0;
    }

    /// Advances the world, drives every node and samples queue occupancy.
    fn pump(&mut self, steps: usize) {
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..steps {
            self.world.advance(TICK);
            let now = self.world.now();
            let now_ms = now.as_millis() as u64;
            self.apply_mobility(now_ms);
            for i in 0..self.nodes.len() {
                loop {
                    let event = match self.nodes[i].adapter.network_mut().poll_event(&mut cx, now) {
                        Poll::Pending => break,
                        Poll::Ready(event) => event,
                    };
                    let (input, received_id) = match &event {
                        NetworkEvent::LinkUp { link, remote_hello } => (
                            MeshInput::LinkUp {
                                link: *link,
                                remote_hello: remote_hello.clone(),
                            },
                            None,
                        ),
                        NetworkEvent::LinkDown { link, reason } => {
                            self.pending[i].remove(link);
                            self.tx_last[i].remove(link);
                            (
                                MeshInput::LinkDown {
                                    link: *link,
                                    reason: *reason,
                                },
                                None,
                            )
                        }
                        NetworkEvent::Data {
                            link,
                            channel,
                            payload,
                        } => {
                            // Broadcast has no Deliver event yet. Count a
                            // structurally valid flooded packet as a unique
                            // reception at this node, once per content id.
                            let received_id = crate::Packet::decode(payload)
                                .ok()
                                .filter(|packet| {
                                    matches!(
                                        packet.header.class,
                                        PacketClass::Broadcast | PacketClass::Presence
                                    )
                                })
                                .map(|packet| packet.header.msg_id);
                            (
                                MeshInput::Data {
                                    link: *link,
                                    channel: *channel,
                                    payload,
                                    identity: &self.identities[i],
                                },
                                received_id,
                            )
                        }
                        _ => continue,
                    };
                    if let Some(id) = received_id {
                        self.received_ids[i].insert(id);
                    }
                    let outputs = self.nodes[i]
                        .adapter
                        .engine_mut()
                        .handle(now_ms, input)
                        .expect("engine inputs are well formed");
                    self.count_outputs(i, now_ms, &outputs);
                    let events = self.nodes[i].adapter.apply(now, outputs);
                    for event in events {
                        if let crate::AdapterEvent::SendFailed { .. } = event {
                            self.send_failures += 1;
                        }
                    }
                }
            }
            self.sample_queues();
        }
    }

    fn count_outputs(&mut self, node: usize, now_ms: u64, outputs: &[MeshOutput]) {
        for output in outputs {
            match output {
                MeshOutput::Send { link, payload, .. } => {
                    self.transmissions += 1;
                    *self.pending[node].entry(*link).or_insert(0) += payload.len() as u64;
                }
                MeshOutput::Broadcast { payload, .. } => {
                    let links = self.nodes[node].adapter.network().links();
                    self.transmissions += links.len() as u64;
                    for info in links {
                        *self.pending[node].entry(info.link).or_insert(0) += payload.len() as u64;
                    }
                }
                MeshOutput::Deliver { header, .. } => {
                    if self.delivered_ids[node].insert(header.msg_id) {
                        self.delivered += 1;
                        self.latencies
                            .push(now_ms.saturating_sub(header.created_ms));
                        if let Some(origin) = self.origin_index.get(&header.origin) {
                            self.delivered_by_origin[*origin] += 1;
                        }
                    } else {
                        self.duplicate_deliveries += 1;
                    }
                }
                _ => {}
            }
        }
    }

    fn apply_mobility(&mut self, now_ms: u64) {
        match self.scenario.mobility {
            Mobility::Static => {}
            Mobility::Scripted => self.apply_scripted_contacts(now_ms),
            Mobility::RandomWaypoint { every } | Mobility::Community { every } => {
                if now_ms % every.as_millis().max(1) as u64 != 0 {
                    return;
                }
                let n = self.nodes.len() as u64;
                let i = (next(&mut self.rng) % n) as usize;
                let (x, y) = match self.scenario.mobility {
                    Mobility::Community { .. } => {
                        let groups = match self.scenario.topology {
                            Topology::Communities { groups } => groups.max(1),
                            _ => 1,
                        };
                        let spread = self.side / (groups as i64 * 2);
                        let cx = self.nodes[i].group as i64 * (self.side / groups as i64)
                            + self.side / (groups as i64 * 2);
                        let cy = self.side / 2;
                        (
                            cx + (next(&mut self.rng) % spread as u64) as i64 - spread / 2,
                            cy + (next(&mut self.rng) % spread as u64) as i64 - spread / 2,
                        )
                    }
                    _ => (
                        (next(&mut self.rng) % self.side as u64) as i64,
                        (next(&mut self.rng) % self.side as u64) as i64,
                    ),
                };
                self.nodes[i].pos = (x, y);
                let pos = self.nodes[i].pos;
                let radius = RADIUS;
                for b in 0..self.nodes.len() {
                    if b == i {
                        continue;
                    }
                    let on = near(pos, self.nodes[b].pos, radius);
                    self.ranges[i][b] = on;
                    self.ranges[b][i] = on;
                }
                self.apply_ranges();
            }
        }
    }

    /// Applies contacts whose run-relative time has arrived, in seed order.
    fn apply_scripted_contacts(&mut self, now_ms: u64) {
        if !self.run_started {
            return;
        }
        let elapsed = now_ms.saturating_sub(self.run_start_ms);
        let mut changed = false;
        while self.contact_cursor < self.contacts.len()
            && self.contacts[self.contact_cursor].at_ms <= elapsed
        {
            let contact = self.contacts[self.contact_cursor];
            self.ranges[contact.a][contact.b] = contact.up;
            self.ranges[contact.b][contact.a] = contact.up;
            self.contact_cursor += 1;
            changed = true;
        }
        if changed {
            self.apply_ranges();
        }
    }

    /// Submits one sealed message at the current world time. Staggering
    /// these across the run phase is what lets mobility and scripted contacts
    /// affect delivery instead of finishing before the first contact changes.
    fn submit_one(&mut self, m: usize) {
        let n = self.nodes.len();
        let (origin, broadcast) = match self.scenario.traffic {
            Traffic::Balanced => (m % n, false),
            Traffic::Flood {
                origin: flood,
                weight,
            } => {
                let round = weight.max(1) + 1;
                if m % round == 0 {
                    (flood.min(n - 1), false)
                } else {
                    let honest = n - 1;
                    let slot = (m / round) * weight + (m % round) - 1;
                    ((flood.min(n - 1) + 1 + slot % honest) % n, false)
                }
            }
            Traffic::Broadcast { origin } => (origin.min(n - 1), true),
            Traffic::MixedBroadcast {
                origin,
                direct_every,
            } => {
                if m % direct_every.max(1) == 0 {
                    (m % n, false)
                } else {
                    (origin.min(n - 1), true)
                }
            }
        };
        // Destinations stay inside the packet's eight-hop TTL so the
        // baseline measures forwarding, not expiry at an impossible
        // graph distance. Reflect at the ends because a line has no
        // wrap-around edge; two hops or more still exercises relaying.
        let span = 2 + m % 7;
        let dst = if origin + span < n {
            origin + span
        } else {
            origin - span
        };
        let now_ms = self.world.now().as_millis() as u64;
        let mut rng = SealRng::seed_from_u64(self.scenario.seed ^ (m as u64 + 1));
        let plaintext = vec![(m % 251) as u8; self.scenario.payload_len];
        let (header, payload) = if broadcast {
            // Plain Broadcast: the engine caps TTL at ADR-0001's six hops
            // on submission. Payload is opaque to the mesh.
            let sender = &self.identities[origin];
            let mut header = Header {
                class: PacketClass::Broadcast,
                dst: None,
                msg_id: [0; 16].into(),
                origin: *sender.node_id().as_bytes(),
                created_ms: now_ms,
                lifetime_s: 600,
                payload_len: plaintext.len() as u64,
                ttl: 255,
                hops: 0,
            };
            let signature = sign_packet(sender, &mut header, &plaintext).expect("fixed key signs");
            let packet = crate::Packet::new(header, signature, &plaintext).expect("lengths agree");
            (packet.header, plaintext)
        } else {
            let sender = &self.identities[origin];
            let recipient = &self.identities[dst];
            let (mut header, payload) =
                seal_delivery(&mut rng, sender, recipient, now_ms, 3_600, 8, &plaintext)
                    .expect("fixed identities seal");
            let signature = sign_packet(sender, &mut header, &payload).expect("fixed key signs");
            let packet = crate::Packet::new(header, signature, &payload).expect("lengths agree");
            (packet.header, payload)
        };
        let submitted_id = header.msg_id;
        let outputs = self.nodes[origin]
            .adapter
            .engine_mut()
            .handle(
                now_ms,
                MeshInput::Submit {
                    identity: &self.identities[origin],
                    header,
                    payload: &payload,
                    via: None,
                },
            )
            .expect("valid submission");
        self.submitted += 1;
        if broadcast {
            self.received_ids[origin].insert(submitted_id);
        } else {
            self.direct_submitted += 1;
        }
        self.count_outputs(origin, now_ms, &outputs);
        let events = self.nodes[origin].adapter.apply(self.world.now(), outputs);
        for event in events {
            if let crate::AdapterEvent::SendFailed { .. } = event {
                self.send_failures += 1;
            }
        }
    }

    /// Runs the full scenario and returns its metrics.
    pub fn run(mut self) -> Metrics {
        let settle_steps = (self.scenario.settle.as_millis() / TICK.as_millis()) as usize;
        self.pump(settle_steps);
        self.links_after_settle = self
            .nodes
            .iter()
            .map(|node| node.adapter.engine().neighbors().len())
            .sum();
        self.run_start_ms = self.world.now().as_millis() as u64;
        self.run_started = true;
        self.reset_queue_baseline();
        let run_steps = (self.scenario.run.as_millis() / TICK.as_millis()) as usize;
        let steps = run_steps.max(1);
        // Keep the last fifth of the run free so the final message can
        // propagate; otherwise the last submission is cut off at the clock.
        let submit_steps = (steps * 4 / 5).max(1);
        for step in 0..steps {
            if step < submit_steps {
                let target = (step + 1) * self.scenario.messages / submit_steps;
                while (self.submitted as usize) < target {
                    self.submit_one(self.submitted as usize);
                }
            }
            self.pump(1);
        }
        let receptions = self
            .nodes
            .iter()
            .map(|node| {
                node.adapter
                    .engine()
                    .neighbors()
                    .iter()
                    .map(|neighbor| neighbor.received_packets)
                    .sum::<u64>()
            })
            .sum();
        let mean = if self.latencies.is_empty() {
            0
        } else {
            self.latencies.iter().sum::<u64>() / self.latencies.len() as u64
        };
        let max = self.latencies.iter().copied().max().unwrap_or(0);
        Metrics {
            scenario: self.scenario.name,
            seed: self.scenario.seed,
            nodes: self.scenario.nodes,
            submitted: self.submitted,
            direct_submitted: self.direct_submitted,
            delivered: self.delivered,
            duplicate_deliveries: self.duplicate_deliveries,
            transmissions: self.transmissions,
            receptions,
            send_failures: self.send_failures,
            radio_bytes: self.radio_bytes_run,
            mean_latency_ms: mean,
            max_latency_ms: max,
            delivery_ratio: self.delivered as f64
                / if self.direct_submitted > 0 {
                    self.direct_submitted
                } else {
                    self.submitted
                } as f64,
            overhead: self.transmissions as f64 / self.delivered.max(1) as f64,
            duplicate_ratio: self.duplicate_deliveries as f64 / self.delivered.max(1) as f64,
            peak_queued_bytes: self.peak_queued_bytes,
            links_after_settle: self.links_after_settle,
            delivered_by_origin: self.delivered_by_origin,
            unique_receptions_by_node: self
                .received_ids
                .iter()
                .map(|ids| ids.len() as u64)
                .collect(),
            unique_receptions: self.received_ids.iter().map(BTreeSet::len).sum::<usize>() as u64,
        }
    }
}

/// Runs one scenario. Kept as a free function so the example and tests
/// share exactly the same path.
pub fn run(scenario: Scenario) -> Metrics {
    Simulation::new(scenario).run()
}

fn near(a: (i64, i64), b: (i64, i64), radius: i64) -> bool {
    let dx = a.0 - b.0;
    let dy = a.1 - b.1;
    dx.saturating_mul(dx).saturating_add(dy.saturating_mul(dy)) <= radius.saturating_mul(radius)
}

fn ring_position(i: usize, n: usize, side: i64) -> (i64, i64) {
    // Integer perimeter, so positions are identical on every platform.
    let per = side * 4;
    let at = (i as i64 * per / n as i64).rem_euclid(per);
    let half = side / 2;
    if at < side {
        (at - half, -half)
    } else if at < side * 2 {
        (half, at - side - half)
    } else if at < side * 3 {
        (side * 3 - at - half, half)
    } else {
        (-half, side * 4 - at - half)
    }
}

/// The sender-side seal recipe from ADR-0005, used by the simulator and
/// available to hosts that need to build a sealed Direct payload.
fn seal_delivery<R: rand08::RngCore + rand08::CryptoRng>(
    rng: &mut R,
    sender: &Identity,
    recipient: &Identity,
    created_ms: u64,
    lifetime_s: u64,
    ttl: u8,
    plaintext: &[u8],
) -> Result<(Header, Vec<u8>), ao_idents::IdentError> {
    let probe = SealedMessage::seal(sender, recipient.public(), &[0; 16], plaintext, &mut *rng)?;
    let payload_len = probe.encode().len();
    let header = Header {
        class: PacketClass::Direct,
        dst: Some(*recipient.node_id().as_bytes()),
        msg_id: [0; 16].into(),
        origin: *sender.node_id().as_bytes(),
        created_ms,
        lifetime_s,
        payload_len: payload_len as u64,
        ttl,
        hops: 0,
    };
    let binding = derive_msg_id(&header, &[]);
    let sealed = SealedMessage::seal(
        sender,
        recipient.public(),
        binding.as_bytes(),
        plaintext,
        rng,
    )?;
    let payload = sealed.encode();
    debug_assert_eq!(payload.len(), payload_len);
    Ok((header, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_is_one_line_with_a_stable_column_count() {
        let m = Metrics {
            scenario: "test",
            seed: 1,
            nodes: 2,
            submitted: 3,
            direct_submitted: 3,
            delivered: 2,
            duplicate_deliveries: 0,
            transmissions: 8,
            receptions: 6,
            send_failures: 0,
            radio_bytes: 1024,
            mean_latency_ms: 12,
            max_latency_ms: 20,
            delivery_ratio: 2.0 / 3.0,
            overhead: 4.0,
            duplicate_ratio: 0.0,
            peak_queued_bytes: 100,
            links_after_settle: 1,
            delivered_by_origin: vec![1, 1],
            unique_receptions_by_node: vec![2, 2],
            unique_receptions: 4,
        };
        let row = m.csv_row();
        assert_eq!(row.lines().count(), 1);
        assert_eq!(
            row.split(',').count(),
            Metrics::csv_header().split(',').count()
        );
        assert_eq!(
            row,
            "test,1,2,3,2,0,8,6,0,1024,12,20,0.6667,4.0000,0.0000,100,1"
        );
    }
}
