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

use crate::directory::{DirectoryConfig, NodeObservation};
use crate::presence::{ANNOUNCE_LEN, ANNOUNCE_MAGIC};
use crate::store::{MemoryStore, MessageStore, StoreLimits, StoreMetadata, StoredMessage};
use crate::{
    CAP_PRESENCE_V1, CAP_RECEIPT_V1, CAP_SYNC_V1, CAPS, CHANNEL_MAGIC, ChannelEnvelope,
    DirectoryChange, Header, MeshConfig, MeshEngine, MeshHello, MeshInput, MeshOutput, MessageId,
    NetworkAdapter, Packet, PacketClass, PresenceConfig, RouteHintMode, SHORT_ID_BYTES, SYNC_MAGIC,
    SYNC_V2_VERSION, Snapshot, StoreSummary, SuppressionConfig, SyncOffer, TelemetryConfig,
    TelemetryFrame, TelemetryKind, derive_channel_id, derive_msg_id, sign_packet,
};
use ao_idents::{Identity, NodeId, SealedMessage};
use ao_network::{
    AppHello, BeaconFlags, Channel, Hello, LinkId, LinkInfo, LocalTag, Network, NetworkConfig,
    NetworkEvent, SimConfig as WorldConfig, SimNode, SimTransport, SimWorld,
};
use rand::{SeedableRng as SeedableRng09, rngs::StdRng as EngineRng};
use rand08::{SeedableRng as SeedableRng08, rngs::StdRng as SealRng};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// Poll step: the world runs scheduled events exactly, so this only bounds
/// how late a node reacts to them.
const TICK: Duration = Duration::from_millis(50);
/// A sync offer can trigger another need; bound one input's host work.
const MAX_STORE_SERVICE_ROUNDS: usize = 64;
/// Radio range in the position units used by random and community layouts.
const RADIUS: i64 = 100;
/// How often the harness supplies MSH-20 directory observations for the
/// MSH-21 paired report. These are host facts, not mesh packets; verified
/// presence announcements feed the same seam automatically in other scenarios.
const HINT_REFRESH: Duration = Duration::from_secs(5);

type TelemetryStream = ([u8; 16], TelemetryKind);
type TelemetrySeqs = BTreeMap<TelemetryStream, BTreeSet<u64>>;

/// Where nodes start and which pairs are in radio range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Topology {
    /// Uniform random positions in a square sized for about six neighbours.
    Random,
    /// A chain of `n` nodes, each in range of its immediate neighbours.
    Line,
    /// A cycle of `n` nodes, each in range of its two neighbours.
    Ring,
    /// A fixed circulant: each node reaches `i +/- step` for every step.
    ///
    /// MSH-19 uses coprime steps 1, 8 and 12 on 50 nodes. The six-degree
    /// graph has diameter three, exactly ADR-0001's Presence TTL, so the
    /// convergence case does not need a longer relay hop limit. The scenario
    /// raises aoNetwork's link cap to six; production still uses five.
    Circulant {
        /// Positive index offsets, all smaller than `n / 2`.
        steps: Vec<usize>,
    },
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
    /// No application traffic: only MSH-19 announcements are gossiped.
    ///
    /// This isolates presence convergence and overhead from message delivery.
    Presence,
    /// Submit latest-wins Telemetry updates through the typed MSH-22 path.
    Telemetry {
        /// Node index of the origin.
        origin: usize,
        /// Opaque stream tag, passed through unchanged.
        kind: u8,
        /// Submit every update at once instead of staggering it.
        ///
        /// The burst is what makes a send queue the bottleneck: NET-21's
        /// coalescing key must leave one pending update for the stream.
        burst: bool,
    },
    /// Submit signed public-channel Broadcasts (MSH-23).
    ///
    /// Only the listed nodes subscribe locally; every other node is a relay
    /// with no channel state. The message must reach every subscriber in
    /// direct radio range of `origin`, while all channel traffic stays inside
    /// the Broadcast relay budget.
    Channel {
        /// Node index of the channel's origin.
        origin: usize,
        /// Channel name, hashed locally by subscribers and the origin.
        name: &'static str,
        /// Nodes with a local subscription.
        subscribers: &'static [usize],
    },
}

/// Host-side directory observation schedule for one scenario (MSH-20).
///
/// The harness injects the same bounded facts that verified MSH-19
/// announcements produce, with presence traffic off, so the test isolates
/// directory capacity and expiry. It never changes routing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryPlan {
    /// Directory bounds and staleness under test.
    pub config: DirectoryConfig,
    /// Local milliseconds between announcement rounds.
    pub every_ms: u64,
    /// Number of rounds; each node announces one other node per round.
    pub announcements: usize,
    /// Magnitude of the alternating observation-time skew. Even-index nodes
    /// report this far in the future, odd-index nodes that far in the past.
    pub observed_skew_ms: u64,
}

/// A mid-run engine restart (MSH-29).
///
/// The host snapshots every engine, drops it and constructs a new one with
/// the same RNG seed and config. With `restore` set the snapshot is applied;
/// the ablation discards it. Live links are re-announced with `MeshInput::LinkUp`
/// because link capabilities are per-session and are not persisted. One
/// previously relayed packet is replayed on each node immediately afterwards:
/// that delayed copy is exactly what a lost seen-cache would re-relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Restart {
    /// Run-relative time of the restart.
    pub at: Duration,
    /// Whether the new engine receives the old engine's snapshot.
    pub restore: bool,
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
    /// Whether Direct traffic uses MSH-16 copy tickets.
    ///
    /// The published MSH-27 baselines keep this false so they remain the
    /// relay-only MSH-08 reference; spray gets its own paired report.
    pub spray: bool,
    /// Whether signed receipts and store purges are enabled (MSH-17).
    ///
    /// Ablation runs keep this false so the effect of receipts can be
    /// measured without changing any other engine behaviour.
    pub receipts: bool,
    /// MSH-21 route-hint mode. `Off` keeps every published row unchanged.
    pub route_hint: RouteHintMode,
    /// Suppression bounds and timer parameters under test.
    pub suppression: SuppressionConfig,
    /// Whether links advertise and consume MSH-19 announcements.
    ///
    /// Existing baselines leave this false so their published numbers and
    /// pre-MSH-19 fallback behaviour stay unchanged.
    pub presence: bool,
    /// Presence trickle parameters under test.
    pub presence_config: PresenceConfig,
    /// Optional directory observation schedule (MSH-20).
    pub directory: Option<DirectoryPlan>,
    /// Telemetry freshness, throttle and state bounds under test (MSH-22).
    pub telemetry: TelemetryConfig,
    /// Mid-run engine restart, if this scenario exercises MSH-29.
    pub restart: Option<Restart>,
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
    /// Typed Telemetry submissions attempted in this scenario (MSH-22).
    pub telemetry_attempts: u64,
    /// Telemetry submissions the origin's throttle accepted.
    pub telemetry_accepted: u64,
    /// Telemetry submissions refused by the typed policy.
    pub telemetry_rejected: u64,
    /// Structurally valid Telemetry packets received at mesh nodes.
    pub telemetry_receptions: u64,
    /// Distinct sequences observed per `(origin, kind)`, summed over nodes.
    pub telemetry_distinct_seqs: u64,
    /// Most sequences any one node observed for one stream.
    ///
    /// With an in-flight first frame, a value of two proves at most one
    /// further update stayed pending per coalescing key.
    pub telemetry_max_seqs_per_node: u64,
    /// Highest Telemetry sequence observed anywhere in the scenario.
    pub telemetry_max_seq: u64,
    /// Store evictions caused by authenticated delivery receipts.
    ///
    /// Not part of the CSV report; MSH-17 uses it with `remaining_copies`.
    pub purges: u64,
    /// Authenticated receipts that reached their origin.
    ///
    /// Not part of the CSV report; this is the sender's Delivered status.
    pub delivery_receipts: u64,
    /// Stored copies still present when the scenario ends.
    ///
    /// Not part of the CSV report; includes messages that were never
    /// delivered, for which no receipt can exist.
    pub remaining_copies: usize,
    /// Stored copies of delivered messages still present at the end.
    ///
    /// Not part of the CSV report; zero is the MSH-17 purge requirement.
    pub remaining_delivered_copies: usize,
    /// Of the remaining delivered copies, how many sit at nodes that already
    /// hold the receipt. Non-zero means the host did not honour its purge.
    ///
    /// Not part of the CSV report; a diagnosis field for MSH-17.
    pub remaining_delivered_copies_immune: usize,
    /// Slowest interval from first delivery to an empty store set.
    ///
    /// Not part of the CSV report; bounded by the MSH-02 immunity lifetime.
    pub max_purge_latency_ms: u64,
    /// Whether every node learned every other node's announcement.
    ///
    /// Not part of the CSV report; MSH-19 convergence evidence.
    pub presence_converged: bool,
    /// Run-relative time when the last node reached full knowledge.
    ///
    /// Not part of the CSV report; zero when convergence did not happen.
    pub convergence_ms: u64,
    /// Fewest announcements learned by any node at the end of the run.
    ///
    /// Not part of the CSV report; the denominator is `nodes - 1`.
    pub learned_nodes_min: usize,
    /// Unknown-card host events emitted during the run.
    ///
    /// Not part of the CSV report; the fixed scenario declares all hashes.
    pub card_fetches: u64,
    /// Announcement sends and wire bytes during the run.
    ///
    /// Not part of the CSV report; these isolate MSH-19 from other traffic.
    pub announcement_sends: u64,
    /// Announcement wire bytes during the run.
    pub announcement_bytes: u64,
    /// Announcement sends in the last 60 seconds of the run.
    pub steady_announcement_sends: u64,
    /// Announcement wire bytes in the last 60 seconds of the run.
    pub steady_announcement_bytes: u64,
    /// Peak entries held by any node's directory (MSH-20).
    ///
    /// Not part of the MSH-27 CSV report.
    pub directory_peak_entries: usize,
    /// Relative-time expirations summed over all nodes (MSH-20).
    ///
    /// Not part of the MSH-27 CSV report.
    pub directory_expirations: u64,
    /// Capacity evictions summed over all nodes (MSH-20).
    ///
    /// Not part of the MSH-27 CSV report.
    pub directory_evictions: u64,
    /// Last local millisecond at which any directory entry was removed
    /// (MSH-20). Not part of the MSH-27 CSV report.
    pub directory_last_removal_ms: u64,
    /// Entries still live at the end of the run (MSH-20). The scenario's
    /// staleness must have reclaimed every entry by then.
    ///
    /// Not part of the MSH-27 CSV report.
    pub directory_live_entries: usize,
    /// MSH-21 submissions that had a fresh hint for their destination.
    ///
    /// Not part of the CSV report; the denominator of the fresh-path
    /// latency comparison.
    pub fresh_hint_submissions: u64,
    /// Deliveries of messages that had a fresh hint at submission.
    ///
    /// Not part of the CSV report.
    pub fresh_hint_deliveries: u64,
    /// Mean latency of fresh-hint deliveries in milliseconds.
    ///
    /// Not part of the CSV report; the MSH-21 acceptance measure.
    pub fresh_hint_mean_latency_ms: u64,
    /// Nodes with a local channel subscription (MSH-23).
    ///
    /// Not part of the published MSH-27 CSV; `channel_csv_row` reports it.
    pub channel_subscribers: usize,
    /// Signed channel envelopes accepted by local subscribers (MSH-23).
    ///
    /// Not part of the published MSH-27 CSV; `channel_csv_row` reports it.
    pub channel_deliveries: u64,
    /// Unique channel messages accepted at each local subscriber.
    ///
    /// Not part of the published MSH-27 CSV.
    pub channel_delivered_ids: Vec<BTreeSet<MessageId>>,
    /// Mesh sends whose payload was a channel envelope.
    ///
    /// Not part of the published MSH-27 CSV; this is the numerator of the
    /// Broadcast-budget gate.
    pub channel_transmissions: u64,
    /// Radio bytes in channel-envelope sends.
    ///
    /// Not part of the published MSH-27 CSV.
    pub channel_bytes: u64,
    /// Bytes in the largest MSH-29 snapshot taken at the restart.
    ///
    /// Not part of the CSV report.
    pub restart_snapshot_bytes: usize,
    /// Message sends after the restart whose id this node had already sent.
    ///
    /// Not part of the CSV report; the MSH-29 replay signal must be zero.
    pub restart_replays: u64,
    /// All message sends after the restart, for context on `restart_replays`.
    ///
    /// Not part of the CSV report.
    pub restart_sends_after: u64,
}

impl Metrics {
    /// CSV column names, in the same order as [`Self::csv_row`].
    pub fn csv_header() -> &'static str {
        "scenario,seed,nodes,submitted,delivered,duplicate_deliveries,transmissions,receptions,send_failures,radio_bytes,mean_latency_ms,max_latency_ms,delivery_ratio,overhead,duplicate_ratio,peak_queued_bytes,links_after_settle,presence_converged,convergence_ms,learned_nodes_min,card_fetches,announcement_sends,announcement_bytes,steady_announcement_sends,steady_announcement_bytes"
    }
    /// One CSV line with four decimal places on every ratio.
    pub fn csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{:.4},{:.4},{:.4},{},{},{},{},{},{},{},{},{},{}",
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
            self.presence_converged,
            self.convergence_ms,
            self.learned_nodes_min,
            self.card_fetches,
            self.announcement_sends,
            self.announcement_bytes,
            self.steady_announcement_sends,
            self.steady_announcement_bytes,
        )
    }
    /// Telemetry-specific columns, outside the published MSH-27 schema.
    pub fn telemetry_csv_header() -> &'static str {
        "scenario,seed,nodes,telemetry_attempts,telemetry_accepted,telemetry_rejected,telemetry_receptions,telemetry_distinct_seqs,telemetry_max_seqs_per_node,telemetry_max_seq,transmissions,radio_bytes"
    }
    /// One MSH-22 row. Receptions and distinct sequences are the observable
    /// proof that only one pending update survived a slow send queue.
    pub fn telemetry_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            self.scenario,
            self.seed,
            self.nodes,
            self.telemetry_attempts,
            self.telemetry_accepted,
            self.telemetry_rejected,
            self.telemetry_receptions,
            self.telemetry_distinct_seqs,
            self.telemetry_max_seqs_per_node,
            self.telemetry_max_seq,
            self.transmissions,
            self.radio_bytes,
        )
    }

    /// MSH-23 columns, outside the published MSH-27 radio schema.
    ///
    /// `broadcast_burst_bytes` is the full MSH-10 Broadcast allowance for
    /// `burst_seconds`. `within_broadcast_budget` is true when every channel
    /// transmission this run could fit in that one bucket, which is the
    /// channel issue's "without exceeding the Broadcast budget" gate.
    pub fn channel_csv_header() -> &'static str {
        "scenario,seed,nodes,submitted,subscribers,channel_deliveries,channel_transmissions,channel_bytes,broadcast_burst_bytes,within_broadcast_budget"
    }

    /// One MSH-23 CSV line.
    pub fn channel_csv_row(&self) -> String {
        let burst = crate::BudgetConfig::default().rates
            [crate::PacketClass::Broadcast as usize - 1]
            .burst_bytes();
        format!(
            "{},{},{},{},{},{},{},{},{},{}",
            self.scenario,
            self.seed,
            self.nodes,
            self.submitted,
            self.channel_subscribers,
            self.channel_deliveries,
            self.channel_transmissions,
            self.channel_bytes,
            burst,
            self.channel_bytes <= burst,
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
            spray: false,
            receipts: false,
            route_hint: RouteHintMode::Off,
            suppression: SuppressionConfig::default(),
            presence: false,
            presence_config: PresenceConfig::default(),
            directory: None,
            telemetry: TelemetryConfig::default(),
            restart: None,
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
            spray: false,
            receipts: false,
            route_hint: RouteHintMode::Off,
            suppression: SuppressionConfig::default(),
            presence: false,
            presence_config: PresenceConfig::default(),
            directory: None,
            telemetry: TelemetryConfig::default(),
            restart: None,
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
            spray: false,
            receipts: false,
            route_hint: RouteHintMode::Off,
            suppression: SuppressionConfig::default(),
            presence: false,
            presence_config: PresenceConfig::default(),
            directory: None,
            telemetry: TelemetryConfig::default(),
            restart: None,
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
            spray: false,
            receipts: false,
            route_hint: RouteHintMode::Off,
            suppression: SuppressionConfig::default(),
            presence: false,
            presence_config: PresenceConfig::default(),
            directory: None,
            telemetry: TelemetryConfig::default(),
            restart: None,
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
        spray: false,
        receipts: false,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: false,
        presence_config: PresenceConfig::default(),
        directory: None,
        telemetry: TelemetryConfig::default(),
        restart: None,
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
        spray: false,
        receipts: false,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: false,
        presence_config: PresenceConfig::default(),
        directory: None,
        telemetry: TelemetryConfig::default(),
        restart: None,
    }]
}

/// MSH-23's fixed public-channel case.
///
/// A line gives an exact, topology-independent expectation: nodes 9 and 11
/// are the only subscribers in node 10's radio range. Only those two nodes
/// receive a `ChannelSubscribe`; every other node stays a subscription-free
/// relay. One signed envelope is enough to check reachability and the
/// Broadcast-budget ceiling without a long run.
pub fn channel_scenarios() -> Vec<Scenario> {
    vec![Scenario {
        name: "channel-line-20",
        seed: 1_297_304_023,
        nodes: 20,
        topology: Topology::Line,
        mobility: Mobility::Static,
        settle: Duration::from_secs(30),
        run: Duration::from_secs(30),
        messages: 1,
        payload_len: 128,
        traffic: Traffic::Channel {
            origin: 10,
            name: "town-square",
            subscribers: &[9, 11],
        },
        enforce_budgets: true,
        enforce_suppression: true,
        spray: false,
        receipts: false,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: false,
        presence_config: PresenceConfig::default(),
        directory: None,
        telemetry: TelemetryConfig::default(),
        restart: None,
    }]
}

/// MSH-16's paired mobility case.
///
/// Both scenarios share the MSH-27 waypoint seed, topology, traffic and
/// budgets. The only difference is the spray bit, so the report isolates
/// binary copy tickets from the relay-only MSH-08 baseline.
pub fn spray_scenarios() -> Vec<Scenario> {
    let line = Scenario {
        name: "spray-relay-line-20",
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
        spray: false,
        receipts: false,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: false,
        presence_config: PresenceConfig::default(),
        directory: None,
        telemetry: TelemetryConfig::default(),
        restart: None,
    };
    let scripted = Scenario {
        name: "spray-relay-scripted-200",
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
        spray: false,
        receipts: false,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: false,
        presence_config: PresenceConfig::default(),
        directory: None,
        telemetry: TelemetryConfig::default(),
        restart: None,
    };
    vec![
        line.clone(),
        Scenario {
            name: "spray-enabled-line-20",
            spray: true,
            receipts: false,
            ..line
        },
        scripted.clone(),
        Scenario {
            name: "spray-enabled-scripted-200",
            spray: true,
            receipts: false,
            ..scripted
        },
    ]
}

/// MSH-17's paired store-purge case.
///
/// Both rows use spray so their stores are actually populated; the only
/// difference is the receipt bit. This isolates bounded immunity gossip from
/// the MSH-16 delivery measurements, whose published rows stay unchanged.
pub fn receipt_scenarios() -> Vec<Scenario> {
    let line = Scenario {
        name: "receipt-relay-line-20",
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
        spray: true,
        receipts: false,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: false,
        presence_config: PresenceConfig::default(),
        directory: None,
        telemetry: TelemetryConfig::default(),
        restart: None,
    };
    let scripted = Scenario {
        name: "receipt-relay-scripted-200",
        seed: 1_297_303_752,
        nodes: 200,
        topology: Topology::Scripted(scripted_contacts(200)),
        mobility: Mobility::Scripted,
        settle: Duration::from_secs(60),
        run: Duration::from_secs(90),
        messages: 100,
        payload_len: 128,
        traffic: Traffic::Balanced,
        enforce_budgets: true,
        enforce_suppression: true,
        spray: true,
        receipts: false,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: false,
        presence_config: PresenceConfig::default(),
        directory: None,
        telemetry: TelemetryConfig::default(),
        restart: None,
    };
    vec![
        line.clone(),
        Scenario {
            name: "receipt-enabled-line-20",
            receipts: true,
            route_hint: RouteHintMode::Off,
            ..line
        },
        scripted.clone(),
        Scenario {
            name: "receipt-enabled-scripted-200",
            receipts: true,
            route_hint: RouteHintMode::Off,
            ..scripted
        },
    ]
}

/// MSH-19's fixed 50-node presence case.
///
/// The topology is a seeded four-degree circulant with diameter two, so
/// ADR-0001's three-hop Presence TTL can reach the whole mesh. No application
/// messages are submitted: every byte on the wire is an announcement or an
/// ordinary link-control frame. The one-second quick delay proves bounded
/// convergence, and a 60-second steady interval is deliberately more frequent
/// than the 15-minute default so a short run still measures a conservative
/// per-node hourly overhead. All nodes declare each other's card hashes, so
/// zero `CardFetch` events is part of the expected steady state.
pub fn presence_scenarios() -> Vec<Scenario> {
    vec![Scenario {
        name: "presence-smallworld-50",
        seed: 1_297_304_021,
        nodes: 50,
        topology: Topology::Circulant {
            steps: vec![1, 8, 12],
        },
        mobility: Mobility::Static,
        settle: Duration::from_secs(30),
        run: Duration::from_secs(120),
        messages: 0,
        payload_len: 0,
        traffic: Traffic::Presence,
        enforce_budgets: true,
        enforce_suppression: true,
        spray: false,
        receipts: false,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: true,
        presence_config: PresenceConfig {
            quick_ms: 1_000,
            base_interval_ms: 60_000,
            steady_interval_ms: 60_000,
            ..PresenceConfig::default()
        },
        directory: None,
        telemetry: TelemetryConfig::default(),
        restart: None,
    }]
}

/// MSH-22's paired Telemetry cases.
///
/// The slow-line row bursts eight updates from one origin before the radio
/// gets a tick. NET-21 must coalesce them to one pending frame per key, so
/// every receiver observes only the newest sequence. The chatty row uses the
/// default per-origin interval; eleven of its twelve attempts must be
/// rejected locally before they ever reach a queue.
pub fn telemetry_scenarios() -> Vec<Scenario> {
    let slow = Scenario {
        name: "telemetry-slow-line-5",
        seed: 1_297_304_023,
        nodes: 5,
        topology: Topology::Line,
        mobility: Mobility::Static,
        settle: Duration::from_secs(30),
        run: Duration::from_secs(5),
        messages: 8,
        payload_len: 64,
        traffic: Traffic::Telemetry {
            origin: 0,
            kind: 7,
            burst: true,
        },
        enforce_budgets: true,
        enforce_suppression: true,
        spray: false,
        receipts: false,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: false,
        presence_config: PresenceConfig::default(),
        directory: None,
        telemetry: TelemetryConfig {
            rate_limit_ms: 0,
            ..TelemetryConfig::default()
        },
        restart: None,
    };
    let chatty = Scenario {
        name: "telemetry-chatty-random-20",
        seed: 1_297_304_029,
        nodes: 20,
        topology: Topology::Random,
        mobility: Mobility::Static,
        settle: Duration::from_secs(30),
        run: Duration::from_secs(8),
        messages: 12,
        payload_len: 64,
        traffic: Traffic::Telemetry {
            origin: 0,
            kind: 7,
            burst: false,
        },
        enforce_budgets: true,
        enforce_suppression: true,
        spray: false,
        receipts: false,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: false,
        presence_config: PresenceConfig::default(),
        directory: None,
        telemetry: TelemetryConfig::default(),
        restart: None,
    };
    vec![slow, chatty]
}

/// MSH-20's fixed directory case: a small static line whose nodes announce
/// each other on a seeded schedule with alternating observation-time skew.
///
/// The four-entry ceiling and two-second relative lifetime are far smaller
/// than the defaults so the run exercises both capacity eviction and
/// scheduled expiry. Presence traffic stays off; the host injects the typed
/// observations that verified MSH-19 announcements produce at runtime.
pub fn directory_scenarios() -> Vec<Scenario> {
    vec![Scenario {
        name: "directory-line-6",
        seed: 1_297_304_021,
        nodes: 6,
        topology: Topology::Line,
        mobility: Mobility::Static,
        settle: Duration::from_millis(100),
        run: Duration::from_secs(6),
        messages: 1,
        payload_len: 32,
        traffic: Traffic::Balanced,
        enforce_budgets: true,
        enforce_suppression: true,
        spray: false,
        receipts: false,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: false,
        presence_config: PresenceConfig::default(),
        directory: Some(DirectoryPlan {
            config: DirectoryConfig {
                capacity: 4,
                stale_after_ms: 2_000,
                max_location_bytes: 8,
                max_change_events: 8,
            },
            every_ms: 250,
            announcements: 8,
            observed_skew_ms: 5_000,
        }),
        telemetry: TelemetryConfig::default(),
        restart: None,
    }]
}

/// MSH-21's paired route-hint case.
///
/// All three rows share the MSH-16 spray seed, topology, traffic, budgets and
/// receipt setting; only the hint mode differs. The harness supplies the same
/// seeded facts through `MeshInput::ObserveNode` in every row, so the engine's
/// MSH-20 directory derives identical hints and latency changes are attributable
/// to how a fresh hint is used. `Off` is the unhinted spray baseline.
pub fn route_hint_scenarios() -> Vec<Scenario> {
    let line = Scenario {
        name: "hint-spray-line-20",
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
        spray: true,
        receipts: false,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: false,
        presence_config: PresenceConfig::default(),
        directory: None,
        telemetry: TelemetryConfig::default(),
        restart: None,
    };
    let random = Scenario {
        name: "hint-spray-random-20",
        seed: 1_297_303_632,
        nodes: 20,
        topology: Topology::Random,
        mobility: Mobility::Static,
        settle: Duration::from_secs(30),
        run: Duration::from_secs(30),
        messages: 20,
        payload_len: 128,
        traffic: Traffic::Balanced,
        enforce_budgets: true,
        enforce_suppression: true,
        spray: true,
        receipts: false,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: false,
        presence_config: PresenceConfig::default(),
        directory: None,
        telemetry: TelemetryConfig::default(),
        restart: None,
    };
    vec![
        line.clone(),
        Scenario {
            name: "hint-additive-line-20",
            route_hint: RouteHintMode::AdditiveUnicast,
            ..line.clone()
        },
        Scenario {
            name: "hint-substitute-line-20",
            route_hint: RouteHintMode::SubstituteCopy,
            ..line
        },
        random.clone(),
        Scenario {
            name: "hint-additive-random-20",
            route_hint: RouteHintMode::AdditiveUnicast,
            ..random.clone()
        },
        Scenario {
            name: "hint-substitute-random-20",
            route_hint: RouteHintMode::SubstituteCopy,
            ..random
        },
    ]
}

/// MSH-29's paired restart case.
///
/// Both rows use the fixed line-20 seed, spray and receipts so all three
/// snapshot sections are populated. Engines restart halfway through the run;
/// only the `restore` bit differs, so the replay count is attributable to
/// the snapshot rather than to topology, traffic or the RNG stream.
pub fn restart_scenarios() -> Vec<Scenario> {
    let base = Scenario {
        name: "restart-lost-line-20",
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
        spray: true,
        receipts: true,
        route_hint: RouteHintMode::Off,
        suppression: SuppressionConfig::default(),
        presence: false,
        presence_config: PresenceConfig::default(),
        directory: None,
        telemetry: TelemetryConfig::default(),
        restart: Some(Restart {
            at: Duration::from_secs(16),
            restore: false,
        }),
    };
    vec![
        base.clone(),
        Scenario {
            name: "restart-restored-line-20",
            restart: Some(Restart {
                at: Duration::from_secs(16),
                restore: true,
            }),
            ..base
        },
    ]
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

fn engine_config(scenario: &Scenario) -> MeshConfig {
    let mut config = MeshConfig::default();
    config.budgets.enforce = scenario.enforce_budgets;
    config.spray.enabled = scenario.spray;
    config.receipt.enabled = scenario.receipts;
    config.presence = PresenceConfig {
        enabled: scenario.presence,
        ..scenario.presence_config
    };
    if let Some(plan) = &scenario.directory {
        config.directory = plan.config;
    }
    config.route_hint.mode = scenario.route_hint;
    config.suppression = SuppressionConfig {
        enabled: scenario.enforce_suppression,
        ..scenario.suppression
    };
    config.telemetry = scenario.telemetry;
    config
}

struct Node {
    adapter: NetworkAdapter<EngineRng, SimTransport>,
    card_hash: [u8; 8],
    pos: (i64, i64),
    group: usize,
}

/// Owns the simulated world and the metrics accumulated while driving it.
pub struct Simulation {
    scenario: Scenario,
    world: SimWorld,
    nodes: Vec<Node>,
    stores: Vec<MemoryStore>,
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
    telemetry_attempts: u64,
    telemetry_accepted: u64,
    telemetry_rejected: u64,
    telemetry_receptions: u64,
    telemetry_seqs: Vec<TelemetrySeqs>,
    origin_index: BTreeMap<[u8; 16], usize>,
    links_after_settle: usize,
    receipts: u64,
    purges: u64,
    store_holders: BTreeMap<MessageId, BTreeSet<usize>>,
    first_delivery_ms: BTreeMap<MessageId, u64>,
    purge_latencies: Vec<u64>,
    purge_recorded: BTreeSet<MessageId>,
    presence_converged: bool,
    convergence_ms: u64,
    card_fetches: u64,
    announcement_sends: u64,
    announcement_bytes: u64,
    steady_announcement_sends: u64,
    steady_announcement_bytes: u64,
    directory_last_ms: u64,
    directory_announcements: usize,
    directory_peak_entries: usize,
    directory_last_removal_ms: u64,
    hint_seq: u64,
    injected_fresh: Vec<BTreeSet<NodeId>>,
    fresh_hint_ids: BTreeSet<MessageId>,
    fresh_hint_submissions: u64,
    fresh_hint_deliveries: u64,
    fresh_latencies: Vec<u64>,
    channel_delivered_ids: Vec<BTreeSet<MessageId>>,
    channel_deliveries: u64,
    channel_transmissions: u64,
    channel_bytes: u64,
    channel_subscribers: usize,
    restart_done: bool,
    restart_snapshot_bytes: usize,
    restart_replays: u64,
    restart_sends_after: u64,
    sent_ids: Vec<BTreeSet<MessageId>>,
    probe_wires: Vec<Option<(LinkId, Channel, Vec<u8>)>>,
    link_hellos: Vec<BTreeMap<LinkId, Hello>>,
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
        assert!(
            scenario.messages > 0 || matches!(scenario.traffic, Traffic::Presence),
            "a scenario needs messages"
        );
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
        let mut card_hashes = Vec::with_capacity(n);
        for i in 0..n {
            let radio = world
                .add_node(SimNode::default())
                .expect("sim node is valid");
            let mut seed_input = [0u8; 16];
            seed_input[..8].copy_from_slice(&scenario.seed.to_be_bytes());
            seed_input[8..].copy_from_slice(&(i as u64).to_be_bytes());
            let digest = blake3::hash(&seed_input);
            let mut seed = [0u8; 32];
            seed.copy_from_slice(digest.as_bytes());
            let mut card_hash = [0u8; 8];
            card_hash.copy_from_slice(&digest.as_bytes()[8..16]);
            let identity = Identity::from_seed(seed);
            let engine_rng = EngineRng::seed_from_u64(scenario.seed ^ (i as u64 + 1));
            let mut engine = MeshEngine::with_config(engine_rng, engine_config(&scenario));
            // Subscription is a local host declaration. Only configured
            // subscribers get one; relays keep an empty channel registry and
            // forward from the ordinary Broadcast path.
            if let Traffic::Channel {
                name, subscribers, ..
            } = scenario.traffic
            {
                if subscribers.contains(&i) {
                    let outputs = engine
                        .handle(
                            0,
                            MeshInput::ChannelSubscribe {
                                name: name.as_bytes(),
                            },
                        )
                        .expect("fixed subscription is valid");
                    assert!(
                        outputs.is_empty(),
                        "subscribing emits no host action: {outputs:?}"
                    );
                }
            }
            // Baseline nodes have empty stores. The hello and beacon must
            // advertise the engine's actual digest, otherwise every link
            // looks different and MSH-14 starts a needless sync contact.
            let store_digest = engine.sync().local_digest();
            let network_config = if matches!(scenario.topology, Topology::Circulant { .. }) {
                // The circulant's full six-degree graph is part of the
                // scenario; aoNetwork still owns and enforces the cap.
                NetworkConfig::default()
                    .with_max_links(6)
                    .expect("six is a valid link cap")
            } else {
                NetworkConfig::default()
            };
            let mut adapter = NetworkAdapter::new(engine, Network::new(network_config, radio));
            let tag = {
                let mut t = next(&mut rng).to_be_bytes().repeat(2);
                t[0] = i as u8;
                let mut out = [0u8; 16];
                out.copy_from_slice(&t[..16]);
                LocalTag::new(out)
            };
            let mut caps = if scenario.receipts {
                CAPS
            } else {
                CAPS & !CAP_RECEIPT_V1
            };
            if !scenario.presence {
                caps &= !CAP_PRESENCE_V1;
            }
            let signed = MeshHello::sign_with_caps(&identity, card_hash, store_digest, caps)
                .expect("fixed identity signs");
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
                Topology::Ring | Topology::Circulant { .. } => ring_position(i, n, side),
                Topology::Random | Topology::Communities { .. } | Topology::Scripted(_) => {
                    let x = (next(&mut rng) % side as u64) as i64;
                    let y = (next(&mut rng) % side as u64) as i64;
                    (x, y)
                }
            };
            identities.push(identity);
            card_hashes.push(card_hash);
            nodes.push(Node {
                adapter,
                card_hash,
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
                let on = match &scenario.topology {
                    Topology::Line => b == a + 1,
                    Topology::Ring => b == a + 1 || (a == 0 && b == n - 1),
                    Topology::Circulant { steps } => {
                        let forward = (b + n - a) % n;
                        steps.iter().any(|step| {
                            *step != 0
                                && (*step == forward || n.checked_sub(*step) == Some(forward))
                        })
                    }
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
        // The host declares all cards up front. With a complete set the
        // presence scenario must emit no CardFetch events, which also proves
        // that refreshes do not repeatedly ask for the same hash.
        if scenario.presence {
            for node in &mut nodes {
                let outputs = node
                    .adapter
                    .engine_mut()
                    .handle(
                        0,
                        MeshInput::KnownCards {
                            hashes: &card_hashes,
                        },
                    )
                    .expect("bounded known-card input");
                assert!(
                    outputs.is_empty(),
                    "known cards are host state, not packets: {outputs:?}"
                );
            }
        }
        let applied = vec![vec![false; n]; n];
        let stores = (0..n)
            .map(|_| MemoryStore::new(StoreLimits::default()))
            .collect();
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
        let channel_subscribers = match scenario.traffic {
            Traffic::Channel { subscribers, .. } => subscribers.len(),
            _ => 0,
        };
        let mut sim = Self {
            scenario,
            world,
            nodes,
            stores,
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
            telemetry_attempts: 0,
            telemetry_accepted: 0,
            telemetry_rejected: 0,
            telemetry_receptions: 0,
            telemetry_seqs: vec![BTreeMap::new(); n],
            origin_index,
            links_after_settle: 0,
            receipts: 0,
            purges: 0,
            store_holders: BTreeMap::new(),
            first_delivery_ms: BTreeMap::new(),
            purge_latencies: Vec::new(),
            purge_recorded: BTreeSet::new(),
            presence_converged: false,
            convergence_ms: 0,
            card_fetches: 0,
            announcement_sends: 0,
            announcement_bytes: 0,
            steady_announcement_sends: 0,
            steady_announcement_bytes: 0,
            directory_last_ms: 0,
            directory_announcements: 0,
            directory_peak_entries: 0,
            directory_last_removal_ms: 0,
            hint_seq: 0,
            injected_fresh: vec![BTreeSet::new(); n],
            fresh_hint_ids: BTreeSet::new(),
            fresh_hint_submissions: 0,
            fresh_hint_deliveries: 0,
            fresh_latencies: Vec::new(),
            channel_delivered_ids: vec![BTreeSet::new(); n],
            channel_deliveries: 0,
            channel_transmissions: 0,
            channel_bytes: 0,
            channel_subscribers,
            restart_done: false,
            restart_snapshot_bytes: 0,
            restart_replays: 0,
            restart_sends_after: 0,
            sent_ids: vec![BTreeSet::new(); n],
            probe_wires: vec![None; n],
            link_hellos: vec![BTreeMap::new(); n],
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

    fn remove_store_holder(&mut self, id: MessageId, node: usize, now_ms: u64) {
        let mut empty = false;
        if let Some(holders) = self.store_holders.get_mut(&id) {
            holders.remove(&node);
            empty = holders.is_empty();
        }
        if empty {
            self.store_holders.remove(&id);
            if !self.purge_recorded.contains(&id) {
                if let Some(first) = self.first_delivery_ms.get(&id).copied() {
                    self.purge_latencies.push(now_ms.saturating_sub(first));
                    self.purge_recorded.insert(id);
                }
            }
        }
    }

    fn purge_stored(&mut self, node: usize, now_ms: u64, id: MessageId) {
        if self.stores[node].evict(&id).is_some() {
            self.purges += 1;
        }
        self.remove_store_holder(id, node, now_ms);
    }

    fn store_item(&mut self, node: usize, now_ms: u64, wire: &[u8], copies_left: u8) {
        let metadata = StoreMetadata {
            copies_left: copies_left.max(1),
            first_seen: now_ms,
            received_at: now_ms,
            priority: 0,
            received_from: None,
            age_ms: 0,
        };
        let Ok(message) = StoredMessage::new(wire, metadata) else {
            return;
        };
        let id = message.header().msg_id;
        let evicted = self.stores[node].put(now_ms, message).unwrap_or_default();
        for gone in evicted {
            self.remove_store_holder(gone, node, now_ms);
        }
        if self.stores[node].get(now_ms, &id).is_some() {
            self.store_holders.entry(id).or_default().insert(node);
        }
    }

    fn refresh_store_summary(&mut self, node: usize, now: Duration, now_ms: u64) {
        let ids = self.stores[node].summary(now_ms);
        let outputs = self.nodes[node]
            .adapter
            .engine_mut()
            .handle(now_ms, MeshInput::StoreSummary { ids: &ids })
            .expect("store summary is valid");
        if outputs.is_empty() {
            return;
        }
        self.count_outputs(node, now_ms, &outputs);
        let events = self.nodes[node].adapter.apply(now, outputs);
        for event in events {
            if let crate::AdapterEvent::SendFailed { .. } = event {
                self.send_failures += 1;
            }
        }
    }

    /// Services the host side of MSH-14/15/16 outputs: persist received
    /// items and answer sync needs from that node's bounded store.
    fn service_stores(
        &mut self,
        node: usize,
        now: Duration,
        now_ms: u64,
        outputs: Vec<MeshOutput>,
    ) {
        let mut pending = outputs;
        for _ in 0..MAX_STORE_SERVICE_ROUNDS {
            let mut needs = Vec::new();
            let mut items = Vec::new();
            let mut purges = Vec::new();
            for output in &pending {
                match output {
                    MeshOutput::SyncNeed { link, prefixes } => {
                        needs.push((*link, prefixes.clone()));
                    }
                    MeshOutput::SyncItem {
                        id,
                        wire,
                        copies_left,
                    } => items.push((*id, wire.clone(), *copies_left)),
                    MeshOutput::Purge { id } => purges.push(*id),
                    _ => {}
                }
            }
            let mut stored = false;
            for (id, wire, copies_left) in items {
                debug_assert_eq!(
                    crate::Packet::decode(&wire).map(|packet| packet.header.msg_id),
                    Ok(id)
                );
                self.store_item(node, now_ms, &wire, copies_left);
                stored = true;
            }
            if stored {
                self.refresh_store_summary(node, now, now_ms);
            }
            if !purges.is_empty() {
                for id in purges {
                    self.purge_stored(node, now_ms, id);
                }
                self.refresh_store_summary(node, now, now_ms);
            }
            let mut extra = Vec::new();
            for (link, prefixes) in needs {
                let store = &self.stores[node];
                let ids = store.summary(now_ms);
                let offers: Vec<SyncOffer<'_>> = prefixes
                    .iter()
                    .filter_map(|prefix| {
                        let id = ids
                            .iter()
                            .find(|id| id.as_bytes()[..SHORT_ID_BYTES] == prefix[..])?;
                        let message = store.get(now_ms, id)?;
                        Some(SyncOffer {
                            prefix: *prefix,
                            wire: message.wire(),
                            copies_left: message.metadata().copies_left,
                        })
                    })
                    .collect();
                if offers.is_empty() {
                    continue;
                }
                let produced = self.nodes[node]
                    .adapter
                    .engine_mut()
                    .handle(
                        now_ms,
                        MeshInput::SyncItems {
                            link,
                            items: &offers,
                        },
                    )
                    .expect("host sync offers are valid");
                extra.extend(produced);
            }
            if extra.is_empty() {
                return;
            }
            self.count_outputs(node, now_ms, &extra);
            let events = self.nodes[node].adapter.apply(now, extra.clone());
            for event in events {
                if let crate::AdapterEvent::SendFailed { .. } = event {
                    self.send_failures += 1;
                }
            }
            pending = extra;
        }
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
                    let (input, received_id, telemetry, probe_source) = match &event {
                        NetworkEvent::LinkUp { link, remote_hello } => {
                            self.link_hellos[i].insert(*link, remote_hello.clone());
                            (
                                MeshInput::LinkUp {
                                    link: *link,
                                    remote_hello: remote_hello.clone(),
                                },
                                None,
                                None,
                                None,
                            )
                        }
                        NetworkEvent::LinkDown { link, reason } => {
                            self.pending[i].remove(link);
                            self.tx_last[i].remove(link);
                            self.link_hellos[i].remove(link);
                            (
                                MeshInput::LinkDown {
                                    link: *link,
                                    reason: *reason,
                                },
                                None,
                                None,
                                None,
                            )
                        }
                        NetworkEvent::Data {
                            link,
                            channel,
                            payload,
                        } => {
                            let decoded = packet_bytes(payload)
                                .and_then(|bytes| crate::Packet::decode(bytes).ok());
                            // Broadcast has no Deliver event yet. Count a
                            // structurally valid flooded packet as a unique
                            // reception at this node, once per content id.
                            // Telemetry has no Deliver either; its framed
                            // sequence is the only observable coalescing
                            // result at a receiver.
                            let telemetry = decoded
                                .as_ref()
                                .filter(|packet| packet.header.class == PacketClass::Telemetry)
                                .and_then(|packet| {
                                    TelemetryFrame::decode(packet.payload)
                                        .ok()
                                        .map(|frame| (packet.header.origin, frame.kind, frame.seq))
                                });
                            let received_id = decoded
                                .as_ref()
                                .filter(|packet| {
                                    matches!(
                                        packet.header.class,
                                        PacketClass::Broadcast | PacketClass::Presence
                                    )
                                })
                                .map(|packet| packet.header.msg_id);
                            // The replay probe needs every class: Direct is
                            // the traffic that actually fills a relay store.
                            let probe_source = decoded
                                .as_ref()
                                .map(|packet| (*link, *channel, packet.header.msg_id));
                            (
                                MeshInput::Data {
                                    link: *link,
                                    channel: *channel,
                                    payload,
                                    identity: &self.identities[i],
                                },
                                received_id,
                                telemetry,
                                probe_source,
                            )
                        }
                        _ => continue,
                    };
                    if let Some(id) = received_id {
                        self.received_ids[i].insert(id);
                    }
                    if let Some((origin, kind, seq)) = telemetry {
                        self.telemetry_receptions += 1;
                        let streams = self.telemetry_seqs[i].entry((origin, kind)).or_default();
                        streams.insert(seq);
                    }
                    let outputs = self.nodes[i]
                        .adapter
                        .engine_mut()
                        .handle(now_ms, input)
                        .expect("engine inputs are well formed");
                    if let Some((link, channel, id)) = probe_source {
                        self.capture_probe(i, link, channel, id, &outputs);
                    }
                    self.count_outputs(i, now_ms, &outputs);
                    self.service_stores(i, now, now_ms, outputs.clone());
                    let events = self.nodes[i].adapter.apply(now, outputs);
                    for event in events {
                        if let crate::AdapterEvent::SendFailed { .. } = event {
                            self.send_failures += 1;
                        }
                    }
                }
                // Presence trickle is host-driven: the borrowed identity and
                // card hash are supplied on every tick, never retained.
                let card_hash = self.nodes[i].card_hash;
                let outputs = self.nodes[i]
                    .adapter
                    .engine_mut()
                    .handle(
                        now_ms,
                        MeshInput::Tick {
                            identity: &self.identities[i],
                            card_hash,
                        },
                    )
                    .expect("presence tick inputs are well formed");
                self.count_outputs(i, now_ms, &outputs);
                self.service_stores(i, now, now_ms, outputs.clone());
                let events = self.nodes[i].adapter.apply(now, outputs);
                for event in events {
                    if let crate::AdapterEvent::SendFailed { .. } = event {
                        self.send_failures += 1;
                    }
                }
            }
            if self.scenario.presence && !self.presence_converged && self.run_started {
                let learned = self
                    .nodes
                    .iter()
                    .map(|node| node.adapter.engine().presence().len())
                    .min()
                    .unwrap_or(0);
                if learned >= self.nodes.len().saturating_sub(1) {
                    self.presence_converged = true;
                    self.convergence_ms = now_ms.saturating_sub(self.run_start_ms);
                }
            }
            self.sample_queues();
            self.directory_tick(now_ms);
        }
    }

    /// Injects one seeded directory observation round when due, then ticks
    /// every engine so relative-time expiry happens even without traffic.
    fn directory_tick(&mut self, now_ms: u64) {
        let Some(plan) = self.scenario.directory.clone() else {
            return;
        };
        if !self.run_started {
            return;
        }
        let n = self.nodes.len();
        if self.directory_announcements < plan.announcements
            && now_ms.saturating_sub(self.directory_last_ms) >= plan.every_ms
        {
            self.directory_last_ms = now_ms;
            let round = self.directory_announcements;
            for i in 0..n {
                let target = (i + 1 + round) % n;
                let card_hash = self.nodes[target].card_hash;
                let location = [i as u8, target as u8, round as u8, (round >> 8) as u8];
                // Half the nodes report a future timestamp and half a past
                // one; the directory clamps both and never uses either for
                // expiry.
                let observed_at_ms = if i % 2 == 0 {
                    now_ms.saturating_add(plan.observed_skew_ms)
                } else {
                    now_ms.saturating_sub(plan.observed_skew_ms)
                };
                let observation = NodeObservation {
                    node: self.identities[target].node_id(),
                    card_hash,
                    caps: 1 << ((i + round) % 4),
                    seq: round as u64 + 1,
                    hops: ((i + round) % 4 + 1) as u8,
                    via: self.identities[(i + 1) % n].node_id(),
                    observed_at_ms,
                    location: &location,
                };
                let outputs = self.nodes[i]
                    .adapter
                    .engine_mut()
                    .handle(now_ms, MeshInput::ObserveNode { observation })
                    .expect("host observations are bounded");
                self.note_directory_changes(&outputs, now_ms);
            }
            self.directory_announcements = self.directory_announcements.saturating_add(1);
        }

        for i in 0..n {
            let card_hash = self.nodes[i].card_hash;
            let outputs = self.nodes[i]
                .adapter
                .engine_mut()
                .handle(
                    now_ms,
                    MeshInput::Tick {
                        identity: &self.identities[i],
                        card_hash,
                    },
                )
                .expect("tick is valid");
            self.note_directory_changes(&outputs, now_ms);
        }
        for node in &self.nodes {
            self.directory_peak_entries = self
                .directory_peak_entries
                .max(node.adapter.engine().directory().len());
        }
    }

    fn note_directory_changes(&mut self, outputs: &[MeshOutput], now_ms: u64) {
        for output in outputs {
            if let MeshOutput::DirectoryChanged { changes } = output {
                for change in changes {
                    if matches!(change, DirectoryChange::Removed { .. }) {
                        self.directory_last_removal_ms = self.directory_last_removal_ms.max(now_ms);
                    }
                }
            }
        }
    }

    /// True only for an MSH-19 announcement, not other Presence traffic.
    fn is_announcement(payload: &[u8]) -> bool {
        Packet::decode(payload).is_ok_and(|packet| {
            packet.header.class == PacketClass::Presence
                && packet.payload.len() == ANNOUNCE_LEN
                && packet.payload.first() == Some(&ANNOUNCE_MAGIC)
        })
    }

    /// Keeps one wire this node actually relayed, for the post-restart probe.
    ///
    /// A delayed copy of the same content is what a store-and-forward relay
    /// sees when a peer repeats a packet after the engine comes back. The
    /// probe is recorded only when the node put that id on the air, so the
    /// restored and ablated rows differ solely in persisted state.
    fn capture_probe(
        &mut self,
        node: usize,
        link: LinkId,
        channel: Channel,
        id: MessageId,
        outputs: &[MeshOutput],
    ) {
        if self.probe_wires[node].is_some() {
            return;
        }
        for output in outputs {
            let payload = match output {
                MeshOutput::Send { payload, .. } | MeshOutput::Broadcast { payload, .. } => payload,
                _ => continue,
            };
            if probe_id(payload) == Some(id) {
                self.probe_wires[node] = Some((link, channel, payload.clone()));
                return;
            }
        }
    }

    /// Tracks which ids this node has already put on the air so a restarted
    /// engine can be checked for re-relays of the same content.
    fn count_relay(&mut self, node: usize, payload: &[u8]) {
        let Some(id) = probe_id(payload) else {
            return;
        };
        if self.restart_done {
            self.restart_sends_after += 1;
            if self.sent_ids[node].contains(&id) {
                self.restart_replays += 1;
            }
        } else {
            let _ = self.sent_ids[node].insert(id);
        }
    }

    fn count_outputs(&mut self, node: usize, now_ms: u64, outputs: &[MeshOutput]) {
        for output in outputs {
            match output {
                MeshOutput::Send { link, payload, .. } => {
                    self.transmissions += 1;
                    *self.pending[node].entry(*link).or_insert(0) += payload.len() as u64;
                    if self.run_started && Self::is_announcement(payload) {
                        self.announcement_sends += 1;
                        self.announcement_bytes += payload.len() as u64;
                        if now_ms >= self.run_start_ms + 60_000 {
                            self.steady_announcement_sends += 1;
                            self.steady_announcement_bytes += payload.len() as u64;
                        }
                    }
                    if is_channel_payload(payload) {
                        self.channel_transmissions += 1;
                        self.channel_bytes += payload.len() as u64;
                    }
                    self.count_relay(node, payload);
                }
                MeshOutput::Broadcast { payload, .. } => {
                    let links = self.nodes[node].adapter.network().links();
                    self.transmissions += links.len() as u64;
                    if is_channel_payload(payload) {
                        self.channel_transmissions += links.len() as u64;
                        self.channel_bytes += payload.len() as u64 * links.len() as u64;
                    }
                    for info in links {
                        *self.pending[node].entry(info.link).or_insert(0) += payload.len() as u64;
                    }
                    self.count_relay(node, payload);
                }
                MeshOutput::TelemetrySend { link, payload, .. } => {
                    self.transmissions += 1;
                    *self.pending[node].entry(*link).or_insert(0) += payload.len() as u64;
                }
                MeshOutput::TelemetryBroadcast { payload, .. } => {
                    let links = self.nodes[node].adapter.network().links();
                    self.transmissions += links.len() as u64;
                    for info in links {
                        *self.pending[node].entry(info.link).or_insert(0) += payload.len() as u64;
                    }
                }
                MeshOutput::Deliver { header, .. } => {
                    if self.delivered_ids[node].insert(header.msg_id) {
                        self.delivered += 1;
                        let latency = now_ms.saturating_sub(header.created_ms);
                        self.latencies.push(latency);
                        if self.fresh_hint_ids.contains(&header.msg_id) {
                            self.fresh_latencies.push(latency);
                            self.fresh_hint_deliveries += 1;
                        }
                        if let Some(origin) = self.origin_index.get(&header.origin) {
                            self.delivered_by_origin[*origin] += 1;
                        }
                        self.first_delivery_ms
                            .entry(header.msg_id)
                            .or_insert(now_ms);
                        if self
                            .store_holders
                            .get(&header.msg_id)
                            .is_none_or(BTreeSet::is_empty)
                        {
                            self.purge_latencies.push(0);
                            self.purge_recorded.insert(header.msg_id);
                        }
                    } else {
                        self.duplicate_deliveries += 1;
                    }
                }
                MeshOutput::ChannelDeliver { header, .. } => {
                    if self.channel_delivered_ids[node].insert(header.msg_id) {
                        self.channel_deliveries += 1;
                    }
                }
                MeshOutput::Delivered { origin, .. }
                    if self.origin_index.get(origin) == Some(&node) =>
                {
                    self.receipts += 1;
                }
                MeshOutput::CardFetch { .. } => self.card_fetches += 1,
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

    /// Hop counts over the current radio graph, used only to model MSH-20's
    /// presence observation seam. No transmission or engine state is involved.
    fn hop_distances(&self) -> Vec<Vec<u8>> {
        let n = self.nodes.len();
        let mut dist = vec![vec![u8::MAX; n]; n];
        for (src, row) in dist.iter_mut().enumerate() {
            let mut queue = VecDeque::new();
            row[src] = 0;
            queue.push_back(src);
            while let Some(at) = queue.pop_front() {
                let hops = row[at].saturating_add(1);
                for (next, seen) in row.iter_mut().enumerate() {
                    if self.ranges[at][next] && *seen == u8::MAX {
                        *seen = hops;
                        queue.push_back(next);
                    }
                }
            }
        }
        dist
    }

    /// The neighbour on a shortest path, or `None` when the target is
    /// unreachable at this instant.
    fn first_hop(&self, from: usize, to: usize, dist: &[Vec<u8>]) -> Option<usize> {
        let hops = dist[from][to];
        if hops == 0 || hops == u8::MAX {
            return None;
        }
        (0..self.nodes.len()).find(|&next| {
            self.ranges[from][next]
                && dist[next][to] != u8::MAX
                && dist[next][to].saturating_add(1) == hops
        })
    }

    /// Feeds one round of typed directory facts into every node.
    ///
    /// The BFS supplies the same facts the host would learn from presence:
    /// destination, via-neighbour, hop count and a fresh sequence. They enter
    /// the engine through MSH-20's `ObserveNode` seam, which both records the
    /// directory entry and derives an MSH-21 hint when the via-node is a
    /// verified neighbour. No mesh packet is generated. Off-mode rows get the
    /// same facts, keeping the fresh-path denominator identical.
    fn inject_route_hints(&mut self, now_ms: u64) {
        self.hint_seq = self.hint_seq.saturating_add(1);
        for set in &mut self.injected_fresh {
            set.clear();
        }
        let dist = self.hop_distances();
        let n = self.nodes.len();
        let seq = self.hint_seq;
        let world_now = self.world.now();
        let mut observations = Vec::new();
        let mut fresh_updates = Vec::new();
        for i in 0..n {
            let links: Vec<NodeId> = self.nodes[i]
                .adapter
                .engine()
                .neighbors()
                .iter()
                .filter_map(|neighbor| neighbor.node_id)
                .collect();
            for dst in 0..n {
                if dst == i || dist[i][dst] == u8::MAX {
                    continue;
                }
                let Some(first) = self.first_hop(i, dst, &dist) else {
                    continue;
                };
                let first_id = self.identities[first].node_id();
                if !links.contains(&first_id) {
                    continue;
                }
                let destination = self.identities[dst].node_id();
                observations.push((
                    i,
                    NodeObservation {
                        node: destination,
                        card_hash: self.nodes[dst].card_hash,
                        caps: 0,
                        seq,
                        hops: dist[i][dst],
                        via: first_id,
                        observed_at_ms: now_ms,
                        location: &[],
                    },
                ));
                fresh_updates.push((i, destination));
            }
        }
        for (i, destination) in fresh_updates {
            self.injected_fresh[i].insert(destination);
        }
        for (i, observation) in observations {
            let outputs = self.nodes[i]
                .adapter
                .engine_mut()
                .handle(now_ms, MeshInput::ObserveNode { observation })
                .expect("directory observation is bounded");
            self.note_directory_changes(&outputs, now_ms);
            self.count_outputs(i, now_ms, &outputs);
            self.service_stores(i, world_now, now_ms, outputs.clone());
            let events = self.nodes[i].adapter.apply(world_now, outputs);
            for event in events {
                if let crate::AdapterEvent::SendFailed { .. } = event {
                    self.send_failures += 1;
                }
            }
        }
    }

    /// Submits one sealed message at the current world time. Staggering
    /// these across the run phase is what lets mobility and scripted contacts
    /// affect delivery instead of finishing before the first contact changes.
    fn submit_one(&mut self, m: usize) {
        let n = self.nodes.len();
        if let Traffic::Telemetry {
            origin: source,
            kind,
            ..
        } = self.scenario.traffic
        {
            let origin = source.min(n - 1);
            let now_ms = self.world.now().as_millis() as u64;
            let payload = vec![(m % 251) as u8; self.scenario.payload_len];
            self.telemetry_attempts += 1;
            self.submitted += 1;
            match self.nodes[origin].adapter.engine_mut().handle(
                now_ms,
                MeshInput::SubmitTelemetry {
                    identity: &self.identities[origin],
                    kind: TelemetryKind::new(kind),
                    seq: m as u64 + 1,
                    payload: &payload,
                    via: None,
                },
            ) {
                Ok(outputs) => {
                    self.telemetry_accepted += 1;
                    self.count_outputs(origin, now_ms, &outputs);
                    self.service_stores(origin, self.world.now(), now_ms, outputs.clone());
                    let events = self.nodes[origin].adapter.apply(self.world.now(), outputs);
                    for event in events {
                        if let crate::AdapterEvent::SendFailed { .. } = event {
                            self.send_failures += 1;
                        }
                    }
                }
                // A throttled submission is a policy result, not a simulator
                // failure. It must never reach a radio queue.
                Err(_) => self.telemetry_rejected += 1,
            }
            return;
        }
        let (origin, broadcast, channel_name) = match self.scenario.traffic {
            Traffic::Balanced => (m % n, false, None),
            Traffic::Flood {
                origin: flood,
                weight,
            } => {
                let round = weight.max(1) + 1;
                if m % round == 0 {
                    (flood.min(n - 1), false, None)
                } else {
                    let honest = n - 1;
                    let slot = (m / round) * weight + (m % round) - 1;
                    ((flood.min(n - 1) + 1 + slot % honest) % n, false, None)
                }
            }
            Traffic::Broadcast { origin } => (origin.min(n - 1), true, None),
            Traffic::MixedBroadcast {
                origin,
                direct_every,
            } => {
                if m % direct_every.max(1) == 0 {
                    (m % n, false, None)
                } else {
                    (origin.min(n - 1), true, None)
                }
            }
            // Presence scenarios submit no application messages, so this is
            // unreachable for the fixed scenario. Returning keeps the harness
            // total without a panic on a misconfigured scenario.
            Traffic::Presence => return,
            // The typed path returned above; this keeps the match total
            // without a simulator-only panic.
            Traffic::Telemetry { origin, .. } => (origin.min(n - 1), false, None),
            Traffic::Channel { origin, name, .. } => (origin.min(n - 1), true, Some(name)),
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
        let (header, payload, wire) = if broadcast {
            // Broadcast payloads are opaque to the mesh: a channel is a v1
            // envelope around the same host bytes. The engine caps TTL at
            // ADR-0001's six hops on submission.
            let sender = &self.identities[origin];
            let wire_payload = match channel_name {
                Some(name) => {
                    let id = derive_channel_id(name.as_bytes()).expect("fixed channel name");
                    ChannelEnvelope::new(id, &plaintext)
                        .expect("fixed opaque payload fits")
                        .encode()
                }
                None => plaintext.clone(),
            };
            let mut header = Header {
                class: PacketClass::Broadcast,
                dst: None,
                msg_id: [0; 16].into(),
                origin: *sender.node_id().as_bytes(),
                created_ms: now_ms,
                lifetime_s: 600,
                payload_len: wire_payload.len() as u64,
                ttl: 255,
                hops: 0,
            };
            let signature =
                sign_packet(sender, &mut header, &wire_payload).expect("fixed key signs");
            let packet =
                crate::Packet::new(header, signature, &wire_payload).expect("lengths agree");
            let wire = packet.encode();
            (packet.header, wire_payload, wire)
        } else {
            let sender = &self.identities[origin];
            let recipient = &self.identities[dst];
            let (mut header, payload) =
                seal_delivery(&mut rng, sender, recipient, now_ms, 3_600, 8, &plaintext)
                    .expect("fixed identities seal");
            let signature = sign_packet(sender, &mut header, &payload).expect("fixed key signs");
            let packet = crate::Packet::new(header, signature, &payload).expect("lengths agree");
            let wire = packet.encode();
            (packet.header, payload, wire)
        };
        let submitted_id = header.msg_id;
        if !broadcast {
            let destination = self.identities[dst].node_id();
            if self.injected_fresh[origin].contains(&destination) {
                self.fresh_hint_ids.insert(submitted_id);
                self.fresh_hint_submissions += 1;
            }
        }
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
        if self.scenario.spray && !broadcast {
            let copies = self.nodes[origin]
                .adapter
                .engine()
                .spray_copies_left(submitted_id);
            self.store_item(origin, now_ms, &wire, copies);
            self.refresh_store_summary(origin, self.world.now(), now_ms);
        }
        self.count_outputs(origin, now_ms, &outputs);
        self.service_stores(origin, self.world.now(), now_ms, outputs.clone());
        let events = self.nodes[origin].adapter.apply(self.world.now(), outputs);
        for event in events {
            if let crate::AdapterEvent::SendFailed { .. } = event {
                self.send_failures += 1;
            }
        }
    }

    /// Restarts every engine at a scenario checkpoint (MSH-29).
    ///
    /// The radio facade and its live links stay in place; only the engine is
    /// replaced. The host snapshots all engines before mutating any of them,
    /// so a snapshot failure cannot leave a half-restarted simulation. Links
    /// are re-announced because their capability bits belong to the session,
    /// not to the routing snapshot.
    fn restart(&mut self) {
        self.restart_done = true;
        let now = self.world.now();
        let now_ms = now.as_millis() as u64;
        let restore = self.scenario.restart.is_some_and(|restart| restart.restore);
        let n = self.nodes.len();
        let mut snapshots = Vec::with_capacity(n);
        for i in 0..n {
            let bytes = self.nodes[i]
                .adapter
                .engine()
                .snapshot()
                .expect("engine state has a valid snapshot");
            self.restart_snapshot_bytes = self.restart_snapshot_bytes.max(bytes.len());
            snapshots.push(bytes);
        }
        let hellos = self.link_hellos.clone();
        let probes = self.probe_wires.clone();
        for i in 0..n {
            let engine_rng = EngineRng::seed_from_u64(self.scenario.seed ^ (i as u64 + 1));
            let mut engine = MeshEngine::with_config(engine_rng, engine_config(&self.scenario));
            if restore {
                engine
                    .restore(&snapshots[i])
                    .expect("a snapshot taken from this engine restores");
            }
            let _ = self.nodes[i].adapter.replace_engine(engine);

            for (link, remote_hello) in &hellos[i] {
                let outputs = self.nodes[i]
                    .adapter
                    .engine_mut()
                    .handle(
                        now_ms,
                        MeshInput::LinkUp {
                            link: *link,
                            remote_hello: remote_hello.clone(),
                        },
                    )
                    .expect("recorded link hello is well formed");
                self.count_outputs(i, now_ms, &outputs);
                let events = self.nodes[i].adapter.apply(now, outputs);
                for event in events {
                    if let crate::AdapterEvent::SendFailed { .. } = event {
                        self.send_failures += 1;
                    }
                }
            }

            if let Some((link, channel, payload)) = probes[i].as_ref() {
                let outputs = self.nodes[i]
                    .adapter
                    .engine_mut()
                    .handle(
                        now_ms,
                        MeshInput::Data {
                            link: *link,
                            channel: *channel,
                            payload,
                            identity: &self.identities[i],
                        },
                    )
                    .expect("a previously relayed wire is still well formed");
                self.count_outputs(i, now_ms, &outputs);
                let events = self.nodes[i].adapter.apply(now, outputs);
                for event in events {
                    if let crate::AdapterEvent::SendFailed { .. } = event {
                        self.send_failures += 1;
                    }
                }
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
        let hint_every = HINT_REFRESH.as_millis() as u64;
        self.inject_route_hints(self.world.now().as_millis() as u64);
        let run_steps = (self.scenario.run.as_millis() / TICK.as_millis()) as usize;
        let steps = run_steps.max(1);
        // Keep the last fifth of the run free so the final message can
        // propagate; otherwise the last submission is cut off at the clock.
        let submit_steps = (steps * 4 / 5).max(1);
        let burst_telemetry = matches!(
            self.scenario.traffic,
            Traffic::Telemetry { burst: true, .. }
        );
        for step in 0..steps {
            if burst_telemetry {
                // All updates are accepted into the send queue before the
                // radio gets a tick, which is the slow-link case NET-21
                // coalescing exists to handle.
                if step == 0 {
                    while (self.submitted as usize) < self.scenario.messages {
                        self.submit_one(self.submitted as usize);
                    }
                }
            } else if step < submit_steps {
                let target = (step + 1) * self.scenario.messages / submit_steps;
                while (self.submitted as usize) < target {
                    self.submit_one(self.submitted as usize);
                }
            }
            if !self.restart_done {
                if let Some(restart) = self.scenario.restart {
                    let now_ms = self.world.now().as_millis() as u64;
                    if now_ms.saturating_sub(self.run_start_ms) >= restart.at.as_millis() as u64 {
                        self.restart();
                    }
                }
            }
            self.pump(1);
            let now_ms = self.world.now().as_millis() as u64;
            if now_ms % hint_every == 0 {
                self.inject_route_hints(now_ms);
            }
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
        let learned_nodes_min = self
            .nodes
            .iter()
            .map(|node| node.adapter.engine().presence().len())
            .min()
            .unwrap_or(0);
        let denominator = if self.direct_submitted > 0 {
            self.direct_submitted
        } else {
            self.submitted
        };
        let fresh_mean = if self.fresh_latencies.is_empty() {
            0
        } else {
            self.fresh_latencies.iter().sum::<u64>() / self.fresh_latencies.len() as u64
        };
        let telemetry_distinct_seqs = self
            .telemetry_seqs
            .iter()
            .flat_map(|streams| streams.values())
            .map(BTreeSet::len)
            .sum::<usize>() as u64;
        let telemetry_max_seqs_per_node = self
            .telemetry_seqs
            .iter()
            .map(|streams| streams.values().map(BTreeSet::len).sum::<usize>())
            .max()
            .unwrap_or(0) as u64;
        let telemetry_max_seq = self
            .telemetry_seqs
            .iter()
            .flat_map(|streams| streams.values())
            .flat_map(BTreeSet::iter)
            .copied()
            .max()
            .unwrap_or(0);
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
            delivery_ratio: if denominator == 0 {
                0.0
            } else {
                self.delivered as f64 / denominator as f64
            },
            overhead: self.transmissions as f64 / self.delivered.max(1) as f64,
            duplicate_ratio: self.duplicate_deliveries as f64 / self.delivered.max(1) as f64,
            peak_queued_bytes: self.peak_queued_bytes,
            links_after_settle: self.links_after_settle,
            delivered_by_origin: self.delivered_by_origin,
            purges: self.purges,
            delivery_receipts: self.receipts,
            remaining_copies: self.store_holders.values().map(BTreeSet::len).sum(),
            remaining_delivered_copies: self
                .store_holders
                .iter()
                .filter(|(id, _)| self.first_delivery_ms.contains_key(id))
                .map(|(_, holders)| holders.len())
                .sum(),
            remaining_delivered_copies_immune: self
                .store_holders
                .iter()
                .filter(|(id, _)| self.first_delivery_ms.contains_key(id))
                .map(|(id, holders)| {
                    holders
                        .iter()
                        .filter(|node| self.nodes[**node].adapter.engine().is_immune(*id))
                        .count()
                })
                .sum(),
            max_purge_latency_ms: self.purge_latencies.iter().copied().max().unwrap_or(0),
            directory_peak_entries: self.directory_peak_entries,
            directory_expirations: self
                .nodes
                .iter()
                .map(|node| node.adapter.engine().directory().stats().expirations)
                .sum(),
            directory_evictions: self
                .nodes
                .iter()
                .map(|node| node.adapter.engine().directory().stats().evictions)
                .sum(),
            directory_last_removal_ms: self.directory_last_removal_ms,
            directory_live_entries: self
                .nodes
                .iter()
                .map(|node| {
                    node.adapter
                        .engine()
                        .directory()
                        .live_len(self.world.now().as_millis() as u64)
                })
                .sum(),
            fresh_hint_submissions: self.fresh_hint_submissions,
            fresh_hint_deliveries: self.fresh_hint_deliveries,
            fresh_hint_mean_latency_ms: fresh_mean,
            channel_subscribers: self.channel_subscribers,
            channel_deliveries: self.channel_deliveries,
            channel_delivered_ids: self.channel_delivered_ids,
            channel_transmissions: self.channel_transmissions,
            channel_bytes: self.channel_bytes,
            restart_snapshot_bytes: self.restart_snapshot_bytes,
            restart_replays: self.restart_replays,
            restart_sends_after: self.restart_sends_after,
            unique_receptions_by_node: self
                .received_ids
                .iter()
                .map(|ids| ids.len() as u64)
                .collect(),
            unique_receptions: self.received_ids.iter().map(BTreeSet::len).sum::<usize>() as u64,
            presence_converged: self.presence_converged,
            convergence_ms: self.convergence_ms,
            learned_nodes_min,
            card_fetches: self.card_fetches,
            announcement_sends: self.announcement_sends,
            announcement_bytes: self.announcement_bytes,
            steady_announcement_sends: self.steady_announcement_sends,
            steady_announcement_bytes: self.steady_announcement_bytes,
            telemetry_attempts: self.telemetry_attempts,
            telemetry_accepted: self.telemetry_accepted,
            telemetry_rejected: self.telemetry_rejected,
            telemetry_receptions: self.telemetry_receptions,
            telemetry_distinct_seqs,
            telemetry_max_seqs_per_node,
            telemetry_max_seq,
        }
    }
}

/// Runs one scenario. Kept as a free function so the example and tests
/// share exactly the same path.
pub fn run(scenario: Scenario) -> Metrics {
    Simulation::new(scenario).run()
}

/// Whether a mesh send payload is a v1 channel envelope. Used only by the
/// harness's MSH-23 accounting; the engine keeps no such counter.
fn is_channel_payload(wire: &[u8]) -> bool {
    Packet::decode(wire).is_ok_and(|packet| {
        packet.header.class == PacketClass::Broadcast
            && packet.payload.first() == Some(&CHANNEL_MAGIC)
    })
}

/// Returns the mesh packet inside an optional spray envelope.
fn packet_bytes(payload: &[u8]) -> Option<&[u8]> {
    if payload.first() == Some(&crate::SPRAY_MAGIC) && payload.len() >= 6 {
        let len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
        payload.get(6..6 + len)
    } else {
        Some(payload)
    }
}

/// Content address of one emitted message send, through a spray envelope if
/// present. Control frames return `None` and never count as a replay.
fn probe_id(payload: &[u8]) -> Option<MessageId> {
    Packet::decode(packet_bytes(payload)?)
        .ok()
        .map(|packet| packet.header.msg_id)
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

/// Measured cost of one MSH-14 or MSH-15 contact.
///
/// Bytes are counted on the Bulk frames both engines emit, so the report is
/// the wire cost a radio would carry. Item packets are separated from the
/// control frames that discover them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncComparison {
    /// Negotiated sync protocol: `v1` or `v2`.
    pub mode: &'static str,
    /// Reproduction seed.
    pub seed: u64,
    /// Ids in the local store.
    pub local_ids: usize,
    /// Ids in the remote store.
    pub remote_ids: usize,
    /// Ids present in exactly one store.
    pub difference: usize,
    /// Bytes of summary, request and range frames.
    pub control_bytes: usize,
    /// Bytes of packet items sent to reconcile the stores.
    pub item_bytes: usize,
    /// Control plus item bytes in both directions.
    pub total_bytes: usize,
    /// Number of MSH-14 control frames.
    pub v1_frames: usize,
    /// Number of MSH-15 control frames.
    pub v2_frames: usize,
    /// Whether both stores ended with the same summary.
    pub converged: bool,
}

impl SyncComparison {
    /// CSV column names, in the same order as [`Self::csv_row`].
    pub fn csv_header() -> &'static str {
        "mode,seed,local_ids,remote_ids,difference,control_bytes,item_bytes,total_bytes,v1_frames,v2_frames,converged"
    }

    /// One CSV line for this measured contact.
    pub fn csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{}",
            self.mode,
            self.seed,
            self.local_ids,
            self.remote_ids,
            self.difference,
            self.control_bytes,
            self.item_bytes,
            self.total_bytes,
            self.v1_frames,
            self.v2_frames,
            self.converged,
        )
    }
}

const BENCH_LINK_A: LinkId = LinkId::new(91);
const BENCH_LINK_B: LinkId = LinkId::new(92);
/// MSH-14 `SyncFrame::Item` tag; item frames share the sync magic byte.
const BENCH_TAG_ITEM: u8 = 3;

fn bench_hello(identity: &Identity, digest: [u8; 4], caps: u32) -> Hello {
    let signed = MeshHello::sign_with_caps(identity, [0; 8], digest, caps)
        .expect("benchmark identity signs");
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps: 0,
        max_frame: 16_384,
        tag: LocalTag::new([1; 16]),
        app_hello: AppHello::new(signed.encode().to_vec()).expect("hello fits"),
    }
}

fn bench_wire(owner: &Identity, tag: u32) -> Vec<u8> {
    let payload = format!("sync-comparison-{tag}").into_bytes();
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
    let signature = sign_packet(owner, &mut header, &payload).expect("benchmark packet signs");
    Packet::new(header, signature, &payload)
        .expect("benchmark packet fields agree")
        .encode()
}

fn bench_put(store: &mut MemoryStore, now: u64, bytes: &[u8]) {
    let metadata = StoreMetadata {
        copies_left: 1,
        first_seen: now,
        received_at: now,
        priority: 0,
        received_from: None,
        age_ms: 0,
    };
    let message = StoredMessage::new(bytes, metadata).expect("bounded benchmark item");
    store.put(now, message).expect("store has room");
}

#[derive(Default)]
struct BenchService {
    frames: Vec<Vec<u8>>,
    items: Vec<Vec<u8>>,
    releases: usize,
    control_bytes: usize,
    item_bytes: usize,
    v1_frames: usize,
    v2_frames: usize,
}

fn bench_service(
    engine: &mut MeshEngine<EngineRng>,
    store: &MemoryStore,
    now: u64,
    outputs: Vec<MeshOutput>,
) -> BenchService {
    let mut result = BenchService::default();
    for output in outputs {
        match output {
            MeshOutput::Send {
                channel: Channel::Bulk,
                payload,
                ..
            } => {
                if payload.first() == Some(&SYNC_MAGIC)
                    && payload.get(1) != Some(&SYNC_V2_VERSION)
                    && payload.get(2) == Some(&BENCH_TAG_ITEM)
                {
                    result.item_bytes += payload.len();
                } else if payload.first() == Some(&SYNC_MAGIC) {
                    result.control_bytes += payload.len();
                    if payload.get(1) == Some(&SYNC_V2_VERSION) {
                        result.v2_frames += 1;
                    } else {
                        result.v1_frames += 1;
                    }
                } else {
                    result.item_bytes += payload.len();
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
                            copies_left: message.metadata().copies_left,
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
                let nested = bench_service(engine, store, now, extra);
                result.frames.extend(nested.frames);
                result.items.extend(nested.items);
                result.releases += nested.releases;
                result.control_bytes += nested.control_bytes;
                result.item_bytes += nested.item_bytes;
                result.v1_frames += nested.v1_frames;
                result.v2_frames += nested.v2_frames;
            }
            _ => {}
        }
    }
    result
}

/// Runs one deterministic contact with either negotiated protocol.
///
/// Both runs use identical stores, identities and wires; only the advertised
/// capability bit changes, so the byte difference is the protocol's cost.
#[must_use]
pub fn run_sync_comparison(
    mode: &'static str,
    seed: u64,
    local_ids: usize,
    remote_ids: usize,
) -> SyncComparison {
    let caps = if mode == "v2" { CAPS } else { CAP_SYNC_V1 };
    let mut owner_seed = [0u8; 32];
    owner_seed.copy_from_slice(blake3::hash(&seed.to_be_bytes()).as_bytes());
    let owner = Identity::from_seed(owner_seed);
    let mut peer_seed = [0u8; 32];
    peer_seed.copy_from_slice(blake3::hash(&(seed ^ 0x515f_2026).to_be_bytes()).as_bytes());
    let peer = Identity::from_seed(peer_seed);

    let mut a_store = MemoryStore::new(Default::default());
    let mut b_store = MemoryStore::new(Default::default());
    let wires: Vec<Vec<u8>> = (0..local_ids.max(remote_ids))
        .map(|tag| bench_wire(&owner, tag as u32))
        .collect();
    for wire in &wires[..local_ids] {
        bench_put(&mut a_store, 0, wire);
    }
    for wire in &wires[..remote_ids] {
        bench_put(&mut b_store, 0, wire);
    }
    let a_ids = a_store.summary(0);
    let b_ids = b_store.summary(0);

    let config = MeshConfig {
        max_neighbors: 4,
        ..MeshConfig::default()
    };
    let mut a = MeshEngine::with_config(EngineRng::seed_from_u64(seed), config);
    let mut b = MeshEngine::with_config(EngineRng::seed_from_u64(seed ^ 1), config);
    a.handle(0, MeshInput::StoreSummary { ids: &a_ids })
        .expect("local summary");
    b.handle(0, MeshInput::StoreSummary { ids: &b_ids })
        .expect("remote summary");

    let mut report = SyncComparison {
        mode,
        seed,
        local_ids,
        remote_ids,
        difference: local_ids.max(remote_ids) - local_ids.min(remote_ids),
        control_bytes: 0,
        item_bytes: 0,
        total_bytes: 0,
        v1_frames: 0,
        v2_frames: 0,
        converged: false,
    };

    let mut a_frames = Vec::new();
    let mut b_frames = Vec::new();
    let mut a_releases = 0;
    let mut b_releases = 0;

    let out = a
        .handle(
            0,
            MeshInput::LinkUp {
                link: BENCH_LINK_A,
                remote_hello: bench_hello(
                    &peer,
                    StoreSummary::from_store(&b_store, 0).digest(),
                    caps,
                ),
            },
        )
        .expect("link up");
    let serviced = bench_service(&mut a, &a_store, 0, out);
    a_frames.extend(serviced.frames);
    a_releases += serviced.releases;
    report.control_bytes += serviced.control_bytes;
    report.item_bytes += serviced.item_bytes;
    report.v1_frames += serviced.v1_frames;
    report.v2_frames += serviced.v2_frames;

    let out = b
        .handle(
            0,
            MeshInput::LinkUp {
                link: BENCH_LINK_B,
                remote_hello: bench_hello(
                    &owner,
                    StoreSummary::from_store(&a_store, 0).digest(),
                    caps,
                ),
            },
        )
        .expect("link up");
    let serviced = bench_service(&mut b, &b_store, 0, out);
    b_frames.extend(serviced.frames);
    b_releases += serviced.releases;
    report.control_bytes += serviced.control_bytes;
    report.item_bytes += serviced.item_bytes;
    report.v1_frames += serviced.v1_frames;
    report.v2_frames += serviced.v2_frames;

    for round in 0..256u64 {
        let outgoing = std::mem::take(&mut a_frames);
        for payload in outgoing {
            let now = round + 1;
            let outputs = b
                .handle(
                    now,
                    MeshInput::Data {
                        link: BENCH_LINK_B,
                        channel: Channel::Bulk,
                        identity: &peer,
                        payload: &payload,
                    },
                )
                .expect("sync frame");
            let serviced = bench_service(&mut b, &b_store, now, outputs);
            b_frames.extend(serviced.frames);
            for item in serviced.items {
                bench_put(&mut b_store, now, &item);
            }
            b_releases += serviced.releases;
            report.control_bytes += serviced.control_bytes;
            report.item_bytes += serviced.item_bytes;
            report.v1_frames += serviced.v1_frames;
            report.v2_frames += serviced.v2_frames;
        }
        let outgoing = std::mem::take(&mut b_frames);
        for payload in outgoing {
            let now = round + 1;
            let outputs = a
                .handle(
                    now,
                    MeshInput::Data {
                        link: BENCH_LINK_A,
                        channel: Channel::Bulk,
                        identity: &owner,
                        payload: &payload,
                    },
                )
                .expect("sync frame");
            let serviced = bench_service(&mut a, &a_store, now, outputs);
            a_frames.extend(serviced.frames);
            for item in serviced.items {
                bench_put(&mut a_store, now, &item);
            }
            a_releases += serviced.releases;
            report.control_bytes += serviced.control_bytes;
            report.item_bytes += serviced.item_bytes;
            report.v1_frames += serviced.v1_frames;
            report.v2_frames += serviced.v2_frames;
        }
        if a_frames.is_empty() && b_frames.is_empty() && a_releases > 0 && b_releases > 0 {
            break;
        }
    }
    report.converged = a_store.summary(0) == b_store.summary(0);
    report.total_bytes = report.control_bytes + report.item_bytes;
    report
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
            telemetry_attempts: 0,
            telemetry_accepted: 0,
            telemetry_rejected: 0,
            telemetry_receptions: 0,
            telemetry_distinct_seqs: 0,
            telemetry_max_seqs_per_node: 0,
            telemetry_max_seq: 0,
            purges: 2,
            delivery_receipts: 1,
            remaining_copies: 0,
            remaining_delivered_copies: 0,
            remaining_delivered_copies_immune: 0,
            max_purge_latency_ms: 18,
            presence_converged: true,
            convergence_ms: 9_000,
            learned_nodes_min: 1,
            card_fetches: 0,
            announcement_sends: 12,
            announcement_bytes: 1_800,
            steady_announcement_sends: 4,
            steady_announcement_bytes: 600,
            directory_peak_entries: 0,
            directory_expirations: 0,
            directory_evictions: 0,
            directory_last_removal_ms: 0,
            directory_live_entries: 0,
            fresh_hint_submissions: 1,
            fresh_hint_deliveries: 1,
            fresh_hint_mean_latency_ms: 12,
            channel_subscribers: 2,
            channel_deliveries: 1,
            channel_delivered_ids: vec![BTreeSet::new(), BTreeSet::new()],
            channel_transmissions: 3,
            channel_bytes: 6_144,
            restart_snapshot_bytes: 0,
            restart_replays: 0,
            restart_sends_after: 0,
        };
        let row = m.csv_row();
        assert_eq!(row.lines().count(), 1);
        assert_eq!(
            row.split(',').count(),
            Metrics::csv_header().split(',').count()
        );
        assert_eq!(
            row,
            "test,1,2,3,2,0,8,6,0,1024,12,20,0.6667,4.0000,0.0000,100,1,true,9000,1,0,12,1800,4,600"
        );
    }

    #[test]
    fn v2_contact_cost_drops_for_large_stores() {
        const SEED: u64 = 0x515f_2026;
        let v1 = run_sync_comparison("v1", SEED, 1_000, 1_001);
        let v2 = run_sync_comparison("v2", SEED, 1_000, 1_001);
        assert!(v1.converged, "v1 must converge");
        assert!(v2.converged, "v2 must converge");
        assert_eq!(v1.difference, 1);
        assert_eq!(v2.difference, 1);
        assert!(
            v2.total_bytes * 2 < v1.total_bytes,
            "v2 must use less than half the bytes of v1: {} vs {}",
            v2.total_bytes,
            v1.total_bytes
        );
    }
}
