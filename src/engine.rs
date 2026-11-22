//! Sans-IO command dispatch with borrowed submissions and bounded neighbours.

use crate::budget::{BudgetOutcome, BudgetTracker};
use crate::channel::{
    CHANNEL_MAGIC, ChannelBudgetScope, ChannelEnvelope, ChannelError, ChannelId, ChannelRules,
    channel_budget_origin,
};
use crate::deliver;
use crate::directory::{DirectoryChange, DirectoryError, NodeDirectory, NodeObservation};
use crate::forward::{self, Action};
use crate::hop::{HopFrameError, HopTracker, encode_control};
use crate::linkhint::{HintChange, LinkHintObservation, LinkHintTable};
use crate::neighbor::{MeshConfig, NeighborTable};
use crate::observability::{MESH_SNAPSHOT_VERSION, MeshSnapshot, saturating_u32};
use crate::presence::{self, PresenceError, PresenceTracker};
use crate::receipt::{self, ReceiptError};
use crate::routehint::{RouteHintMode, RouteHintObservation, RouteHintTable};
use crate::seen::SeenCache;
use crate::suppress::{self, Sighting, SuppressionTable};
use crate::sync::{
    BeaconTracker, SHORT_ID_BYTES, StoreSummary, SyncAction, SyncFrame, SyncFrameV2, SyncOffer,
    SyncTracker,
};
use crate::telemetry::{TelemetryAdvisory, TelemetryFrame, TelemetryTracker};
use crate::{
    Header, MessageId, Packet, PacketClass, PacketError, sign_packet, verify_origin_with_signing_pk,
};
use ao_idents::{IdentError, Identity, NodeId, ReplayGuard, Signature};
use ao_network::{
    AppHello, BeaconFlags, Channel, DisconnectReason, Hello, LinkHintPreference, LinkId, LocalTag,
    PeerKey,
};
use rand_core::RngCore;
use std::collections::BTreeSet;

/// One input. Borrowed payloads and identities remain owned by the caller.
#[non_exhaustive]
pub enum MeshInput<'a> {
    /// A link is transport-ready; its signed `MeshHello` introduction
    /// is verified here before any identity is recorded.
    LinkUp {
        /// The link.
        link: LinkId,
        /// The untrusted introduction.
        remote_hello: Hello,
    },
    /// A previously observed link ended.
    LinkDown {
        /// The link.
        link: LinkId,
        /// The local closing reason.
        reason: DisconnectReason,
    },
    /// Opaque bytes received from a link. Parsing never copies the payload.
    Data {
        /// The sending link.
        link: LinkId,
        /// Transport channel, not a packet class or trust assertion.
        channel: Channel,
        /// The complete encoded mesh packet.
        payload: &'a [u8],
        /// The local identity, borrowed for this call: MSH-09's
        /// pipeline opens a Direct packet addressed to this node
        /// against it. The host must pass the identity its `dst`
        /// values name; a payload sealed to anyone else never
        /// delivers, and the engine retains no key.
        identity: &'a Identity,
    },
    /// The host's current live store ids (MSH-13).
    ///
    /// The engine never opens or persists the store; it canonicalises the
    /// ids into a compact summary and debounces the beacon digest.
    StoreSummary {
        /// Live message ids from [`crate::store::MessageStore::summary`].
        ids: &'a [MessageId],
    },
    /// Host-encoded packets for prefixes requested by a sync contact
    /// (MSH-14). The host owns the store; only the borrowed bytes are read.
    SyncItems {
        /// The contact's link.
        link: LinkId,
        /// One item per requested prefix, in host order.
        items: &'a [SyncOffer<'a>],
    },
    /// Time-driven step; fires MSH-11 timers, MSH-14 contact deadlines,
    /// MSH-19's presence trickle, MSH-20 directory expiry and MSH-21 hint
    /// expiry. The identity and card hash are borrowed for this call only;
    /// a change produces an announcement after the quick delay, then quiet
    /// refreshes back off to the steady interval.
    Tick {
        /// Borrowed signing identity; the engine retains no key.
        identity: &'a Identity,
        /// Opaque eight-byte hash of the host's current identity card.
        card_hash: [u8; 8],
    },
    /// Card hashes the host already knows (MSH-19). An announcement carrying
    /// any other hash produces a [`MeshOutput::CardFetch`]; the mesh never
    /// fetches, stores or interprets cards.
    KnownCards {
        /// The host's complete known-hash set, bounded by
        /// [`crate::PresenceConfig::max_known_cards`].
        hashes: &'a [[u8; 8]],
    },
    /// Record one advisory link fact for an unlinked radio peer (MSH-25).
    ///
    /// The host maps a recognised contact tag (or another peer it wants the
    /// mesh to reach) to aoNetwork's opaque `PeerKey` and supplies the mesh
    /// identity it associates with that peer. The engine combines it with
    /// directory diversity and MSH-10 penalties and emits at most one
    /// [`MeshOutput::SetLinkHint`] or [`MeshOutput::ClearLinkHint`].
    /// aoNetwork alone decides whether to form a link and enforces its cap.
    ObserveLinkHint {
        /// The fact to record.
        observation: LinkHintObservation,
    },
    /// Record one typed presence fact in the node directory (MSH-20).
    ///
    /// Verified MSH-19 announcements feed this narrow seam; the engine does
    /// not parse presence packets or fetch identity cards. An accepted fact
    /// also supplies an MSH-21 reverse-path hint when its `via` names a
    /// verified neighbour.
    ObserveNode {
        /// The opaque observation to record.
        observation: NodeObservation<'a>,
    },
    /// Host-produced Noise XX handshake bytes for one link (MSH-26).
    ///
    /// The engine adds the one-byte Control tag and emits a Control-frame
    /// send. It never sees a card, a handshake state or a key; the host
    /// drives `HopHandshake` and passes each `write_message` result here.
    HopControl {
        /// Link whose peer should receive the handshake message.
        link: LinkId,
        /// Opaque Noise message, bounded by framing.
        message: &'a [u8],
    },
    /// The host installed a verified `HopTransport` for this link (MSH-26).
    ///
    /// Until this input arrives the adapter must not seal Data frames, even
    /// when both hellos advertised the cap. Only a negotiated link can be
    /// activated, so a host cannot turn encryption on for an unaware peer.
    HopReady {
        /// Link whose session is ready.
        link: LinkId,
    },
    /// Originate a packet. This does not encrypt or deliver its payload.
    Submit {
        /// Borrowed only for this signing call; the engine retains no keys.
        identity: &'a Identity,
        /// Packet fields; origin and ID are stamped by signing.
        header: Header,
        /// Opaque payload, retained by the caller even on error.
        payload: &'a [u8],
        /// A selected neighbour, or all current neighbours.
        via: Option<LinkId>,
    },
    /// Originate one latest-wins Telemetry update (MSH-22).
    ///
    /// The engine frames the opaque payload with `kind` and a monotonic
    /// `seq`, signs it with the existing Telemetry class and returns an
    /// advisory for NET-21 coalescing. Unlike low-level [`Self::Submit`],
    /// this path applies the per-origin throttle and freshness policy.
    SubmitTelemetry {
        /// Borrowed only for this signing call; the engine retains no keys.
        identity: &'a Identity,
        /// Opaque latest-wins stream tag; the mesh does not interpret it.
        kind: crate::telemetry::TelemetryKind,
        /// Sender-monotonic sequence; a relay drops anything not newer.
        seq: u64,
        /// Opaque application bytes, framed unchanged behind the kind/seq.
        payload: &'a [u8],
        /// A selected neighbour, or all current neighbours.
        via: Option<LinkId>,
    },
    /// Declares a local public-channel subscription by name.
    ///
    /// Subscription is a host/UI concern: relays forward channel packets
    /// without ever receiving one of these inputs. The name is bounded by
    /// `MeshConfig::channels` and copied only into that local registry.
    ChannelSubscribe {
        /// Channel name, opaque to the mesh except for id derivation.
        name: &'a [u8],
    },
    /// Removes a local public-channel subscription by name.
    ChannelUnsubscribe {
        /// Channel name previously passed to [`Self::ChannelSubscribe`].
        name: &'a [u8],
    },
}

/// Actions for the host. The MSH-08 baseline emits `Send` relays;
/// MSH-09 authenticates every `Deliver`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MeshOutput {
    /// Queue bytes on one link.
    Send {
        /// Destination link.
        link: LinkId,
        /// Scheduling channel.
        channel: Channel,
        /// Complete encoded packet.
        payload: Vec<u8>,
    },
    /// Queue bytes on every up link.
    Broadcast {
        /// Scheduling channel.
        channel: Channel,
        /// Complete encoded packet.
        payload: Vec<u8>,
    },
    /// Queue one Telemetry update on one link under a NET-21 coalesce key.
    ///
    /// The advisory is a bounded policy statement, not a radio command: the
    /// adapter hands it to aoNetwork's real send-queue options.
    TelemetrySend {
        /// Destination link.
        link: LinkId,
        /// Always [`Channel::Telemetry`].
        channel: Channel,
        /// Complete encoded packet.
        payload: Vec<u8>,
        /// Coalescing key, freshness and hop policy for this update.
        advisory: TelemetryAdvisory,
    },
    /// Queue one Telemetry update on every up link under one coalesce key.
    TelemetryBroadcast {
        /// Always [`Channel::Telemetry`].
        channel: Channel,
        /// Complete encoded packet.
        payload: Vec<u8>,
        /// Coalescing key, freshness and hop policy for this update.
        advisory: TelemetryAdvisory,
    },
    /// Release a refused or penalised neighbour through the network facade.
    /// A budget penalty uses `DisconnectReason::AbuseDetected`; aoNetwork
    /// owns any later blacklist decision.
    Release {
        /// Link to close.
        link: LinkId,
        /// Local closing reason.
        reason: DisconnectReason,
    },
    /// A local delivery authenticated by MSH-09: the payload opened
    /// against the local identity, the seal's authenticated sender
    /// matched to `origin`, the origin signature verified and the
    /// replay guard accepted. `payload` is the opened plaintext;
    /// `header` is as received, so its `payload_len` counts the sealed
    /// wire payload, not this plaintext's length.
    Deliver {
        /// Packet header, as received.
        header: Header,
        /// The opened application payload.
        payload: Vec<u8>,
    },
    /// A signed public-channel Broadcast accepted for a local subscriber.
    ///
    /// The origin signature was checked with the key from the sender's
    /// verified hello, and the recipient's replay guard accepted the id.
    /// Relays never emit this: only a node with a local subscription does.
    ChannelDeliver {
        /// The channel the message was addressed to.
        channel_id: ChannelId,
        /// Packet header, as received.
        header: Header,
        /// Opaque application bytes from the envelope, unmodified.
        payload: Vec<u8>,
    },
    /// Replace the introduction used by new links.
    SetHello {
        /// Rotating local tag.
        tag: LocalTag,
        /// Opaque mesh introduction.
        app_hello: AppHello,
    },
    /// Advise aoNetwork to dial `peer` sooner (MSH-25).
    ///
    /// This is advisory only: it changes candidate ordering and skips
    /// aoNetwork's initiation delay, never its admission floor or degree cap.
    SetLinkHint {
        /// Opaque radio peer the advice refers to.
        peer: PeerKey,
        /// Preference to install.
        preference: LinkHintPreference,
    },
    /// Withdraw advice for `peer` (MSH-25), restoring aoNetwork's ordinary
    /// candidate ordering.
    ClearLinkHint {
        /// Opaque radio peer whose advice is withdrawn.
        peer: PeerKey,
    },
    /// Replace mesh-owned beacon fields.
    SetBeacon {
        /// Discovery hint.
        hint: [u8; 8],
        /// Store digest.
        digest: [u8; 4],
        /// Advertisement flags.
        flags: BeaconFlags,
    },
    /// Ask the host to resolve short ids to encoded store packets.
    /// This is a host action, not a network send.
    SyncNeed {
        /// The contact's link.
        link: LinkId,
        /// Prefixes the peer is missing.
        prefixes: Vec<[u8; SHORT_ID_BYTES]>,
    },
    /// An item from a peer or a local submission, ready for the host to
    /// insert in its store. The engine checked bounds and the content
    /// address, not the origin signature: final authenticity remains the
    /// store owner's job. Locally submitted Direct items appear here too,
    /// so the host can persist the same metadata the spray policy uses.
    SyncItem {
        /// Full content address parsed from the packet.
        id: MessageId,
        /// Complete encoded mesh packet.
        wire: Vec<u8>,
        /// Remaining spray copies to record with the item. Non-spray items
        /// and peers without the spray capability use one.
        copies_left: u8,
    },
    /// End an MSH-14 contact. The adapter uses aoNetwork's `release`, which
    /// only closes opportunistic links and leaves stable ones alone.
    ReleaseOpportunistic {
        /// Link to release.
        link: LinkId,
    },
    /// Remove a delivered message from the host store (MSH-17). The engine
    /// owns immunity policy, but the host owns the bytes.
    Purge {
        /// Content address whose copies are no longer needed.
        id: MessageId,
    },
    /// An authenticated delivery receipt reached its sender (MSH-17). The
    /// host maps `origin` to its own identity to move sender status to
    /// Delivered; the engine deliberately holds no key or user state.
    Delivered {
        /// The acknowledged message.
        id: MessageId,
        /// Original sender from the acknowledged packet.
        origin: [u8; 16],
        /// Authenticated destination that issued the receipt.
        by: [u8; 16],
    },
    /// Ask the host to fetch an identity card it does not yet know (MSH-19).
    /// This is a host action, not a network send; the engine emits it once per
    /// node and card hash and never interprets the card.
    CardFetch {
        /// Node whose announcement advertised the unknown card.
        node_id: [u8; 16],
        /// Opaque card hash to resolve.
        card_hash: [u8; 8],
    },
    /// Coalesced directory changes for the UI (MSH-20). The entries carry
    /// only ids and kinds; the UI queries the directory for details.
    DirectoryChanged {
        /// Bounded, ordered change stream from this input.
        changes: Vec<DirectoryChange>,
    },
}

/// Submission failure; no packet is emitted on error.
#[derive(Debug)]
pub enum MeshError {
    /// Invalid payload length or packet size.
    Packet(PacketError),
    /// Identity-layer signing failure.
    Signing(IdentError),
    /// The selected link has not been admitted to the neighbour table.
    UnknownLink(LinkId),
    /// A locally generated receipt could not be signed or encoded.
    Receipt(ReceiptError),
    /// Presence configuration or local announcement signing failed.
    Presence(PresenceError),
    /// A directory observation violated its configured bounds.
    Directory(DirectoryError),
    /// A Telemetry policy or framing failure; no packet is emitted.
    Telemetry(crate::telemetry::TelemetryError),
    /// A channel name, envelope or budget limit was rejected (MSH-23).
    Channel(ChannelError),
    /// A hop Control frame exceeded the bounded framing rules (MSH-26).
    Hop(HopFrameError),
}
impl core::fmt::Display for MeshError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Packet(e) => write!(f, "invalid submission: {e}"),
            Self::Signing(e) => write!(f, "signing failed: {e}"),
            Self::UnknownLink(link) => write!(f, "unknown submission link: {link:?}"),
            Self::Receipt(error) => write!(f, "receipt failed: {error}"),
            Self::Presence(error) => write!(f, "presence failed: {error}"),
            Self::Directory(error) => write!(f, "directory observation failed: {error}"),
            Self::Telemetry(error) => write!(f, "telemetry rejected: {error}"),
            Self::Channel(error) => write!(f, "channel rejected: {error}"),
            Self::Hop(error) => write!(f, "hop framing rejected: {error}"),
        }
    }
}
impl std::error::Error for MeshError {}

/// Deterministic engine state. No I/O, runtime, clock reads or retained keys.
///
/// State is bounded by configuration: `max_neighbors` neighbour entries,
/// one forwarding dedupe cache at `SeenConfig::default()`'s documented
/// bounds (ADR-0003), and the replay guard at `MeshConfig::replay`'s
/// window times senders (65536 message ids at the default, about
/// 1.5 MiB only if every slot holds one), and at most
/// `MeshConfig::suppression.max_entries` pending floods (MSH-11), and
/// `MeshConfig::directory.capacity` nodes plus
/// `MeshConfig::directory.max_change_events` UI events (MSH-20).
pub struct MeshEngine<R: RngCore> {
    clock_restore_ready: bool,
    rng: R,
    config: MeshConfig,
    neighbors: NeighborTable,
    seen: SeenCache,
    replay: ReplayGuard,
    budgets: BudgetTracker,
    suppression: SuppressionTable,
    beacon: BeaconTracker,
    sync: SyncTracker,
    spray: crate::spray::SprayTracker,
    receipt: crate::receipt::ReceiptTracker,
    presence: PresenceTracker,
    directory: NodeDirectory,
    hints: RouteHintTable,
    link_hints: LinkHintTable,
    hop: HopTracker,
    telemetry: TelemetryTracker,
    channels: ChannelRules,
}
impl<R: RngCore> MeshEngine<R> {
    /// Creates an engine with the default limits (`MeshConfig::default`).
    pub fn new(rng: R) -> Self {
        Self::with_config(rng, MeshConfig::default())
    }
    /// Creates an engine with explicit limits.
    pub fn with_config(rng: R, mut config: MeshConfig) -> Self {
        // One neighbour bound owns both tables; a mismatch would let budget
        // state outlive its link or refuse honest links silently.
        config.budgets.max_neighbors = config.max_neighbors;
        // One hop limit owns both the class table and the advisory; a
        // mismatch would advertise a radius the relay path does not use.
        config.telemetry.hop_limit = config
            .telemetry
            .hop_limit
            .min(config.suppression.telemetry_ttl);
        let budgets = BudgetTracker::new(config.budgets);
        Self {
            clock_restore_ready: true,
            rng,
            config,
            neighbors: NeighborTable::new(config.max_neighbors),
            seen: SeenCache::new(config.seen),
            replay: ReplayGuard::new(config.replay),
            budgets,
            suppression: SuppressionTable::new(config.suppression),
            beacon: BeaconTracker::new(config.summary),
            sync: SyncTracker::new(config.sync),
            spray: crate::spray::SprayTracker::new(config.spray),
            receipt: crate::receipt::ReceiptTracker::new(config.receipt),
            presence: PresenceTracker::new(config.presence),
            directory: NodeDirectory::new(config.directory),
            hints: RouteHintTable::new(config.route_hint),
            link_hints: LinkHintTable::new(config.link_hints),
            hop: HopTracker::new(config.max_neighbors),
            telemetry: TelemetryTracker::new(config.telemetry),
            channels: ChannelRules::new(config.channels),
        }
    }
    /// Read-only bookkeeping, not a list of authenticated identities.
    pub fn neighbors(&self) -> &NeighborTable {
        &self.neighbors
    }
    /// Read-only relay budget and penalty state (MSH-10).
    pub fn budgets(&self) -> &BudgetTracker {
        &self.budgets
    }
    /// Read-only hop negotiation state (MSH-26). It holds link ids only;
    /// the host owns the handshake and all session keys.
    #[must_use]
    pub fn hop(&self) -> &HopTracker {
        &self.hop
    }
    /// Whether both ends advertised hop encryption on `link` (MSH-26).
    #[must_use]
    pub fn hop_negotiated(&self, link: LinkId) -> bool {
        self.hop.is_negotiated(link)
    }
    /// Whether the host installed a session and Data must be sealed (MSH-26).
    #[must_use]
    pub fn hop_active(&self, link: LinkId) -> bool {
        self.hop.is_active(link)
    }
    /// Verified neighbour and signed card-hash pin for a negotiated hop link
    /// (MSH-26). The host uses this to select its out-of-band card; no key
    /// material is exposed.
    #[must_use]
    pub fn hop_peer(&self, link: LinkId) -> Option<(ao_idents::NodeId, [u8; 8])> {
        self.hop.peer(link)
    }
    /// Capabilities this engine negotiates. Hop is included only when the
    /// host opted in and signed its hello with the same bit (MSH-26).
    fn local_caps(&self) -> u32 {
        if self.config.hop_enabled {
            crate::hello::SUPPORTED_CAPS
        } else {
            crate::hello::CAPS
        }
    }

    /// The Data outputs a fresh link normally starts with (MSH-14/17). On a
    /// hop link these are deferred to `HopReady` so none can leave in
    /// cleartext before the host installs its session (MSH-26).
    fn post_link_outputs(
        &mut self,
        now: u64,
        link: LinkId,
        caps: u32,
        remote_digest: [u8; 4],
    ) -> Vec<MeshOutput> {
        let mut outputs = Vec::new();
        for payload in self.receipt.pending_for(link) {
            outputs.push(MeshOutput::Send {
                link,
                channel: Channel::Message,
                payload,
            });
        }
        let spray = self.config.spray.enabled && caps & crate::hello::CAP_SPRAY_V1 != 0;
        let actions = if caps & crate::hello::CAP_SYNC_V2 != 0 {
            self.sync.start_v2(now, link, remote_digest, spray)
        } else if caps & crate::hello::CAP_SYNC_V1 != 0 {
            self.sync.start(now, link, remote_digest, spray)
        } else {
            Vec::new()
        };
        outputs.extend(self.apply_sync_actions(now, actions));
        outputs
    }
    /// Digest currently advertised in the beacon, if one was published.
    pub fn published_store_digest(&self) -> Option<[u8; 4]> {
        self.beacon.published_digest()
    }
    /// Read-only anti-entropy state (MSH-14).
    pub fn sync(&self) -> &SyncTracker {
        &self.sync
    }
    /// Read-only mesh-wide node directory (MSH-20). Queries take the local
    /// time explicitly and never mutate this state.
    pub fn directory(&self) -> &NodeDirectory {
        &self.directory
    }
    /// Remaining MSH-16 copies for one id, or one when spray is inactive.
    ///
    /// The host persists this with the packet bytes so later sync offers
    /// carry the same ticket the relay policy holds.
    pub fn spray_copies_left(&self, id: MessageId) -> u8 {
        self.spray.copies_left(id)
    }
    /// Read-only learned presence state (MSH-19), for host diagnostics.
    pub fn presence(&self) -> &PresenceTracker {
        &self.presence
    }
    /// Read-only reverse-path hint state (MSH-21).
    ///
    /// The simulator uses this to report latency for messages with a fresh
    /// path; hosts may inspect it for diagnostics. No hint is a wire field.
    pub fn route_hints(&self) -> &RouteHintTable {
        &self.hints
    }
    /// Read-only advisory link-hint state (MSH-25).
    ///
    /// The simulator and hosts use this to verify that advice stayed within
    /// its configured bound. Advice is never a radio command: aoNetwork owns
    /// link formation and the degree cap.
    #[must_use]
    pub fn link_hints(&self) -> &LinkHintTable {
        &self.link_hints
    }
    /// The Telemetry policy a host must mirror in NET-21 (MSH-22).
    ///
    /// The returned reference is the same config that produced every
    /// [`MeshOutput::TelemetrySend`] advisory, so a host configuring a send
    /// queue before any update exists reads one source of truth.
    pub fn telemetry_policy(&self) -> &crate::telemetry::TelemetryConfig {
        self.telemetry.config()
    }
    /// Read-only latest-wins state, for diagnostics and resource-bound tests.
    pub fn telemetry(&self) -> &TelemetryTracker {
        &self.telemetry
    }
    /// Read-only local channel registry (MSH-23). Relays keep it empty.
    #[must_use]
    pub fn channels(&self) -> &ChannelRules {
        &self.channels
    }

    /// Plain-data diagnostics view (MSH-30).
    ///
    /// Reading a snapshot never mutates state or allocates: cumulative values
    /// come from the counters owned by the decision modules, and gauges are
    /// derived from state the engine already holds. The host may call this on
    /// a debug screen and map the fields into APP-15's diagnostics bundle;
    /// no packet content, key or personal data is exposed. `version` selects
    /// the field layout.
    #[must_use]
    pub fn observability_snapshot(&self) -> MeshSnapshot {
        let mut penalty_total = 0u64;
        let mut penalty_max = 0u32;
        let mut penalised_neighbours = 0u32;
        for neighbor in self.neighbors.iter() {
            let penalty = self.budgets.penalty(neighbor.link);
            penalty_total = penalty_total.saturating_add(u64::from(penalty));
            penalty_max = penalty_max.max(penalty);
            if penalty > 0 {
                penalised_neighbours = penalised_neighbours.saturating_add(1);
            }
        }
        let (sync_bytes_sent, sync_bytes_received) = self.sync.byte_totals();
        MeshSnapshot {
            version: MESH_SNAPSHOT_VERSION,
            duplicate_packets: self.seen.duplicates(),
            suppressed_relays: self.suppression.suppressed_relays(),
            store_entries: saturating_u32(self.sync.local_len()),
            sync_bytes_sent,
            sync_bytes_received,
            neighbour_penalty_events: self.budgets.penalty_events(),
            neighbour_penalty_total: penalty_total,
            neighbour_penalty_max: penalty_max,
            penalised_neighbours,
            seen_records: saturating_u32(self.seen.len()),
            suppression_pending: saturating_u32(self.suppression.len()),
        }
    }
    /// Whether an acknowledged id is immune from store re-sync (MSH-17).
    ///
    /// Hosts can read this before re-offering a stored copy; it is policy
    /// state, not message content or a key.
    #[must_use]
    pub fn is_immune(&self, id: MessageId) -> bool {
        self.receipt.is_immune(id)
    }
    /// Processes one input at caller-supplied milliseconds.
    ///
    /// LinkUp decodes, verifies and negotiates the peer's `MeshHello`
    /// (MSH-07): a verified neighbour records its `NodeId`, a rejected
    /// introduction still counts traffic but records none, and only a
    /// full table releases the link. Data is structurally validated and
    /// counted, then the MSH-08 rules apply: a fresh Direct packet for
    /// `identity.node_id()` is handed to MSH-09's pipeline, which
    /// opens the seal against `identity`, binds the seal's
    /// authenticated sender to `origin`, verifies the origin signature
    /// and runs the replay guard before a `Deliver` is emitted; a
    /// refusal counts against the link as `rejected_packets` and
    /// produces nothing. Any other fresh Direct packet relays to
    /// verified neighbours but the sender with `ttl` decremented.
    /// MSH-10 gates onward relays on both the origin and sender token
    /// buckets and releases a neighbour whose penalty crosses its
    /// threshold; local delivery is never suppressed by a budget.
    /// Broadcast and Presence use MSH-11's seeded assessment delay and
    /// cancel their relay when enough distinct neighbours carried the
    /// same content address. `StoreSummary` canonicalises host-provided
    /// ids and emits a debounced `SetBeacon` when the digest changes
    /// (MSH-13). Submission errors are typed and the caller still owns
    /// the input bytes.
    pub fn handle(&mut self, now: u64, input: MeshInput<'_>) -> Result<Vec<MeshOutput>, MeshError> {
        self.clock_restore_ready = false;
        match input {
            MeshInput::ObserveLinkHint { observation } => {
                let mut outputs = Vec::new();
                for (peer, change) in self.link_hints.observe(
                    now,
                    observation,
                    &self.directory,
                    &self.neighbors,
                    &self.budgets,
                ) {
                    outputs.extend(Self::link_hint_outputs(peer, change));
                }
                Ok(outputs)
            }
            MeshInput::ObserveNode { observation } => {
                let node = observation.node;
                let via = observation.via;
                let hops = observation.hops;
                let seq = observation.seq;
                self.directory
                    .observe(now, observation)
                    .map_err(MeshError::Directory)?;
                // The directory ignores an older sequence. Only a fact it
                // actually retained may mint or refresh a reverse-path hint.
                if self
                    .directory
                    .get(now, node)
                    .is_some_and(|entry| entry.seq == seq && entry.via == via && entry.hops == hops)
                {
                    self.observe_hint(now, node, via, hops, seq);
                }
                Ok(self.take_directory_changes())
            }
            MeshInput::StoreSummary { ids } => {
                let digest = StoreSummary::from_ids(ids).digest();
                self.sync.set_local(ids);
                Ok(self
                    .beacon
                    .observe(now, digest)
                    .map(|digest| MeshOutput::SetBeacon {
                        hint: self.config.summary.beacon_hint,
                        digest,
                        flags: BeaconFlags {
                            accepting: true,
                            relay_willing: true,
                            low_battery: false,
                        },
                    })
                    .into_iter()
                    .collect())
            }
            MeshInput::SyncItems { link, items } => {
                if !self.neighbors.contains(link) {
                    return Ok(Vec::new());
                }
                let actions = self.sync.on_offers(link, items);
                Ok(self.apply_sync_actions(now, actions))
            }
            MeshInput::HopControl { link, message } => {
                if !self.hop.is_negotiated(link) {
                    return Ok(Vec::new());
                }
                let payload = encode_control(message).map_err(MeshError::Hop)?;
                Ok(vec![MeshOutput::Send {
                    link,
                    channel: Channel::Control,
                    payload,
                }])
            }
            MeshInput::HopReady { link } => {
                // A host cannot activate a link whose signed hello did not
                // advertise the cap, so it cannot encrypt for an unaware peer.
                Ok(match self.hop.activate(link) {
                    Some((caps, remote_digest)) => {
                        self.post_link_outputs(now, link, caps, remote_digest)
                    }
                    None => Vec::new(),
                })
            }
            MeshInput::Tick {
                identity,
                card_hash,
            } => {
                let mut outputs = self.drain_due(now);
                self.receipt.expire(now);
                self.hints.expire(now);
                self.telemetry.expire(now);
                // Penalties decay and directory facts expire on ticks; both
                // can change the advisory preference of an existing peer.
                for (peer, advice) in
                    self.link_hints
                        .refresh(now, &self.directory, &self.neighbors, &self.budgets)
                {
                    outputs.extend(Self::link_hint_outputs(peer, advice));
                }
                let actions = self.sync.expire(now);
                outputs.extend(self.apply_sync_actions(now, actions));
                outputs.extend(self.presence_tick(now, identity, card_hash)?);
                // Directory staleness is local and relative: a Tick reclaims
                // entries even when no new announcement arrives, and the UI
                // learns about each removal at the scheduled instant.
                self.directory.expire(now);
                outputs.extend(self.take_directory_changes());
                Ok(outputs)
            }
            MeshInput::KnownCards { hashes } => {
                self.presence
                    .set_known_cards(hashes)
                    .map_err(MeshError::Presence)?;
                Ok(Vec::new())
            }
            MeshInput::LinkUp { link, remote_hello } => {
                if self.neighbors.contains(link) {
                    // A repeated LinkUp keeps the existing entry, counters
                    // and identity; it cannot downgrade or reset them.
                    return Ok(Vec::new());
                }
                if !self.neighbors.has_room() {
                    return Ok(vec![MeshOutput::Release {
                        link,
                        reason: DisconnectReason::Closed,
                    }]);
                }
                // A failed introduction is dropped, not penalised here:
                // the entry observes the peer and MSH-10's penalties
                // decide its fate (ADR-0004).
                let hello = crate::hello::verified_hello(remote_hello.app_hello.as_bytes()).ok();
                let node_id = hello.map(|hello| hello.node_id);
                // The same verified introduction proves this signing key, so
                // a channel recipient can authenticate a Broadcast without
                // holding an identity or querying a directory.
                let signing_pk = hello.map(|hello| hello.signing_pk);
                self.neighbors
                    .insert(now, link, remote_hello, node_id, signing_pk);
                let caps = hello.and_then(|hello| {
                    hello
                        .negotiate(crate::hello::PROTO, self.local_caps())
                        .ok()
                        .map(|(_, caps)| caps)
                });
                let Some(caps) = caps else {
                    return Ok(Vec::new());
                };
                let hop = caps & crate::hello::CAP_HOP_V1 != 0;
                let remote_digest = hello.map_or([0; 4], |hello| hello.store_digest);
                if hop {
                    if let (Some(peer), Some(hello)) = (node_id, hello) {
                        self.hop
                            .negotiate(link, peer, hello.card_hash, caps, hello.store_digest);
                    }
                }
                self.spray.set_caps(link, caps);
                self.receipt.set_caps(link, caps);
                self.presence.set_caps(link, caps);
                // On a hop link every Data frame must wait for the host's
                // session. Sending sync or receipts at LinkUp would leak
                // their encoded headers before the handshake completes;
                // HopReady replays the same policy in link order.
                if hop {
                    Ok(Vec::new())
                } else {
                    Ok(self.post_link_outputs(now, link, caps, remote_digest))
                }
            }
            MeshInput::LinkDown { link, .. } => {
                self.neighbors.remove(link);
                self.budgets.link_down(link);
                self.sync.link_down(link);
                self.spray.link_down(link);
                self.receipt.link_down(link);
                self.presence.link_down(link);
                self.hints.link_down(link);
                self.hop.link_down(link);
                Ok(Vec::new())
            }
            MeshInput::Data {
                link,
                channel,
                identity,
                payload,
            } => {
                // An untracked link has no counters or penalty state; do not
                // let arbitrary link ids create either.
                if !self.neighbors.contains(link) {
                    return Ok(Vec::new());
                }
                if channel == Channel::Bulk
                    && payload.first() == Some(&crate::sync::SYNC_MAGIC)
                    && payload.get(1) == Some(&crate::sync::SYNC_V2_VERSION)
                {
                    match SyncFrameV2::decode(payload) {
                        Ok(Some(frame)) => {
                            let verified = self
                                .neighbors
                                .get(link)
                                .is_some_and(|neighbor| neighbor.node_id.is_some());
                            if !verified {
                                return Ok(Self::release_if_penalised(
                                    link,
                                    self.budgets.penalize(
                                        now,
                                        link,
                                        self.config.budgets.penalty_unverified,
                                    ),
                                ));
                            }
                            // A valid frame on a verified link is sync traffic;
                            // malformed or unverified frames are penalties.
                            self.sync.note_received_bytes(payload.len());
                            let actions = self.sync.on_v2_frame(now, link, frame, payload.len());
                            return Ok(self.apply_sync_actions(now, actions));
                        }
                        Ok(None) => {}
                        Err(_) => {
                            self.neighbors.reject(link);
                            return Ok(Self::release_if_penalised(
                                link,
                                self.budgets.penalize(
                                    now,
                                    link,
                                    self.config.budgets.penalty_invalid,
                                ),
                            ));
                        }
                    }
                }
                if channel == Channel::Bulk {
                    match SyncFrame::decode(payload) {
                        Ok(Some(frame)) => {
                            let verified = self
                                .neighbors
                                .get(link)
                                .is_some_and(|neighbor| neighbor.node_id.is_some());
                            if !verified {
                                return Ok(Self::release_if_penalised(
                                    link,
                                    self.budgets.penalize(
                                        now,
                                        link,
                                        self.config.budgets.penalty_unverified,
                                    ),
                                ));
                            }
                            self.sync.note_received_bytes(payload.len());
                            let actions = self.sync.on_frame(now, link, frame);
                            return Ok(self.apply_sync_actions(now, actions));
                        }
                        Ok(None) => {}
                        Err(_) => {
                            self.neighbors.reject(link);
                            return Ok(Self::release_if_penalised(
                                link,
                                self.budgets.penalize(
                                    now,
                                    link,
                                    self.config.budgets.penalty_invalid,
                                ),
                            ));
                        }
                    }
                }
                // A receipt envelope is self-authenticating and cap-gated.
                // It is parsed header-first, before any packet decode, and a
                // stray or malformed one is attributable to the sending link.
                if payload.first() == Some(&crate::receipt::RECEIPT_MAGIC) {
                    if !self.receipt.supports(link) {
                        self.neighbors.reject(link);
                        return Ok(Self::release_if_penalised(
                            link,
                            self.budgets
                                .penalize(now, link, self.config.budgets.penalty_invalid),
                        ));
                    }
                    let verified = self
                        .neighbors
                        .get(link)
                        .is_some_and(|neighbor| neighbor.node_id.is_some());
                    if !verified {
                        return Ok(Self::release_if_penalised(
                            link,
                            self.budgets.penalize(
                                now,
                                link,
                                self.config.budgets.penalty_unverified,
                            ),
                        ));
                    }
                    return Ok(match crate::receipt::decode_frame(payload) {
                        Ok(Some(frame)) => {
                            self.neighbors.received(now, link, payload.len(), true);
                            self.on_receipt(now, link, identity, frame)
                        }
                        Ok(None) => Vec::new(),
                        Err(_) => {
                            self.neighbors.reject(link);
                            Self::release_if_penalised(
                                link,
                                self.budgets.penalize(
                                    now,
                                    link,
                                    self.config.budgets.penalty_invalid,
                                ),
                            )
                        }
                    });
                }
                // A spray envelope is parsed header-first and never allocates
                // its inner packet. It is only meaningful on a link that
                // negotiated the capability, so a stray envelope is an
                // attributable protocol error.
                let (packet_bytes, incoming_copies) = match crate::spray::decode_frame(payload) {
                    Ok(Some((copies, inner))) => {
                        if !self.spray.supports(link) {
                            self.neighbors.reject(link);
                            return Ok(Self::release_if_penalised(
                                link,
                                self.budgets.penalize(
                                    now,
                                    link,
                                    self.config.budgets.penalty_invalid,
                                ),
                            ));
                        }
                        (inner, Some(copies))
                    }
                    Ok(None) => (payload, None),
                    Err(_) => {
                        self.neighbors.reject(link);
                        return Ok(Self::release_if_penalised(
                            link,
                            self.budgets
                                .penalize(now, link, self.config.budgets.penalty_invalid),
                        ));
                    }
                };
                // Packet::decode parses the bounded header before inspecting or
                // borrowing the payload, and allocates nothing on either path.
                let packet = Packet::decode(packet_bytes);
                self.neighbors
                    .received(now, link, payload.len(), packet.is_ok());
                let (sender_id, sender_signing_pk) =
                    self.neighbors.get(link).map_or((None, None), |neighbor| {
                        (neighbor.node_id, neighbor.signing_pk)
                    });
                let verified = sender_id.is_some();
                let packet = match packet {
                    Ok(packet) => packet,
                    Err(_) => {
                        return Ok(Self::release_if_penalised(
                            link,
                            self.budgets
                                .penalize(now, link, self.config.budgets.penalty_invalid),
                        ));
                    }
                };
                // Admission through LinkUp is the gate, and ADR-0004 adds
                // that an entry whose hello failed verification may not
                // forward or deliver on that peer's behalf: its counters
                // observe, nothing more.
                if !verified {
                    return Ok(Self::release_if_penalised(
                        link,
                        self.budgets
                            .penalize(now, link, self.config.budgets.penalty_unverified),
                    ));
                }
                if self.budgets.is_released(link) {
                    return Ok(Vec::new());
                }
                // Telemetry is ambient state, not a stored message. Its
                // policy runs before the relay budget so superseded, stale
                // or throttled updates cost neither a token nor a state
                // change beyond the signed packet's traffic counters.
                if packet.header.class == PacketClass::Telemetry {
                    return Ok(self.on_telemetry_data(now, link, packet));
                }
                // Complete timers that expired while this packet was in
                // flight before adding a new sighting for the same id. Done
                // before early returns so an expired relay is never lost.
                let mut outputs = self.drain_due(now);
                // A channel envelope is recognised only inside Broadcast.
                // The magic byte is reserved, so a truncated or wrong-version
                // envelope is an attributable protocol error, not ordinary
                // Broadcast data. Decoding borrows; it allocates no payload.
                let envelope = match parse_channel_envelope(packet.header.class, packet.payload) {
                    Ok(envelope) => envelope,
                    Err(_) => {
                        self.neighbors.reject(link);
                        return Ok(Self::release_if_penalised(
                            link,
                            self.budgets
                                .penalize(now, link, self.config.budgets.penalty_invalid),
                        ));
                    }
                };
                // Only the origin's own hello proves the key that signed this
                // envelope. A relayed copy cannot be authenticated locally
                // without a directory lookup, so it is forwarded as ordinary
                // Broadcast but not delivered to this node's subscriber.
                if let Some(envelope) = envelope {
                    let origin = NodeId::from_bytes(packet.header.origin);
                    if self.channels.contains(envelope.channel_id) && sender_id == Some(origin) {
                        match sender_signing_pk {
                            Some(signing_pk)
                                if verify_origin_with_signing_pk(
                                    &signing_pk,
                                    &packet.header,
                                    packet.payload,
                                    &packet.signature,
                                )
                                .is_ok() =>
                            {
                                if self
                                    .replay
                                    .accept(
                                        origin,
                                        packet.header.msg_id.as_bytes(),
                                        packet.header.created_ms,
                                        now,
                                    )
                                    .is_ok()
                                {
                                    outputs.push(MeshOutput::ChannelDeliver {
                                        channel_id: envelope.channel_id,
                                        header: packet.header,
                                        payload: envelope.payload.to_vec(),
                                    });
                                }
                            }
                            _ => {
                                self.neighbors.reject(link);
                                return Ok(Self::release_if_penalised(
                                    link,
                                    self.budgets.penalize(
                                        now,
                                        link,
                                        self.config.budgets.penalty_invalid,
                                    ),
                                ));
                            }
                        }
                    }
                }
                // Both the claimed origin and the sending link pay for a
                // relay. A local delivery still happens; only its onward
                // copies are withheld when either bucket is empty.
                let origin = NodeId::from_bytes(packet.header.origin);
                let outcome =
                    self.budgets
                        .admit(now, link, origin, packet.header.class, payload.len());
                // An exhausted origin blames that origin, not the neighbour
                // that happened to carry the packet. Disconnecting such a
                // link partitions honest traffic; only a saturated sending
                // link is locally attributable and feeds its penalty.
                let release = match outcome {
                    BudgetOutcome::Admitted | BudgetOutcome::OriginDenied => false,
                    BudgetOutcome::NeighborDenied => {
                        self.budgets
                            .penalize(now, link, self.config.budgets.penalty_excess)
                    }
                };
                if release {
                    outputs.push(MeshOutput::Release {
                        link,
                        reason: DisconnectReason::AbuseDetected,
                    });
                    return Ok(outputs);
                }
                // A hot channel gets its own bucket under a domain-separated
                // synthetic key. This is the same bounded MSH-10 table, not a
                // second limiter; a refusal withholds only this relay.
                if let Some(envelope) = envelope {
                    if self.budgets.admit_channel(
                        now,
                        channel_budget_origin(envelope.channel_id),
                        packet.header.class,
                        payload.len(),
                    ) != BudgetOutcome::Admitted
                    {
                        return Ok(outputs);
                    }
                }
                let wire = packet.encode();
                let msg_id = packet.header.msg_id;
                let destination = packet.header.dst.unwrap_or([0; 16]);
                let lifetime_s = packet.header.lifetime_s;
                match packet.header.class {
                    crate::PacketClass::Direct => {
                        match forward::on_data(identity.node_id(), &mut self.seen, now, packet) {
                            Action::Drop => {}
                            Action::Reject => {
                                // A forged content address is attributable to the
                                // link that carried it, unlike a duplicate or a
                                // packet whose ttl simply ran out.
                                self.neighbors.reject(link);
                                if self.budgets.penalize(
                                    now,
                                    link,
                                    self.config.budgets.penalty_invalid,
                                ) {
                                    return Ok(Self::release_if_penalised(link, true));
                                }
                            }
                            Action::Deliver {
                                header,
                                signature,
                                payload,
                            } => match deliver::open_delivery(
                                identity,
                                &mut self.replay,
                                now,
                                &header,
                                &signature,
                                &payload,
                            ) {
                                Ok(plaintext) => {
                                    // Recording only after acceptance: a forgery
                                    // that fails the pipeline must not consume
                                    // the dedupe key the honest copy needs.
                                    // MSH-28: no assertion here. The peek
                                    // was fresh and nothing re-entered the
                                    // engine, so the recording is a no-op
                                    // on the happy path; an unexpected
                                    // duplicate must not turn hostile input
                                    // into a debug-build panic.
                                    let _ = self.seen.check_and_insert(
                                        now,
                                        header.class,
                                        header.msg_id,
                                    );
                                    outputs.push(MeshOutput::Deliver {
                                        header,
                                        payload: plaintext,
                                    });
                                    if self.config.spray.enabled {
                                        outputs.push(MeshOutput::SyncItem {
                                            id: msg_id,
                                            wire: wire.clone(),
                                            copies_left: incoming_copies.unwrap_or(1),
                                        });
                                    }
                                    if self.config.receipt.enabled {
                                        let hash = crate::sign::payload_hash(&payload);
                                        let receipt =
                                            receipt::encode_ack(now, identity, &header, &hash)
                                                .map_err(MeshError::Receipt)?;
                                        let frame = match receipt::decode_frame(&receipt) {
                                            Ok(Some(frame)) => frame,
                                            Ok(None) | Err(_) => {
                                                return Err(MeshError::Receipt(
                                                    ReceiptError::BadAck,
                                                ));
                                            }
                                        };
                                        let _ = self.receipt.accept(now, &frame, None);
                                        self.spray.forget(msg_id);
                                        outputs.push(MeshOutput::Purge { id: msg_id });
                                        let links: Vec<LinkId> = self
                                            .neighbors
                                            .iter()
                                            .filter(|neighbor| self.receipt.supports(neighbor.link))
                                            .map(|neighbor| neighbor.link)
                                            .collect();
                                        for link in links {
                                            for payload in self.receipt.pending_for(link) {
                                                outputs.push(MeshOutput::Send {
                                                    link,
                                                    channel: Channel::Message,
                                                    payload,
                                                });
                                            }
                                        }
                                    }
                                }
                                Err(_) => {
                                    self.neighbors.reject(link);
                                    if self.budgets.penalize(
                                        now,
                                        link,
                                        self.config.budgets.penalty_invalid,
                                    ) {
                                        return Ok(Self::release_if_penalised(link, true));
                                    }
                                }
                            },
                            Action::Relay { bytes } if outcome == BudgetOutcome::Admitted => {
                                // An acknowledged id must not be forwarded or
                                // re-stored, even if an old spray copy arrives
                                // after its receipt on another contact.
                                if self.receipt.is_immune(msg_id) {
                                    return Ok(Vec::new());
                                }
                                if self.config.spray.enabled && incoming_copies.is_some() {
                                    self.spray.observe(
                                        now,
                                        msg_id,
                                        crate::PacketClass::Direct,
                                        destination,
                                        lifetime_s,
                                        incoming_copies.unwrap_or(1),
                                    );
                                    let candidates: Vec<(LinkId, [u8; 16])> = self
                                        .neighbors
                                        .iter()
                                        .filter_map(|neighbor| {
                                            neighbor
                                                .node_id
                                                .map(|id| (neighbor.link, *id.as_bytes()))
                                        })
                                        .collect();
                                    let plan = self.spray_plan(
                                        now,
                                        msg_id,
                                        Some(link),
                                        &candidates,
                                        destination,
                                    );
                                    for (next, give) in &plan {
                                        if let Some(payload) =
                                            crate::spray::encode_frame(*give, &bytes)
                                        {
                                            outputs.push(MeshOutput::Send {
                                                link: *next,
                                                channel: Channel::Message,
                                                payload,
                                            });
                                        }
                                    }
                                    outputs.extend(self.additive_hint_sends(
                                        now,
                                        Some(link),
                                        &plan,
                                        destination,
                                        &bytes,
                                    ));
                                    outputs.push(MeshOutput::SyncItem {
                                        id: msg_id,
                                        wire: wire.clone(),
                                        copies_left: self.spray.copies_left(msg_id),
                                    });
                                } else {
                                    let mut senders = BTreeSet::new();
                                    senders.insert(link);
                                    outputs.extend(self.send_to_links(bytes, &senders));
                                }
                            }
                            Action::Relay { .. } => {}
                        }
                    }
                    crate::PacketClass::Presence
                        if self.presence.supports(link)
                            && packet.payload.first() == Some(&presence::ANNOUNCE_MAGIC) =>
                    {
                        outputs.extend(self.on_presence_data(now, link, packet, outcome)?);
                    }
                    crate::PacketClass::Broadcast | crate::PacketClass::Presence => {
                        if !suppress::content_valid(&packet) {
                            self.neighbors.reject(link);
                            if self
                                .budgets
                                .penalize(now, link, self.config.budgets.penalty_invalid)
                            {
                                return Ok(Self::release_if_penalised(link, true));
                            }
                            return Ok(outputs);
                        }
                        if outcome != BudgetOutcome::Admitted {
                            return Ok(outputs);
                        }
                        let msg_id = packet.header.msg_id;
                        let class = packet.header.class;
                        if self.seen.is_duplicate(now, &msg_id) {
                            // The peek leaves the dedupe window alone, but
                            // this repeat is still a forwarding duplicate.
                            self.seen.note_duplicate();
                            return Ok(outputs);
                        }
                        let Some(relay) =
                            suppress::relay_bytes(packet, self.config.suppression.ttl(class))
                        else {
                            let _ = self.seen.check_and_insert(now, class, msg_id);
                            return Ok(outputs);
                        };
                        if !self.config.suppression.enabled {
                            let _ = self.seen.check_and_insert(now, class, msg_id);
                            let mut senders = BTreeSet::new();
                            senders.insert(link);
                            outputs.extend(self.send_to_links(relay, &senders));
                            return Ok(outputs);
                        }
                        let degree = self
                            .neighbors
                            .iter()
                            .filter(|neighbor| neighbor.node_id.is_some() && neighbor.link != link)
                            .count();
                        let threshold = self.config.suppression.copy_threshold_for(
                            class,
                            degree,
                            &mut self.rng,
                        );
                        let deadline_ms = now.saturating_add(
                            self.config
                                .suppression
                                .assessment_delay(degree, &mut self.rng),
                        );
                        match self.suppression.observe(Sighting {
                            now,
                            msg_id,
                            class,
                            sender: link,
                            threshold,
                            deadline_ms,
                            relay,
                        }) {
                            suppress::Observe::Pending => {}
                            suppress::Observe::Suppressed => {
                                let _ = self.seen.check_and_insert(now, class, msg_id);
                            }
                            suppress::Observe::RelayNow(due) => {
                                let _ = self.seen.check_and_insert(now, class, msg_id);
                                outputs.extend(self.send_to_links(due.bytes, &due.senders));
                            }
                        }
                    }
                    crate::PacketClass::Telemetry => {}
                }
                Ok(outputs)
            }
            MeshInput::SubmitTelemetry {
                identity,
                kind,
                seq,
                payload,
                via,
            } => {
                if let Some(link) = via {
                    if self.neighbors.get(link).is_none() {
                        return Err(MeshError::UnknownLink(link));
                    }
                }
                let framed =
                    TelemetryFrame::encode(kind, seq, payload).map_err(MeshError::Telemetry)?;
                // Round up: a sub-second policy window must not become a
                // zero-lifetime packet at a relay. The tracker still caps
                // freshness at the configured millisecond value.
                let lifetime_s = self.config.telemetry.expiry_ms.saturating_add(999) / 1000;
                let origin = *identity.node_id().as_bytes();
                let advisory = self
                    .telemetry
                    .admit(now, &origin, kind, seq, lifetime_s)
                    .map_err(MeshError::Telemetry)?;
                let mut header = Header {
                    class: crate::PacketClass::Telemetry,
                    dst: None,
                    msg_id: [0; 16].into(),
                    origin,
                    created_ms: now,
                    lifetime_s,
                    payload_len: framed.len() as u64,
                    ttl: self.config.telemetry.hop_limit,
                    hops: 0,
                };
                let signature =
                    sign_packet(identity, &mut header, &framed).map_err(MeshError::Signing)?;
                let bytes = Packet::new(header, signature, &framed)
                    .map_err(MeshError::Packet)?
                    .encode();
                // A looped copy must be recognised without consulting the
                // store, which never holds Telemetry.
                let _ = self.seen.check_and_insert(now, header.class, header.msg_id);
                Ok(vec![match via {
                    Some(link) => MeshOutput::TelemetrySend {
                        link,
                        channel: Channel::Telemetry,
                        payload: bytes,
                        advisory,
                    },
                    None => MeshOutput::TelemetryBroadcast {
                        channel: Channel::Telemetry,
                        payload: bytes,
                        advisory,
                    },
                }])
            }
            MeshInput::Submit {
                identity,
                mut header,
                payload,
                via,
            } => {
                if let Some(link) = via {
                    if self.neighbors.get(link).is_none() {
                        return Err(MeshError::UnknownLink(link));
                    }
                }
                // ADR-0001's per-class hop limit applies to locally
                // submitted packets as well as relays. Clamp before
                // validation and signing so the signed header is the
                // one that goes on the wire (MSH-11).
                header.ttl = header.ttl.min(self.config.suppression.ttl(header.class));
                // Reject caller mistakes before signing or allocating the wire packet.
                Packet::new(header, Signature::from_bytes([0; 64]), payload)
                    .map_err(MeshError::Packet)?;
                // A Broadcast payload carrying the reserved magic must be a
                // complete channel envelope. Validate and budget it before
                // signing so a denied submission emits no packet and consumes
                // no dedupe key.
                let channel_envelope = match parse_channel_envelope(header.class, payload) {
                    Ok(envelope) => envelope,
                    Err(error) => return Err(MeshError::Channel(error)),
                };
                if let Some(envelope) = channel_envelope {
                    let origin = NodeId::from_bytes(*identity.node_id().as_bytes());
                    if self
                        .budgets
                        .admit_origin(now, origin, header.class, payload.len())
                        != BudgetOutcome::Admitted
                    {
                        return Err(MeshError::Channel(ChannelError::BudgetDenied {
                            scope: ChannelBudgetScope::Origin,
                        }));
                    }
                    if self.budgets.admit_channel(
                        now,
                        channel_budget_origin(envelope.channel_id),
                        header.class,
                        payload.len(),
                    ) != BudgetOutcome::Admitted
                    {
                        // The channel refused a packet the origin would
                        // otherwise have paid for; restore its tokens.
                        self.budgets
                            .refund_origin(now, origin, header.class, payload.len());
                        return Err(MeshError::Channel(ChannelError::BudgetDenied {
                            scope: ChannelBudgetScope::Channel,
                        }));
                    }
                }
                let signature =
                    sign_packet(identity, &mut header, payload).map_err(MeshError::Signing)?;
                // The origin has already put this message on the air:
                // recording it like any sighting means a copy that loops
                // back is dropped instead of re-relayed, so no node ever
                // transmits the same message twice.
                let _ = self.seen.check_and_insert(now, header.class, header.msg_id);
                let channel = match header.class {
                    crate::PacketClass::Telemetry => Channel::Telemetry,
                    _ => Channel::Message,
                };
                let bytes = Packet::new(header, signature, payload)
                    .map_err(MeshError::Packet)?
                    .encode();
                if header.class == crate::PacketClass::Direct && self.config.spray.enabled {
                    self.spray.observe(
                        now,
                        header.msg_id,
                        header.class,
                        header.dst.unwrap_or([0; 16]),
                        header.lifetime_s,
                        self.config.spray.copies,
                    );
                    let candidates: Vec<(LinkId, [u8; 16])> = match via {
                        Some(link) => self
                            .neighbors
                            .get(link)
                            .and_then(|neighbor| neighbor.node_id)
                            .map(|id| vec![(link, *id.as_bytes())])
                            .unwrap_or_default(),
                        None => self
                            .neighbors
                            .iter()
                            .filter_map(|neighbor| {
                                neighbor.node_id.map(|id| (neighbor.link, *id.as_bytes()))
                            })
                            .collect(),
                    };
                    let destination = header.dst.unwrap_or([0; 16]);
                    let plan = self.spray_plan(now, header.msg_id, None, &candidates, destination);
                    let mut outputs = Vec::new();
                    for (link, give) in &plan {
                        let payload = if self.spray.supports(*link) {
                            match crate::spray::encode_frame(*give, &bytes) {
                                Some(payload) => payload,
                                None => bytes.clone(),
                            }
                        } else {
                            bytes.clone()
                        };
                        outputs.push(MeshOutput::Send {
                            link: *link,
                            channel,
                            payload,
                        });
                    }
                    outputs.extend(self.additive_hint_sends(now, None, &plan, destination, &bytes));
                    // The host submitted these bytes and already owns them;
                    // only received copies need a store event.
                    return Ok(outputs);
                }
                Ok(vec![match via {
                    Some(link) => MeshOutput::Send {
                        link,
                        channel,
                        payload: bytes,
                    },
                    None => MeshOutput::Broadcast {
                        channel,
                        payload: bytes,
                    },
                }])
            }
            MeshInput::ChannelSubscribe { name } => {
                self.channels.subscribe(name).map_err(MeshError::Channel)?;
                Ok(Vec::new())
            }
            MeshInput::ChannelUnsubscribe { name } => {
                self.channels
                    .unsubscribe(name)
                    .map_err(MeshError::Channel)?;
                Ok(Vec::new())
            }
        }
    }

    /// Emits the announcement due on this tick to links that negotiated
    /// [`crate::CAP_PRESENCE_V1`]. Signing uses the borrowed host identity;
    /// the tracker owns only the sequence number and deadline.
    fn presence_tick(
        &mut self,
        now: u64,
        identity: &Identity,
        card_hash: [u8; 8],
    ) -> Result<Vec<MeshOutput>, MeshError> {
        let Some(announcement) = self.presence.on_tick(now, card_hash, crate::hello::CAPS) else {
            return Ok(Vec::new());
        };
        let (id, payload) = presence::encode_announcement(
            now,
            identity,
            announcement,
            self.config.suppression.ttl(crate::PacketClass::Presence),
            self.config.presence.lifetime_s,
        )
        .map_err(MeshError::Presence)?;
        // Record the local send like any sighting so a looped copy is dropped.
        let _ = self
            .seen
            .check_and_insert(now, crate::PacketClass::Presence, id);
        Ok(self.send_to_capable_links(payload, &BTreeSet::new()))
    }

    /// Authenticates and gossips one announcement from a capability peer.
    /// Direct packets are checked against the neighbour's verified hello key;
    /// relayed packets are accepted only when their content address still
    /// matches the signed bytes the ingress hop checked.
    fn on_presence_data(
        &mut self,
        now: u64,
        link: LinkId,
        packet: Packet<'_>,
        outcome: BudgetOutcome,
    ) -> Result<Vec<MeshOutput>, MeshError> {
        let mut outputs = Vec::new();
        let announcement = match presence::verify_announcement(&packet) {
            Ok(announcement) => announcement,
            Err(_) => {
                self.neighbors.reject(link);
                let release = self
                    .budgets
                    .penalize(now, link, self.config.budgets.penalty_invalid);
                outputs.extend(Self::release_if_penalised(link, release));
                return Ok(outputs);
            }
        };
        let (card_fetch, accepted) = self
            .presence
            .observe(now, packet.header.origin, announcement);
        if let Some(card_hash) = card_fetch {
            outputs.push(MeshOutput::CardFetch {
                node_id: packet.header.origin,
                card_hash,
            });
        }
        if accepted {
            let via = self
                .neighbors
                .get(link)
                .and_then(|neighbor| neighbor.node_id);
            if let Some(via) = via {
                let observation = NodeObservation {
                    node: NodeId::from_bytes(packet.header.origin),
                    card_hash: announcement.card_hash,
                    caps: announcement.caps,
                    seq: announcement.seq,
                    hops: packet.header.hops,
                    via,
                    observed_at_ms: now,
                    location: &[],
                };
                self.directory
                    .observe(now, observation)
                    .map_err(MeshError::Directory)?;
                // Match the host seam: only a fact the directory retained
                // may mint or refresh a hint.
                if self
                    .directory
                    .get(now, observation.node)
                    .is_some_and(|entry| {
                        entry.seq == observation.seq
                            && entry.via == via
                            && entry.hops == observation.hops
                    })
                {
                    self.observe_hint(
                        now,
                        observation.node,
                        via,
                        observation.hops,
                        observation.seq,
                    );
                }
                outputs.extend(self.take_directory_changes());
            }
        }
        if outcome != BudgetOutcome::Admitted || self.seen.is_duplicate(now, &packet.header.msg_id)
        {
            return Ok(outputs);
        }
        let msg_id = packet.header.msg_id;
        let class = crate::PacketClass::Presence;
        let Some(relay) = suppress::relay_bytes(packet, self.config.suppression.ttl(class)) else {
            let _ = self.seen.check_and_insert(now, class, msg_id);
            return Ok(outputs);
        };
        if !self.config.suppression.enabled {
            let _ = self.seen.check_and_insert(now, class, msg_id);
            let mut senders = BTreeSet::new();
            senders.insert(link);
            outputs.extend(self.send_to_capable_links(relay, &senders));
            return Ok(outputs);
        }
        let degree = self
            .neighbors
            .iter()
            .filter(|neighbor| {
                neighbor.node_id.is_some()
                    && neighbor.link != link
                    && self.presence.supports(neighbor.link)
            })
            .count();
        let threshold = self
            .config
            .suppression
            .copy_threshold_for(class, degree, &mut self.rng);
        let deadline_ms = now.saturating_add(
            self.config
                .suppression
                .assessment_delay(degree, &mut self.rng),
        );
        match self.suppression.observe(Sighting {
            now,
            msg_id,
            class,
            sender: link,
            threshold,
            deadline_ms,
            relay,
        }) {
            suppress::Observe::Pending => {}
            suppress::Observe::Suppressed => {
                let _ = self.seen.check_and_insert(now, class, msg_id);
            }
            suppress::Observe::RelayNow(due) => {
                let _ = self.seen.check_and_insert(now, class, msg_id);
                outputs.extend(self.send_to_capable_links(due.bytes, &due.senders));
            }
        }
        Ok(outputs)
    }

    /// Applies an authenticated receipt: purge locally, report sender status
    /// only to the origin, stop spraying the delivered id and gossip the
    /// receipt to other capable links.
    fn on_receipt(
        &mut self,
        now: u64,
        sender: LinkId,
        identity: &Identity,
        frame: crate::receipt::ReceiptFrame<'_>,
    ) -> Vec<MeshOutput> {
        if !self.receipt.accept(now, &frame, Some(sender)) {
            return Vec::new();
        }
        self.spray.forget(frame.msg_id);
        let mut outputs = vec![MeshOutput::Purge { id: frame.msg_id }];
        if frame.origin == *identity.node_id().as_bytes() {
            outputs.push(MeshOutput::Delivered {
                id: frame.msg_id,
                origin: frame.origin,
                by: frame.signer,
            });
        }
        let links: Vec<LinkId> = self
            .neighbors
            .iter()
            .filter(|neighbor| self.receipt.supports(neighbor.link))
            .map(|neighbor| neighbor.link)
            .collect();
        for link in links {
            for payload in self.receipt.pending_for(link) {
                outputs.push(MeshOutput::Send {
                    link,
                    channel: Channel::Message,
                    payload,
                });
            }
        }
        outputs
    }

    /// Fires completed MSH-11 assessment windows. A dedupe record is written
    /// only when this node actually transmits, so a later copy can still
    /// cancel nothing but will be recognised as a duplicate.
    fn drain_due(&mut self, now: u64) -> Vec<MeshOutput> {
        let due = self.suppression.take_due(now);
        self.spray.expire(now);
        let mut outputs = Vec::new();
        for entry in due {
            let _ = self.seen.check_and_insert(now, entry.class, entry.msg_id);
            if entry.class == crate::PacketClass::Presence {
                outputs.extend(self.send_to_capable_links(entry.bytes, &entry.senders));
            } else {
                outputs.extend(self.send_to_links(entry.bytes, &entry.senders));
            }
        }
        outputs
    }

    /// Emits one bounded output for queued directory changes, if any.
    fn take_directory_changes(&mut self) -> Vec<MeshOutput> {
        let changes = self.directory.drain_changes();
        if changes.is_empty() {
            Vec::new()
        } else {
            vec![MeshOutput::DirectoryChanged { changes }]
        }
    }

    /// Translates sync state changes into host actions and Bulk sends.
    /// A frame that cannot fit the two-byte length field is simply not
    /// emitted; every tracker-produced frame is already bounded by config.
    fn apply_sync_actions(&mut self, now: u64, actions: Vec<SyncAction>) -> Vec<MeshOutput> {
        let mut outputs = Vec::new();
        for action in actions {
            match action {
                SyncAction::Send { link, frame } => {
                    if let Some(payload) = frame.encode() {
                        self.sync.note_sent_bytes(payload.len());
                        outputs.push(MeshOutput::Send {
                            link,
                            channel: Channel::Bulk,
                            payload,
                        });
                    }
                }
                SyncAction::SendV2 { link, frame } => {
                    if let Some(payload) = frame.encode() {
                        self.sync.note_sent_bytes(payload.len());
                        outputs.push(MeshOutput::Send {
                            link,
                            channel: Channel::Bulk,
                            payload,
                        });
                    }
                }
                SyncAction::Need { link, prefixes } => {
                    let peer = self
                        .neighbors
                        .get(link)
                        .and_then(|neighbor| neighbor.node_id)
                        .map(|id| *id.as_bytes())
                        .unwrap_or([0; 16]);
                    let prefixes: Vec<_> = prefixes
                        .into_iter()
                        .filter(|prefix| {
                            self.sync.local_id_for_prefix(*prefix).is_none_or(|id| {
                                !self.receipt.is_immune(id) && self.spray.can_sync(id, peer)
                            })
                        })
                        .collect();
                    if !prefixes.is_empty() {
                        outputs.push(MeshOutput::SyncNeed { link, prefixes });
                    }
                }
                SyncAction::Item {
                    link,
                    id,
                    wire,
                    copies_left,
                } => {
                    if self.receipt.is_immune(id) {
                        continue;
                    }
                    if self.config.spray.enabled && copies_left > 1 {
                        if let Ok(header) = crate::Header::decode(&wire) {
                            if header.class == crate::PacketClass::Direct {
                                self.spray.observe(
                                    now,
                                    id,
                                    header.class,
                                    header.dst.unwrap_or([0; 16]),
                                    header.lifetime_s,
                                    copies_left,
                                );
                                let candidates: Vec<(LinkId, [u8; 16])> = self
                                    .neighbors
                                    .iter()
                                    .filter_map(|neighbor| {
                                        neighbor.node_id.map(|id| (neighbor.link, *id.as_bytes()))
                                    })
                                    .collect();
                                let destination = header.dst.unwrap_or([0; 16]);
                                let plan =
                                    self.spray_plan(now, id, Some(link), &candidates, destination);
                                for (next, give) in &plan {
                                    if let Some(payload) = crate::spray::encode_frame(*give, &wire)
                                    {
                                        outputs.push(MeshOutput::Send {
                                            link: *next,
                                            channel: Channel::Message,
                                            payload,
                                        });
                                    }
                                }
                                outputs.extend(self.additive_hint_sends(
                                    now,
                                    Some(link),
                                    &plan,
                                    destination,
                                    &wire,
                                ));
                            }
                        }
                    }
                    outputs.push(MeshOutput::SyncItem {
                        id,
                        wire,
                        copies_left,
                    });
                }
                SyncAction::Release { link } => {
                    outputs.push(MeshOutput::ReleaseOpportunistic { link })
                }
            }
        }
        outputs
    }

    /// Derives one reverse-path hint from an accepted directory observation.
    ///
    /// The directory records the via-neighbour as a `NodeId` because it must
    /// survive link churn; a hint is only actionable while that identity is
    /// reachable through a currently verified link. An unverified or departed
    /// neighbour therefore cannot steer traffic.
    fn observe_hint(&mut self, now: u64, destination: NodeId, via: NodeId, hops: u8, seq: u64) {
        if self.config.route_hint.mode == RouteHintMode::Off {
            return;
        }
        let Some(link) = self
            .neighbors
            .iter()
            .find_map(|neighbor| (neighbor.node_id == Some(via)).then_some(neighbor.link))
        else {
            return;
        };
        let observation = RouteHintObservation {
            destination,
            neighbour: link,
            hops,
            seq,
        };
        let _ = self.hints.observe(now, observation, true);
    }

    /// The link named by a fresh hint, if hints are active. The table's
    /// relative expiry decides freshness; no packet timestamp is consulted.
    fn hint_link(&self, now: u64, destination: [u8; 16]) -> Option<LinkId> {
        if self.config.route_hint.mode == RouteHintMode::Off {
            return None;
        }
        self.hints
            .hint(now, NodeId::from_bytes(destination))
            .map(|hint| hint.neighbour)
    }

    /// MSH-16 spray plan, optionally steered by an MSH-21 hint.
    fn spray_plan(
        &mut self,
        now: u64,
        id: MessageId,
        sender: Option<LinkId>,
        candidates: &[(LinkId, [u8; 16])],
        destination: [u8; 16],
    ) -> Vec<(LinkId, u8)> {
        let mode = self.config.route_hint.mode;
        let hint = self.hint_link(now, destination);
        if mode == RouteHintMode::SubstituteCopy {
            self.spray
                .plan_with_hint(now, id, sender, candidates.iter().copied(), hint)
        } else {
            self.spray.plan(now, id, sender, candidates.iter().copied())
        }
    }

    /// Additive mode's extra unicast: one copy along the hint, only when the
    /// base spray plan did not already choose that link.
    fn additive_hint_sends(
        &self,
        now: u64,
        sender: Option<LinkId>,
        plan: &[(LinkId, u8)],
        destination: [u8; 16],
        bytes: &[u8],
    ) -> Vec<MeshOutput> {
        if self.config.route_hint.mode != RouteHintMode::AdditiveUnicast {
            return Vec::new();
        }
        let Some(link) = self.hint_link(now, destination) else {
            return Vec::new();
        };
        if Some(link) == sender || plan.iter().any(|(existing, _)| *existing == link) {
            return Vec::new();
        }
        let payload = if self.spray.supports(link) {
            crate::spray::encode_frame(1, bytes).unwrap_or_else(|| bytes.to_vec())
        } else {
            bytes.to_vec()
        };
        vec![MeshOutput::Send {
            link,
            channel: Channel::Message,
            payload,
        }]
    }

    /// Applies MSH-22's latest-wins policy to one inbound Telemetry packet.
    ///
    /// This runs after header parsing and neighbour verification but before
    /// the relay budget: a superseded, throttled or expired update must not
    /// spend a token or leave a dedupe record. Only a malformed frame or a
    /// bad content address is attributable to the sending link. Telemetry is
    /// never offered to the store or sync tracker.
    fn on_telemetry_data(&mut self, now: u64, link: LinkId, packet: Packet<'_>) -> Vec<MeshOutput> {
        let mut outputs = self.drain_due(now);
        if !suppress::content_valid(&packet) {
            return self.reject_telemetry(now, link, outputs);
        }
        let frame = match TelemetryFrame::decode(packet.payload) {
            Ok(frame) => frame,
            Err(_) => return self.reject_telemetry(now, link, outputs),
        };
        let hop_limit = self.config.telemetry.hop_limit;
        if hop_limit <= 1 || packet.header.ttl <= 1 || packet.header.hops >= hop_limit {
            return outputs;
        }
        let origin = packet.header.origin;
        let advisory = match self.telemetry.admit(
            now,
            &origin,
            frame.kind,
            frame.seq,
            packet.header.lifetime_s,
        ) {
            Ok(advisory) => advisory,
            // Expiry, staleness and throttling are ordinary policy drops:
            // no neighbour penalty and no budget debit.
            Err(_) => return outputs,
        };
        if self.seen.is_duplicate(now, &packet.header.msg_id) {
            return outputs;
        }
        let outcome = self.budgets.admit(
            now,
            link,
            ao_idents::NodeId::from_bytes(origin),
            packet.header.class,
            packet.payload.len(),
        );
        match outcome {
            BudgetOutcome::Admitted => {}
            BudgetOutcome::OriginDenied => return outputs,
            BudgetOutcome::NeighborDenied => {
                if self
                    .budgets
                    .penalize(now, link, self.config.budgets.penalty_excess)
                {
                    outputs.push(MeshOutput::Release {
                        link,
                        reason: DisconnectReason::AbuseDetected,
                    });
                }
                return outputs;
            }
        }
        let _ = self
            .seen
            .check_and_insert(now, packet.header.class, packet.header.msg_id);
        let Some(bytes) = suppress::relay_bytes(packet, hop_limit) else {
            return outputs;
        };
        outputs.extend(self.telemetry_to_links(bytes, link, advisory));
        outputs
    }

    /// Counts a malformed Telemetry frame against its sender, preserving any
    /// unrelated suppression outputs already due at this timestamp.
    fn reject_telemetry(
        &mut self,
        now: u64,
        link: LinkId,
        mut outputs: Vec<MeshOutput>,
    ) -> Vec<MeshOutput> {
        self.neighbors.reject(link);
        if self
            .budgets
            .penalize(now, link, self.config.budgets.penalty_invalid)
        {
            outputs.push(MeshOutput::Release {
                link,
                reason: DisconnectReason::AbuseDetected,
            });
        }
        outputs
    }

    /// Copies one accepted update to every verified neighbour except the
    /// sender, carrying the same coalescing advisory on each link.
    fn telemetry_to_links(
        &self,
        bytes: Vec<u8>,
        sender: LinkId,
        advisory: TelemetryAdvisory,
    ) -> Vec<MeshOutput> {
        self.neighbors
            .iter()
            .filter(|neighbor| neighbor.node_id.is_some() && neighbor.link != sender)
            .map(|neighbor| MeshOutput::TelemetrySend {
                link: neighbor.link,
                channel: Channel::Telemetry,
                payload: bytes.clone(),
                advisory,
            })
            .collect()
    }

    /// Sends one relayed packet to every verified neighbour that did not
    /// already carry a copy. `BTreeSet` keeps the exclusion set bounded and
    /// deterministic, matching the MSH-10 link cap.
    fn send_to_links(&self, bytes: Vec<u8>, senders: &BTreeSet<LinkId>) -> Vec<MeshOutput> {
        self.send_to_links_filtered(bytes, senders, false)
    }

    /// Announcements go only to links that negotiated MSH-19; older peers keep
    /// the pre-MSH-19 Presence path and never learn from this body.
    fn send_to_capable_links(&self, bytes: Vec<u8>, senders: &BTreeSet<LinkId>) -> Vec<MeshOutput> {
        self.send_to_links_filtered(bytes, senders, true)
    }

    fn send_to_links_filtered(
        &self,
        bytes: Vec<u8>,
        senders: &BTreeSet<LinkId>,
        presence_only: bool,
    ) -> Vec<MeshOutput> {
        self.neighbors
            .iter()
            .filter(|neighbor| {
                neighbor.node_id.is_some()
                    && !senders.contains(&neighbor.link)
                    && (!presence_only || self.presence.supports(neighbor.link))
            })
            .map(|neighbor| MeshOutput::Send {
                link: neighbor.link,
                channel: Channel::Message,
                payload: bytes.clone(),
            })
            .collect()
    }

    fn release_if_penalised(link: LinkId, release: bool) -> Vec<MeshOutput> {
        if release {
            vec![MeshOutput::Release {
                link,
                reason: DisconnectReason::AbuseDetected,
            }]
        } else {
            Vec::new()
        }
    }

    /// Translates one advisory change into an output. `Clear` means the peer
    /// lost its advice and aoNetwork must fall back to its own rules.
    fn link_hint_outputs(peer: PeerKey, change: HintChange) -> Vec<MeshOutput> {
        match change {
            HintChange::Set(preference) => vec![MeshOutput::SetLinkHint { peer, preference }],
            HintChange::Clear => vec![MeshOutput::ClearLinkHint { peer }],
            HintChange::Unchanged => Vec::new(),
        }
    }
}

/// Recognises a channel envelope only in an ordinary Broadcast payload.
///
/// `Ok(None)` covers every other class and legacy opaque Broadcast bytes
/// whose first byte is not the reserved channel magic. A magic byte that
/// does not decode as v1 is an error attributable to the sender.
fn parse_channel_envelope(
    class: PacketClass,
    payload: &[u8],
) -> Result<Option<ChannelEnvelope<'_>>, ChannelError> {
    if class != PacketClass::Broadcast || payload.first() != Some(&CHANNEL_MAGIC) {
        return Ok(None);
    }
    ChannelEnvelope::decode(payload).map(Some)
}

impl<R: RngCore> crate::snapshot::Snapshot for MeshEngine<R> {
    fn snapshot(&self) -> Result<Vec<u8>, crate::snapshot::SnapshotError> {
        crate::snapshot::encode_snapshot(
            self.seen.export_state(),
            self.receipt.export_state(),
            self.spray.export_state(),
        )
    }

    fn restore(&mut self, bytes: &[u8]) -> Result<(), crate::snapshot::SnapshotError> {
        // Decode against this engine's bounds first: a snapshot from a
        // differently configured host is rejected without partial state.
        let (seen, immunity, spray) = crate::snapshot::decode_snapshot(
            bytes,
            self.seen.capacity(),
            self.config.receipt.max_entries,
            self.config.spray.max_entries,
            self.config.max_neighbors,
        )?;
        self.seen.import_state(seen);
        self.receipt.import_state(immunity);
        self.spray.import_state(spray);
        self.clock_restore_ready = false;
        Ok(())
    }
}

impl<R: RngCore> crate::snapshot::TimedSnapshot for MeshEngine<R> {
    fn snapshot_at(
        &self,
        now: u64,
        owner: NodeId,
    ) -> Result<Vec<u8>, crate::snapshot::SnapshotError> {
        crate::snapshot::encode_timed_snapshot(
            now,
            owner,
            self.seen.export_state(),
            self.receipt.export_state(),
            self.spray.export_state(),
        )
    }
    fn restore_at(
        &mut self,
        now: u64,
        owner: NodeId,
        elapsed_ms: u64,
        bytes: &[u8],
    ) -> Result<(), crate::snapshot::SnapshotError> {
        if !self.clock_restore_ready {
            return Err(crate::snapshot::SnapshotError::AlreadyStarted);
        }
        let (seen, immunity, spray) = crate::snapshot::decode_timed_snapshot(
            bytes,
            now,
            owner,
            elapsed_ms,
            crate::snapshot::TimedRestoreLimits {
                seen: self.seen.capacity(),
                immunity: self.config.receipt.max_entries,
                spray: self.config.spray.max_entries,
                links: self.config.max_neighbors,
                immunity_ms: self.config.receipt.lifetime_s.saturating_mul(1000),
            },
        )?;
        self.seen.import_state(seen);
        self.receipt.import_state(immunity);
        self.spray.import_state(spray);
        self.clock_restore_ready = false;
        Ok(())
    }
}
