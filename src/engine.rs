//! Sans-IO command dispatch with borrowed submissions and bounded neighbours.

use crate::budget::{BudgetOutcome, BudgetTracker};
use crate::deliver;
use crate::forward::{self, Action};
use crate::neighbor::{MeshConfig, NeighborTable};
use crate::seen::{Offer, SeenCache};
use crate::suppress::{self, Sighting, SuppressionTable};
use crate::sync::{BeaconTracker, StoreSummary};
use crate::{Header, MessageId, Packet, PacketError, sign_packet};
use ao_idents::{IdentError, Identity, ReplayGuard, Signature};
use ao_network::{AppHello, BeaconFlags, Channel, DisconnectReason, Hello, LinkId, LocalTag};
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
    /// Time-driven step; fires completed MSH-11 assessment timers.
    Tick,
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
    /// Replace the introduction used by new links.
    SetHello {
        /// Rotating local tag.
        tag: LocalTag,
        /// Opaque mesh introduction.
        app_hello: AppHello,
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
}
impl core::fmt::Display for MeshError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Packet(e) => write!(f, "invalid submission: {e}"),
            Self::Signing(e) => write!(f, "signing failed: {e}"),
            Self::UnknownLink(link) => write!(f, "unknown submission link: {link:?}"),
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
/// `MeshConfig::suppression.max_entries` pending floods (MSH-11).
pub struct MeshEngine<R: RngCore> {
    rng: R,
    config: MeshConfig,
    neighbors: NeighborTable,
    seen: SeenCache,
    replay: ReplayGuard,
    budgets: BudgetTracker,
    suppression: SuppressionTable,
    beacon: BeaconTracker,
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
        let budgets = BudgetTracker::new(config.budgets);
        Self {
            rng,
            config,
            neighbors: NeighborTable::new(config.max_neighbors),
            seen: SeenCache::default(),
            replay: ReplayGuard::new(config.replay),
            budgets,
            suppression: SuppressionTable::new(config.suppression),
            beacon: BeaconTracker::new(config.summary),
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
    /// Digest currently advertised in the beacon, if one was published.
    pub fn published_store_digest(&self) -> Option<[u8; 4]> {
        self.beacon.published_digest()
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
        match input {
            MeshInput::StoreSummary { ids } => {
                let digest = StoreSummary::from_ids(ids).digest();
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
            MeshInput::Tick => Ok(self.drain_due(now)),
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
                let node_id =
                    crate::hello::verified_node_id(remote_hello.app_hello.as_bytes()).ok();
                self.neighbors.insert(now, link, remote_hello, node_id);
                Ok(Vec::new())
            }
            MeshInput::LinkDown { link, .. } => {
                self.neighbors.remove(link);
                self.budgets.link_down(link);
                Ok(Vec::new())
            }
            MeshInput::Data {
                link,
                identity,
                payload,
                ..
            } => {
                // An untracked link has no counters or penalty state; do not
                // let arbitrary link ids create either.
                if !self.neighbors.contains(link) {
                    return Ok(Vec::new());
                }
                // Packet::decode parses the bounded header before inspecting or
                // borrowing the payload, and allocates nothing on either path.
                let packet = Packet::decode(payload);
                self.neighbors
                    .received(now, link, payload.len(), packet.is_ok());
                let verified = self
                    .neighbors
                    .get(link)
                    .is_some_and(|neighbor| neighbor.node_id.is_some());
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
                // Both the claimed origin and the sending link pay for a
                // relay. A local delivery still happens; only its onward
                // copies are withheld when either bucket is empty.
                let origin = ao_idents::NodeId::from_bytes(packet.header.origin);
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
                    return Ok(Self::release_if_penalised(link, true));
                }
                // Complete timers that expired while this packet was in
                // flight before adding a new sighting for the same id.
                let mut outputs = self.drain_due(now);
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
                                    let offer = self.seen.check_and_insert(
                                        now,
                                        header.class,
                                        header.msg_id,
                                    );
                                    debug_assert_eq!(offer, Offer::Fresh, "forward peeked fresh");
                                    outputs.push(MeshOutput::Deliver {
                                        header,
                                        payload: plaintext,
                                    });
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
                                let mut senders = BTreeSet::new();
                                senders.insert(link);
                                outputs.extend(self.send_to_links(bytes, &senders));
                            }
                            Action::Relay { .. } => {}
                        }
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
                        let threshold = self
                            .config
                            .suppression
                            .copy_threshold(degree, &mut self.rng);
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
        }
    }

    /// Fires completed MSH-11 assessment windows. A dedupe record is written
    /// only when this node actually transmits, so a later copy can still
    /// cancel nothing but will be recognised as a duplicate.
    fn drain_due(&mut self, now: u64) -> Vec<MeshOutput> {
        let due = self.suppression.take_due(now);
        let mut outputs = Vec::new();
        for entry in due {
            let _ = self.seen.check_and_insert(now, entry.class, entry.msg_id);
            outputs.extend(self.send_to_links(entry.bytes, &entry.senders));
        }
        outputs
    }

    /// Sends one relayed packet to every verified neighbour that did not
    /// already carry a copy. `BTreeSet` keeps the exclusion set bounded and
    /// deterministic, matching the MSH-10 link cap.
    fn send_to_links(&self, bytes: Vec<u8>, senders: &BTreeSet<LinkId>) -> Vec<MeshOutput> {
        self.neighbors
            .iter()
            .filter(|neighbor| neighbor.node_id.is_some() && !senders.contains(&neighbor.link))
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
}
