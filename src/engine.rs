//! Sans-IO command dispatch with borrowed submissions and bounded neighbours.

use crate::forward::{self, Action};
use crate::neighbor::{MeshConfig, NeighborTable};
use crate::seen::SeenCache;
use crate::{Header, Packet, PacketError, sign_packet};
use ao_idents::{IdentError, Identity, NodeId, Signature};
use ao_network::{AppHello, BeaconFlags, Channel, DisconnectReason, Hello, LinkId, LocalTag};
use rand_core::RngCore;

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
    },
    /// Time-driven step; baseline forwarding needs no timers (MSH-11
    /// adds assessment delays).
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

/// Actions for the host. The MSH-08 baseline emits `Send` relays and
/// structural `Deliver`s; MSH-09 authenticates delivery.
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
    Release {
        /// Link to close.
        link: LinkId,
        /// Local closing reason.
        reason: DisconnectReason,
    },
    /// A local delivery: a fresh Direct packet whose `dst` is this
    /// engine's node (MSH-08). The payload is still opaque and the
    /// origin unverified until MSH-09's checks run.
    Deliver {
        /// Packet header.
        header: Header,
        /// Opaque application payload.
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
/// State is bounded by configuration: `max_neighbors` neighbour entries
/// plus one forwarding dedupe cache at `SeenConfig::default()`'s
/// documented bounds (ADR-0003).
pub struct MeshEngine<R: RngCore> {
    // MSH-11's assessment delay consumes this injected RNG; MSH-08
    // relays immediately, so nothing reads it yet.
    #[allow(dead_code)]
    rng: R,
    // The node this engine delivers to: `dst` is compared against it.
    local_id: NodeId,
    neighbors: NeighborTable,
    seen: SeenCache,
}
impl<R: RngCore> MeshEngine<R> {
    /// Creates an engine for `local_id` with the default 32-entry
    /// neighbour limit.
    pub fn new(rng: R, local_id: NodeId) -> Self {
        Self::with_config(rng, local_id, MeshConfig::default())
    }
    /// Creates an engine for `local_id` with an explicit neighbour bound.
    pub fn with_config(rng: R, local_id: NodeId, config: MeshConfig) -> Self {
        Self {
            rng,
            local_id,
            neighbors: NeighborTable::new(config.max_neighbors),
            seen: SeenCache::default(),
        }
    }
    /// Read-only bookkeeping, not a list of authenticated identities.
    pub fn neighbors(&self) -> &NeighborTable {
        &self.neighbors
    }
    /// Processes one input at caller-supplied milliseconds.
    ///
    /// LinkUp decodes, verifies and negotiates the peer's `MeshHello`
    /// (MSH-07): a verified neighbour records its `NodeId`, a rejected
    /// introduction still counts traffic but records none, and only a
    /// full table releases the link. Data is structurally validated and
    /// counted, then the MSH-08 rules apply: a fresh Direct packet for
    /// this node's id is delivered, any other fresh Direct packet
    /// relays to verified neighbours but the sender with `ttl`
    /// decremented, and delivery stays unauthenticated until MSH-09's
    /// checks. Submission errors are typed and the caller still owns
    /// the input bytes.
    pub fn handle(&mut self, now: u64, input: MeshInput<'_>) -> Result<Vec<MeshOutput>, MeshError> {
        match input {
            MeshInput::Tick => Ok(Vec::new()),
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
                Ok(Vec::new())
            }
            MeshInput::Data { link, payload, .. } => {
                // Packet::decode parses the bounded header before inspecting or
                // borrowing the payload, and allocates nothing on either path.
                let packet = Packet::decode(payload);
                self.neighbors
                    .received(now, link, payload.len(), packet.is_ok());
                let packet = match packet {
                    Ok(packet) => packet,
                    Err(_) => return Ok(Vec::new()),
                };
                // Admission through LinkUp is the gate, and ADR-0004 adds
                // that an entry whose hello failed verification may not
                // forward or deliver on that peer's behalf: its counters
                // observe, nothing more.
                if !self
                    .neighbors
                    .get(link)
                    .is_some_and(|neighbor| neighbor.node_id.is_some())
                {
                    return Ok(Vec::new());
                }
                match forward::on_data(self.local_id, &mut self.seen, now, packet) {
                    Action::Drop => Ok(Vec::new()),
                    Action::Deliver { header, payload } => {
                        Ok(vec![MeshOutput::Deliver { header, payload }])
                    }
                    Action::Relay { bytes } => Ok(self
                        .neighbors
                        .iter()
                        // Never send a packet back down the link it
                        // arrived on, and never through an unverified one.
                        .filter(|neighbor| neighbor.link != link && neighbor.node_id.is_some())
                        .map(|neighbor| MeshOutput::Send {
                            link: neighbor.link,
                            channel: Channel::Message,
                            payload: bytes.clone(),
                        })
                        .collect()),
                }
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
}
