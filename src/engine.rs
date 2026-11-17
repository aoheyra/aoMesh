//! Sans-IO command dispatch with borrowed submissions and bounded neighbours.

use crate::neighbor::{MeshConfig, NeighborTable};
use crate::{Header, Packet, PacketError, sign_packet};
use ao_idents::{IdentError, Identity, Signature};
use ao_network::{AppHello, BeaconFlags, Channel, DisconnectReason, Hello, LinkId, LocalTag};
use rand_core::RngCore;

/// One input. Borrowed payloads and identities remain owned by the caller.
#[non_exhaustive]
pub enum MeshInput<'a> {
    /// A link is transport-ready, but its introduction is not authenticated.
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
    /// Time-driven step; no routing timers exist until the forwarding issues.
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

/// Actions for the host. Forwarding and delivery producers land in MSH-08/09.
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
    /// A future verified local delivery; never emitted by structural parsing.
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
pub struct MeshEngine<R: RngCore> {
    // MSH-08/11 consume this injected RNG for forwarding jitter.
    #[allow(dead_code)]
    rng: R,
    neighbors: NeighborTable,
}
impl<R: RngCore> MeshEngine<R> {
    /// Creates an engine with the default 32-entry neighbour limit.
    pub fn new(rng: R) -> Self {
        Self::with_config(rng, MeshConfig::default())
    }
    /// Creates an engine with an explicit state bound.
    pub fn with_config(rng: R, config: MeshConfig) -> Self {
        Self {
            rng,
            neighbors: NeighborTable::new(config.max_neighbors),
        }
    }
    /// Read-only bookkeeping, not a list of authenticated identities.
    pub fn neighbors(&self) -> &NeighborTable {
        &self.neighbors
    }
    /// Processes one input at caller-supplied milliseconds.
    ///
    /// Data is structurally validated and counted, then discarded. It cannot
    /// produce Deliver or forwarding before MSH-08/09's security pipeline.
    /// Submission errors are typed and the caller still owns the input bytes.
    pub fn handle(&mut self, now: u64, input: MeshInput<'_>) -> Result<Vec<MeshOutput>, MeshError> {
        match input {
            MeshInput::Tick => Ok(Vec::new()),
            MeshInput::LinkUp { link, remote_hello } => {
                if self.neighbors.insert(now, link, remote_hello) {
                    Ok(Vec::new())
                } else {
                    Ok(vec![MeshOutput::Release {
                        link,
                        reason: DisconnectReason::Closed,
                    }])
                }
            }
            MeshInput::LinkDown { link, .. } => {
                self.neighbors.remove(link);
                Ok(Vec::new())
            }
            MeshInput::Data { link, payload, .. } => {
                // Packet::decode parses the bounded header before inspecting or
                // borrowing the payload, and allocates nothing on either path.
                let valid = Packet::decode(payload).is_ok();
                self.neighbors.received(now, link, payload.len(), valid);
                Ok(Vec::new())
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
