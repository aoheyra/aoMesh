//! Runtime-neutral async glue, usable from a Tokio-owned task without I/O in the core.
//!
//! The host owns time and wakeups. Race polling against a timer for
//! `next_deadline`, then poll again with fresh timestamps. No task is spawned
//! and no clock is read here. Network durations and mesh milliseconds are
//! explicit separate inputs; no wall-clock/monotonic conversion is guessed.

use crate::hop::{HopFrameError, decode_control};
use crate::telemetry::TelemetryAdvisory;
use crate::{MeshEngine, MeshError, MeshInput, MeshOutput};
use ao_idents::{HopSessions, IdentError, Identity, NodeId};
use ao_network::{
    Channel, LinkId, LinkRole, Network, NetworkEvent, SendError, SendOpts, Transport,
};
use rand_core::RngCore;
use std::future::poll_fn;
use std::task::{Context, Poll};
use std::time::Duration;

/// Why a link could not be sealed or opened with the host's session table.
///
/// The adapter never falls back to cleartext on any of these errors: that
/// would hide an impostor, a missing session or a tampered frame.
#[derive(Debug)]
pub enum HopAdapterError {
    /// The caller did not pass its host-owned `HopSessions` for an active link.
    SessionNotSupplied(LinkId),
    /// The link has no verified peer identity, so a session cannot be keyed.
    NoVerifiedPeer(LinkId),
    /// Sealing a Data frame failed.
    Seal(IdentError),
    /// Opening a Data frame failed; no plaintext reached the engine.
    Open(IdentError),
}

/// Host-visible results of applying engine actions.
#[derive(Debug)]
pub enum AdapterEvent {
    /// A local delivery authenticated by MSH-09: the payload is the
    /// opened plaintext after the seal, origin-signature and replay
    /// checks accepted it.
    Deliver {
        /// Packet header, as received; `payload_len` counts the sealed
        /// wire payload, not this plaintext's length.
        header: crate::Header,
        /// The opened application payload.
        payload: Vec<u8>,
    },
    /// A signed public-channel Broadcast accepted for a local subscriber
    /// (MSH-23). The engine verified the origin signature with the key from
    /// the sender's signed hello and accepted the id in its replay guard;
    /// the payload is the opaque envelope body, unmodified.
    ChannelDeliver {
        /// The channel the message was addressed to.
        channel_id: crate::ChannelId,
        /// Packet header, as received.
        header: crate::Header,
        /// Opaque application bytes from the envelope.
        payload: Vec<u8>,
    },
    /// Network admission failed; SendError retains the original payload.
    SendFailed {
        /// The refusing link.
        link: LinkId,
        /// Typed cause and original payload.
        error: SendError,
    },
    /// The store owner must resolve these short ids to encoded packets and
    /// feed them back with `MeshInput::SyncItems`.
    SyncNeed {
        /// The contact's link.
        link: LinkId,
        /// Prefixes the peer is missing.
        prefixes: Vec<[u8; crate::sync::SHORT_ID_BYTES]>,
    },
    /// The host store must remove this delivered message (MSH-17).
    Purge {
        /// Content address whose copies are no longer needed.
        id: crate::MessageId,
    },
    /// An authenticated receipt reached its sender (MSH-17).
    Delivered {
        /// The acknowledged message.
        id: crate::MessageId,
        /// Original sender from the acknowledged packet.
        origin: [u8; 16],
        /// Authenticated destination that issued the receipt.
        by: [u8; 16],
    },
    /// The host must fetch an identity card it does not yet know (MSH-19).
    /// The adapter neither resolves nor caches cards.
    CardFetch {
        /// Node whose signed announcement advertised the card.
        node_id: [u8; 16],
        /// Opaque hash to resolve out of band.
        card_hash: [u8; 8],
    },
    /// Coalesced directory changes for the UI (MSH-20). No network action
    /// follows; the UI queries `MeshEngine::directory` for details.
    DirectoryChanged {
        /// Bounded, ordered change stream.
        changes: Vec<crate::directory::DirectoryChange>,
    },
    /// A Telemetry update was accepted under this latest-wins advisory.
    /// The adapter has already handed its key and deadline to aoNetwork's
    /// send queue; the event is for host diagnostics, not another queue.
    TelemetryAccepted {
        /// Link that received the update.
        link: LinkId,
        /// Policy values mirrored into `SendOpts`.
        advisory: TelemetryAdvisory,
    },
    /// Both ends advertised hop encryption on this link. The host starts
    /// its own `HopHandshake`, pinned to `card_hash`, and writes the first
    /// Noise message through [`MeshInput::HopControl`] when `initiator` is
    /// true; a responder waits for [`Self::HopControl`] (MSH-26).
    HopStart {
        /// Link whose signed hello completed the negotiation.
        link: LinkId,
        /// Verified neighbour the card must belong to.
        peer: NodeId,
        /// Eight-byte pin from the signed hello.
        card_hash: [u8; 8],
        /// Whether this side opened the radio link and writes message 1.
        initiator: bool,
    },
    /// An inbound Control frame carried a Noise XX handshake message. The
    /// host drives its own `HopHandshake` with these bytes; the engine never
    /// sees a card, a handshake state or a key (MSH-26).
    HopControl {
        /// Link that sent the frame.
        link: LinkId,
        /// Verified neighbour the card must belong to.
        peer: NodeId,
        /// Eight-byte pin from the signed hello.
        card_hash: [u8; 8],
        /// Whether this side opened the radio link and writes message 1.
        initiator: bool,
        /// The opaque Noise message after the one-byte kind tag.
        message: Vec<u8>,
    },
    /// An inbound Control frame used an unknown tag or exceeded its bound.
    HopFrameInvalid {
        /// Link that sent the frame.
        link: LinkId,
        /// Typed framing failure.
        error: HopFrameError,
    },
    /// A Data frame could not be sealed or opened on an encrypted link.
    /// Nothing was sent to the radio and no plaintext reached the engine.
    HopFailed {
        /// Link whose session failed.
        link: LinkId,
        /// Typed cause.
        error: HopAdapterError,
    },
    /// A negotiated hop link went down. The host should close or forget its
    /// own session (and drop any in-flight handshake) for `peer` (MSH-26).
    HopEnded {
        /// Link that ended.
        link: LinkId,
        /// Neighbour whose session must be closed.
        peer: NodeId,
    },
    /// A peer's item is ready for the store owner to validate and insert.
    SyncItem {
        /// Full content address parsed from the packet.
        id: crate::MessageId,
        /// Complete encoded mesh packet.
        wire: Vec<u8>,
        /// Remaining spray copies for the host store metadata.
        copies_left: u8,
    },
}

/// Engine and facade owned together by one caller task.
pub struct NetworkAdapter<R: RngCore, T: Transport> {
    engine: MeshEngine<R>,
    network: Network<T>,
}
impl<R: RngCore, T: Transport> NetworkAdapter<R, T> {
    /// Takes ownership of already constructed components.
    pub fn new(engine: MeshEngine<R>, network: Network<T>) -> Self {
        Self { engine, network }
    }
    /// Replaces the engine without tearing down the network facade.
    ///
    /// A host restoring an MSH-29 snapshot keeps its live radio links and
    /// re-announces them to the new engine; only the routing state is swapped.
    /// The previous engine is returned so the caller can drop it explicitly.
    pub fn replace_engine(&mut self, engine: MeshEngine<R>) -> MeshEngine<R> {
        std::mem::replace(&mut self.engine, engine)
    }
    /// Inspect engine state without a second source of truth.
    pub fn engine(&self) -> &MeshEngine<R> {
        &self.engine
    }
    /// The engine's versioned diagnostics snapshot (MSH-30).
    ///
    /// The host maps these plain integer fields into its own diagnostics
    /// bundle; the adapter adds no I/O, clock read or second counter.
    #[must_use]
    pub fn snapshot(&self) -> crate::MeshSnapshot {
        self.engine.observability_snapshot()
    }
    /// Inspect the network and its transport.
    pub fn network(&self) -> &Network<T> {
        &self.network
    }
    /// Borrow the engine to feed a host input directly. The simulator uses
    /// this to count the outputs before the adapter applies them.
    pub fn engine_mut(&mut self) -> &mut MeshEngine<R> {
        &mut self.engine
    }
    /// Borrow the network to poll a transport event directly. The
    /// simulator uses this with [`Self::engine_mut`] and [`Self::apply`].
    pub fn network_mut(&mut self) -> &mut Network<T> {
        &mut self.network
    }
    /// Earliest network timer; the caller must arrange a wakeup by this time.
    pub fn next_deadline(&self) -> Option<Duration> {
        self.network.next_deadline()
    }
    /// Feed a host input, applying every resulting command immediately.
    /// `network_now` is the caller's clock for the network commands the
    /// input produces, the same timestamp `poll_event` takes.
    pub fn handle(
        &mut self,
        network_now: Duration,
        mesh_now_ms: u64,
        input: MeshInput<'_>,
    ) -> Result<Vec<AdapterEvent>, MeshError> {
        let outputs = self.engine.handle(mesh_now_ms, input)?;
        Ok(self.apply(network_now, outputs))
    }

    /// Feed a host input and apply its outputs with the host's hop sessions
    /// borrowed for this call (MSH-26). Handshake bytes arrive through
    /// `MeshInput::HopControl`; Data sends are sealed only for active links.
    pub fn handle_with_hop(
        &mut self,
        network_now: Duration,
        mesh_now_ms: u64,
        input: MeshInput<'_>,
        sessions: &mut HopSessions,
    ) -> Result<Vec<AdapterEvent>, MeshError> {
        let outputs = self.engine.handle(mesh_now_ms, input)?;
        Ok(self.apply_with_hop(network_now, outputs, sessions))
    }
    /// Translates mesh milliseconds into aoNetwork's absolute monotonic
    /// deadline. A clock overflow leaves the frame undated rather than
    /// inventing a deadline in the past.
    fn telemetry_opts(now: Duration, advisory: TelemetryAdvisory) -> SendOpts {
        SendOpts {
            coalesce_key: Some(*advisory.coalesce_key.as_bytes()),
            expires_at: now.checked_add(Duration::from_millis(advisory.expires_in_ms)),
        }
    }

    /// Maps actions to the facade in cleartext mode. Errors and deliveries
    /// are returned, never swallowed. The adapter reads no clock:
    /// `network_now` is passed straight to every facade command that needs it.
    pub fn apply(&mut self, network_now: Duration, outputs: Vec<MeshOutput>) -> Vec<AdapterEvent> {
        self.apply_inner(network_now, outputs, None)
    }

    /// Maps actions to the facade, sealing Data frames for links whose host
    /// installed a hop session (MSH-26). `sessions` is the host's own
    /// `HopSessions`, borrowed for this call only: the adapter keeps no key.
    /// An active link with no usable session emits `HopFailed` and sends
    /// nothing, so an encryption failure can never become a cleartext leak.
    pub fn apply_with_hop(
        &mut self,
        network_now: Duration,
        outputs: Vec<MeshOutput>,
        sessions: &mut HopSessions,
    ) -> Vec<AdapterEvent> {
        self.apply_inner(network_now, outputs, Some(sessions))
    }

    /// Seals one outbound Data frame when the link is hop-active. Control
    /// frames stay as framed by the engine: they carry the handshake itself.
    fn maybe_seal(
        &self,
        link: LinkId,
        channel: Channel,
        payload: Vec<u8>,
        sessions: Option<&mut HopSessions>,
        events: &mut Vec<AdapterEvent>,
    ) -> Option<Vec<u8>> {
        if channel == Channel::Control || !self.engine.hop_active(link) {
            return Some(payload);
        }
        let Some(sessions) = sessions else {
            events.push(AdapterEvent::HopFailed {
                link,
                error: HopAdapterError::SessionNotSupplied(link),
            });
            return None;
        };
        let Some((peer, _)) = self.engine.hop_peer(link) else {
            events.push(AdapterEvent::HopFailed {
                link,
                error: HopAdapterError::NoVerifiedPeer(link),
            });
            return None;
        };
        match sessions.seal_frame(peer, &payload) {
            Ok(sealed) => Some(sealed),
            Err(error) => {
                events.push(AdapterEvent::HopFailed {
                    link,
                    error: HopAdapterError::Seal(error),
                });
                None
            }
        }
    }

    fn apply_inner(
        &mut self,
        network_now: Duration,
        outputs: Vec<MeshOutput>,
        mut sessions: Option<&mut HopSessions>,
    ) -> Vec<AdapterEvent> {
        let mut events = Vec::new();
        for output in outputs {
            match output {
                MeshOutput::Send {
                    link,
                    channel,
                    payload,
                } => {
                    if let Some(payload) = self.maybe_seal(
                        link,
                        channel,
                        payload,
                        sessions.as_deref_mut(),
                        &mut events,
                    ) {
                        if let Err(error) = self.network.send(network_now, link, channel, payload) {
                            events.push(AdapterEvent::SendFailed { link, error });
                        }
                    }
                }
                MeshOutput::Broadcast { channel, payload } => {
                    if self.engine.hop().is_empty() {
                        events.extend(
                            self.network
                                .broadcast(network_now, channel, &payload)
                                .into_iter()
                                .map(|(link, error)| AdapterEvent::SendFailed { link, error }),
                        );
                    } else {
                        // Sealing is per neighbour: the peer id keys the
                        // session, so a shared ciphertext cannot be broadcast.
                        let links: Vec<LinkId> = self
                            .network
                            .links()
                            .into_iter()
                            .map(|info| info.link)
                            .collect();
                        for link in links {
                            if let Some(sealed) = self.maybe_seal(
                                link,
                                channel,
                                payload.clone(),
                                sessions.as_deref_mut(),
                                &mut events,
                            ) {
                                if let Err(error) =
                                    self.network.send(network_now, link, channel, sealed)
                                {
                                    events.push(AdapterEvent::SendFailed { link, error });
                                }
                            }
                        }
                    }
                }
                MeshOutput::TelemetrySend {
                    link,
                    channel,
                    payload,
                    advisory,
                } => {
                    let opts = Self::telemetry_opts(network_now, advisory);
                    if let Some(payload) = self.maybe_seal(
                        link,
                        channel,
                        payload,
                        sessions.as_deref_mut(),
                        &mut events,
                    ) {
                        if let Err(error) =
                            self.network
                                .send_opts(network_now, link, channel, payload, opts)
                        {
                            events.push(AdapterEvent::SendFailed { link, error });
                        } else {
                            events.push(AdapterEvent::TelemetryAccepted { link, advisory });
                        }
                    }
                }
                MeshOutput::TelemetryBroadcast {
                    channel,
                    payload,
                    advisory,
                } => {
                    let opts = Self::telemetry_opts(network_now, advisory);
                    let links: Vec<LinkId> = self
                        .network
                        .links()
                        .into_iter()
                        .map(|info| info.link)
                        .collect();
                    for link in links {
                        let Some(sealed) = self.maybe_seal(
                            link,
                            channel,
                            payload.clone(),
                            sessions.as_deref_mut(),
                            &mut events,
                        ) else {
                            continue;
                        };
                        match self
                            .network
                            .send_opts(network_now, link, channel, sealed, opts)
                        {
                            Err(error) => events.push(AdapterEvent::SendFailed { link, error }),
                            Ok(()) => {
                                events.push(AdapterEvent::TelemetryAccepted { link, advisory })
                            }
                        }
                    }
                }
                MeshOutput::Release { link, reason } => {
                    self.network.disconnect(network_now, link, reason)
                }
                MeshOutput::SetHello { tag, app_hello } => {
                    self.network.set_local_hello(tag, app_hello)
                }
                MeshOutput::SetLinkHint { peer, preference } => {
                    self.network.set_link_hint(peer, preference);
                }
                MeshOutput::ClearLinkHint { peer } => {
                    let _ = self.network.clear_link_hint(peer);
                }
                MeshOutput::SetBeacon {
                    hint,
                    digest,
                    flags,
                } => self.network.set_beacon(hint, digest, flags),
                MeshOutput::ReleaseOpportunistic { link } => {
                    self.network.release(network_now, link)
                }
                MeshOutput::SyncNeed { link, prefixes } => {
                    events.push(AdapterEvent::SyncNeed { link, prefixes })
                }
                MeshOutput::SyncItem {
                    id,
                    wire,
                    copies_left,
                } => events.push(AdapterEvent::SyncItem {
                    id,
                    wire,
                    copies_left,
                }),
                MeshOutput::Deliver { header, payload } => {
                    events.push(AdapterEvent::Deliver { header, payload })
                }
                MeshOutput::ChannelDeliver {
                    channel_id,
                    header,
                    payload,
                } => events.push(AdapterEvent::ChannelDeliver {
                    channel_id,
                    header,
                    payload,
                }),
                MeshOutput::Purge { id } => events.push(AdapterEvent::Purge { id }),
                MeshOutput::Delivered { id, origin, by } => {
                    events.push(AdapterEvent::Delivered { id, origin, by })
                }
                MeshOutput::CardFetch { node_id, card_hash } => {
                    events.push(AdapterEvent::CardFetch { node_id, card_hash })
                }
                MeshOutput::DirectoryChanged { changes } => {
                    events.push(AdapterEvent::DirectoryChanged { changes })
                }
            }
        }
        events
    }
    /// Pumps one network event into the engine in cleartext mode. Ready with
    /// no host events still means one input was processed; Pending registers
    /// the transport waker. `identity` is borrowed only when a Data event
    /// needs MSH-09's pipeline; the engine retains no key.
    pub fn poll_event(
        &mut self,
        cx: &mut Context<'_>,
        network_now: Duration,
        mesh_now_ms: u64,
        identity: &Identity,
    ) -> Poll<Result<Vec<AdapterEvent>, MeshError>> {
        let event = match self.network.poll_event(cx, network_now) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(event) => event,
        };
        Poll::Ready(self.handle_network_event(network_now, mesh_now_ms, identity, None, event))
    }

    /// Pumps one network event with the host-owned hop sessions borrowed for
    /// this call (MSH-26). Control frames become host handshake events; Data
    /// frames on an active link are opened before the engine sees them and
    /// engine outputs are sealed per neighbour before they reach the radio.
    pub fn poll_event_with_hop(
        &mut self,
        cx: &mut Context<'_>,
        network_now: Duration,
        mesh_now_ms: u64,
        identity: &Identity,
        sessions: &mut HopSessions,
    ) -> Poll<Result<Vec<AdapterEvent>, MeshError>> {
        let event = match self.network.poll_event(cx, network_now) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(event) => event,
        };
        Poll::Ready(self.handle_network_event(
            network_now,
            mesh_now_ms,
            identity,
            Some(sessions),
            event,
        ))
    }

    /// Which side writes the first Noise message. aoNetwork's link role is
    /// the authoritative answer; never guess from neighbour ordering.
    fn hop_initiator(&self, link: LinkId) -> Option<bool> {
        self.network
            .links()
            .into_iter()
            .find(|info| info.link == link)
            .map(|info| info.role == LinkRole::Initiator)
    }

    /// Converts one already-polled network event into an engine input and
    /// applies the resulting outputs. `sessions` is `None` only for the
    /// cleartext facade; an active hop link with `None` is an error event,
    /// never a cleartext fallback.
    fn handle_network_event(
        &mut self,
        network_now: Duration,
        mesh_now_ms: u64,
        identity: &Identity,
        mut sessions: Option<&mut HopSessions>,
        event: NetworkEvent,
    ) -> Result<Vec<AdapterEvent>, MeshError> {
        let up = match &event {
            NetworkEvent::LinkUp { link, .. } => Some(*link),
            _ => None,
        };
        let ended = match &event {
            NetworkEvent::LinkDown { link, .. } => {
                self.engine.hop_peer(*link).map(|(peer, _)| (*link, peer))
            }
            _ => None,
        };
        let plaintext: Vec<u8>;
        let input = match &event {
            NetworkEvent::LinkUp { link, remote_hello } => MeshInput::LinkUp {
                link: *link,
                remote_hello: remote_hello.clone(),
            },
            NetworkEvent::LinkDown { link, reason } => MeshInput::LinkDown {
                link: *link,
                reason: *reason,
            },
            NetworkEvent::Data {
                link,
                channel: Channel::Control,
                payload,
            } => {
                if !self.engine.hop_negotiated(*link) {
                    return Ok(Vec::new());
                }
                let message = match decode_control(payload) {
                    Ok(message) => message,
                    Err(error) => {
                        return Ok(vec![AdapterEvent::HopFrameInvalid { link: *link, error }]);
                    }
                };
                let (Some((peer, card_hash)), Some(initiator)) =
                    (self.engine.hop_peer(*link), self.hop_initiator(*link))
                else {
                    return Ok(Vec::new());
                };
                return Ok(vec![AdapterEvent::HopControl {
                    link: *link,
                    peer,
                    card_hash,
                    initiator,
                    message: message.to_vec(),
                }]);
            }
            NetworkEvent::Data {
                link,
                channel,
                payload,
            } if self.engine.hop_active(*link) => {
                let Some(active) = sessions.as_deref_mut() else {
                    return Ok(vec![AdapterEvent::HopFailed {
                        link: *link,
                        error: HopAdapterError::SessionNotSupplied(*link),
                    }]);
                };
                let Some((peer, _)) = self.engine.hop_peer(*link) else {
                    return Ok(vec![AdapterEvent::HopFailed {
                        link: *link,
                        error: HopAdapterError::NoVerifiedPeer(*link),
                    }]);
                };
                plaintext = match active.open_frame(peer, payload) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        return Ok(vec![AdapterEvent::HopFailed {
                            link: *link,
                            error: HopAdapterError::Open(error),
                        }]);
                    }
                };
                MeshInput::Data {
                    link: *link,
                    channel: *channel,
                    payload: &plaintext,
                    identity,
                }
            }
            NetworkEvent::Data {
                link,
                channel,
                payload,
            } => MeshInput::Data {
                link: *link,
                channel: *channel,
                payload,
                identity,
            },
            // Future network events are observable progress but have no engine effect yet.
            _ => return Ok(Vec::new()),
        };
        let outputs = self.engine.handle(mesh_now_ms, input)?;
        let mut events = self.apply_inner(network_now, outputs, sessions);
        if let Some(link) = up {
            if let (Some((peer, card_hash)), Some(initiator)) =
                (self.engine.hop_peer(link), self.hop_initiator(link))
            {
                events.push(AdapterEvent::HopStart {
                    link,
                    peer,
                    card_hash,
                    initiator,
                });
            }
        }
        if let Some((link, peer)) = ended {
            events.push(AdapterEvent::HopEnded { link, peer });
        }
        Ok(events)
    }

    /// Future wrapper for a single polling interval in cleartext mode.
    /// Timestamps are fixed for its lifetime: cancel it at next_deadline and
    /// recreate with fresh time. `identity` has the same meaning as in
    /// [`Self::poll_event`].
    pub async fn next_event(
        &mut self,
        network_now: Duration,
        mesh_now_ms: u64,
        identity: &Identity,
    ) -> Result<Vec<AdapterEvent>, MeshError> {
        poll_fn(|cx| self.poll_event(cx, network_now, mesh_now_ms, identity)).await
    }

    /// Future wrapper for [`Self::poll_event_with_hop`] with the same fixed
    /// timestamps and host-owned session borrow.
    pub async fn next_event_with_hop(
        &mut self,
        network_now: Duration,
        mesh_now_ms: u64,
        identity: &Identity,
        sessions: &mut HopSessions,
    ) -> Result<Vec<AdapterEvent>, MeshError> {
        poll_fn(|cx| self.poll_event_with_hop(cx, network_now, mesh_now_ms, identity, sessions))
            .await
    }
}
