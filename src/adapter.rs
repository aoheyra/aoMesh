//! Runtime-neutral async glue, usable from a Tokio-owned task without I/O in the core.
//!
//! The host owns time and wakeups. Race polling against a timer for
//! `next_deadline`, then poll again with fresh timestamps. No task is spawned
//! and no clock is read here. Network durations and mesh milliseconds are
//! explicit separate inputs; no wall-clock/monotonic conversion is guessed.

use crate::{MeshEngine, MeshError, MeshInput, MeshOutput};
use ao_idents::Identity;
use ao_network::{LinkId, Network, NetworkEvent, SendError, Transport};
use rand_core::RngCore;
use std::future::poll_fn;
use std::task::{Context, Poll};
use std::time::Duration;

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
    /// Inspect engine state without a second source of truth.
    pub fn engine(&self) -> &MeshEngine<R> {
        &self.engine
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
    /// Maps actions to the facade; errors and deliveries are returned, never swallowed.
    /// The adapter reads no clock: `network_now` is passed straight to
    /// every facade command that needs the time.
    pub fn apply(&mut self, network_now: Duration, outputs: Vec<MeshOutput>) -> Vec<AdapterEvent> {
        let mut events = Vec::new();
        for output in outputs {
            match output {
                MeshOutput::Send {
                    link,
                    channel,
                    payload,
                } => {
                    if let Err(error) = self.network.send(network_now, link, channel, payload) {
                        events.push(AdapterEvent::SendFailed { link, error });
                    }
                }
                MeshOutput::Broadcast { channel, payload } => {
                    events.extend(
                        self.network
                            .broadcast(network_now, channel, &payload)
                            .into_iter()
                            .map(|(link, error)| AdapterEvent::SendFailed { link, error }),
                    );
                }
                MeshOutput::Release { link, reason } => {
                    self.network.disconnect(network_now, link, reason)
                }
                MeshOutput::SetHello { tag, app_hello } => {
                    self.network.set_local_hello(tag, app_hello)
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
            }
        }
        events
    }
    /// Pumps one network event into the engine. Ready with no host events still
    /// means one input was processed; Pending registers the transport waker.
    /// `identity` is borrowed only when a Data event needs MSH-09's
    /// pipeline; the engine retains no key.
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
                channel,
                payload,
            } => MeshInput::Data {
                link: *link,
                channel: *channel,
                payload,
                identity,
            },
            // Future network events are observable progress but have no engine effect yet.
            _ => return Poll::Ready(Ok(Vec::new())),
        };
        Poll::Ready(self.handle(network_now, mesh_now_ms, input))
    }
    /// Future wrapper for a single polling interval. Timestamps are fixed for
    /// its lifetime: cancel it at next_deadline and recreate with fresh time.
    /// `identity` has the same meaning as in [`Self::poll_event`].
    pub async fn next_event(
        &mut self,
        network_now: Duration,
        mesh_now_ms: u64,
        identity: &Identity,
    ) -> Result<Vec<AdapterEvent>, MeshError> {
        poll_fn(|cx| self.poll_event(cx, network_now, mesh_now_ms, identity)).await
    }
}
