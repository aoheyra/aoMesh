//! The routing and store-and-forward engine of the aoheyra mesh.
//!
//! The core is **sans-IO**: [`MeshEngine::handle`] takes `(now, input)` and
//! returns outputs; time and randomness are injected, nothing reads a clock,
//! global RNG, threads or sockets. Async glue lives behind the `adapter`
//! feature and needs no runtime dependency.
//!
//! The engine deals in packet classes and opaque payload bytes; it never
//! interprets the app schema (that belongs to `aoheyra`) and never does
//! identity work (that belongs to `ao_idents`).
//!
//! MSH-06 adds signed submissions, bounded neighbour bookkeeping and the
//! optional network adapter. Forwarding and local delivery arrive in MSH-08/09.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "adapter")]
pub mod adapter;
pub mod engine;
pub mod neighbor;
pub mod packet;
pub mod seen;
pub mod sign;
pub mod store;

#[cfg(feature = "adapter")]
pub use adapter::{AdapterEvent, NetworkAdapter};
pub use engine::{MeshEngine, MeshError, MeshInput, MeshOutput};
pub use neighbor::{MeshConfig, Neighbor, NeighborTable};
pub use packet::{Header, MessageId, Packet, PacketClass, PacketError, SIGNATURE_LEN};
pub use seen::{Offer, SeenCache, SeenConfig};
pub use sign::{
    RelayOutcome, VerifyError, derive_msg_id, sign_packet, verify_for_relay, verify_origin,
};
