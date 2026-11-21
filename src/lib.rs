//! The routing and store-and-forward engine of the aoheyra mesh.
//!
//! The core is **sans-IO**: [`MeshEngine::handle`] takes `(now, input)` and
//! returns outputs; time and randomness are injected, nothing reads a clock,
//! global RNG, threads or sockets. Async glue lives behind the `adapter`
//! feature and needs no runtime dependency.
//!
//! The engine deals in packet classes and opaque payload bytes; it never
//! interprets the app schema (that belongs to `aoheyra`) and never
//! implements identity or crypto work (that belongs to `ao_idents`).
//!
//! MSH-06 adds signed submissions, bounded neighbour bookkeeping and the
//! optional network adapter. MSH-07 verifies the signed `MeshHello` on
//! link-up, so every admitted neighbour carries a derived `NodeId`.
//! MSH-08 relays Direct packets to every verified neighbour but the
//! sender and hands packets addressed to this node to MSH-09, which
//! opens the sealed payload against the local identity, binds the
//! seal's sender to `origin`, verifies the origin signature and runs
//! the replay guard before a `Deliver` is emitted. MSH-10 bounds
//! relays with per-origin and per-neighbour token buckets and
//! releases abusive links. MSH-11 suppresses Broadcast and Presence
//! floods with seeded assessment delays and neighbour copy counters.
//! MSH-13 canonicalises store ids into a compact summary and publishes a
//! debounced four-byte digest through aoNetwork's beacon.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "adapter")]
pub mod adapter;
pub mod budget;
mod deliver;
pub mod engine;
mod forward;
pub mod hello;
pub mod neighbor;
pub mod packet;
pub mod receipt;
pub mod seen;
pub mod sign;
#[cfg(feature = "sim")]
pub mod sim;
pub mod spray;
pub mod store;
pub mod suppress;
pub mod sync;

#[cfg(feature = "adapter")]
pub use adapter::{AdapterEvent, NetworkAdapter};
pub use budget::{BudgetConfig, BudgetOutcome, BudgetTracker, ClassRate};
pub use engine::{MeshEngine, MeshError, MeshInput, MeshOutput};
pub use hello::{
    CAP_RECEIPT_V1, CAP_SPRAY_V1, CAP_SYNC_V1, CAP_SYNC_V2, CAPS, HelloError, MeshHello,
};
pub use neighbor::{MeshConfig, Neighbor, NeighborTable};
pub use packet::{Header, MessageId, Packet, PacketClass, PacketError, SIGNATURE_LEN};
pub use receipt::{RECEIPT_MAGIC, RECEIPT_VERSION, ReceiptConfig, ReceiptError, ReceiptTracker};
pub use seen::{Offer, SeenCache, SeenConfig};
pub use sign::{
    RelayOutcome, VerifyError, derive_msg_id, sign_packet, verify_for_relay, verify_origin,
};
pub use spray::{MAX_COPIES, SPRAY_MAGIC, SPRAY_VERSION, SprayConfig, SprayError, SprayTracker};
pub use suppress::SuppressionConfig;
pub use sync::{
    BeaconTracker, RangeKey, RangeSummary, SHORT_ID_BYTES, SYNC_MAGIC, SYNC_V2_VERSION,
    SYNC_VERSION, StoreSummary, SummaryConfig, SyncConfig, SyncFrame, SyncFrameV2, SyncOffer,
};

// A signed hello must fit the opaque blob aoNetwork allows (NET-04's
// MAX_APP_HELLO); this fails at compile time if the layout ever grows.
const _: () = assert!(hello::HELLO_LEN <= ao_network::MAX_APP_HELLO);
