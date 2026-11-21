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
//! debounced four-byte digest through aoNetwork's beacon. MSH-19 signs
//! presence announcements; MSH-20 keeps a bounded, ephemeral node directory
//! from typed presence observations, whose coalesced changes are UI events
//! and never wire bytes. MSH-21 derives bounded reverse-path hints from
//! those directory observations and uses a fresh one to steer a Direct spray
//! copy. MSH-22 frames bounded latest-wins telemetry under the existing
//! class and passes typed coalescing advice to aoNetwork. MSH-23 carries
//! public channels as a bounded envelope inside signed Broadcast payloads:
//! subscriptions stay local, relays keep no subscription state, and the
//! channel key reuses MSH-10's bucket table and MSH-11's suppression. MSH-28
//! bounds every decoder and host-supplied stream; `tests/resource_bounds.rs`
//! and the `fuzz/` targets check those limits without changing the sans-IO
//! core. MSH-29 snapshots the bounded seen-cache, immunity list and spray
//! tickets so a restart cannot re-relay traffic the node already handled.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "adapter")]
pub mod adapter;
pub mod budget;
pub mod channel;
mod deliver;
pub mod directory;
pub mod engine;
pub mod expiry;
mod forward;
pub mod hello;
pub mod neighbor;
pub mod packet;
pub mod presence;
pub mod receipt;
pub mod routehint;
pub mod seen;
pub mod sign;
#[cfg(feature = "sim")]
pub mod sim;
pub mod snapshot;
pub mod spray;
pub mod store;
pub mod suppress;
pub mod sync;
pub mod telemetry;

#[cfg(feature = "adapter")]
pub use adapter::{AdapterEvent, NetworkAdapter};
pub use budget::{BudgetConfig, BudgetOutcome, BudgetTracker, ClassRate};
pub use channel::{
    CHANNEL_HEADER_LEN, CHANNEL_ID_LEN, CHANNEL_MAGIC, CHANNEL_VERSION, ChannelBudgetScope,
    ChannelConfig, ChannelEnvelope, ChannelError, ChannelId, ChannelRules, MAX_CHANNEL_NAME_LEN,
    MAX_CHANNEL_SUBSCRIPTIONS, derive_channel_id,
};
pub use directory::{
    DirectoryChange, DirectoryConfig, DirectoryEntry, DirectoryError, DirectoryStats,
    NodeDirectory, NodeObservation,
};
pub use engine::{MeshEngine, MeshError, MeshInput, MeshOutput};
pub use hello::{
    CAP_PRESENCE_V1, CAP_RECEIPT_V1, CAP_SPRAY_V1, CAP_SYNC_V1, CAP_SYNC_V2, CAPS, HelloError,
    MeshHello,
};
pub use neighbor::{MeshConfig, Neighbor, NeighborTable};
pub use packet::{Header, MessageId, Packet, PacketClass, PacketError, SIGNATURE_LEN};
pub use presence::{
    ANNOUNCE_LEN, ANNOUNCE_MAGIC, ANNOUNCE_VERSION, Announcement, PresenceConfig, PresenceError,
    PresenceTracker, encode_announcement, verify_announcement,
};
pub use receipt::{RECEIPT_MAGIC, RECEIPT_VERSION, ReceiptConfig, ReceiptError, ReceiptTracker};
pub use routehint::{RouteHint, RouteHintConfig, RouteHintMode, RouteHintTable};
pub use seen::{Offer, SeenCache, SeenConfig};
pub use sign::{
    RelayOutcome, VerifyError, derive_msg_id, sign_packet, verify_for_relay, verify_origin,
    verify_origin_with_signing_pk,
};
pub use snapshot::{
    MAX_SNAPSHOT_LEN, SNAPSHOT_MAGIC, SNAPSHOT_VERSION, Snapshot, SnapshotError, SnapshotSection,
};
pub use spray::{MAX_COPIES, SPRAY_MAGIC, SPRAY_VERSION, SprayConfig, SprayError, SprayTracker};
pub use suppress::SuppressionConfig;
pub use sync::{
    BeaconTracker, MAX_FRAME_BODY_BYTES, MAX_SUMMARY_ENTRIES, RangeKey, RangeSummary,
    SHORT_ID_BYTES, SYNC_MAGIC, SYNC_V2_VERSION, SYNC_VERSION, StoreSummary, SummaryConfig,
    SyncConfig, SyncError, SyncFrame, SyncFrameV2, SyncOffer, SyncV2Error,
};
pub use telemetry::{
    CoalesceKey, DEFAULT_EXPIRY_MS, DEFAULT_HOP_LIMIT, DEFAULT_MAX_ENTRIES, DEFAULT_RATE_LIMIT_MS,
    TELEMETRY_PREFIX_LEN, TELEMETRY_VERSION, TelemetryAdvisory, TelemetryConfig, TelemetryError,
    TelemetryFrame, TelemetryKind, TelemetryTracker, coalesce_key,
};

// A signed hello must fit the opaque blob aoNetwork allows (NET-04's
// MAX_APP_HELLO); this fails at compile time if the layout ever grows.
const _: () = assert!(hello::HELLO_LEN <= ao_network::MAX_APP_HELLO);
