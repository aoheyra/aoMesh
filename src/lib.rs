//! The routing and store-and-forward engine of the aoheyra mesh.
//!
//! The core is **sans-IO**: [`MeshEngine::handle`] takes `(now, input)` and
//! returns outputs; time and randomness are injected, nothing reads a clock,
//! global RNG, threads or sockets. `tokio` appears only behind the `adapter`
//! feature, never in this module.
//!
//! The engine deals in packet classes and opaque payload bytes; it never
//! interprets the app schema (that belongs to `aoheyra`) and never does
//! identity work (that belongs to `ao_idents`).
//!
//! M0 delivers the interface and a no-op loop; packet handling grows in
//! MSH-03 onward.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod engine;
pub mod packet;

pub use engine::{MeshEngine, MeshInput, MeshOutput};
