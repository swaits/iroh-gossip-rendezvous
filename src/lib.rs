//! # iroh-gossip-rendezvous
//!
//! Passphrase-based peer rendezvous for [`iroh-gossip`] swarms, using the
//! BitTorrent [Mainline DHT] as an out-of-band meeting place.
//!
//! Two nodes that share a passphrase and an application salt can find each
//! other and join the same gossip topic with no central bootstrap server and
//! no prior knowledge of each other's network address.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use iroh_gossip_rendezvous::Rendezvous;
//!
//! let rendezvous = Rendezvous::join("my-passphrase", "my-app/v1").await?;
//! rendezvous.broadcast(bytes::Bytes::from_static(b"hello")).await?;
//!
//! let mut receiver = rendezvous.subscribe();
//! while let Ok(event) = receiver.recv().await {
//!     // handle event (iroh_gossip::api::Event)
//!     drop(event);
//! }
//! # Ok(()) }
//! ```
//!
//! The algorithm is a clock-free variant of a HyParView-healing protocol with
//! K-sharded slots, logical aging, vouching, and a two-layer AEAD record
//! format. See `dht-partition-healing.md` in the repository for the design
//! specification and `examples/simulator.rs` for validation scaffolding.
//!
//! ## Lifetime
//!
//! The returned [`Rendezvous`] is the keep-alive anchor for the DHT
//! maintenance loops. Dropping it cancels the loops and the swarm will
//! slowly drift off the DHT as entries age out. Any [`iroh_gossip::api::GossipSender`]
//! or [`iroh_gossip::api::GossipReceiver`] extracted from the handle via
//! [`Rendezvous::sender`] or [`Rendezvous::subscribe`] must be dropped
//! before — or kept alongside — the [`Rendezvous`].
//!
//! [`iroh-gossip`]: https://docs.rs/iroh-gossip
//! [Mainline DHT]: https://en.wikipedia.org/wiki/Mainline_DHT

#![cfg_attr(docsrs, feature(doc_cfg))]

mod builder;
mod crypto;
mod dht;
mod error;
mod gossip_glue;
mod keys;
mod merge;
mod protocol;
mod rendezvous;
mod state;
mod wire;

#[cfg(feature = "sim")]
#[cfg_attr(docsrs, doc(cfg(feature = "sim")))]
#[allow(clippy::module_name_repetitions)]
mod sim_impl;

// Kani bounded-model-checking harnesses. Gated on the `kani` cfg (set
// automatically by `cargo kani`), so regular builds never see them.
#[cfg(kani)]
mod kani_proofs;

pub use builder::Builder;
pub use error::{Error, Result};
pub use rendezvous::Rendezvous;
pub use state::{DhtStatus, RendezvousState};

/// Algorithm defaults, one per `§2` parameter of [`PROTOCOL.md`].
///
/// All defaults are overridable via [`Builder`]. The constants are re-exported
/// here so callers (and the `tests/spec_drift.rs` consistency check) can
/// reference them without poking at private modules.
///
/// [`PROTOCOL.md`]: https://github.com/swaits/iroh-gossip-rendezvous/blob/main/PROTOCOL.md
pub mod defaults {
    pub use crate::builder::{
        DEFAULT_EPOCH_WRITES, DEFAULT_HEAL_PERIOD, DEFAULT_JITTER, DEFAULT_MAX_AGE,
        DEFAULT_MAX_ENTRIES, DEFAULT_MAX_VOUCHES, DEFAULT_SHARDS, DEFAULT_WRITE_PERIOD,
    };
}

/// Discrete-event simulator + DHT-backend surface.
///
/// Gated behind the `sim` feature flag. See [`sim::run`] and
/// [`sim::Scenario`] for the simulator entry points used by
/// `examples/simulator.rs`. [`sim::InMemoryDht`], [`sim::DhtSlots`],
/// [`sim::SlotKey`], [`sim::SlotRecord`], and [`sim::DhtError`] are
/// exposed here for third-party DHT backend implementations and for
/// integration tests that inject a custom backend via
/// [`Builder::dht_backend`] (under the `test-support` feature).
///
/// Not part of the stable public API; function signatures and item layout
/// may shift between `0.x` releases as simulation results move the defaults.
#[cfg(feature = "sim")]
#[cfg_attr(docsrs, doc(cfg(feature = "sim")))]
pub mod sim {
    pub use crate::sim_impl::{
        ENTRY_LEN, Entry, MAX_ENTRIES, Outcome, PubDhtError as DhtError, PubDhtSlots as DhtSlots,
        PubInMemoryDht as InMemoryDht, PubSlotKey as SlotKey, Scenario, SimConfig, SlotRecord,
        decode_entries, encode_entries, run,
    };
}
