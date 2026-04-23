//! DHT abstraction.
#![allow(dead_code)]
//
//!
//! The rendezvous algorithm uses two primitives — read and write — against
//! named slots. This module models that with a [`DhtSlots`] trait and ships
//! two implementations: the production `mainline` DHT (public BitTorrent
//! network) and an in-memory store used by integration tests and the
//! simulator.
//!
//! The trait + types are exposed publicly via [`crate::sim`] (gated by the
//! `sim` feature) and [`crate::Builder::dht_backend`] (gated by the
//! `test-support` feature). Third-party DHT backends can implement
//! `DhtSlots`; the API is not covered by the stable semver commitment and
//! may shift between 0.x releases.

use async_trait::async_trait;

pub(crate) mod mainline;
pub(crate) mod memory;

/// A BEP 44 mutable-item address. We encode it as the 32-byte Ed25519 public
/// key of the slot; both the mainline and in-memory impls hash it into their
/// internal address form (SHA1 for mainline, or direct map key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlotKey(pub [u8; 32]);

/// BEP 44 monotonic sequence number. `i64` to match the mainline crate.
pub type Seq = i64;

/// A signed record, as read from the DHT. The `value` field holds the
/// two-layer AEAD envelope described in `PROTOCOL.md §3` — opaque to the
/// DHT transport layer.
#[derive(Debug, Clone)]
pub struct SlotRecord {
    pub value: Vec<u8>,
    pub seq: Seq,
    pub signature: [u8; 64],
}

/// Errors from DHT ops. The outer crate wraps these into [`crate::Error::Dht`].
#[derive(thiserror::Error, Debug)]
pub enum DhtError {
    #[error("dht transport error: {0}")]
    Transport(String),
    #[error("signature verification failed")]
    BadSignature,
}

/// Two primitives: read the latest value at a slot, and write a new value
/// (signed, with a monotonic sequence number).
#[async_trait]
pub trait DhtSlots: Send + Sync + 'static {
    /// Read the most recent record at `slot`. Returns `Ok(None)` if the slot
    /// is empty or nothing was retrieved in time.
    async fn read(&self, slot: SlotKey) -> Result<Option<SlotRecord>, DhtError>;

    /// Write `record` to `slot`. The caller has already signed it with the
    /// slot's signing key; we only transport it.
    async fn write(&self, slot: SlotKey, record: SlotRecord) -> Result<(), DhtError>;
}
