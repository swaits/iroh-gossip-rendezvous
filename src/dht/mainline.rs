//! Production [`DhtSlots`] over the public Mainline DHT.
#![allow(dead_code)]
//
//!
//! Wraps [`mainline::async_dht::AsyncDht`]. Uses BEP 44 mutable items with
//! distinct Ed25519 keys per slot (no BEP 44 `salt` field — different
//! `pk_k` give different addresses inherently).

use async_trait::async_trait;
use mainline::{MutableItem, SigningKey, async_dht::AsyncDht};

use super::{DhtError, DhtSlots, SlotKey, SlotRecord};

pub(crate) struct MainlineDht {
    dht: AsyncDht,
    /// Signing keys indexed by slot public key. Every write needs the
    /// corresponding secret. We re-use the caller's HKDF-derived keys.
    signers: Vec<(SlotKey, SigningKey)>,
}

impl MainlineDht {
    /// Create a new client. `signers` must contain the Ed25519 signing keys
    /// for every slot this node might write to.
    pub(crate) fn new(dht: AsyncDht, signers: Vec<(SlotKey, SigningKey)>) -> Self {
        Self { dht, signers }
    }

    fn signer_for(&self, slot: &SlotKey) -> Option<&SigningKey> {
        self.signers.iter().find(|(k, _)| k == slot).map(|(_, s)| s)
    }
}

#[async_trait]
impl DhtSlots for MainlineDht {
    async fn read(&self, slot: SlotKey) -> Result<Option<SlotRecord>, DhtError> {
        let item = self.dht.get_mutable_most_recent(&slot.0, None).await;
        Ok(item.map(|i| SlotRecord {
            value: i.value().to_vec(),
            seq: i.seq(),
            signature: *i.signature(),
        }))
    }

    async fn write(&self, slot: SlotKey, record: SlotRecord) -> Result<(), DhtError> {
        // Re-sign with mainline's BEP 44 canonical form — remote storing
        // nodes verify signatures against `3:seqi<seq>e1:v<len>:<value>`.
        // Our crate-internal signature format (seq_be || value) used by the
        // InMemoryDht would fail that verification, so we discard
        // `record.signature` here and let `MutableItem::new` re-sign.
        let Some(signer) = self.signer_for(&slot) else {
            return Err(DhtError::Transport("no signing key for slot".into()));
        };
        let item = MutableItem::new(signer.clone(), &record.value, record.seq, None);
        self.dht
            .put_mutable(item, None)
            .await
            .map_err(|e| DhtError::Transport(e.to_string()))?;
        Ok(())
    }
}
