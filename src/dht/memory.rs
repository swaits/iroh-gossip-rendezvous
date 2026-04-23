//! In-memory [`DhtSlots`] for tests and the simulator.
#![allow(dead_code)]
//
//!
//! Semantics match the mainline BEP 44 subset we depend on:
//! * Signature-verified before accepting a write.
//! * Last-writer-wins at equal seq; lower seq is silently ignored.
//! * Read returns the most recent record or `None`.
//!
//! Not production: process-local, no network, no TTL.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ed25519_dalek::{Signature, VerifyingKey};

use super::{DhtError, DhtSlots, SlotKey, SlotRecord};

/// In-memory [`DhtSlots`](super::DhtSlots) for tests, simulator, and
/// third-party code. Semantics match the Mainline BEP 44 subset: LWW at
/// equal seq, signature-verified writes.
#[derive(Clone, Default)]
pub struct InMemoryDht {
    inner: Arc<Mutex<HashMap<SlotKey, SlotRecord>>>,
}

impl InMemoryDht {
    /// Construct an empty in-memory DHT.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many slots have records right now. Test helper.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }
}

/// Verify signature. Mainline signs the BEP 44 tuple `(seq, salt?, value)`;
/// for the in-memory impl we use a simpler canonicalization: `(seq_be, value)`.
/// Only the signing/verification code in this file needs to agree — this
/// path is never observable to callers of [`InMemoryDht`], they only pass
/// already-signed records through.
fn canonical_message(seq: i64, value: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + value.len());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(value);
    m
}

/// Sign a record for the in-memory DHT. Test + sim helper.
pub(crate) fn sign_record(
    signing: &ed25519_dalek::SigningKey,
    value: Vec<u8>,
    seq: i64,
) -> SlotRecord {
    use ed25519_dalek::Signer;
    let sig = signing.sign(&canonical_message(seq, &value)).to_bytes();
    SlotRecord {
        value,
        seq,
        signature: sig,
    }
}

#[async_trait]
impl DhtSlots for InMemoryDht {
    async fn read(&self, slot: SlotKey) -> Result<Option<SlotRecord>, DhtError> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| DhtError::Transport(e.to_string()))?;
        Ok(guard.get(&slot).cloned())
    }

    async fn write(&self, slot: SlotKey, record: SlotRecord) -> Result<(), DhtError> {
        // Verify signature.
        let vk = VerifyingKey::from_bytes(&slot.0).map_err(|_| DhtError::BadSignature)?;
        let sig = Signature::from_bytes(&record.signature);
        vk.verify_strict(&canonical_message(record.seq, &record.value), &sig)
            .map_err(|_| DhtError::BadSignature)?;

        let mut guard = self
            .inner
            .lock()
            .map_err(|e| DhtError::Transport(e.to_string()))?;
        match guard.get(&slot) {
            Some(existing) if existing.seq > record.seq => {
                // Lower seq → ignore silently (same as mainline LWW behavior).
            }
            _ => {
                guard.insert(slot, record);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key() -> SigningKey {
        let mut seed = [0u8; 32];
        seed[0] = 1;
        SigningKey::from_bytes(&seed)
    }

    fn pk(sk: &SigningKey) -> SlotKey {
        SlotKey(sk.verifying_key().to_bytes())
    }

    #[tokio::test]
    async fn read_empty() {
        let dht = InMemoryDht::new();
        let slot = SlotKey([0u8; 32]);
        assert!(dht.read(slot).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn write_then_read() {
        let dht = InMemoryDht::new();
        let sk = key();
        let slot = pk(&sk);
        let rec = sign_record(&sk, b"hello".to_vec(), 1);
        dht.write(slot, rec.clone()).await.unwrap();
        let got = dht.read(slot).await.unwrap().unwrap();
        assert_eq!(got.value, rec.value);
        assert_eq!(got.seq, rec.seq);
    }

    #[tokio::test]
    async fn bad_signature_rejected() {
        let dht = InMemoryDht::new();
        let sk = key();
        let slot = pk(&sk);
        let mut rec = sign_record(&sk, b"hello".to_vec(), 1);
        rec.signature[0] ^= 0x01;
        assert!(matches!(
            dht.write(slot, rec).await,
            Err(DhtError::BadSignature)
        ));
    }

    #[tokio::test]
    async fn higher_seq_overwrites_lower() {
        let dht = InMemoryDht::new();
        let sk = key();
        let slot = pk(&sk);
        dht.write(slot, sign_record(&sk, b"one".to_vec(), 1))
            .await
            .unwrap();
        dht.write(slot, sign_record(&sk, b"two".to_vec(), 2))
            .await
            .unwrap();
        assert_eq!(dht.read(slot).await.unwrap().unwrap().value, b"two");
    }

    #[tokio::test]
    async fn lower_seq_ignored() {
        let dht = InMemoryDht::new();
        let sk = key();
        let slot = pk(&sk);
        dht.write(slot, sign_record(&sk, b"new".to_vec(), 5))
            .await
            .unwrap();
        dht.write(slot, sign_record(&sk, b"old".to_vec(), 3))
            .await
            .unwrap();
        assert_eq!(dht.read(slot).await.unwrap().unwrap().value, b"new");
    }

    #[tokio::test]
    async fn equal_seq_lww() {
        // mainline allows equal-seq clobbers. We mirror that.
        let dht = InMemoryDht::new();
        let sk = key();
        let slot = pk(&sk);
        dht.write(slot, sign_record(&sk, b"first".to_vec(), 5))
            .await
            .unwrap();
        dht.write(slot, sign_record(&sk, b"second".to_vec(), 5))
            .await
            .unwrap();
        // At equal seq, latest write wins.
        assert_eq!(dht.read(slot).await.unwrap().unwrap().value, b"second");
    }

    #[tokio::test]
    async fn concurrent_writes_converge_cleanly() {
        // 50 parallel write tasks to the same slot. All either succeed or
        // get overwritten; the final state is some writer's record at a seq
        // ≥ the minimum submitted. No panics, no partial updates.
        let dht = InMemoryDht::new();
        let sk = key();
        let slot = pk(&sk);

        let mut handles = Vec::new();
        for i in 1..=50_i64 {
            let dht = dht.clone();
            let sk = sk.clone();
            handles.push(tokio::spawn(async move {
                let payload = format!("v{i}").into_bytes();
                dht.write(slot, sign_record(&sk, payload, i)).await
            }));
        }
        for h in handles {
            h.await.unwrap().unwrap();
        }

        // Final state must exist and have a seq in [1, 50].
        let final_rec = dht.read(slot).await.unwrap().unwrap();
        assert!(
            final_rec.seq >= 1 && final_rec.seq <= 50,
            "seq out of range: {}",
            final_rec.seq
        );
    }

    #[tokio::test]
    async fn max_i64_seq_accepted() {
        // Writes at i64::MAX are accepted; nothing smaller can overwrite.
        let dht = InMemoryDht::new();
        let sk = key();
        let slot = pk(&sk);
        dht.write(slot, sign_record(&sk, b"max".to_vec(), i64::MAX))
            .await
            .unwrap();
        // Attempt to overwrite with a lower seq — silently ignored per LWW.
        dht.write(slot, sign_record(&sk, b"lower".to_vec(), 100))
            .await
            .unwrap();
        assert_eq!(dht.read(slot).await.unwrap().unwrap().value, b"max");
    }
}
