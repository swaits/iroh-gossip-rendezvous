//! Per-slot key derivation from passphrase + app salt.
//!
//! Everything is derived deterministically from `(passphrase, app_salt, K)` via
//! HKDF-SHA256. No wall clock or runtime state is involved: a node that boots
//! fresh can re-derive every key needed to read or write any slot.
//!
//! For each shard `k ∈ 0..K`:
//!   * `sk_k` (Ed25519 signing key) — signs `MutableItem` puts to slot `k`.
//!   * `pk_k` (Ed25519 verifying key) — the slot's DHT address base; readers
//!     verify `sk` signatures with this.
//!   * `W_k` (32-byte wrapper master key) — input to the per-epoch wrapper
//!     key ratchet used to protect record contents (see [`crate::crypto`]).
//!
//! The gossip topic id is derived from the same pair — one topic per
//! (passphrase, app_salt).

use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use iroh_gossip::TopicId;
use sha2::Sha256;
use zeroize::Zeroize;

/// Size of one wrapper master key.
pub(crate) const WRAPPER_KEY_LEN: usize = 32;

/// Per-slot keying material.
#[derive(Clone)]
pub(crate) struct SlotKeys {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
    /// Wrapper master key `W_k`. Kept raw (not wrapped in `Zeroizing`) because
    /// it needs to live as long as the `Rendezvous` handle does.
    pub wrapper: [u8; WRAPPER_KEY_LEN],
}

/// All keys derived from a passphrase + app salt.
pub(crate) struct PassphraseKeys {
    pub topic_id: TopicId,
    pub slots: Vec<SlotKeys>,
}

impl PassphraseKeys {
    /// Derive everything. `shards` is the K parameter; must be >= 1.
    ///
    /// The passphrase is zeroized from the intermediate HKDF input buffer
    /// after extraction. Caller-owned copies are the caller's concern.
    pub(crate) fn derive(passphrase: &str, app_salt: &str, shards: usize) -> Self {
        debug_assert!(shards >= 1, "shards must be >= 1");

        // HKDF-Extract(salt=app_salt_bytes, ikm=passphrase.as_bytes())
        // Buffer the ikm so we can zeroize after.
        let mut ikm: Vec<u8> = passphrase.as_bytes().to_vec();
        let hk = Hkdf::<Sha256>::new(Some(app_salt.as_bytes()), &ikm);
        ikm.zeroize();

        // Topic id: HKDF-Expand with info="topic", 32 bytes.
        let mut topic_bytes = [0u8; 32];
        // SAFETY: HKDF-Expand only errors if the output length exceeds
        // 255 * HashLen (255 * 32 = 8160 bytes for SHA-256). 32 bytes is safe.
        #[allow(clippy::expect_used)]
        hk.expand(b"topic", &mut topic_bytes)
            .expect("HKDF 32-byte output cannot fail");
        let topic_id = TopicId::from_bytes(topic_bytes);

        // Per-slot material.
        let mut slots = Vec::with_capacity(shards);
        for k in 0..shards {
            slots.push(derive_slot(&hk, k));
        }

        Self { topic_id, slots }
    }

    /// Total number of shards.
    #[cfg(test)]
    pub(crate) fn k(&self) -> usize {
        self.slots.len()
    }
}

/// Derive one slot's keys. Split out so the HKDF buffers are easy to zeroize.
fn derive_slot(hk: &Hkdf<Sha256>, k: usize) -> SlotKeys {
    // Info = "sk25519:" || be64(k), 32 bytes out = Ed25519 seed.
    let mut info_sk = Vec::with_capacity(8 + 8);
    info_sk.extend_from_slice(b"sk25519:");
    let k_be = (k as u64).to_be_bytes();
    info_sk.extend_from_slice(&k_be);
    let mut sk_seed = [0u8; 32];
    // SAFETY: 32 bytes is well under HKDF-SHA256's 255*32 output cap.
    #[allow(clippy::expect_used)]
    hk.expand(&info_sk, &mut sk_seed)
        .expect("HKDF 32-byte output cannot fail");
    let signing = SigningKey::from_bytes(&sk_seed);
    sk_seed.zeroize();
    let verifying = signing.verifying_key();

    // Info = "wrap:" || be64(k), 32 bytes out = W_k.
    let mut info_w = Vec::with_capacity(5 + 8);
    info_w.extend_from_slice(b"wrap:");
    info_w.extend_from_slice(&k_be);
    let mut wrapper = [0u8; WRAPPER_KEY_LEN];
    // SAFETY: 32 bytes is well under HKDF-SHA256's 255*32 output cap.
    #[allow(clippy::expect_used)]
    hk.expand(&info_w, &mut wrapper)
        .expect("HKDF 32-byte output cannot fail");

    SlotKeys {
        signing,
        verifying,
        wrapper,
    }
}

/// Which slot does a given endpoint ID (32-byte public key) write to?
/// `H(id) mod K` with `H = blake3`, per §3 of the design doc.
pub(crate) fn slot_for_id(id: &[u8; 32], shards: usize) -> usize {
    debug_assert!(shards >= 1);
    let hash = blake3::hash(id);
    let bytes = hash.as_bytes();
    // Fold 8 bytes of the blake3 output into a u64 and mod by K.
    let mut u = [0u8; 8];
    u.copy_from_slice(&bytes[..8]);
    let v = u64::from_le_bytes(u);
    (v % shards as u64) as usize
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let a = PassphraseKeys::derive("passphrase", "app/v1", 3);
        let b = PassphraseKeys::derive("passphrase", "app/v1", 3);
        assert_eq!(a.topic_id, b.topic_id);
        assert_eq!(a.k(), 3);
        for (sa, sb) in a.slots.iter().zip(b.slots.iter()) {
            assert_eq!(sa.signing.to_bytes(), sb.signing.to_bytes());
            assert_eq!(sa.verifying.to_bytes(), sb.verifying.to_bytes());
            assert_eq!(sa.wrapper, sb.wrapper);
        }
    }

    #[test]
    fn different_passphrase_different_keys() {
        let a = PassphraseKeys::derive("alpha", "app/v1", 3);
        let b = PassphraseKeys::derive("beta", "app/v1", 3);
        assert_ne!(a.topic_id, b.topic_id);
        assert_ne!(a.slots[0].signing.to_bytes(), b.slots[0].signing.to_bytes());
        assert_ne!(a.slots[0].wrapper, b.slots[0].wrapper);
    }

    #[test]
    fn different_app_salt_different_keys() {
        let a = PassphraseKeys::derive("passphrase", "app/v1", 3);
        let b = PassphraseKeys::derive("passphrase", "app/v2", 3);
        assert_ne!(a.topic_id, b.topic_id);
        assert_ne!(a.slots[0].signing.to_bytes(), b.slots[0].signing.to_bytes());
        assert_ne!(a.slots[0].wrapper, b.slots[0].wrapper);
    }

    #[test]
    fn slots_within_one_keyset_are_distinct() {
        let keys = PassphraseKeys::derive("passphrase", "app/v1", 4);
        // All sk, pk, and wrapper keys must be unique across slots.
        for i in 0..keys.k() {
            for j in (i + 1)..keys.k() {
                assert_ne!(
                    keys.slots[i].signing.to_bytes(),
                    keys.slots[j].signing.to_bytes()
                );
                assert_ne!(
                    keys.slots[i].verifying.to_bytes(),
                    keys.slots[j].verifying.to_bytes()
                );
                assert_ne!(keys.slots[i].wrapper, keys.slots[j].wrapper);
            }
        }
    }

    #[test]
    fn slot_for_id_uniform_ish() {
        // 10000 random IDs into 4 buckets: every bucket should be populated.
        let mut counts = [0usize; 4];
        for i in 0u32..10_000 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_le_bytes());
            counts[slot_for_id(&id, 4)] += 1;
        }
        for c in counts {
            assert!(c > 1500, "expected roughly 2500 per bucket, got {counts:?}");
        }
    }

    // ── Audit gap tests ───────────────────────────────────────────────

    #[test]
    fn keys_k_one_produces_single_slot() {
        let keys = PassphraseKeys::derive("p", "app/v1", 1);
        assert_eq!(keys.k(), 1);
        // Topic id derivation is independent of K but uses the same HKDF
        // source, so a K=1 and K=3 with the same passphrase share a topic.
        let k3 = PassphraseKeys::derive("p", "app/v1", 3);
        assert_eq!(keys.topic_id, k3.topic_id);
        // slot_for_id(id, 1) always returns 0.
        assert_eq!(slot_for_id(&[0xAA; 32], 1), 0);
        assert_eq!(slot_for_id(&[0x55; 32], 1), 0);
    }

    #[test]
    fn keys_k_large_all_distinct() {
        // K=256 — smoke test: every slot has a distinct signing + wrapper key.
        let keys = PassphraseKeys::derive("p", "app/v1", 256);
        assert_eq!(keys.k(), 256);
        let mut seen_signing = std::collections::HashSet::new();
        let mut seen_wrapper = std::collections::HashSet::new();
        for slot in &keys.slots {
            assert!(seen_signing.insert(slot.signing.to_bytes()));
            assert!(seen_wrapper.insert(slot.wrapper));
        }
    }

    #[test]
    fn keys_hkdf_kat_passphrase_abc_app_test_v1_k3() {
        // Known-Answer Test. Changing any HKDF info string, the salt/ikm
        // order, or the output length would change these bytes. This test
        // locks the derivation format so an accidental rewrite is caught
        // immediately.
        let keys = PassphraseKeys::derive("abc", "test/v1", 3);

        // Topic ID — HKDF-SHA256(salt=app_salt, ikm=passphrase) expand "topic".
        // Baselined from the current implementation; any change here means
        // a wire-format compat break that needs a major-version bump.
        let expected_topic_prefix: [u8; 8] = hex_literal::hex!("cec561e3e49b4c61");
        let topic_bytes = keys.topic_id.as_bytes();
        assert_eq!(
            &topic_bytes[..8],
            &expected_topic_prefix,
            "topic_id derivation format changed — was {topic_bytes:02x?}"
        );

        // Slot 0 signing key prefix.
        // Baselined from the current implementation.
        let slot0_sk = keys.slots[0].signing.to_bytes();
        let expected_sk0_prefix: [u8; 8] = hex_literal::hex!("5c58b94a1421f2ef");
        assert_eq!(
            &slot0_sk[..8],
            &expected_sk0_prefix,
            "slot-0 signing key derivation changed — was {slot0_sk:02x?}"
        );
    }
}
