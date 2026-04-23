//! Two-layer AEAD (ChaCha20-Poly1305) with per-epoch wrapper key ratchet.
//!
//! Each DHT record is encrypted under a fresh 32-byte one-time key `k_r`
//! sampled at write time. `k_r` is then wrapped under a seq-ratcheted
//! wrapper key derived from the slot's master `W_k`:
//!
//! ```text
//! e         = seq / E                                # epoch number
//! W_k^(e)   = HKDF-Expand(W_k, "epoch" || be64(e))   # per-epoch wrapper
//! wrap_ct   = ChaCha20Poly1305(W_k^(e), wrap_nonce, k_r)
//! body_ct   = ChaCha20Poly1305(k_r, zeros(12), entries)   # nonce=0 is safe;
//!                                                         # k_r is one-shot
//! ```
//!
//! A reader observes `seq` alongside the record, derives `e` identically,
//! unwraps `k_r`, then decrypts the body. `k_r` is zeroized after both
//! encryption and decryption.
//!
//! The only per-slot long-lived secret is `W_k`. Epoch boundaries rotate
//! the effective wrapper; per-record isolation comes from the fresh
//! `k_r` + independent `wrap_nonce` per write.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{Error, Result};

pub(crate) const WRAP_NONCE_LEN: usize = 12;
pub(crate) const WRAP_CT_LEN: usize = 32; // one-time key k_r
pub(crate) const WRAP_TAG_LEN: usize = 16; // Poly1305 tag
pub(crate) const BODY_TAG_LEN: usize = 16; // Poly1305 tag
pub(crate) const BODY_NONCE: [u8; 12] = [0; 12];

pub(crate) const WRAP_HEADER_LEN: usize = WRAP_NONCE_LEN + WRAP_CT_LEN + WRAP_TAG_LEN; // 60

/// Compute epoch `e` for a given sequence number.
///
/// `< 0` vs `<= 0` at the branch is an equivalent mutant: at `seq == 0`
/// the if-branch produces `0u64`, the else-branch produces `0 as u64 = 0` —
/// both 0. The function is correctness-tested by `crypto::tests::epoch_*`
/// which cover negative, zero, and boundary values.
#[mutants::skip]
pub(crate) fn epoch_of(seq: i64, epoch_size: u64) -> u64 {
    debug_assert!(epoch_size > 0);
    let s = if seq < 0 { 0u64 } else { seq as u64 };
    s / epoch_size
}

/// Derive the per-epoch wrapper key `W_k^(e)` from slot master `W_k`.
fn derive_epoch_key(wk: &[u8; 32], e: u64) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::from_prk(wk).unwrap_or_else(|_| Hkdf::<Sha256>::new(None, wk));
    let mut info = [0u8; 5 + 8];
    info[..5].copy_from_slice(b"epoch");
    info[5..].copy_from_slice(&e.to_be_bytes());
    let mut out = [0u8; 32];
    // SAFETY: 32-byte expand is always within HKDF-SHA256's budget.
    #[allow(clippy::expect_used)]
    hk.expand(&info, &mut out)
        .expect("HKDF 32-byte output cannot fail");
    out
}

/// Encrypt a plaintext entry-buffer under slot master `W_k` at sequence `seq`.
/// Returns the on-wire envelope bytes (nonce ‖ wrap_ct_with_tag ‖ body_ct_with_tag).
pub(crate) fn seal(wk: &[u8; 32], plaintext: &[u8], seq: i64, epoch_size: u64) -> Result<Vec<u8>> {
    let e = epoch_of(seq, epoch_size);
    let mut w_e = derive_epoch_key(wk, e);

    // Fresh one-time body key + wrap nonce. `rand::rng()` returns a
    // thread-local CSPRNG seeded from the OS.
    let mut rng = rand::rng();
    let mut k_r = [0u8; 32];
    rng.fill_bytes(&mut k_r);
    let mut wrap_nonce = [0u8; WRAP_NONCE_LEN];
    rng.fill_bytes(&mut wrap_nonce);

    let wrap_cipher = ChaCha20Poly1305::new(Key::from_slice(&w_e));
    let wrap_out = wrap_cipher
        .encrypt(
            Nonce::from_slice(&wrap_nonce),
            Payload {
                msg: &k_r,
                aad: b"",
            },
        )
        .map_err(|_| Error::Crypto("wrap encrypt failed"))?;
    debug_assert_eq!(wrap_out.len(), WRAP_CT_LEN + WRAP_TAG_LEN);

    // Body: one-shot key with zero nonce.
    let body_cipher = ChaCha20Poly1305::new(Key::from_slice(&k_r));
    let body_out = body_cipher
        .encrypt(
            Nonce::from_slice(&BODY_NONCE),
            Payload {
                msg: plaintext,
                aad: b"",
            },
        )
        .map_err(|_| Error::Crypto("body encrypt failed"))?;

    // Zeroize ephemeral keys.
    k_r.zeroize();
    w_e.zeroize();

    let mut out = Vec::with_capacity(WRAP_HEADER_LEN + body_out.len());
    out.extend_from_slice(&wrap_nonce);
    out.extend_from_slice(&wrap_out);
    out.extend_from_slice(&body_out);
    Ok(out)
}

/// Inverse of [`seal`]. Returns the decrypted plaintext.
pub(crate) fn open(wk: &[u8; 32], envelope: &[u8], seq: i64, epoch_size: u64) -> Result<Vec<u8>> {
    if envelope.len() < WRAP_HEADER_LEN + BODY_TAG_LEN {
        return Err(Error::MalformedRecord("envelope too short"));
    }
    let (wrap_nonce, rest) = envelope.split_at(WRAP_NONCE_LEN);
    let (wrap_ct, body_ct) = rest.split_at(WRAP_CT_LEN + WRAP_TAG_LEN);

    let e = epoch_of(seq, epoch_size);
    let mut w_e = derive_epoch_key(wk, e);

    let wrap_cipher = ChaCha20Poly1305::new(Key::from_slice(&w_e));
    let mut k_r_vec = wrap_cipher
        .decrypt(
            Nonce::from_slice(wrap_nonce),
            Payload {
                msg: wrap_ct,
                aad: b"",
            },
        )
        .map_err(|_| Error::Crypto("wrap decrypt failed"))?;
    if k_r_vec.len() != WRAP_CT_LEN {
        k_r_vec.zeroize();
        return Err(Error::Crypto("wrapped key wrong size"));
    }
    let mut k_r = [0u8; 32];
    k_r.copy_from_slice(&k_r_vec);
    k_r_vec.zeroize();

    let body_cipher = ChaCha20Poly1305::new(Key::from_slice(&k_r));
    let plaintext = body_cipher
        .decrypt(
            Nonce::from_slice(&BODY_NONCE),
            Payload {
                msg: body_ct,
                aad: b"",
            },
        )
        .map_err(|_| Error::Crypto("body decrypt failed"))?;

    k_r.zeroize();
    w_e.zeroize();
    Ok(plaintext)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        // A non-trivial fixed test key.
        let mut k = [0u8; 32];
        for (i, byte) in k.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        k
    }

    #[test]
    fn roundtrip_basic() {
        let wk = key();
        let pt = b"hello, swarm!";
        let ct = seal(&wk, pt, 1, 64).unwrap();
        let back = open(&wk, &ct, 1, 64).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn roundtrip_empty_plaintext() {
        let wk = key();
        let ct = seal(&wk, b"", 0, 64).unwrap();
        let back = open(&wk, &ct, 0, 64).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn two_seals_differ() {
        // Same plaintext + key + seq → different ciphertexts (fresh k_r + nonce).
        let wk = key();
        let pt = b"same data";
        let a = seal(&wk, pt, 5, 64).unwrap();
        let b = seal(&wk, pt, 5, 64).unwrap();
        assert_ne!(a, b, "nondeterministic encryption");
    }

    #[test]
    fn wrong_seq_epoch_breaks_decrypt() {
        // At epoch E=64, seq=63 (e=0) and seq=64 (e=1) are different epochs.
        let wk = key();
        let pt = b"hello";
        let ct = seal(&wk, pt, 63, 64).unwrap();
        // Decrypting with an epoch-mismatched seq must fail.
        assert!(open(&wk, &ct, 64, 64).is_err());
    }

    #[test]
    fn tampered_envelope_fails() {
        let wk = key();
        let pt = b"hello";
        let mut ct = seal(&wk, pt, 1, 64).unwrap();
        let last_idx = ct.len() - 1;
        ct[last_idx] ^= 0x01;
        assert!(open(&wk, &ct, 1, 64).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let wk = key();
        let mut other = wk;
        other[0] ^= 0x01;
        let ct = seal(&wk, b"hello", 1, 64).unwrap();
        assert!(open(&other, &ct, 1, 64).is_err());
    }

    #[test]
    fn epoch_boundary() {
        assert_eq!(epoch_of(0, 64), 0);
        assert_eq!(epoch_of(63, 64), 0);
        assert_eq!(epoch_of(64, 64), 1);
        assert_eq!(epoch_of(127, 64), 1);
        assert_eq!(epoch_of(128, 64), 2);
        assert_eq!(epoch_of(-5, 64), 0, "negative seq folds to epoch 0");
    }

    #[test]
    fn within_epoch_interop() {
        // Two writes at the same epoch are decryptable by the same code path.
        let wk = key();
        let pt_a = b"first";
        let pt_b = b"second";
        let ct_a = seal(&wk, pt_a, 10, 64).unwrap();
        let ct_b = seal(&wk, pt_b, 11, 64).unwrap();
        assert_eq!(open(&wk, &ct_a, 10, 64).unwrap(), pt_a);
        assert_eq!(open(&wk, &ct_b, 11, 64).unwrap(), pt_b);
    }

    #[test]
    fn epoch_rotation_boundary_seq_e_minus_one_and_e() {
        const E: u64 = 8; // small E to make the boundary close
        // PROTOCOL.md §3: writers + readers use e = floor(seq / E). Writes
        // at seq = E-1 (epoch 0) and seq = E (epoch 1) use different wrapper
        // keys. Both must round-trip under their respective seqs.
        let wk = key();

        let last_of_epoch0 = seal(&wk, b"old-epoch", (E - 1) as i64, E).unwrap();
        let first_of_epoch1 = seal(&wk, b"new-epoch", E as i64, E).unwrap();

        // Each decrypts under its own seq.
        assert_eq!(
            open(&wk, &last_of_epoch0, (E - 1) as i64, E).unwrap(),
            b"old-epoch"
        );
        assert_eq!(
            open(&wk, &first_of_epoch1, E as i64, E).unwrap(),
            b"new-epoch"
        );

        // Cross-epoch reads must fail: decrypting last_of_epoch0 with seq=E
        // uses the epoch-1 wrapper and produces an AEAD auth failure.
        assert!(
            open(&wk, &last_of_epoch0, E as i64, E).is_err(),
            "reader at epoch 1 must NOT decrypt an epoch-0 record"
        );
        assert!(
            open(&wk, &first_of_epoch1, (E - 1) as i64, E).is_err(),
            "reader at epoch 0 must NOT decrypt an epoch-1 record"
        );
    }

    #[test]
    fn epoch_seq_negative_folds_to_zero() {
        // PROTOCOL.md §3 documented behavior: negative seq folds to epoch 0.
        assert_eq!(epoch_of(i64::MIN, 64), 0);
        assert_eq!(epoch_of(-1, 64), 0);
        assert_eq!(epoch_of(-1_000_000, 1), 0);
    }

    #[test]
    fn kat_wrapper_format_is_stable() {
        // Known-Answer Test: lock the wrapper-key derivation format by
        // asserting that a fixed (wk, seq, plaintext) produces a ciphertext
        // whose non-random portion (body_ct after its 12-byte fixed nonce
        // contribution — which is zero — and the wrap header structure)
        // round-trips. We can't assert exact bytes because wrap_nonce +
        // k_r are random per-seal, but we CAN assert size and format.
        let wk = [0x42u8; 32];
        let ct = seal(&wk, b"x", 100, 64).unwrap();

        // Envelope size: 12 + 32 + 16 (wrap) + 1 + 16 (body_tag) = 77.
        assert_eq!(
            ct.len(),
            WRAP_NONCE_LEN + WRAP_CT_LEN + WRAP_TAG_LEN + 1 + BODY_TAG_LEN
        );

        // Roundtrip with the same seq + epoch_size.
        assert_eq!(open(&wk, &ct, 100, 64).unwrap(), b"x");
    }

    #[test]
    fn short_envelope_rejected() {
        // Envelopes shorter than the wrap header + body tag fail cleanly.
        let wk = key();
        let too_short = vec![0u8; 60]; // < WRAP_HEADER_LEN + BODY_TAG_LEN = 76
        assert!(open(&wk, &too_short, 0, 64).is_err());
    }

    #[test]
    fn constants_have_exact_expected_values() {
        // Kills arithmetic mutations (`+` → `-`) on WRAP_HEADER_LEN.
        // WRAP_HEADER_LEN = 12 + 32 + 16 = 60.
        assert_eq!(WRAP_NONCE_LEN, 12);
        assert_eq!(WRAP_CT_LEN, 32);
        assert_eq!(WRAP_TAG_LEN, 16);
        assert_eq!(BODY_TAG_LEN, 16);
        assert_eq!(WRAP_HEADER_LEN, 60, "derived constant locked: 12 + 32 + 16");
        assert_eq!(WRAP_HEADER_LEN, WRAP_NONCE_LEN + WRAP_CT_LEN + WRAP_TAG_LEN);
    }

    #[test]
    #[allow(clippy::panic)]
    fn envelope_exact_threshold_is_accepted() {
        // Kills the `+` → `-` mutation on line 114's `WRAP_HEADER_LEN + BODY_TAG_LEN`.
        // At exactly WRAP_HEADER_LEN + BODY_TAG_LEN bytes (76, an empty-plaintext
        // envelope), open() must parse past the length check — it'll fail the
        // AEAD decrypt but NOT return the "envelope too short" error.
        let wk = key();
        let at_threshold = vec![0u8; WRAP_HEADER_LEN + BODY_TAG_LEN];
        let err = open(&wk, &at_threshold, 0, 64).unwrap_err();
        match err {
            Error::MalformedRecord(msg) => {
                assert_ne!(
                    msg, "envelope too short",
                    "76-byte envelope should not be rejected as short"
                );
            }
            Error::Crypto(_) => {} // expected — AEAD auth fails
            other => panic!("unexpected error: {other:?}"),
        }

        // One byte short: must return "envelope too short".
        let one_short = vec![0u8; WRAP_HEADER_LEN + BODY_TAG_LEN - 1];
        let err = open(&wk, &one_short, 0, 64).unwrap_err();
        match err {
            Error::MalformedRecord(msg) => {
                assert_eq!(msg, "envelope too short");
            }
            other => panic!("expected MalformedRecord, got {other:?}"),
        }
    }

    #[test]
    fn epoch_of_seq_zero_is_epoch_zero() {
        // Kills `< 0` → `<= 0`: the difference is visible at seq=0.
        // With `<=`, seq=0 would fold to epoch 0 via the branch (still 0),
        // but seq=0 via the else branch also yields 0 — equivalent here.
        // Test separately: seq=1 with `<=` would NOT enter the branch
        // (since 1 > 0), but that's the same as current behavior.
        // The real mutation target is at seq=0 — only the `<` form takes
        // the `else` branch (correct). A `<=` mutation takes the `if`
        // branch at seq=0, yielding `0u64 / epoch_size = 0` — same result.
        //
        // So for `< 0 → <= 0`, the mutant is *semantically equivalent* at
        // the output level (both yield 0 for seq=0). But the intent of the
        // branch is to handle negatives only; we pin that via a negative
        // seq test which exercises the `if` branch.
        assert_eq!(epoch_of(0, 64), 0);
        assert_eq!(epoch_of(-1, 64), 0, "negative folds via the if branch");
        assert_eq!(epoch_of(-64, 64), 0);
        // At seq = -1, the `<=` mutant and the `<` original both enter the
        // if branch. At seq = 0, the `<` original takes else (`0 / 64 = 0`)
        // and the `<=` mutant takes if (`0u64 = 0`). Outputs match.
        //
        // This is an equivalent mutant; we accept that the mutation is
        // semantically equivalent and document it here. The function's
        // contract is preserved under both forms.
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn roundtrip_prop(
                pt in proptest::collection::vec(any::<u8>(), 0..512),
                seq in 0i64..1_000_000,
                epoch_size in 1u64..=256,
            ) {
                let wk = key();
                let ct = seal(&wk, &pt, seq, epoch_size).unwrap();
                let back = open(&wk, &ct, seq, epoch_size).unwrap();
                prop_assert_eq!(back, pt);
            }
        }
    }
}
