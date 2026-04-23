//! BEP 44 record wire format.
//!
//! One **entry** is `(id: 32 B, age: 1 B)`. A record is an ordered list of
//! entries wrapped in the two-layer AEAD envelope described in the design
//! doc §3:
//!
//! ```text
//! ┌────────────┬────────────┬──────────┬──────────────┬──────────┐
//! │ wrap_nonce │ wrap_ct    │ wrap_tag │ entry₁ … ₙ   │ body_tag │
//! │  (12 B)    │  (32 B)    │  (16 B)  │  (33 B each) │  (16 B)  │
//! └────────────┴────────────┴──────────┴──────────────┴──────────┘
//! ```
//!
//! The envelope layer is provided by [`crate::crypto`]; this module only
//! handles the plaintext entry serialization and the byte-budget invariant.

use crate::{Error, Result};

/// Size of one serialized entry.
pub const ENTRY_LEN: usize = 32 + 1;

/// Max entries that fit under the 1000-byte BEP 44 `v` budget.
/// See PROTOCOL.md §3 for the arithmetic.
pub const MAX_ENTRIES: usize = 27;

/// One entry: `(endpoint_id, age)`. `id` is a 32-byte Ed25519 public key;
/// `age` is the logical age in `0..A_max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub id: [u8; 32],
    pub age: u8,
}

/// Serialize a slice of entries to the flat byte buffer that will be fed to
/// the body-AEAD. Caller must ensure `entries.len() <= MAX_ENTRIES`.
pub fn encode_entries(entries: &[Entry]) -> Vec<u8> {
    debug_assert!(entries.len() <= MAX_ENTRIES);
    let mut buf = Vec::with_capacity(entries.len() * ENTRY_LEN);
    for entry in entries {
        buf.extend_from_slice(&entry.id);
        buf.push(entry.age);
    }
    buf
}

/// Parse entries from a flat byte buffer (the plaintext that came out of
/// the body-AEAD). Returns an error on length misalignment.
pub fn decode_entries(bytes: &[u8]) -> Result<Vec<Entry>> {
    if !bytes.len().is_multiple_of(ENTRY_LEN) {
        return Err(Error::MalformedRecord(
            "entry buffer not a multiple of 33 bytes",
        ));
    }
    let n = bytes.len() / ENTRY_LEN;
    if n > MAX_ENTRIES {
        return Err(Error::MalformedRecord("too many entries (> 27)"));
    }
    let mut out = Vec::with_capacity(n);
    for chunk in bytes.chunks_exact(ENTRY_LEN) {
        let mut id = [0u8; 32];
        id.copy_from_slice(&chunk[..32]);
        let age = chunk[32];
        out.push(Entry { id, age });
    }
    Ok(out)
}

/// Compute the total byte-size of the outer envelope (for budget checks).
///
/// Layout: `wrap_nonce(12) + wrap_ct(32) + wrap_tag(16) + n * ENTRY_LEN + body_tag(16)`.
#[cfg(test)]
pub(crate) const fn envelope_size(n_entries: usize) -> usize {
    12 + 32 + 16 + n_entries * ENTRY_LEN + 16
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn entry_roundtrip() {
        let entries = vec![
            Entry {
                id: [0xAA; 32],
                age: 0,
            },
            Entry {
                id: [0xBB; 32],
                age: 5,
            },
            Entry {
                id: [0xCC; 32],
                age: 26,
            },
        ];
        let encoded = encode_entries(&entries);
        assert_eq!(encoded.len(), 3 * ENTRY_LEN);
        let decoded = decode_entries(&encoded).unwrap();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn empty_entries_roundtrip() {
        let encoded = encode_entries(&[]);
        assert_eq!(encoded.len(), 0);
        let decoded = decode_entries(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn misaligned_input_is_error() {
        let bytes = vec![0u8; 32]; // short by one byte
        assert!(decode_entries(&bytes).is_err());
    }

    #[test]
    fn too_many_entries_is_error() {
        let bytes = vec![0u8; ENTRY_LEN * (MAX_ENTRIES + 1)];
        assert!(decode_entries(&bytes).is_err());
    }

    #[test]
    fn wire_age_boundary_values_roundtrip() {
        // age=0 (freshest) and age=255 (u8::MAX) roundtrip unchanged.
        let entries = vec![
            Entry {
                id: [0xAA; 32],
                age: 0,
            },
            Entry {
                id: [0xBB; 32],
                age: 255,
            },
        ];
        let encoded = encode_entries(&entries);
        let decoded = decode_entries(&encoded).unwrap();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn wire_entry_order_is_preserved() {
        // Encode/decode must not reorder entries. Construct 5 entries with
        // recognizable prefixes and verify exact output order.
        let entries: Vec<Entry> = (1..=5)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i;
                Entry { id, age: i }
            })
            .collect();
        let encoded = encode_entries(&entries);
        let decoded = decode_entries(&encoded).unwrap();
        for (expected, actual) in entries.iter().zip(decoded.iter()) {
            assert_eq!(expected.id[0], actual.id[0]);
            assert_eq!(expected.age, actual.age);
        }
    }

    #[test]
    fn envelope_at_max_entries_fits_bep44_budget() {
        // BEP 44 permits the bencoded `v` field up to 1000 bytes. A byte
        // string of length N bencodes as "<ascii-N>:" + N bytes.
        let bencoded = |n: usize| {
            let prefix = format!("{n}:").len();
            prefix + n
        };

        // At MAX_ENTRIES=27 the plaintext envelope is 967 bytes; bencoded =
        // "967:" + 967 = 971 bytes — under the 1000-byte cap.
        let at_max = envelope_size(MAX_ENTRIES);
        assert_eq!(at_max, 967);
        assert!(
            bencoded(at_max) <= 1000,
            "27 entries bencoded should fit; got {}",
            bencoded(at_max)
        );

        // 28 entries produces a 1000-byte envelope exactly, which bencodes
        // to "1000:" + 1000 = 1005 bytes — over the cap.
        let over = envelope_size(MAX_ENTRIES + 1);
        assert_eq!(over, 1000);
        assert!(
            bencoded(over) > 1000,
            "28 entries bencoded must overflow; got {}",
            bencoded(over)
        );
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn entries_roundtrip_prop(n in 0usize..=MAX_ENTRIES) {
                let entries: Vec<Entry> = (0..n)
                    .map(|i| {
                        let mut id = [0u8; 32];
                        id[0] = i as u8;
                        Entry { id, age: (i % 27) as u8 }
                    })
                    .collect();
                let encoded = encode_entries(&entries);
                let decoded = decode_entries(&encoded).unwrap();
                prop_assert_eq!(decoded, entries);
            }

            #[test]
            fn misalignment_rejected_prop(n in 1usize..=100) {
                // Any buffer whose length isn't a multiple of 33 must fail.
                let misaligned = ENTRY_LEN * n + 1;
                let bytes = vec![0u8; misaligned];
                prop_assert!(decode_entries(&bytes).is_err());
            }
        }
    }
}
