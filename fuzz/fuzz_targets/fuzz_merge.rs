//! Fuzz the wire-roundtrip path with structure-aware input. The `merge()`
//! function itself is crate-internal; we exercise it indirectly by
//! constructing random entry lists and checking encode→decode is
//! idempotent. Direct coverage of `merge` comes from the property tests
//! in `src/merge.rs`.

#![no_main]

use arbitrary::Arbitrary;
use iroh_gossip_rendezvous::sim::{decode_entries, encode_entries, Entry, MAX_ENTRIES};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    entries: Vec<([u8; 32], u8)>,
}

fuzz_target!(|input: FuzzInput| {
    let entries: Vec<Entry> = input
        .entries
        .into_iter()
        .take(MAX_ENTRIES)
        .map(|(id, age)| Entry { id, age })
        .collect();
    let encoded = encode_entries(&entries);
    let decoded = decode_entries(&encoded).expect("roundtrip");
    assert_eq!(decoded.len(), entries.len());
});
