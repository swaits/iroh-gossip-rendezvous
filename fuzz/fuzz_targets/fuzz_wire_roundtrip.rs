//! Fuzz `decode_entries(encode_entries(x))` roundtrip. Any well-formed
//! input must roundtrip exactly; any malformed input must fail cleanly.

#![no_main]

use arbitrary::Arbitrary;
use iroh_gossip_rendezvous::sim::{decode_entries, encode_entries, Entry, MAX_ENTRIES};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    entries: Vec<([u8; 32], u8)>,
}

fuzz_target!(|input: FuzzInput| {
    // Cap at MAX_ENTRIES since encode_entries requires it.
    let entries: Vec<Entry> = input
        .entries
        .into_iter()
        .take(MAX_ENTRIES)
        .map(|(id, age)| Entry { id, age })
        .collect();

    let encoded = encode_entries(&entries);
    let decoded = decode_entries(&encoded).expect("well-formed encode decodes");
    assert_eq!(decoded, entries);
});
