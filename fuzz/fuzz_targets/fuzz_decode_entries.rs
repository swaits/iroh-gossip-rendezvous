//! Fuzz `decode_entries` with arbitrary bytes. Must never panic —
//! malformed input always returns `Err(MalformedRecord)`.

#![no_main]

use iroh_gossip_rendezvous::sim::decode_entries;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Any byte slice is a valid input. Either returns Ok(entries) with
    // len ≤ MAX_ENTRIES or returns Err. Never panics.
    let _ = decode_entries(data);
});
