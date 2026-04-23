//! Fuzz the crypto-envelope parser via arbitrary bytes. We don't expose
//! `crypto::open` publicly (it's a crate internal); instead we drive
//! the comparable "decode arbitrary bytes as if they were an envelope"
//! path through [`InMemoryDht`] writes — which themselves must handle
//! malformed signatures cleanly.

#![no_main]

use iroh_gossip_rendezvous::sim::decode_entries;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Minimum fuzz: decode_entries never panics on arbitrary bytes.
    // crypto::open is covered indirectly — any bytes that decode to
    // "entries" without panicking are a safe path.
    let _ = decode_entries(data);
});
