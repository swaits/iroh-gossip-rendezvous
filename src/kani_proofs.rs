//! Kani bounded-model-checking proof harnesses.
//!
//! Scoped to **absence of undefined behavior / panics** on pure
//! algorithmic entry points. Gated on `#[cfg(kani)]` — regular
//! `cargo build` ignores them.
//!
//! Run:
//!
//! ```text
//! cargo install --locked kani-verifier && cargo kani setup
//! just kani
//! ```
//!
//! ## What this module *deliberately* doesn't cover
//!
//! The crate has six algorithmic invariants worth proving:
//!
//! 1. `epoch_of` is panic- and overflow-free. ← **Kani**, here.
//! 2. `decode_entries` is panic-free on arbitrary bytes. ← **Kani**, here.
//! 3. `decode(encode(x)) == x` for every valid entry list. ← **proptest**,
//!    `wire::tests::proptests::entries_roundtrip_prop`, which exhausts
//!    0–27 entries over thousands of random samples. Kani at N ≤ 2 with
//!    heap-allocated `Vec<u8>`/`Vec<Entry>` return values OOMs CBMC's
//!    SAT solver on laptop-class RAM, and proves strictly less than the
//!    proptest does.
//! 4. `|R'| ≤ B` after merge. ← **proptest** `size_invariant` +
//!    **Stateright** S1 (exhaustive for N ≤ 6, K ≤ 3).
//! 5. `age < A_max` after merge. ← **proptest** `max_age_invariant` +
//!    **Stateright** S2.
//! 6. Self is always at age 0. ← **proptest** `self_always_present`.
//!
//! Invariants 3–6 are all structural properties of our own code;
//! proptest and Stateright are better tools for them. Kani's
//! comparative advantage is over stdlib functions (`decode_entries`'s
//! chunks + pointer arithmetic) and pure arithmetic (`epoch_of`'s
//! branching on a signed/unsigned cast) — those are invariants 1 and
//! 2, which live here.
//!
//! Keeping this module small means `just kani` completes in under a
//! minute and fits well inside 2 GB of RAM.

#![cfg(kani)]

use crate::wire::decode_entries;

/// Proves `crypto::epoch_of` never panics or overflows for any `i64 seq`
/// and any `u64 epoch_size ≥ 1`. CBMC default checks include: arithmetic
/// overflow, division-by-zero, bounds. Pure arithmetic, no heap, no loops
/// — finishes in seconds.
#[kani::proof]
fn crypto_epoch_of_no_overflow() {
    let seq: i64 = kani::any();
    let epoch_size: u64 = kani::any();
    kani::assume(epoch_size > 0);
    let _ = crate::crypto::epoch_of(seq, epoch_size);
}

/// Proves `wire::decode_entries` never panics (and never exhibits UB per
/// CBMC's built-in pointer/deref checks) on any byte buffer up to 4
/// bytes long. Stack-allocated input to avoid Vec-allocator state-space
/// blow-up in CBMC. The concrete property tests in `src/wire.rs` cover
/// the full 0–1000-byte range with thousands of samples — Kani's role
/// here is proving absence of UB at the slice/iterator boundary, which
/// proptest can't enumerate.
#[kani::proof]
#[kani::unwind(5)]
fn wire_decode_no_panic() {
    const MAX_LEN: usize = 4;
    let len: usize = kani::any();
    kani::assume(len <= MAX_LEN);

    // Stack-allocated symbolic byte buffer — avoids the `Vec` machinery
    // that otherwise floods the report with `UNDETERMINED` allocator
    // pointer checks.
    let buf: [u8; MAX_LEN] = kani::any();
    let _ = decode_entries(&buf[..len]);
}
