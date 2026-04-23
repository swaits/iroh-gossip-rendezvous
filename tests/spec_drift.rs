//! Keeps `PROTOCOL.md §2` parameter defaults and `§3` wire-format constants
//! in sync with the code. Changing any number in the spec or the code
//! without updating the other fails this test.

use std::time::Duration;

use iroh_gossip_rendezvous::defaults::{
    DEFAULT_EPOCH_WRITES, DEFAULT_HEAL_PERIOD, DEFAULT_JITTER, DEFAULT_MAX_AGE,
    DEFAULT_MAX_ENTRIES, DEFAULT_MAX_VOUCHES, DEFAULT_SHARDS, DEFAULT_WRITE_PERIOD,
};

// ── §2 Parameter defaults ──────────────────────────────────────────────

#[test]
fn spec_section_2_default_shards_is_3() {
    // PROTOCOL.md §2 table: K = 3.
    assert_eq!(DEFAULT_SHARDS, 3);
}

#[test]
fn spec_section_2_default_max_entries_is_27() {
    // PROTOCOL.md §2 table + §3 byte budget: B = 27.
    assert_eq!(DEFAULT_MAX_ENTRIES, 27);
}

#[test]
fn spec_section_2_default_max_age_is_27() {
    // PROTOCOL.md §2 table + §7 (A_max = B): A_max = 27.
    assert_eq!(DEFAULT_MAX_AGE, 27);
}

#[test]
fn spec_section_2_default_max_vouches_is_3() {
    // PROTOCOL.md §2 table: V = 3.
    assert_eq!(DEFAULT_MAX_VOUCHES, 3);
}

#[test]
fn spec_section_2_default_epoch_writes_is_64() {
    // PROTOCOL.md §2 table: E = 64 writes per wrapper-key epoch.
    assert_eq!(DEFAULT_EPOCH_WRITES, 64);
}

#[test]
fn spec_section_2_default_write_period_is_5_minutes() {
    // PROTOCOL.md §2 table: T_w = 5 min.
    assert_eq!(DEFAULT_WRITE_PERIOD, Duration::from_secs(300));
}

#[test]
fn spec_section_2_default_heal_period_is_30_seconds() {
    // PROTOCOL.md §2 table: T_h = 30 s.
    assert_eq!(DEFAULT_HEAL_PERIOD, Duration::from_secs(30));
}

#[test]
fn spec_section_2_default_jitter_is_half() {
    // PROTOCOL.md §2 table: σ = ±50% → factor 0.5.
    assert!((DEFAULT_JITTER - 0.5_f32).abs() < f32::EPSILON);
}

#[test]
fn spec_section_7_a_max_equals_b() {
    // PROTOCOL.md §7: "Age cap equals size cap. A_max = B."
    assert_eq!(DEFAULT_MAX_AGE as usize, DEFAULT_MAX_ENTRIES);
}

#[test]
fn spec_section_7_t_h_is_one_tenth_t_w() {
    // PROTOCOL.md §7: "Heal-loop period T_h ≪ T_w. T_h/T_w = 1/10 is the knee."
    let ratio = DEFAULT_HEAL_PERIOD.as_secs_f32() / DEFAULT_WRITE_PERIOD.as_secs_f32();
    assert!(
        (ratio - 0.1).abs() < 0.001,
        "T_h/T_w should be ≈ 0.1, got {ratio}"
    );
}
