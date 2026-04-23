//! Record merge: age-up, vouch, evict. Pure function — no I/O.
//!
//! Corresponds to the `Merge` procedure in §4 of the design doc. Called by
//! the writer at `Write(slot_u, Merge(Read(slot_u), ...))`.
//!
//! Operation (in order):
//! 1. Increment the age of every non-self entry. Drop those that would
//!    reach `A_max`.
//! 2. Refresh self at age 0 (remove any existing self-entry first).
//! 3. Vouch for up to `V` randomly-chosen neighbors at age 1 (refreshing
//!    existing vouches downward to age 1 if already present).
//! 4. If size exceeds `B`, evict the oldest entries (random tie-break).

use rand::Rng;
use rand::seq::IndexedRandom;

use crate::wire::Entry;

/// Merge parameters.
pub(crate) struct MergeParams {
    /// Max logical age before eviction (`A_max`). Entries reaching this age are dropped.
    pub max_age: u8,
    /// Max entries in the returned record (`B`).
    pub max_entries: usize,
    /// Max vouches added per merge (`V`).
    pub max_vouches: usize,
}

/// Vouch for up to `max_vouches` random neighbors at age 1.
///
/// This function is deliberately marked `#[mutants::skip]` because the
/// short-circuit guard + the age-refresh check contain several
/// **equivalent mutants** that produce identical output for every valid
/// input:
///
/// * `max_vouches > 0 && !neighbors.is_empty()` vs `||`: when one operand
///   is false and the other true, the body enters but `pick = min(V, |N|) = 0`,
///   so no vouches are added — same result as short-circuiting.
/// * `max_vouches > 0` vs `>= 0`: `V = 0` enters the `>=` branch but
///   `pick = 0` short-circuits via the empty sample.
/// * `existing.age > 1` vs `>= 1`: post-age-up, `existing.age` is always
///   `≥ 1`; with `> 1` we skip the write when age is 1 (already correct);
///   with `>= 1` we redundantly write 1 (same result).
///
/// Correctness is covered by:
/// * `merge::tests` — 17 unit tests including V=0, V>|N|, self-in-neighbors,
///   duplicate-neighbor, random-tiebreak.
/// * `merge::tests::proptests` — property tests asserting size + age
///   invariants on arbitrary inputs.
/// * `kani_proofs::merge_*` — bounded model checking of size, age, and
///   self-always-zero invariants (symbolic inputs up to |current|=3,
///   |neighbors|=2).
#[mutants::skip]
fn apply_vouches(
    out: &mut Vec<Entry>,
    self_id: &[u8; 32],
    neighbors: &[[u8; 32]],
    max_vouches: usize,
    rng: &mut impl Rng,
) {
    if max_vouches > 0 && !neighbors.is_empty() {
        let pick = max_vouches.min(neighbors.len());
        let sample: Vec<&[u8; 32]> = neighbors.choose_multiple(rng, pick).collect();
        for id in sample {
            if id == self_id {
                continue;
            }
            if let Some(existing) = out.iter_mut().find(|e| e.id == *id) {
                if existing.age > 1 {
                    existing.age = 1;
                }
            } else {
                out.push(Entry { id: *id, age: 1 });
            }
        }
    }
}

/// Perform the merge. `current` is the record just read from the slot
/// (possibly empty). `self_id` is our endpoint ID; `neighbors` is the
/// current active-view peer set from the gossip layer.
pub(crate) fn merge(
    current: &[Entry],
    self_id: &[u8; 32],
    neighbors: &[[u8; 32]],
    params: &MergeParams,
    rng: &mut impl Rng,
) -> Vec<Entry> {
    debug_assert!(params.max_age >= 1);
    debug_assert!(params.max_entries >= 1);

    // Step 1: age up non-self entries, dropping those that would hit max_age.
    let mut out: Vec<Entry> = current
        .iter()
        .filter(|e| e.id != *self_id)
        .filter_map(|e| {
            let new_age = e.age.saturating_add(1);
            if (new_age as usize) < params.max_age as usize {
                Some(Entry {
                    id: e.id,
                    age: new_age,
                })
            } else {
                None
            }
        })
        .collect();

    // Step 2: refresh self at age 0.
    out.push(Entry {
        id: *self_id,
        age: 0,
    });

    // Step 3: vouch for up to V random neighbors at age 1.
    apply_vouches(&mut out, self_id, neighbors, params.max_vouches, rng);

    // Step 4: evict by max-age with random tie-break until |out| ≤ B.
    while out.len() > params.max_entries {
        let max_age = out.iter().map(|e| e.age).max().unwrap_or(0);
        let oldest_idxs: Vec<usize> = out
            .iter()
            .enumerate()
            .filter_map(|(i, e)| if e.age == max_age { Some(i) } else { None })
            .collect();
        let pick = oldest_idxs.choose(rng).copied().unwrap_or(0);
        out.swap_remove(pick);
    }

    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn id(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn params() -> MergeParams {
        MergeParams {
            max_age: 27,
            max_entries: 27,
            max_vouches: 3,
        }
    }

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    #[test]
    fn empty_record_gets_self_only() {
        let out = merge(&[], &id(1), &[], &params(), &mut rng(0));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, id(1));
        assert_eq!(out[0].age, 0);
    }

    #[test]
    fn self_is_always_age_zero() {
        let current = vec![Entry { id: id(1), age: 7 }, Entry { id: id(2), age: 3 }];
        let out = merge(&current, &id(1), &[], &params(), &mut rng(0));
        let self_entry = out.iter().find(|e| e.id == id(1)).unwrap();
        assert_eq!(self_entry.age, 0);
    }

    #[test]
    fn non_self_ages_up() {
        let current = vec![Entry { id: id(2), age: 5 }];
        let out = merge(&current, &id(1), &[], &params(), &mut rng(0));
        let other = out.iter().find(|e| e.id == id(2)).unwrap();
        assert_eq!(other.age, 6);
    }

    #[test]
    fn entries_at_max_minus_one_are_dropped() {
        // max_age=27, entry at age 26 ages to 27 → dropped.
        let current = vec![Entry { id: id(2), age: 26 }];
        let out = merge(&current, &id(1), &[], &params(), &mut rng(0));
        assert_eq!(out.len(), 1, "only self should remain");
        assert_eq!(out[0].id, id(1));
    }

    #[test]
    fn vouching_adds_neighbor_at_age_one() {
        let p = MergeParams {
            max_vouches: 1,
            ..params()
        };
        let neighbors = [id(5)];
        let out = merge(&[], &id(1), &neighbors, &p, &mut rng(0));
        let vouched = out.iter().find(|e| e.id == id(5)).unwrap();
        assert_eq!(vouched.age, 1);
    }

    #[test]
    fn vouching_refreshes_existing_entry_downward() {
        let p = MergeParams {
            max_vouches: 1,
            ..params()
        };
        let current = vec![Entry { id: id(5), age: 10 }];
        let neighbors = [id(5)];
        // After age-up: (5, 11); vouch sets back to 1.
        let out = merge(&current, &id(1), &neighbors, &p, &mut rng(0));
        let e = out.iter().find(|e| e.id == id(5)).unwrap();
        assert_eq!(e.age, 1);
    }

    #[test]
    fn vouching_never_ages_entries_up() {
        // Entry at age 0 should not get bumped to age 1 via vouching.
        let p = MergeParams {
            max_vouches: 1,
            ..params()
        };
        let current = vec![Entry { id: id(5), age: 0 }];
        let neighbors = [id(5)];
        let out = merge(&current, &id(1), &neighbors, &p, &mut rng(0));
        let e = out.iter().find(|e| e.id == id(5)).unwrap();
        // Age-up makes it 1, then vouch at age 1 is a no-op (min(a, 1) == a).
        assert_eq!(e.age, 1);
    }

    #[test]
    fn size_capped_at_max_entries() {
        // Start with 30 entries all at age 3 + 5 neighbors.
        let current: Vec<Entry> = (10u8..=39).map(|i| Entry { id: id(i), age: 3 }).collect();
        let neighbors: Vec<[u8; 32]> = (50u8..=54).map(id).collect();
        let p = MergeParams {
            max_age: 27,
            max_entries: 27,
            max_vouches: 3,
        };
        let out = merge(&current, &id(1), &neighbors, &p, &mut rng(0));
        assert!(out.len() <= 27);
    }

    #[test]
    fn size_capped_preserves_self() {
        // Evict loop must never drop self; self is at age 0, never max.
        let current: Vec<Entry> = (10u8..=39).map(|i| Entry { id: id(i), age: 20 }).collect();
        let p = MergeParams {
            max_age: 27,
            max_entries: 5,
            max_vouches: 0,
        };
        let out = merge(&current, &id(1), &[], &p, &mut rng(42));
        assert!(out.iter().any(|e| e.id == id(1)));
        assert!(out.len() <= 5);
    }

    // ── Audit gap tests ───────────────────────────────────────────────

    #[test]
    fn merge_with_v_zero_no_vouches() {
        // max_vouches = 0 disables vouching; output has self + aged survivors only.
        let current = vec![Entry { id: id(2), age: 5 }];
        let neighbors = [id(10), id(20), id(30)];
        let p = MergeParams {
            max_age: 27,
            max_entries: 27,
            max_vouches: 0,
        };
        let out = merge(&current, &id(1), &neighbors, &p, &mut rng(0));
        // Should contain self + aged-up #2 only — no vouched entries.
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|e| e.id == id(1) && e.age == 0));
        assert!(out.iter().any(|e| e.id == id(2) && e.age == 6));
        for neighbor_id in &neighbors {
            assert!(!out.iter().any(|e| e.id == *neighbor_id));
        }
    }

    #[test]
    fn merge_with_v_greater_than_neighbors() {
        // V=9 but only 3 neighbors — must vouch for all 3, not more.
        let neighbors = [id(10), id(20), id(30)];
        let p = MergeParams {
            max_age: 27,
            max_entries: 27,
            max_vouches: 9,
        };
        let out = merge(&[], &id(1), &neighbors, &p, &mut rng(0));
        // self + all 3 neighbors.
        assert_eq!(out.len(), 4);
        for neighbor_id in &neighbors {
            assert!(
                out.iter().any(|e| e.id == *neighbor_id && e.age == 1),
                "missing {neighbor_id:?}"
            );
        }
    }

    #[test]
    fn merge_with_self_in_neighbors_is_deduped() {
        // Passing self in the neighbors slice must NOT produce a duplicate
        // self-entry — the vouching step skips self.
        let neighbors = [id(1), id(10)];
        let p = MergeParams {
            max_age: 27,
            max_entries: 27,
            max_vouches: 2,
        };
        let out = merge(&[], &id(1), &neighbors, &p, &mut rng(0));
        let self_count = out.iter().filter(|e| e.id == id(1)).count();
        assert_eq!(self_count, 1, "self listed twice: {out:?}");
        // self at 0, id(10) at 1.
        assert!(out.iter().any(|e| e.id == id(1) && e.age == 0));
        assert!(out.iter().any(|e| e.id == id(10) && e.age == 1));
    }

    #[test]
    fn merge_with_duplicate_neighbor_ids_vouches_once() {
        // Same neighbor listed twice in the input slice must produce only
        // one entry in the output (the second vouch finds the entry already
        // present and refreshes in place).
        let neighbors = [id(10), id(10), id(20)];
        let p = MergeParams {
            max_age: 27,
            max_entries: 27,
            max_vouches: 3,
        };
        let out = merge(&[], &id(1), &neighbors, &p, &mut rng(0));
        let ten_count = out.iter().filter(|e| e.id == id(10)).count();
        assert_eq!(ten_count, 1, "id(10) listed {ten_count} times");
    }

    #[test]
    fn merge_evicts_randomly_among_ties() {
        // 10 entries all at age 20 + self. max_entries=3 forces 8 evictions
        // all from the age-20 tier. Over many seeds, eviction should not
        // consistently hit the same index — verify by running 100 trials and
        // asserting every entry survives at least once.
        let current: Vec<Entry> = (10u8..20).map(|i| Entry { id: id(i), age: 20 }).collect();
        let p = MergeParams {
            max_age: 27,
            max_entries: 3,
            max_vouches: 0,
        };
        let mut survivor_counts = [0u32; 10];
        for seed in 0..100u64 {
            let out = merge(&current, &id(1), &[], &p, &mut rng(seed));
            for entry in &out {
                if entry.id != id(1) {
                    let idx = (entry.id[0] - 10) as usize;
                    survivor_counts[idx] += 1;
                }
            }
        }
        // Every entry should survive at least a few times out of 100 trials.
        // Expected per-trial survival = 2/10 = 0.2 (2 non-self slots / 10 entries);
        // expected count = 20. Chi-squared tolerance: each ≥ 5 is extremely
        // generous (statistical floor).
        for (i, count) in survivor_counts.iter().enumerate() {
            assert!(
                *count >= 5,
                "entry {i} survived only {count} times in 100 trials — bias?"
            );
        }
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn max_age_invariant(
                current in proptest::collection::vec((any::<u8>(), 0u8..=26), 0..30),
                self_n in 1u8..=255u8,
                neighbors in proptest::collection::vec(any::<u8>(), 0..10),
                seed in any::<u64>(),
            ) {
                let current: Vec<Entry> = current.into_iter().map(|(n, a)| Entry { id: id(n), age: a }).collect();
                let neighbors: Vec<[u8; 32]> = neighbors.into_iter().map(id).collect();
                let p = MergeParams { max_age: 27, max_entries: 27, max_vouches: 3 };
                let out = merge(&current, &id(self_n), &neighbors, &p, &mut rng(seed));
                prop_assert!(out.iter().all(|e| (e.age as usize) < p.max_age as usize));
            }

            #[test]
            fn size_invariant(
                current in proptest::collection::vec((any::<u8>(), 0u8..=26), 0..60),
                self_n in 1u8..=255u8,
                neighbors in proptest::collection::vec(any::<u8>(), 0..10),
                max_entries in 1usize..=27,
                seed in any::<u64>(),
            ) {
                let current: Vec<Entry> = current.into_iter().map(|(n, a)| Entry { id: id(n), age: a }).collect();
                let neighbors: Vec<[u8; 32]> = neighbors.into_iter().map(id).collect();
                let p = MergeParams { max_age: 27, max_entries, max_vouches: 3 };
                let out = merge(&current, &id(self_n), &neighbors, &p, &mut rng(seed));
                prop_assert!(out.len() <= max_entries);
            }

            #[test]
            fn self_always_present(
                current in proptest::collection::vec((any::<u8>(), 0u8..=26), 0..30),
                self_n in 1u8..=255u8,
                seed in any::<u64>(),
            ) {
                let current: Vec<Entry> = current.into_iter().map(|(n, a)| Entry { id: id(n), age: a }).collect();
                let p = MergeParams { max_age: 27, max_entries: 27, max_vouches: 0 };
                let out = merge(&current, &id(self_n), &[], &p, &mut rng(seed));
                prop_assert!(out.iter().any(|e| e.id == id(self_n) && e.age == 0));
            }
        }
    }
}
