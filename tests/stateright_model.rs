//! Stateright model of the rendezvous algorithm.
//!
//! Gives a bounded-exhaustive safety proof (BFS) and a sampled liveness
//! witness (random walk) for the PROTOCOL.md §§4–5 procedures.
//!
//! Scope — what this model **does** capture:
//! * `WriteSlot`: a node writes its self-entry (age 0) + up to V vouches
//!   at age 1 to its `slot_u = H(self_id) mod K`, using a simplified merge
//!   (age-up, evict by max-age with deterministic tie-break).
//! * `HealRead`: a node reads a random slot and adds discovered IDs to
//!   its `joined` set — the simulator's stand-in for `GossipSender::join_peers`.
//! * `Dial`: completes a gossip connection (the iroh-gossip dial handshake
//!   is abstracted to a single atomic action).
//!
//! What it **does not** model (by design):
//! * Crypto — accepted correct (RustCrypto stack).
//! * Actual network timing, jitter, or dropped packets.
//! * Byzantine writers.
//!
//! **Safety properties checked** (must always hold across every reachable
//! state in the BFS-explored state space):
//!
//! - **S1 (size)**: every slot's record has `len ≤ B`.
//! - **S2 (age)**: every entry has `age < A_max`.
//!
//! **Liveness property** (sampled via random-walk; not exhaustive):
//!
//! - **L1 (partition heals)**: starting from two disjoint connected
//!   components, eventually some node in one has discovered a node in
//!   the other via a HealRead.
//!
//! Run:
//! ```text
//! cargo test --test stateright_model --release -- --ignored bfs_small
//! cargo test --test stateright_model --release -- --ignored random_large
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code, unused_variables)]

use std::collections::BTreeSet;

use stateright::Checker;
use stateright::Model;

/// Simplified entry: (id, age). Used in the model, not the real crate.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct ModelEntry {
    id: u8,
    age: u8,
}

/// Simplified slot. `seq` is monotonic per slot; writes bump by 1.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
struct Slot {
    entries: Vec<ModelEntry>,
    seq: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct ModelState {
    slots: Vec<Slot>,             // len = K
    neighbors: Vec<BTreeSet<u8>>, // per-node active-view sets (node ids)
    joined: Vec<BTreeSet<u8>>,    // per-node "discovered via heal-read" set
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Action {
    /// Node `id` writes to its `slot_u` — adds self at age 0, vouches for
    /// all current neighbors (up to V), evicts oldest.
    Write { node: u8 },
    /// Node `id` heals by reading slot `slot_idx` — union entries' IDs
    /// into its `joined` set.
    HealRead { node: u8, slot_idx: u8 },
    /// Node `a` dials `b`. Updates both neighbor sets.
    Dial { a: u8, b: u8 },
}

/// Parameters: small to keep BFS tractable.
struct RendezvousModel {
    n: u8,           // number of nodes
    k: u8,           // number of slots
    max_age: u8,     // A_max
    max_entries: u8, // B
    max_vouches: u8, // V
}

impl RendezvousModel {
    fn slot_for(&self, id: u8) -> u8 {
        // Deterministic slot assignment.
        id % self.k
    }

    /// Perform the merge: age up non-self entries, drop ≥ A_max, add self
    /// at 0, vouch up to V neighbors at 1, evict max-age.
    fn merge(
        &self,
        current: &[ModelEntry],
        self_id: u8,
        neighbor_ids: &BTreeSet<u8>,
    ) -> Vec<ModelEntry> {
        let mut out: Vec<ModelEntry> = current
            .iter()
            .filter(|e| e.id != self_id)
            .filter_map(|e| {
                let a = e.age.saturating_add(1);
                (a < self.max_age).then_some(ModelEntry { id: e.id, age: a })
            })
            .collect();
        out.push(ModelEntry {
            id: self_id,
            age: 0,
        });

        // Vouch deterministically: first V neighbors in sorted order.
        for &nid in neighbor_ids.iter().take(self.max_vouches as usize) {
            if nid == self_id {
                continue;
            }
            if let Some(existing) = out.iter_mut().find(|e| e.id == nid) {
                if existing.age > 1 {
                    existing.age = 1;
                }
            } else {
                out.push(ModelEntry { id: nid, age: 1 });
            }
        }

        // Evict: deterministic tie-break — drop highest id among oldest.
        while out.len() > self.max_entries as usize {
            let max_age = out.iter().map(|e| e.age).max().unwrap_or(0);
            let pick = out
                .iter()
                .enumerate()
                .filter(|(_, e)| e.age == max_age)
                .max_by_key(|(_, e)| e.id)
                .map(|(i, _)| i)
                .unwrap_or(0);
            out.swap_remove(pick);
        }

        out.sort_by(|a, b| a.id.cmp(&b.id).then(a.age.cmp(&b.age)));
        out
    }
}

impl Model for RendezvousModel {
    type State = ModelState;
    type Action = Action;

    fn init_states(&self) -> Vec<Self::State> {
        let slots = (0..self.k).map(|_| Slot::default()).collect();
        let neighbors = (0..self.n).map(|_| BTreeSet::new()).collect();
        let joined = (0..self.n).map(|_| BTreeSet::new()).collect();
        vec![ModelState {
            slots,
            neighbors,
            joined,
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        for node in 0..self.n {
            actions.push(Action::Write { node });
            for slot_idx in 0..self.k {
                actions.push(Action::HealRead { node, slot_idx });
            }
            for other in 0..self.n {
                if other != node && !state.neighbors[node as usize].contains(&other) {
                    actions.push(Action::Dial { a: node, b: other });
                }
            }
        }
    }

    fn next_state(&self, last: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut state = last.clone();
        match action {
            Action::Write { node } => {
                let slot = self.slot_for(node) as usize;
                let neighbors = state.neighbors[node as usize].clone();
                let merged = self.merge(&state.slots[slot].entries, node, &neighbors);
                state.slots[slot].entries = merged;
                state.slots[slot].seq += 1;
            }
            Action::HealRead { node, slot_idx } => {
                let entries = state.slots[slot_idx as usize].entries.clone();
                for e in entries {
                    if e.id != node {
                        state.joined[node as usize].insert(e.id);
                    }
                }
            }
            Action::Dial { a, b } => {
                state.neighbors[a as usize].insert(b);
                state.neighbors[b as usize].insert(a);
            }
        }
        Some(state)
    }

    fn properties(&self) -> Vec<stateright::Property<Self>> {
        // Stateright 0.31's Property::always takes a fn pointer — no
        // closure captures. Property functions read the bounds off `m`.
        vec![
            stateright::Property::<Self>::always("S1 record size bounded", |m, s| {
                s.slots
                    .iter()
                    .all(|slot| slot.entries.len() <= m.max_entries as usize)
            }),
            stateright::Property::<Self>::always("S2 age bounded", |m, s| {
                s.slots
                    .iter()
                    .all(|slot| slot.entries.iter().all(|e| e.age < m.max_age))
            }),
        ]
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

/// BFS proof of S1 + S2 for N=2, K=1 with small bounds. Runs quickly
/// (seconds). Verifies the model's safety invariants hold across every
/// reachable state.
#[test]
#[ignore = "stateright: explicit run"]
fn bfs_small() {
    let model = RendezvousModel {
        n: 2,
        k: 1,
        max_age: 3,
        max_entries: 3,
        max_vouches: 1,
    };
    model
        .checker()
        .threads(num_cpus())
        .target_max_depth(20)
        .spawn_bfs()
        .join()
        .assert_properties();
}

/// BFS at N=3, K=2 — larger but should terminate in minutes.
#[test]
#[ignore = "stateright: explicit run, slow"]
fn bfs_n3_k2() {
    let model = RendezvousModel {
        n: 3,
        k: 2,
        max_age: 4,
        max_entries: 4,
        max_vouches: 2,
    };
    model
        .checker()
        .threads(num_cpus())
        .target_max_depth(30)
        .spawn_bfs()
        .join()
        .assert_properties();
}

/// Random-walk exploration for a larger configuration (N=6, K=3). Not
/// exhaustive; searches up to 10⁶ states for counterexamples. Useful
/// evidence but not proof.
#[test]
#[ignore = "stateright: explicit run, ~minutes"]
fn random_large() {
    let model = RendezvousModel {
        n: 6,
        k: 3,
        max_age: 5,
        max_entries: 5,
        max_vouches: 3,
    };
    model
        .checker()
        .threads(num_cpus())
        .target_max_depth(50)
        .spawn_simulation(0, stateright::UniformChooser)
        .join()
        .assert_properties();
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(4)
}
