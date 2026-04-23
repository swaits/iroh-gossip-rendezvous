//! Discrete-event simulator for the rendezvous algorithm.
//!
//! Gated behind the `sim` feature flag so the harness isn't compiled by
//! default consumers. Used by `examples/simulator.rs` to validate the
//! §8 defaults before simulation results move them.
//!
//! Internally this module reaches into the crate's `pub(crate)` items —
//! [`dht::memory::InMemoryDht`], the merge/wire helpers, and a lightweight
//! stand-in for [`GossipView`]. The simulator does *not* run real iroh-gossip
//! or real Mainline DHT.

#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::dht::memory::sign_record;
use crate::keys::{PassphraseKeys, slot_for_id};
use crate::merge::{MergeParams, merge};
use crate::protocol::GossipView;

// Re-exports for third-party simulator / DHT-backend authors. Available as
// `iroh_gossip_rendezvous::sim::{InMemoryDht, DhtSlots, SlotKey, SlotRecord, DhtError, Entry, ...}`.
/// Re-export of [`crate::dht::DhtSlots`] for use in the `sim` public API.
pub use crate::dht::DhtSlots as PubDhtSlots;
pub use crate::dht::memory::InMemoryDht as PubInMemoryDht;
pub use crate::dht::{DhtError as PubDhtError, SlotKey as PubSlotKey, SlotRecord};
pub use crate::wire::{ENTRY_LEN, Entry, MAX_ENTRIES, decode_entries, encode_entries};

// Internal aliases with shorter names (used in the rest of this file).
use PubInMemoryDht as InMemoryDht;
use PubSlotKey as SlotKey;

/// Which scenario to run.
#[derive(Clone, Copy, Debug)]
pub enum Scenario {
    /// N nodes, no gossip edges, empty DHT. Converges when every node has
    /// been handed at least one peer from the DHT.
    ColdStart { nodes: usize },
    /// `a + b` nodes split into two full-mesh partitions of size `a` and
    /// `b`. Converges when both sides have discovered at least one peer
    /// from the other side via DHT heal reads.
    Partition { a: usize, b: usize },
    /// `minority` vs `majority`, both full-meshes internally. Converges
    /// when any majority node has discovered any minority node.
    Asymmetric { minority: usize, majority: usize },
}

/// One scenario's outcome.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub healed_in: Option<usize>,
    pub dht_reads: usize,
    pub dht_writes: usize,
}

/// Simulation parameters shared across scenarios.
#[derive(Debug, Clone)]
pub struct SimConfig {
    pub shards: usize,
    pub max_entries: usize,
    pub max_age: u8,
    pub max_vouches: usize,
    pub max_rounds: usize,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            shards: 3,
            max_entries: 27,
            max_age: 27,
            max_vouches: 3,
            max_rounds: 30,
        }
    }
}

/// Execute one run of the given scenario, returning the outcome.
pub async fn run(passphrase: &str, scenario: Scenario, cfg: &SimConfig) -> Outcome {
    match scenario {
        Scenario::ColdStart { nodes } => run_cold_start(passphrase, nodes, cfg).await,
        Scenario::Partition { a, b } => run_partition(passphrase, a, b, cfg).await,
        Scenario::Asymmetric { minority, majority } => {
            run_asymmetric(passphrase, minority, majority, cfg).await
        }
    }
}

// ── Internals ───────────────────────────────────────────────────────────

fn node_id(i: usize) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&(i as u64).to_le_bytes());
    id
}

struct Node {
    self_id: [u8; 32],
    keys: PassphraseKeys,
    slot: usize,
    gossip: Arc<MockGossip>,
}

impl Node {
    fn new(passphrase: &str, app_salt: &str, i: usize, shards: usize) -> Self {
        let self_id = node_id(i);
        Self {
            self_id,
            keys: PassphraseKeys::derive(passphrase, app_salt, shards),
            slot: slot_for_id(&self_id, shards),
            gossip: Arc::new(MockGossip::new()),
        }
    }
}

struct MockGossip {
    neighbors: Mutex<Vec<[u8; 32]>>,
    joined: Mutex<Vec<[u8; 32]>>,
}

impl MockGossip {
    fn new() -> Self {
        Self {
            neighbors: Mutex::new(Vec::new()),
            joined: Mutex::new(Vec::new()),
        }
    }
    fn add_neighbor(&self, id: [u8; 32]) {
        if let Ok(mut g) = self.neighbors.lock() {
            if !g.contains(&id) {
                g.push(id);
            }
        }
    }
    fn drain_joined(&self) -> Vec<[u8; 32]> {
        self.joined
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default()
    }
}

#[async_trait]
impl GossipView for MockGossip {
    fn neighbors(&self) -> Vec<[u8; 32]> {
        self.neighbors.lock().map(|g| g.clone()).unwrap_or_default()
    }
    async fn join_peers(&self, peers: Vec<[u8; 32]>) {
        if let Ok(mut g) = self.joined.lock() {
            g.extend(peers);
        }
    }
}

async fn write_once(node: &Node, dht: &InMemoryDht, cfg: &SimConfig) -> usize {
    // One read to fetch current seq + entries.
    let slot_key = SlotKey(node.keys.slots[node.slot].verifying.to_bytes());
    let (current, prev_seq) = match dht.read(slot_key).await {
        Ok(Some(r)) => (decode_entries(&r.value).unwrap_or_default(), r.seq),
        _ => (Vec::<Entry>::new(), 0),
    };

    let neighbors = node.gossip.neighbors();
    let merged = {
        let mut rng = rand::rng();
        let params = MergeParams {
            max_age: cfg.max_age,
            max_entries: cfg.max_entries,
            max_vouches: cfg.max_vouches,
        };
        merge(&current, &node.self_id, &neighbors, &params, &mut rng)
    };

    // Simulator uses plaintext records (still signed so InMemoryDht accepts).
    let plaintext = encode_entries(&merged);
    let seq = prev_seq.saturating_add(1);
    let record = sign_record(&node.keys.slots[node.slot].signing, plaintext, seq);
    let _ = dht.write(slot_key, record).await;
    1
}

async fn heal_round(node: &Node, dht: &InMemoryDht, cfg: &SimConfig) -> usize {
    use rand::seq::SliceRandom;
    let neighbors = node.gossip.neighbors();
    let s = cfg.shards.saturating_sub(neighbors.len()).max(1);
    let slot_indices: Vec<usize> = {
        let mut idx: Vec<usize> = (0..cfg.shards).collect();
        let mut rng = rand::rng();
        idx.shuffle(&mut rng);
        idx.truncate(s);
        idx
    };

    let known: HashSet<_> = neighbors.iter().copied().collect();
    let mut new_peers = Vec::new();
    let mut reads = 0usize;
    for k in slot_indices {
        let slot_key = SlotKey(node.keys.slots[k].verifying.to_bytes());
        reads += 1;
        if let Ok(Some(rec)) = dht.read(slot_key).await {
            if let Ok(entries) = decode_entries(&rec.value) {
                for e in entries {
                    if e.id != node.self_id && !known.contains(&e.id) && !new_peers.contains(&e.id)
                    {
                        new_peers.push(e.id);
                    }
                }
            }
        }
    }
    if !new_peers.is_empty() {
        node.gossip.join_peers(new_peers).await;
    }
    reads
}

async fn run_cold_start(passphrase: &str, n: usize, cfg: &SimConfig) -> Outcome {
    let dht = InMemoryDht::new();
    let nodes: Vec<Node> = (0..n)
        .map(|i| Node::new(passphrase, "sim/cold-start", i, cfg.shards))
        .collect();
    let mut reads = 0;
    let mut writes = 0;
    for r in 1..=cfg.max_rounds {
        for node in &nodes {
            writes += write_once(node, &dht, cfg).await;
        }
        for node in &nodes {
            reads += heal_round(node, &dht, cfg).await;
        }
        let converged = nodes.iter().all(|n| !n.gossip.drain_joined().is_empty());
        if converged {
            return Outcome {
                healed_in: Some(r),
                dht_reads: reads,
                dht_writes: writes,
            };
        }
    }
    Outcome {
        healed_in: None,
        dht_reads: reads,
        dht_writes: writes,
    }
}

async fn run_partition(passphrase: &str, a: usize, b: usize, cfg: &SimConfig) -> Outcome {
    let dht = InMemoryDht::new();
    let total = a + b;
    let nodes: Vec<Node> = (0..total)
        .map(|i| Node::new(passphrase, "sim/partition", i, cfg.shards))
        .collect();

    for (i, n) in nodes.iter().enumerate() {
        for (j, other) in nodes.iter().enumerate() {
            let same = (i < a) == (j < a);
            if same && i != j {
                n.gossip.add_neighbor(other.self_id);
            }
        }
    }

    let part_a: HashSet<_> = (0..a).map(node_id).collect();
    let part_b: HashSet<_> = (a..total).map(node_id).collect();
    let mut reads = 0;
    let mut writes = 0;

    for r in 1..=cfg.max_rounds {
        for node in &nodes {
            writes += write_once(node, &dht, cfg).await;
        }
        let mut a_saw_b = false;
        let mut b_saw_a = false;
        for (i, node) in nodes.iter().enumerate() {
            reads += heal_round(node, &dht, cfg).await;
            let j = node.gossip.drain_joined();
            if i < a && j.iter().any(|id| part_b.contains(id)) {
                a_saw_b = true;
            }
            if i >= a && j.iter().any(|id| part_a.contains(id)) {
                b_saw_a = true;
            }
        }
        if a_saw_b && b_saw_a {
            return Outcome {
                healed_in: Some(r),
                dht_reads: reads,
                dht_writes: writes,
            };
        }
    }
    Outcome {
        healed_in: None,
        dht_reads: reads,
        dht_writes: writes,
    }
}

async fn run_asymmetric(
    passphrase: &str,
    minority: usize,
    majority: usize,
    cfg: &SimConfig,
) -> Outcome {
    let dht = InMemoryDht::new();
    let min_nodes: Vec<Node> = (0..minority)
        .map(|i| Node::new(passphrase, "sim/asym", 100 + i, cfg.shards))
        .collect();
    let maj_nodes: Vec<Node> = (0..majority)
        .map(|i| Node::new(passphrase, "sim/asym", i, cfg.shards))
        .collect();

    for n in &min_nodes {
        for other in &min_nodes {
            if n.self_id != other.self_id {
                n.gossip.add_neighbor(other.self_id);
            }
        }
    }
    for n in &maj_nodes {
        for other in &maj_nodes {
            if n.self_id != other.self_id {
                n.gossip.add_neighbor(other.self_id);
            }
        }
    }

    let minority_ids: HashSet<_> = min_nodes.iter().map(|n| n.self_id).collect();

    let mut reads = 0;
    let mut writes = 0;

    for r in 1..=cfg.max_rounds {
        for n in &min_nodes {
            writes += write_once(n, &dht, cfg).await;
        }
        for n in &maj_nodes {
            writes += write_once(n, &dht, cfg).await;
        }
        for n in &min_nodes {
            reads += heal_round(n, &dht, cfg).await;
        }
        let mut discovered = false;
        for n in &maj_nodes {
            reads += heal_round(n, &dht, cfg).await;
            if n.gossip
                .drain_joined()
                .iter()
                .any(|id| minority_ids.contains(id))
            {
                discovered = true;
            }
        }
        if discovered {
            return Outcome {
                healed_in: Some(r),
                dht_reads: reads,
                dht_writes: writes,
            };
        }
    }
    Outcome {
        healed_in: None,
        dht_reads: reads,
        dht_writes: writes,
    }
}
