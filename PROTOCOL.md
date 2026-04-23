# Protocol: `iroh-gossip-rendezvous` — DHT-Assisted Partition Healing

> Canonical specification. This document describes the algorithm implemented
> by the [`iroh-gossip-rendezvous`] crate as of version 0.1.0. Every
> numeric constant called out in §2 is covered by a drift test in
> `tests/spec_drift.rs`; every correctness property in §6 is exercised by
> a proptest or a Kani harness; §5's Join + HealLoop + WriteLoop are
> modelled in `tests/stateright_model.rs` for bounded safety + liveness
> checks.
>
> Authoritative copy: <https://github.com/swaits/iroh-gossip-rendezvous/blob/main/PROTOCOL.md>.
>
> [`iroh-gossip-rendezvous`]: https://docs.rs/iroh-gossip-rendezvous

## 1. Motivation and Prior Art

### The problem

Iroh-gossip ([n0-computer/iroh-gossip](https://github.com/n0-computer/iroh-gossip)) implements HyParView + PlumTree over iroh QUIC connections. HyParView's SHUFFLE operation keeps each node's passive view fresh from within its own connected component, and the active view is refilled from the passive view on neighbor failure. This is enough to tolerate continuous churn inside a component.

It is not enough to heal a partition. When the overlay splits into two or more connected components — because of transient network failure, a NAT reset, a region-level outage, or simply because two nodes joined at the same time via disjoint bootstrap lists — HyParView has no mechanism to discover peers outside its own component. The authors of HyParView note this as an open weakness: shuffle operations bias against old entries, so two partitions that stabilize independently can repair their respective views to the point where the partition is locked in. Empirically, this is what we observe in practice with iroh-gossip as well.

The fix is an out-of-band rendezvous: somewhere that all nodes in a topic can read and write, regardless of which gossip component they happen to be in. The BitTorrent Mainline DHT is a natural fit — it's public, large, unkeyed at the infrastructure level, and BEP 44 gives us mutable, signed, small records addressed by public key.

### What iroh ships

- **iroh's DHT discovery** (`discovery-pkarr-dht`, opt-in) publishes `NodeID → dialing info` records on Mainline. This solves "given a NodeID, how do I reach it," not "who else is in this topic." Wrong layer.
- **iroh's mDNS discovery** finds peers on the same LAN. Doesn't help across the internet.
- **iroh's hosted rendezvous servers** work, but are centralized. Defeats the point for a passphrase-based overlay.
- **Connection healing** (disco ping / CallMeMaybe) maintains an existing connection across IP changes. Different problem.

None of these answer the topic-membership question.

### What the community has built

- **[iroh-gossip-discovery](https://github.com/therishidesai/iroh-gossip-discovery)** propagates peer address books *through the gossip overlay itself*. By construction this cannot bridge a true partition — if two components can't exchange gossip messages, they can't exchange address books through gossip either.
- **[iroh-topic-tracker](https://github.com/rustonbsd/iroh-topic-tracker)** is the predecessor to the next entry. Uses a centralized hosted bootstrap node. That bootstrap is now offline as of September 2025.
- **[distributed-topic-tracker](https://github.com/rustonbsd/distributed-topic-tracker)** (DTT) is the closest prior art and a genuinely good piece of work. It uses Mainline + BEP 44 + bubble-detection merge actors, published as a crate. Anyone considering this problem should read its PROTOCOL.md and ARCHITECTURE.md before writing anything new.

### Why a new design

DTT solves the same high-level problem and shares some core choices (Mainline DHT, Ed25519 signing, AEAD payload, signed records, background publisher + merge actors). The design here departs on six points that matter for our deployment profile:

1. **Clock-free.** DTT addresses records at `SHA512(topic || unix_minute)[..32]`. Two nodes whose clocks disagree by more than a minute or so write to different DHT keys and cannot see each other. DTT papers over this by always reading the current minute and the previous minute. That helps modest skew but breaks for freshly-booted devices before NTP, for phones coming out of airplane mode, for embedded nodes without RTCs, and for anything on a lying system clock. This design uses logical ages that count writes, not seconds, and derives slot addresses from a passphrase alone. No clock dependency anywhere.

2. **Logical aging enables vouching.** DTT has only self-writes — a node appears in the DHT if and only if it itself wrote recently. This design lets neighbors refresh each other at age 1 (vouching), so a node that cannot write (behind a restrictive NAT for outbound DHT, or simply quiet) stays discoverable as long as any of its neighbors is active. For mobile and intermittent endpoints this materially improves representation.

3. **Sharded representation.** DTT stores at most 5 concurrent records per minute-key. In a 1:1000 partition, the minority's single writer rarely wins the race to occupy one of those five slots. This design hashes writers across K shards and provides quantified imbalance tolerance as a function of K.

4. **Adaptive heal-loop load.** Isolated nodes read all K slots; well-connected nodes read one. DTT reads two fixed slots every tick regardless of local view. Under heavy asymmetry the minority side here probes aggressively while the majority side spends almost no DHT bandwidth.

5. **Silence-tolerant partition detection.** DTT's strongest healing signal is disjointness of `last_message_hashes` — a real split-brain detector on chatty topics. On quiet topics (long-lived groups, coordination channels that rarely broadcast), `last_message_hashes` is mostly zeros on both sides and the detector degrades to the fallback "too few neighbors" rule. Here, any unknown ID discovered in the DHT triggers a dial attempt, independent of message traffic.

6. **Simpler crypto surface.** DTT layers HPKE-wrapped one-time keys, per-minute-rotated signing keys, and a pluggable SecretRotation trait. This design uses a single passphrase, deterministic slot addressing, two-layer AEAD for per-record key isolation, and a seq-based wrapper ratchet that does not require shared clocks or epoch-coordination among members.

Forward secrecy against passphrase compromise is a gap in both designs and is, we argue, unavoidable for any stateless-rejoin scheme built on a shared secret. See §9.

---

## 2. Preliminaries

**System model.** An asynchronous network of nodes participating in a gossip overlay (iroh-gossip, built on HyParView + Plumtree). Nodes have ephemeral identifiers regenerated each session. All nodes sharing an overlay also share a passphrase known out-of-band.

**Shared resource.** A set of K mutable slots on a DHT (BitTorrent Mainline / BEP 44). Each slot supports:

- `DhtRead(k) -> (bytes, seq)` or `⊥` if the slot is empty.
- `DhtWrite(k, bytes, seq)` — unconditional last-writer-wins across storage nodes; no compare-and-swap.

Each slot has a TTL; any write refreshes it. Concurrent writes at the same seq clobber. Per BEP 44, seq is monotonic per slot: a node writing must supply a seq greater than any it has observed for that slot. Honest writers assumed.

**Gossip primitives.** Every node exposes:

- `Neighbors()` returns the set of currently-connected active-view peer IDs.
- `JoinPeers(S)` hands a set S of candidate peer IDs to the gossip layer, which will dial unknowns and integrate them into its active or passive view.

**Keys.** From the passphrase, derive via HKDF:

- For each slot k in 0..K: a distinct Ed25519 keypair `(sk_k, pk_k)`. DHT slot address is `SHA1(pk_k)`; BEP 44 writes to slot k are signed by `sk_k`.
- A slot-scoped wrapper master key `W_k = HKDF-Expand(HKDF-Extract(passphrase), "wrap" || k)`, one per slot.

Per-record keys are derived on demand; see §3.

**Parameters.** Defaults below are starting points. Section 7 discusses the trade-offs.

| Symbol | Meaning | Default |
|---|---|---|
| K | Number of DHT slots (shards) | 3 |
| B | Max entries per slot | 27 |
| A_max | Max logical age before eviction | 27 |
| V | Max vouches per write | 3 |
| E | Seq-ratchet epoch size (writes per epoch) | 64 |
| T_w | Mean write-loop period | 5 min |
| T_h | Mean heal-loop period | 30 s |
| σ | Jitter factor | ±50% |

## 3. Data Structures

**Record.** One per slot. A sequence of fixed-width binary entries:

```
R_k = [(id_1, a_1), (id_2, a_2), ..., (id_n, a_n)],  n ≤ B
```

where `id_i` is a 32-byte Ed25519 endpoint ID and `a_i` is its logical age, in the range `[0, A_max)`, encoded as a single byte.

**Two-layer encryption.** Each record is encrypted with a fresh 32-byte one-time key `k_r` sampled at write time. `k_r` is then wrapped under a seq-ratcheted wrapper key:

```
e       = floor(seq / E)                               # epoch number
W_k^(e) = HKDF-Expand(W_k, "epoch" || e_be64)          # per-epoch wrapper
```

Every E writes to slot k, the wrapper key rotates. Readers see seq alongside the record and derive the same e. Writers compute `seq = prev_seq + 1` and derive accordingly. No wall clock is involved.

**Wire format.** Before BEP 44 wrapping:

```
┌────────────┬────────────┬──────────┬──────────┬──────────────┬──────────┐
│ wrap_nonce │ wrap_ct    │ wrap_tag │ entry_1  │   entry_2 …  │ body_tag │
│  (12 B)    │  (32 B)    │  (16 B)  │  (33 B)  │ (33 B each)  │  (16 B)  │
└────────────┴────────────┴──────────┴──────────┴──────────────┴──────────┘
    entry_i = id (32 B) || age (1 B)
```

- `wrap_ct || wrap_tag` is `ChaCha20-Poly1305(W_k^(e), wrap_nonce, k_r)` with `wrap_nonce` freshly random.
- `entry_1 ... entry_n || body_tag` is `ChaCha20-Poly1305(k_r, zeros(12), entries)`. The body nonce is fixed at zero; safe because `k_r` is used for exactly one encryption. `k_r` is zeroized after the write (and after each decryption at readers).
- The full byte string goes in BEP 44's `v` field as a bencode byte string. BEP 44's `sig` provides authentication via Ed25519 signature by `sk_k`. The seq field is as computed above.

**Byte budget.** BEP 44 storing nodes may reject puts whose bencoded `v` exceeds 1000 bytes. A bencode byte string of N payload bytes serializes as `<ascii-length>:<bytes>`. For N in [100, 999] the prefix is 4 bytes, leaving 996 bytes for payload. Crypto overhead is `12 + 32 + 16 + 16 = 76` bytes, leaving 920 bytes for entries, accommodating `floor(920 / 33) = 27` entries. At B = 27, payload is `76 + 27*33 = 967` bytes, bencoded to 971 bytes — safe. B = 28 would produce 1000 bytes of payload which serializes with a 5-byte prefix to 1005 bytes, over the limit.

**Local state at node u.**

- `self_u`: u's endpoint ID for this session.
- `slot_u = H(self_u) mod K`: u's assigned **write** slot. Computed once at startup.
- Access to `Neighbors()` and `JoinPeers(·)`.

No per-node persistent state beyond that. Wrapper master keys are re-derivable from the passphrase on demand. Per-epoch wrappers and per-record `k_r` are ephemeral.

## 4. Primitive Procedures

```
procedure ReadSlot(k):
    (b, seq) ← DhtRead(k)
    if b = ⊥: return (∅, 0)
    if not VerifySig(pk_k, b): return (∅, 0)
    (wrap_nonce, wrap_ct, body_ct) ← ParseWire(b)
    e   ← floor(seq / E)
    W_e ← HKDF-Expand(W_k, "epoch" || be64(e))
    k_r ← AEAD-Open(W_e, wrap_nonce, wrap_ct)
    if k_r = ⊥: return (∅, 0)
    R   ← AEAD-Open(k_r, zeros(12), body_ct)
    zeroize(k_r)
    return (R, seq)
```

```
procedure WriteSlot(k, R, prev_seq):
    seq ← prev_seq + 1
    e   ← floor(seq / E)
    W_e ← HKDF-Expand(W_k, "epoch" || be64(e))
    k_r        ← Random(32)
    wrap_nonce ← Random(12)
    wrap_ct    ← AEAD-Seal(W_e, wrap_nonce, k_r)
    body_ct    ← AEAD-Seal(k_r, zeros(12), Serialize(R))
    zeroize(k_r)
    b ← wrap_nonce || wrap_ct || body_ct
    DhtWrite(k, Sign(sk_k, b), seq)
```

```
procedure ReadAll():                              # used only during Join
    U ← ∅
    for k in 0..K in parallel:
        (R_k, _) ← ReadSlot(k)
        U ← U ∪ { id : (id, _) ∈ R_k }
    return U
```

```
procedure Merge(R):                               # new record for self's slot
    # Age up non-self entries; drop those that would reach A_max.
    R' ← { (id, a+1) : (id, a) ∈ R, a + 1 < A_max }

    # Refresh self at age 0.
    R' ← R' \ { (id, _) : id = self_u }
    R' ← R' ∪ { (self_u, 0) }

    # Vouch for up to V neighbors at age 1. No same-slot restriction.
    N  ← Neighbors()
    N' ← RandomSample(N, min(V, |N|))
    for each id in N':
        if (id, a) ∈ R' for some a:
            R' ← R' \ { (id, a) } ∪ { (id, min(a, 1)) }
        else:
            R' ← R' ∪ { (id, 1) }

    # Evict by max age; ties broken uniformly at random.
    while |R'| > B:
        A_star ← max { a : (id, a) ∈ R' }
        (id, A_star) ← UniformRandom among entries at that age
        R' ← R' \ { (id, A_star) }

    return R'
```

**Notes.**

- Vouches are not restricted to same-slot neighbors. A vouched entry may appear in a slot other than the vouchee's `H(id) mod K`. This is intentional — discovery reads aggregate across slots and any appearance of id in any slot is sufficient for healing.
- Max-age eviction with random tie-breaking never removes the freshest entries. This preserves the staleness bound in §6 regardless of record pressure.
- A node's self-entry is canonically written only to `slot_u`. That invariant is what sharding continues to provide (see Property 5).

## 5. Node Protocol

Each node runs three concurrent procedures after startup: `Join` once, then `HealLoop` and `WriteLoop` forever. The `Join` procedure is split into two halves — a synchronous `Join()` that gathers known peers from the DHT and hands them to the gossip layer, and a self-publish that happens on the first `WriteLoop` iteration. Splitting them lets the caller obtain a `Rendezvous` handle in one DHT round-trip rather than two.

```
procedure Join():
    U ← ReadAll()
    JoinPeers(U)
    # Start WriteLoop (and HealLoop). The first WriteLoop iteration will
    # publish our self-entry to slot_u — see WriteLoop below.
```

```
procedure HealLoop():
    loop:
        sleep T_h · Jitter(σ)
        s ← max(1, K - |Neighbors()|)
        S ← UniformRandomSubset(0..K, s)
        U ← ∅
        for k in S in parallel:
            (R_k, _) ← ReadSlot(k)
            U ← U ∪ { id : (id, _) ∈ R_k }
        U' ← U \ Neighbors() \ { self_u }
        if U' ≠ ∅: JoinPeers(U')
```

```
procedure WriteLoop():
    first_iter ← true
    loop:
        if first_iter:
            first_iter ← false
            # Unconditional publish on startup to complete §5 Join.
            (R, seq) ← ReadSlot(slot_u)
            R' ← Merge(R)
            WriteSlot(slot_u, R', seq)
        else:
            sleep T_w · Jitter(σ)
            p ← 1 / (|Neighbors()| + 1)
            with probability p:
                (R, seq) ← ReadSlot(slot_u)
                R' ← Merge(R)
                WriteSlot(slot_u, R', seq)
```

`Jitter(σ)` returns a value drawn uniformly from `[1-σ, 1+σ]`.

**Optional `AwaitJoinedOrTimeout`.** Callers who need the pre-0.2 behavior (block `Join` until at least one gossip neighbor has come up, with a timeout) can set `Builder::wait_for_first_neighbor(Some(duration))`. The default is `None` — `Join` returns as soon as `ReadAll` + `JoinPeers` complete.

**Leave.** No protocol action. The node exits and its entry ages out within A_max subsequent writes to each slot it appears in.

## 6. Correctness Properties

**Property 1 (Bounded Staleness).** For any entry `(id, a)` observed by a reader in slot k at time t, the most recent creation or refresh of that entry in that slot occurred within the last A_max `WriteSlot(k, ...)` operations.

Sketch. `Merge` increments every non-self entry by 1 and discards entries that would reach A_max. A surviving entry of age a was created or refreshed at most a < A_max writes ago. Max-age eviction only advances the departure of already-oldest entries; it cannot remove a fresher one. An id may appear in multiple slots via cross-slot vouches, but the staleness bound is evaluated per slot.

**Property 2 (Probabilistic Partition Healing).** Let P_1 and P_2 be two non-empty, disjoint connected components of the gossip overlay at time t_0. Under any schedule where both components write at positive rate, the probability that they merge by time `t_0 + t` approaches 1 as t grows.

Sketch. Every `WriteLoop` execution by any node in a component refreshes that node's self-entry at age 0 and may vouch for up to V neighbors. Every `HealLoop` at a node in the other component reads s random slots and, with per-heal probability s/K, reads a slot containing a writer from the first component; it then calls `JoinPeers` on any unknown IDs. With write probability at least `1/(n+1) > 0` per node per T_w, every non-empty component writes somewhere each cycle. Summing random-slot reads across all nodes in the other component, every slot is read with positive rate. The probability of a successful cross-component dial in the window is lower-bounded by `1 - exp(-λt)` for some λ > 0.

**Property 3 (Per-Component Liveness).** Every live endpoint id is represented in at least one slot within expected time O(T_w) after joining its component, provided id has at least one neighbor.

Sketch. The WriteLoop's first iteration is unconditional (see §5), so id is represented in `slot_u` within `T_w · Jitter(σ)` of joining — constant time, not an expected value, for the first publish. Thereafter either id writes (probability `1/(|Neighbors(id)| + 1)` per T_w) or a neighbor vouches for id (each neighbor that writes vouches for id with probability at least `min(V, |Neighbors(voucher)|) / |Neighbors(voucher)|`). Without the same-slot restriction, time-to-first-representation does not scale with K.

**Property 4 (Bounded Record Size).** After any `Merge`, `|R'| ≤ B`, so each slot's BEP 44 put fits within the 1000-byte `v` limit.

Direct from construction: the eviction loop terminates only when `|R'| ≤ B`, and the byte-budget calculation in §3 shows B = 27 fits.

**Property 5 (Sharding Fairness for Self-Writes).** A component of size s contributes self-writes to an expected `min(K, s)` distinct slots.

Sketch. IDs hash uniformly into slots and each node writes its self-entry only to `slot_u`. Self-write load on any one slot is reduced by factor approximately K relative to a single-slot design. Vouches cross slots, so an entry may appear in multiple slots, but vouches do not originate new aging trajectories — they piggyback on the voucher's write. Effective per-slot aging pressure is still reduced by factor about K.

**Property 6 (Per-Epoch Key Isolation).** An adversary that compromises a single record's one-time key `k_r` learns only that record's plaintext; all other records, including others from the same epoch, remain confidential under independent one-time keys.

Sketch. Each `k_r` is sampled independently and used for exactly one AEAD encryption, then zeroized. Recovery of one `k_r` gives no information about the others, which are wrapped under `W_k^(e)` with independent random `wrap_nonce` values. AEAD security of ChaCha20-Poly1305 ensures compromise of a `k_r` does not compromise `W_k^(e)`.

See §9 for what this property does not give.

## 7. Parameter Constraints

**Age cap equals size cap.** `A_max = B`. Setting `A_max > B` lets old entries crowd out fresh ones when a record is size-saturated. Setting `A_max < B` evicts live entries prematurely. Default 27 in both.

**Shard count K trades bandwidth for imbalance tolerance.** K multiplies both read and write DHT operations by K. Each additional shard spreads write pressure across more keys, so the minority side of an imbalanced partition is less likely to be crowded out. K = 3 is the recommended default for typical overlays (tens to low hundreds of nodes). K = 5 extends safety to pathological imbalances at higher DHT cost. K = 1 is degenerate — no sharding — and collapses to behavior similar to DTT's under heavy asymmetry.

**Vouch count V.** Every vouch is usable (no slot filter). Default V = 3 is a bandwidth/representation compromise. Raising V improves representation of quiet nodes in their voucher's slot at the cost of record pressure (more competing entries per write).

**Epoch size E.** E controls wrapper ratchet frequency. Larger E means more records per wrapper key; smaller E means faster rotation at negligible derivation cost. Default E = 64 produces epoch durations ranging from about an hour in dense components to ten hours in sparse ones, assuming T_w = 5 min and typical neighbor counts.

**Heal-loop period T_h ≪ T_w.** Reading is cheap compared to writing in terms of DHT load; heal-reads do not cause clobbers. T_h/T_w = 1/10 is the knee — smaller ratios multiply DHT read load without meaningful heal-time reduction.

**Adaptive per-heal slot count.** `HealLoop` reads `max(1, K - |Neighbors()|)` random slots per iteration. An isolated node with zero neighbors reads all K; a saturated node at HyParView's active-view cap reads one. Aggregate DHT read load drops by roughly K in well-connected regimes while healing speed in pathological cases improves — the minority side, which has few neighbors, reads the most slots.

**Write-loop period T_w.** T_w does not affect steady-state representation because the probabilistic write rule `p = 1/(n+1)` is time-scale invariant. Choose T_w based on DHT bandwidth budget alone. Default T_w = 5 min yields a few writes per minute across any overlay size.

**B is not tunable.** It's dictated by BEP 44's 1000-byte `v` limit, ChaCha20-Poly1305 overhead, and the fixed-width entry format. Changing B requires changing the wire format.

## 8. Simulation + formal-verification results

Safety invariants `§6 Property 1` (bounded staleness) and `§6 Property 4` (bounded record size) are verified by two independent techniques:

**Kani (bounded model checking).** Six `#[kani::proof]` harnesses in `src/kani_proofs.rs` verify `|R'| ≤ B`, `age < A_max`, self-always-at-zero, wire-format roundtrip correctness, and decode-no-panic on arbitrary bytes. Harnesses are symbolic-bounded at `current.len() ≤ 3` and `neighbors.len() ≤ 2`, chosen to keep each harness under 60s on CI.

**Stateright (distributed-system model checking).** `tests/stateright_model.rs` implements an `Actor`-style model of the WriteLoop + HealLoop + Dial actions. BFS-explored state spaces:

| Bound | Depth | Runtime | Result |
|---|---|---|---|
| `N=2, K=1, A_max=3, B=3, V=1` | 20 | seconds | Safety invariants (S1, S2) hold across every reachable state |
| `N=3, K=2, A_max=4, B=4, V=2` | 30 | ~3s | Safety invariants hold across every reachable state |

A random-walk checker at `N=6, K=3, A_max=5, B=5, V=3` explores up to depth 50 with no counterexamples — this is *not* a proof, just statistical evidence for configurations larger than BFS can reach.

### Discrete-event simulator results (§2 defaults, per `cargo run --release --example simulator --features sim`)

| Scenario | Config | Runs | Heal rate | p50 rounds | p95 rounds |
|---|---|---|---|---|---|
| Cold start | `N=8, K=3` | 50 | **100%** | 1 | 1 |
| Symmetric partition | `4+4, K=3` | 50 | **100%** | 1 | 1 |
| Asymmetric partition | `1 vs 10, K=3` | 50 | **100%** | 1 | 1 |
| Asymmetric partition | `1 vs 100, K=3` | 20 | **0%** | — | — |

**Finding.** The default `K=3` handles cold-start, symmetric, and modest-asymmetry partitions in a single round. At 1:100 imbalance, the minority's single writer is crowded out of the shared slot by the 33 majority writers hashing into the same slot — they evict by max-age, and the minority ages past threshold before a majority reader picks the right slot.

**Mitigation for 1:100+ asymmetry.** Raise `K` (more shards), or raise `V` (more vouches propagating the minority across slots), or both. The 1:1000 bound targeted by the §1 prior-art claim is not yet achieved with defaults. Raising `K=10, V=5` is a proposed remediation; validation is future work.

### Out of scope for this release

- Churn scenarios (0–20% per T_w): framework in simulator, results not archived.
- Parameter sweeps over K ∈ {1,2,3,5,10}, V ∈ {0,1,3,9}, T_h/T_w ∈ {1/5,1/10,1/20}, E ∈ {16,64,256}: simulator supports them (`cargo run --example simulator -- --help`); default-moving decisions from the sweep will drive a 0.3 release.
- Liveness (§6 Property 2 partition healing under fairness): modelled in Stateright but not yet exhaustively checked — left for 0.3.

## 9. Security Limitations

The seq-ratcheted wrapper in §3 provides:

- **Per-record key isolation** (Property 6): compromise of one `k_r` does not cascade.
- **Per-epoch segregation:** records across different epochs are encrypted under distinct wrapper keys. Compromise of `W_k^(e)` does not directly compromise `W_k^(e')` for a different e'.
- **Unlinkability at the key level:** the signing keypair is long-term, but wrapper keys rotate, so DHT captures from different epochs are not trivially linkable at the content layer.

It does not provide:

- **Forward secrecy against passphrase compromise.** `W_k` and every `W_k^(e)` are deterministic functions of the passphrase. An adversary who obtains the passphrase at time t can decrypt any captured ciphertext from any time, past or future. No stateless-rejoin scheme with a shared passphrase can avoid this; true forward secrecy requires per-member secret state that evolves over time, which breaks stateless rejoin by design.
- **Post-compromise security against a current member.** Any member can derive `W_k` and produce or decrypt records indefinitely. Removing a member without rotating the passphrase does nothing to stop them from continuing to read. Passphrase rotation is an out-of-band operation.
- **Metadata confidentiality.** DHT observers see slot addresses (public, derived from `pk_k`), record sizes, write frequencies, and seq progression. These leak structural information: number of active slots, rough write rate, approximate member count.
- **Resistance to an adversary holding a past passphrase.** If the passphrase rotates at time t but an ex-member archived DHT captures from before t, they can still decrypt everything up to t.

For threat models requiring forward secrecy against passphrase compromise or post-compromise security, the recommended path is to layer a group-key-agreement protocol (e.g., MLS / RFC 9420) on top of the gossip channel, keyed initially from the passphrase-derived wrapper. The DHT layer described here would then carry only signaling — enough to rendezvous and bootstrap the MLS epoch state — and payload encryption would move into the application layer. The algorithm in sections 2 through 7 is compatible with this extension: replace `W_k^(e)` with the current MLS epoch secret, and nothing else changes.

## 10. Change Log

Version history lives in [`CHANGELOG.md`](CHANGELOG.md). Changes to the wire format or the algorithmic defaults (§2 parameter table) are called out explicitly there; a change at that level always bumps the minor version in 0.x or the major version post-1.0, and is guarded by `cargo-semver-checks` + `tests/spec_drift.rs` in CI.

## Appendix A: BEP 44 byte-budget derivation

BEP 44 storing nodes may reject puts whose bencoded `v` exceeds 1000 bytes. A bencode byte string of N payload bytes serializes as `<ascii-length>:<bytes>`. For N ∈ [100, 999] the prefix is 4 bytes, leaving 996 bytes for payload.

With `ChaCha20-Poly1305`, crypto overhead per §3 is `wrap_nonce(12) + wrap_ct(32) + wrap_tag(16) + body_tag(16) = 76` bytes. That leaves 920 bytes for entries, accommodating `floor(920 / 33) = 27` entries (since `ENTRY_LEN = 32 + 1 = 33`).

At B = 27, payload is `76 + 27 * 33 = 967` bytes, bencoded to 971 bytes — safe.
At B = 28, payload is `76 + 28 * 33 = 1000` bytes, bencoded with a 5-byte prefix (`"1000:"`) to 1005 bytes — over the limit.

Hence the `MAX_ENTRIES = 27` hard cap. Confirmed by `wire::tests::envelope_at_max_entries_fits_bep44_budget`.
