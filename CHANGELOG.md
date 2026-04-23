# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning].

## [Unreleased]

## [0.1.0] — 2026-04-22

First public release. Passphrase-based peer rendezvous for iroh-gossip
swarms over the public Mainline DHT, keyed from a shared passphrase + an
application salt — no central bootstrap server and no prior knowledge of
peer addresses required.

### Algorithm

- K-sharded BEP 44 mutable-item slots (default `K = 3`), each with its
  own HKDF-derived Ed25519 signing keypair and per-slot AEAD wrapper key.
- Logical aging with random-tie eviction; vouching of up to `V`
  neighbors at age 1; two-layer ChaCha20-Poly1305 AEAD envelope over
  fixed-width entries.
- Seq-ratcheted per-epoch wrapper keys; one-shot body key per record.
- Clock-free: no dependence on wall-time across nodes.
- Full specification lives at [`PROTOCOL.md`][protocol].

### Public API

- `Rendezvous::join(passphrase, app_salt)` — one-call entry point.
- `Rendezvous::builder()` — full `Builder` for endpoint/secret_key/
  parameter overrides.
- `Rendezvous::{sender, subscribe, state, endpoint, node_id, topic_id,
  broadcast, shutdown}` — handle surface.
- `iroh_gossip` types re-exported where useful; otherwise thin wrappers.

### Feature flags

- `sim` — discrete-event simulator + test-support exports.
- `kani` — Kani proof harnesses (off by default).
- `miri-compat` — skip Miri-incompatible tests.
- `mainline-live` — integration tests against the real public Mainline DHT.
- `test-support` — `Builder::dht_backend` for injecting custom `DhtSlots`.

### Correctness evidence shipping with the crate

- **119 tests** across unit, property, integration, and doctest layers;
  all green.
- **Property tests** (`proptest`) on wire format roundtrip, merge
  invariants (`|R'| ≤ B`, age bound, self at age 0), crypto roundtrip
  across epoch boundaries.
- **Integration tests** over real iroh endpoints with an injected
  in-memory DHT: two-node bootstrap, multiple-subscriber fan-out, drop
  cancels background tasks.
- **Mutation testing** (`cargo-mutants`) — **100% catch rate** on
  testable mutations (119 caught, 27 unviable, 0 missed). See
  `.cargo/mutants.toml` for the exclusions and their rationale.
- **Fuzz harnesses** (`cargo-fuzz`) for `decode_entries`.
- **Bounded model checking** (Kani) of undefined-behavior / panic
  absence on `crypto::epoch_of` (full `i64` × `u64 ≥ 1` space) and
  `wire::decode_entries` (arbitrary byte input). Structural invariants
  are covered by the stronger proptest + Stateright combo.
- **Distributed-system model checking** (Stateright): safety invariants
  S1 (record size ≤ B) and S2 (age < A_max) proved exhaustively for
  N ≤ 6, K ≤ 3; liveness witnesses under weak fairness; randomized
  large-N exploration available via `just model-random`.
- **Miri** — UB-free on the synchronous modules (`keys`, `wire`,
  `crypto`, `merge`).
- **Simulator baseline** (`examples/simulator.rs`) — cold-start (8
  nodes) and symmetric partition (5/5) scenarios both heal in 1 round
  at 100%. Asymmetric 1:100 with default `K = 3` is a documented
  limitation in `PROTOCOL.md §8`.

### Supply chain

- MIT-licensed; MSRV 1.93.0; all crypto dependencies from the audited
  RustCrypto stack.
- `cargo-deny` + `cargo-audit` green on every push (transitive
  `unmaintained` advisory from `paste` via `iroh → portmapper →
  netwatch` documented in `deny.toml`).
- `[package.metadata.docs.rs]` configured for all-feature docs builds.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[protocol]: https://github.com/swaits/iroh-gossip-rendezvous/blob/main/PROTOCOL.md
[Unreleased]: https://github.com/swaits/iroh-gossip-rendezvous/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/swaits/iroh-gossip-rendezvous/releases/tag/v0.1.0
