# iroh-gossip-rendezvous

[![crates.io](https://img.shields.io/crates/v/iroh-gossip-rendezvous.svg)](https://crates.io/crates/iroh-gossip-rendezvous)
[![docs.rs](https://img.shields.io/docsrs/iroh-gossip-rendezvous)](https://docs.rs/iroh-gossip-rendezvous)
[![CI](https://github.com/swaits/iroh-gossip-rendezvous/workflows/CI/badge.svg)](https://github.com/swaits/iroh-gossip-rendezvous/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.93.0-blue)](#msrv)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Zero-configuration peer rendezvous for [iroh-gossip] swarms.** Two nodes
that share a passphrase and an application label find each other over the
public [Mainline DHT] and join the same gossip topic — no bootstrap server,
no prior knowledge of peer addresses.

```rust,no_run
use iroh_gossip_rendezvous::Rendezvous;

# async fn run() -> anyhow::Result<()> {
let rendezvous = Rendezvous::join("my-shared-passphrase", "my-app/v1").await?;

// Send to the swarm.
rendezvous.broadcast(bytes::Bytes::from_static(b"hello")).await?;

// Receive swarm events.
let mut events = rendezvous.subscribe();
while let Ok(event) = events.recv().await {
    println!("{event:?}");
}
# Ok(()) }
```

## How it works

The crate implements a clock-free variant of HyParView-style partition
healing on top of BEP 44 mutable items. Every `(passphrase, app_salt)` pair
deterministically derives:

- A gossip `TopicId` (via HKDF-SHA256).
- `K` independent DHT slot keys (default `K=3`), each with its own Ed25519
  signing key and a per-slot AEAD wrapper key.

Nodes publish their endpoint ID to one of the `K` slots and read from a
changing subset of slots to discover peers. Records age out naturally, so
crashed or silently-departed nodes don't clutter the DHT indefinitely. A
two-layer AEAD envelope (per-record one-time key wrapped under a
seq-ratcheted per-epoch key) ensures content confidentiality against DHT
observers.

See **[PROTOCOL.md](PROTOCOL.md)** for the full algorithm specification.
See **[ARCHITECTURE.md](ARCHITECTURE.md)** for a module map.

## Correctness

The crate ships with a test suite that goes beyond unit tests:

- **Property tests** (proptest) for wire format, merge invariants, and AEAD
  roundtrips.
- **Integration tests** driving multi-node scenarios over an in-memory DHT:
  cold start, partition healing, asymmetric minority visibility.
- **Mutation testing** (cargo-mutants) on the algorithmic core.
- **Fuzz harnesses** (cargo-fuzz) for `decode_entries`, `crypto::open`,
  merge, and wire-format roundtrip.
- **Bounded model checking** (Kani) of **absence of undefined behavior**
  on pure algorithmic entry points: `crypto::epoch_of` never panics /
  overflows for any `(i64 seq, u64 epoch_size ≥ 1)`; `wire::decode_entries`
  never panics on arbitrary byte input. Structural invariants (merge size
  bound, age bound, roundtrip) are covered by the stronger proptest +
  Stateright combination — Kani's niche here is UB-absence at the
  slice/iterator boundary.
- **Distributed-system model checking** (Stateright): bounded safety +
  liveness witness for `N ≤ 6, K ≤ 3` under weak fairness; randomized
  exploration of 10⁷ states for `N = 20`.
- **Miri** UB checks on the synchronous modules (keys, wire, crypto, merge).

The precise claim: *the record-size and age invariants always hold across
all explored reachable states up to N=6, K=3; under a weak-fairness
assumption on action scheduling, any bipartite-partitioned initial state
eventually reaches a state where both components overlap. For larger N,
randomized exploration has found no counterexample. This is not a proof for
unbounded deployments — it is the strongest tractable evidence available
short of a hand proof.*

## Security

See [SECURITY.md](SECURITY.md) for the threat model and known limitations.
Short version: the design protects against DHT observers and passive
eavesdroppers, but not against a compromise of the passphrase (no forward
secrecy) or a malicious member (no post-compromise security). For threat
models requiring those properties, layer MLS / RFC 9420 on top.

## Features

| Feature | Default | Purpose |
|---|---|---|
| `sim` | off | Discrete-event simulator (`examples/simulator.rs`) + test-support exports |
| `kani` | off | Build Kani proof harnesses (`#[kani::proof]` functions) |
| `miri-compat` | off | Skip Miri-incompatible tests (`#[cfg_attr(miri, ignore)]`) |
| `mainline-live` | off | Tests against the real public Mainline DHT (flaky, nightly-only) |
| `test-support` | off | Exposes `Builder::dht_backend` for injecting an in-memory DHT in integration tests |

## MSRV

Minimum Supported Rust Version: **1.93.0**. Enforced in CI. Bumps are minor
releases; we don't raise MSRV without releasing a new minor version.

Pinned iroh / iroh-gossip major versions: `0.98.x`. Bumping the iroh major
will be a minor version of this crate.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Local testing via [`just`]:

```sh
just check            # fmt + clippy + nextest + doctests (fast CI lane)
just all              # everything including miri, kani, stateright
```

See the [CHANGELOG](CHANGELOG.md) for release history.

## License

MIT. See [LICENSE](LICENSE).

[iroh-gossip]: https://docs.rs/iroh-gossip
[Mainline DHT]: https://en.wikipedia.org/wiki/Mainline_DHT
[`just`]: https://just.systems/
