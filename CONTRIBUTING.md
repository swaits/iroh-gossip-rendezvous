# Contributing to iroh-gossip-rendezvous

Bug reports, feature requests, and pull requests welcome.

## Developer setup

```sh
# Clone the repo.
git clone https://github.com/swaits/iroh-gossip-rendezvous
cd iroh-gossip-rendezvous

# Install the dev toolchain. Most tools are lightweight; Kani is the
# heaviest and only needed if you're running formal proofs.
cargo install --locked \
    cargo-nextest \
    cargo-llvm-cov \
    cargo-deny \
    cargo-audit \
    cargo-semver-checks \
    cargo-mutants \
    cargo-fuzz

# Optional: Kani bounded model checker (needed only for `just kani`).
cargo install --locked kani-verifier
cargo kani setup  # one-time; downloads the solver toolchain.

# Optional: just (task runner). Most distros package it; via cargo:
cargo install just

# Sanity check.
just check
```

MSRV is **1.93.0**. Newer Rust features are not allowed in the main
crate; they are allowed in `dev-dependencies` and examples only.

## Local testing

Every CI lane is replayable locally via `just`:

| Task | What it runs |
|---|---|
| `just check` | fmt check + clippy + nextest + doctests (the fast CI lane) |
| `just test` | nextest + doctests only |
| `just fmt` | apply rustfmt |
| `just clippy` | lint only |
| `just deny` | cargo-deny (licenses, advisories, bans) |
| `just audit` | cargo-audit (RUSTSEC) |
| `just semver` | cargo-semver-checks vs last published |
| `just coverage` | cargo-llvm-cov HTML report |
| `just mutants` | cargo-mutants (30–90 min) |
| `just fuzz TARGET=x` | 60s fuzz run (nightly toolchain required) |
| `just miri` | cargo-miri on sync modules (nightly) |
| `just kani` | Kani proofs (`kani` feature) |
| `just model-bfs` | Stateright BFS N=4, K=3 |
| `just model-random` | Stateright random N=20, K=3, 10⁷ steps |
| `just bench` | criterion (not a release gate) |
| `just docs` | open rustdoc locally |
| `just all` | everything, in order |

## Before you open a PR

- `just check` must pass locally.
- Add tests for new behavior. Aim for ≥90% coverage on the module you
  touched; crate-wide minimum is 85%.
- If you change the wire format, the protocol spec, or public API, update
  `PROTOCOL.md` / `CHANGELOG.md` / doctests as appropriate.
- If you touch the algorithmic core (`keys`, `wire`, `crypto`, `merge`,
  `protocol`), re-run `just mutants` and `just kani` locally.
- Breaking API changes require `cargo-semver-checks` to flag them and a
  major/minor version bump depending on the semver rules.

## Where things live

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the module map.

- Algorithm spec: [`PROTOCOL.md`](PROTOCOL.md).
- Security posture: [`SECURITY.md`](SECURITY.md).
- API docs: run `just docs` or visit <https://docs.rs/iroh-gossip-rendezvous>.

## Style

- `rustfmt` with default config; `clippy pedantic + nursery` with the
  module-level allows documented in `Cargo.toml`'s `[lints.clippy]` block.
- `unwrap_used`, `expect_used`, `panic` denied in non-test code. If you
  need one, justify it with a SAFETY comment and `#[allow(...)]`.
- Keep async code in `protocol.rs` / `rendezvous.rs` / `gossip_glue.rs`.
  Algorithmic core (`keys`, `wire`, `crypto`, `merge`) must stay pure —
  Miri and Kani both want sync code.

## License

By contributing, you agree that your contributions will be licensed under
the [MIT license](LICENSE).
