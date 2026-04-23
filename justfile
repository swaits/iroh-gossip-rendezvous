# iroh-gossip-rendezvous task runner.
# Every CI lane replayable locally. Matches .github/workflows/{ci,nightly}.yml.

default: check

# ── Fast lane (matches CI per-push) ────────────────────────────────

# Format + lint + fast tests. Match CI fast-lane exactly.
check: fmt-check clippy test

# rustfmt — verify only (CI mode).
fmt-check:
    cargo fmt --check

# rustfmt — apply.
fmt:
    cargo fmt

# clippy with deny-warnings, all features.
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Unit + integration + doctests. nextest is faster for the first two.
test: test-lib test-doc

test-lib:
    cargo nextest run --all-features

test-doc:
    cargo test --doc --all-features

# Supply-chain hygiene.
deny:
    cargo deny check

audit:
    cargo audit

# SemVer compliance vs the last released version. Skipped until the crate
# has a baseline on crates.io (i.e., post-0.1.0 publish).
semver:
    @if cargo semver-checks check-release 2>&1 | grep -q "not found in registry"; then \
        echo "skip: crate not yet on crates.io (pre-first-publish)"; \
    else \
        cargo semver-checks check-release; \
    fi

# ── Slow / nightly lane ────────────────────────────────────────────

# Line + branch coverage via LLVM source-based coverage.
coverage:
    cargo llvm-cov --all-features --html
    @echo "Report: target/llvm-cov/html/index.html"

coverage-lcov:
    cargo llvm-cov --all-features --lcov --output-path lcov.info

# Mutation testing. Long-running.
mutants:
    cargo mutants --all-features --timeout-multiplier 3.0

# Fuzz a single target for 60s (parameterized). Requires nightly toolchain.
# Usage: just fuzz fuzz_decode_entries
fuzz TARGET:
    cd fuzz && cargo +nightly fuzz run {{TARGET}} -- -max_total_time=60

# Miri UB check on the pure algorithmic modules (keys / wire / crypto / merge).
# Other modules use tokio I/O which Miri can't drive. ~5-10 min per module.
miri:
    MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test --lib \
        keys:: wire:: crypto:: merge::

# Kani bounded model checking on the pure algorithmic core.
#
# Marches through all harnesses cheapest → priciest, bailing on the first
# failure (just's default fail-fast recipe semantics). A per-process memory
# cap (ulimit -v) keeps a runaway proof from OOMing the machine — if a
# harness blows the cap it dies with an allocation error and the recipe
# stops, rather than swapping the system to death.
#
# Tune KANI_MEM_KB for your box (default 6 GB suits an 8-GB laptop):
#   KANI_MEM_KB=3145728 just kani   # 3 GB cap
#
# Run a single harness with: `just kani-one <name>`.
KANI_MEM_KB := env_var_or_default("KANI_MEM_KB", "6291456")

kani:
    @echo "Running Kani harnesses in order, bailing on first failure."
    @echo "Per-process memory cap: {{KANI_MEM_KB}} KB."
    just kani-one crypto_epoch_of_no_overflow
    just kani-one wire_decode_no_panic
    @echo "All Kani harnesses passed."

# Run a single Kani harness under a memory cap. Usage: `just kani-one NAME`.
kani-one NAME:
    @echo "━━━ kani: {{NAME}} ━━━"
    ulimit -v {{KANI_MEM_KB}} && cargo kani --harness {{NAME}}

# Stateright: BFS safety + bounded liveness for N=4, K=3. Minutes.
model-bfs:
    cargo test --test stateright_model --release -- --ignored bfs_small

# Stateright: random-walk for N=20, K=3, 10^7 steps. ~10 minutes.
model-random:
    cargo test --test stateright_model --release -- --ignored random_large

# Criterion benchmarks.
bench:
    cargo bench --all-features

# ── Docs ───────────────────────────────────────────────────────────

# Build and open rustdoc.
docs:
    cargo doc --no-deps --all-features --open

# Build docs without opening (CI).
docs-build:
    cargo doc --no-deps --all-features

# ── Aggregate targets ──────────────────────────────────────────────

# Everything: the whole CI matrix locally. Heavy.
all: check coverage deny audit semver miri kani model-bfs bench docs-build
    @echo "All checks green."

# ── Simulator ──────────────────────────────────────────────────────

# Run the §8 scenario matrix and archive results.
sim-matrix:
    cargo run --release --example simulator --features sim -- --scenario cold-start --nodes 8 --runs 50
    cargo run --release --example simulator --features sim -- --scenario partition --nodes 10 --runs 50
    cargo run --release --example simulator --features sim -- --scenario asymmetric --minority 1 --majority 10 --runs 50
    cargo run --release --example simulator --features sim -- --scenario asymmetric --minority 1 --majority 100 --runs 20

# ── Release ────────────────────────────────────────────────────────

# Dry-run publish. Must be green before tagging.
publish-check: all
    cargo publish --dry-run
