# Description

<!-- What does this PR do and why? -->

## Checklist

- [ ] Tests added / updated for the behavior touched.
- [ ] `just check` green locally.
- [ ] If public API changed: `cargo semver-checks` considered; version bump in the PR title.
- [ ] If wire format / PROTOCOL.md changed: `tests/spec_drift.rs` updated; CHANGELOG entry added.
- [ ] If algorithmic core (`keys`/`wire`/`crypto`/`merge`/`protocol`) changed: re-ran `just mutants` and `just kani` locally.
