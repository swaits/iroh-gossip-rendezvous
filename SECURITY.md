# Security Policy

## Reporting a vulnerability

Email **steve@waits.net** with the subject prefix `[iroh-gossip-rendezvous
security]`. Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce, ideally with a minimal test case.
- Your suggestion for a fix or mitigation, if you have one.

I'll acknowledge receipt within 5 business days and aim to publish a fix
(or a detailed mitigation advisory) within 30 days. Please do not file a
public issue for security vulnerabilities until a fix is available.

## Supported versions

Only the latest minor release receives security fixes. Older `0.x` lines
become unsupported once a newer minor version ships. `1.0` will establish
a longer support window.

## Threat model

The crate's design assumes:

- The public Mainline DHT is **untrusted**: any node can read any slot,
  publish spoofed records under keys it controls, or drop / replay puts.
  Signature verification prevents spoofing; last-writer-wins semantics
  tolerates drop/replay.
- The **passphrase** is a shared secret among members. Anyone with the
  passphrase can participate in the swarm, decrypt DHT records, and sign
  their own slot writes.
- The iroh-gossip layer **itself** provides point-to-point TLS between
  gossip members. Application payload broadcast over the swarm is visible
  to every gossip member.

### What the crate protects against

- **Passive DHT eavesdroppers**: record plaintext (peer IDs, ages) is
  AEAD-encrypted under a key derived from the passphrase. An observer
  sees only opaque ciphertext, a public key, and a monotonic sequence
  number.
- **Active DHT attackers who don't know the passphrase**: cannot produce
  valid signed puts; their malformed records are rejected on read.
- **Cryptographic correctness of the core primitives**: HKDF-SHA256 for
  key derivation, Ed25519 for signing, ChaCha20-Poly1305 for AEAD, all
  from the audited [RustCrypto] stack.
- **Per-record key isolation**: compromise of a single record's one-time
  key (`k_r`) leaks only that record — the wrapper master key `W_k` stays
  protected.

### What the crate does **not** protect against

- **Passphrase compromise.** The passphrase is the sole secret. Anyone
  obtaining it can decrypt every past and future DHT record, forge slot
  writes, and impersonate members. There is no forward secrecy: an
  adversary who captures DHT traffic and later obtains the passphrase can
  decrypt the archive.
- **Post-compromise security against a former member.** A removed member
  who still has the passphrase retains full read/write access. Revocation
  requires an out-of-band passphrase rotation.
- **Metadata confidentiality on the DHT.** Observers see: the slot
  addresses (public, deterministically derived from the passphrase), record
  sizes, write frequencies, and sequence numbers. These reveal the rough
  number of active members, the write rate, and the app salt's identity
  (via slot-address fingerprinting if the adversary guesses app salts).
- **Gossip-layer payload confidentiality.** Once the gossip topic is
  joined, application payloads broadcast over iroh-gossip are visible to
  every member. Payload encryption is out of scope; layer MLS / RFC 9420
  on top if needed.
- **Denial of service on the Mainline DHT.** An adversary with heavy DHT
  resources can crowd out slots or drop puts. The K-sharded design
  mitigates this (§7 of PROTOCOL.md) but does not eliminate it.

### Non-goals

- **MLS / post-compromise security** — future work; separate crate if built.
- **Anonymity.** Mainline DHT participation is observable; adversaries who
  correlate DHT queries with network metadata can de-anonymize members.
- **Traffic analysis resistance.** Same caveat.

## Cryptographic primitives and key derivation

- **Key agreement**: None. Keys are deterministically derived from the
  passphrase + app_salt via HKDF-SHA256.
- **Slot signing**: Ed25519 via [`ed25519-dalek`]. Each slot has its own
  signing key, derived via HKDF info string `"sk25519:" || be64(slot_k)`.
- **Wrapper master key**: 32 bytes per slot, HKDF info string
  `"wrap:" || be64(slot_k)`.
- **Per-epoch wrapper**: `W_k^(e) = HKDF-Expand(W_k, "epoch" || be64(e))`
  where `e = floor(seq / E)` (default `E = 64`). Epoch rotation provides
  coarse-grained key hygiene but not forward secrecy.
- **Per-record AEAD**: a fresh 32-byte one-time key `k_r`, wrapped under
  `W_k^(e)` with a random 12-byte nonce; the record body is AEAD-encrypted
  under `k_r` with a fixed all-zero nonce (safe because `k_r` is one-shot
  and discarded after encryption).
- **Zeroization**: `k_r`, the derived `W_k^(e)`, and any intermediate
  HKDF buffers containing passphrase bytes are [`zeroize`]d after use.

## Supply chain

- All crypto dependencies are from the [RustCrypto] organization.
- CI runs `cargo deny check` and `cargo audit` on every push; known
  transitive `unmaintained` advisories are documented in `deny.toml`.
- `cargo-semver-checks` guards public API stability on PRs.

[RustCrypto]: https://github.com/RustCrypto
[`ed25519-dalek`]: https://docs.rs/ed25519-dalek
[`zeroize`]: https://docs.rs/zeroize
