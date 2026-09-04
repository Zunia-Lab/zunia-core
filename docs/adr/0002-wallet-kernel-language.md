# ADR-0002: Wallet kernel language

- Status: **Accepted**
- Date: 2026-08-31
- Decision owner: kernel + security

## Context

Extension and dashboard are TypeScript. Mobile is Flutter (Dart). Mobile is in v1, so a
TypeScript-only kernel is not an option, and duplicating BIP-39/32/44, the keyring envelope
and every signing path in both TS and Dart would mean two implementations, two sets of test
vectors and two audits of the same threat surface.

## Options considered

1. **Rust core**, compiled to WASM for the extension and web, and to native libraries plus
   generated Dart bindings for Flutter. One implementation, one audit.
2. **TypeScript core plus a separate Dart port.** Faster to a web MVP, but the cost is paid
   forever: every signing bug must be fixed and re-verified twice, and the two ports drift.
3. **TypeScript only, mobile deferred to v2.** Rejected because mobile is v1 scope.

## Decision

**Option 1. A single Rust wallet kernel in this repository.**

`zunia-core` becomes a Cargo workspace:

- `crates/kernel`: BIP-39, BIP-32 and SLIP-0010 derivation, bech32, the Argon2id plus
  XChaCha20-Poly1305 keyring envelope, and secret zeroization.
- `crates/cosmos`: Amino JSON and Direct sign modes, transaction builders, message decoding.
- `crates/evm`, `crates/svm`: chain-family signing, SVM feature-gated for v2.
- `crates/registry`: parses `zunia-chain-registry` JSON, resolves coin types and prefixes.
- `crates/wasm`: `wasm-bindgen` bindings published as the npm package `@zunialab/core`.
- `crates/ffi`: `flutter_rust_bridge` v2 bindings published as the Dart package `zunia_core`.

The npm package name `@zunialab/core` is retained so downstream imports do not churn. The
TypeScript scaffold in `src/` is replaced by generated WASM bindings plus a thin typed facade.

## Consequences

- Private key material only ever exists inside Rust memory, with `zeroize` on drop. The
  JavaScript and Dart layers hold opaque handles, never key bytes.
- Every consumer needs a build step for the artifact, not a source dependency. Artifact
  distribution is specified in [ADR-0005](./0005-polyrepo-package-flow.md).
- Mobile app CI does not need a Rust toolchain, because native libraries are consumed as
  pinned release artifacts.
- Higher upfront cost, and the team needs Rust review capability on the crypto path.
- `secp256k1` uses the pure-Rust `k256` crate so WASM and native share one code path. The
  tradeoff versus the libsecp256k1 C library is accepted for portability and auditability of
  a single implementation.
- Amino JSON has no mature Rust implementation. It must be written here and pinned to golden
  vectors generated with CosmJS, asserted byte for byte. See
  [ADR-0004](./0004-cosmos-client-libs.md).
