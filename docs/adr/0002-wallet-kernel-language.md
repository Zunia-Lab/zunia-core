# ADR-0002: Wallet kernel language

- Status: Proposed
- Date: 2026-08-31

## Context

Extension and dashboard are TypeScript. Mobile is Flutter. Duplicating BIP-39/32/44 + signing in TS and Dart doubles audit surface. Alternatives: Rust core → WASM (web) + FFI (Flutter), or TS-only until mobile is v2+.

## Options

1. **Rust core** (recommended if mobile is v1): one audit, WASM + Flutter FFI.
2. **TypeScript `@zunialab/core` + Dart port**: faster web MVP, higher long-term cost.
3. **TypeScript only, mobile v2+**: smallest near-term scope.

## Decision

**Pending team answer to PRE-DEVELOPMENT §8 Q1 (is mobile in v1?).** Default recommendation if unanswered: option 1 when mobile is v1; option 3 otherwise.

## Consequences

Scaffold stays TypeScript package shape; may become thin bindings over Rust later. Do not ship production key material handling until this ADR is Accepted.
