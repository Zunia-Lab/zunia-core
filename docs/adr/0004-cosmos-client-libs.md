# ADR-0004: Cosmos client libraries

- Status: **Accepted**
- Date: 2026-08-31
- Decision owner: kernel

## Context

Protobuf registry drift is a recurring source of signing bugs: a client that encodes a
transaction with a different proto definition than the chain expects produces a signature over
a byte string nobody can verify. Candidate stacks were CosmJS, cosmes, and telescope-generated
clients.

[ADR-0002](./0002-wallet-kernel-language.md) moves the kernel to Rust, which changes this
question. Signing no longer happens in TypeScript, so the choice splits in two.

## Decision

**Signing and encoding live in Rust. CosmJS is demoted to network I/O only.**

Inside the kernel:

- `prost` for protobuf encoding.
- `cosmos-sdk-proto` for generated Cosmos SDK, IBC and CosmWasm types.
- `cosmrs` as the base for `SignDoc`, fee and account handling.
- A hand-written Amino JSON serializer in `crates/cosmos`, because no Rust crate implements it
  correctly. It must produce sorted keys, omit empty fields, and encode integers as strings.

In the TypeScript clients (extension, dashboard):

- `@cosmjs/tendermint-rpc` and `@cosmjs/stargate` for queries, account and sequence lookup,
  simulation, and broadcast only.
- CosmJS must never construct a sign document, derive a key, or hold key material.

Rejected: cosmes (smaller ecosystem, still a TypeScript signing path we no longer need) and
telescope codegen (adds a codegen pipeline whose output we would only use for queries).

## Consequences

- The signing path has exactly one implementation, in Rust, and one audit target.
- Amino JSON is the single highest-risk component in the kernel. It is gated by golden
  vectors generated with CosmJS and asserted byte for byte in CI. A mismatch means silently
  invalid signatures, so a failing golden blocks release.
- Proto versions are pinned in `Cargo.toml` and every bump is a changelog entry naming the
  `cosmos-sdk-proto` version, because a proto change can alter signed bytes.
- Chain-specific message types beyond the pinned proto set are decoded generically and
  surfaced to the user as "cannot decode", never signed blind by default.
