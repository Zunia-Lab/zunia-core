<p align="center">
  <img src="https://raw.githubusercontent.com/Zunia-Lab/zunia-brand/main/png/icons/app/zunia-icon-256.png" alt="Zunia" width="96" />
</p>

# zunia-core

> Shared wallet kernel for Zunia (keys, derivation, encryption, signing, tx builders).

**Status:** scaffold only. Crypto implementation and test vectors land in Phase 1 (see workspace `PRE-DEVELOPMENT.md`).

## Scope

| Module | Responsibility |
|--------|----------------|
| `bip39` / `bip32` / `bip44` | Mnemonic + HD paths from chain registry coin types |
| `keyring` | Encrypted seed vault (Argon2id + AEAD envelope) |
| `signing` | Amino + Direct (protobuf) signing |
| `address` | bech32 / EVM / SVM address helpers |
| `tx` | Message builders + simulation helpers |

Consumed by: `zunia-extension`, `zunia-dashboard`, `zunia-sdk` (types), and eventually Flutter via WASM/FFI or a Dart port (ADR pending).

## Decisions (ADRs)

See [`docs/adr/`](./docs/adr/). Kernel language (Rust vs TS) is **unresolved** — do not implement crypto until ADR-0002 is accepted.

## Develop

```bash
pnpm install
pnpm test
pnpm typecheck
```

Crypto test vectors live under `tests/vectors/` (BIP-39/32/44 official vectors to be added).

## Security

Report to [security@zuniawallet.com](mailto:security@zuniawallet.com). Never log or transmit seed material.

## License

Apache-2.0.
