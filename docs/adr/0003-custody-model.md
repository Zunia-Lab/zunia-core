# ADR-0003: Custody model

- Status: **Accepted**
- Date: 2026-08-31

## Context

Wallet products can mix self-custody seeds with social login, MPC/TSS, passkeys, or encrypted cloud backups. Those paths change legal exposure, trust assumptions, and recovery UX.

## Decision

**Self-custody only.**

1. Users create or import a BIP-39 seed (12 or 24 words), with mandatory backup verification before the wallet is treated as funded/ready.
2. Seeds and private keys exist only on the user device (extension memory / OS keystore). Zunia Lab never holds key shares or recovery material.
3. Recovery is the seed phrase (and optional BIP-39 passphrase). No account-based recovery.

## Explicitly out of scope (do not implement)

- MPC / TSS providers (Web3Auth, Privy, Particle, Turnkey, Dfns, etc.)
- Social login / email / Google / Apple as wallet creation or key unlock
- Encrypted seed blobs stored in iCloud, Google Drive, or any Zunia backend
- Passkey-derived or smart-account / AA wallets as a product path
- Custodial key holding by Zunia Lab

## Consequences

- No auth-provider or MPC vendor selection for wallet keys.
- `zunia-backend` must not store seeds, key shares, or encrypted wallet backups (push tokens / hashed watch addresses only).
- Docs and UI must describe Zunia as self-custody / non-custodial only.
- Onboarding is create seed, import seed, or hardware wallet (when supported) — nothing else.
