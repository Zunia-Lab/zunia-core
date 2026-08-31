# ADR-0003: Custody model

- Status: Proposed
- Date: 2026-08-31

## Context

Self-custody seed vs social login (MPC / encrypted cloud backup) changes legal, UX, and security model. See PRE-DEVELOPMENT §5.

## Decision (proposed default)

1. **Primary:** self-custody BIP-39 seed with mandatory backup verification (§3.2).
2. **Optional easy mode:** encrypted cloud backup and/or MPC — custody model always visible in UI; seed export path required.
3. **Never:** custodial key holding by Zunia Lab.

## Consequences

Auth provider (Clerk/etc.) and MPC vendor selection blocked until Accepted. Backend may store only encrypted blobs / push tokens, never plaintext seeds.
