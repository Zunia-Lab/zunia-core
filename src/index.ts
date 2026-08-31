/**
 * Zunia wallet kernel public surface (scaffold).
 * Do not add production crypto until ADR-0002 (kernel language) is accepted
 * and §3 of PRE-DEVELOPMENT.md is implemented with official test vectors.
 */

export const KERNEL_VERSION = "0.0.0-scaffold";

/** BIP-44 coin types — prefer values from zunia-chain-registry at runtime. */
export const COIN_TYPES = {
  cosmos: 118,
  ethereum: 60,
  solana: 501,
} as const;

export type DerivationPathTemplate =
  | `m/44'/${number}'/0'/0/${number}`
  | `m/44'/${number}'/${number}'/0'`;

export interface KeyringConfig {
  /** Argon2id preferred; scrypt N≥2^17 fallback */
  kdf: "argon2id" | "scrypt";
  aead: "xchacha20-poly1305" | "aes-256-gcm";
  autoLockMs: number;
}

export const DEFAULT_KEYRING_CONFIG: KeyringConfig = {
  kdf: "argon2id",
  aead: "xchacha20-poly1305",
  autoLockMs: 10 * 60 * 1000,
};

/** Placeholder — implementation forbidden until crypto ADRs land. */
export function notImplemented(feature: string): never {
  throw new Error(
    `@zunialab/core: "${feature}" is not implemented (scaffold only). See PRE-DEVELOPMENT.md Phase 1.`,
  );
}
