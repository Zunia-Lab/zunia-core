#!/usr/bin/env node
/**
 * Generates per-chain address vectors from the real chain registry.
 *
 * Zunia derives addresses from registry data rather than a hardcoded table, so the thing that
 * needs testing is not "does bech32 work" but "does every chain we actually ship produce the
 * address the rest of the ecosystem produces". This walks `zunia-chain-registry/cosmos` and,
 * for every distinct (coin type, prefix, address scheme) combination, derives an address with
 * CosmJS. `crates/kernel/tests/registry_addresses.rs` asserts the Rust kernel agrees.
 *
 * Coverage matters more than volume: one chain per distinct combination catches a broken
 * scheme, whereas 300 near-identical cosmos-prefix chains catch the same bug 300 times and
 * make the vector file unreviewable.
 *
 * Run:  pnpm install && node address-vectors.mjs
 */

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing';
import {
  Bip39,
  EnglishMnemonic,
  Secp256k1,
  Slip10,
  Slip10Curve,
  keccak256,
  ripemd160,
  sha256,
  stringToPath,
} from '@cosmjs/crypto';
import { toBech32, toHex } from '@cosmjs/encoding';

const HERE = dirname(fileURLToPath(import.meta.url));
// CI checks the registry out to its own path, so the sibling layout is only the default.
const REGISTRY_ROOT =
  process.env.ZUNIA_CHAIN_REGISTRY ?? join(HERE, '../../../../zunia-chain-registry');
const REGISTRY = join(REGISTRY_ROOT, 'cosmos');
const OUT = join(HERE, '..', 'registry-addresses.json');

const MNEMONIC = `${'abandon '.repeat(11)}about`;
const seed = await Bip39.mnemonicToSeed(new EnglishMnemonic(MNEMONIC));

const keyCache = new Map();

/** Derives the key pair for a coin type at the first account, first address. */
async function keysFor(coinType) {
  if (!keyCache.has(coinType)) {
    const path = stringToPath(`m/44'/${coinType}'/0'/0/0`);
    const { privkey } = Slip10.derivePath(Slip10Curve.Secp256k1, seed, path);
    const { pubkey } = await Secp256k1.makeKeypair(privkey);
    keyCache.set(coinType, {
      uncompressed: pubkey,
      compressed: Secp256k1.compressPubkey(pubkey),
    });
  }
  return keyCache.get(coinType);
}

/** The 20-byte account identifier, which is what the bech32 prefix is applied to. */
async function accountId(coinType, scheme) {
  const { uncompressed, compressed } = await keysFor(coinType);
  if (scheme === 'ethermint') {
    // Keccak-256 over the 64-byte uncompressed key with its 0x04 prefix removed, last 20 bytes.
    return keccak256(uncompressed.slice(1)).slice(-20);
  }
  // Cosmos: RIPEMD-160 of SHA-256 of the compressed key.
  return ripemd160(sha256(compressed));
}

/**
 * Mirrors `ChainInfo::address_scheme` in `crates/registry`.
 *
 * `eth-address-gen` is the only signal. Coin type 60 deliberately does not imply Ethermint:
 * several chains use coin type 60 for Ledger compatibility while keeping standard Cosmos
 * address derivation, and treating those as Ethermint would derive the wrong address. Keep
 * this in step with the Rust, or the vectors will encode the generator's opinion rather than
 * the shipped behaviour.
 */
function inferScheme(chain) {
  const features = chain.features ?? [];
  return features.includes('eth-address-gen') ? 'ethermint' : 'cosmos';
}

const files = readdirSync(REGISTRY)
  .filter((f) => f.endsWith('.json'))
  .sort();

const combos = new Map();
let parsed = 0;
const skipped = [];

for (const file of files) {
  let chain;
  try {
    chain = JSON.parse(readFileSync(join(REGISTRY, file), 'utf8'));
  } catch (error) {
    skipped.push({ file, reason: `unparseable: ${error.message}` });
    continue;
  }

  const coinType = chain.bip44?.coinType;
  const prefix = chain.bech32Config?.bech32PrefixAccAddr;
  if (coinType === undefined || !prefix) {
    skipped.push({ file, reason: 'no coin type or no account prefix' });
    continue;
  }
  parsed += 1;

  const scheme = inferScheme(chain);
  const key = `${coinType}|${prefix}|${scheme}`;
  if (!combos.has(key)) {
    combos.set(key, {
      chain_id: chain.chainId,
      chain_name: chain.chainName,
      file,
      coin_type: coinType,
      prefix,
      scheme,
      valoper_prefix: chain.bech32Config?.bech32PrefixValAddr ?? null,
    });
  }
}

const cases = [];
for (const combo of combos.values()) {
  const id = await accountId(combo.coin_type, combo.scheme);
  const { compressed } = await keysFor(combo.coin_type);

  const entry = {
    ...combo,
    pubkey_compressed_hex: toHex(compressed),
    account_id_hex: toHex(id),
    address: toBech32(combo.prefix, id, 200),
  };
  if (combo.valoper_prefix) {
    entry.valoper_address = toBech32(combo.valoper_prefix, id, 200);
  }
  if (combo.scheme === 'ethermint') {
    // Ethermint chains expose the same account as a 0x address too, and a user who pastes one
    // into the other must not silently end up at a different account.
    entry.eth_address = `0x${toHex(id)}`;
  }
  cases.push(entry);
}

cases.sort((a, b) =>
  a.prefix === b.prefix ? a.coin_type - b.coin_type : a.prefix.localeCompare(b.prefix),
);

// Cross-check the hand-rolled hashing above against the higher-level CosmJS wallet API, so a
// mistake in this generator cannot quietly become the expected answer.
const selfCheck = cases.filter((c) => c.scheme === 'cosmos').slice(0, 8);
for (const entry of selfCheck) {
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(MNEMONIC, {
    prefix: entry.prefix,
    hdPaths: [stringToPath(`m/44'/${entry.coin_type}'/0'/0/0`)],
  });
  const [account] = await wallet.getAccounts();
  if (account.address !== entry.address) {
    throw new Error(
      `self-check failed for ${entry.prefix}: CosmJS wallet says ${account.address}, ` +
        `this generator says ${entry.address}`,
    );
  }
}

const output = {
  _comment:
    'Per-chain address vectors derived with CosmJS from zunia-chain-registry. Generated by ' +
    'tests/vectors/generate/address-vectors.mjs. Do not edit by hand.',
  mnemonic: MNEMONIC,
  hd_path_template: "m/44'/{coin_type}'/0'/0/0",
  registry: {
    chains_parsed: parsed,
    chains_skipped: skipped.length,
    distinct_combinations: cases.length,
    self_checked_against_cosmjs_wallet: selfCheck.length,
  },
  skipped,
  cases,
};

writeFileSync(OUT, `${JSON.stringify(output, null, 2)}\n`);
console.log(`wrote ${OUT}`);
console.log(
  `${parsed} chains parsed, ${skipped.length} skipped, ` +
    `${cases.length} distinct coin-type/prefix/scheme combinations`,
);
const ethermint = cases.filter((c) => c.scheme === 'ethermint').length;
console.log(`  ${ethermint} ethermint, ${cases.length - ethermint} cosmos`);
console.log(`  ${new Set(cases.map((c) => c.coin_type)).size} distinct coin types`);
