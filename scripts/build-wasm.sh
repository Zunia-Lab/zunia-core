#!/usr/bin/env bash
# Builds the @zunialab/core npm package from crates/wasm.
#
# Output lands in packages/npm/, which is what `pnpm publish` ships with provenance.
#
# Requires: rustup with the wasm32-unknown-unknown target, and a wasm-bindgen CLI whose
# version matches the wasm-bindgen crate in Cargo.lock exactly. wasm-opt (binaryen) is
# optional; without it the artifact is larger but identical in behaviour.
#
# The bindgen target is `web`, not `bundler`. The bundler target emits
# `import * as wasm from "./zunia_core_bg.wasm"`, which relies on WebAssembly ESM
# integration; Vite (which is what WXT builds the extension with) resolves a bare `.wasm`
# import to an asset URL string instead, so the module object is a string at runtime and
# every exported function is `undefined`. The failure mode is a kernel that loads without
# error and then throws on the first call, which is exactly the silent degradation this
# package exists to remove. The `web` target instead exposes an explicit `init`, so the
# caller decides where the bytes come from and a missing artifact fails loudly at load.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/packages/npm"
WASM="$ROOT/target/wasm32-unknown-unknown/release-wasm/zunia_wasm.wasm"
BINDGEN_OUT="$ROOT/target/wasm-bindgen"

cd "$ROOT"

# The CLI and the crate must be the same version. wasm-bindgen refuses to process a module
# built by a different version, but a stale CLI that happens to be close enough produces
# glue that mismatches the wasm ABI, and that surfaces as garbage arguments rather than an
# error. Take the version from Cargo.lock so a dependency bump cannot leave this pinned to
# a number nobody updated.
BINDGEN_VERSION="$(
  awk '/^name = "wasm-bindgen"$/ { getline; gsub(/[",]/, "", $3); print $3; exit }' \
    "$ROOT/Cargo.lock"
)"
if [[ -z "$BINDGEN_VERSION" ]]; then
  echo "could not read the wasm-bindgen version from Cargo.lock" >&2
  exit 1
fi

rustup target add wasm32-unknown-unknown >/dev/null

INSTALLED=""
if command -v wasm-bindgen >/dev/null 2>&1; then
  INSTALLED="$(wasm-bindgen --version | awk '{print $2}')"
fi
if [[ "$INSTALLED" != "$BINDGEN_VERSION" ]]; then
  echo "installing wasm-bindgen-cli ${BINDGEN_VERSION} (found: ${INSTALLED:-none})" >&2
  cargo install wasm-bindgen-cli --locked --version "$BINDGEN_VERSION"
fi

echo "compiling zunia-wasm (release-wasm)"
cargo build -p zunia-wasm --target wasm32-unknown-unknown --profile release-wasm

if [[ ! -f "$WASM" ]]; then
  echo "$WASM not found; the cargo build did not produce the expected artifact" >&2
  exit 1
fi

rm -rf "$BINDGEN_OUT"
mkdir -p "$BINDGEN_OUT"
wasm-bindgen "$WASM" \
  --out-dir "$BINDGEN_OUT" \
  --target web \
  --out-name zunia_core \
  --typescript

# wasm-opt is a size win, never a correctness one. If it is missing or rejects a feature
# this rustc emitted, keep the unoptimised module rather than shipping nothing: an artifact
# that is 400 KB larger is a cost, an artifact that does not exist is an outage.
if command -v wasm-opt >/dev/null 2>&1; then
  echo "optimising with wasm-opt -Oz"
  if wasm-opt -Oz --all-features \
    "$BINDGEN_OUT/zunia_core_bg.wasm" \
    -o "$BINDGEN_OUT/zunia_core_bg.opt.wasm" 2>"$BINDGEN_OUT/wasm-opt.log"; then
    mv "$BINDGEN_OUT/zunia_core_bg.opt.wasm" "$BINDGEN_OUT/zunia_core_bg.wasm"
  else
    rm -f "$BINDGEN_OUT/zunia_core_bg.opt.wasm"
    echo "wasm-opt failed; shipping the unoptimised module. Log:" >&2
    sed 's/^/  /' "$BINDGEN_OUT/wasm-opt.log" >&2
  fi
else
  echo "wasm-opt not found; shipping unoptimised wasm (install binaryen for release builds)" >&2
fi

# Clear the previous build so a renamed or dropped output cannot linger into the tarball.
# packages/npm/.gitkeep is tracked (see .gitignore) and is the one thing that survives.
mkdir -p "$OUT"
find "$OUT" -mindepth 1 -not -name .gitkeep -delete
mkdir -p "$OUT/node"
cp "$BINDGEN_OUT"/zunia_core.js "$OUT/"
cp "$BINDGEN_OUT"/zunia_core.d.ts "$OUT/"
cp "$BINDGEN_OUT"/zunia_core_bg.wasm "$OUT/"
cp "$BINDGEN_OUT"/zunia_core_bg.wasm.d.ts "$OUT/" 2>/dev/null || true

# ---------------------------------------------------------------------------------------
# The facade. Consumers import `@zunialab/core`, not the bindgen names, so that a change to
# the bindgen output (a rename, an added export) is absorbed here instead of rippling into
# every call site.
#
# Two things the raw bindgen output cannot do on its own:
#
#   * u64 parameters arrive at the wasm boundary as i64, and the WebAssembly JS API converts
#     them with ToBigInt, which throws on a Number. A caller reading `account_number` out of
#     a JSON REST response holds a Number. Coercing here turns a TypeError deep inside the
#     glue into a working call.
#   * `preview_tx` returns a JSON string rather than a JsValue, because serde-wasm-bindgen
#     renders a serde map as a JS `Map` and `preview.memo` would read `undefined`. The same
#     applies to `derive_address`, `decode_direct_tx`, `parse_chain` and `sign_evm_tx`, which
#     do return JsValue and therefore do hand back `Map`s. `toPlain` converts them, so the
#     package's contract is plain objects everywhere.
# ---------------------------------------------------------------------------------------
cat > "$OUT/index.js" <<'EOF'
import init, { initSync } from "./zunia_core.js";
import * as raw from "./zunia_core.js";

export { init as initZuniaCore, initSync as initZuniaCoreSync };

/**
 * serde-wasm-bindgen serialises a serde map to a JS `Map`, not an object. Reading
 * `derived.address` off a Map yields `undefined` with no error, so every value that crosses
 * the boundary as a JsValue is normalised here before a caller can trip over it.
 */
function toPlain(value) {
  if (value instanceof Map) {
    const out = {};
    for (const [k, v] of value) out[String(k)] = toPlain(v);
    return out;
  }
  if (Array.isArray(value)) return value.map(toPlain);
  return value;
}

/**
 * u64 crosses the wasm boundary as i64 and the JS API converts with ToBigInt, which throws
 * on a Number. Account numbers and sequences come off a REST response as Numbers.
 */
function u64(value, name) {
  try {
    return BigInt(value);
  } catch {
    throw new TypeError(`${name} must be an integer, got ${String(value)}`);
  }
}

export const kernelVersion = () => raw.kernel_version();
export const generateMnemonic = (words) => raw.generate_mnemonic(words);
export const validateMnemonic = (phrase) => raw.validate_mnemonic(phrase);
export const sealKeyring = (phrase, password, metadataJson) =>
  raw.seal_keyring(phrase, password, metadataJson);
export const openKeyring = (envelopeJson, password) =>
  raw.open_keyring(envelopeJson, password);
export const rotateKeyringPassword = (envelopeJson, oldPassword, newPassword) =>
  raw.rotate_keyring_password(envelopeJson, oldPassword, newPassword);
export const deriveAddress = (phrase, passphrase, chainJson, accountIndex) =>
  toPlain(raw.derive_address(phrase, passphrase, chainJson, accountIndex));
export const signCosmos = (phrase, passphrase, chainJson, accountIndex, signBytesHex) =>
  raw.sign_cosmos(phrase, passphrase, chainJson, accountIndex, signBytesHex);
export const decodeDirectTx = (signDocHex) => toPlain(raw.decode_direct_tx(signDocHex));
export const personalSign = (phrase, passphrase, accountIndex, message) =>
  raw.personal_sign(phrase, passphrase, accountIndex, message);
export const signTypedData = (phrase, passphrase, accountIndex, typedDataJson) =>
  raw.sign_typed_data(phrase, passphrase, accountIndex, typedDataJson);
export const signEvmTx = (phrase, passphrase, accountIndex, txJson) =>
  toPlain(raw.sign_evm_tx(phrase, passphrase, accountIndex, txJson));
export const validateBech32Address = (address, expectedPrefix) =>
  raw.validate_bech32_address(address, expectedPrefix);
export const parseChain = (chainJson) => toPlain(raw.parse_chain(chainJson));

/** @deprecated Superseded by {@link buildSignBytes}, which covers all eight message types. */
export const buildBankSendDirect = (
  chainId, from, to, amount, denom, memo,
  accountNumber, sequence, feeAmount, feeDenom, gasLimit, publicKeyHex, ethKeyType,
) =>
  raw.build_bank_send_direct(
    chainId, from, to, amount, denom, memo,
    u64(accountNumber, "accountNumber"), u64(sequence, "sequence"),
    feeAmount, feeDenom, u64(gasLimit, "gasLimit"), publicKeyHex, ethKeyType,
  );

export const buildSignBytes = (
  chainId, msgsJson, feeJson, memo, accountNumber, sequence, publicKeyHex, ethKeyType, mode,
) =>
  raw.build_sign_bytes(
    chainId, msgsJson, feeJson, memo,
    u64(accountNumber, "accountNumber"), u64(sequence, "sequence"),
    publicKeyHex, ethKeyType, mode,
  );

export const assembleTxRaw = (
  chainId, msgsJson, feeJson, memo, accountNumber, sequence, publicKeyHex, ethKeyType,
  mode, signatureHex,
) =>
  raw.assemble_tx_raw(
    chainId, msgsJson, feeJson, memo,
    u64(accountNumber, "accountNumber"), u64(sequence, "sequence"),
    publicKeyHex, ethKeyType, mode, signatureHex,
  );

export const buildSimulateTx = (
  chainId, msgsJson, feeJson, memo, accountNumber, sequence, publicKeyHex, ethKeyType,
) =>
  raw.build_simulate_tx(
    chainId, msgsJson, feeJson, memo,
    u64(accountNumber, "accountNumber"), u64(sequence, "sequence"),
    publicKeyHex, ethKeyType,
  );

export const signTx = (
  phrase, passphrase, chainJson, accountIndex, chainId, msgsJson, feeJson, memo,
  accountNumber, sequence, mode,
) =>
  raw.sign_tx(
    phrase, passphrase, chainJson, accountIndex, chainId, msgsJson, feeJson, memo,
    u64(accountNumber, "accountNumber"), u64(sequence, "sequence"), mode,
  );

/** Parsed, because `preview_tx` returns JSON text to avoid serde-wasm-bindgen's `Map`. */
export const previewTx = (
  chainId, msgsJson, feeJson, memo, accountNumber, sequence, publicKeyHex, ethKeyType, mode,
) =>
  JSON.parse(
    raw.preview_tx(
      chainId, msgsJson, feeJson, memo,
      u64(accountNumber, "accountNumber"), u64(sequence, "sequence"),
      publicKeyHex, ethKeyType, mode,
    ),
  );
EOF

cat > "$OUT/index.d.ts" <<'EOF'
/**
 * `@zunialab/core` — the Rust wallet kernel compiled to WebAssembly.
 *
 * Load this only in a privileged context (the extension background worker). The linear
 * memory holds decrypted key material while the wallet is unlocked.
 *
 * Call {@link initZuniaCore} once before any other export. The module is built for the
 * wasm-bindgen `web` target, so nothing is instantiated at import time.
 */

/** An integer parameter that reaches the wasm boundary as u64. Numbers are coerced. */
export type U64Like = bigint | number | string;

export interface InitInput {
  module_or_path?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module;
}

/** Instantiates the module. Resolves once every other export is callable. */
export function initZuniaCore(
  input?: InitInput | RequestInfo | URL | Response | BufferSource | WebAssembly.Module,
): Promise<unknown>;

/** Synchronous instantiation, for hosts that already hold the bytes. */
export function initZuniaCoreSync(
  input: InitInput | BufferSource | WebAssembly.Module,
): unknown;

export interface DerivedAddress {
  address: string;
  publicKeyHex: string;
  path: string;
  /** Present only for chains that derive an Ethereum-style address. */
  ethAddress?: string;
}

export interface DecodedDirectTx {
  chainId: string;
  memo: string;
  hasUnknownMsgs: boolean;
  safeWithoutBlindSigning: boolean;
  summaries: string[];
  addresses: string[];
}

export interface Coin {
  denom: string;
  amount: string;
}

/** One entry of `msgs_json`. `value` is proto-JSON: snake_case keys, amounts as strings. */
export interface BuiltMsg {
  typeUrl: string;
  value: Record<string, unknown>;
}

/** `fee_json`. `gas_limit` is a string because a JSON number cannot hold a full u64. */
export interface FeeJson {
  amount: Coin[];
  gas_limit: string;
}

export type SignMode = "direct" | "amino";

/** What {@link previewTx} returns: enough to render an approval screen without signing. */
export interface SigningPreview {
  chainId: string;
  mode: SignMode;
  messages: Array<{ typeUrl: string; summary: string; spendsFunds: boolean }>;
  summaries: string[];
  fee: Coin[];
  /** String: a u64 does not survive a JSON number. */
  gasLimit: string;
  memo: string;
  spendsFunds: boolean;
  counterparties: string[];
  /** SHA-256 of the sign bytes, hex. Lets a user confirm the prompt and the broadcast match. */
  signBytesHash: string;
}

export function kernelVersion(): string;
export function generateMnemonic(words: number): string;
export function validateMnemonic(phrase: string): boolean;
export function sealKeyring(phrase: string, password: string, metadataJson: string): string;
export function openKeyring(envelopeJson: string, password: string): string;
export function rotateKeyringPassword(
  envelopeJson: string,
  oldPassword: string,
  newPassword: string,
): string;
export function deriveAddress(
  phrase: string,
  passphrase: string,
  chainJson: string,
  accountIndex: number,
): DerivedAddress;
export function signCosmos(
  phrase: string,
  passphrase: string,
  chainJson: string,
  accountIndex: number,
  signBytesHex: string,
): string;
export function decodeDirectTx(signDocHex: string): DecodedDirectTx;
export function personalSign(
  phrase: string,
  passphrase: string,
  accountIndex: number,
  message: string,
): string;
export function signTypedData(
  phrase: string,
  passphrase: string,
  accountIndex: number,
  typedDataJson: string,
): string;
export function signEvmTx(
  phrase: string,
  passphrase: string,
  accountIndex: number,
  txJson: string,
): unknown;
export function validateBech32Address(address: string, expectedPrefix: string): boolean;
export function parseChain(chainJson: string): unknown;

/**
 * @deprecated Only expresses a bank send. Use {@link buildSignBytes} with a
 * `[{ typeUrl: "/cosmos.bank.v1beta1.MsgSend", value: {...} }]` payload, which is the only
 * path that can also express staking, governance, IBC and contract calls.
 */
export function buildBankSendDirect(
  chainId: string,
  from: string,
  to: string,
  amount: string,
  denom: string,
  memo: string,
  accountNumber: U64Like,
  sequence: U64Like,
  feeAmount: string,
  feeDenom: string,
  gasLimit: U64Like,
  publicKeyHex: string,
  ethKeyType: boolean,
): string;

/**
 * The bytes the kernel must sign, hex encoded. Pure: no key material crosses this call.
 *
 * `msgsJson` is a JSON array of {@link BuiltMsg}. `feeJson` is a {@link FeeJson}.
 */
export function buildSignBytes(
  chainId: string,
  msgsJson: string,
  feeJson: string,
  memo: string,
  accountNumber: U64Like,
  sequence: U64Like,
  publicKeyHex: string,
  ethKeyType: boolean,
  mode: SignMode,
): string;

/**
 * The broadcastable `TxRaw`, hex encoded, given a signature over {@link buildSignBytes}.
 *
 * The signature is not verified here. A signature produced over different bytes assembles
 * without complaint and fails on chain as an opaque "unauthorized".
 */
export function assembleTxRaw(
  chainId: string,
  msgsJson: string,
  feeJson: string,
  memo: string,
  accountNumber: U64Like,
  sequence: U64Like,
  publicKeyHex: string,
  ethKeyType: boolean,
  mode: SignMode,
  signatureHex: string,
): string;

/**
 * A `TxRaw` carrying a 64-byte zero signature, for `POST /cosmos/tx/v1beta1/simulate`.
 * Simulation does not verify signatures, but the transaction must still decode.
 */
export function buildSimulateTx(
  chainId: string,
  msgsJson: string,
  feeJson: string,
  memo: string,
  accountNumber: U64Like,
  sequence: U64Like,
  publicKeyHex: string,
  ethKeyType: boolean,
): string;

/**
 * derive -> sign bytes -> sign -> assemble, in one call. Returns a hex `TxRaw`.
 *
 * Intermediate key material is zeroized. Unlike the pure functions above, this one holds a
 * chain document and so refuses a `chainId` that disagrees with it, and refuses addresses
 * that do not carry the chain's bech32 prefix.
 */
export function signTx(
  phrase: string,
  passphrase: string,
  chainJson: string,
  accountIndex: number,
  chainId: string,
  msgsJson: string,
  feeJson: string,
  memo: string,
  accountNumber: U64Like,
  sequence: U64Like,
  mode: SignMode,
): string;

/** What will be signed, without signing it. Pure: no key material crosses this call. */
export function previewTx(
  chainId: string,
  msgsJson: string,
  feeJson: string,
  memo: string,
  accountNumber: U64Like,
  sequence: U64Like,
  publicKeyHex: string,
  ethKeyType: boolean,
  mode: SignMode,
): SigningPreview;
EOF

# Node entry. The `web` target does not instantiate at import time and its default init
# fetches a URL, which does not work for a file:// path under Node. Reading the bytes and
# calling initSync keeps `import "@zunialab/core"` synchronous and side-effect-complete for
# scripts and tests, which is what scripts/smoke-npm.mjs relies on.
cat > "$OUT/node/index.mjs" <<'EOF'
import { readFileSync } from "node:fs";
import { initSync } from "../zunia_core.js";

initSync({
  module: readFileSync(new URL("../zunia_core_bg.wasm", import.meta.url)),
});

export * from "../index.js";
EOF

cat > "$OUT/node/index.d.ts" <<'EOF'
// The Node entry instantiates the module at import time; the surface is otherwise identical.
export * from "../index.js";
EOF

# package.json for the published artifact. Version is stamped by changesets / the release
# workflow. The "node" condition points at the self-initialising entry; browsers and
# bundlers get the root entry and must call initZuniaCore() themselves.
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
cat > "$OUT/package.json" <<EOF
{
  "name": "@zunialab/core",
  "version": "${VERSION}",
  "description": "Zunia wallet kernel (WASM). Keys, signing and encryption. Load only in a privileged context.",
  "type": "module",
  "main": "./index.js",
  "types": "./index.d.ts",
  "exports": {
    ".": {
      "types": "./index.d.ts",
      "node": "./node/index.mjs",
      "browser": "./index.js",
      "default": "./index.js"
    },
    "./node": {
      "types": "./node/index.d.ts",
      "default": "./node/index.mjs"
    },
    "./wasm": "./zunia_core_bg.wasm",
    "./package.json": "./package.json"
  },
  "files": [
    "index.js",
    "index.d.ts",
    "node/index.mjs",
    "node/index.d.ts",
    "zunia_core.js",
    "zunia_core.d.ts",
    "zunia_core_bg.wasm",
    "zunia_core_bg.wasm.d.ts",
    "README.md",
    "LICENSE"
  ],
  "sideEffects": [
    "./zunia_core.js",
    "./node/index.mjs"
  ],
  "license": "Apache-2.0",
  "repository": {
    "type": "git",
    "url": "https://github.com/Zunia-Lab/zunia-core.git"
  },
  "engines": {
    "node": ">=22"
  },
  "publishConfig": {
    "access": "public",
    "provenance": true
  }
}
EOF

cp "$ROOT/LICENSE" "$OUT/LICENSE" 2>/dev/null || cat > "$OUT/LICENSE" <<'EOF'
Apache License 2.0. See the repository root for the full text.
EOF

cat > "$OUT/README.md" <<'EOF'
# `@zunialab/core`

WASM build of the Zunia wallet kernel: BIP-39/BIP-32 derivation, keyring sealing, Cosmos
transaction assembly and signing, EVM signing.

**Load this only in the extension background worker or another privileged context.** Never in
a content script or a web page: the linear memory is visible to the host, and that is where
decrypted key material lives while the wallet is unlocked.

## Loading

The module is built for the wasm-bindgen `web` target, so nothing is instantiated at import
time. Under Node the package's `node` export condition instantiates for you:

```js
import { buildSignBytes } from "@zunialab/core"; // Node: ready on import
```

In a browser, an extension worker or a bundler, initialise explicitly:

```js
import { initZuniaCore, buildSignBytes } from "@zunialab/core";
await initZuniaCore(); // fetches zunia_core_bg.wasm next to the module
```

`initZuniaCore` also accepts bytes or a compiled `WebAssembly.Module`, which is the reliable
option inside an extension where the asset URL is bundler-dependent:

```js
const bytes = await fetch(browser.runtime.getURL("zunia_core_bg.wasm")).then((r) =>
  r.arrayBuffer(),
);
await initZuniaCore({ module_or_path: bytes });
```

### Manifest V3

Instantiating WebAssembly in an MV3 extension requires `'wasm-unsafe-eval'` in the
`content_security_policy.extension_pages` `script-src`. Without it the module fails to
compile and the wallet has no signer.

## Transaction surface

`buildSignBytes`, `assembleTxRaw`, `buildSimulateTx` and `previewTx` are pure — no key
material crosses them — and take the message envelope `@zunialab/interchain` already emits:

```js
const msgs = JSON.stringify([
  {
    typeUrl: "/cosmos.bank.v1beta1.MsgSend",
    value: {
      from_address: "cosmos1...",
      to_address: "cosmos1...",
      amount: [{ denom: "uatom", amount: "1000000" }],
    },
  },
]);
const fee = JSON.stringify({
  amount: [{ denom: "uatom", amount: "5000" }],
  gas_limit: "200000",
});

const signBytes = buildSignBytes(
  "cosmoshub-4", msgs, fee, "", 12345, 7, pubkeyHex, false, "direct",
);
const txRaw = assembleTxRaw(
  "cosmoshub-4", msgs, fee, "", 12345, 7, pubkeyHex, false, "direct", signatureHex,
);
```

Note `/cosmwasm.wasm.v1.MsgExecuteContract`: `value.msg` is a **base64 string** of the
contract JSON, matching what `@zunialab/interchain` emits. The bridge decodes it on the way
in and re-encodes it on the way out.

`signTx` is the one-shot convenience path (derive → sign bytes → sign → assemble) and is the
only entry point that holds a chain document, so it also refuses a chain-id mismatch and
addresses carrying another chain's bech32 prefix.

Byte-for-byte equality with CosmJS is enforced by `tests/vectors/cosmos-signing.json` in the
Rust workspace and re-checked against this built artifact by `scripts/smoke-npm.mjs`.

See [ADR-0002](https://github.com/Zunia-Lab/zunia-core/blob/main/docs/adr/0002-wallet-kernel-language.md)
and [ADR-0005](https://github.com/Zunia-Lab/zunia-core/blob/main/docs/adr/0005-polyrepo-package-flow.md).
EOF

echo "wrote $OUT (version $VERSION, wasm-bindgen $BINDGEN_VERSION)"
ls -la "$OUT" "$OUT/node"
