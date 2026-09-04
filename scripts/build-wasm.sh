#!/usr/bin/env bash
# Builds the @zunialab/core npm package from crates/wasm.
#
# Requires: rustup target wasm32-unknown-unknown, wasm-bindgen-cli, wasm-opt (binaryen).
# Output lands in packages/npm/, which is what `pnpm publish` ships with provenance.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/packages/npm"
TARGET_DIR="$ROOT/target/wasm32-unknown-unknown/release-wasm"
BINDGEN_OUT="$ROOT/target/wasm-bindgen"

cd "$ROOT"

rustup target add wasm32-unknown-unknown >/dev/null

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "installing wasm-bindgen-cli" >&2
  cargo install wasm-bindgen-cli --locked --version 0.2.100
fi

echo "compiling zunia-wasm (release-wasm)"
cargo build -p zunia-wasm --target wasm32-unknown-unknown --profile release-wasm

WASM="$(find "$ROOT/target/wasm32-unknown-unknown" -name 'zunia_wasm.wasm' | head -1)"
if [[ -z "$WASM" ]]; then
  echo "zunia_wasm.wasm not found under target/" >&2
  exit 1
fi

rm -rf "$BINDGEN_OUT"
mkdir -p "$BINDGEN_OUT"
wasm-bindgen "$WASM" \
  --out-dir "$BINDGEN_OUT" \
  --target bundler \
  --out-name zunia_core \
  --typescript

if command -v wasm-opt >/dev/null 2>&1; then
  echo "optimising with wasm-opt -Oz"
  wasm-opt -Oz --enable-bulk-memory --enable-mutable-globals \
    "$BINDGEN_OUT/zunia_core_bg.wasm" \
    -o "$BINDGEN_OUT/zunia_core_bg.wasm"
else
  echo "wasm-opt not found; shipping unoptimised wasm (install binaryen for release builds)" >&2
fi

rm -rf "$OUT"
mkdir -p "$OUT"
cp "$BINDGEN_OUT"/zunia_core.js "$OUT/"
cp "$BINDGEN_OUT"/zunia_core.d.ts "$OUT/"
cp "$BINDGEN_OUT"/zunia_core_bg.wasm "$OUT/"
cp "$BINDGEN_OUT"/zunia_core_bg.wasm.d.ts "$OUT/" 2>/dev/null || true

# Thin TypeScript facade so consumers import `@zunialab/core` rather than the raw bindgen names.
cat > "$OUT/index.js" <<'EOF'
export {
  kernel_version as kernelVersion,
  generate_mnemonic as generateMnemonic,
  validate_mnemonic as validateMnemonic,
  seal_keyring as sealKeyring,
  open_keyring as openKeyring,
  rotate_keyring_password as rotateKeyringPassword,
  derive_address as deriveAddress,
  sign_cosmos as signCosmos,
  decode_direct_tx as decodeDirectTx,
  build_bank_send_direct as buildBankSendDirect,
  personal_sign as personalSign,
  sign_typed_data as signTypedData,
  sign_evm_tx as signEvmTx,
  validate_bech32_address as validateBech32Address,
  parse_chain as parseChain,
} from "./zunia_core.js";
EOF

cat > "$OUT/index.d.ts" <<'EOF'
export function kernelVersion(): string;
export function generateMnemonic(words: number): string;
export function validateMnemonic(phrase: string): boolean;
export function sealKeyring(phrase: string, password: string, metadataJson: string): string;
export function openKeyring(envelopeJson: string, password: string): string;
export function rotateKeyringPassword(envelopeJson: string, oldPassword: string, newPassword: string): string;
export function deriveAddress(phrase: string, passphrase: string, chainJson: string, accountIndex: number): unknown;
export function signCosmos(phrase: string, passphrase: string, chainJson: string, accountIndex: number, signBytesHex: string): string;
export function decodeDirectTx(signDocHex: string): unknown;
export function buildBankSendDirect(
  chainId: string,
  from: string,
  to: string,
  amount: string,
  denom: string,
  memo: string,
  accountNumber: bigint,
  sequence: bigint,
  feeAmount: string,
  feeDenom: string,
  gasLimit: bigint,
  publicKeyHex: string,
  ethKeyType: boolean,
): string;
export function personalSign(phrase: string, passphrase: string, accountIndex: number, message: string): string;
export function signTypedData(phrase: string, passphrase: string, accountIndex: number, typedDataJson: string): string;
export function signEvmTx(phrase: string, passphrase: string, accountIndex: number, txJson: string): unknown;
export function validateBech32Address(address: string, expectedPrefix: string): boolean;
export function parseChain(chainJson: string): unknown;
EOF

# package.json for the published artifact. Version is stamped by changesets / the release workflow.
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
      "import": "./index.js"
    }
  },
  "files": [
    "index.js",
    "index.d.ts",
    "zunia_core.js",
    "zunia_core.d.ts",
    "zunia_core_bg.wasm",
    "zunia_core_bg.wasm.d.ts",
    "README.md",
    "LICENSE"
  ],
  "sideEffects": ["./zunia_core.js"],
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

cp "$ROOT/../LICENSE" "$OUT/LICENSE" 2>/dev/null || cat > "$OUT/LICENSE" <<'EOF'
Apache License 2.0. See the repository root for the full text.
EOF

cat > "$OUT/README.md" <<'EOF'
# `@zunialab/core`

WASM build of the Zunia wallet kernel. **Load this only in the extension background worker
or another privileged context.** Never in a content script or a web page: the linear memory
is visible to the host, and that is where decrypted key material lives while the wallet is
unlocked.

See [ADR-0002](https://github.com/Zunia-Lab/zunia-core/blob/main/docs/adr/0002-wallet-kernel-language.md)
and [ADR-0005](https://github.com/Zunia-Lab/zunia-core/blob/main/docs/adr/0005-polyrepo-package-flow.md).
EOF

echo "wrote $OUT (version $VERSION)"
ls -la "$OUT"
