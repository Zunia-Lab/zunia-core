#!/usr/bin/env bash
# Cross-compiles crates/ffi for the Android and iOS targets that mobile CI pins, then
# assembles an xcframework. Artifacts land in dist/native/ and are attached to the GitHub
# Release by the release workflow; they are never published to a package registry.
#
# Requires: rustup, Android NDK (ANDROID_NDK_HOME), Xcode (on macOS, for iOS).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/native"
mkdir -p "$OUT"

cd "$ROOT"

ANDROID_TARGETS=(
  aarch64-linux-android
  armv7-linux-androideabi
  x86_64-linux-android
)

IOS_TARGETS=(
  aarch64-apple-ios
  aarch64-apple-ios-sim
)

build_android() {
  if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    echo "ANDROID_NDK_HOME unset; skipping Android targets" >&2
    return 0
  fi
  if ! command -v cargo-ndk >/dev/null 2>&1; then
    cargo install cargo-ndk --locked
  fi
  for target in "${ANDROID_TARGETS[@]}"; do
    rustup target add "$target"
  done
  cargo ndk \
    -t arm64-v8a -t armeabi-v7a -t x86_64 \
    -o "$OUT/android" \
    build -p zunia-ffi --release
  (cd "$OUT" && tar -czf android-libs.tar.gz android)
}

build_ios() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "not macOS; skipping iOS targets" >&2
    return 0
  fi
  for target in "${IOS_TARGETS[@]}"; do
    rustup target add "$target"
    cargo build -p zunia-ffi --release --target "$target"
  done

  local ios_lib sim_lib
  ios_lib="$ROOT/target/aarch64-apple-ios/release/libzunia_ffi.a"
  sim_lib="$ROOT/target/aarch64-apple-ios-sim/release/libzunia_ffi.a"
  mkdir -p "$OUT/ios/headers"
  cat > "$OUT/ios/headers/zunia_ffi.h" <<'EOF'
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void zunia_string_free(char *ptr);
char *zunia_kernel_version(void);
char *zunia_generate_mnemonic(uint32_t words);
char *zunia_seal_keyring(const char *phrase, const char *password, const char *metadata_json);
char *zunia_open_keyring(const char *envelope_json, const char *password);
char *zunia_derive_address(const char *phrase, const char *passphrase, const char *chain_json, uint32_t account_index);
char *zunia_sign_cosmos(const char *phrase, const char *passphrase, const char *chain_json, uint32_t account_index, const char *sign_bytes_hex);
char *zunia_decode_direct_tx(const char *sign_doc_hex);
char *zunia_build_bank_send_direct(
  const char *chain_id, const char *from, const char *to, const char *amount, const char *denom,
  const char *memo, uint64_t account_number, uint64_t sequence, const char *fee_amount,
  const char *fee_denom, uint64_t gas_limit, const char *public_key_hex, uint8_t eth_key_type
);

#ifdef __cplusplus
}
#endif
EOF

  rm -rf "$OUT/ZuniaCore.xcframework"
  xcodebuild -create-xcframework \
    -library "$ios_lib" -headers "$OUT/ios/headers" \
    -library "$sim_lib" -headers "$OUT/ios/headers" \
    -output "$OUT/ZuniaCore.xcframework"

  (cd "$OUT" && tar -czf ZuniaCore.xcframework.tar.gz ZuniaCore.xcframework)
}

echo "building Android"
build_android
echo "building iOS"
build_ios

# Checksums for the release notes. Consumers verify these before loading a native lib.
(cd "$OUT" && shasum -a 256 *.tar.gz > SHA256SUMS 2>/dev/null || true)
ls -la "$OUT"
