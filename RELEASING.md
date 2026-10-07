# Releasing zunia-core

The kernel ships three artifacts (ADR-0005):

1. **`@zunialab/core`** on npm: the `wasm-bindgen` + `wasm-opt` output, published with
   provenance. Loaded only by the extension background worker.
2. **Native libraries** on the GitHub Release for the matching tag: Android `.so` set and an
   iOS `xcframework`, plus `SHA256SUMS` (and a detached GPG signature when the release key is
   configured). Mobile CI downloads these by tag and never compiles Rust itself.
3. **`zunia_core` Dart package** under `packages/dart/`: FFI bindings that load those native
   libs. Published by copying into the mobile repo or as a path dependency until the Dart
   pub workspace is reserved.

## Versions and tags

One version for the whole workspace, `[workspace.package] version` in `Cargo.toml`. The npm
package and `kernelVersion()` both report it, so a build says which kernel it is. Bump it in
the change that alters what the kernel signs or returns, never after the fact: 0.1.0 shipped
twice with different decoders, and nothing could tell the two apart.

Every release is a tag `v<version>` on the merged `main` commit, pushed once CI is green. Tags
are signed:

```bash
# GPG, or SSH when the machine has no GPG key:
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
git tag -s v0.1.1 -m "zunia-core 0.1.1"
git push origin v0.1.1
```

A machine without a signing key can still cut a release, but only as the owner's explicit
decision for that one release: an annotated tag (`git tag -a`), noted in the release notes. A
lightweight tag is never used. Unsigned tags are rejected by branch protection once it is on.

## What the tag starts

`.github/workflows/release.yml` runs on every `main` push, on every `v*` tag and on demand:

1. Format, clippy and the test suite, then `./scripts/build-wasm.sh` and
   `node scripts/smoke-npm.mjs` against the built package.
2. On a tag, a check that the tag names the version built. `v0.1.2` over a kernel that calls
   itself 0.1.1 fails here.
3. The sha256 of `zunia_core_bg.wasm`, `zunia_core.js` and `index.js` in the job summary.
4. npm publish, only for a dispatch with `publish: true`, or for a `v*` tag when the repository
   has an `NPM_TOKEN` secret. Without the secret a tag builds, checks and releases everything
   but publishes nothing, which is the state to keep while `@zunialab/core` is not on npm.
5. The native libraries, and on a tag the GitHub Release with `SHA256SUMS` and the consumer
   dispatch below.

`wasm-opt` in CI is binaryen 130 from its release tarball, checked against a pinned sha256,
not apt's binaryen. Rebuilt from the tag with rustc 1.93.0 (`rust-toolchain.toml`),
wasm-bindgen 0.2.127 (read from `Cargo.lock`) and wasm-opt 130, `./scripts/build-wasm.sh`
reproduces `zunia_core_bg.wasm` byte for byte on the machine that built the release candidate.
Check that before tagging, and record the hash in the extension's `SHA256SUMS`, since the
extension bundles this file.

A CI build is not yet byte-identical to a local one: the module embeds the absolute path of the
cargo registry in its panic locations (`$HOME/.cargo/registry/...`), which differs between
machines. Until the build remaps that path, the release artifact is the one the extension was
built and tested with, identified by its hash, and CI's hash is a record, not a check.

## Local builds

```bash
./scripts/build-wasm.sh && node scripts/smoke-npm.mjs   # -> packages/npm, then checked
./scripts/build-native.sh                               # -> dist/native (needs NDK / Xcode)
```

`packages/npm` is what every local extension checkout links through `link:`, so a build swaps
the kernel under all of them at once.

## Payload versions

`decodeDirectTx` (wasm) and `zunia_decode_direct_tx` (FFI) return one JSON object, built by
`zunia_cosmos::describe::decoded_tx_payload` for both. The extension's signing prompt and the
mobile app read it, so its shape is a contract:

- **v1 (0.1.0)**: `chainId`, `memo`, `hasUnknownMsgs`, `safeWithoutBlindSigning`, `summaries`,
  and `addresses` (wasm only).
- **v2 (0.1.1)**: v1 unchanged, value for value, plus `accountNumber`, `sequence`,
  `timeoutHeight`, `fee: { amount, gasLimit }` (every u64 a decimal string) and `messages`,
  one per message: `{ typeUrl, summary, unknown, recipient?, detail? }`. `detail` carries a
  contract call's parsed message and funds, or an IBC transfer's channel, receiver, token and
  packet memo. The FFI gains `addresses`.

A consumer that must run against both tells them apart by `messages`. Adding a key is a patch
release. Removing or renaming one, or changing a value's meaning, is a minor release, with a PR
in every consumer before the tag.

## Consumer update PRs

On a successful tagged release the workflow dispatches `zunia-core-released` to
`zunia-extension`, `zunia-mobile` and `zunia-dashboard`. Each consumer's
`.github/workflows/dependabot-core.yml` (or equivalent) opens a PR that bumps the pin and
runs its own CI. Merge is a human decision: crypto changes are never auto-merged.

## Verifying an artifact

```bash
gh release download v0.1.1 -R Zunia-Lab/zunia-core
shasum -a 256 -c SHA256SUMS
gpg --verify SHA256SUMS.asc SHA256SUMS   # when present
npm view @zunialab/core@0.1.1 dist.attestations   # once published
```
