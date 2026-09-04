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

## Cutting a release

```bash
# 1. Confirm green CI on main.
# 2. Tag. The release workflow builds everything and notifies consumers.
git tag -s v0.1.0 -m "zunia-core 0.1.0"
git push origin v0.1.0
```

Signed tags are required. Unsigned tags are rejected by branch protection once it is on.

## Local builds

```bash
./scripts/build-wasm.sh      # -> packages/npm
./scripts/build-native.sh    # -> dist/native (needs NDK / Xcode)
```

## Consumer update PRs

On a successful tagged release the workflow dispatches `zunia-core-released` to
`zunia-extension`, `zunia-mobile` and `zunia-dashboard`. Each consumer's
`.github/workflows/dependabot-core.yml` (or equivalent) opens a PR that bumps the pin and
runs its own CI. Merge is a human decision: crypto changes are never auto-merged.

## Verifying an artifact

```bash
gh release download v0.1.0 -R Zunia-Lab/zunia-core
shasum -a 256 -c SHA256SUMS
gpg --verify SHA256SUMS.asc SHA256SUMS   # when present
npm view @zunialab/core@0.1.0 dist.attestations
```
