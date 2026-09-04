# ADR-0005: Polyrepo package flow

- Status: **Accepted**
- Date: 2026-08-31
- Decision owner: release engineering

## Context

Zunia is a polyrepo: `zunia-core`, `zunia-ui`, `zunia-extension`, `zunia-mobile`,
`zunia-dashboard`, `zunia-website`, `zunia-backend`, `zunia-indexer` and others are
independent git repositories. Today the JavaScript consumers depend on shared code with
filesystem links, for example:

```json
"@zunialab/ui": "file:../zunia-ui/packages/ui"
```

That only works on a machine with the whole workspace checked out side by side. In CI, and for
any contributor with a single repo cloned, the dependency does not resolve. It also means there
is no version boundary at all: a breaking change in the design system or, far worse, in the
wallet kernel, silently reaches every consumer with no changelog and no way to pin.

A monorepo would solve this. The team has decided to stay polyrepo, so the boundary has to be
enforced by publishing instead.

## Decision

**Shared code is consumed as published, versioned packages. No `file:` or `path:`
dependencies across repository boundaries.**

Published from `zunia-core`:

- `@zunialab/core` to npm, containing the `wasm-bindgen` output plus the TypeScript facade,
  built with `--provenance`.
- `zunia_core`, a Dart package containing the `flutter_rust_bridge` bindings.
- Native libraries as signed GitHub Release artifacts: `aarch64-linux-android`,
  `armv7-linux-androideabi`, `x86_64-linux-android`, `aarch64-apple-ios`,
  `aarch64-apple-ios-sim`, and an assembled `xcframework`. Mobile CI downloads these by tag,
  so app builds do not need a Rust toolchain.

Published from `zunia-ui`:

- `@zunialab/ui`, `@zunialab/tokens`, `@zunialab/fonts` to npm.
- `zunia_ui` and `zunia_tokens` as Dart packages for the Flutter app.

Mechanics:

- Changesets in every publishing repository, producing semver bumps and a changelog.
- Signed git tags, GitHub Releases, npm provenance.
- Consumers depend on caret ranges, never `file:`, and commit their lockfile.
- A `repository_dispatch` on release opens an update pull request in each consumer, so a
  kernel bump is a reviewed change with a diff, not an invisible one.
- pnpm 9 in every JavaScript repository per `PACKAGE_MANAGERS.md`, with the exception of
  `zunia-chain-registry`, which stays on yarn 3 to track upstream.

## Bootstrap state

The npm scope `@zunialab` is not reserved yet, tracked as `npm.scope_reserved` in
`zunia-infra/provisioning/status.yaml`. Until it is, a consumer cannot resolve the semver range
it declares, and reverting to `file:` dependencies would undo this decision.

The transition is handled explicitly rather than by leaving `file:` in place:

- `dependencies` already declares the real contract, for example `"@zunialab/ui": "^0.1.0"`.
- A marked `pnpm.overrides` block in the same `package.json` resolves that range to a local
  `link:` path so installs work today.

Deleting the override block is the only step required once publishing works. Because the
declared dependency is already a version range, nothing else in the consumer changes, and a
`pnpm install` after deletion resolves from the registry and records it in the lockfile.

This is the one sanctioned committed override. Any other local override is a working-copy
change that must not reach `main`.

## Consequences

- Local development against unpublished changes uses `pnpm link` or a temporary pnpm
  `overrides` block in the consumer, deliberately and never committed to `main`, with the
  single documented exception of the bootstrap block above.
- A kernel patch reaches production only after a release plus a merged consumer bump. That is
  slower than a monorepo, and it is the intended tradeoff: crypto changes should be visible.
- The npm scope `@zunialab` must be reserved and access restricted to the release role.
- CI in every repository must install from the registry, which means a release that fails to
  publish breaks consumers loudly rather than silently.
