# Fuzzing

Six targets, all covering parsers that read attacker-controlled input.

| Target | Input reaches it from | Worst case if it breaks |
| --- | --- | --- |
| `tx_decoder` | A website, via `signDirect` | The signing prompt describes a different transaction from the one being signed |
| `eip712_parser` | A website, via `eth_signTypedData_v4` | A permit is signed that grants something other than what the prompt displayed |
| `svm_message` | A website, via a Solana signing request | Positional privileges are misread, so an account the prompt calls read-only can be drained |
| `registry_parser` | Community-submitted registry JSON | Chain loading dies for every user, or addresses are derived on the wrong scheme |
| `address_parser` | Paste, QR scan, dApp request | The wallet displays one address and sends to another |
| `keyring_envelope` | Local storage, writable by anything with device access | The wallet cannot start, or opens without the right password |

Each target asserts properties rather than just checking for the absence of a crash. A panic is
a bug, but so is a decode that succeeds while misrepresenting what it read: the user approves
based on what the prompt says, so a confident wrong answer is more dangerous than an error.

Two bugs of that second kind have been found so far, both by the mutation sweep below:

- A NUL byte spliced into the middle of a validator address survived decoding and reached the
  prompt, where it would render as an invisible break. A user comparing the displayed address
  against one from a validator's website would have seen a match that was not one. Fixed by
  demoting any message with an unrenderable address to unknown, in `crates/cosmos/src/decode.rs`.
- EIP-712 documents with an undefined `primaryType`, a field typed `256`, and a `bytes32` holding
  57 hex characters all parsed and none could be hashed, so the prompt could render a payload the
  wallet was unable to sign. Fixed by checking hashability at parse time, in
  `crates/evm/src/eip712.rs`.

## Running without nightly

`cargo-fuzz` needs a nightly toolchain, which is not always available and is a slow first-time
install. `crates/properties/examples/mutate.rs` is a stable-toolchain mutation sweep over the same
property assertions and the same corpus. It has no coverage feedback, so it will never reach the
deep paths libFuzzer finds, but it is what actually found both bugs listed above, and it runs
anywhere in seconds.

```bash
cd zunia-core

# Every target, 200k mutations each.
cargo run -p zunia-properties --features solana --example mutate

# One target, harder.
cargo run -p zunia-properties --example mutate -- eip712_parser 2000000
```

Run it unoptimised. The release profile sets `panic = "abort"`, so `catch_unwind` cannot collect
findings there and the process dies on the first one instead of reporting it.

Each target is seeded from a fixed value derived from its name, so a run is reproducible and a
clean run means something. The sweep also feeds every target a sample of the other targets'
corpora, because a parser is most likely to break on input shaped for a format its author never
pictured.

## Running the real fuzzer

`cargo-fuzz` needs a nightly toolchain for the sanitizer support:

```bash
cargo install cargo-fuzz
rustup toolchain install nightly

cd zunia-core
cargo +nightly fuzz run tx_decoder
```

A crash is written to `fuzz/artifacts/<target>/`. Reproduce it with:

```bash
cargo +nightly fuzz run tx_decoder fuzz/artifacts/tx_decoder/crash-<hash>
```

Any artifact found must be committed to `fuzz/corpus/<target>/` as a regression case and turned
into a unit test in the crate it came from, so that the fix stays fixed without needing the
fuzzer to rediscover it.

## Seeding the corpus

The fuzzer finds structured input far faster from a seed corpus than from nothing. The signing
vectors make good seeds for `tx_decoder`:

```bash
mkdir -p fuzz/corpus/tx_decoder
python3 - <<'PY'
import json, pathlib
vectors = json.load(open("tests/vectors/cosmos-signing.json"))
out = pathlib.Path("fuzz/corpus/tx_decoder")
for case in vectors["cases"]:
    (out / case["name"]).write_bytes(bytes.fromhex(case["direct"]["sign_bytes_hex"]))
PY
```

And the registry itself for `registry_parser`:

```bash
mkdir -p fuzz/corpus/registry_parser
cp ../zunia-chain-registry/cosmos/*.json fuzz/corpus/registry_parser/
```

The EVM and Solana vectors seed the two newer targets:

```bash
mkdir -p fuzz/corpus/eip712_parser fuzz/corpus/svm_message
python3 - <<'PY'
import json, pathlib
evm = json.load(open("tests/vectors/evm-signing.json"))
out = pathlib.Path("fuzz/corpus/eip712_parser")
for case in evm["typedData"]:
    (out / f"{case['name']}.json").write_text(json.dumps(case["payload"]))

svm = json.load(open("tests/vectors/svm-signing.json"))
out = pathlib.Path("fuzz/corpus/svm_message")
for case in svm["transactions"]:
    (out / case["name"]).write_bytes(bytes.fromhex(case["messageBytes"]))
PY
```

## Why this is a separate workspace

`fuzz/Cargo.toml` declares an empty `[workspace]`, so it is excluded from the main one.
`cargo-fuzz` passes sanitizer flags to every crate it compiles; without the split, a plain
`cargo test` in `zunia-core` would start resolving `libfuzzer-sys` and building against those
flags.

## CI

Fuzzing runs on a schedule rather than per pull request, because a useful run takes minutes to
hours and a per-PR budget of seconds finds nothing. Per-PR CI builds the targets so they cannot
rot, and replays the committed corpus, which is fast and catches regressions on previously
found crashes.
