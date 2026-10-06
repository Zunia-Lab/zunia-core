#!/usr/bin/env node
/**
 * End-to-end check of the built `packages/npm` artifact.
 *
 * `cargo test` proves the Rust is right. This proves the *artifact* is right: that the
 * wasm-bindgen glue, the facade, the exports map and the .d.ts survived the build and still
 * produce the bytes CosmJS produces. The failure mode it exists to catch is a package that
 * imports cleanly and signs the wrong document — a signature that verifies against nothing,
 * which surfaces on chain as an opaque "unauthorized".
 *
 * The package is imported through its own `exports` map, resolved by Node, from a scratch
 * directory that symlinks `@zunialab/core` at `packages/npm`. Importing the file path
 * directly would skip exactly the part of package.json most likely to be wrong.
 *
 * Run: node scripts/smoke-npm.mjs   (after ./scripts/build-wasm.sh)
 */

import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PKG = path.join(ROOT, "packages", "npm");
const VECTORS = path.join(ROOT, "tests", "vectors", "cosmos-signing.json");

let failures = 0;
let checks = 0;

function ok(name, condition, detail = "") {
  checks += 1;
  if (condition) {
    console.log(`  ok   ${name}`);
  } else {
    failures += 1;
    console.log(`  FAIL ${name}${detail ? `\n       ${detail}` : ""}`);
  }
}

function eq(name, actual, expected) {
  ok(
    name,
    actual === expected,
    actual === expected ? "" : `expected ${expected}\n       actual   ${actual}`,
  );
}

/**
 * Resolve `@zunialab/core` the way a consumer does, so the `exports` map is under test.
 * A scratch root keeps this out of the repo: nothing here is installed or committed.
 */
function importBuiltPackage() {
  const scratch = mkdtempSync(path.join(tmpdir(), "zunia-core-smoke-"));
  mkdirSync(path.join(scratch, "node_modules", "@zunialab"), { recursive: true });
  symlinkSync(PKG, path.join(scratch, "node_modules", "@zunialab", "core"), "dir");
  writeFileSync(
    path.join(scratch, "package.json"),
    JSON.stringify({ name: "zunia-core-smoke", private: true, type: "module" }),
  );
  const entry = path.join(scratch, "entry.mjs");
  writeFileSync(entry, 'export * from "@zunialab/core";\n');
  return { entry: pathToFileURL(entry).href, cleanup: () => rmSync(scratch, { recursive: true, force: true }) };
}

// --- the message set, written the way @zunialab/interchain writes it -----------------------
//
// Hand-written rather than round-tripped through the kernel's own JSON bridge: rebuilding the
// payload with the code that parses it would prove only that the bridge is self-consistent.

const FEE = JSON.stringify({
  amount: [{ denom: "uatom", amount: "5000" }],
  gas_limit: "200000",
});

/** A chain document matching the vector key: coin type 118, `cosmos` prefix, secp256k1. */
const COSMOS_HUB = JSON.stringify({
  chainId: "cosmoshub-4",
  chainName: "Cosmos Hub",
  rpc: "https://rpc.cosmos.example",
  rest: "https://api.cosmos.example",
  bip44: { coinType: 118 },
  bech32Config: {
    bech32PrefixAccAddr: "cosmos",
    bech32PrefixValAddr: "cosmosvaloper",
    bech32PrefixConsAddr: "cosmosvalcons",
  },
  currencies: [{ coinDenom: "ATOM", coinMinimalDenom: "uatom", coinDecimals: 6 }],
  feeCurrencies: [{ coinDenom: "ATOM", coinMinimalDenom: "uatom", coinDecimals: 6 }],
  stakeCurrency: { coinDenom: "ATOM", coinMinimalDenom: "uatom", coinDecimals: 6 },
});

/** Osmosis, for the swap signing round: same coin type, so the vector key owns `addresses.osmo`. */
const OSMOSIS = JSON.stringify({
  chainId: "osmosis-1",
  chainName: "Osmosis",
  rpc: "https://rpc.osmosis.example",
  rest: "https://lcd.osmosis.example",
  bip44: { coinType: 118 },
  bech32Config: {
    bech32PrefixAccAddr: "osmo",
    bech32PrefixValAddr: "osmovaloper",
    bech32PrefixConsAddr: "osmovalcons",
  },
  currencies: [{ coinDenom: "OSMO", coinMinimalDenom: "uosmo", coinDecimals: 6 }],
  feeCurrencies: [{ coinDenom: "OSMO", coinMinimalDenom: "uosmo", coinDecimals: 6 }],
  stakeCurrency: { coinDenom: "OSMO", coinMinimalDenom: "uosmo", coinDecimals: 6 },
});
const OSMOSIS_FEE = JSON.stringify({
  amount: [{ denom: "uosmo", amount: "5000" }],
  gas_limit: "300000",
});

const TO = "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz";
const ATOM_ON_OSMOSIS = "ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2";
const SWAP_OUT_DENOM = "ibc/794C7D7F3B857713878A3A1927251FA6AC1EEE520424C1F6FAFE9BA26D476138";

function messageFor(name, addresses) {
  const from = addresses.cosmos;
  switch (name) {
    case "msg_send":
      return {
        typeUrl: "/cosmos.bank.v1beta1.MsgSend",
        value: {
          from_address: from,
          to_address: TO,
          amount: [{ denom: "uatom", amount: "1000000" }],
        },
      };
    case "msg_transfer_with_timeout":
      return {
        typeUrl: "/ibc.applications.transfer.v1.MsgTransfer",
        value: {
          source_port: "transfer",
          source_channel: "channel-141",
          token: { denom: "uatom", amount: "1000000" },
          sender: from,
          receiver: addresses.addr_safro,
          timeout_height: { revision_number: "1", revision_height: "20000000" },
          timeout_timestamp: "1700000000000000000",
          memo: "forward",
        },
      };
    case "msg_transfer_no_timeout":
      return {
        typeUrl: "/ibc.applications.transfer.v1.MsgTransfer",
        value: {
          source_port: "transfer",
          source_channel: "channel-141",
          token: { denom: "uatom", amount: "1000000" },
          sender: from,
          receiver: addresses.addr_safro,
          timeout_height: { revision_number: "0", revision_height: "0" },
          timeout_timestamp: "0",
          memo: "",
        },
      };
    case "msg_execute_contract":
      // base64 of {"swap":{"offer":"100"}} — interchain base64-encodes the contract call, and
      // the bridge must decode on the way in. Get the direction wrong and every swap and NFT
      // transfer produces an invalid contract call that still assembles.
      return {
        typeUrl: "/cosmwasm.wasm.v1.MsgExecuteContract",
        value: {
          sender: from,
          contract: TO,
          msg: "eyJzd2FwIjp7Im9mZmVyIjoiMTAwIn19",
          funds: [{ denom: "uatom", amount: "100" }],
        },
      };
    // Osmosis's native swaps, shaped as the extension sends them. The split carries its pool
    // ids as numbers on purpose: callers emit both, and the osmojs bytes must come out either way.
    case "msg_swap_exact_amount_in":
      return {
        typeUrl: "/osmosis.poolmanager.v1beta1.MsgSwapExactAmountIn",
        value: {
          sender: addresses.osmo,
          routes: [{ pool_id: "3586", token_out_denom: SWAP_OUT_DENOM }],
          token_in: { denom: "uosmo", amount: "9950000" },
          token_out_min_amount: "350000",
        },
      };
    case "msg_swap_exact_amount_in_multi_hop":
      return {
        typeUrl: "/osmosis.poolmanager.v1beta1.MsgSwapExactAmountIn",
        value: {
          sender: addresses.osmo,
          routes: [
            { pool_id: "1", token_out_denom: ATOM_ON_OSMOSIS },
            { pool_id: "3586", token_out_denom: SWAP_OUT_DENOM },
          ],
          token_in: { denom: "uosmo", amount: "10000000" },
          token_out_min_amount: "340000",
        },
      };
    case "msg_split_route_swap_exact_amount_in":
      return {
        typeUrl: "/osmosis.poolmanager.v1beta1.MsgSplitRouteSwapExactAmountIn",
        value: {
          sender: addresses.osmo,
          routes: [
            { pools: [{ pool_id: 3498, token_out_denom: SWAP_OUT_DENOM }], token_in_amount: "6000000" },
            { pools: [{ pool_id: 3586, token_out_denom: SWAP_OUT_DENOM }], token_in_amount: "4000000" },
          ],
          token_in_denom: "uosmo",
          token_out_min_amount: "350000",
        },
      };
    default:
      throw new Error(`no proto-JSON counterpart for vector "${name}"`);
  }
}

// --- run ----------------------------------------------------------------------------------

const { entry, cleanup } = importBuiltPackage();
let core;
try {
  core = await import(entry);
} finally {
  // The module and its wasm are already in memory; the scratch tree is no longer needed.
  cleanup();
}

const vectors = JSON.parse(readFileSync(VECTORS, "utf8"));
const { addresses, mnemonic, pubkey_compressed_hex: pubkey } = vectors.key;
const signer = vectors.signer;
const caseNamed = (name) => {
  const found = vectors.cases.find((c) => c.name === name);
  if (!found) throw new Error(`vector ${name} is missing`);
  return found;
};

console.log(`@zunialab/core resolved through its exports map, kernelVersion ${core.kernelVersion()}`);
console.log(
  `vectors: ${path.relative(ROOT, VECTORS)} ` +
    `(CosmJS ${vectors.generated_with.cosmjs}, osmojs ${vectors.generated_with.osmojs})\n`,
);

// 1. build_sign_bytes matches CosmJS, in both sign modes, for the three shapes the task names,
//    and matches osmojs for the three Osmosis swaps.
console.log("build_sign_bytes vs golden vectors");
for (const name of [
  "msg_send",
  "msg_transfer_with_timeout",
  "msg_execute_contract",
  "msg_swap_exact_amount_in",
  "msg_swap_exact_amount_in_multi_hop",
  "msg_split_route_swap_exact_amount_in",
]) {
  const vector = caseNamed(name);
  const msgs = JSON.stringify([messageFor(name, addresses)]);
  for (const mode of ["direct", "amino"]) {
    const actual = core.buildSignBytes(
      signer.chain_id,
      msgs,
      FEE,
      vector.memo,
      signer.account_number,
      signer.sequence,
      pubkey,
      false,
      mode,
    );
    eq(`${name} / ${mode}`, actual, vector[mode].sign_bytes_hex);
  }
}

// 2. The one payload the bridge must refuse. An IBC transfer with neither a timeout height nor
//    a timeout timestamp can leave the tokens escrowed on the source chain forever, so the
//    refusal has to survive the trip through wasm rather than being a Rust-only guard.
console.log("\nrefusals survive the boundary");
{
  const msgs = JSON.stringify([messageFor("msg_transfer_no_timeout", addresses)]);
  let threw = null;
  try {
    core.buildSignBytes(signer.chain_id, msgs, FEE, "", signer.account_number, signer.sequence, pubkey, false, "direct");
  } catch (error) {
    threw = error;
  }
  ok(
    "an IBC transfer with no timeout is refused, not signed",
    threw instanceof Error,
    threw ? `threw: ${threw.message}` : "returned sign bytes instead of throwing",
  );
  // Distinguishes the deliberate refusal from a bridge that simply cannot parse an
  // MsgTransfer: the same message with a timeout must go straight through.
  ok(
    "the same transfer with a timeout is not refused",
    typeof core.buildSignBytes(
      signer.chain_id,
      JSON.stringify([messageFor("msg_transfer_with_timeout", addresses)]),
      FEE, "", signer.account_number, signer.sequence, pubkey, false, "direct",
    ) === "string",
  );
  if (threw) console.log(`       (message: "${threw.message}")`);

  // A swap without a price floor is the other payload the kernel must never sign: whoever
  // orders the block decides what it returns.
  const swap = messageFor("msg_swap_exact_amount_in", addresses);
  const noFloor = JSON.stringify([{ ...swap, value: { ...swap.value, token_out_min_amount: "0" } }]);
  let refused = null;
  try {
    core.buildSignBytes("osmosis-1", noFloor, OSMOSIS_FEE, "", 1, 0, pubkey, false, "direct");
  } catch (error) {
    refused = error;
  }
  ok(
    "a swap with token_out_min_amount 0 is refused, not signed",
    refused instanceof Error && refused.message.includes("token_out_min_amount"),
    refused ? `threw: ${refused.message}` : "returned sign bytes instead of throwing",
  );
  if (refused) console.log(`       (message: "${refused.message}")`);
}

// 3. assemble_tx_raw carries the golden body and auth_info. Checked by containment because the
//    signature is the caller's; the encoded halves are the part the kernel owns.
console.log("\nassemble_tx_raw / build_simulate_tx carry the golden encodings");
{
  const name = "msg_send";
  const vector = caseNamed(name);
  const msgs = JSON.stringify([messageFor(name, addresses)]);
  // 64 bytes: r || s, the shape assemble_tx_raw requires.
  const signature = "ab".repeat(64);
  const raw = core.assembleTxRaw(
    signer.chain_id, msgs, FEE, vector.memo,
    signer.account_number, signer.sequence, pubkey, false, "direct", signature,
  );
  ok("TxRaw contains the golden body_bytes", raw.includes(vector.direct.body_bytes_hex));
  ok("TxRaw contains the golden auth_info_bytes", raw.includes(vector.direct.auth_info_bytes_hex));
  ok("TxRaw contains the signature it was given", raw.includes(signature));

  const simulate = core.buildSimulateTx(
    signer.chain_id, msgs, FEE, vector.memo,
    signer.account_number, signer.sequence, pubkey, false,
  );
  ok("simulate tx contains the golden body_bytes", simulate.includes(vector.direct.body_bytes_hex));
  ok("simulate tx carries a 64-byte zero signature", simulate.includes("00".repeat(64)));
  ok("simulate tx is not the signed tx", simulate !== raw);
}

// 4. preview_tx describes the bytes that will actually be signed.
console.log("\npreview_tx");
{
  const name = "msg_execute_contract";
  const vector = caseNamed(name);
  const msgs = JSON.stringify([messageFor(name, addresses)]);
  const args = [
    signer.chain_id, msgs, FEE, vector.memo,
    signer.account_number, signer.sequence, pubkey, false, "direct",
  ];
  const preview = core.previewTx(...args);
  ok("preview is a plain object, not a Map", preview instanceof Map === false && typeof preview === "object");
  eq("preview.chainId", preview.chainId, signer.chain_id);
  eq("preview.gasLimit is a string", typeof preview.gasLimit, "string");
  eq("preview.gasLimit", preview.gasLimit, "200000");
  ok("preview names the contract action", preview.summaries.some((s) => s.includes("swap")));
  eq(
    "preview.signBytesHash is sha256 of the sign bytes",
    preview.signBytesHash,
    createHash("sha256").update(Buffer.from(core.buildSignBytes(...args), "hex")).digest("hex"),
  );

  // A split swap: the prompt must show the total spent, the floor, the output and the pools.
  const split = core.previewTx(
    "osmosis-1",
    JSON.stringify([messageFor("msg_split_route_swap_exact_amount_in", addresses)]),
    OSMOSIS_FEE, "", 1, 0, pubkey, false, "direct",
  );
  eq(
    "split swap summary",
    split.summaries[0],
    `Swap 10000000 uosmo for at least 350000 ${SWAP_OUT_DENOM} through 2 routes (pools 3498; 3586)`,
  );
  eq("split swap spends funds", split.spendsFunds, true);
  eq("split swap names only the sender", JSON.stringify(split.counterparties), JSON.stringify([addresses.osmo]));
}

// 5. The one-shot path, from the vector mnemonic. sign_tx must be exactly
//    derive -> sign_bytes -> sign -> assemble; secp256k1 signing here is RFC 6979
//    deterministic, so equality with the assembled form pins it.
console.log("\nsign_tx from the vector mnemonic");
{
  const derived = core.deriveAddress(mnemonic, "", COSMOS_HUB, 0);
  ok("deriveAddress returns a plain object", derived instanceof Map === false);
  eq("derived address", derived.address, addresses.cosmos);
  eq("derived public key", derived.publicKeyHex, pubkey);

  for (const name of ["msg_send", "msg_transfer_with_timeout", "msg_execute_contract"]) {
    const vector = caseNamed(name);
    const msgs = JSON.stringify([messageFor(name, addresses)]);
    for (const mode of ["direct", "amino"]) {
      const signBytes = core.buildSignBytes(
        signer.chain_id, msgs, FEE, vector.memo,
        signer.account_number, signer.sequence, pubkey, false, mode,
      );
      eq(`${name} / ${mode}: sign_tx signs the golden bytes`, signBytes, vector[mode].sign_bytes_hex);

      const signature = core.signCosmos(mnemonic, "", COSMOS_HUB, 0, signBytes);
      const expected = core.assembleTxRaw(
        signer.chain_id, msgs, FEE, vector.memo,
        signer.account_number, signer.sequence, pubkey, false, mode, signature,
      );
      const actual = core.signTx(
        mnemonic, "", COSMOS_HUB, 0, signer.chain_id, msgs, FEE, vector.memo,
        signer.account_number, signer.sequence, mode,
      );
      eq(`${name} / ${mode}: sign_tx == derive+sign+assemble`, actual, expected);
      ok(
        `${name} / ${mode}: TxRaw carries the golden body`,
        actual.includes(vector.direct.body_bytes_hex),
      );
    }
  }
}

// 5b. The same one-shot path for an Osmosis swap, against an Osmosis chain document. No golden
//     bytes exist for osmosis-1, so equality with the three-step path is what pins it, and the
//     Cosmos Hub document must refuse the osmo sender outright.
console.log("\nsign_tx for an Osmosis swap");
for (const name of ["msg_swap_exact_amount_in", "msg_split_route_swap_exact_amount_in"]) {
  const msgs = JSON.stringify([messageFor(name, addresses)]);
  for (const mode of ["direct", "amino"]) {
    const signBytes = core.buildSignBytes("osmosis-1", msgs, OSMOSIS_FEE, "", 1, 0, pubkey, false, mode);
    const signature = core.signCosmos(mnemonic, "", OSMOSIS, 0, signBytes);
    const expected = core.assembleTxRaw(
      "osmosis-1", msgs, OSMOSIS_FEE, "", 1, 0, pubkey, false, mode, signature,
    );
    const actual = core.signTx(mnemonic, "", OSMOSIS, 0, "osmosis-1", msgs, OSMOSIS_FEE, "", 1, 0, mode);
    eq(`${name} / ${mode}: sign_tx == derive+sign+assemble`, actual, expected);
  }
  let refused = null;
  try {
    core.signTx(mnemonic, "", COSMOS_HUB, 0, signer.chain_id, msgs, FEE, "", 1, 0, "direct");
  } catch (error) {
    refused = error;
  }
  ok(
    `${name}: an osmo sender is refused on the Cosmos Hub`,
    refused instanceof Error && refused.message.includes("address"),
    refused ? `threw: ${refused.message}` : "signed instead of throwing",
  );
}

// 5c. decode_direct_tx never describes a singular field written twice: the chain keeps the last
//     occurrence, so a reader that kept the first could show one recipient or message type while
//     another executes. The two documents are the fuzz corpus's regression seeds; before the fix
//     both read as an ordinary send, safe to sign.
console.log("\ndecode_direct_tx and a singular field written twice");
{
  const seed = (name) =>
    readFileSync(path.join(ROOT, "fuzz", "corpus", "tx_decoder", name)).toString("hex");
  const golden = core.decodeDirectTx(caseNamed("msg_send").direct.sign_bytes_hex);
  eq("the golden send is safe without blind signing", golden.safeWithoutBlindSigning, true);

  const twoRecipients = core.decodeDirectTx(seed("regression_send_with_two_recipients"));
  eq("a send with two recipients carries an unknown message", twoRecipients.hasUnknownMsgs, true);
  eq("a send with two recipients is not safe without blind signing", twoRecipients.safeWithoutBlindSigning, false);
  ok(
    "a send with two recipients names neither",
    twoRecipients.summaries[0].startsWith("UNKNOWN ACTION") && twoRecipients.addresses.length === 0,
    JSON.stringify(twoRecipients.summaries),
  );

  let threw = null;
  try {
    core.decodeDirectTx(seed("regression_any_with_two_type_urls"));
  } catch (error) {
    threw = error;
  }
  ok(
    "an Any naming two message types is refused outright",
    threw instanceof Error,
    threw ? `threw: ${threw.message}` : "decoded instead of throwing",
  );
}

// 6. Numbers, not just BigInts. account_number and sequence come off a REST response as JSON
//    numbers; the wasm boundary converts u64 with ToBigInt, which throws on a Number.
console.log("\nu64 arguments accept what a REST response actually hands you");
{
  const msgs = JSON.stringify([messageFor("msg_send", addresses)]);
  const call = (accountNumber, sequence) =>
    core.buildSignBytes(signer.chain_id, msgs, FEE, "", accountNumber, sequence, pubkey, false, "direct");
  const golden = caseNamed("msg_send").direct.sign_bytes_hex;
  eq("number arguments", call(signer.account_number, signer.sequence), golden);
  eq("bigint arguments", call(BigInt(signer.account_number), BigInt(signer.sequence)), golden);
  eq("string arguments", call(String(signer.account_number), String(signer.sequence)), golden);
}

// 7. The package itself: everything `files` promises exists, and the .d.ts declares the surface
//    this task added. A published tarball missing a declaration is a silent downgrade to `any`.
console.log("\npackage shape");
{
  const pkg = JSON.parse(readFileSync(path.join(PKG, "package.json"), "utf8"));
  eq("package name", pkg.name, "@zunialab/core");
  eq("package type", pkg.type, "module");
  eq("types entry", pkg.types, "./index.d.ts");
  eq("node condition", pkg.exports["."].node, "./node/index.mjs");
  for (const file of pkg.files) {
    ok(`files: ${file} exists`, existsInPackage(file));
  }
  const dts = readFileSync(path.join(PKG, "index.d.ts"), "utf8");
  for (const fn of ["buildSignBytes", "assembleTxRaw", "buildSimulateTx", "signTx", "previewTx"]) {
    ok(`index.d.ts declares ${fn}`, new RegExp(`export function ${fn}\\(`).test(dts));
  }
  const generated = readFileSync(path.join(PKG, "zunia_core.d.ts"), "utf8");
  for (const fn of ["build_sign_bytes", "assemble_tx_raw", "build_simulate_tx", "sign_tx", "preview_tx"]) {
    ok(`generated zunia_core.d.ts declares ${fn}`, new RegExp(`export function ${fn}\\(`).test(generated));
  }
}

function existsInPackage(relative) {
  try {
    readFileSync(path.join(PKG, relative));
    return true;
  } catch {
    return false;
  }
}

console.log(`\n${checks - failures}/${checks} checks passed`);
if (failures > 0) {
  console.error(`${failures} check(s) failed`);
  process.exit(1);
}
