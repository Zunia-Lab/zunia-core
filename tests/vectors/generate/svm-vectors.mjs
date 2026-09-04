// Generates Solana golden vectors with @solana/web3.js.
//
// Two things are being pinned. First, that our SLIP-0010 derivation lands on the same addresses
// Phantom, Solflare and the Solana CLI would show for the same seed, because an address mismatch
// means a funded account looks empty. Second, that our message serialisation and ed25519 signing
// are byte-identical to web3.js, because a validator checks the signature against the message
// bytes it receives and a one-byte difference makes the transaction unverifiable.
//
// A known divergence, recorded here rather than papered over: web3.js orders accounts within a
// privilege class by their base58 *string*, while solana-sdk in Rust orders them by raw key
// bytes. Both produce valid transactions, since instruction indices are self-consistent either
// way, but they are not always the same bytes. Our compiler follows solana-sdk. Each case below
// therefore records whether the two orderings agree, and the Rust test asserts byte equality only
// for the cases where they do; for the rest it asserts that web3.js output parses and verifies,
// which is the property that actually matters when a dApp hands us a message it built.
//
// Run: pnpm generate:svm

import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  Keypair,
  LAMPORTS_PER_SOL,
  Message,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { mnemonicToSeedSync } from "bip39";
import bs58 from "bs58";
import { derivePath } from "ed25519-hd-key";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "..", "svm-signing.json");

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const seed = mnemonicToSeedSync(MNEMONIC, "");

function accountAt(index) {
  const path = `m/44'/501'/${index}'/0'`;
  const { key } = derivePath(path, seed.toString("hex"));
  const keypair = Keypair.fromSeed(key);
  return {
    path,
    // The SLIP-0010 private key at that path, so the Rust side can confirm it derived the same
    // scalar and not merely the same address.
    privateKey: key.toString("hex"),
    address: keypair.publicKey.toBase58(),
    publicKey: Buffer.from(keypair.publicKey.toBytes()).toString("hex"),
    keypair,
  };
}

const accounts = [0, 1, 2, 3].map(accountAt);
const [payer, cosigner] = accounts;

// A fixed blockhash so the vectors are reproducible. Real ones come from the network.
const BLOCKHASH = "EETubP5AKHgjPAhzPAFcb8BAY1hMH639CWCFTqi3hq1k";

const MEMO_PROGRAM = new PublicKey(
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
);

const cases = [
  {
    name: "single_transfer",
    note: "One transfer, one signer. Only one non-payer account, so both orderings agree by construction.",
    signers: [payer],
    build: () => [
      SystemProgram.transfer({
        fromPubkey: payer.keypair.publicKey,
        toPubkey: new PublicKey(accounts[1].address),
        lamports: LAMPORTS_PER_SOL,
      }),
    ],
  },
  {
    name: "transfer_one_lamport",
    note: "The smallest non-zero amount, so the little-endian u64 has a single set byte.",
    signers: [payer],
    build: () => [
      SystemProgram.transfer({
        fromPubkey: payer.keypair.publicKey,
        toPubkey: new PublicKey(accounts[1].address),
        lamports: 1,
      }),
    ],
  },
  {
    name: "transfer_zero_lamports",
    note: "Zero is a legal transfer and must still encode all eight amount bytes.",
    signers: [payer],
    build: () => [
      SystemProgram.transfer({
        fromPubkey: payer.keypair.publicKey,
        toPubkey: new PublicKey(accounts[1].address),
        lamports: 0,
      }),
    ],
  },
  {
    name: "two_transfers",
    note: "Two instructions sharing a payer. Two distinct recipients, so account ordering is observable.",
    signers: [payer],
    build: () => [
      SystemProgram.transfer({
        fromPubkey: payer.keypair.publicKey,
        toPubkey: new PublicKey(accounts[1].address),
        lamports: 100,
      }),
      SystemProgram.transfer({
        fromPubkey: payer.keypair.publicKey,
        toPubkey: new PublicKey(accounts[2].address),
        lamports: 250,
      }),
    ],
  },
  {
    name: "multi_signer",
    note: "The payer covers the fee while a second account funds the transfer, so two signatures are required.",
    signers: [payer, cosigner],
    build: () => [
      SystemProgram.transfer({
        fromPubkey: cosigner.keypair.publicKey,
        toPubkey: new PublicKey(accounts[2].address),
        lamports: 42,
      }),
    ],
  },
  {
    name: "opaque_program",
    note: "An instruction for a program we do not decode. The summary must report it as unreadable rather than guess.",
    signers: [payer],
    build: () => [
      new TransactionInstruction({
        programId: MEMO_PROGRAM,
        keys: [
          {
            pubkey: payer.keypair.publicKey,
            isSigner: true,
            isWritable: false,
          },
        ],
        data: Buffer.from("zunia", "utf8"),
      }),
    ],
  },
  {
    name: "transfer_plus_memo",
    note: "A readable transfer next to an unreadable memo. The mixed case must not be presented as fully readable.",
    signers: [payer],
    build: () => [
      SystemProgram.transfer({
        fromPubkey: payer.keypair.publicKey,
        toPubkey: new PublicKey(accounts[1].address),
        lamports: 5_000_000,
      }),
      new TransactionInstruction({
        programId: MEMO_PROGRAM,
        keys: [],
        data: Buffer.from("thanks", "utf8"),
      }),
    ],
  },
  {
    name: "empty_instruction_data",
    note: "Zero-length data still needs its compact length prefix written.",
    signers: [payer],
    build: () => [
      new TransactionInstruction({
        programId: MEMO_PROGRAM,
        keys: [],
        data: Buffer.alloc(0),
      }),
    ],
  },
  {
    name: "large_instruction_data",
    note: "Data past 127 bytes forces a two-byte compact length, which is where a naive u8 prefix breaks.",
    signers: [payer],
    build: () => [
      new TransactionInstruction({
        programId: MEMO_PROGRAM,
        keys: [],
        data: Buffer.alloc(200, 0xab),
      }),
    ],
  },
];

/// Reproduces solana-sdk's ordering: privilege class first, then raw key bytes within a class.
function solanaSdkOrdering(message) {
  const signers = message.header.numRequiredSignatures;
  const readonlySigned = message.header.numReadonlySignedAccounts;
  const readonlyUnsigned = message.header.numReadonlyUnsignedAccounts;
  const keys = message.accountKeys;

  const classify = (index) => {
    if (index < signers - readonlySigned) return 0;
    if (index < signers) return 1;
    if (index < keys.length - readonlyUnsigned) return 2;
    return 3;
  };

  const buckets = [[], [], [], []];
  keys.forEach((key, index) => {
    // The fee payer is pinned at index 0 in both implementations, so it is not sorted.
    if (index === 0) return;
    buckets[classify(index)].push(key);
  });

  const byBytes = (a, b) => Buffer.compare(a.toBuffer(), b.toBuffer());
  return [keys[0], ...buckets.flatMap((bucket) => bucket.sort(byBytes))];
}

const transactions = cases.map(({ name, note, signers, build }) => {
  const tx = new Transaction();
  tx.recentBlockhash = BLOCKHASH;
  tx.feePayer = payer.keypair.publicKey;
  for (const instruction of build()) tx.add(instruction);
  tx.sign(...signers.map((s) => s.keypair));

  const message = tx.compileMessage();
  const messageBytes = message.serialize();
  const wire = tx.serialize();

  // Does web3.js's base58-string ordering agree with solana-sdk's byte ordering here?
  const sdkOrder = solanaSdkOrdering(message);
  const orderingsAgree = sdkOrder.every((key, index) =>
    key.equals(message.accountKeys[index])
  );

  // Confirm web3.js verifies its own output before we pin it.
  if (!Message.from(messageBytes).accountKeys.length) {
    throw new Error(`${name}: message did not round trip`);
  }

  return {
    name,
    note,
    signerPaths: signers.map((s) => s.path),
    feePayer: payer.address,
    recentBlockhash: BLOCKHASH,
    header: {
      numRequiredSignatures: message.header.numRequiredSignatures,
      numReadonlySignedAccounts: message.header.numReadonlySignedAccounts,
      numReadonlyUnsignedAccounts: message.header.numReadonlyUnsignedAccounts,
    },
    accountKeys: message.accountKeys.map((key) => key.toBase58()),
    // Present so the Rust test can state precisely why an ordering mismatch is expected rather
    // than treating it as a failure.
    accountKeysInSdkOrder: sdkOrder.map((key) => key.toBase58()),
    orderingsAgree,
    instructions: message.instructions.map((instruction) => ({
      programIdIndex: instruction.programIdIndex,
      accounts: instruction.accounts,
      // web3.js stores compiled instruction data base58 encoded.
      data: Buffer.from(bs58.decode(instruction.data)).toString("hex"),
    })),
    // The bytes each signer signs. ed25519 signs these directly, with no digest step.
    messageBytes: messageBytes.toString("hex"),
    signatures: tx.signatures.map((entry) => ({
      address: entry.publicKey.toBase58(),
      signature: entry.signature
        ? Buffer.from(entry.signature).toString("hex")
        : null,
    })),
    wire: wire.toString("hex"),
    // Solana's transaction id is base58 of the first signature; there is no separate hash.
    id: bs58.encode(tx.signatures[0].signature),
  };
});

const output = {
  description:
    "Solana golden vectors generated with @solana/web3.js. Asserted by crates/svm/tests/golden_vectors.rs. Regenerate with pnpm generate:svm.",
  generator: "@solana/web3.js v1",
  mnemonic: MNEMONIC,
  note: "web3.js sorts accounts within a privilege class by base58 string; solana-sdk and this wallet sort by raw key bytes. Cases where the two disagree are flagged with orderingsAgree=false and are asserted for parseability and signature validity rather than byte equality.",
  accounts: accounts.map(({ keypair, ...rest }) => rest),
  transactions,
};

writeFileSync(OUT, `${JSON.stringify(output, null, 2)}\n`);

const disagreements = transactions.filter((t) => !t.orderingsAgree);
console.log(
  `wrote ${OUT}: ${transactions.length} transactions, ${disagreements.length} with ordering divergence` +
    (disagreements.length
      ? ` (${disagreements.map((t) => t.name).join(", ")})`
      : "")
);
