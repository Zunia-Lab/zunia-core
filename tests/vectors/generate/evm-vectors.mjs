// Generates Ethereum golden vectors with ethers v6.
//
// ethers is the reference here for the same reason CosmJS is the reference for Cosmos: it is the
// implementation that the chains and the dApps in front of them have been agreeing with for
// years. If our RLP, EIP-155, EIP-1559, EIP-191 or EIP-712 encoding differs from ethers by a
// single byte, the signature verifies against nothing and the transaction is rejected or, worse,
// authorises something other than what the prompt displayed.
//
// Every vector records both the digest and the signature. The digest catches encoding bugs
// directly; the signature catches them too but also pins the low-s and recovery-id conventions.
//
// Run: pnpm generate:evm

import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  HDNodeWallet,
  Mnemonic,
  Signature,
  Transaction,
  TypedDataEncoder,
  Wallet,
  hashMessage,
  hexlify,
  keccak256,
  toUtf8Bytes,
  verifyMessage,
} from "ethers";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "..", "evm-signing.json");

// The all-abandon mnemonic. Its first Ethereum account is the default in Hardhat, Foundry's
// anvil and Ganache, so the addresses below can be checked against any of them.
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Explicitly "m", not the default. `fromMnemonic` defaults to m/44'/60'/0'/0/0, so deriving a
// path from that root silently appends to it and produces addresses that match nothing.
const root = HDNodeWallet.fromMnemonic(Mnemonic.fromPhrase(MNEMONIC), "m");

function account(path) {
  const node = root.derivePath(path.replace(/^m\//, ""));
  return {
    path,
    privateKey: node.privateKey.slice(2),
    publicKeyCompressed: node.publicKey.slice(2),
    address: node.address,
    addressLowercase: node.address.toLowerCase(),
  };
}

const accounts = [
  account("m/44'/60'/0'/0/0"),
  account("m/44'/60'/0'/0/1"),
  account("m/44'/60'/1'/0/0"),
  // Ethermint chains, notably Injective and Evmos, derive with coin type 60 on the Cosmos path
  // shape, so the wallet needs this to produce the same key as their own tooling.
  account("m/44'/60'/0'/0/5"),
];

const wallet = new Wallet(`0x${accounts[0].privateKey}`);

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

const txCases = [
  {
    name: "legacy_transfer",
    note: "The plainest possible transaction: an EIP-155 legacy transfer with no data.",
    tx: {
      type: 0,
      chainId: 1,
      nonce: 9,
      gasPrice: 20_000_000_000n,
      gasLimit: 21_000n,
      to: "0x3535353535353535353535353535353535353535",
      value: 1_000_000_000_000_000_000n,
      data: "0x",
    },
  },
  {
    name: "legacy_zero_value_with_data",
    note: "A contract call. Zero value must RLP-encode as an empty string, not as 0x00.",
    tx: {
      type: 0,
      chainId: 1,
      nonce: 0,
      gasPrice: 1n,
      gasLimit: 100_000n,
      to: "0xdac17f958d2ee523a2206206994597c13d831ec7",
      value: 0n,
      data: "0xa9059cbb0000000000000000000000003535353535353535353535353535353535353535000000000000000000000000000000000000000000000000000000000000000a",
    },
  },
  {
    name: "legacy_contract_creation",
    note: "No recipient. The `to` field is an empty RLP string, which is what makes it a deploy.",
    tx: {
      type: 0,
      chainId: 1,
      nonce: 3,
      gasPrice: 10_000_000_000n,
      gasLimit: 500_000n,
      to: null,
      value: 0n,
      data: "0x60806040",
    },
  },
  {
    name: "legacy_large_chain_id",
    note: "Injective's chain id. A 32-bit v computation overflows here, so this is the case that catches it.",
    tx: {
      type: 0,
      chainId: 2525,
      nonce: 1,
      gasPrice: 500_000_000n,
      gasLimit: 300_000n,
      to: "0x1111111111111111111111111111111111111111",
      value: 12_345n,
      data: "0x",
    },
  },
  {
    name: "eip1559_transfer",
    note: "The modern default. Fee fields are two separate caps, and the payload is type-prefixed.",
    tx: {
      type: 2,
      chainId: 1,
      nonce: 42,
      maxPriorityFeePerGas: 1_500_000_000n,
      maxFeePerGas: 30_000_000_000n,
      gasLimit: 21_000n,
      to: "0x3535353535353535353535353535353535353535",
      value: 500_000_000_000_000_000n,
      data: "0x",
    },
  },
  {
    name: "eip1559_zero_priority_fee",
    note: "A zero fee cap is a legitimate value and must encode as an empty string, not 0x00.",
    tx: {
      type: 2,
      chainId: 137,
      nonce: 0,
      maxPriorityFeePerGas: 0n,
      maxFeePerGas: 1n,
      gasLimit: 21_000n,
      to: "0x0000000000000000000000000000000000000001",
      value: 1n,
      data: "0x",
    },
  },
  {
    name: "eip1559_with_access_list",
    note: "A populated access list, so the nested list encoding is exercised rather than skipped.",
    tx: {
      type: 2,
      chainId: 1,
      nonce: 7,
      maxPriorityFeePerGas: 2_000_000_000n,
      maxFeePerGas: 50_000_000_000n,
      gasLimit: 200_000n,
      to: "0xdac17f958d2ee523a2206206994597c13d831ec7",
      value: 0n,
      data: "0x70a08231",
      accessList: [
        {
          address: "0xdac17f958d2ee523a2206206994597c13d831ec7",
          storageKeys: [
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000000000000000000000000001",
          ],
        },
        {
          address: "0x3535353535353535353535353535353535353535",
          storageKeys: [],
        },
      ],
    },
  },
  {
    name: "eip2930_access_list_type",
    note: "Type 1. Rarely used in the wild, but a dApp can still request one and we must not misencode it.",
    tx: {
      type: 1,
      chainId: 1,
      nonce: 2,
      gasPrice: 15_000_000_000n,
      gasLimit: 150_000n,
      to: "0x1111111111111111111111111111111111111111",
      value: 0n,
      data: "0xdeadbeef",
      accessList: [
        {
          address: "0x1111111111111111111111111111111111111111",
          storageKeys: [
            "0x00000000000000000000000000000000000000000000000000000000000000ff",
          ],
        },
      ],
    },
  },
];

const transactions = await Promise.all(
  txCases.map(async ({ name, note, tx }) => {
    const unsigned = Transaction.from({ ...tx });
    const signedSerialized = await wallet.signTransaction({ ...tx });
    const signed = Transaction.from(signedSerialized);

    return {
      name,
      note,
      signerPath: accounts[0].path,
      signerAddress: accounts[0].address,
      tx: {
        type: tx.type,
        chainId: String(tx.chainId),
        nonce: String(tx.nonce),
        gasLimit: String(tx.gasLimit),
        gasPrice: tx.gasPrice === undefined ? null : String(tx.gasPrice),
        maxFeePerGas:
          tx.maxFeePerGas === undefined ? null : String(tx.maxFeePerGas),
        maxPriorityFeePerGas:
          tx.maxPriorityFeePerGas === undefined
            ? null
            : String(tx.maxPriorityFeePerGas),
        to: tx.to,
        value: String(tx.value),
        data: tx.data,
        accessList: (tx.accessList ?? []).map((item) => ({
          address: item.address,
          storageKeys: item.storageKeys,
        })),
      },
      // The bytes that get hashed. This is where an encoding bug shows up first.
      signPayload: unsigned.unsignedSerialized.slice(2),
      signHash: unsigned.unsignedHash.slice(2),
      signature: {
        r: signed.signature.r.slice(2),
        s: signed.signature.s.slice(2),
        // ethers normalises `signature.v` to 27 or 28 and keeps the EIP-155 value in
        // `networkV`, so `v` is not the byte that appears on the wire. Recorded separately
        // because reading `v` as the wire value is an easy and silent mistake.
        vNormalised: String(signed.signature.v),
        yParity: signed.signature.yParity,
        // What the RLP payload actually contains: the EIP-155 value for legacy transactions,
        // and the bare y parity for typed ones, which carry the chain id in a field of their own.
        onWireV: String(
          tx.type === 0
            ? (signed.signature.networkV ??
              BigInt(27 + signed.signature.yParity))
            : signed.signature.yParity
        ),
      },
      signedSerialized: signedSerialized.slice(2),
      txHash: signed.hash.slice(2),
    };
  })
);

// ---------------------------------------------------------------------------
// personal_sign, EIP-191
// ---------------------------------------------------------------------------

const messageCases = [
  { name: "ascii", message: "Hello, Zunia" },
  { name: "empty", message: "" },
  {
    name: "siwe",
    message:
      "app.zunialab.com wants you to sign in with your Ethereum account:\n0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n\nURI: https://app.zunialab.com\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2026-08-31T12:00:00.000Z",
  },
  {
    name: "unicode",
    // Multi-byte characters make the length prefix count bytes, not characters. A wallet that
    // counts characters produces a different digest and an invalid signature.
    message: "Zunia \u00e9\u00e8 \u4f60\u597d \ud83d\ude80",
  },
  {
    name: "length_boundary_9",
    message: "123456789",
  },
  {
    name: "length_boundary_10",
    // Ten bytes is where the decimal length prefix becomes two characters.
    message: "1234567890",
  },
  {
    name: "length_boundary_100",
    message: "a".repeat(100),
  },
  {
    name: "hex_looking_text",
    // Text that looks like hex must still be signed as text. Treating it as bytes changes the
    // digest, and this is a real source of interop bugs.
    message: "0xdeadbeef",
  },
];

const messages = await Promise.all(
  messageCases.map(async ({ name, message }) => {
    const bytes = toUtf8Bytes(message);
    const prefix = toUtf8Bytes(
      `\u0019Ethereum Signed Message:\n${bytes.length}`
    );
    const payload = new Uint8Array([...prefix, ...bytes]);
    const signature = await wallet.signMessage(message);

    return {
      name,
      message,
      messageUtf8Hex: hexlify(bytes).slice(2),
      byteLength: bytes.length,
      payload: hexlify(payload).slice(2),
      hash: hashMessage(message).slice(2),
      // Sanity: our own reconstruction of the payload must hash to what ethers says.
      hashOfPayload: keccak256(payload).slice(2),
      signature: signature.slice(2),
      signerAddress: accounts[0].address,
    };
  })
);

for (const message of messages) {
  if (message.hash !== message.hashOfPayload) {
    throw new Error(`payload reconstruction disagrees for ${message.name}`);
  }
}

// ---------------------------------------------------------------------------
// EIP-712 typed data
// ---------------------------------------------------------------------------

const typedCases = [
  {
    name: "spec_mail_example",
    note: "The example from the EIP-712 specification itself, so the published intermediate hashes apply.",
    domain: {
      name: "Ether Mail",
      version: "1",
      chainId: 1,
      verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    },
    types: {
      Person: [
        { name: "name", type: "string" },
        { name: "wallet", type: "address" },
      ],
      Mail: [
        { name: "from", type: "Person" },
        { name: "to", type: "Person" },
        { name: "contents", type: "string" },
      ],
    },
    value: {
      from: {
        name: "Cow",
        wallet: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
      },
      to: {
        name: "Bob",
        wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
      },
      contents: "Hello, Bob!",
    },
  },
  {
    name: "permit",
    note: "ERC-2612 permit. The single most-signed typed payload in the ecosystem, and an unlimited value here is a drain.",
    domain: {
      name: "USD Coin",
      version: "2",
      chainId: 1,
      verifyingContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    },
    types: {
      Permit: [
        { name: "owner", type: "address" },
        { name: "spender", type: "address" },
        { name: "value", type: "uint256" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
      ],
    },
    value: {
      owner: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
      spender: "0x1111111254EEB25477B68fb85Ed929f73A960582",
      value:
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
      nonce: "0",
      deadline: "1893456000",
    },
  },
  {
    name: "arrays_and_nesting",
    note: "Dynamic arrays hash element-wise then hash the concatenation. Nested structs recurse. Both are easy to get subtly wrong.",
    domain: {
      name: "Zunia",
      version: "1",
      chainId: 1,
      verifyingContract: "0x0000000000000000000000000000000000000001",
      salt: "0x0000000000000000000000000000000000000000000000000000000000000042",
    },
    types: {
      Item: [
        { name: "id", type: "uint256" },
        { name: "tags", type: "string[]" },
      ],
      Order: [
        { name: "items", type: "Item[]" },
        { name: "recipients", type: "address[]" },
        { name: "note", type: "bytes" },
        { name: "flag", type: "bool" },
        { name: "small", type: "int8" },
      ],
    },
    value: {
      items: [
        { id: "1", tags: ["a", "bb"] },
        { id: "2", tags: [] },
      ],
      recipients: [
        "0x3535353535353535353535353535353535353535",
        "0x0000000000000000000000000000000000000000",
      ],
      note: "0xc0ffee",
      flag: true,
      small: "-5",
    },
  },
  {
    name: "fixed_bytes_and_negative_ints",
    note: "bytes32 is padded right, ints are two's complement padded left. Opposite directions, so a shared code path is a bug.",
    domain: {
      name: "Zunia",
      version: "1",
      chainId: 42161,
      verifyingContract: "0x0000000000000000000000000000000000000002",
    },
    types: {
      Sample: [
        { name: "hash", type: "bytes32" },
        { name: "short", type: "bytes4" },
        { name: "negative", type: "int256" },
        { name: "positive", type: "int256" },
        { name: "big", type: "uint128" },
      ],
    },
    value: {
      hash: "0x1111111111111111111111111111111111111111111111111111111111111111",
      short: "0xdeadbeef",
      negative: "-1",
      positive: "1",
      big: "340282366920938463463374607431768211455",
    },
  },
  {
    name: "minimal_domain",
    note: "A domain with only a name. Absent fields are omitted from EIP712Domain entirely, not zero-filled.",
    domain: { name: "Zunia" },
    types: {
      Ping: [{ name: "nonce", type: "uint256" }],
    },
    value: { nonce: "1" },
  },
];

const typedData = await Promise.all(
  typedCases.map(async ({ name, note, domain, types, value }) => {
    const encoder = TypedDataEncoder.from(types);
    const primaryType = encoder.primaryType;

    return {
      name,
      note,
      // The payload as a dApp would send it over the provider, which is what our parser has to
      // accept: types map including EIP712Domain, plus primaryType, domain and message.
      payload: {
        types: {
          EIP712Domain: TypedDataEncoder.from({
            EIP712Domain: domainFields(domain),
          }).types.EIP712Domain,
          ...types,
        },
        primaryType,
        domain,
        message: value,
      },
      primaryType,
      encodeType: encoder.encodeType(primaryType),
      typeHash: keccak256(
        toUtf8Bytes(encoder.encodeType(primaryType))
      ).slice(2),
      domainSeparator: TypedDataEncoder.hashDomain(domain).slice(2),
      hashStruct: encoder.hashStruct(primaryType, value).slice(2),
      // ethers' `encodeData` prepends the type hash, so it is `typeHash || encodeData` in the
      // specification's terms rather than `encodeData`. Named for what it contains, because the
      // mismatch with the EIP-712 vocabulary is a trap.
      typeHashAndEncodedData: encoder.encodeData(primaryType, value).slice(2),
      signingHash: TypedDataEncoder.hash(domain, types, value).slice(2),
      signature: (await wallet.signTypedData(domain, types, value)).slice(2),
      signerAddress: accounts[0].address,
    };
  })
);

function domainFields(domain) {
  // EIP-712 fixes the order of the domain fields; only the present ones appear.
  const order = [
    ["name", "string"],
    ["version", "string"],
    ["chainId", "uint256"],
    ["verifyingContract", "address"],
    ["salt", "bytes32"],
  ];
  return order
    .filter(([key]) => domain[key] !== undefined)
    .map(([name, type]) => ({ name, type }));
}

// ---------------------------------------------------------------------------
// Signature recovery, so the low-s and recovery-id conventions are pinned
// ---------------------------------------------------------------------------

// Half the curve order. Every signature ethers produces is low-s, because a high-s signature is
// malleable and some contracts reject it outright.
const HALF_N =
  0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;

const recovery = messages.map((message) => {
  const signature = Signature.from(`0x${message.signature}`);
  return {
    name: message.name,
    hash: message.hash,
    r: signature.r.slice(2),
    s: signature.s.slice(2),
    v: signature.v,
    yParity: signature.yParity,
    sIsLow: BigInt(signature.s) <= HALF_N,
    recoveredAddress: verifyMessage(message.message, `0x${message.signature}`),
  };
});

for (const entry of recovery) {
  if (!entry.sIsLow) {
    throw new Error(`ethers produced a high-s signature for ${entry.name}`);
  }
  if (entry.recoveredAddress !== accounts[0].address) {
    throw new Error(`recovery disagrees for ${entry.name}`);
  }
}

// ---------------------------------------------------------------------------

const output = {
  description:
    "Ethereum golden vectors generated with ethers v6. Asserted byte for byte by crates/evm/tests/golden_vectors.rs. Regenerate with pnpm generate:evm; a diff means our encoding changed and every signature we produce is suspect.",
  generator: "ethers v6",
  mnemonic: MNEMONIC,
  accounts,
  transactions,
  messages,
  typedData,
  recovery,
};

writeFileSync(OUT, `${JSON.stringify(output, null, 2)}\n`);
console.log(
  `wrote ${OUT}: ${transactions.length} transactions, ${messages.length} messages, ${typedData.length} typed-data cases`
);
