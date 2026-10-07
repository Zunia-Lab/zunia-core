#!/usr/bin/env node
/**
 * Generates golden signing vectors with CosmJS.
 *
 * Per ADR-0004, CosmJS is the reference implementation for Cosmos encoding. The Rust kernel
 * must produce byte-identical sign bytes, and `tests/golden_vectors.rs` asserts that. A
 * mismatch is a release blocker: the failure mode is a signature that verifies against
 * nothing, which surfaces on chain as an opaque "unauthorized" rather than as an error the
 * user can act on.
 *
 * The Osmosis poolmanager swaps are not in cosmjs-types, so their messages come from osmojs
 * instead: its telescope-generated encoder for the protobuf, and its Amino converter for the
 * Amino document, which is what the Osmosis app signs with. Nothing about those two messages is
 * written by hand here, so the type URL, the Amino name, the field numbers and the Amino shape
 * the Rust side is asserted against are osmojs's. CosmJS still assembles both sign documents.
 *
 * No Amino value is written by hand for the other messages either. Each one is rebuilt from the
 * case's own protobuf bytes by the converter a CosmJS client registers for its type URL:
 * `@cosmjs/stargate`'s defaults, pinned to 0.32.3 (the version osmojs resolves), and osmojs's
 * wasm converter for `MsgExecuteContract`. A hand-typed expectation is how a vector ends up
 * asserting the implementation's own bug back at itself, and two did: a vote option written as
 * its name, and an IBC transfer without its empty `timeout_height`. The chain rejects both.
 *
 * Regenerate after any change to the message set or to a proto version pin:
 *
 *   cd tests/vectors/generate && pnpm install && pnpm generate
 *
 * Then review the diff. An unexpected byte change means either a CosmJS upgrade altered the
 * encoding, or the vector inputs changed. Both need a human to look.
 */

import { writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  DirectSecp256k1HdWallet,
  makeSignDoc as makeDirectSignDoc,
  makeSignBytes,
} from '@cosmjs/proto-signing';
import { makeSignDoc as makeAminoSignDoc, serializeSignDoc } from '@cosmjs/amino';
import { Bip39, EnglishMnemonic, Slip10, Slip10Curve, sha256, stringToPath } from '@cosmjs/crypto';
import { fromBech32, toBech32, toHex, toUtf8 } from '@cosmjs/encoding';
import { AminoTypes, createDefaultAminoConverters } from '@cosmjs/stargate';

import { TxBody, AuthInfo, SignerInfo, Fee } from 'cosmjs-types/cosmos/tx/v1beta1/tx.js';
import { SignMode } from 'cosmjs-types/cosmos/tx/signing/v1beta1/signing.js';
import { MsgSend } from 'cosmjs-types/cosmos/bank/v1beta1/tx.js';
import { MsgDelegate, MsgUndelegate, MsgBeginRedelegate } from 'cosmjs-types/cosmos/staking/v1beta1/tx.js';
import { MsgWithdrawDelegatorReward } from 'cosmjs-types/cosmos/distribution/v1beta1/tx.js';
import { MsgVote } from 'cosmjs-types/cosmos/gov/v1beta1/tx.js';
import { MsgTransfer } from 'cosmjs-types/ibc/applications/transfer/v1/tx.js';
import { MsgExecuteContract } from 'cosmjs-types/cosmwasm/wasm/v1/tx.js';
import { PubKey } from 'cosmjs-types/cosmos/crypto/secp256k1/keys.js';
import { Any } from 'cosmjs-types/google/protobuf/any.js';

import {
  MsgSwapExactAmountIn,
  MsgSplitRouteSwapExactAmountIn,
} from 'osmojs/osmosis/poolmanager/v1beta1/tx.js';
import { AminoConverter as PoolmanagerAmino } from 'osmojs/osmosis/poolmanager/v1beta1/tx.amino.js';
import { MsgExecuteContract as OsmojsExecuteContract } from 'osmojs/cosmwasm/wasm/v1/tx.js';
import { AminoConverter as WasmAmino } from 'osmojs/cosmwasm/wasm/v1/tx.amino.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const OSMOJS_VERSION = createRequire(import.meta.url)('osmojs/package.json').version;

// The all-abandon BIP-39 test mnemonic. Public, worthless, and the standard vector input.
const MNEMONIC = `${'abandon '.repeat(11)}about`;
const HD_PATH = "m/44'/118'/0'/0/0";
const CHAIN_ID = 'cosmoshub-4';
const ACCOUNT_NUMBER = 12345;
const SEQUENCE = 7;

const wallet = await DirectSecp256k1HdWallet.fromMnemonic(MNEMONIC, {
  prefix: 'cosmos',
  hdPaths: [stringToPath(HD_PATH)],
});
const [account] = await wallet.getAccounts();

const FROM = account.address;
const TO = 'cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz';
const { data: accountBytes } = fromBech32(FROM, 200);
const VALOPER = toBech32('cosmosvaloper', accountBytes, 200);
const VALOPER_DST = toBech32('cosmosvaloper', accountBytes, 200);
const SAFRO = toBech32('addr_safro', accountBytes, 200);

const FEE_AMOUNT = [{ denom: 'uatom', amount: '5000' }];
const GAS_LIMIT = 200000;

// Osmosis mainnet data, read from the chain and from its router (sqs.osmosis.zone) on
// 2026-10-06. Pool 3498 is a concentrated-liquidity pool and pool 3586 a balancer pool, both
// holding OSMO and the IBC token below; the router splits 9.95 OSMO 60/40 across them, the
// shape pinned here at 10 OSMO. Pool 1 is OSMO/ATOM, and 3586 holds ATOM too, which makes the
// two-hop route a real one. The sender is the test key's own osmo address.
const OSMO_SENDER = toBech32('osmo', accountBytes, 200);
const ATOM_ON_OSMOSIS = 'ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2';
const SWAP_OUT_DENOM = 'ibc/794C7D7F3B857713878A3A1927251FA6AC1EEE520424C1F6FAFE9BA26D476138';

// The Osmosis crosschain-swaps contract, a real one. wasmd derives every instantiated contract's
// address as 32 bytes; only an account is 20.
const XCS = 'osmo1uwk8xc6q0s6t5qcpr6rht3sczu6du83xq8pwxjua0hfj5hzcnh3sqxwvxs';
// The same 32 bytes under the hub's prefix: what a send to a contract, an interchain account or a
// DAO treasury carries.
const TO_32_BYTE = toBech32('cosmos', fromBech32(XCS, 200).data, 200);
// A CW721 collection. Any 32 bytes have a contract's shape; these are the signing harness's.
const CW721 = toBech32('osmo', sha256(toUtf8('cw721 test collection')), 200);
const NFT_RECIPIENT = toBech32('osmo', fromBech32(TO, 200).data, 200);

/**
 * A case built entirely by osmojs: the message through its `fromPartial` and `encode`, the Amino
 * `{type, value}` through the converter a CosmJS client registers for that type URL.
 */
function osmosisCase(name, Msg, value) {
  const message = Msg.fromPartial(value);
  const converter = PoolmanagerAmino[Msg.typeUrl];
  return {
    name,
    typeUrl: Msg.typeUrl,
    proto: Msg.encode(message).finish(),
    amino: { type: converter.aminoType, value: converter.toAmino(message) },
    memo: '',
  };
}

/**
 * Each case supplies the protobuf `Any`. Its Amino `{type, value}` is derived from those bytes
 * below, by `aminoOf`; the swaps carry osmojs's from `osmosisCase`.
 */
const cases = [
  {
    name: 'msg_send',
    typeUrl: '/cosmos.bank.v1beta1.MsgSend',
    proto: MsgSend.encode(MsgSend.fromPartial({
      fromAddress: FROM,
      toAddress: TO,
      amount: [{ denom: 'uatom', amount: '1000000' }],
    })).finish(),
    memo: '',
  },
  {
    name: 'msg_send_with_memo',
    typeUrl: '/cosmos.bank.v1beta1.MsgSend',
    proto: MsgSend.encode(MsgSend.fromPartial({
      fromAddress: FROM,
      toAddress: TO,
      amount: [{ denom: 'uatom', amount: '1' }],
    })).finish(),
    // Exchange deposit memos are the reason memo handling has to be exact.
    memo: 'deposit-id:1234567890',
  },
  {
    name: 'msg_delegate',
    typeUrl: '/cosmos.staking.v1beta1.MsgDelegate',
    proto: MsgDelegate.encode(MsgDelegate.fromPartial({
      delegatorAddress: FROM,
      validatorAddress: VALOPER,
      amount: { denom: 'uatom', amount: '5000000' },
    })).finish(),
    memo: '',
  },
  {
    name: 'msg_undelegate',
    typeUrl: '/cosmos.staking.v1beta1.MsgUndelegate',
    proto: MsgUndelegate.encode(MsgUndelegate.fromPartial({
      delegatorAddress: FROM,
      validatorAddress: VALOPER,
      amount: { denom: 'uatom', amount: '1000000' },
    })).finish(),
    memo: '',
  },
  {
    name: 'msg_begin_redelegate',
    typeUrl: '/cosmos.staking.v1beta1.MsgBeginRedelegate',
    proto: MsgBeginRedelegate.encode(MsgBeginRedelegate.fromPartial({
      delegatorAddress: FROM,
      validatorSrcAddress: VALOPER,
      validatorDstAddress: VALOPER_DST,
      amount: { denom: 'uatom', amount: '1000000' },
    })).finish(),
    memo: '',
  },
  {
    // Its Amino name is cosmos-sdk/MsgWithdrawDelegationReward: Delegation, not Delegator.
    name: 'msg_withdraw_delegator_reward',
    typeUrl: '/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward',
    proto: MsgWithdrawDelegatorReward.encode(MsgWithdrawDelegatorReward.fromPartial({
      delegatorAddress: FROM,
      validatorAddress: VALOPER,
    })).finish(),
    memo: '',
  },
  {
    name: 'msg_vote',
    typeUrl: '/cosmos.gov.v1beta1.MsgVote',
    proto: MsgVote.encode(MsgVote.fromPartial({
      proposalId: BigInt(848),
      voter: FROM,
      // VOTE_OPTION_NO_WITH_VETO. Amino writes the number as well, not the name.
      option: 4,
    })).finish(),
    memo: '',
  },
  {
    name: 'msg_transfer_no_timeout',
    typeUrl: '/ibc.applications.transfer.v1.MsgTransfer',
    proto: MsgTransfer.encode(MsgTransfer.fromPartial({
      sourcePort: 'transfer',
      sourceChannel: 'channel-141',
      token: { denom: 'uatom', amount: '1000000' },
      sender: FROM,
      receiver: SAFRO,
    })).finish(),
    memo: '',
  },
  {
    name: 'msg_transfer_with_timeout',
    typeUrl: '/ibc.applications.transfer.v1.MsgTransfer',
    proto: MsgTransfer.encode(MsgTransfer.fromPartial({
      sourcePort: 'transfer',
      sourceChannel: 'channel-141',
      token: { denom: 'uatom', amount: '1000000' },
      sender: FROM,
      receiver: SAFRO,
      timeoutHeight: { revisionNumber: BigInt(1), revisionHeight: BigInt(20000000) },
      timeoutTimestamp: BigInt('1700000000000000000'),
      memo: 'forward',
    })).finish(),
    memo: '',
  },
  {
    name: 'msg_execute_contract',
    typeUrl: '/cosmwasm.wasm.v1.MsgExecuteContract',
    proto: MsgExecuteContract.encode(MsgExecuteContract.fromPartial({
      sender: FROM,
      contract: TO,
      // Protobuf carries the contract message as raw bytes, Amino embeds it as parsed JSON.
      msg: new TextEncoder().encode(JSON.stringify({ swap: { offer: '100' } })),
      funds: [{ denom: 'uatom', amount: '100' }],
    })).finish(),
    memo: '',
  },
  osmosisCase('msg_swap_exact_amount_in', MsgSwapExactAmountIn, {
    sender: OSMO_SENDER,
    routes: [{ poolId: 3586n, tokenOutDenom: SWAP_OUT_DENOM }],
    tokenIn: { denom: 'uosmo', amount: '9950000' },
    tokenOutMinAmount: '350000',
  }),
  osmosisCase('msg_swap_exact_amount_in_multi_hop', MsgSwapExactAmountIn, {
    sender: OSMO_SENDER,
    // OSMO to ATOM through pool 1, then ATOM to the target through pool 3586.
    routes: [
      { poolId: 1n, tokenOutDenom: ATOM_ON_OSMOSIS },
      { poolId: 3586n, tokenOutDenom: SWAP_OUT_DENOM },
    ],
    tokenIn: { denom: 'uosmo', amount: '10000000' },
    tokenOutMinAmount: '340000',
  }),
  osmosisCase('msg_split_route_swap_exact_amount_in', MsgSplitRouteSwapExactAmountIn, {
    sender: OSMO_SENDER,
    routes: [
      { pools: [{ poolId: 3498n, tokenOutDenom: SWAP_OUT_DENOM }], tokenInAmount: '6000000' },
      { pools: [{ poolId: 3586n, tokenOutDenom: SWAP_OUT_DENOM }], tokenInAmount: '4000000' },
    ],
    tokenInDenom: 'uosmo',
    tokenOutMinAmount: '350000',
  }),
  {
    // & < > in a signed string. Go's encoding/json, which rebuilds the document the chain
    // verifies, writes them as & < >, and so does serializeSignDoc. Signed
    // unescaped, a memo like this one verifies against nothing.
    name: 'msg_send_memo_html',
    typeUrl: '/cosmos.bank.v1beta1.MsgSend',
    proto: MsgSend.encode(MsgSend.fromPartial({
      fromAddress: FROM,
      toAddress: TO,
      amount: [{ denom: 'uatom', amount: '1' }],
    })).finish(),
    memo: 'rent & food <3>',
  },
  {
    // A recipient that is not an account: 32 bytes under the sender's own prefix.
    name: 'msg_send_to_32_byte',
    typeUrl: '/cosmos.bank.v1beta1.MsgSend',
    proto: MsgSend.encode(MsgSend.fromPartial({
      fromAddress: FROM,
      toAddress: TO_32_BYTE,
      amount: [{ denom: 'uatom', amount: '1000000' }],
    })).finish(),
    memo: '',
  },
  {
    // A crosschain swap's recovery: a 32-byte contract and no coins attached, which Amino still
    // writes as "funds":[].
    name: 'msg_execute_contract_32_no_funds',
    typeUrl: '/cosmwasm.wasm.v1.MsgExecuteContract',
    proto: MsgExecuteContract.encode(MsgExecuteContract.fromPartial({
      sender: OSMO_SENDER,
      contract: XCS,
      msg: new TextEncoder().encode(JSON.stringify({ recover: {} })),
      funds: [],
    })).finish(),
    memo: '',
  },
  {
    // An NFT whose token id carries an &. Amino embeds the contract message as JSON, so the
    // escaping reaches inside it.
    name: 'msg_execute_contract_nft_html',
    typeUrl: '/cosmwasm.wasm.v1.MsgExecuteContract',
    proto: MsgExecuteContract.encode(MsgExecuteContract.fromPartial({
      sender: OSMO_SENDER,
      contract: CW721,
      msg: new TextEncoder().encode(
        JSON.stringify({ transfer_nft: { recipient: NFT_RECIPIENT, token_id: 'rock & roll' } }),
      ),
      funds: [],
    })).finish(),
    memo: '',
  },
  {
    // What a wallet sends: a timestamp and no height. Amino still writes "timeout_height":{}.
    name: 'msg_transfer_timestamp_only',
    typeUrl: '/ibc.applications.transfer.v1.MsgTransfer',
    proto: MsgTransfer.encode(MsgTransfer.fromPartial({
      sourcePort: 'transfer',
      sourceChannel: 'channel-141',
      token: { denom: 'uatom', amount: '1000000' },
      sender: FROM,
      receiver: OSMO_SENDER,
      timeoutTimestamp: BigInt('1791400000000000000'),
    })).finish(),
    memo: '',
  },
];

// The converter a CosmJS client registers for each type URL: @cosmjs/stargate's defaults, and
// osmojs's wasm converter for contract calls, which stargate does not register. Each reads the
// case's own protobuf bytes, so the Amino value describes exactly the message the Direct vector
// carries.
const aminoTypes = new AminoTypes(createDefaultAminoConverters());
const COSMJS_TYPES = Object.fromEntries(
  [
    MsgSend,
    MsgDelegate,
    MsgUndelegate,
    MsgBeginRedelegate,
    MsgWithdrawDelegatorReward,
    MsgVote,
    MsgTransfer,
  ].map((Msg) => [Msg.typeUrl, Msg]),
);

function aminoOf({ typeUrl, proto }) {
  if (typeUrl === MsgExecuteContract.typeUrl) {
    const converter = WasmAmino[typeUrl];
    return {
      type: converter.aminoType,
      value: converter.toAmino(OsmojsExecuteContract.decode(proto)),
    };
  }
  const Msg = COSMJS_TYPES[typeUrl];
  if (!Msg) {
    throw new Error(`${typeUrl}: no reference converter to derive the Amino value from`);
  }
  return aminoTypes.toAmino({ typeUrl, value: Msg.decode(proto) });
}

for (const testCase of cases) {
  testCase.amino ??= aminoOf(testCase);
}

const pubkeyAny = Any.fromPartial({
  typeUrl: '/cosmos.crypto.secp256k1.PubKey',
  value: PubKey.encode(PubKey.fromPartial({ key: account.pubkey })).finish(),
});

function directVector(testCase) {
  const bodyBytes = TxBody.encode(TxBody.fromPartial({
    messages: [Any.fromPartial({ typeUrl: testCase.typeUrl, value: testCase.proto })],
    memo: testCase.memo,
  })).finish();

  const authInfoBytes = AuthInfo.encode(AuthInfo.fromPartial({
    signerInfos: [SignerInfo.fromPartial({
      publicKey: pubkeyAny,
      modeInfo: { single: { mode: SignMode.SIGN_MODE_DIRECT } },
      sequence: BigInt(SEQUENCE),
    })],
    fee: Fee.fromPartial({ amount: FEE_AMOUNT, gasLimit: BigInt(GAS_LIMIT) }),
  })).finish();

  const signDoc = makeDirectSignDoc(bodyBytes, authInfoBytes, CHAIN_ID, ACCOUNT_NUMBER);
  return {
    msg_proto_hex: toHex(testCase.proto),
    body_bytes_hex: toHex(bodyBytes),
    auth_info_bytes_hex: toHex(authInfoBytes),
    sign_bytes_hex: toHex(makeSignBytes(signDoc)),
  };
}

function aminoVector(testCase) {
  const signDoc = makeAminoSignDoc(
    [testCase.amino],
    { amount: FEE_AMOUNT, gas: String(GAS_LIMIT) },
    CHAIN_ID,
    testCase.memo,
    ACCOUNT_NUMBER,
    SEQUENCE,
  );
  const bytes = serializeSignDoc(signDoc);
  return {
    sign_doc: new TextDecoder().decode(bytes),
    sign_bytes_hex: toHex(bytes),
  };
}

// ADR-36 arbitrary-message signing. Built by hand rather than through a helper so the fixed
// values the specification mandates are visible: empty chain id, zero account number and
// sequence, zero fee.
function adr36Vector(text) {
  const data = Buffer.from(text, 'utf8').toString('base64');
  const signDoc = {
    chain_id: '',
    account_number: '0',
    sequence: '0',
    fee: { gas: '0', amount: [] },
    msgs: [{ type: 'sign/MsgSignData', value: { signer: FROM, data } }],
    memo: '',
  };
  const bytes = serializeSignDoc(signDoc);
  return {
    message: text,
    data_base64: data,
    sign_doc: new TextDecoder().decode(bytes),
    sign_bytes_hex: toHex(bytes),
  };
}

const seed = await Bip39.mnemonicToSeed(new EnglishMnemonic(MNEMONIC));
const { privkey, chainCode } = Slip10.derivePath(
  Slip10Curve.Secp256k1,
  seed,
  stringToPath(HD_PATH),
);

const output = {
  _comment:
    'Generated by tests/vectors/generate/generate.mjs with CosmJS. Do not edit by hand. ' +
    'A byte change here means the reference encoding changed and needs review.',
  generated_with: {
    cosmjs: '0.33',
    osmojs: OSMOJS_VERSION,
    note:
      'ADR-0004 pins CosmJS as the reference for Cosmos encoding. The Osmosis poolmanager ' +
      'messages are encoded, and their Amino documents converted, by osmojs.',
  },
  key: {
    mnemonic: MNEMONIC,
    hd_path: HD_PATH,
    seed_hex: toHex(seed),
    privkey_hex: toHex(privkey),
    chain_code_hex: toHex(chainCode),
    pubkey_compressed_hex: toHex(account.pubkey),
    addresses: {
      cosmos: FROM,
      cosmosvaloper: VALOPER,
      addr_safro: SAFRO,
      osmo: toBech32('osmo', accountBytes, 200),
    },
  },
  signer: {
    chain_id: CHAIN_ID,
    account_number: ACCOUNT_NUMBER,
    sequence: SEQUENCE,
    fee: { amount: FEE_AMOUNT, gas: String(GAS_LIMIT) },
  },
  cases: cases.map((testCase) => ({
    name: testCase.name,
    type_url: testCase.typeUrl,
    amino_type: testCase.amino.type,
    memo: testCase.memo,
    direct: directVector(testCase),
    amino: aminoVector(testCase),
  })),
  adr36: [
    adr36Vector('Sign in to Zunia at 2026-08-31T12:00:00Z'),
    adr36Vector(''),
    adr36Vector('unicode 안녕 مرحبا 🔐 and html <b>&amp;</b>'),
  ],
};

const target = join(HERE, '..', 'cosmos-signing.json');
writeFileSync(target, `${JSON.stringify(output, null, 2)}\n`);
console.log(`wrote ${target}`);
console.log(`${output.cases.length} signing cases, ${output.adr36.length} ADR-36 cases`);
