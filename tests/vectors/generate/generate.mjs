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
 * Regenerate after any change to the message set or to a proto version pin:
 *
 *   cd tests/vectors/generate && pnpm install && pnpm generate
 *
 * Then review the diff. An unexpected byte change means either a CosmJS upgrade altered the
 * encoding, or the vector inputs changed. Both need a human to look.
 */

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  DirectSecp256k1HdWallet,
  makeSignDoc as makeDirectSignDoc,
  makeSignBytes,
} from '@cosmjs/proto-signing';
import { makeSignDoc as makeAminoSignDoc, serializeSignDoc } from '@cosmjs/amino';
import { Bip39, EnglishMnemonic, Slip10, Slip10Curve, stringToPath } from '@cosmjs/crypto';
import { fromBech32, toBech32, toHex } from '@cosmjs/encoding';

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

const HERE = dirname(fileURLToPath(import.meta.url));

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

/** Each case supplies the protobuf `Any` and the equivalent Amino `{type, value}`. */
const cases = [
  {
    name: 'msg_send',
    typeUrl: '/cosmos.bank.v1beta1.MsgSend',
    proto: MsgSend.encode(MsgSend.fromPartial({
      fromAddress: FROM,
      toAddress: TO,
      amount: [{ denom: 'uatom', amount: '1000000' }],
    })).finish(),
    amino: {
      type: 'cosmos-sdk/MsgSend',
      value: {
        from_address: FROM,
        to_address: TO,
        amount: [{ denom: 'uatom', amount: '1000000' }],
      },
    },
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
    amino: {
      type: 'cosmos-sdk/MsgSend',
      value: {
        from_address: FROM,
        to_address: TO,
        amount: [{ denom: 'uatom', amount: '1' }],
      },
    },
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
    amino: {
      type: 'cosmos-sdk/MsgDelegate',
      value: {
        delegator_address: FROM,
        validator_address: VALOPER,
        amount: { denom: 'uatom', amount: '5000000' },
      },
    },
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
    amino: {
      type: 'cosmos-sdk/MsgUndelegate',
      value: {
        delegator_address: FROM,
        validator_address: VALOPER,
        amount: { denom: 'uatom', amount: '1000000' },
      },
    },
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
    amino: {
      type: 'cosmos-sdk/MsgBeginRedelegate',
      value: {
        delegator_address: FROM,
        validator_src_address: VALOPER,
        validator_dst_address: VALOPER_DST,
        amount: { denom: 'uatom', amount: '1000000' },
      },
    },
    memo: '',
  },
  {
    name: 'msg_withdraw_delegator_reward',
    typeUrl: '/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward',
    proto: MsgWithdrawDelegatorReward.encode(MsgWithdrawDelegatorReward.fromPartial({
      delegatorAddress: FROM,
      validatorAddress: VALOPER,
    })).finish(),
    amino: {
      // Delegation, not Delegator. The Amino registry name differs from the proto name.
      type: 'cosmos-sdk/MsgWithdrawDelegationReward',
      value: { delegator_address: FROM, validator_address: VALOPER },
    },
    memo: '',
  },
  {
    name: 'msg_vote',
    typeUrl: '/cosmos.gov.v1beta1.MsgVote',
    proto: MsgVote.encode(MsgVote.fromPartial({
      proposalId: BigInt(848),
      voter: FROM,
      option: 4, // VOTE_OPTION_NO_WITH_VETO
    })).finish(),
    amino: {
      type: 'cosmos-sdk/MsgVote',
      value: { proposal_id: '848', voter: FROM, option: 'VOTE_OPTION_NO_WITH_VETO' },
    },
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
    amino: {
      type: 'cosmos-sdk/MsgTransfer',
      value: {
        source_port: 'transfer',
        source_channel: 'channel-141',
        token: { denom: 'uatom', amount: '1000000' },
        sender: FROM,
        receiver: SAFRO,
      },
    },
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
    amino: {
      type: 'cosmos-sdk/MsgTransfer',
      value: {
        source_port: 'transfer',
        source_channel: 'channel-141',
        token: { denom: 'uatom', amount: '1000000' },
        sender: FROM,
        receiver: SAFRO,
        timeout_height: { revision_number: '1', revision_height: '20000000' },
        timeout_timestamp: '1700000000000000000',
        memo: 'forward',
      },
    },
    memo: '',
  },
  {
    name: 'msg_execute_contract',
    typeUrl: '/cosmwasm.wasm.v1.MsgExecuteContract',
    proto: MsgExecuteContract.encode(MsgExecuteContract.fromPartial({
      sender: FROM,
      contract: TO,
      msg: new TextEncoder().encode(JSON.stringify({ swap: { offer: '100' } })),
      funds: [{ denom: 'uatom', amount: '100' }],
    })).finish(),
    amino: {
      type: 'wasm/MsgExecuteContract',
      value: {
        sender: FROM,
        contract: TO,
        // Amino embeds the contract message as parsed JSON, protobuf as raw bytes.
        msg: { swap: { offer: '100' } },
        funds: [{ denom: 'uatom', amount: '100' }],
      },
    },
    memo: '',
  },
];

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
    note: 'ADR-0004 pins CosmJS as the reference for Cosmos encoding.',
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
