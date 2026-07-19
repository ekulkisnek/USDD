import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  ANNEX_MAGIC_HEX,
  BURN_ID_DOMAIN_HEX,
  BURN_LEAF_DOMAIN_HEX,
  DEPOSIT_ID_DOMAIN_HEX,
  EMPTY_BURN_ROOT_HEX,
  ENCODING_SCHEMA,
  MAX_BURN_AMOUNT_USDT6,
  MAX_DEPOSIT_AMOUNT_USDT6,
  MAX_MINT_BATCH_USDD8,
  MAX_MINT_BATCH_USDT6,
  annexMagicBytes,
  burnAccumulatorEmpty,
  burnId,
  burnIdDomainBytes,
  burnLeafDomainBytes,
  bytesToHex,
  computeBurnRoot,
  decodeBurn,
  decodeBurnAppend,
  decodeBurnProof,
  decodeBurnPayload,
  decodeDepositPublicOutput,
  decodeElementsStatePublicOutput,
  decodeElementsStateTransitionClaim,
  decodeEthereumDepositClaim,
  decodeEthereumFinalityWitness,
  decodeEthereumHeartbeatClaim,
  decodeHeartbeatPublicOutput,
  decodeMintControllerState,
  decodeSp1Annex,
  decodeStrictJournal,
  decodeTypedPublicValues,
  decodeVaultDeposit,
  depositIdDomainBytes,
  depositId,
  depositPreimage,
  emptyBurnRootBytes,
  encodeBurnBranch,
  encodeBurn,
  encodeBurnAppend,
  encodeBurnProof,
  encodeBurnPayload,
  encodeDepositPublicOutput,
  encodeElementsStatePublicOutput,
  encodeElementsStateTransitionClaim,
  encodeEthereumDepositClaim,
  encodeEthereumFinalityWitness,
  encodeEthereumHeartbeatClaim,
  encodeHeartbeatPublicOutput,
  encodeMintBatch,
  encodeMintControllerState,
  encodeSolidityElementsBridgeState,
  encodeSp1Annex,
  encodeStrictJournal,
  encodeVaultDeposit,
  hexToBytes,
  journalMagicBytes,
  journalSuccessBytes,
  sha256,
  solidityBurnLeaf,
} from "../src/index.ts";

const vectors = JSON.parse(
  readFileSync(new URL("../../specs/fixed-vectors.json", import.meta.url), "utf8"),
);

function claimPriorState() {
  return {
    version: 1,
    sequence: 4n,
    nextMintNonce: 7n,
    ethereumLightClientDigest: new Uint8Array(32).fill(1),
    finalizedBeaconSlot: 100n,
    finalizedBeaconRoot: new Uint8Array(32).fill(2),
    finalizedExecutionStateRoot: new Uint8Array(32).fill(3),
    totalMintedUSDDBase: 1_000n,
    configurationHash: new Uint8Array(32).fill(4),
  };
}

function claimFinality() {
  return {
    ethereumLightClientDigest: new Uint8Array(32).fill(5),
    finalizedBeaconSlot: 101n,
    finalizedBeaconRoot: new Uint8Array(32).fill(6),
    finalizedExecutionBlock: new Uint8Array(32).fill(7),
    finalizedExecutionStateRoot: new Uint8Array(32).fill(8),
    executionBlockNumber: 20_000_000n,
    executionBlockTimestamp: 1_700_000_000n,
  };
}

function claimDeposit(nonce: bigint) {
  return {
    chainId: 1n,
    vault: new Uint8Array(20).fill(0x11),
    usdt: new Uint8Array(20).fill(0x22),
    nonce,
    depositor: new Uint8Array(20).fill(0x33),
    amountUSDT6: 5n,
    elementsScript: Uint8Array.of(0x51),
    userSalt: new Uint8Array(32).fill(0x44),
  };
}

function zeroBridgeState() {
  return {
    sequence: 0n,
    burnCount: 0n,
    elementsTipHash: new Uint8Array(32),
    elementsConsensusStateDigest: new Uint8Array(32),
    cumulativeBurnRoot: new Uint8Array(32),
    finalizedBitcoinBlockHash: new Uint8Array(32),
    bitcoinHeight: 0n,
    elementsHeight: 0n,
    bitcoinMedianTimePast: 0n,
    bitcoinChainwork: new Uint8Array(32),
  };
}

function burnAppendFixture() {
  return {
    burn: {
      vaultId: new Uint8Array(32).fill(0x11),
      usddAsset: new Uint8Array(32).fill(0x22),
      amountUSDD8: 500n,
      amountUSDT6: 5n,
      burnOutpoint: {
        txid: new Uint8Array(32).fill(0x33),
        vout: 2,
      },
      ethereumDestination: new Uint8Array(20).fill(0x44),
    },
    emptyBranch: {
      siblings: Array.from({ length: 64 }, (_, height) =>
        new Uint8Array(32).fill(height),
      ),
    },
  };
}

test("Solidity deposit commitment vector", () => {
  const v = vectors.deposit;
  const deposit = {
    chainId: BigInt(v.chainId),
    vault: hexToBytes(v.vault),
    usdt: hexToBytes(v.usdt),
    nonce: BigInt(v.nonce),
    depositor: hexToBytes(v.depositor),
    amountUSDT6: BigInt(v.amount),
    elementsScript: hexToBytes(v.script),
    userSalt: hexToBytes(v.salt),
  };
  assert.equal(bytesToHex(sha256(deposit.elementsScript)), v.scriptHash);
  assert.equal(bytesToHex(depositPreimage(deposit)), v.preimage);
  assert.equal(bytesToHex(depositId(deposit)), v.depositId);
});

test("deposit validation matches the Rust u64 and nonzero rules", () => {
  const deposit = {
    chainId: 1n,
    vault: new Uint8Array(20).fill(1),
    usdt: new Uint8Array(20).fill(2),
    nonce: 0n,
    depositor: new Uint8Array(20).fill(3),
    amountUSDT6: 1n,
    elementsScript: Uint8Array.of(0x51),
    userSalt: new Uint8Array(32),
  };

  assert.doesNotThrow(() => depositPreimage(deposit));
  assert.doesNotThrow(() => depositPreimage({ ...deposit, chainId: (1n << 64n) - 1n }));
  assert.doesNotThrow(() =>
    depositPreimage({ ...deposit, amountUSDT6: MAX_DEPOSIT_AMOUNT_USDT6 }),
  );
  assert.throws(() => depositPreimage({ ...deposit, chainId: 1n << 64n }), /chain ID/);
  assert.throws(() => depositPreimage({ ...deposit, vault: new Uint8Array(20) }), /vault.*nonzero/);
  assert.throws(() => depositPreimage({ ...deposit, usdt: new Uint8Array(20) }), /USDT.*nonzero/);
  assert.throws(
    () => depositPreimage({ ...deposit, depositor: new Uint8Array(20) }),
    /depositor.*nonzero/,
  );
  assert.throws(() => depositPreimage({ ...deposit, nonce: 1n << 64n }), /nonce.*u64/);
  assert.throws(
    () => depositPreimage({ ...deposit, amountUSDT6: MAX_DEPOSIT_AMOUNT_USDT6 + 1n }),
    /vault limit/,
  );
  assert.throws(
    () =>
      depositPreimage({
        ...deposit,
        amountUSDT6: ((1n << 64n) - 1n) / 100n + 1n,
      }),
    /vault limit|checked USDT6-to-USDD8 conversion/,
  );
});

test("mint batches retain Elements transaction-wide explicit-value headroom", () => {
  const output = (nonce: bigint, amountUSDT6: bigint) => ({
    depositId: new Uint8Array(32).fill(Number(nonce) + 1),
    nonce,
    amountUSDT6,
    amountUSDD8: amountUSDT6 * 100n,
    elementsScript: Uint8Array.of(0x51),
  });
  const half = MAX_MINT_BATCH_USDT6 / 2n;
  const accepted = {
    firstNonce: 0n,
    nextNonce: 2n,
    outputs: [output(0n, half), output(1n, half)],
    totalAmountUSDT6: MAX_MINT_BATCH_USDT6,
    totalAmountUSDD8: MAX_MINT_BATCH_USDD8,
  };
  assert.doesNotThrow(() => encodeMintBatch(accepted));
  assert.throws(
    () =>
      encodeMintBatch({
        ...accepted,
        nextNonce: 3n,
        outputs: [...accepted.outputs, output(2n, 1n)],
        totalAmountUSDT6: MAX_MINT_BATCH_USDT6 + 1n,
        totalAmountUSDD8: MAX_MINT_BATCH_USDD8 + 100n,
      }),
    /explicit-output budget/,
  );
  assert.throws(
    () =>
      encodeMintBatch({
        firstNonce: 0n,
        nextNonce: 1n,
        outputs: [output(0n, 0n)],
        totalAmountUSDT6: 0n,
        totalAmountUSDD8: 0n,
      }),
    /positive u64/,
  );
});

test("burn payload, identity, and Solidity leaf vectors", () => {
  const v = vectors.burn;
  const id = burnId(hexToBytes(v.elementsGenesis), hexToBytes(v.txid), v.vout);
  assert.equal(bytesToHex(id), v.burnId);
  const payload = encodeBurnPayload({
    vaultId: hexToBytes(v.vaultId),
    ethereumRecipient: hexToBytes(v.recipient),
    amountUSDT6: BigInt(v.amount),
  });
  assert.equal(payload.length, 65);
  assert.equal(bytesToHex(payload), v.payload);
  assert.deepEqual(decodeBurnPayload(payload), {
    vaultId: hexToBytes(v.vaultId),
    ethereumRecipient: hexToBytes(v.recipient),
    amountUSDT6: BigInt(v.amount),
  });
  assert.equal(
    bytesToHex(
      solidityBurnLeaf({
        elementsGenesis: hexToBytes(v.elementsGenesis),
        usddAssetId: hexToBytes(v.asset),
        vaultId: hexToBytes(v.vaultId),
        burnTxidDisplay: hexToBytes(v.txid),
        burnVout: v.vout,
        burnId: id,
        burnIndex: BigInt(v.burnIndex),
        amountUSDT6: BigInt(v.amount),
        recipient: hexToBytes(v.recipient),
      }),
    ),
    v.burnLeaf,
  );

  const branch = Array.from({ length: 64 }, (_, height) =>
    burnAccumulatorEmpty(height),
  );
  assert.equal(bytesToHex(burnAccumulatorEmpty(64)), v.emptyRoot);
  assert.equal(bytesToHex(sha256(encodeBurnBranch(branch))), v.branchEncodingSha256);
  assert.equal(
    bytesToHex(computeBurnRoot(hexToBytes(v.burnLeaf), 0n, branch)),
    v.oneLeafRoot,
  );
  assert.throws(() => encodeBurnBranch(branch.slice(0, 63)), /exactly 64/);
  assert.throws(() => encodeBurnBranch([...branch, branch[0]]), /exactly 64/);
});

test("burn encoders reject zero identifiers, destinations, and amounts", () => {
  const v = vectors.burn;
  const payload = {
    vaultId: hexToBytes(v.vaultId),
    ethereumRecipient: hexToBytes(v.recipient),
    amountUSDT6: BigInt(v.amount),
  };
  assert.throws(() => encodeBurnPayload({ ...payload, vaultId: new Uint8Array(32) }), /vault ID.*nonzero/);
  assert.throws(
    () => encodeBurnPayload({ ...payload, ethereumRecipient: new Uint8Array(20) }),
    /Ethereum recipient.*nonzero/,
  );
  assert.throws(() => encodeBurnPayload({ ...payload, amountUSDT6: 0n }), /positive u64/);
  assert.doesNotThrow(() =>
    encodeBurnPayload({ ...payload, amountUSDT6: MAX_BURN_AMOUNT_USDT6 }),
  );
  assert.throws(
    () => encodeBurnPayload({ ...payload, amountUSDT6: MAX_BURN_AMOUNT_USDT6 + 1n }),
    /explicit-output limit/,
  );
  const invalidPayload = encodeBurnPayload(payload);
  invalidPayload.fill(0, 5, 37);
  assert.throws(() => decodeBurnPayload(invalidPayload), /vault ID.*nonzero/);
  assert.throws(
    () => burnId(hexToBytes(v.elementsGenesis), new Uint8Array(32), v.vout),
    /transaction ID.*nonzero/,
  );

  const validClaim = {
    elementsGenesis: hexToBytes(v.elementsGenesis),
    usddAssetId: hexToBytes(v.asset),
    vaultId: hexToBytes(v.vaultId),
    burnTxidDisplay: hexToBytes(v.txid),
    burnVout: v.vout,
    burnId: hexToBytes(v.burnId),
    burnIndex: BigInt(v.burnIndex),
    amountUSDT6: BigInt(v.amount),
    recipient: hexToBytes(v.recipient),
  };
  assert.throws(
    () => solidityBurnLeaf({ ...validClaim, usddAssetId: new Uint8Array(32) }),
    /USDD asset.*nonzero/,
  );
  assert.throws(() => solidityBurnLeaf({ ...validClaim, amountUSDT6: 0n }), /positive u64/);
  assert.throws(
    () => solidityBurnLeaf({ ...validClaim, recipient: new Uint8Array(20) }),
    /recipient.*nonzero/,
  );
});

test("exact 164-byte mint controller encoding", () => {
  const state = {
    version: 1,
    sequence: 2n,
    nextMintNonce: 3n,
    ethereumLightClientDigest: new Uint8Array(32).fill(0x11),
    finalizedBeaconSlot: 4n,
    finalizedBeaconRoot: new Uint8Array(32).fill(0x22),
    finalizedExecutionStateRoot: new Uint8Array(32).fill(0x33),
    totalMintedUSDDBase: 500n,
    configurationHash: new Uint8Array(32).fill(0x44),
  };
  const encoded = encodeMintControllerState(state);
  assert.equal(encoded.length, 164);
  assert.deepEqual(decodeMintControllerState(encoded), state);
  assert.throws(() => decodeMintControllerState(encoded.slice(0, 163)), /164/);
  const nonconvertible = encoded.slice();
  nonconvertible.fill(0, 124, 132);
  nonconvertible[131] = 5;
  assert.throws(() => decodeMintControllerState(nonconvertible), /nonconvertible minted total/);
});

test("controller codec enforces Rust state semantics", () => {
  const state = {
    version: 1,
    sequence: 2n,
    nextMintNonce: 3n,
    ethereumLightClientDigest: new Uint8Array(32).fill(0x11),
    finalizedBeaconSlot: 4n,
    finalizedBeaconRoot: new Uint8Array(32).fill(0x22),
    finalizedExecutionStateRoot: new Uint8Array(32).fill(0x33),
    totalMintedUSDDBase: 500n,
    configurationHash: new Uint8Array(32).fill(0x44),
  };
  assert.doesNotThrow(() => encodeMintControllerState(state));
  assert.throws(
    () => encodeMintControllerState({ ...state, totalMintedUSDDBase: 5n }),
    /nonconvertible minted total/,
  );
  assert.throws(
    () => encodeMintControllerState({ ...state, ethereumLightClientDigest: new Uint8Array(32) }),
    /light-client digest.*nonzero/,
  );
  assert.throws(
    () => encodeMintControllerState({ ...state, configurationHash: new Uint8Array(32) }),
    /configuration hash.*nonzero/,
  );
  assert.throws(
    () => encodeMintControllerState({ ...state, finalizedBeaconRoot: new Uint8Array(32) }),
    /zero finalized state commitment/,
  );

  const bootstrap = {
    ...state,
    sequence: 0n,
    finalizedBeaconSlot: 0n,
    finalizedBeaconRoot: new Uint8Array(32),
    finalizedExecutionStateRoot: new Uint8Array(32),
    totalMintedUSDDBase: 0n,
  };
  assert.doesNotThrow(() => encodeMintControllerState(bootstrap));
  assert.throws(
    () => encodeMintControllerState({ ...bootstrap, sequence: 1n }),
    /invalid bootstrap controller state/,
  );
});

test("exported consensus constants cannot mutate internal codec state", () => {
  const exportedCopies = [
    [depositIdDomainBytes, DEPOSIT_ID_DOMAIN_HEX],
    [burnLeafDomainBytes, BURN_LEAF_DOMAIN_HEX],
    [burnIdDomainBytes, BURN_ID_DOMAIN_HEX],
    [annexMagicBytes, ANNEX_MAGIC_HEX],
  ] as const;
  for (const [getBytes, expectedHex] of exportedCopies) {
    const first = getBytes();
    first.fill(0);
    assert.equal(bytesToHex(getBytes()), expectedHex);
  }

  const journalMagic = journalMagicBytes();
  journalMagic.fill(0);
  assert.equal(new TextDecoder().decode(journalMagicBytes()), "USDDJNL1");
  const success = journalSuccessBytes();
  success.fill(0);
  assert.equal(new TextDecoder().decode(journalSuccessBytes()), "SUCCESS!");
});

test("schema-2 Ethereum claim codecs exactly reject obsolete BMM-time layouts", () => {
  const deposit = claimDeposit(7n);
  const finality = claimFinality();
  const heartbeatClaim = {
    manifestId: new Uint8Array(32).fill(9),
    priorState: claimPriorState(),
    finality,
  };
  const depositClaim = {
    ...heartbeatClaim,
    deposits: [deposit],
  };

  const encodedDeposit = encodeVaultDeposit(deposit);
  assert.equal(encodedDeposit.length, 125);
  assert.equal(bytesToHex(encodedDeposit.slice(0, 4)), "00020101");
  assert.deepEqual(decodeVaultDeposit(encodedDeposit), deposit);
  assert.equal(encodeEthereumFinalityWitness(finality).length, 156);
  assert.deepEqual(decodeEthereumFinalityWitness(encodeEthereumFinalityWitness(finality)), finality);

  const encodedHeartbeat = encodeEthereumHeartbeatClaim(heartbeatClaim);
  const encodedClaim = encodeEthereumDepositClaim(depositClaim);
  assert.equal(encodedHeartbeat.length, 356);
  assert.equal(encodedClaim.length, 482);
  assert.equal(bytesToHex(encodedHeartbeat.slice(0, 4)), "00025105");
  assert.equal(bytesToHex(encodedClaim.slice(0, 4)), "00025101");
  assert.deepEqual(decodeEthereumHeartbeatClaim(encodedHeartbeat), heartbeatClaim);
  assert.deepEqual(decodeEthereumDepositClaim(encodedClaim), depositClaim);

  for (const [encoded, decode] of [
    [encodedHeartbeat, decodeEthereumHeartbeatClaim],
    [encodedClaim, decodeEthereumDepositClaim],
  ] as const) {
    const obsolete = encoded.slice();
    obsolete.set(Uint8Array.of(0, 1), 0);
    assert.throws(() => decode(obsolete), /schema/);
    // Schema 1 carried a caller-controlled BMM-parent MTP after these fields.
    // Schema 2 has no such field, so even an eight-byte suffix is trailing data.
    assert.throws(
      () => decode(Uint8Array.from([...encoded, ...new Uint8Array(8)])),
      /trailing bytes/,
    );
  }

  assert.throws(
    () =>
      encodeEthereumHeartbeatClaim({
        ...heartbeatClaim,
        finality: { ...finality, finalizedBeaconSlot: 0n },
      }),
    /positive u64/,
  );
  assert.throws(
    () =>
      encodeEthereumDepositClaim({
        ...depositClaim,
        deposits: [deposit, { ...deposit, nonce: 9n }],
      }),
    /not consecutive/,
  );
  assert.throws(
    () =>
      encodeEthereumDepositClaim({
        ...depositClaim,
        deposits: [deposit, { ...deposit, nonce: 8n, usdt: new Uint8Array(20).fill(0x55) }],
      }),
    /mixes chains, vaults, or tokens/,
  );
});

test("Ethereum deposit claims enforce the inclusive 64-deposit bound", () => {
  const deposits = Array.from({ length: 64 }, (_, offset) =>
    claimDeposit(7n + BigInt(offset)),
  );
  const claim = {
    manifestId: new Uint8Array(32).fill(9),
    priorState: claimPriorState(),
    finality: claimFinality(),
    deposits,
  };
  const encoded = encodeEthereumDepositClaim(claim);
  assert.equal(encoded[356], 64);
  assert.equal(decodeEthereumDepositClaim(encoded).deposits.length, 64);
  assert.throws(
    () => encodeEthereumDepositClaim({ ...claim, deposits: [...deposits, claimDeposit(71n)] }),
    /1\.\.64/,
  );
  const excessiveCount = encodeEthereumDepositClaim({ ...claim, deposits: [deposits[0]!] });
  excessiveCount[356] = 65;
  assert.throws(() => decodeEthereumDepositClaim(excessiveCount), /1\.\.64/);
});

test("BurnAppend is exact and Elements transition claims cap appends at 64", () => {
  const append = burnAppendFixture();
  const encodedBurn = encodeBurn(append.burn);
  const encodedProof = encodeBurnProof(append.emptyBranch);
  const encodedAppend = encodeBurnAppend(append);
  assert.equal(encodedBurn.length, 140);
  assert.equal(encodedProof.length, 2_048);
  assert.equal(encodedAppend.length, 2_192);
  assert.deepEqual(decodeBurn(encodedBurn), append.burn);
  assert.deepEqual(decodeBurnProof(encodedProof), append.emptyBranch);
  assert.deepEqual(decodeBurnAppend(encodedAppend), append);
  assert.throws(
    () => encodeBurnProof({ siblings: append.emptyBranch.siblings.slice(0, 63) }),
    /exactly 64/,
  );
  assert.throws(
    () => encodeBurn({ ...append.burn, amountUSDD8: 501n }),
    /exactly convertible/,
  );

  const obsoleteAppend = encodedAppend.slice();
  obsoleteAppend.set(Uint8Array.of(0, 1), 0);
  assert.throws(() => decodeBurnAppend(obsoleteAppend), /schema/);
  assert.throws(
    () => decodeBurnAppend(Uint8Array.from([...encodedAppend, 0])),
    /trailing bytes/,
  );

  const baseClaim = {
    manifestId: new Uint8Array(32).fill(0x55),
    priorBridgeStateHash: new Uint8Array(32),
    priorState: zeroBridgeState(),
    nextState: zeroBridgeState(),
    appendedBurns: [] as ReturnType<typeof burnAppendFixture>[],
  };
  const encodedBase = encodeElementsStateTransitionClaim(baseClaim);
  assert.equal(encodedBase.length, 477);
  assert.equal(bytesToHex(encodedBase.slice(0, 4)), "00025103");
  assert.deepEqual(decodeElementsStateTransitionClaim(encodedBase), baseClaim);

  const obsoleteClaim = encodedBase.slice();
  obsoleteClaim.set(Uint8Array.of(0, 1), 0);
  assert.throws(() => decodeElementsStateTransitionClaim(obsoleteClaim), /schema/);
  assert.throws(
    () =>
      decodeElementsStateTransitionClaim(
        Uint8Array.from([...encodedBase, ...new Uint8Array(8)]),
      ),
    /trailing bytes/,
  );

  const maxClaim = { ...baseClaim, appendedBurns: Array.from({ length: 64 }, () => append) };
  const encodedMax = encodeElementsStateTransitionClaim(maxClaim);
  assert.equal(encodedMax[476], 64);
  assert.equal(decodeElementsStateTransitionClaim(encodedMax).appendedBurns.length, 64);
  assert.throws(
    () =>
      encodeElementsStateTransitionClaim({
        ...baseClaim,
        appendedBurns: Array.from({ length: 65 }, () => append),
      }),
    /too many burns/,
  );
  const excessiveCount = encodedBase.slice();
  excessiveCount[476] = 65;
  assert.throws(() => decodeElementsStateTransitionClaim(excessiveCount), /too many burns/);
});

test("schema-2 heartbeat public values match the Rust fixed vector", () => {
  assert.equal(ENCODING_SCHEMA, 2);
  const payload = hexToBytes(vectors.journal.payload);
  const heartbeat = decodeHeartbeatPublicOutput(payload);
  assert.equal(heartbeat.finalizedExecutionBlockTimestamp, 1_700_000_000n);
  assert.equal(heartbeat.priorState.finalizedBeaconSlot, 100n);
  assert.equal(heartbeat.nextState.finalizedBeaconSlot, 101n);
  assert.equal(bytesToHex(encodeHeartbeatPublicOutput(heartbeat)), vectors.journal.payload);

  const typed = decodeTypedPublicValues(1, payload);
  assert.equal(typed.recordType, "heartbeat");
  assert.throws(
    () => decodeHeartbeatPublicOutput(Uint8Array.from([...payload, 0])),
    /trailing bytes/,
  );
  assert.throws(() => decodeTypedPublicValues(2, payload), /not allowed/);
  assert.throws(
    () =>
      encodeHeartbeatPublicOutput({
        ...heartbeat,
        nextState: {
          ...heartbeat.nextState,
          ethereumLightClientDigest: heartbeat.priorState.ethereumLightClientDigest,
        },
      }),
    /does not bind/,
  );
});

test("deposit public values exact-decode and bind the mint transition", () => {
  const configurationHash = new Uint8Array(32).fill(0x44);
  const priorState = {
    version: 1,
    sequence: 0n,
    nextMintNonce: 7n,
    ethereumLightClientDigest: new Uint8Array(32).fill(0x11),
    finalizedBeaconSlot: 100n,
    finalizedBeaconRoot: new Uint8Array(32).fill(0x22),
    finalizedExecutionStateRoot: new Uint8Array(32).fill(0x33),
    totalMintedUSDDBase: 1_000n,
    configurationHash,
  };
  const nextState = {
    ...priorState,
    sequence: 1n,
    nextMintNonce: 8n,
    ethereumLightClientDigest: new Uint8Array(32).fill(0x55),
    finalizedBeaconSlot: 101n,
    finalizedBeaconRoot: new Uint8Array(32).fill(0x66),
    finalizedExecutionStateRoot: new Uint8Array(32).fill(0x77),
    totalMintedUSDDBase: 1_500n,
  };
  const output = {
    manifestId: new Uint8Array(32).fill(0x88),
    claimId: new Uint8Array(32).fill(0x99),
    priorState,
    nextState,
    finalizedExecutionBlockTimestamp: 1_700_000_001n,
    mintBatch: {
      firstNonce: 7n,
      nextNonce: 8n,
      outputs: [
        {
          depositId: new Uint8Array(32).fill(0xaa),
          nonce: 7n,
          amountUSDT6: 5n,
          amountUSDD8: 500n,
          elementsScript: Uint8Array.of(0x51),
        },
      ],
      totalAmountUSDT6: 5n,
      totalAmountUSDD8: 500n,
    },
  };

  const encoded = encodeDepositPublicOutput(output);
  assert.equal(encoded.length, 506);
  assert.deepEqual(decodeDepositPublicOutput(encoded), output);
  assert.equal(decodeTypedPublicValues(1, encoded).recordType, "deposit");
  assert.throws(
    () => encodeDepositPublicOutput({ ...output, finalizedExecutionBlockTimestamp: 0n }),
    /positive u64/,
  );
  assert.throws(
    () => encodeDepositPublicOutput({ ...output, nextState: { ...nextState, sequence: 2n } }),
    /does not bind/,
  );
  assert.throws(
    () =>
      encodeDepositPublicOutput({
        ...output,
        nextState: {
          ...nextState,
          ethereumLightClientDigest: priorState.ethereumLightClientDigest,
        },
      }),
    /does not bind/,
  );
  const sameSlotState = {
    ...nextState,
    finalizedBeaconSlot: priorState.finalizedBeaconSlot,
    ethereumLightClientDigest: priorState.ethereumLightClientDigest,
    finalizedBeaconRoot: priorState.finalizedBeaconRoot,
    finalizedExecutionStateRoot: priorState.finalizedExecutionStateRoot,
  };
  assert.doesNotThrow(() =>
    encodeDepositPublicOutput({ ...output, nextState: sameSlotState }),
  );
  assert.throws(
    () =>
      encodeDepositPublicOutput({
        ...output,
        nextState: {
          ...sameSlotState,
          finalizedExecutionStateRoot: new Uint8Array(32).fill(0xab),
        },
      }),
    /does not bind/,
  );
  assert.throws(
    () => decodeDepositPublicOutput(Uint8Array.from([...encoded, 0])),
    /trailing bytes/,
  );
});

test("Elements-state public values include and advance the consensus-state digest", () => {
  const zeroState = {
    sequence: 0n,
    burnCount: 0n,
    elementsTipHash: new Uint8Array(32),
    elementsConsensusStateDigest: new Uint8Array(32),
    cumulativeBurnRoot: new Uint8Array(32),
    finalizedBitcoinBlockHash: new Uint8Array(32),
    bitcoinHeight: 0n,
    elementsHeight: 0n,
    bitcoinMedianTimePast: 0n,
    bitcoinChainwork: new Uint8Array(32),
  };
  const chainwork = new Uint8Array(32);
  chainwork[31] = 1;
  const nextState = {
    sequence: 1n,
    burnCount: 0n,
    elementsTipHash: new Uint8Array(32).fill(0x11),
    elementsConsensusStateDigest: new Uint8Array(32).fill(0x22),
    cumulativeBurnRoot: hexToBytes(EMPTY_BURN_ROOT_HEX),
    finalizedBitcoinBlockHash: new Uint8Array(32).fill(0x44),
    bitcoinHeight: 100n,
    elementsHeight: 10n,
    bitcoinMedianTimePast: 1_700_000_000n,
    bitcoinChainwork: chainwork,
  };
  const output = {
    manifestId: new Uint8Array(32).fill(0x55),
    claimId: new Uint8Array(32).fill(0x66),
    priorBridgeStateHash: new Uint8Array(32),
    nextBridgeStateHash: new Uint8Array(32).fill(0x77),
    verifierStatement: new Uint8Array(32).fill(0x88),
    priorState: zeroState,
    nextState,
  };

  assert.equal(encodeSolidityElementsBridgeState(nextState).length, 204);
  assert.deepEqual(emptyBurnRootBytes(), hexToBytes(EMPTY_BURN_ROOT_HEX));
  const mutableEmptyRoot = emptyBurnRootBytes();
  mutableEmptyRoot[0] ^= 0xff;
  assert.deepEqual(emptyBurnRootBytes(), hexToBytes(EMPTY_BURN_ROOT_HEX));
  assert.throws(
    () =>
      encodeSolidityElementsBridgeState({
        ...nextState,
        cumulativeBurnRoot: new Uint8Array(32).fill(0x33),
      }),
    /noncanonical empty burn root/,
  );
  const encoded = encodeElementsStatePublicOutput(output);
  assert.equal(encoded.length, 572);
  assert.deepEqual(decodeElementsStatePublicOutput(encoded), output);
  assert.equal(decodeTypedPublicValues(2, encoded).recordType, "elementsState");
  assert.throws(() => decodeTypedPublicValues(1, encoded), /not allowed/);
  assert.throws(
    () => decodeElementsStatePublicOutput(Uint8Array.from([...encoded, 0])),
    /trailing bytes/,
  );

  const nextChainwork = chainwork.slice();
  nextChainwork[31] = 2;
  const unchangedDigestSuccessor = {
    ...nextState,
    sequence: 2n,
    elementsTipHash: new Uint8Array(32).fill(0x99),
    finalizedBitcoinBlockHash: new Uint8Array(32).fill(0xaa),
    bitcoinHeight: 101n,
    elementsHeight: 11n,
    bitcoinMedianTimePast: 1_700_000_001n,
    bitcoinChainwork: nextChainwork,
  };
  assert.throws(
    () =>
      encodeElementsStatePublicOutput({
        ...output,
        priorBridgeStateHash: new Uint8Array(32).fill(0xbb),
        priorState: nextState,
        nextState: unchangedDigestSuccessor,
      }),
    /consensus state digest did not advance/,
  );

  const growthChainwork = nextChainwork.slice();
  growthChainwork[31] = 3;
  assert.throws(
    () =>
      encodeElementsStatePublicOutput({
        ...output,
        priorBridgeStateHash: new Uint8Array(32).fill(0xbb),
        priorState: nextState,
        nextState: {
          ...unchangedDigestSuccessor,
          burnCount: 65n,
          elementsConsensusStateDigest: new Uint8Array(32).fill(0xcc),
          cumulativeBurnRoot: new Uint8Array(32).fill(0xdd),
          bitcoinChainwork: growthChainwork,
        },
      }),
    /burn count growth exceeds 64/,
  );
});

test("strict journals reject arbitrary, trailing, and semantically invalid typed payloads", () => {
  const programId = new Uint8Array(32).fill(0x77);
  assert.throws(
    () => encodeStrictJournal({ statementKind: 1, programId, payload: Uint8Array.of(1, 2, 3, 4) }),
    /payload schema|canonical typed record/,
  );

  const heartbeatPayload = hexToBytes(vectors.journal.payload);
  assert.throws(
    () =>
      encodeStrictJournal({
        statementKind: 1,
        programId,
        payload: Uint8Array.from([...heartbeatPayload, 0]),
      }),
    /trailing bytes/,
  );

  // Preserve a valid envelope and digest while corrupting the typed heartbeat
  // timestamp. The journal decoder must still reject the semantic payload.
  const invalidTypedJournal = hexToBytes(vectors.journal.encoded);
  invalidTypedJournal.fill(0, invalidTypedJournal.length - 8);
  const invalidPayload = invalidTypedJournal.slice(88);
  invalidTypedJournal.set(sha256(invalidPayload), 52);
  assert.throws(() => decodeStrictJournal(invalidTypedJournal), /positive u64/);
});

test("strict journal and C++ annex vectors", () => {
  const journal = {
    statementKind: vectors.journal.statementKind as 1,
    programId: hexToBytes(vectors.journal.programId),
    payload: hexToBytes(vectors.journal.payload),
  };
  assert.equal(bytesToHex(encodeStrictJournal(journal)), vectors.journal.encoded);
  assert.deepEqual(decodeStrictJournal(hexToBytes(vectors.journal.encoded)), journal);
  assert.throws(
    () => encodeStrictJournal({ ...journal, statementKind: 3 as unknown as 1 }),
    /statement kind/,
  );

  const annex = {
    statementKind: vectors.annex.statementKind as 1,
    guestProgramId: hexToBytes(vectors.annex.guestProgramId),
    publicValues: hexToBytes(vectors.annex.publicValues),
    proof: hexToBytes(vectors.annex.proof),
  };
  assert.equal(bytesToHex(encodeSp1Annex(annex)), vectors.annex.encoded);
  assert.deepEqual(decodeSp1Annex(hexToBytes(vectors.annex.encoded)), annex);
});

test("alternate digest and trailing bytes fail closed", () => {
  const journal = hexToBytes(vectors.journal.encoded);
  journal[10] = 2;
  assert.throws(() => decodeStrictJournal(journal), /SHA-256/);

  const annex = hexToBytes(vectors.annex.encoded + "00");
  assert.throws(() => decodeSp1Annex(annex), /length/);

  const outboundKind = hexToBytes(vectors.annex.encoded);
  outboundKind[11] = 2;
  assert.throws(() => decodeSp1Annex(outboundKind), /statement/);
});
