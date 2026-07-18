import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  burnAccumulatorEmpty,
  burnId,
  bytesToHex,
  computeBurnRoot,
  decodeBurnPayload,
  decodeMintControllerState,
  decodeSp1Annex,
  decodeStrictJournal,
  depositId,
  depositPreimage,
  encodeBurnBranch,
  encodeBurnPayload,
  encodeMintControllerState,
  encodeSp1Annex,
  encodeStrictJournal,
  hexToBytes,
  sha256,
  solidityBurnLeaf,
} from "../src/index.ts";

const vectors = JSON.parse(
  readFileSync(new URL("../../specs/fixed-vectors.json", import.meta.url), "utf8"),
);

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

test("exact 164-byte mint controller encoding", () => {
  const state = {
    version: 1,
    sequence: 2n,
    nextMintNonce: 3n,
    ethereumLightClientDigest: new Uint8Array(32).fill(0x11),
    finalizedBeaconSlot: 4n,
    finalizedBeaconRoot: new Uint8Array(32).fill(0x22),
    finalizedExecutionStateRoot: new Uint8Array(32).fill(0x33),
    totalMintedUSDDBase: 5n,
    configurationHash: new Uint8Array(32).fill(0x44),
  };
  const encoded = encodeMintControllerState(state);
  assert.equal(encoded.length, 164);
  assert.deepEqual(decodeMintControllerState(encoded), state);
  assert.throws(() => decodeMintControllerState(encoded.slice(0, 163)), /164/);
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
    guestVkeyHash: hexToBytes(vectors.annex.guestVkeyHash),
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
