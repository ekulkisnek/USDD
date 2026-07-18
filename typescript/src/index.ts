import { createHash } from "node:crypto";

export const DEPOSIT_ID_DOMAIN = hexToBytes(
  "c0bb4b992ddfe42d70536346a594fd9750dbf7e10534ed34aecdc78d203b88e0",
);
export const BURN_LEAF_DOMAIN = hexToBytes(
  "b15e96910e56013406f4167f79c8b6e369c3abf0b409d50a63e99e095b25fb94",
);
export const BURN_ID_DOMAIN = hexToBytes(
  "5811f3ff8b8f31fb49ffb91afab13197c3d72e926549ae29dbda46c6998a3e45",
);

export const JOURNAL_MAGIC = new TextEncoder().encode("USDDJNL1");
export const JOURNAL_SUCCESS = new TextEncoder().encode("SUCCESS!");
export const ANNEX_MAGIC = Uint8Array.from([85, 83, 68, 68, 83, 80, 49, 0]);
export const ANNEX_HEADER_SIZE = 55;
export const ANNEX_MAX_SIZE = 512 * 1024;
export const PUBLIC_VALUES_MAX_SIZE = 16 * 1024;

export interface VaultDeposit {
  chainId: bigint;
  vault: Uint8Array;
  usdt: Uint8Array;
  nonce: bigint;
  depositor: Uint8Array;
  amountUSDT6: bigint;
  elementsScript: Uint8Array;
  userSalt: Uint8Array;
}

export function depositPreimage(value: VaultDeposit): Uint8Array {
  assertLength(value.vault, 20, "vault");
  assertLength(value.usdt, 20, "USDT");
  assertLength(value.depositor, 20, "depositor");
  assertLength(value.userSalt, 32, "user salt");
  if (value.chainId <= 0n || value.chainId >= 1n << 256n) throw new Error("chain ID");
  if (value.nonce < 0n || value.nonce >= 1n << 64n) throw new Error("nonce");
  if (value.amountUSDT6 <= 0n || value.amountUSDT6 >= 1n << 64n) throw new Error("amount");
  if (value.elementsScript.length === 0 || value.elementsScript.length > 128) {
    throw new Error("Elements script length");
  }
  return concat(
    DEPOSIT_ID_DOMAIN,
    u32be(1),
    uintBe(value.chainId, 32),
    value.vault,
    value.usdt,
    u64be(value.nonce),
    value.depositor,
    u64be(value.amountUSDT6),
    sha256(value.elementsScript),
    value.userSalt,
  );
}

export function depositId(value: VaultDeposit): Uint8Array {
  return sha256(depositPreimage(value));
}

export interface BurnPayload {
  vaultId: Uint8Array;
  ethereumRecipient: Uint8Array;
  amountUSDT6: bigint;
}

export function encodeBurnPayload(value: BurnPayload): Uint8Array {
  assertLength(value.vaultId, 32, "vault ID");
  assertLength(value.ethereumRecipient, 20, "Ethereum recipient");
  if (value.amountUSDT6 <= 0n || value.amountUSDT6 >= 1n << 64n) throw new Error("amount");
  const encoded = concat(
    new TextEncoder().encode("USDD"),
    Uint8Array.of(1),
    value.vaultId,
    value.ethereumRecipient,
    u64be(value.amountUSDT6),
  );
  if (encoded.length !== 65) throw new Error("internal burn payload length");
  return encoded;
}

export function decodeBurnPayload(bytes: Uint8Array): BurnPayload {
  if (bytes.length !== 65 || bytesToHex(bytes.slice(0, 4)) !== "55534444" || bytes[4] !== 1) {
    throw new Error("noncanonical burn payload");
  }
  const value = {
    vaultId: bytes.slice(5, 37),
    ethereumRecipient: bytes.slice(37, 57),
    amountUSDT6: readUintBe(bytes.slice(57, 65)),
  };
  encodeBurnPayload(value);
  return value;
}

export function burnId(elementsGenesis: Uint8Array, txidDisplayBytes: Uint8Array, vout: number): Uint8Array {
  assertLength(elementsGenesis, 32, "Elements genesis");
  assertLength(txidDisplayBytes, 32, "transaction ID");
  return sha256(concat(BURN_ID_DOMAIN, elementsGenesis, txidDisplayBytes, u32be(vout)));
}

export interface SolidityBurnClaim {
  elementsGenesis: Uint8Array;
  usddAssetId: Uint8Array;
  vaultId: Uint8Array;
  burnTxidDisplay: Uint8Array;
  burnVout: number;
  burnId: Uint8Array;
  burnIndex: bigint;
  amountUSDT6: bigint;
  recipient: Uint8Array;
}

export function solidityBurnLeaf(value: SolidityBurnClaim): Uint8Array {
  for (const [name, bytes] of [
    ["Elements genesis", value.elementsGenesis],
    ["USDD asset", value.usddAssetId],
    ["vault ID", value.vaultId],
    ["burn ID", value.burnId],
  ] as const) assertLength(bytes, 32, name);
  assertLength(value.burnTxidDisplay, 32, "burn txid display bytes");
  if (
    bytesToHex(burnId(value.elementsGenesis, value.burnTxidDisplay, value.burnVout)) !==
    bytesToHex(value.burnId)
  ) {
    throw new Error("burn ID does not bind outpoint");
  }
  assertLength(value.recipient, 20, "recipient");
  return sha256(
    concat(
      Uint8Array.of(0),
      BURN_LEAF_DOMAIN,
      u32be(1),
      value.elementsGenesis,
      value.usddAssetId,
      value.vaultId,
      value.burnId,
      u64be(value.burnIndex),
      u64be(value.amountUSDT6),
      value.recipient,
    ),
  );
}

/** Empty subtree commitment for the fixed-depth (64) redemption accumulator. */
export function burnAccumulatorEmpty(height: number): Uint8Array {
  if (!Number.isInteger(height) || height < 0 || height > 64) {
    throw new Error("burn accumulator height");
  }
  let value = sha256(Uint8Array.of(0));
  for (let level = 0; level < height; level += 1) {
    value = burnAccumulatorNode(value, value);
  }
  return value;
}

export function burnAccumulatorNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  assertLength(left, 32, "left burn node");
  assertLength(right, 32, "right burn node");
  return sha256(concat(Uint8Array.of(1), left, right));
}

/** Canonical branch encoding: exactly 64 siblings, bottom-up, with no length prefix. */
export function encodeBurnBranch(branch: readonly Uint8Array[]): Uint8Array {
  if (branch.length !== 64) throw new Error("burn proof must contain exactly 64 siblings");
  for (const sibling of branch) assertLength(sibling, 32, "burn sibling");
  return concat(...branch);
}

export function computeBurnRoot(
  leaf: Uint8Array,
  index: bigint,
  branch: readonly Uint8Array[],
): Uint8Array {
  assertLength(leaf, 32, "burn leaf");
  if (index < 0n || index >= 1n << 64n) throw new Error("burn index");
  encodeBurnBranch(branch);
  let value = leaf;
  let path = index;
  for (const sibling of branch) {
    value = (path & 1n) === 0n
      ? burnAccumulatorNode(value, sibling)
      : burnAccumulatorNode(sibling, value);
    path >>= 1n;
  }
  return value;
}

export interface MintControllerState {
  version: number;
  sequence: bigint;
  nextMintNonce: bigint;
  ethereumLightClientDigest: Uint8Array;
  finalizedBeaconSlot: bigint;
  finalizedBeaconRoot: Uint8Array;
  finalizedExecutionStateRoot: Uint8Array;
  totalMintedUSDDBase: bigint;
  configurationHash: Uint8Array;
}

/** Exact 164-byte consensus encoding; unlike other records it has no schema/tag prefix. */
export function encodeMintControllerState(value: MintControllerState): Uint8Array {
  if (value.version !== 1) throw new Error("controller version");
  for (const [name, bytes] of [
    ["Ethereum light-client digest", value.ethereumLightClientDigest],
    ["finalized beacon root", value.finalizedBeaconRoot],
    ["finalized execution state root", value.finalizedExecutionStateRoot],
    ["configuration hash", value.configurationHash],
  ] as const) assertLength(bytes, 32, name);
  const encoded = concat(
    u32be(value.version),
    u64be(value.sequence),
    u64be(value.nextMintNonce),
    value.ethereumLightClientDigest,
    u64be(value.finalizedBeaconSlot),
    value.finalizedBeaconRoot,
    value.finalizedExecutionStateRoot,
    u64be(value.totalMintedUSDDBase),
    value.configurationHash,
  );
  if (encoded.length !== 164) throw new Error("internal controller encoding length");
  return encoded;
}

export function decodeMintControllerState(bytes: Uint8Array): MintControllerState {
  if (bytes.length !== 164) throw new Error("controller state must be exactly 164 bytes");
  const value: MintControllerState = {
    version: Number(readUintBe(bytes.slice(0, 4))),
    sequence: readUintBe(bytes.slice(4, 12)),
    nextMintNonce: readUintBe(bytes.slice(12, 20)),
    ethereumLightClientDigest: bytes.slice(20, 52),
    finalizedBeaconSlot: readUintBe(bytes.slice(52, 60)),
    finalizedBeaconRoot: bytes.slice(60, 92),
    finalizedExecutionStateRoot: bytes.slice(92, 124),
    totalMintedUSDDBase: readUintBe(bytes.slice(124, 132)),
    configurationHash: bytes.slice(132, 164),
  };
  if (bytesToHex(encodeMintControllerState(value)) !== bytesToHex(bytes)) {
    throw new Error("noncanonical controller state");
  }
  return value;
}

export interface StrictJournal {
  statementKind: 1 | 2;
  programId: Uint8Array;
  payload: Uint8Array;
}

export function encodeStrictJournal(value: StrictJournal): Uint8Array {
  assertLength(value.programId, 32, "program ID");
  if (value.statementKind !== 1 && value.statementKind !== 2) throw new Error("statement kind");
  if (isZero(value.programId) || value.payload.length === 0) throw new Error("empty journal field");
  return concat(
    JOURNAL_MAGIC,
    u16be(1),
    Uint8Array.of(1),
    JOURNAL_SUCCESS,
    Uint8Array.of(value.statementKind),
    value.programId,
    sha256(value.payload),
    u32be(value.payload.length),
    value.payload,
  );
}

export function decodeStrictJournal(bytes: Uint8Array): StrictJournal {
  if (bytes.length < 88) throw new Error("truncated journal");
  if (bytesToHex(bytes.slice(0, 8)) !== bytesToHex(JOURNAL_MAGIC)) throw new Error("journal magic");
  if (readUintBe(bytes.slice(8, 10)) !== 1n) throw new Error("journal schema");
  if (bytes[10] !== 1) throw new Error("SHA-256 required");
  if (bytesToHex(bytes.slice(11, 19)) !== bytesToHex(JOURNAL_SUCCESS)) throw new Error("success marker");
  if (bytes[19] !== 1 && bytes[19] !== 2) throw new Error("statement kind");
  const programId = bytes.slice(20, 52);
  if (isZero(programId)) throw new Error("zero program ID");
  const digest = bytes.slice(52, 84);
  const length = Number(readUintBe(bytes.slice(84, 88)));
  if (length === 0 || 88 + length !== bytes.length) throw new Error("journal length/trailing bytes");
  const payload = bytes.slice(88);
  if (bytesToHex(sha256(payload)) !== bytesToHex(digest)) throw new Error("payload digest");
  const value = { statementKind: bytes[19] as 1 | 2, programId, payload };
  if (bytesToHex(encodeStrictJournal(value)) !== bytesToHex(bytes)) throw new Error("noncanonical journal");
  return value;
}

export interface Sp1Annex {
  statementKind: 1 | 2;
  guestVkeyHash: Uint8Array;
  publicValues: Uint8Array;
  proof: Uint8Array;
}

export function encodeSp1Annex(value: Sp1Annex): Uint8Array {
  if (value.statementKind !== 1) throw new Error("Elements annex supports ETH_STATE_V1 only");
  assertLength(value.guestVkeyHash, 32, "guest vkey hash");
  if (isZero(value.guestVkeyHash)) throw new Error("zero guest vkey");
  if (value.publicValues.length === 0 || value.publicValues.length > PUBLIC_VALUES_MAX_SIZE) {
    throw new Error("public values length");
  }
  if (value.proof.length === 0) throw new Error("empty proof");
  const bytes = concat(
    Uint8Array.of(0x50),
    ANNEX_MAGIC,
    Uint8Array.of(1, 1, value.statementKind, 1),
    u16be(0),
    u32be(value.publicValues.length),
    u32be(value.proof.length),
    value.guestVkeyHash,
    value.publicValues,
    value.proof,
  );
  if (bytes.length > ANNEX_MAX_SIZE) throw new Error("annex too large");
  return bytes;
}

export function decodeSp1Annex(bytes: Uint8Array): Sp1Annex {
  if (bytes.length < ANNEX_HEADER_SIZE || bytes.length > ANNEX_MAX_SIZE) throw new Error("annex size");
  if (bytes[0] !== 0x50 || bytesToHex(bytes.slice(1, 9)) !== bytesToHex(ANNEX_MAGIC)) throw new Error("annex magic");
  if (bytes[9] !== 1 || bytes[10] !== 1) throw new Error("annex version/system");
  if (bytes[11] !== 1) throw new Error("annex statement");
  if (bytes[12] !== 1) throw new Error("annex SHA-256 mode");
  if (bytes[13] !== 0 || bytes[14] !== 0) throw new Error("annex flags");
  const publicLength = Number(readUintBe(bytes.slice(15, 19)));
  const proofLength = Number(readUintBe(bytes.slice(19, 23)));
  if (ANNEX_HEADER_SIZE + publicLength + proofLength !== bytes.length) throw new Error("annex length/trailing bytes");
  const value = {
    statementKind: bytes[11] as 1 | 2,
    guestVkeyHash: bytes.slice(23, 55),
    publicValues: bytes.slice(55, 55 + publicLength),
    proof: bytes.slice(55 + publicLength),
  };
  if (bytesToHex(encodeSp1Annex(value)) !== bytesToHex(bytes)) throw new Error("noncanonical annex");
  const journal = decodeStrictJournal(value.publicValues);
  if (journal.statementKind !== value.statementKind || bytesToHex(journal.programId) !== bytesToHex(value.guestVkeyHash)) {
    throw new Error("annex/journal mismatch");
  }
  return value;
}

export function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

export function hexToBytes(value: string): Uint8Array {
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error("invalid hex");
  return Uint8Array.from(hex.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

export function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function concat(...values: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

function uintBe(value: bigint, width: number): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(width * 8)) throw new Error("integer overflow");
  const output = new Uint8Array(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    output[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return output;
}

function u16be(value: number): Uint8Array {
  return uintBe(BigInt(value), 2);
}

function u32be(value: number): Uint8Array {
  return uintBe(BigInt(value), 4);
}

function u64be(value: bigint): Uint8Array {
  return uintBe(value, 8);
}

function readUintBe(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function assertLength(bytes: Uint8Array, length: number, name: string): void {
  if (bytes.length !== length) throw new Error(`${name} must be ${length} bytes`);
}

function isZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}
