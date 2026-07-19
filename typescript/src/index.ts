import { createHash } from "node:crypto";

export const DEPOSIT_ID_DOMAIN_HEX =
  "c0bb4b992ddfe42d70536346a594fd9750dbf7e10534ed34aecdc78d203b88e0";
export const BURN_LEAF_DOMAIN_HEX =
  "b15e96910e56013406f4167f79c8b6e369c3abf0b409d50a63e99e095b25fb94";
export const BURN_ID_DOMAIN_HEX =
  "5811f3ff8b8f31fb49ffb91afab13197c3d72e926549ae29dbda46c6998a3e45";
export const EMPTY_BURN_ROOT_HEX =
  "c13fcc5e95b202155d131894da01dff87c8ac722937c76415daab46e53ed40db";
export const JOURNAL_MAGIC_ASCII = "USDDJNL1";
export const JOURNAL_SUCCESS_ASCII = "SUCCESS!";
export const ANNEX_MAGIC_HEX = "5553444453503100";
export const ANNEX_HEADER_SIZE = 55;
export const ANNEX_MAX_SIZE = 512 * 1024;
export const PUBLIC_VALUES_MAX_SIZE = 16 * 1024;
export const ENCODING_SCHEMA = 2;

const U64_LIMIT = 1n << 64n;
const U64_MAX = U64_LIMIT - 1n;
const USDD_UNITS_PER_USDT_MICRO = 100n;
export const ELEMENTS_MAX_EXPLICIT_OUTPUT_TOTAL_BASE = 21_000_000n * 100_000_000n;
export const MAX_MINT_BATCH_USDD8 = 20_000_000n * 100_000_000n;
export const MAX_MINT_BATCH_USDT6 = MAX_MINT_BATCH_USDD8 / USDD_UNITS_PER_USDT_MICRO;
export const MAX_DEPOSIT_AMOUNT_USDT6 = MAX_MINT_BATCH_USDT6;
export const MAX_BURN_AMOUNT_USDT6 = MAX_MINT_BATCH_USDT6;
const MAX_ETHEREUM_FINALITY_SLOT_GAP = 4_096n;
const TAG_VAULT_DEPOSIT = 0x0101;
const TAG_ETHEREUM_FINALITY = 0x0102;
const TAG_MINT_OUTPUT = 0x0103;
const TAG_MINT_BATCH = 0x0104;
const TAG_BURN = 0x0201;
const TAG_SOLIDITY_ELEMENTS_STATE = 0x0204;
const TAG_ETHEREUM_DEPOSIT_CLAIM = 0x5101;
const TAG_ELEMENTS_STATE_TRANSITION_CLAIM = 0x5103;
const TAG_BURN_APPEND = 0x5104;
const TAG_ETHEREUM_HEARTBEAT_CLAIM = 0x5105;
const TAG_DEPOSIT_PUBLIC_OUTPUT = 0x5201;
const TAG_ELEMENTS_STATE_PUBLIC_OUTPUT = 0x5203;
const TAG_HEARTBEAT_PUBLIC_OUTPUT = 0x5204;

// Keep consensus byte constants private. Exported Uint8Arrays are mutable even
// when their bindings are `const`, so exposing them would let one caller alter
// every later commitment produced in the same JavaScript process.
const DEPOSIT_ID_DOMAIN = hexToBytes(DEPOSIT_ID_DOMAIN_HEX);
const BURN_LEAF_DOMAIN = hexToBytes(BURN_LEAF_DOMAIN_HEX);
const BURN_ID_DOMAIN = hexToBytes(BURN_ID_DOMAIN_HEX);
const EMPTY_BURN_ROOT = hexToBytes(EMPTY_BURN_ROOT_HEX);
const JOURNAL_MAGIC = new TextEncoder().encode(JOURNAL_MAGIC_ASCII);
const JOURNAL_SUCCESS = new TextEncoder().encode(JOURNAL_SUCCESS_ASCII);
const ANNEX_MAGIC = hexToBytes(ANNEX_MAGIC_HEX);

/** Return an owned copy so callers cannot mutate the process-global constant. */
export function depositIdDomainBytes(): Uint8Array {
  return DEPOSIT_ID_DOMAIN.slice();
}

/** Return an owned copy so callers cannot mutate the process-global constant. */
export function burnLeafDomainBytes(): Uint8Array {
  return BURN_LEAF_DOMAIN.slice();
}

/** Return an owned copy so callers cannot mutate the process-global constant. */
export function burnIdDomainBytes(): Uint8Array {
  return BURN_ID_DOMAIN.slice();
}

/** Return an owned copy of the canonical depth-64 empty burn root. */
export function emptyBurnRootBytes(): Uint8Array {
  return EMPTY_BURN_ROOT.slice();
}

/** Return an owned copy so callers cannot mutate the process-global constant. */
export function journalMagicBytes(): Uint8Array {
  return JOURNAL_MAGIC.slice();
}

/** Return an owned copy so callers cannot mutate the process-global constant. */
export function journalSuccessBytes(): Uint8Array {
  return JOURNAL_SUCCESS.slice();
}

/** Return an owned copy so callers cannot mutate the process-global constant. */
export function annexMagicBytes(): Uint8Array {
  return ANNEX_MAGIC.slice();
}

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
  assertNonzero(value.vault, "vault");
  assertNonzero(value.usdt, "USDT");
  assertNonzero(value.depositor, "depositor");
  if (value.chainId <= 0n || value.chainId >= U64_LIMIT) throw new Error("chain ID");
  assertU64(value.nonce, "nonce");
  if (
    value.amountUSDT6 <= 0n ||
    value.amountUSDT6 > MAX_DEPOSIT_AMOUNT_USDT6 ||
    value.amountUSDT6 > U64_MAX / USDD_UNITS_PER_USDT_MICRO
  ) {
    throw new Error("amount exceeds the vault limit or checked USDT6-to-USDD8 conversion");
  }
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

/** Canonical schema-2 VaultDeposit record consumed by the Ethereum guest. */
export function encodeVaultDeposit(value: VaultDeposit): Uint8Array {
  // The Solidity-compatible preimage validator enforces the same field
  // semantics as Rust's VaultDeposit::validate.
  depositPreimage(value);
  return concat(
    encodeRecordHeader(TAG_VAULT_DEPOSIT),
    u64be(value.chainId),
    value.vault,
    value.usdt,
    u64be(value.nonce),
    value.depositor,
    u64be(value.amountUSDT6),
    encodeByteString(value.elementsScript),
    value.userSalt,
  );
}

export function decodeVaultDeposit(bytes: Uint8Array): VaultDeposit {
  return decodeExact(bytes, decodeVaultDepositFrom, "vault deposit");
}

function decodeVaultDepositFrom(decoder: CanonicalDecoder): VaultDeposit {
  decodeRecordHeader(decoder, TAG_VAULT_DEPOSIT);
  const value: VaultDeposit = {
    chainId: decoder.u64("Ethereum chain ID"),
    vault: decoder.fixed(20, "vault"),
    usdt: decoder.fixed(20, "USDT"),
    nonce: decoder.u64("deposit nonce"),
    depositor: decoder.fixed(20, "depositor"),
    amountUSDT6: decoder.u64("USDT amount"),
    elementsScript: decoder.byteString("Elements script"),
    userSalt: decoder.fixed(32, "user salt"),
  };
  depositPreimage(value);
  return value;
}

export interface EthereumFinalityWitness {
  ethereumLightClientDigest: Uint8Array;
  finalizedBeaconSlot: bigint;
  finalizedBeaconRoot: Uint8Array;
  finalizedExecutionBlock: Uint8Array;
  finalizedExecutionStateRoot: Uint8Array;
  executionBlockNumber: bigint;
  executionBlockTimestamp: bigint;
}

function validateEthereumFinalityWitness(value: EthereumFinalityWitness): void {
  assertRequiredHash(value.ethereumLightClientDigest, "Ethereum light-client digest");
  assertPositiveU64(value.finalizedBeaconSlot, "finalized beacon slot");
  assertRequiredHash(value.finalizedBeaconRoot, "finalized beacon root");
  assertRequiredHash(value.finalizedExecutionBlock, "finalized execution block");
  assertRequiredHash(value.finalizedExecutionStateRoot, "finalized execution state root");
  // Rust permits zero for both execution metadata fields; they remain u64.
  assertU64(value.executionBlockNumber, "execution block number");
  assertU64(value.executionBlockTimestamp, "execution block timestamp");
}

export function encodeEthereumFinalityWitness(value: EthereumFinalityWitness): Uint8Array {
  validateEthereumFinalityWitness(value);
  return concat(
    encodeRecordHeader(TAG_ETHEREUM_FINALITY),
    value.ethereumLightClientDigest,
    u64be(value.finalizedBeaconSlot),
    value.finalizedBeaconRoot,
    value.finalizedExecutionBlock,
    value.finalizedExecutionStateRoot,
    u64be(value.executionBlockNumber),
    u64be(value.executionBlockTimestamp),
  );
}

export function decodeEthereumFinalityWitness(bytes: Uint8Array): EthereumFinalityWitness {
  return decodeExact(bytes, decodeEthereumFinalityWitnessFrom, "Ethereum finality witness");
}

function decodeEthereumFinalityWitnessFrom(
  decoder: CanonicalDecoder,
): EthereumFinalityWitness {
  decodeRecordHeader(decoder, TAG_ETHEREUM_FINALITY);
  const value: EthereumFinalityWitness = {
    ethereumLightClientDigest: decoder.fixed(32, "Ethereum light-client digest"),
    finalizedBeaconSlot: decoder.u64("finalized beacon slot"),
    finalizedBeaconRoot: decoder.fixed(32, "finalized beacon root"),
    finalizedExecutionBlock: decoder.fixed(32, "finalized execution block"),
    finalizedExecutionStateRoot: decoder.fixed(32, "finalized execution state root"),
    executionBlockNumber: decoder.u64("execution block number"),
    executionBlockTimestamp: decoder.u64("execution block timestamp"),
  };
  validateEthereumFinalityWitness(value);
  return value;
}

export interface BurnPayload {
  vaultId: Uint8Array;
  ethereumRecipient: Uint8Array;
  amountUSDT6: bigint;
}

export function encodeBurnPayload(value: BurnPayload): Uint8Array {
  assertLength(value.vaultId, 32, "vault ID");
  assertLength(value.ethereumRecipient, 20, "Ethereum recipient");
  assertNonzero(value.vaultId, "vault ID");
  assertNonzero(value.ethereumRecipient, "Ethereum recipient");
  assertPositiveU64(value.amountUSDT6, "amount");
  if (value.amountUSDT6 > MAX_BURN_AMOUNT_USDT6) {
    throw new Error("burn exceeds the Elements explicit-output limit");
  }
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

export function burnId(
  elementsGenesis: Uint8Array,
  txidDisplayBytes: Uint8Array,
  vout: number,
): Uint8Array {
  assertLength(elementsGenesis, 32, "Elements genesis");
  assertLength(txidDisplayBytes, 32, "transaction ID");
  assertNonzero(elementsGenesis, "Elements genesis");
  assertNonzero(txidDisplayBytes, "transaction ID");
  assertU32Number(vout, "output index");
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
  ] as const) {
    assertLength(bytes, 32, name);
    assertNonzero(bytes, name);
  }
  assertLength(value.burnTxidDisplay, 32, "burn txid display bytes");
  assertNonzero(value.burnTxidDisplay, "burn txid display bytes");
  assertU32Number(value.burnVout, "burn output index");
  assertU64(value.burnIndex, "burn index");
  assertPositiveU64(value.amountUSDT6, "amount");
  if (
    bytesToHex(burnId(value.elementsGenesis, value.burnTxidDisplay, value.burnVout)) !==
    bytesToHex(value.burnId)
  ) {
    throw new Error("burn ID does not bind outpoint");
  }
  assertLength(value.recipient, 20, "recipient");
  assertNonzero(value.recipient, "recipient");
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

export interface OutPoint {
  /** Canonical RPC/display-order transaction-ID bytes. */
  txid: Uint8Array;
  vout: number;
}

export interface Burn {
  vaultId: Uint8Array;
  usddAsset: Uint8Array;
  amountUSDD8: bigint;
  amountUSDT6: bigint;
  burnOutpoint: OutPoint;
  ethereumDestination: Uint8Array;
}

function validateBurn(value: Burn): void {
  assertRequiredHash(value.vaultId, "vault ID");
  assertRequiredHash(value.usddAsset, "USDD asset");
  assertPositiveU64(value.amountUSDD8, "burn USDD amount");
  assertU64(value.amountUSDT6, "burn USDT amount");
  assertRequiredHash(value.burnOutpoint.txid, "burn transaction ID");
  assertU32Number(value.burnOutpoint.vout, "burn output index");
  assertLength(value.ethereumDestination, 20, "Ethereum destination");
  assertNonzero(value.ethereumDestination, "Ethereum destination");
  if (
    value.amountUSDD8 % USDD_UNITS_PER_USDT_MICRO !== 0n ||
    value.amountUSDD8 / USDD_UNITS_PER_USDT_MICRO !== value.amountUSDT6 ||
    value.amountUSDT6 > MAX_BURN_AMOUNT_USDT6 ||
    value.amountUSDD8 > MAX_MINT_BATCH_USDD8
  ) {
    throw new Error("burn is not exactly convertible to micro-USDT");
  }
}

export function encodeBurn(value: Burn): Uint8Array {
  validateBurn(value);
  return concat(
    encodeRecordHeader(TAG_BURN),
    value.vaultId,
    value.usddAsset,
    u64be(value.amountUSDD8),
    u64be(value.amountUSDT6),
    value.burnOutpoint.txid,
    u32be(value.burnOutpoint.vout),
    value.ethereumDestination,
  );
}

export function decodeBurn(bytes: Uint8Array): Burn {
  return decodeExact(bytes, decodeBurnFrom, "burn");
}

function decodeBurnFrom(decoder: CanonicalDecoder): Burn {
  decodeRecordHeader(decoder, TAG_BURN);
  const value: Burn = {
    vaultId: decoder.fixed(32, "vault ID"),
    usddAsset: decoder.fixed(32, "USDD asset"),
    amountUSDD8: decoder.u64("burn USDD amount"),
    amountUSDT6: decoder.u64("burn USDT amount"),
    burnOutpoint: {
      txid: decoder.fixed(32, "burn transaction ID"),
      vout: decoder.u32("burn output index"),
    },
    ethereumDestination: decoder.fixed(20, "Ethereum destination"),
  };
  validateBurn(value);
  return value;
}

export interface BurnProof {
  /** Exactly 64 bottom-up siblings; the encoding has no length prefix. */
  siblings: readonly Uint8Array[];
}

function validateBurnProof(value: BurnProof): void {
  if (value.siblings.length !== 64) {
    throw new Error("burn proof must contain exactly 64 siblings");
  }
  for (const sibling of value.siblings) assertLength(sibling, 32, "burn sibling");
}

export function encodeBurnProof(value: BurnProof): Uint8Array {
  validateBurnProof(value);
  return concat(...value.siblings);
}

export function decodeBurnProof(bytes: Uint8Array): BurnProof {
  return decodeExact(bytes, decodeBurnProofFrom, "burn proof");
}

function decodeBurnProofFrom(decoder: CanonicalDecoder): BurnProof {
  const siblings: Uint8Array[] = [];
  for (let index = 0; index < 64; index += 1) {
    siblings.push(decoder.fixed(32, "burn sibling"));
  }
  return { siblings };
}

export interface BurnAppend {
  burn: Burn;
  emptyBranch: BurnProof;
}

export function encodeBurnAppend(value: BurnAppend): Uint8Array {
  return concat(
    encodeRecordHeader(TAG_BURN_APPEND),
    encodeBurn(value.burn),
    encodeBurnProof(value.emptyBranch),
  );
}

export function decodeBurnAppend(bytes: Uint8Array): BurnAppend {
  return decodeExact(bytes, decodeBurnAppendFrom, "burn append");
}

function decodeBurnAppendFrom(decoder: CanonicalDecoder): BurnAppend {
  decodeRecordHeader(decoder, TAG_BURN_APPEND);
  return {
    burn: decodeBurnFrom(decoder),
    emptyBranch: decodeBurnProofFrom(decoder),
  };
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
  assertU64(value.sequence, "controller sequence");
  assertU64(value.nextMintNonce, "next mint nonce");
  assertU64(value.finalizedBeaconSlot, "finalized beacon slot");
  assertU64(value.totalMintedUSDDBase, "total minted USDD");
  assertNonzero(value.ethereumLightClientDigest, "Ethereum light-client digest");
  assertNonzero(value.configurationHash, "configuration hash");
  if (value.finalizedBeaconSlot === 0n) {
    if (
      value.sequence !== 0n ||
      value.totalMintedUSDDBase !== 0n ||
      !isZero(value.finalizedBeaconRoot) ||
      !isZero(value.finalizedExecutionStateRoot)
    ) {
      throw new Error("invalid bootstrap controller state");
    }
  } else if (isZero(value.finalizedBeaconRoot) || isZero(value.finalizedExecutionStateRoot)) {
    throw new Error("zero finalized state commitment");
  }
  if (value.totalMintedUSDDBase % USDD_UNITS_PER_USDT_MICRO !== 0n) {
    throw new Error("nonconvertible minted total");
  }
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

export interface MintOutput {
  depositId: Uint8Array;
  nonce: bigint;
  amountUSDT6: bigint;
  amountUSDD8: bigint;
  elementsScript: Uint8Array;
}

function validateMintOutput(value: MintOutput): void {
  assertLength(value.depositId, 32, "deposit ID");
  assertNonzero(value.depositId, "deposit ID");
  assertU64(value.nonce, "mint nonce");
  assertPositiveU64(value.amountUSDT6, "mint USDT amount");
  assertPositiveU64(value.amountUSDD8, "mint USDD amount");
  if (
    value.amountUSDT6 > MAX_DEPOSIT_AMOUNT_USDT6 ||
    value.amountUSDT6 > U64_MAX / USDD_UNITS_PER_USDT_MICRO ||
    value.amountUSDT6 * USDD_UNITS_PER_USDT_MICRO !== value.amountUSDD8
  ) {
    throw new Error("USDT/USDD conversion mismatch");
  }
  if (value.elementsScript.length === 0 || value.elementsScript.length > 128) {
    throw new Error("invalid Elements script length");
  }
}

export function encodeMintOutput(value: MintOutput): Uint8Array {
  validateMintOutput(value);
  return concat(
    encodeRecordHeader(TAG_MINT_OUTPUT),
    value.depositId,
    u64be(value.nonce),
    u64be(value.amountUSDT6),
    u64be(value.amountUSDD8),
    encodeByteString(value.elementsScript),
  );
}

export function decodeMintOutput(bytes: Uint8Array): MintOutput {
  return decodeExact(bytes, decodeMintOutputFrom, "mint output");
}

function decodeMintOutputFrom(decoder: CanonicalDecoder): MintOutput {
  decodeRecordHeader(decoder, TAG_MINT_OUTPUT);
  const value: MintOutput = {
    depositId: decoder.fixed(32, "deposit ID"),
    nonce: decoder.u64("mint nonce"),
    amountUSDT6: decoder.u64("mint USDT amount"),
    amountUSDD8: decoder.u64("mint USDD amount"),
    elementsScript: decoder.byteString("Elements script"),
  };
  validateMintOutput(value);
  return value;
}

export interface MintBatch {
  firstNonce: bigint;
  nextNonce: bigint;
  outputs: readonly MintOutput[];
  totalAmountUSDT6: bigint;
  totalAmountUSDD8: bigint;
}

function validateMintBatch(value: MintBatch): void {
  assertU64(value.firstNonce, "first mint nonce");
  assertU64(value.nextNonce, "next mint nonce");
  assertU64(value.totalAmountUSDT6, "batch USDT total");
  assertU64(value.totalAmountUSDD8, "batch USDD total");
  if (value.outputs.length === 0 || value.outputs.length > 64) {
    throw new Error("mint batch size must be 1..64");
  }
  const expectedNext = checkedAddU64(
    value.firstNonce,
    BigInt(value.outputs.length),
    "batch next nonce",
  );
  if (value.nextNonce !== expectedNext) throw new Error("wrong batch next nonce");

  let usdtTotal = 0n;
  let usddTotal = 0n;
  for (const [offset, output] of value.outputs.entries()) {
    validateMintOutput(output);
    const expectedNonce = checkedAddU64(value.firstNonce, BigInt(offset), "batch nonce");
    if (output.nonce !== expectedNonce) throw new Error("mint output nonces are not consecutive");
    usdtTotal = checkedAddU64(usdtTotal, output.amountUSDT6, "batch USDT total");
    usddTotal = checkedAddU64(usddTotal, output.amountUSDD8, "batch USDD total");
  }
  if (
    usdtTotal !== value.totalAmountUSDT6 ||
    usddTotal !== value.totalAmountUSDD8 ||
    usdtTotal > U64_MAX / USDD_UNITS_PER_USDT_MICRO ||
    usdtTotal * USDD_UNITS_PER_USDT_MICRO !== usddTotal
  ) {
    throw new Error("wrong mint batch totals");
  }
  if (usdtTotal > MAX_MINT_BATCH_USDT6 || usddTotal > MAX_MINT_BATCH_USDD8) {
    throw new Error("mint batch exceeds the Elements explicit-output budget");
  }
}

export function encodeMintBatch(value: MintBatch): Uint8Array {
  validateMintBatch(value);
  return concat(
    encodeRecordHeader(TAG_MINT_BATCH),
    u64be(value.firstNonce),
    u64be(value.nextNonce),
    Uint8Array.of(value.outputs.length),
    ...value.outputs.map(encodeMintOutput),
    u64be(value.totalAmountUSDT6),
    u64be(value.totalAmountUSDD8),
  );
}

export function decodeMintBatch(bytes: Uint8Array): MintBatch {
  return decodeExact(bytes, decodeMintBatchFrom, "mint batch");
}

function decodeMintBatchFrom(decoder: CanonicalDecoder): MintBatch {
  decodeRecordHeader(decoder, TAG_MINT_BATCH);
  const firstNonce = decoder.u64("first mint nonce");
  const nextNonce = decoder.u64("next mint nonce");
  const count = decoder.u8("mint output count");
  if (count === 0 || count > 64) throw new Error("mint batch size must be 1..64");
  const outputs: MintOutput[] = [];
  for (let index = 0; index < count; index += 1) outputs.push(decodeMintOutputFrom(decoder));
  const value: MintBatch = {
    firstNonce,
    nextNonce,
    outputs,
    totalAmountUSDT6: decoder.u64("batch USDT total"),
    totalAmountUSDD8: decoder.u64("batch USDD total"),
  };
  validateMintBatch(value);
  return value;
}

export interface DepositPublicOutput {
  manifestId: Uint8Array;
  claimId: Uint8Array;
  priorState: MintControllerState;
  nextState: MintControllerState;
  finalizedExecutionBlockTimestamp: bigint;
  mintBatch: MintBatch;
}

function validateDepositPublicOutput(value: DepositPublicOutput): void {
  assertRequiredHash(value.manifestId, "manifest ID");
  assertRequiredHash(value.claimId, "claim ID");
  assertPositiveU64(value.finalizedExecutionBlockTimestamp, "finalized execution timestamp");
  encodeMintControllerState(value.priorState);
  encodeMintControllerState(value.nextState);
  validateMintBatch(value.mintBatch);

  const expectedTotal = checkedAddU64(
    value.priorState.totalMintedUSDDBase,
    value.mintBatch.totalAmountUSDD8,
    "minted supply",
  );
  const expectedSequence = checkedAddU64(value.priorState.sequence, 1n, "controller sequence");
  if (
    value.nextState.version !== value.priorState.version ||
    value.nextState.sequence !== expectedSequence ||
    value.nextState.nextMintNonce !== value.mintBatch.nextNonce ||
    value.mintBatch.firstNonce !== value.priorState.nextMintNonce ||
    value.nextState.totalMintedUSDDBase !== expectedTotal ||
    !bytesEqual(value.nextState.configurationHash, value.priorState.configurationHash) ||
    value.nextState.finalizedBeaconSlot < value.priorState.finalizedBeaconSlot ||
    value.nextState.finalizedBeaconSlot - value.priorState.finalizedBeaconSlot >
      MAX_ETHEREUM_FINALITY_SLOT_GAP ||
    (value.nextState.finalizedBeaconSlot === value.priorState.finalizedBeaconSlot &&
      (!bytesEqual(
        value.nextState.ethereumLightClientDigest,
        value.priorState.ethereumLightClientDigest,
      ) ||
        !bytesEqual(value.nextState.finalizedBeaconRoot, value.priorState.finalizedBeaconRoot) ||
        !bytesEqual(
          value.nextState.finalizedExecutionStateRoot,
          value.priorState.finalizedExecutionStateRoot,
        ))) ||
    (value.nextState.finalizedBeaconSlot > value.priorState.finalizedBeaconSlot &&
      bytesEqual(
        value.nextState.ethereumLightClientDigest,
        value.priorState.ethereumLightClientDigest,
      ))
  ) {
    throw new Error("deposit output does not bind the controller transition");
  }
}

export function encodeDepositPublicOutput(value: DepositPublicOutput): Uint8Array {
  validateDepositPublicOutput(value);
  return concat(
    encodeRecordHeader(TAG_DEPOSIT_PUBLIC_OUTPUT),
    value.manifestId,
    value.claimId,
    encodeMintControllerState(value.priorState),
    encodeMintControllerState(value.nextState),
    u64be(value.finalizedExecutionBlockTimestamp),
    encodeMintBatch(value.mintBatch),
  );
}

export function decodeDepositPublicOutput(bytes: Uint8Array): DepositPublicOutput {
  return decodeExact(bytes, decodeDepositPublicOutputFrom, "deposit public output");
}

function decodeDepositPublicOutputFrom(decoder: CanonicalDecoder): DepositPublicOutput {
  decodeRecordHeader(decoder, TAG_DEPOSIT_PUBLIC_OUTPUT);
  const value: DepositPublicOutput = {
    manifestId: decoder.fixed(32, "manifest ID"),
    claimId: decoder.fixed(32, "claim ID"),
    priorState: decodeMintControllerStateFrom(decoder),
    nextState: decodeMintControllerStateFrom(decoder),
    finalizedExecutionBlockTimestamp: decoder.u64("finalized execution timestamp"),
    mintBatch: decodeMintBatchFrom(decoder),
  };
  validateDepositPublicOutput(value);
  return value;
}

export interface HeartbeatPublicOutput {
  manifestId: Uint8Array;
  claimId: Uint8Array;
  priorState: MintControllerState;
  nextState: MintControllerState;
  finalizedExecutionBlockTimestamp: bigint;
}

function validateHeartbeatPublicOutput(value: HeartbeatPublicOutput): void {
  assertRequiredHash(value.manifestId, "manifest ID");
  assertRequiredHash(value.claimId, "claim ID");
  assertPositiveU64(value.finalizedExecutionBlockTimestamp, "finalized execution timestamp");
  encodeMintControllerState(value.priorState);
  encodeMintControllerState(value.nextState);
  const expectedSequence = checkedAddU64(value.priorState.sequence, 1n, "controller sequence");
  if (
    value.nextState.version !== value.priorState.version ||
    value.nextState.sequence !== expectedSequence ||
    value.nextState.nextMintNonce !== value.priorState.nextMintNonce ||
    value.nextState.totalMintedUSDDBase !== value.priorState.totalMintedUSDDBase ||
    !bytesEqual(value.nextState.configurationHash, value.priorState.configurationHash) ||
    value.nextState.finalizedBeaconSlot <= value.priorState.finalizedBeaconSlot ||
    bytesEqual(
      value.nextState.ethereumLightClientDigest,
      value.priorState.ethereumLightClientDigest,
    ) ||
    value.nextState.finalizedBeaconSlot - value.priorState.finalizedBeaconSlot >
      MAX_ETHEREUM_FINALITY_SLOT_GAP
  ) {
    throw new Error("heartbeat output does not bind a state-only transition");
  }
}

export function encodeHeartbeatPublicOutput(value: HeartbeatPublicOutput): Uint8Array {
  validateHeartbeatPublicOutput(value);
  return concat(
    encodeRecordHeader(TAG_HEARTBEAT_PUBLIC_OUTPUT),
    value.manifestId,
    value.claimId,
    encodeMintControllerState(value.priorState),
    encodeMintControllerState(value.nextState),
    u64be(value.finalizedExecutionBlockTimestamp),
  );
}

export function decodeHeartbeatPublicOutput(bytes: Uint8Array): HeartbeatPublicOutput {
  return decodeExact(bytes, decodeHeartbeatPublicOutputFrom, "heartbeat public output");
}

function decodeHeartbeatPublicOutputFrom(decoder: CanonicalDecoder): HeartbeatPublicOutput {
  decodeRecordHeader(decoder, TAG_HEARTBEAT_PUBLIC_OUTPUT);
  const value: HeartbeatPublicOutput = {
    manifestId: decoder.fixed(32, "manifest ID"),
    claimId: decoder.fixed(32, "claim ID"),
    priorState: decodeMintControllerStateFrom(decoder),
    nextState: decodeMintControllerStateFrom(decoder),
    finalizedExecutionBlockTimestamp: decoder.u64("finalized execution timestamp"),
  };
  validateHeartbeatPublicOutput(value);
  return value;
}

export interface SolidityElementsBridgeState {
  sequence: bigint;
  burnCount: bigint;
  elementsTipHash: Uint8Array;
  elementsConsensusStateDigest: Uint8Array;
  cumulativeBurnRoot: Uint8Array;
  finalizedBitcoinBlockHash: Uint8Array;
  bitcoinHeight: bigint;
  elementsHeight: bigint;
  bitcoinMedianTimePast: bigint;
  bitcoinChainwork: Uint8Array;
}

export function isZeroSolidityElementsBridgeState(value: SolidityElementsBridgeState): boolean {
  return (
    value.sequence === 0n &&
    value.burnCount === 0n &&
    isZero(value.elementsTipHash) &&
    isZero(value.elementsConsensusStateDigest) &&
    isZero(value.cumulativeBurnRoot) &&
    isZero(value.finalizedBitcoinBlockHash) &&
    value.bitcoinHeight === 0n &&
    value.elementsHeight === 0n &&
    value.bitcoinMedianTimePast === 0n &&
    isZero(value.bitcoinChainwork)
  );
}

function validateSolidityElementsBridgeState(value: SolidityElementsBridgeState): void {
  assertU64(value.sequence, "Elements state sequence");
  assertU64(value.burnCount, "burn count");
  assertU64(value.bitcoinHeight, "Bitcoin height");
  assertU64(value.elementsHeight, "Elements height");
  assertU64(value.bitcoinMedianTimePast, "Bitcoin median time past");
  for (const [name, bytes] of [
    ["Elements tip hash", value.elementsTipHash],
    ["Elements consensus state digest", value.elementsConsensusStateDigest],
    ["cumulative burn root", value.cumulativeBurnRoot],
    ["finalized Bitcoin block hash", value.finalizedBitcoinBlockHash],
    ["Bitcoin chainwork", value.bitcoinChainwork],
  ] as const) {
    assertLength(bytes, 32, name);
  }
  if (isZeroSolidityElementsBridgeState(value)) return;
  for (const [name, bytes] of [
    ["Elements tip hash", value.elementsTipHash],
    ["Elements consensus state digest", value.elementsConsensusStateDigest],
    ["cumulative burn root", value.cumulativeBurnRoot],
    ["finalized Bitcoin block hash", value.finalizedBitcoinBlockHash],
    ["Bitcoin chainwork", value.bitcoinChainwork],
  ] as const) {
    assertNonzero(bytes, name);
  }
  if (value.burnCount === 0n && !bytesEqual(value.cumulativeBurnRoot, EMPTY_BURN_ROOT)) {
    throw new Error("noncanonical empty burn root");
  }
}

function validateElementsStateSuccessor(
  prior: SolidityElementsBridgeState,
  next: SolidityElementsBridgeState,
): void {
  validateSolidityElementsBridgeState(prior);
  validateSolidityElementsBridgeState(next);
  if (isZeroSolidityElementsBridgeState(next)) throw new Error("zero successor Elements state");
  if (next.sequence !== checkedAddU64(prior.sequence, 1n, "Elements state sequence")) {
    throw new Error("wrong Elements state sequence");
  }
  if (next.burnCount < prior.burnCount) throw new Error("burn count decreased");
  if (next.burnCount - prior.burnCount > 64n) {
    throw new Error("burn count growth exceeds 64");
  }
  if (
    prior.sequence !== 0n &&
    next.burnCount === prior.burnCount &&
    !bytesEqual(next.cumulativeBurnRoot, prior.cumulativeBurnRoot)
  ) {
    throw new Error("burn root changed without a burn");
  }
  if (
    prior.sequence !== 0n &&
    bytesEqual(next.elementsConsensusStateDigest, prior.elementsConsensusStateDigest)
  ) {
    throw new Error("Elements consensus state digest did not advance");
  }
  if (
    next.bitcoinHeight <= prior.bitcoinHeight ||
    next.elementsHeight <= prior.elementsHeight ||
    next.bitcoinMedianTimePast < prior.bitcoinMedianTimePast ||
    compareBigEndian(next.bitcoinChainwork, prior.bitcoinChainwork) <= 0
  ) {
    throw new Error("Elements/Bitcoin finalized context did not advance");
  }
}

export function encodeSolidityElementsBridgeState(
  value: SolidityElementsBridgeState,
): Uint8Array {
  validateSolidityElementsBridgeState(value);
  return concat(
    encodeRecordHeader(TAG_SOLIDITY_ELEMENTS_STATE),
    u64be(value.sequence),
    u64be(value.burnCount),
    value.elementsTipHash,
    value.elementsConsensusStateDigest,
    value.cumulativeBurnRoot,
    value.finalizedBitcoinBlockHash,
    u64be(value.bitcoinHeight),
    u64be(value.elementsHeight),
    u64be(value.bitcoinMedianTimePast),
    value.bitcoinChainwork,
  );
}

export function decodeSolidityElementsBridgeState(
  bytes: Uint8Array,
): SolidityElementsBridgeState {
  return decodeExact(bytes, decodeSolidityElementsBridgeStateFrom, "Solidity Elements state");
}

function decodeSolidityElementsBridgeStateFrom(
  decoder: CanonicalDecoder,
): SolidityElementsBridgeState {
  decodeRecordHeader(decoder, TAG_SOLIDITY_ELEMENTS_STATE);
  const value: SolidityElementsBridgeState = {
    sequence: decoder.u64("Elements state sequence"),
    burnCount: decoder.u64("burn count"),
    elementsTipHash: decoder.fixed(32, "Elements tip hash"),
    elementsConsensusStateDigest: decoder.fixed(32, "Elements consensus state digest"),
    cumulativeBurnRoot: decoder.fixed(32, "cumulative burn root"),
    finalizedBitcoinBlockHash: decoder.fixed(32, "finalized Bitcoin block hash"),
    bitcoinHeight: decoder.u64("Bitcoin height"),
    elementsHeight: decoder.u64("Elements height"),
    bitcoinMedianTimePast: decoder.u64("Bitcoin median time past"),
    bitcoinChainwork: decoder.fixed(32, "Bitcoin chainwork"),
  };
  validateSolidityElementsBridgeState(value);
  return value;
}

export interface ElementsStatePublicOutput {
  manifestId: Uint8Array;
  claimId: Uint8Array;
  priorBridgeStateHash: Uint8Array;
  nextBridgeStateHash: Uint8Array;
  verifierStatement: Uint8Array;
  priorState: SolidityElementsBridgeState;
  nextState: SolidityElementsBridgeState;
}

function validateElementsStatePublicOutput(value: ElementsStatePublicOutput): void {
  assertRequiredHash(value.manifestId, "manifest ID");
  assertRequiredHash(value.claimId, "claim ID");
  assertLength(value.priorBridgeStateHash, 32, "prior bridge state hash");
  assertRequiredHash(value.nextBridgeStateHash, "next bridge state hash");
  assertRequiredHash(value.verifierStatement, "verifier statement");
  validateElementsStateSuccessor(value.priorState, value.nextState);
  if (
    isZeroSolidityElementsBridgeState(value.priorState) !== isZero(value.priorBridgeStateHash)
  ) {
    throw new Error("prior Elements state/hash mismatch");
  }
}

export function encodeElementsStatePublicOutput(value: ElementsStatePublicOutput): Uint8Array {
  validateElementsStatePublicOutput(value);
  return concat(
    encodeRecordHeader(TAG_ELEMENTS_STATE_PUBLIC_OUTPUT),
    value.manifestId,
    value.claimId,
    value.priorBridgeStateHash,
    value.nextBridgeStateHash,
    value.verifierStatement,
    encodeSolidityElementsBridgeState(value.priorState),
    encodeSolidityElementsBridgeState(value.nextState),
  );
}

export function decodeElementsStatePublicOutput(bytes: Uint8Array): ElementsStatePublicOutput {
  return decodeExact(bytes, decodeElementsStatePublicOutputFrom, "Elements state public output");
}

function decodeElementsStatePublicOutputFrom(decoder: CanonicalDecoder): ElementsStatePublicOutput {
  decodeRecordHeader(decoder, TAG_ELEMENTS_STATE_PUBLIC_OUTPUT);
  const value: ElementsStatePublicOutput = {
    manifestId: decoder.fixed(32, "manifest ID"),
    claimId: decoder.fixed(32, "claim ID"),
    priorBridgeStateHash: decoder.fixed(32, "prior bridge state hash"),
    nextBridgeStateHash: decoder.fixed(32, "next bridge state hash"),
    verifierStatement: decoder.fixed(32, "verifier statement"),
    priorState: decodeSolidityElementsBridgeStateFrom(decoder),
    nextState: decodeSolidityElementsBridgeStateFrom(decoder),
  };
  validateElementsStatePublicOutput(value);
  return value;
}

export interface EthereumDepositClaim {
  manifestId: Uint8Array;
  priorState: MintControllerState;
  finality: EthereumFinalityWitness;
  deposits: readonly VaultDeposit[];
}

function validateClaimDepositBatch(deposits: readonly VaultDeposit[]): void {
  if (deposits.length === 0 || deposits.length > 64) {
    throw new Error("deposit proof batch must be 1..64");
  }
  const first = deposits[0]!;
  encodeVaultDeposit(first);
  let totalUSDT6 = 0n;
  let totalUSDD8 = 0n;
  for (const [offset, deposit] of deposits.entries()) {
    encodeVaultDeposit(deposit);
    const expectedNonce = checkedAddU64(first.nonce, BigInt(offset), "deposit batch nonce");
    if (deposit.nonce !== expectedNonce) {
      throw new Error("mint batch deposit nonces are not consecutive");
    }
    if (
      deposit.chainId !== first.chainId ||
      !bytesEqual(deposit.vault, first.vault) ||
      !bytesEqual(deposit.usdt, first.usdt)
    ) {
      throw new Error("mint batch mixes chains, vaults, or tokens");
    }
    totalUSDT6 = checkedAddU64(totalUSDT6, deposit.amountUSDT6, "batch USDT total");
    totalUSDD8 = checkedAddU64(
      totalUSDD8,
      deposit.amountUSDT6 * USDD_UNITS_PER_USDT_MICRO,
      "batch USDD total",
    );
  }
  if (totalUSDT6 > MAX_MINT_BATCH_USDT6 || totalUSDD8 > MAX_MINT_BATCH_USDD8) {
    throw new Error("mint batch exceeds the Elements explicit-output budget");
  }
  checkedAddU64(first.nonce, BigInt(deposits.length), "batch next nonce");
}

function validateEthereumDepositClaim(value: EthereumDepositClaim): void {
  assertRequiredHash(value.manifestId, "manifest ID");
  encodeMintControllerState(value.priorState);
  validateEthereumFinalityWitness(value.finality);
  validateClaimDepositBatch(value.deposits);
}

export function encodeEthereumDepositClaim(value: EthereumDepositClaim): Uint8Array {
  validateEthereumDepositClaim(value);
  return concat(
    encodeRecordHeader(TAG_ETHEREUM_DEPOSIT_CLAIM),
    value.manifestId,
    encodeMintControllerState(value.priorState),
    encodeEthereumFinalityWitness(value.finality),
    Uint8Array.of(value.deposits.length),
    ...value.deposits.map(encodeVaultDeposit),
  );
}

export function decodeEthereumDepositClaim(bytes: Uint8Array): EthereumDepositClaim {
  return decodeExact(bytes, decodeEthereumDepositClaimFrom, "Ethereum deposit claim");
}

function decodeEthereumDepositClaimFrom(decoder: CanonicalDecoder): EthereumDepositClaim {
  decodeRecordHeader(decoder, TAG_ETHEREUM_DEPOSIT_CLAIM);
  const manifestId = decoder.fixed(32, "manifest ID");
  const priorState = decodeMintControllerStateFrom(decoder);
  const finality = decodeEthereumFinalityWitnessFrom(decoder);
  const count = decoder.u8("deposit count");
  if (count === 0 || count > 64) throw new Error("deposit proof batch must be 1..64");
  const deposits: VaultDeposit[] = [];
  for (let index = 0; index < count; index += 1) {
    deposits.push(decodeVaultDepositFrom(decoder));
  }
  const value: EthereumDepositClaim = { manifestId, priorState, finality, deposits };
  validateEthereumDepositClaim(value);
  return value;
}

export interface EthereumHeartbeatClaim {
  manifestId: Uint8Array;
  priorState: MintControllerState;
  finality: EthereumFinalityWitness;
}

function validateEthereumHeartbeatClaim(value: EthereumHeartbeatClaim): void {
  assertRequiredHash(value.manifestId, "manifest ID");
  encodeMintControllerState(value.priorState);
  validateEthereumFinalityWitness(value.finality);
}

export function encodeEthereumHeartbeatClaim(value: EthereumHeartbeatClaim): Uint8Array {
  validateEthereumHeartbeatClaim(value);
  return concat(
    encodeRecordHeader(TAG_ETHEREUM_HEARTBEAT_CLAIM),
    value.manifestId,
    encodeMintControllerState(value.priorState),
    encodeEthereumFinalityWitness(value.finality),
  );
}

export function decodeEthereumHeartbeatClaim(bytes: Uint8Array): EthereumHeartbeatClaim {
  return decodeExact(bytes, decodeEthereumHeartbeatClaimFrom, "Ethereum heartbeat claim");
}

function decodeEthereumHeartbeatClaimFrom(decoder: CanonicalDecoder): EthereumHeartbeatClaim {
  decodeRecordHeader(decoder, TAG_ETHEREUM_HEARTBEAT_CLAIM);
  const value: EthereumHeartbeatClaim = {
    manifestId: decoder.fixed(32, "manifest ID"),
    priorState: decodeMintControllerStateFrom(decoder),
    finality: decodeEthereumFinalityWitnessFrom(decoder),
  };
  validateEthereumHeartbeatClaim(value);
  return value;
}

export interface ElementsStateTransitionClaim {
  manifestId: Uint8Array;
  priorBridgeStateHash: Uint8Array;
  priorState: SolidityElementsBridgeState;
  nextState: SolidityElementsBridgeState;
  appendedBurns: readonly BurnAppend[];
}

function validateElementsStateTransitionClaim(value: ElementsStateTransitionClaim): void {
  // Rust deliberately applies no nonzero or successor relationship checks at
  // this claim-codec layer. The guest proves those transition semantics.
  assertLength(value.manifestId, 32, "manifest ID");
  assertLength(value.priorBridgeStateHash, 32, "prior bridge state hash");
  encodeSolidityElementsBridgeState(value.priorState);
  encodeSolidityElementsBridgeState(value.nextState);
  if (value.appendedBurns.length > 64) {
    throw new Error("too many burns in state transition");
  }
  for (const append of value.appendedBurns) encodeBurnAppend(append);
}

export function encodeElementsStateTransitionClaim(
  value: ElementsStateTransitionClaim,
): Uint8Array {
  validateElementsStateTransitionClaim(value);
  return concat(
    encodeRecordHeader(TAG_ELEMENTS_STATE_TRANSITION_CLAIM),
    value.manifestId,
    value.priorBridgeStateHash,
    encodeSolidityElementsBridgeState(value.priorState),
    encodeSolidityElementsBridgeState(value.nextState),
    Uint8Array.of(value.appendedBurns.length),
    ...value.appendedBurns.map(encodeBurnAppend),
  );
}

export function decodeElementsStateTransitionClaim(
  bytes: Uint8Array,
): ElementsStateTransitionClaim {
  return decodeExact(bytes, decodeElementsStateTransitionClaimFrom, "Elements state claim");
}

function decodeElementsStateTransitionClaimFrom(
  decoder: CanonicalDecoder,
): ElementsStateTransitionClaim {
  decodeRecordHeader(decoder, TAG_ELEMENTS_STATE_TRANSITION_CLAIM);
  const manifestId = decoder.fixed(32, "manifest ID");
  const priorBridgeStateHash = decoder.fixed(32, "prior bridge state hash");
  const priorState = decodeSolidityElementsBridgeStateFrom(decoder);
  const nextState = decodeSolidityElementsBridgeStateFrom(decoder);
  const count = decoder.u8("burn append count");
  if (count > 64) throw new Error("too many burns in state transition");
  const appendedBurns: BurnAppend[] = [];
  for (let index = 0; index < count; index += 1) {
    appendedBurns.push(decodeBurnAppendFrom(decoder));
  }
  const value: ElementsStateTransitionClaim = {
    manifestId,
    priorBridgeStateHash,
    priorState,
    nextState,
    appendedBurns,
  };
  validateElementsStateTransitionClaim(value);
  return value;
}

export type TypedPublicValues =
  | { recordType: "deposit"; value: DepositPublicOutput }
  | { recordType: "heartbeat"; value: HeartbeatPublicOutput }
  | { recordType: "elementsState"; value: ElementsStatePublicOutput };

export function encodeTypedPublicValues(value: TypedPublicValues): Uint8Array {
  switch (value.recordType) {
    case "deposit":
      return encodeDepositPublicOutput(value.value);
    case "heartbeat":
      return encodeHeartbeatPublicOutput(value.value);
    case "elementsState":
      return encodeElementsStatePublicOutput(value.value);
  }
}

export function decodeTypedPublicValues(
  statementKind: 1 | 2,
  payload: Uint8Array,
): TypedPublicValues {
  if (payload.length < 4) throw new Error("journal payload is not a canonical typed record");
  const schema = Number(readUintBe(payload.slice(0, 2)));
  const tag = Number(readUintBe(payload.slice(2, 4)));
  if (schema !== ENCODING_SCHEMA) throw new Error("journal payload schema");
  if (statementKind === 1 && tag === TAG_DEPOSIT_PUBLIC_OUTPUT) {
    return { recordType: "deposit", value: decodeDepositPublicOutput(payload) };
  }
  if (statementKind === 1 && tag === TAG_HEARTBEAT_PUBLIC_OUTPUT) {
    return { recordType: "heartbeat", value: decodeHeartbeatPublicOutput(payload) };
  }
  if (statementKind === 2 && tag === TAG_ELEMENTS_STATE_PUBLIC_OUTPUT) {
    return { recordType: "elementsState", value: decodeElementsStatePublicOutput(payload) };
  }
  throw new Error("journal payload is not allowed for its statement kind");
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
  decodeTypedPublicValues(value.statementKind, value.payload);
  return concat(
    JOURNAL_MAGIC,
    u16be(ENCODING_SCHEMA),
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
  if (readUintBe(bytes.slice(8, 10)) !== BigInt(ENCODING_SCHEMA)) {
    throw new Error("journal schema");
  }
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
  decodeTypedPublicValues(value.statementKind, value.payload);
  if (bytesToHex(encodeStrictJournal(value)) !== bytesToHex(bytes)) throw new Error("noncanonical journal");
  return value;
}

export interface Sp1Annex {
  statementKind: 1 | 2;
  guestProgramId: Uint8Array;
  publicValues: Uint8Array;
  proof: Uint8Array;
}

export function encodeSp1Annex(value: Sp1Annex): Uint8Array {
  if (value.statementKind !== 1) throw new Error("Elements annex supports ETH_STATE_V1 only");
  assertLength(value.guestProgramId, 32, "guest program ID");
  if (isZero(value.guestProgramId)) throw new Error("zero guest program ID");
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
    value.guestProgramId,
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
    guestProgramId: bytes.slice(23, 55),
    publicValues: bytes.slice(55, 55 + publicLength),
    proof: bytes.slice(55 + publicLength),
  };
  if (bytesToHex(encodeSp1Annex(value)) !== bytesToHex(bytes)) throw new Error("noncanonical annex");
  const journal = decodeStrictJournal(value.publicValues);
  if (journal.statementKind !== value.statementKind || bytesToHex(journal.programId) !== bytesToHex(value.guestProgramId)) {
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

class CanonicalDecoder {
  readonly #bytes: Uint8Array;
  #offset = 0;

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  take(length: number, name: string): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0 || this.#offset + length > this.#bytes.length) {
      throw new Error(`truncated ${name}`);
    }
    const start = this.#offset;
    this.#offset += length;
    return this.#bytes.slice(start, this.#offset);
  }

  fixed(length: number, name: string): Uint8Array {
    return this.take(length, name);
  }

  u8(name: string): number {
    return this.take(1, name)[0]!;
  }

  u16(name: string): number {
    return Number(readUintBe(this.take(2, name)));
  }

  u32(name: string): number {
    return Number(readUintBe(this.take(4, name)));
  }

  u64(name: string): bigint {
    return readUintBe(this.take(8, name));
  }

  byteString(name: string): Uint8Array {
    const length = this.u32(`${name} length`);
    return this.take(length, name);
  }

  finish(name: string): void {
    const remaining = this.#bytes.length - this.#offset;
    if (remaining !== 0) throw new Error(`${name} has ${remaining} trailing bytes`);
  }
}

function decodeExact<T>(
  bytes: Uint8Array,
  decode: (decoder: CanonicalDecoder) => T,
  name: string,
): T {
  const decoder = new CanonicalDecoder(bytes);
  const value = decode(decoder);
  decoder.finish(name);
  return value;
}

function decodeMintControllerStateFrom(decoder: CanonicalDecoder): MintControllerState {
  return decodeMintControllerState(decoder.take(164, "mint controller state"));
}

function encodeRecordHeader(tag: number): Uint8Array {
  return concat(u16be(ENCODING_SCHEMA), u16be(tag));
}

function decodeRecordHeader(decoder: CanonicalDecoder, expectedTag: number): void {
  if (decoder.u16("record schema") !== ENCODING_SCHEMA) throw new Error("unsupported schema");
  if (decoder.u16("record tag") !== expectedTag) throw new Error("wrong record tag");
}

function encodeByteString(value: Uint8Array): Uint8Array {
  if (value.length > 0xffff_ffff) throw new Error("byte string exceeds u32");
  return concat(u32be(value.length), value);
}

function checkedAddU64(left: bigint, right: bigint, name: string): bigint {
  assertU64(left, name);
  assertU64(right, name);
  const result = left + right;
  if (result >= U64_LIMIT) throw new Error(`${name} overflow`);
  return result;
}

function assertRequiredHash(bytes: Uint8Array, name: string): void {
  assertLength(bytes, 32, name);
  assertNonzero(bytes, name);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  return left.every((byte, index) => byte === right[index]);
}

function compareBigEndian(left: Uint8Array, right: Uint8Array): number {
  assertLength(left, 32, "left uint256");
  assertLength(right, 32, "right uint256");
  for (let index = 0; index < 32; index += 1) {
    if (left[index]! < right[index]!) return -1;
    if (left[index]! > right[index]!) return 1;
  }
  return 0;
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
  assertU32Number(value, "u32");
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

function assertNonzero(bytes: Uint8Array, name: string): void {
  if (isZero(bytes)) throw new Error(`${name} must be nonzero`);
}

function assertU64(value: bigint, name: string): void {
  if (value < 0n || value >= U64_LIMIT) throw new Error(`${name} must fit u64`);
}

function assertPositiveU64(value: bigint, name: string): void {
  if (value <= 0n || value >= U64_LIMIT) throw new Error(`${name} must be a positive u64`);
}

function assertU32Number(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error(`${name} must fit u32`);
  }
}

function isZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}
