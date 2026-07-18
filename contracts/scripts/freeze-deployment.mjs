import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { keccak_256 } from "@noble/hashes/sha3";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function digest(bytes) {
  return {
    sha256: `0x${crypto.createHash("sha256").update(bytes).digest("hex")}`,
    keccak256: `0x${Buffer.from(keccak_256(bytes)).toString("hex")}`
  };
}

async function rpc(url, method, params = []) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })
  });
  if (!response.ok) throw new Error(`RPC HTTP ${response.status}`);
  const body = await response.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

function immutableOffsets(references) {
  const ignored = new Set();
  for (const ranges of Object.values(references)) {
    for (const { start, length } of ranges) {
      for (let offset = start; offset < start + length; ++offset) ignored.add(offset);
    }
  }
  return ignored;
}

function verifyRuntime(template, actual, references) {
  if (template.length !== actual.length) {
    throw new Error(`Runtime length mismatch: template ${template.length}, deployment ${actual.length}`);
  }
  const ignored = immutableOffsets(references);
  for (let offset = 0; offset < template.length; ++offset) {
    if (!ignored.has(offset) && template[offset] !== actual[offset]) {
      throw new Error(`Runtime differs from compiler template at non-immutable byte ${offset}`);
    }
  }
}

function word(callResult, index = 0) {
  const body = callResult.startsWith("0x") ? callResult.slice(2) : callResult;
  const start = index * 64;
  if (body.length < start + 64) throw new Error(`Short ABI return at word ${index}`);
  return body.slice(start, start + 64).toLowerCase();
}

function storageWord(value) {
  const body = (value.startsWith("0x") ? value.slice(2) : value).toLowerCase();
  if (body.length > 64) throw new Error("Storage result exceeds one word");
  return body.padStart(64, "0");
}

function decodeBytes32(callResult, index = 0) {
  return `0x${word(callResult, index)}`;
}

function decodeAddress(callResult, index = 0) {
  return `0x${word(callResult, index).slice(24)}`;
}

function decodeUint(callResult, index = 0) {
  return BigInt(`0x${word(callResult, index)}`).toString();
}

function uint256Bytes(value) {
  const encoded = BigInt(value).toString(16).padStart(64, "0");
  if (encoded.length !== 64) throw new Error(`uint256 overflow: ${value}`);
  return Buffer.from(encoded, "hex");
}

function addressBytes(address) {
  return Buffer.from(address.slice(2).padStart(40, "0"), "hex");
}

function bytes32Bytes(value) {
  const body = value.slice(2);
  if (body.length !== 64) throw new Error(`Not bytes32: ${value}`);
  return Buffer.from(body, "hex");
}

function assertEqual(label, expected, actual) {
  if (String(expected).toLowerCase() !== String(actual).toLowerCase()) {
    throw new Error(`${label} mismatch: expected ${expected}, received ${actual}`);
  }
}

async function contractCall(url, address, build, signature, encodedArguments = "", blockTag = "latest") {
  const selector = build.methodIdentifiers[signature];
  if (!selector) throw new Error(`Missing method identifier for ${signature}`);
  return rpc(url, "eth_call", [{ to: address, data: `0x${selector}${encodedArguments}` }, blockTag]);
}

async function signatureCall(url, address, signature, blockTag = "latest") {
  const selector = Buffer.from(keccak_256(Buffer.from(signature, "ascii"))).toString("hex").slice(0, 8);
  return rpc(url, "eth_call", [{ to: address, data: `0x${selector}` }, blockTag]);
}

async function readImmutableConfiguration(url, address, build, blockTag) {
  const getters = {
    usdt: ["USDT()", decodeAddress],
    proofVerifier: ["PROOF_VERIFIER()", decodeAddress],
    proofVerifierCodehash: ["PROOF_VERIFIER_CODEHASH()", decodeBytes32],
    verifierProgramId: ["VERIFIER_PROGRAM_ID()", decodeBytes32],
    verifierConfigHash: ["VERIFIER_CONFIG_HASH()", decodeBytes32],
    elementsGenesisHash: ["ELEMENTS_GENESIS_HASH()", decodeBytes32],
    usddAssetId: ["USDD_ASSET_ID()", decodeBytes32],
    vaultId: ["VAULT_ID()", decodeBytes32],
    minimumActivationChainwork: ["MINIMUM_ACTIVATION_CHAINWORK()", decodeUint],
    protocolVersion: ["PROTOCOL_VERSION()", decodeUint],
    activeLiabilityCapUSDT6: ["ACTIVE_LIABILITY_CAP_USDT6()", decodeUint]
  };
  const configuration = {};
  for (const [name, [signature, decode]] of Object.entries(getters)) {
    configuration[name] = decode(await contractCall(url, address, build, signature, "", blockTag));
  }
  return configuration;
}

function validateVaultId(chainId, address, configuration) {
  const domain = Buffer.from(keccak_256(Buffer.from("USDD_VAULT_ID_V1", "ascii")));
  const packed = Buffer.concat([
    domain,
    uint256Bytes(chainId),
    addressBytes(address),
    addressBytes(configuration.usdt),
    addressBytes(configuration.proofVerifier),
    bytes32Bytes(configuration.verifierProgramId),
    bytes32Bytes(configuration.verifierConfigHash),
    bytes32Bytes(configuration.elementsGenesisHash),
    bytes32Bytes(configuration.usddAssetId),
    uint256Bytes(configuration.activeLiabilityCapUSDT6),
    uint256Bytes(configuration.minimumActivationChainwork)
  ]);
  const expected = `0x${crypto.createHash("sha256").update(packed).digest("hex")}`;
  assertEqual("VAULT_ID", expected, configuration.vaultId);
}

async function validateInitialState(url, address, build, blockTag) {
  const zeroWord = "0".repeat(64);
  const storageSlots = {};
  for (let slot = 0; slot <= 13; ++slot) {
    const value = await rpc(url, "eth_getStorageAt", [address, `0x${slot.toString(16)}`, blockTag]);
    const normalized = storageWord(value);
    const expected = slot === 13 ? `${"0".repeat(63)}1` : zeroWord;
    assertEqual(`initial storage slot ${slot}`, expected, normalized);
    storageSlots[slot] = `0x${normalized}`;
  }

  const finalizedState = await contractCall(url, address, build, "finalizedState()", "", blockTag);
  for (let index = 0; index < 9; ++index) {
    assertEqual(`initial finalizedState word ${index}`, zeroWord, word(finalizedState, index));
  }
  const zeroGetters = [
    "bridgeStateHash()",
    "nextDepositNonce()",
    "principalLiabilityUSDT6()",
    "totalDepositedUSDT6()",
    "totalRedeemedUSDT6()"
  ];
  for (const signature of zeroGetters) {
    const result = await contractCall(url, address, build, signature, "", blockTag);
    assertEqual(`initial ${signature}`, zeroWord, word(result));
  }
  const zeroArgument = zeroWord;
  assertEqual(
    "initial depositCommitmentByNonce(0)",
    zeroWord,
    word(await contractCall(url, address, build, "depositCommitmentByNonce(uint64)", zeroArgument, blockTag))
  );
  assertEqual(
    "initial spentBurnIds(0)",
    zeroWord,
    word(await contractCall(url, address, build, "spentBurnIds(bytes32)", zeroArgument, blockTag))
  );

  return {
    blockTag,
    allProtocolStateZero: true,
    reentrancyLockSlot13: "0x01",
    rawStorageSlots0Through13: storageSlots
  };
}

function decodeConstructorArguments(argumentsHex) {
  if (argumentsHex.length !== 7 * 64) {
    throw new Error(`Expected 224 constructor-argument bytes, received ${argumentsHex.length / 2}`);
  }
  const data = `0x${argumentsHex}`;
  return {
    usdt: decodeAddress(data, 0),
    proofVerifier: decodeAddress(data, 1),
    verifierProgramId: decodeBytes32(data, 2),
    verifierConfigHash: decodeBytes32(data, 3),
    elementsGenesisHash: decodeBytes32(data, 4),
    usddAssetId: decodeBytes32(data, 5),
    minimumActivationChainwork: decodeUint(data, 6)
  };
}

function validateConstructorArguments(arguments_, configuration) {
  for (const name of [
    "usdt",
    "proofVerifier",
    "verifierProgramId",
    "verifierConfigHash",
    "elementsGenesisHash",
    "usddAssetId",
    "minimumActivationChainwork"
  ]) {
    assertEqual(`constructor ${name}`, configuration[name], arguments_[name]);
  }
}

async function main() {
  const [rpcUrl, address, deploymentTransactionHash] = process.argv.slice(2);
  if (!rpcUrl || !/^0x[0-9a-fA-F]{40}$/.test(address ?? "")) {
    throw new Error(
      "Usage: node scripts/freeze-deployment.mjs <rpc-url> <vault-address> [deployment-transaction-hash]"
    );
  }

  const manifestPath = path.join(root, "artifacts", "build-manifest.json");
  const manifestBytes = fs.readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBytes);
  const build = manifest.contracts.USDDVaultV1;
  const runtimeHex = await rpc(rpcUrl, "eth_getCode", [address, "latest"]);
  if (!runtimeHex || runtimeHex === "0x") throw new Error("No deployed code at vault address");
  const actualRuntime = Buffer.from(runtimeHex.slice(2), "hex");
  const templateRuntime = Buffer.from(build.runtimeBytecodeTemplate.hex.slice(2), "hex");
  verifyRuntime(templateRuntime, actualRuntime, build.runtimeBytecodeTemplate.immutableReferences);

  const chainId = await rpc(rpcUrl, "eth_chainId");
  const latest = await rpc(rpcUrl, "eth_getBlockByNumber", ["latest", false]);
  let deploymentTransaction;
  let deploymentReceipt;
  if (deploymentTransactionHash) {
    deploymentTransaction = await rpc(rpcUrl, "eth_getTransactionByHash", [deploymentTransactionHash]);
    deploymentReceipt = await rpc(rpcUrl, "eth_getTransactionReceipt", [deploymentTransactionHash]);
    if (!deploymentTransaction || !deploymentReceipt) throw new Error("Deployment transaction not found");
    if (deploymentReceipt.status !== "0x1") throw new Error("Deployment transaction reverted");
    if (deploymentReceipt.contractAddress?.toLowerCase() !== address.toLowerCase()) {
      throw new Error("Deployment receipt contract address does not match vault address");
    }
  }

  const stateBlock = deploymentReceipt?.blockNumber ?? "latest";
  const immutableConfiguration = await readImmutableConfiguration(rpcUrl, address, build, stateBlock);
  assertEqual("PROTOCOL_VERSION", "1", immutableConfiguration.protocolVersion);
  assertEqual("ACTIVE_LIABILITY_CAP_USDT6", "1000000000000000", immutableConfiguration.activeLiabilityCapUSDT6);
  if (BigInt(immutableConfiguration.minimumActivationChainwork) === 0n) {
    throw new Error("MINIMUM_ACTIVATION_CHAINWORK must be nonzero");
  }
  validateVaultId(chainId, address, immutableConfiguration);

  const verifierRuntimeHex = await rpc(rpcUrl, "eth_getCode", [immutableConfiguration.proofVerifier, stateBlock]);
  if (!verifierRuntimeHex || verifierRuntimeHex === "0x") throw new Error("Immutable verifier has no code");
  const verifierRuntime = Buffer.from(verifierRuntimeHex.slice(2), "hex");
  assertEqual(
    "PROOF_VERIFIER_CODEHASH",
    immutableConfiguration.proofVerifierCodehash,
    digest(verifierRuntime).keccak256
  );
  const verifierReportedIdentity = {
    verifierProgramId: decodeBytes32(
      await signatureCall(rpcUrl, immutableConfiguration.proofVerifier, "verifierProgramId()", stateBlock)
    ),
    verifierConfigHash: decodeBytes32(
      await signatureCall(rpcUrl, immutableConfiguration.proofVerifier, "verifierConfigHash()", stateBlock)
    )
  };
  assertEqual(
    "verifier-reported program ID",
    immutableConfiguration.verifierProgramId,
    verifierReportedIdentity.verifierProgramId
  );
  assertEqual(
    "verifier-reported config hash",
    immutableConfiguration.verifierConfigHash,
    verifierReportedIdentity.verifierConfigHash
  );
  const usdtRuntimeHex = await rpc(rpcUrl, "eth_getCode", [immutableConfiguration.usdt, stateBlock]);
  if (!usdtRuntimeHex || usdtRuntimeHex === "0x") throw new Error("Immutable USDT has no code");
  const initialState = await validateInitialState(rpcUrl, address, build, stateBlock);

  const frozen = {
    schema: "usdd-vault-deployment-manifest-v1",
    chainId,
    address: address.toLowerCase(),
    observationBlock: { number: latest.number, hash: latest.hash },
    buildManifest: {
      path: "../build-manifest.json",
      ...digest(manifestBytes)
    },
    runtimeCode: {
      bytes: actualRuntime.length,
      ...digest(actualRuntime),
      hex: runtimeHex.toLowerCase()
    },
    templateVerification: {
      allNonImmutableBytesMatch: true,
      immutableReferences: build.runtimeBytecodeTemplate.immutableReferences
    },
    immutableConfiguration,
    immutableDependencyCode: {
      usdt: { address: immutableConfiguration.usdt, ...digest(Buffer.from(usdtRuntimeHex.slice(2), "hex")) },
      proofVerifier: {
        address: immutableConfiguration.proofVerifier,
        ...digest(verifierRuntime),
        reportedIdentity: verifierReportedIdentity
      }
    },
    initialState
  };

  if (deploymentTransactionHash) {
    const input = Buffer.from(deploymentTransaction.input.slice(2), "hex");
    const creationTemplate = build.creationBytecode.hex.slice(2).toLowerCase();
    if (!deploymentTransaction.input.slice(2).toLowerCase().startsWith(creationTemplate)) {
      throw new Error("Deployment initcode does not start with frozen creation-bytecode template");
    }
    const constructorArguments = decodeConstructorArguments(
      deploymentTransaction.input.slice(2 + creationTemplate.length)
    );
    validateConstructorArguments(constructorArguments, immutableConfiguration);
    frozen.deploymentTransaction = {
      hash: deploymentTransactionHash.toLowerCase(),
      inputBytes: input.length,
      ...digest(input),
      constructorArguments
    };
  }

  const outputDirectory = path.join(root, "artifacts", "deployments");
  fs.mkdirSync(outputDirectory, { recursive: true });
  const output = path.join(outputDirectory, `${BigInt(chainId)}-${address.toLowerCase()}.json`);
  fs.writeFileSync(output, `${JSON.stringify(frozen, null, 2)}\n`);
  process.stdout.write(`${path.relative(root, output)} written.\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
