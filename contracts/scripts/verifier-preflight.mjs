import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { keccak_256 } from "@noble/hashes/sha3";

export const PREFLIGHT_SCHEMA = "usdd-verifier-runtime-preflight-v2";

const OPCODES = new Map([
  [0x31, "BALANCE"],
  [0x3b, "EXTCODESIZE"],
  [0x3c, "EXTCODECOPY"],
  [0x3f, "EXTCODEHASH"],
  [0x54, "SLOAD"],
  [0x55, "SSTORE"],
  [0x5c, "TLOAD"],
  [0x5d, "TSTORE"],
  [0xf0, "CREATE"],
  [0xf1, "CALL"],
  [0xf2, "CALLCODE"],
  [0xf4, "DELEGATECALL"],
  [0xf5, "CREATE2"],
  [0xfa, "STATICCALL"],
  [0xff, "SELFDESTRUCT"]
]);

const STORAGE_OPCODES = new Set(["SLOAD", "SSTORE", "TLOAD", "TSTORE"]);
const FORBIDDEN_OPCODES = new Set([
  "CREATE",
  "CREATE2",
  "CALL",
  "CALLCODE",
  "DELEGATECALL",
  "SELFDESTRUCT"
]);
const EXTERNAL_DEPENDENCY_OPCODES = new Set([
  "BALANCE",
  "EXTCODESIZE",
  "EXTCODECOPY",
  "EXTCODEHASH",
  "STATICCALL"
]);

function hexBody(value) {
  const body = value.startsWith("0x") ? value.slice(2) : value;
  if (body.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(body)) throw new Error("Invalid runtime bytecode hex");
  return body;
}

export function runtimeBytes(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  return Buffer.from(hexBody(value), "hex");
}

export function runtimeKeccak256(runtime) {
  return `0x${Buffer.from(keccak_256(runtimeBytes(runtime))).toString("hex")}`;
}

export function disassembleRelevantOpcodes(runtime) {
  const bytes = runtimeBytes(runtime);
  const found = [];
  for (let pc = 0; pc < bytes.length;) {
    const opcode = bytes[pc];
    const name = OPCODES.get(opcode);
    if (name) found.push({ programCounter: pc, opcode: name });
    if (opcode >= 0x60 && opcode <= 0x7f) {
      pc += 2 + opcode - 0x60;
    } else {
      pc += 1;
    }
  }
  return found;
}

function immutableOffsets(references) {
  const ignored = new Set();
  for (const ranges of Object.values(references ?? {})) {
    for (const { start, length } of ranges) {
      for (let offset = start; offset < start + length; ++offset) ignored.add(offset);
    }
  }
  return ignored;
}

export function matchesRuntimeTemplate(runtime, template) {
  const actual = runtimeBytes(runtime);
  const expected = runtimeBytes(template.hex);
  if (actual.length !== expected.length) return false;
  const ignored = immutableOffsets(template.immutableReferences);
  for (let offset = 0; offset < actual.length; ++offset) {
    if (!ignored.has(offset) && actual[offset] !== expected[offset]) return false;
  }
  return true;
}

function formatOpcodes(entries) {
  return entries.map(({ programCounter, opcode }) => `${opcode}@${programCounter}`).join(", ");
}

function evidenceDigest(bytes) {
  return `0x${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function valueAtPath(value, jsonPath, label) {
  if (!Array.isArray(jsonPath) || jsonPath.length === 0) throw new Error(`Missing ${label} JSON path`);
  let current = value;
  for (const key of jsonPath) {
    if (typeof key !== "string" || current === null || typeof current !== "object" || !(key in current)) {
      throw new Error(`Invalid ${label} JSON path`);
    }
    current = current[key];
  }
  return current;
}

function validateCompilerArtifact(runtime, specification, evidencePath) {
  if (
    !specification || typeof specification.path !== "string" || specification.path.length === 0
    || !/^0x[0-9a-fA-F]{64}$/.test(specification.sha256 ?? "")
  ) {
    throw new Error("Verifier preflight must identify a compiler artifact and SHA-256");
  }
  const artifactPath = path.resolve(path.dirname(evidencePath), specification.path);
  const artifactBytes = fs.readFileSync(artifactPath);
  const actualHash = evidenceDigest(artifactBytes);
  if (actualHash.toLowerCase() !== specification.sha256.toLowerCase()) {
    throw new Error("Verifier compiler artifact SHA-256 mismatch");
  }
  const artifact = JSON.parse(artifactBytes);
  const storageLayout = valueAtPath(artifact, specification.storageLayoutJsonPath, "storage layout");
  if (!storageLayout || !Array.isArray(storageLayout.storage) || storageLayout.storage.length !== 0) {
    throw new Error("Verifier compiler artifact must report an empty storage layout");
  }
  const runtimeTemplate = valueAtPath(artifact, specification.runtimeBytecodeJsonPath, "runtime bytecode");
  if (
    !runtimeTemplate || typeof runtimeTemplate.object !== "string"
    || !matchesRuntimeTemplate(runtime, {
      hex: runtimeTemplate.object,
      immutableReferences: runtimeTemplate.immutableReferences ?? {}
    })
  ) {
    throw new Error("Verifier runtime does not match the compiler artifact");
  }
  return {
    path: specification.path,
    sha256: actualHash,
    storageLayoutEntries: 0,
    runtimeMatchesCompilerArtifact: true
  };
}

export function validatePreflightEvidence(runtime, analysis, evidence, evidenceBytes, evidencePath) {
  if (!evidence || evidence.schema !== PREFLIGHT_SCHEMA) throw new Error("Missing verifier preflight evidence");
  if (evidence.runtimeCodeKeccak256?.toLowerCase() !== analysis.runtimeCodeKeccak256.toLowerCase()) {
    throw new Error("Verifier preflight runtime code hash mismatch");
  }
  const compilerArtifact = validateCompilerArtifact(runtime, evidence.compilerArtifact, evidencePath);

  if (
    !Array.isArray(evidence.documentedExternalDependencies)
    || evidence.documentedExternalDependencies.length !== 0
  ) {
    throw new Error("Verifier preflight v2 requires an empty external-dependency list");
  }

  return {
    ...analysis,
    evidenceSha256: evidenceDigest(evidenceBytes),
    compilerArtifact,
    documentedExternalDependencies: []
  };
}

export function analyzeVerifierRuntime(runtime, blockedFingerprints = []) {
  for (const fingerprint of blockedFingerprints) {
    if (matchesRuntimeTemplate(runtime, fingerprint.runtimeBytecodeTemplate)) {
      throw new Error(`Forbidden verifier runtime fingerprint: ${fingerprint.name}`);
    }
  }

  const relevant = disassembleRelevantOpcodes(runtime);
  const storage = relevant.filter((entry) => STORAGE_OPCODES.has(entry.opcode));
  if (storage.length !== 0) {
    throw new Error(`Verifier runtime accesses mutable storage: ${formatOpcodes(storage)}`);
  }
  const forbidden = relevant.filter((entry) => FORBIDDEN_OPCODES.has(entry.opcode));
  if (forbidden.length !== 0) {
    throw new Error(`Verifier runtime contains forbidden opcodes: ${formatOpcodes(forbidden)}`);
  }
  const externalDependencies = relevant.filter((entry) => EXTERNAL_DEPENDENCY_OPCODES.has(entry.opcode));
  if (externalDependencies.length !== 0) {
    throw new Error(
      `Verifier runtime contains unauthenticated external-dependency opcodes: ${formatOpcodes(externalDependencies)}`
    );
  }
  return {
    runtimeBytes: runtimeBytes(runtime).length,
    runtimeCodeKeccak256: runtimeKeccak256(runtime),
    storageOpcodes: [],
    forbiddenOpcodes: [],
    externalDependencies: []
  };
}

export function preflightVerifierRuntime(runtime, blockedFingerprints, evidence, evidenceBytes, evidencePath) {
  const analysis = analyzeVerifierRuntime(runtime, blockedFingerprints);
  return validatePreflightEvidence(runtime, analysis, evidence, evidenceBytes, evidencePath);
}
