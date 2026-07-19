import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  analyzeVerifierRuntime,
  disassembleRelevantOpcodes,
  PREFLIGHT_SCHEMA,
  preflightVerifierRuntime,
  runtimeKeccak256
} from "../scripts/verifier-preflight.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function sha256(bytes) {
  return `0x${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

test("known mock verifier fingerprint is rejected for every immutable identity", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "artifacts", "build-manifest.json")));
  const [fingerprint] = manifest.blockedVerifierFingerprints;
  const runtime = Buffer.from(fingerprint.runtimeBytecodeTemplate.hex.slice(2), "hex");
  for (const ranges of Object.values(fingerprint.runtimeBytecodeTemplate.immutableReferences)) {
    for (const { start, length } of ranges) runtime.fill(0xa5, start, start + length);
  }
  assert.throws(
    () => analyzeVerifierRuntime(runtime, manifest.blockedVerifierFingerprints),
    /Forbidden verifier runtime fingerprint: MockRawProofVerifier/
  );
});

test("opcode scan skips PUSH data and rejects storage, delegation, and destruction", () => {
  const pushed = Buffer.concat([Buffer.from([0x7f]), Buffer.alloc(32, 0xf4), Buffer.from([0x00])]);
  assert.deepEqual(disassembleRelevantOpcodes(pushed), []);
  assert.throws(() => analyzeVerifierRuntime(Buffer.from([0x54, 0x00])), /mutable storage: SLOAD@0/);
  assert.throws(() => analyzeVerifierRuntime(Buffer.from([0xf4, 0x00])), /DELEGATECALL@0/);
  assert.throws(() => analyzeVerifierRuntime(Buffer.from([0xff])), /SELFDESTRUCT@0/);
  assert.throws(
    () => analyzeVerifierRuntime(Buffer.from("60026000fa00", "hex")),
    /unauthenticated external-dependency opcodes: STATICCALL@4/
  );
});

test("self-contained runtime evidence and empty compiler layout are mandatory", () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "usdd-verifier-preflight-"));
  try {
    // Syntactically scanned dependency-free test bytecode; execution semantics
    // are irrelevant to this deterministic preflight-unit test.
    const runtime = Buffer.from("60006000", "hex");
    const analysis = analyzeVerifierRuntime(runtime);
    assert.deepEqual(analysis.externalDependencies, []);

    const artifact = {
      storageLayout: { storage: [], types: {} },
      runtime: { object: runtime.toString("hex"), immutableReferences: {} }
    };
    const artifactBytes = Buffer.from(`${JSON.stringify(artifact)}\n`);
    const artifactPath = path.join(temporary, "verifier-artifact.json");
    fs.writeFileSync(artifactPath, artifactBytes);

    const evidence = {
      schema: PREFLIGHT_SCHEMA,
      runtimeCodeKeccak256: runtimeKeccak256(runtime),
      compilerArtifact: {
        path: "./verifier-artifact.json",
        sha256: sha256(artifactBytes),
        storageLayoutJsonPath: ["storageLayout"],
        runtimeBytecodeJsonPath: ["runtime"]
      },
      documentedExternalDependencies: []
    };
    const evidencePath = path.join(temporary, "preflight.json");
    const evidenceBytes = Buffer.from(`${JSON.stringify(evidence)}\n`);
    fs.writeFileSync(evidencePath, evidenceBytes);

    const report = preflightVerifierRuntime(runtime, [], evidence, evidenceBytes, evidencePath);
    assert.equal(report.compilerArtifact.storageLayoutEntries, 0);
    assert.equal(report.compilerArtifact.runtimeMatchesCompilerArtifact, true);

    const documented = {
      ...evidence,
      documentedExternalDependencies: [{
        programCounter: 1,
        opcode: "STATICCALL",
        dependency: "free-form text is not proof"
      }]
    };
    assert.throws(
      () => preflightVerifierRuntime(runtime, [], documented, Buffer.from(JSON.stringify(documented)), evidencePath),
      /requires an empty external-dependency list/
    );

    const mutableArtifact = { ...artifact, storageLayout: { storage: [{ slot: "0" }], types: {} } };
    const mutableBytes = Buffer.from(`${JSON.stringify(mutableArtifact)}\n`);
    fs.writeFileSync(artifactPath, mutableBytes);
    const mutableEvidence = {
      ...evidence,
      compilerArtifact: { ...evidence.compilerArtifact, sha256: sha256(mutableBytes) }
    };
    assert.throws(
      () => preflightVerifierRuntime(
        runtime,
        [],
        mutableEvidence,
        Buffer.from(JSON.stringify(mutableEvidence)),
        evidencePath
      ),
      /empty storage layout/
    );
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});
