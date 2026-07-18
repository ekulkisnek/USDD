import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { keccak_256 } from "@noble/hashes/sha3";
import solc from "solc";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const artifactDirectory = path.join(root, "artifacts");
const expectedCompiler = "0.8.30+commit.73712a01.Emscripten.clang";
const productionSources = [
  "src/USDDVaultV1.sol",
  "src/USDTHTLC.sol",
  "src/interfaces/IRawProofVerifier.sol",
  "src/libraries/ExactSafeERC20.sol",
  "src/libraries/Sha256SparseMerkle.sol"
].sort();

const compilerSettings = {
  optimizer: { enabled: true, runs: 200 },
  evmVersion: "shanghai",
  viaIR: false,
  metadata: {
    appendCBOR: false,
    bytecodeHash: "none",
    useLiteralContent: true
  }
};

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function hashes(bytes) {
  return {
    sha256: `0x${sha256(bytes)}`,
    keccak256: `0x${hex(keccak_256(bytes))}`
  };
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
  }
  return value;
}

function serialized(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function bytecodeRecord(object, extra = {}) {
  const bytes = Buffer.from(object, "hex");
  return {
    bytes: bytes.length,
    ...hashes(bytes),
    hex: `0x${object}`,
    ...extra
  };
}

function sourceInput() {
  return Object.fromEntries(
    productionSources.map((sourceName) => [
      sourceName,
      { content: fs.readFileSync(path.join(root, sourceName), "utf8") }
    ])
  );
}

function compile() {
  if (solc.version() !== expectedCompiler) {
    throw new Error(`Wrong solc: expected ${expectedCompiler}, received ${solc.version()}`);
  }

  const input = {
    language: "Solidity",
    sources: sourceInput(),
    settings: {
      ...compilerSettings,
      outputSelection: {
        "*": {
          "*": [
            "abi",
            "metadata",
            "storageLayout",
            "evm.bytecode.object",
            "evm.bytecode.linkReferences",
            "evm.deployedBytecode.object",
            "evm.deployedBytecode.immutableReferences",
            "evm.deployedBytecode.linkReferences",
            "evm.methodIdentifiers"
          ]
        }
      }
    }
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors ?? []).filter((diagnostic) => diagnostic.severity === "error");
  if (errors.length) {
    throw new Error(errors.map((diagnostic) => diagnostic.formattedMessage).join("\n"));
  }
  return { input, output };
}

function contractRecord(artifact) {
  const creation = artifact.evm.bytecode;
  const runtime = artifact.evm.deployedBytecode;
  if (Object.keys(creation.linkReferences).length || Object.keys(runtime.linkReferences).length) {
    throw new Error("Unexpected unlinked library reference");
  }
  return {
    abi: artifact.abi,
    methodIdentifiers: artifact.evm.methodIdentifiers,
    storageLayout: artifact.storageLayout,
    creationBytecode: bytecodeRecord(creation.object, {
      note: "Constructor-argument-free initcode; deployment transaction appends ABI-encoded constructor arguments."
    }),
    runtimeBytecodeTemplate: bytecodeRecord(runtime.object, {
      immutableReferences: runtime.immutableReferences,
      note: "Compiler template with zero-filled immutable ranges; this is not the deployed EXTCODEHASH. Freeze an actual deployment with scripts/freeze-deployment.mjs."
    })
  };
}

function buildFiles() {
  const { input, output } = compile();
  const standardInputText = serialized(input);
  const vault = contractRecord(output.contracts["src/USDDVaultV1.sol"].USDDVaultV1);
  const htlc = contractRecord(output.contracts["src/USDTHTLC.sol"].USDTHTLC);
  const depositMapping = vault.storageLayout.storage.find(
    (entry) => entry.label === "depositCommitmentByNonce"
  );
  if (!depositMapping || depositMapping.slot !== "11") {
    throw new Error(`depositCommitmentByNonce moved from frozen slot 11 to ${depositMapping?.slot ?? "missing"}`);
  }

  const sourceHashes = Object.fromEntries(
    productionSources.map((sourceName) => {
      const bytes = Buffer.from(input.sources[sourceName].content, "utf8");
      return [sourceName, hashes(bytes)];
    })
  );
  const manifest = {
    schema: "usdd-solidity-build-manifest-v1",
    compiler: {
      package: "solc",
      version: solc.version()
    },
    settings: compilerSettings,
    standardJsonInput: {
      path: "artifacts/solc-standard-input.json",
      bytes: Buffer.byteLength(standardInputText),
      sha256: `0x${sha256(Buffer.from(standardInputText, "utf8"))}`
    },
    sourceHashes,
    protocolStorage: {
      depositCommitmentByNonce: {
        slot: 11,
        solidityKeyExpression: "keccak256(abi.encode(uint64(nonce), uint256(11)))",
        valueEncoding: "bytes32 depositId"
      }
    },
    contracts: {
      USDDVaultV1: {
        source: "src/USDDVaultV1.sol",
        contract: "USDDVaultV1",
        ...vault
      },
      USDTHTLC: {
        source: "src/USDTHTLC.sol",
        contract: "USDTHTLC",
        ...htlc
      }
    }
  };
  return {
    "solc-standard-input.json": standardInputText,
    "build-manifest.json": serialized(manifest)
  };
}

function main() {
  const check = process.argv.includes("--check");
  const files = buildFiles();
  fs.mkdirSync(artifactDirectory, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    const target = path.join(artifactDirectory, name);
    if (check) {
      if (!fs.existsSync(target) || fs.readFileSync(target, "utf8") !== content) {
        throw new Error(`${path.relative(root, target)} is stale; run npm run build`);
      }
    } else {
      fs.writeFileSync(target, content);
    }
  }
  process.stdout.write(check ? "Build manifest matches sources.\n" : "Build manifest written.\n");
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
}
