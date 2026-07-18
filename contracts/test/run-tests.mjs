import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import ganache from "ganache";
import solc from "solc";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function soliditySources(directory) {
  const sources = {};
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      Object.assign(sources, soliditySources(absolute));
    } else if (entry.name.endsWith(".sol")) {
      const relative = path.relative(root, absolute).split(path.sep).join("/");
      sources[relative] = { content: fs.readFileSync(absolute, "utf8") };
    }
  }
  return sources;
}

function compile() {
  const input = {
    language: "Solidity",
    sources: soliditySources(root),
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "shanghai",
      viaIR: false,
      metadata: { appendCBOR: false, bytecodeHash: "none", useLiteralContent: true },
      outputSelection: {
        "*": {
          "*": ["abi", "evm.bytecode.object", "evm.methodIdentifiers"]
        }
      }
    }
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const diagnostics = output.errors ?? [];
  for (const diagnostic of diagnostics) {
    if (diagnostic.severity === "error") {
      process.stderr.write(`${diagnostic.formattedMessage}\n`);
    }
  }
  if (diagnostics.some((diagnostic) => diagnostic.severity === "error")) {
    throw new Error("Solidity compilation failed");
  }
  return output.contracts;
}

function quantity(value) {
  return `0x${BigInt(value).toString(16)}`;
}

async function receipt(provider, transactionHash) {
  const mined = await provider.request({
    method: "eth_getTransactionReceipt",
    params: [transactionHash]
  });
  if (!mined) throw new Error(`No receipt for ${transactionHash}`);
  return mined;
}

async function deploy(provider, from, artifact, label) {
  const transactionHash = await provider.request({
    method: "eth_sendTransaction",
    params: [{ from, data: `0x${artifact.evm.bytecode.object}`, gas: quantity(110_000_000) }]
  });
  const mined = await receipt(provider, transactionHash);
  if (mined.status !== "0x1" || !mined.contractAddress) {
    throw new Error(`${label} deployment reverted`);
  }
  return mined.contractAddress;
}

async function invoke(provider, from, target, selector, label) {
  let transactionHash;
  try {
    transactionHash = await provider.request({
      method: "eth_sendTransaction",
      params: [{ from, to: target, data: `0x${selector}`, gas: quantity(110_000_000) }]
    });
  } catch (error) {
    throw new Error(`${label} RPC failure: ${error.shortMessage ?? error.message}`);
  }
  const mined = await receipt(provider, transactionHash);
  if (mined.status !== "0x1") {
    let detail = "";
    try {
      await provider.request({
        method: "eth_call",
        params: [{ from, to: target, data: `0x${selector}`, gas: quantity(110_000_000) }, "latest"]
      });
    } catch (error) {
      const revertData = error.data?.result ?? error.data ?? error.info?.error?.data?.result;
      detail = `: ${error.shortMessage ?? error.message}${revertData ? ` (${revertData})` : ""}`;
    }
    throw new Error(`${label} reverted${detail}`);
  }
  process.stdout.write(`ok  ${label}\n`);
}

async function runNoArgumentTests(provider, from, target, artifact, suiteName) {
  const methods = Object.entries(artifact.evm.methodIdentifiers)
    .filter(([signature]) => signature.startsWith("test") && signature.endsWith("()"))
    .sort(([left], [right]) => left.localeCompare(right));
  for (const [signature, selector] of methods) {
    const snapshot = await provider.request({ method: "evm_snapshot", params: [] });
    try {
      await invoke(provider, from, target, selector, `${suiteName}.${signature}`);
    } finally {
      await provider.request({ method: "evm_revert", params: [snapshot] });
    }
  }
  return methods.length;
}

async function main() {
  const contracts = compile();
  const vaultArtifact = contracts["test/USDDVaultV1Test.sol"].USDDVaultV1Test;
  const htlcArtifact = contracts["test/USDTHTLCTest.sol"].USDTHTLCTest;

  const provider = ganache.provider({
    logging: { quiet: true },
    chain: {
      hardfork: "shanghai",
      allowUnlimitedContractSize: true,
      allowUnlimitedInitCodeSize: true
    },
    miner: { blockGasLimit: 120_000_000 },
    wallet: { totalAccounts: 2, defaultBalance: 1_000 }
  });

  try {
    const [from] = await provider.request({ method: "eth_accounts", params: [] });
    const vaultTest = await deploy(provider, from, vaultArtifact, "USDDVaultV1Test");
    const htlcTest = await deploy(provider, from, htlcArtifact, "USDTHTLCTest");

    let passed = 0;
    passed += await runNoArgumentTests(provider, from, vaultTest, vaultArtifact, "USDDVaultV1Test");
    passed += await runNoArgumentTests(provider, from, htlcTest, htlcArtifact, "USDTHTLCTest");

    const timed = htlcArtifact.evm.methodIdentifiers;
    await invoke(
      provider,
      from,
      htlcTest,
      timed["prepareTimedDeadlineScenario()"],
      "USDTHTLCTest.prepareTimedDeadlineScenario()"
    );
    await provider.request({ method: "evm_increaseTime", params: [101] });
    await provider.request({ method: "evm_mine", params: [] });
    await invoke(
      provider,
      from,
      htlcTest,
      timed["checkTimedElementsDeadline()"],
      "USDTHTLCTest.checkTimedElementsDeadline()"
    );
    await provider.request({ method: "evm_increaseTime", params: [24 * 60 * 60] });
    await provider.request({ method: "evm_mine", params: [] });
    await invoke(
      provider,
      from,
      htlcTest,
      timed["finishTimedExternalRefund()"],
      "USDTHTLCTest.finishTimedExternalRefund()"
    );
    passed += 3;

    process.stdout.write(`\n${passed} Solidity integration tests passed.\n`);
  } finally {
    provider.disconnect();
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
