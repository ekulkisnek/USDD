# USDD Ethereum contracts (V1)

This directory contains two deliberately separate, ownerless primitives:

- `USDDVaultV1`: a long-lived Ethereum USDT reserve. Deposits create an append-only commitment for the Elements minting guest. Redemptions require a burn leaf under a proof-finalized Elements accumulator root.
- `USDTHTLC`: a single-swap Solidity escrow with a SHA-256 secret, fixed funder and recipients, and an enforced cross-chain refund ordering.

Neither contract has an owner, proxy, pause, token sweep, arbitrary external call, or yield-management path. The vault's token, Elements network, USDD asset, proof program, verifier configuration hash, verifier address, and verifier runtime code hash are immutable. At construction and before every proof, the vault checks that the verifier's identity getters match those pinned values. Production must deploy an audited transparent-proof verifier; `MockRawProofVerifier` is intentionally proofless and test-only.

### Production verifier blocker

The vault can pin the verifier wrapper's address, runtime `EXTCODEHASH`, reported program ID, and reported configuration hash. Those checks cannot make a proxy or dependency graph immutable: unchanged wrapper bytecode can `DELEGATECALL` a mutable implementation, read mutable storage, call a replaceable verifier/key registry, or report a stable identity while verification behavior changes. A trustless production deployment therefore remains blocked until the pinned address contains a self-contained, audited wrapper with no proxy path, no mutable verification configuration, and no mutable external verification dependency. Its `verifierConfigHash` must commit the entire proof-system and public-input configuration.

## Run tests

```sh
npm install
npm test
```

The custom runner compiles with Solidity 0.8.30 and executes the Solidity suites on an isolated local EVM. Each ordinary test runs against an EVM snapshot; the three-stage deadline test advances local time explicitly.

The tests cover canonical deposit commitments, per-deposit and aggregate caps, exact token deltas, legacy no-return tokens, fee/false-return rejection, state sequencing, nonzero Elements consensus-state commitments, canonical empty burn roots, bounded burn growth, verifier code-hash pinning, burn-index bounds, 64-level proofs, recipient binding, replay, insolvency, HTLC deadline ordering and endpoint validation, permissionless execution, claim/refund exclusivity, and locked donations.

## Reproducible build and deployment freeze

`artifacts/build-manifest.json` and `artifacts/solc-standard-input.json` are the only authoritative compiled artifacts. The ignored `build/` directory is intentionally not generated or used.

```sh
npm run build
node scripts/freeze-deployment.mjs <rpc-url> <vault-address> <direct-deployment-tx-hash> <verifier-preflight-json>
```

The build pins stock solc 0.8.30, optimizer runs 200, Shanghai EVM output, and metadata settings. The deployment freezer requires the direct deployment transaction, checks every non-immutable runtime byte, records the actual immutable-patched code hash, reads every immutable vault getter, independently queries the verifier's program/config identity getters, validates the verifier code hash and recomputed vault ID, confirms pristine protocol storage, and decodes and compares all constructor arguments. Factory deployments require separate authenticated creation-trace tooling and are not accepted by this freezer.

The verifier preflight is also mandatory. It rejects the checked-in `MockRawProofVerifier` under every immutable constructor identity, runtime storage access, `CALL`, `CALLCODE`, `DELEGATECALL`, contract creation, `SELFDESTRUCT`, and every `STATICCALL`, `EXTCODE*`, or `BALANCE` occurrence. It also verifies that the runtime matches a SHA-256-pinned compiler artifact with an empty storage layout. Version 2 intentionally has no documentation-only exception: free-form prose cannot prove that an external target is fixed. A future verifier that needs an EVM precompile remains blocked until the preflight implements and audits machine-verifiable target/code-identity extraction. This scan still does **not** prove verifier correctness or replace source review and adversarial testing.

The preflight JSON has schema `usdd-verifier-runtime-preflight-v2`, binds the deployed runtime code hash, and identifies a SHA-256-pinned compiler artifact. `storageLayoutJsonPath` and `runtimeBytecodeJsonPath` are arrays of JSON object keys locating the compiler's storage-layout and deployed-bytecode records. `documentedExternalDependencies` must be an empty array:

```json
{
  "schema": "usdd-verifier-runtime-preflight-v2",
  "runtimeCodeKeccak256": "0x...",
  "compilerArtifact": {
    "path": "./verifier-solc-output.json",
    "sha256": "0x...",
    "storageLayoutJsonPath": ["contracts", "Verifier.sol", "Verifier", "storageLayout"],
    "runtimeBytecodeJsonPath": ["contracts", "Verifier.sol", "Verifier", "evm", "deployedBytecode"]
  },
  "documentedExternalDependencies": []
}
```

## Scope boundary

These contracts are not the complete bridge. In particular, this directory does not implement:

- the production transparent proof system or verifier;
- the Ethereum-finality and Elements/BIP300 guest programs;
- the SimplicityHL mint/burn covenant;
- relayer software (relayers are permissionless and hold no authority);
- a Tron consensus/state proof verifier.

The byte-exact hashing and ABI contract for those components is specified in [ENCODING.md](./ENCODING.md).

### Tron/TVM status: BLOCKED pending a separate compiler build

The checked-in manifest is an EVM build made with stock `solc` 0.8.30. It is not evidence of TVM compatibility. Before deploying the HTLC on Tron, pin an exact TRON-maintained Solidity compiler version supported by the target TVM, compile the same semantics, compare ABI/hash behavior with the vectors, and run the full claim/refund and real-USDT compatibility suite on a Tron test network. Until that artifact and test evidence exist, Tron deployment is intentionally marked blocked.
