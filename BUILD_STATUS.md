# Build status

This file separates tested protocol plumbing from cryptographic systems that do
not yet exist. Nothing below upgrades an unmeasured item to PASS.

## Implemented and host-tested in this workspace

- canonical, exact-decoding schema-2 records and domain-separated SHA-256 IDs;
- six-decimal USDT to eight-decimal USDD conversion at exactly ×100;
- a 20,000,000-USDT per-deposit, per-mint-batch, and per-burn ceiling that
  preserves transaction-wide Elements explicit-output headroom for authority,
  fee, and change outputs;
- one-controller sequential per-vault nonce consumption and replay rejection;
- irreversible burn records and deterministic outpoint-bound redemption IDs;
- exact depth-64 cumulative burn accumulator roots and proofs;
- cross-chain reserve/supply conservation checks;
- immutable manifest validation for Drivechain slot 24;
- strict SHA-256 proof-journal envelope with explicit success marker, program
  binding, payload hash, exact typed public-output decoding, and trailing-byte
  rejection;
- a pinned SP1 6.3.1 host verifier adapter that accepts only canonical raw
  compressed proofs, binds the canonical `HashableKey::hash_bytes` program ID,
  enforces SHA-256-only public-value commitments, rejects Groth16/PLONK/core
  modes and trailing bytes, and converts upstream panics into rejection;
- Ethereum-proved execution timestamps separated from authenticated
  Elements/BMM parent time, with schema-1 inputs rejected;
- outbound full-consensus-state digest and a derived verifier configuration
  that binds the Bitcoin/Elements networks and finality policy;
- paired Elements-node plumbing that owns exact bounded annex bytes and exposes
  BIP301-authenticated parent MTP through an officially generated
  `current_bmm_parent_mtp : 1 -> Maybe Word64` jet (decoder item 51, fixed CMR,
  deterministic cost, upstream model/C differential tests);
- ownerless Solidity vault and inventory HTLC with exact USDT balance deltas,
  canonical empty-root/burn-growth checks, hardened endpoints, and mandatory
  deployment-transaction provenance; verifier preflight v2 rejects mutable
  storage and every unauthenticated external-dependency opcode rather than
  accepting documentation-only target claims;
- a source-only Elements inventory HTLC with a fixed SHA-256 hashlock, fixed
  and distinct BIP340 claimant/refund keys, signed full-transaction spends,
  timestamp refund, strict renderer, and a compiler-pinned syntax check;
- host-testable proof claim/output cores behind non-accepting verifier traits;
- a `no_std`, exact-decoding Ethereum inbound MPT core that authenticates the
  vault account/code hash and 1..64 consecutive deposit storage commitments
  beneath a finalized execution state root, plus a native `std` Sepolia
  finality verifier pinned to Helios consensus core commit `204c998a...` that
  binds prior committees/header, verifies SSZ/BLS/finality/execution, derives
  every public field, and passes a real Sepolia update fixture; its canonical
  private witness is limited to 512 KiB and two committee updates;
- a pinned SP1 6.3.1 Ethereum-state source entrypoint that checks each hint
  length before allocation, exact-decodes all accepted records, invokes the
  same finality/MPT verifier, and commits only strict-journal bytes; the pure
  wrapper and host target compile/test, but no zkVM artifact is claimed;
- a `no_std` Bitcoin/BIP301 foundation with exact 80-byte header decoding,
  SHA256d internal/display byte-order tests, compact-target and PoW checks,
  overflow-safe block/chainwork arithmetic, the actual LayerTwo Signet
  retarget parameters, exact parent linkage, exact serialized/context-free
  block/transaction/Merkle and Signet-solution validation, and the Elements
  fork's unique minimal slot-24 M7 parser; the bounded replay tranche also
  covers exact M1/M2 activation,
  proposal expiry/replacement, positive-only CTIP transitions, atomic failure,
  and M8-to-M7/P binding. It emits no M6 and rejects every CTIP decrease;
- CLI surfaces for amounts, IDs, canonical decoding, burn-tree and auxiliary
  general-purpose Merkle proofs, audits,
  journals, manifests, and launch-gate reports;
- machine-readable launch gates that default missing or unmeasured evidence to
  BLOCKED.

## Verification in the current worktrees

- Rust workspace: 121 tests pass; all-target/all-feature Clippy passes with
  warnings denied; protocol, proof, Ethereum-MPT, and Bitcoin/BMM crates pass
  their `no_std` checks. The Bitcoin/BMM crate has 31 passing tests, including
  differential-style local-fork proposal and CTIP vectors.
- Ethereum finality additions: 15 inbound tests pass, including one real
  Sepolia SSZ/BLS transition and direct 4096-slot-bound coverage; the nested
  SP1 source wrapper has 1 host test, and both focused crates pass Clippy with
  warnings denied. These focused counts are included separately because the
  nested guest is intentionally not a root-workspace member.
- SP1 provenance check verifies the exact registry checksums and packaged Cargo
  VCS metadata for `sp1-verifier` and `sp1-zkvm` 6.3.1 against commit
  `8252c2905ce32964df68248117015c61ebb854db`.
- Solidity: 25 vault/HTLC integration tests and 3 immutable-verifier preflight
  tests pass; the checked build manifest exactly matches the sources.
- TypeScript: 17 exact-codec/cross-language tests plus both type-check builds
  pass.
- Python/Simplicity formats: 30 strict format, state, controller-transaction,
  renderer, and HTLC tests pass; the rendered inventory source syntax-checks
  with pinned SimplicityHL
  `f62adf11e16816dd8f33f16edb5ff9f4c4b45e36` v0.6.0.
- Generated Simplicity parent-MTP jet: 200 upstream model/C QuickCheck cases,
  479 upstream regressions, and 106 vendored C checks pass.
- Elements: the 541-case `test_bitcoin` suite reports no errors, including all
  21 script tests; one pre-existing script-assets fixture is skipped because
  `DIR_UNIT_TEST_DATA` is unset. The full macOS arm64 release build links
  successfully. The local `elementsd` SHA-256 is
  `0d856ab910ec79c8cbc60ce5a4cf1dcff4425ab1015e45958f6ade1d548ad8f0`.

These are implementation tests, not independent audits or launch-gate
evidence. `SECURITY_REVIEW.md` records the internal adversarial review, three
resolved findings, and the remaining deployment blockers; it explicitly does
not satisfy an independent-audit gate.

## Not implemented or not cryptographically demonstrated

- complete SP1 6.3.1 Ethereum consensus-finality artifact (source entrypoint,
  MPT verification, and native Sepolia light-client verification are
  implemented and host-tested, but the host lacks `cargo prove` and the
  `succinct` toolchain, so no zkVM-target ELF/program ID, executor fixture, or
  raw-compressed positive proof exists);
- complete Elements full-validity proof guest;
- complete Bitcoin/BMM canonical-ancestry proof guest (the header/PoW/work,
  difficulty, linkage, exact block/Merkle/Signet solution, strict M7, and
  bounded slot-24 positive-only BIP300 replay foundation is implemented; full
  contextual Bitcoin/UTXO/scripts, all-slot BIP300, M3/M4/M6,
  fork-choice/reorg, and confirmation logic are not);
- production SP1 guest ELFs and reproducible program IDs;
- a positive raw-compressed SP1 proof fixture demonstrating the complete host
  verifier success path;
- generated, deterministically costed SP1 verification inside Simplicity and a
  deployable immutable Ethereum raw-compressed verifier; pinned SP1 6.3.1
  officially exports on-chain encodings/contracts only for the forbidden
  PLONK and Groth16 wrappers, as recorded in
  `specs/SP1_TRANSPARENT_ONCHAIN_BLOCKER.md`;
- the generated environmental SP1 verifier jet and compiled singleton mint
  controller; the verifier must read the exact owned annex internally while
  the controller binds its typed journal by SHA-256, so no generic annex-byte
  jet is required;
- strict on-chain proof-verifier integration measurements;
- a node-reproduced CMR/encoding/cost/execution artifact for the Elements
  inventory HTLC, and a separately compiled/tested Tron HTLC adapter (neither
  is ever a canonical mint path);
- ecosystem-wide cryptographic transfer paths to other Drivechains;
- performance, block-weight, EVM gas, adversarial-invalid-block, scale, and soak
  evidence.

## Launch decision

**BLOCKED.** The authoritative gate file is `specs/launch-gates.tsv`. Every
required gate is currently unmeasured and BLOCKED. `usdd-cli gates report`
returns launch PASS only when all 16 required rows meet their typed thresholds
and each `sha256:<digest>@<relative-path>` reference matches the local evidence
file byte for byte. This check proves evidence integrity, not the truth or
independence of an audit; release review must still authenticate the published
artifacts and reviewers.
