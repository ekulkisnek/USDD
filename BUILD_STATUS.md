# Build status

This file separates tested protocol plumbing from cryptographic systems that do
not yet exist. Nothing below upgrades an unmeasured item to PASS.

## Implemented and host-tested in this workspace

- canonical, exact-decoding V1 records and domain-separated SHA-256 IDs;
- six-decimal USDT to eight-decimal USDD conversion at exactly ×100;
- one-controller sequential per-vault nonce consumption and replay rejection;
- irreversible burn records and deterministic outpoint-bound redemption IDs;
- exact depth-64 cumulative burn accumulator roots and proofs;
- cross-chain reserve/supply conservation checks;
- immutable manifest validation for Drivechain slot 24;
- strict SHA-256 proof-journal envelope with explicit success marker, program
  binding, payload hash, canonical encoding, and trailing-byte rejection;
- host-testable proof claim/output cores behind non-accepting verifier traits;
- CLI surfaces for amounts, IDs, canonical decoding, burn-tree and auxiliary
  general-purpose Merkle proofs, audits,
  journals, manifests, and launch-gate reports;
- machine-readable launch gates that default missing or unmeasured evidence to
  BLOCKED.

## Not implemented or not cryptographically demonstrated

- complete Ethereum consensus-finality and execution-state proof guest;
- complete Elements full-validity proof guest;
- complete Bitcoin/BMM canonical-ancestry proof guest;
- production SP1 guest ELFs and reproducible program IDs;
- strict on-chain proof-verifier integration measurements;
- permissionless inventory-swap adapters for Tron or other chains (never a
  canonical mint path);
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
