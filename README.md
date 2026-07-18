# USDD protocol workspace

This workspace contains the deterministic USDD bridge protocol model and the
in-progress Ethereum and Simplicity integrations:

- canonical encodings and domain-separated identifiers;
- protocol records for the locked V1 irreversible mint/burn flow;
- the fixed-depth burn accumulator and sequential nonce replay protection;
- reserve/supply audit invariants;
- honest host-testable proof guest cores;
- a dependency-light command-line utility;
- protocol specifications and fixed test vectors.

The `contracts` and `simplicity` directories consume these consensus encodings.
Their presence is not evidence that the end-to-end proof systems are complete;
see `BUILD_STATUS.md` and the mandatory launch gates.

The proof core does not pretend that a boolean or an RPC response proves chain
finality. Instead, it exposes verifier traits. Production guest adapters must
implement those traits with transparent proofs of Ethereum finality/state and
Elements validity plus canonical Bitcoin/BMM ancestry. Test verifiers are
available only under `cfg(test)`.

V1 has exactly one canonical issuance path: finalized Ethereum USDT deposits
mint the native Elements asset. Tron is not a second mint authority. Tron and
other chains may support separately specified atomic inventory swaps, but those
swaps neither issue USDD nor alter canonical backing.

## Workspace

- `crates/usdd-core`: consensus-facing data model and audit logic.
- `crates/usdd-proof-core`: verifier boundaries and deterministic public
  outputs suitable for an SP1-style guest adapter or another transparent VM.
- `crates/usdd-cli`: IDs, encodings, burn-accumulator operations, manifest commitments,
  and audit checks.
- `specs`: normative byte formats, state machines, proof statements, and
  deployment manifest requirements.

See `BUILD_STATUS.md` before treating any interface as a completed bridge. In
particular, this workspace supplies no production SP1 guest binary or complete
Ethereum/Elements/Bitcoin proof circuit yet. The launch-gate report therefore
defaults to BLOCKED.

## Development

```sh
CARGO_TARGET_DIR=/Volumes/T705/space-relief/caches/usdd-target cargo test --workspace
(cd typescript && npm test)
```

No trusted bridge signer, watcher quorum, MPC key, or optimistic challenger is
represented in this workspace. Off-chain provers and relayers are permissionless
and affect liveness only.

USDT amounts are encoded in six-decimal micro-USDT units. USDD is an
eight-decimal Elements asset, so every mint and burn uses the exact conversion
`USDD base units = USDT micro-units × 100`. Mint replay protection is the
controller's monotonically consumed per-vault deposit nonce.
