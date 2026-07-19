# USDD V1 build and activation blockers

Status: **the current code must reject every USDD proof**.  This is an
activation checklist, not a claim that the bridge is deployable.

## 1. Complete and freeze the sole Elements network identity

The node repository now has one canonical production identity, `elements`.
It already fixes Elements mode, Simplicity activation from the first spendable
block, BIP300/301 slot **24**, and the parent-chain identity. Do not create a
second USDD chain name, retain a production alias, or make these values runtime
selectable.

The sole Elements genesis/identity still must bind the remaining USDD launch
artifacts before activation, including:

- the native USDD asset/reissuance-token bootstrap transaction, its public
  asset blinding factor, and the controller's initial UTXO/program commitment;
- proof-system, guest, controller, journal, domain, and configuration hashes;
  and
- block limits sufficient for the final, measured proof size and cost.

Adding those artifacts changes the current pre-launch genesis and invalidates
its datadir. Recompute and freeze every derived identity constant together, but
keep `elements` as the only production network. Changing any frozen value after
launch is a consensus change, not configuration. The deprecated
`-drivechainbmmslot` option may accept only `24`, and the parent genesis must not
be runtime-overridable.

## 2. Keep authenticated proof bytes inside the verifier jet

The Elements fork now retains an owned, bounded copy of the exact Taproot annex
bytes, including the `0x50` tag, only when they exactly match the legacy annex
body used by the transaction hash. The limit is 512 KiB per input and the copy
has transaction-environment lifetime.

Do not expose that variable-length value through a generic Simplicity type or
indexed-byte jet. The single generated verifier jet below must read it directly
from the authenticated current-input environment. The controller supplies a
fixed typed journal, hashes its canonical encoding, and passes that digest to
the verifier. This is sufficient to bind the opaque proof to every controller
check with less consensus surface.

## 3. Add the verifier as an upstream Simplicity jet

There is no SP1 verifier jet. Its frozen interface is
`verify_sp1_compressed_sha256(programId, publicValuesHash) -> Bit`. It reads the
current exact annex internally, strictly parses the V1 envelope, hashes and
matches the carried public values, and accepts only a successful raw-compressed
SP1 6.3.1 proof under `programId`.

The verifier must be integrated through the normal Simplicity generation path,
including its exact input/output type, CMR, C and Haskell identifiers, generated
dispatch, fixed worst-case cost, activation, and independently reproduced
positive and negative vectors. A local C helper, host callback, generic annex
reader, wrapper proof, or parser-only success is not consensus-safe. The full
normative interface is in the paired Elements node document
`doc/usdd-sp1-verifier-jet.md`.

The Elements gate deliberately has no accepting state until this is complete.

## 4. Finish and reproduce the Ethereum proof guest

The Ethereum mint guest must prove, rather than accept as host input:

- a valid finalized beacon/light-client transition from the controller's
  committed checkpoint;
- the corresponding execution-state root;
- the immutable vault's address and code identity;
- one through 64 consecutive, previously unconsumed deposit nonces;
- exact USDT contract storage/log semantics, recipient, amount, and decimal
  conversion; and
- the complete public journal committed by the controller, including the
  finalized execution-block timestamp.

The Ethereum claim and public output must contain no caller-supplied BMM parent
MTP. Ethereum consensus cannot authenticate that Elements/Bitcoin fact. The
controller obtains current parent MTP only from the Elements environment jet
and compares it with the proved execution timestamp.

Pin the SP1 toolchain, guest ELF/program ID, verifier key, proof encoding, and
all consensus constants.  Reproducible builds and adversarial vectors are a
release requirement.

## 5. Compile the real controller and prove the issuance invariants

The `.simf.in` file is deliberately non-compilable and fail-closed.  A real
controller must use released, audited Elements introspection and issuance jets
to enforce one exact successor, preserve every reissuance-token unit in that
successor, issue exactly `USDT6 * 100`, forbid unrelated issuance, authenticate
the current state/configuration, and implement the separately constrained
heartbeat path.  Its CMR and all serialized state bytes must match the canonical
manifest and cross-language vectors.

## 6. Expose the authenticated block context without trusting a server

The Elements fork passes BIP301-authenticated parent MTP into the Simplicity
transaction environment and binds its presence/value into the script cache key.
The officially generated `current_bmm_parent_mtp : 1 -> Maybe Word64` jet is
decoder item 51 with CMR
`12dc3d4f22466873daaf83b10e1cfa1ea551e23ae7d0fbd6d9da64ce7e89a3e2`
and cost 108. It may return `Some` only after validation ties the parent hash to
the sidechain block through its mined BIP301 commitment; otherwise it returns
`None`. The remaining work is to consume that exact jet in the real controller
and reproduce its identity through the controller toolchain. Mempool and
block-template validation must continue to use an explicit candidate-parent
context; wall-clock time and an unbound RPC result are invalid substitutes.

The typed Ethereum journal supplies only its consensus-proved execution-block
timestamp. The Simplicity controller must require
`abs(current_bmm_parent_mtp - execution_block_timestamp) <= 21600` using checked
unsigned arithmetic. A BMM MTP supplied by the prover, Ethereum claim, proof
guest host input, or journal is never authoritative and must be rejected as a
noncanonical field.

An RPC may transport parent-chain data, but cannot be the authority for it.
Every consensus fact it returns must be authenticated against locally verified
parent headers and BIP300/301 commitments, with deterministic revalidation from
stored block data.  Network or RPC failure may stop validation, but must never
turn an invalid proof into a valid one.

## 7. Finish Ethereum redemption independently

Redemption is an Ethereum transaction, not a second Elements annex statement.
The Ethereum vault must verify a proof of a canonical Elements burn plus the
Bitcoin/BIP301 anchoring and finality policy, derive the fixed `burnId` from the
proved transaction and output index, mark it consumed before transfer, and pay
only the recipient and amount committed in that burn output.  The verifier
contract, its code hash, upgrade policy (preferably none), proof guest, and
bootstrap checkpoint must be pinned in the manifest and independently audited.

## 8. Relay policy, vectors, and independent review

Before activation:

- make only fully verified USDD annexes standard, with exact size, weight, fee,
  and per-block limits; do not standardize arbitrary annexes;
- match asset IDs, byte order, state encoding, burn scripts/IDs, journals,
  domains, CMRs, and configuration hashes across C++, Simplicity, Rust,
  Solidity, and test tooling;
- fuzz every parser and state transition and test reorgs, duplicate proofs,
  malformed lengths, stale checkpoints, maximum batches, six-hour timestamp
  boundaries, forged prover-supplied MTP fields, and cache-context separation;
  and
- obtain independent audits of the node consensus patch, Simplicity jet and
  controller, both proof guests, and the Ethereum vault/verifier.

Activation is blocked until every item above has executable tests and the
fail-closed `VERIFIER_UNAVAILABLE` path is replaced atomically with the pinned,
costed verifier and its activation rule.
