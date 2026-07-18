# USDD V1 build and activation blockers

Status: **the current code must reject every USDD proof**.  This is an
activation checklist, not a claim that the bridge is deployable.

## 1. Create a dedicated Elements-mode drivechain network

The repository's existing `signet` identity cannot host USDD:

- `consensus.elements_mode` is false;
- `DEPLOYMENT_SIMPLICITY` is `NEVER_ACTIVE`; and
- its existing Bitcoin-style genesis and network identity must not be silently
  reinterpreted under Elements and Simplicity consensus rules.

Generate a new network and genesis whose immutable chain parameters bind at
least:

- Elements mode and the intended genesis style;
- Simplicity activation from genesis, or an activation rule fixed before the
  network launches;
- BIP300/301 sidechain slot **24**;
- the exact parent-chain genesis and parent proof rules;
- the native USDD asset/reissuance-token bootstrap transaction, its public
  asset blinding factor, and the controller's initial UTXO/program commitment;
- proof-system, guest, controller, journal, domain, and configuration hashes;
  and
- block limits sufficient for the final, measured proof size and cost.

Changing these values after launch is a consensus change, not configuration.
The deprecated `-drivechainbmmslot` option may accept only `24`, and the parent
genesis must not be runtime-overridable for this network.

## 2. Make authenticated proof bytes available to Simplicity

The current transaction environment retains only the Taproot annex hash.  It
must own a bounded copy of the exact annex bytes (maximum 512 KiB), recompute
and match `annexHash`, define allocation/lifetime behavior, and charge a
deterministic resource cost.  Parsing the envelope does not prove its contents.

## 3. Add the verifier as an upstream Simplicity jet

There is no SP1 verifier jet.  The verifier must be integrated through the
normal Simplicity generation path, including its exact input/output type, CMR,
C and Haskell identifiers, generated dispatch, deterministic cost, activation,
and independently reproduced positive and negative vectors.  A local C helper
or host callback is not consensus-safe.

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
- the complete public journal committed by the controller.

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

## 6. Define block and mempool context without trusting a server

`current_bmm_parent_mtp` may be present only after validation ties the parent
hash to the sidechain block through its mined BIP301 commitment.  The script
cache key must bind its presence and value.  Mempool and block-template
validation need an explicit candidate-parent context; wall-clock time and an
unbound RPC result are invalid substitutes.

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
  malformed lengths, stale checkpoints, maximum batches, and cache-context
  separation; and
- obtain independent audits of the node consensus patch, Simplicity jet and
  controller, both proof guests, and the Ethereum vault/verifier.

Activation is blocked until every item above has executable tests and the
fail-closed `VERIFIER_UNAVAILABLE` path is replaced atomically with the pinned,
costed verifier and its activation rule.
