# USDD Bitcoin/BIP301 proof foundation

This no-std crate ports a narrow, independently testable subset of the parent
consensus path used by the Elements Drivechain fork:

- exact 80-byte Bitcoin header decoding and double-SHA256 block IDs;
- Bitcoin Core-compatible compact-target range checks and proof of work;
- exact block-work and overflow-safe cumulative-work arithmetic;
- the actual LayerTwo-Labs Signet 2016-block retarget rule;
- exact parent linkage;
- exact Bitcoin block and transaction parsing with canonical CompactSize rules;
- legacy and SegWit txid derivation, context-free input/output checks, canonical
  coinbase placement, and consensus block-weight enforcement;
- non-mutated transaction-Merkle-root and BIP141 witness-commitment
  verification;
- exact verification of the immutable LayerTwo-Labs P2WPKH Signet challenge,
  including the node's Signet-section rewrite, solution codec, strict DER,
  high-S normalization, BIP143 sighash, and secp256k1 signature; and
- the fork's unique, minimal slot-24 M7 parser and child-hash byte order, now
  cryptographically bound through the coinbase txid and Merkle root to the
  proof-of-work successor header;
- bounded slot-24 M1/M2 proposal replay with the fork's exact same-block ACK,
  strict `votes > threshold` activation, live used/unused threshold selection,
  proposal-expiry, and immutable-required-proposal replacement rules;
- the exact slot-24 OP_DRIVECHAIN treasury chain for positive CTIP transitions,
  including parallel-output, drain, zero-delta, missing-address, and multiple
  treasury-output rejection; and
- exact M8 request binding to the slot-24 M7 child hash and predecessor `P`.
  A nonminimal M7 can satisfy the enforcer's M8 parser but cannot produce the
  Elements fork's strict BMM edge.

The M7 parser fails closed above consensus-safe resource ceilings derived from
Bitcoin's 4,000,000 maximum block weight: at most 1,000,000 base bytes,
111,111 outputs (each serialized output needs at least nine base bytes), and
1,000,000 aggregate output-script bytes. These bounds are deliberately
permissive because a real coinbase must also serialize its inputs, values,
length prefixes, transaction fields, and enclosing block.

The low-level
`verify_header_pow_against_caller_supplied_bits` entry point does not derive
or authenticate its expected difficulty. Production transitions must use
`verify_successor`. Likewise,
`from_unverified_checkpoint_requires_manifest_binding` only checks internal
chainwork consistency; every bootstrap field must be compared to the frozen
manifest before the state is accepted.

The tests include the complete Bitcoin genesis block, legacy and SegWit txid
derivation, mutated-Merkle rejection, proof-of-work/Merkle/M7 end-to-end
binding, the fork's real LayerTwo Signet block 5580 ECDSA solution, tampered
signed-header rejection, the node's malformed-tail Signet rewrite behavior,
and the exact cross-codec M7 vector from `src/test/pegin_witness_tests.cpp`.
The replay tests mirror the fork's proposal, activation, expiry, replacement,
CTIP-increase, and fabricated-transition cases and assert that every failed
transition leaves the prior state unchanged.

The replay's 1,222,221-entry ceiling is consensus-derived rather than an
arbitrary availability cap: at most 111,111 coinbase outputs per block times
the eleven possible live creation heights under the frozen ten-block age. The
bound is deliberately loose, but a history accepted by the implemented block
parser and frozen replay cannot exceed it. No live proposal is evicted.

## Deliberate fail-closed boundary

This is **not** `USDD_ELEMENTS_STATE_V1` and must not be described as full
Bitcoin, BIP300/301, or Elements validity. Before any outbound proof can be
accepted, the SP1 guest still has to faithfully port and differential-test:

1. Remaining Bitcoin consensus validation: median-time-past/version and BIP34
   context, sigop limits, UTXO/input/script validation, subsidy/fees, and every
   activation-height rule.
2. Bootstrap checkpoint authentication, continuous header history, exact
   cumulative-work fork choice, reorg handling, and 100-confirmation tracking.
3. Remaining BIP300 validity: all-slot processing, M3/M4 withdrawal votes,
   authorized M6/CTIP decreases, and global enforcer rules. The implemented
   slot-24 replay authenticates neither an M6 nor a CTIP decrease.
4. Full Elements block, transaction, UTXO, script, Taproot, Simplicity,
   issuance/reissuance, confidential-asset conservation, and burn validity.
5. Canonical burn extraction and append-only accumulator transition.

`extract_elements_slot24_m7` still intentionally returns
`UnboundCanonicalM7` because its standalone scripts are caller-provided. The
generic binding API is `verify_pow_merkle_bound_elements_m7_successor`, which
is useful for non-Signet test vectors but is not a production path. The
production-direction API is
`verify_layer_two_signet_pow_merkle_bound_elements_m7_successor`; it accepts
the exact serialized block and an already manifest-bound parent state, derives
every txid, both Merkle commitments, the frozen Signet solution, successor PoW,
and M7 output itself. Its result still does not imply BIP300 state, best-chain
membership, confirmation depth, contextual/UTXO Bitcoin validity, or Elements
validity.

`apply_merkle_bound_elements_slot24_parent_block` separately advances the
bounded BIP300 state and emits an `ElementsSlot24BmmEdge` only after the frozen
proposal is active and the exact successor contains a minimal M7. Its name
deliberately says `merkle_bound`: input-value conservation, scripts, Signet,
PoW/fork choice, and best-chain membership still have to be composed around it.

There is no accept-all verifier and no trusted fallback in this crate.
