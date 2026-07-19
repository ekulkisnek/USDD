# USDD Ethereum inbound proof core

This crate implements the deterministic Ethereum inbound composition:

- exact, bounded private-witness decoding;
- the Solidity mapping-key derivation for `depositCommitmentByNonce` at frozen
  storage slot 12;
- vault account inclusion against a finalized execution state root;
- immutable vault runtime-code-hash binding;
- one MPT storage proof per consecutive deposit commitment; and
- an adapter to `usdd-proof-core::EthereumStateProofVerifier`; and
- an optional `std` Sepolia verifier that runs the pinned Helios consensus
  checks for SSZ branches, sync-committee BLS signatures, finality, and the
  finalized execution payload.

The MPT core remains `no_std`. The `helios-finality` feature pins
`helios-consensus-core` 0.11.1 at commit
`204c998a927348e1c000a664f08d5b37b1b0d924`, hard-codes the Sepolia execution
genesis, genesis validators root, and fork schedule through Fulu, and implements
`EthereumFinalityTransitionVerifier`. Its private witness has a canonical,
exact, 512-KiB-bounded CBOR codec and at most two committee updates. The
controller digest authenticates the prior header and both current and optional
next sync committees; no RPC-supplied root, fork, genesis value, or local clock
is accepted as authority.

The real Sepolia fixture at slots 10723712..10724224 exercises the positive
SSZ/BLS path. It is an untrusted witness: passing the consensus verifier is what
authenticates it.

`guests/ethereum-state` now wraps this verifier in an exact SP1 6.3.1 source
entrypoint with pre-allocation hint-length checks and canonical strict-journal
output. The source and its pure wrapper host-compile and test, but this is
**not yet an SP1 guest artifact**: the Succinct target toolchain is unavailable
in the workspace, so no RISC-V build, reproducible ELF/program ID, executor
run, or raw-compressed proof is claimed. RPC responses may collect witness
material only.

The implementation was derived from the interfaces and MPT flow in official
SP1-Helios v1.2.0 at commit
`07096e1955bce67546fb9b185772296d41ef0eaa` (MIT). The reference itself pins
SP1 6.2.4 and its public output omits fields USDD requires, so its ELF or proof
cannot be accepted unchanged. The USDD verifier derives all finalized execution
fields itself and does not accept the upstream contract or public output.
