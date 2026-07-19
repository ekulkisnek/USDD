# Ethereum inbound guest implementation boundary

## Frozen reference

The inbound implementation is based on the official, MIT-licensed SP1-Helios
v1.2.0 source at commit
`07096e1955bce67546fb9b185772296d41ef0eaa`. Exact upstream identities are in
`sp1-helios-reference.lock`.

The reference is not itself a USDD proof program. It pins SP1 6.2.4, while USDD
pins 6.3.1 at `8252c2905ce32964df68248117015c61ebb854db`. Its `ProofOutputs`
also omit the finalized execution block hash, execution timestamp, and the
proved account code hash. Its Solidity deployment has mutable guardian/vkey
paths. None of its deployed-contract trust model, existing ELF, or proofs are
accepted by USDD.

## Implemented composition

`usdd-ethereum-inbound` contains the compile-tested, `no_std` MPT verifier and
an optional `std` Sepolia finality verifier:

1. validate the immutable USDD manifest and prior controller state;
2. invoke `EthereumFinalityTransitionVerifier` on the exact prior state and
   requested finalized execution fields;
3. verify the vault `TrieAccount` inclusion beneath the authenticated execution
   state root;
4. require the included account's `code_hash` to equal the manifest-frozen
   deployed vault runtime `EXTCODEHASH`;
5. derive every mapping key as
   `keccak256(abi.encode(uint64(nonce), uint256(12)))`;
6. hash that 32-byte storage key again for the secure storage-trie path;
7. RLP-encode the derived nonzero `depositId` as an Ethereum `U256` storage
   value and verify its MPT inclusion; and
8. repeat for 1..64 consecutive nonces beginning exactly at the controller's
   `nextMintNonce`.

The exact finality-composition commitment is:

```text
SHA256(
  "USDD_ETH_FINALITY_TRANSITION_V1"
  || schema:u16be
  || manifestId[32]
  || len(priorControllerState):u32be || priorControllerState
  || len(finalityWitness):u32be || finalityWitness
)
```

Both state records use the canonical schema-2 codecs. `finalityWitness` includes
the light-client digest, finalized beacon slot/root, execution block hash,
execution state root, block number, and timestamp. An in-guest Helios port or a
recursively verified finality subprogram must commit this value only after
deriving every field from verified consensus. The existing SP1-Helios v1.2.0
public output is not this commitment and cannot be substituted for it.

Proof-node counts, individual node sizes, aggregate bytes, record tags, schema,
and exact decoding are bounded before copies. Trailing bytes are rejected by
`CanonicalDecode::decode_exact`.

An `EthereumInboundVerifier<V>` adapter implements the existing
`usdd-proof-core::EthereumStateProofVerifier` trait. The
`SepoliaHeliosFinalityVerifier` implementation pins Helios consensus core
0.11.1 at commit `204c998a927348e1c000a664f08d5b37b1b0d924` and:

- compiles in the Sepolia execution genesis, genesis validators root, and
  genesis-through-Fulu fork versions rather than reading them from a witness;
- authenticates the prior finalized beacon header, current committee, and
  optional next committee through a frozen SHA-256 controller-state digest;
- verifies the prior execution-payload SSZ branch before trusting its state
  root;
- requires a two-thirds BLS quorum for every generic and finality update;
- runs Helios SSZ, fork-domain, BLS, finality, and execution-payload checks;
- derives the next beacon root/slot, execution block hash/state root, block
  number, timestamp, and complete light-client digest; and
- accepts at most two updates in an exact, re-encoding-checked, 512-KiB-bounded
  private-witness codec.

It never clears and then forgets an authenticated next committee. `None` or the
actual next committee root is part of the prior controller digest, so a caller
cannot insert a committee as happened in GHSA-83q5-vwj7-gxww.

`EthereumFinalityTransitionVerifier::verify_finalized_transition` returning
`Ok(())` is the security-critical authorization boundary for minting. A
production implementation may return success only after cryptographically
verifying the full transition and the exact commitment above. Returning success
because RPC values agree, a prover supplied matching fields, or an operator
signed the input would make the bridge unsound.

`expected_current_slot` is derived as the finality update's own signature slot.
That prevents a witness from supplying wall-clock authority while retaining the
consensus ordering checks. It does **not** prove freshness. The Elements
controller must separately compare the consensus-derived execution timestamp
with `current_bmm_parent_mtp` and enforce the six-hour limit.

Fork versions are compiled only through Sepolia Fulu. A later fork signs under
a new fork domain, so this frozen verifier rejects its updates and halts until a
new program/asset version is deployed; it does not reinterpret an unsupported
fork.

The positive test fixture was fetched on 2026-07-18 from
`ethereum-sepolia-beacon-api.publicnode.com` using the SP1-Helios fixture
generator at commit `2c94eb7f75f45402b7a56661744002ebee5a626b`, retaining one
in-period update for slots 10723712..10724224. Its SHA-256 is
`2661ef34f4b5277fe7e3457586c64f802f789a7fd9d6d5a394e08324f4e944f0`.
The fixture's genesis, fork, clock, and RPC fields are provenance assertions
only and are not copied into the accepted proof.

## SP1 artifact still required

`guests/ethereum-state` packages the verified flow as pinned SP1 6.3.1 source.
It reads five separately length-checked records, uses exact manifest/claim/MPT
codecs and the canonical 512-KiB finality codec, and commits only the canonical
`StrictJournal`. Its pure wrapper and host entrypoint compile and test.

The remaining artifact work is:

- compile and execute that exact source for the Succinct zkVM under SP1 6.3.1 commit
  `8252c2905ce32964df68248117015c61ebb854db`;
- freeze a reproducible ELF and program ID;
- run the real Sepolia fixture through the SP1 executor and produce a positive
  raw-compressed proof fixture;
- differential-test guest outputs against this native verifier and multiple
  consensus clients; and
- satisfy the size, latency, memory, and proof-transaction gates.

SP1-Helios RPC/operator code may collect untrusted witness bytes and submit a
proof, but it has no role in proof validity. A failure or unavailable prover is
a liveness failure only.

The current host has neither `cargo prove` nor the `succinct` Rust toolchain, so
this turn cannot honestly claim a zkVM-target compile. Until the reproducible
ELF/program ID, positive raw-compressed proof,
differential client tests, and launch gates exist, Ethereum minting remains
fail closed and is not deployable. The `std` verifier is security-relevant
preflight code; it is not itself an on-chain authorization mechanism.
