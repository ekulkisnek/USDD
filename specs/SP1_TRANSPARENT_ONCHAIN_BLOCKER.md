# SP1 transparent on-chain verification blocker

USDD V1 freezes SP1 `6.3.1` at commit
`8252c2905ce32964df68248117015c61ebb854db` and requires the raw compressed,
transparent proof. It permanently rejects the PLONK and Groth16 wrappers.

The pinned upstream release does not provide an on-chain verifier for that
proof mode:

- `sp1-sdk-6.3.1/src/proof.rs`, in
  `SP1ProofWithPublicValues::bytes`, serializes only `SP1Proof::Plonk` and
  `SP1Proof::Groth16`. Every other proof kind, including `Compressed`, panics
  with the explicit message that only PLONK and Groth16 are verifiable
  on-chain.
- `sp1-prover-6.3.1/src/build.rs` exports only
  `build_plonk_bn254_contracts` and `build_groth16_bn254_contracts`. It contains
  no raw-compressed Solidity verifier generator.

The audited local copies of those exact crate sources have these SHA-256
digests:

```text
94cf6f081f9578d440293b67d1f6b6e9b034214cc2e38b52496f072fd9916382  sp1-sdk-6.3.1/src/proof.rs
4883c667a4e369fe3d757deda9d48bffd95b013ea826dbc107205d0561b77d5c  sp1-prover-6.3.1/src/build.rs
```

The release also ships its canonical outer shrink-wrap reference proof as
`sp1-prover-6.3.1/wrapped_proof.bin`. It is `1,340,837` bytes, with SHA-256
`e1d92229ea03c73d233795befc43b6c34bd446df4168399250eefb480efade6d`.
That artifact is not a USDD guest proof and is not itself proof that every raw
compressed proof exceeds the V1 limit. It is, however, concrete evidence that
the `512 KiB` annex gate cannot be assumed achievable; the actual frozen guest
proof must be generated and measured before the proof-size gate can pass.

The Rust host adapter in this repository can verify raw compressed proofs on a
normal computer. That does not make the same verifier available to Ethereum or
inside Elements consensus. A host verifier, RPC service, watcher, or relayer
cannot authorize either chain under the V1 trust model.

## Consequence

The frozen requirements are mutually unsatisfied by stock SP1 6.3.1:

1. Ethereum must verify the outbound proof itself.
2. Elements must verify the inbound proof itself.
3. Both must accept only the raw compressed transparent proof.
4. PLONK, Groth16, committees, optimistic challenges, and trusted verification
   services are forbidden.
5. The Ethereum path must remain below 50% of the block gas limit.

Finishing V1 therefore requires a new, independently specified and audited
raw-compressed SP1 verifier for both the EVM and the Elements/Simplicity
consensus environment. That is a new cryptographic/consensus implementation,
not glue code around the upstream release. No deployment artifact or launch
gate may be marked PASS until those verifiers exist and meet the size, gas,
latency, memory, determinism, and invalid-proof rejection gates.

Accepting an upstream wrapper or changing proof systems would be a protocol
design change and must not be smuggled into V1 as an implementation detail.
