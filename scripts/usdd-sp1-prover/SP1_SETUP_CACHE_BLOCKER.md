# SP1 6.3.1 setup-cache blocker

## Status

The public SP1 6.3.1 API cannot seed the full CPU controller's setup cache.
USDD now carries a pinned, host-only source transformation that provides a
one-shot vkey hint, fixes nonzero proof-nonce propagation, and stops retaining
all compose/deferred proving keys concurrently. The exact transformation,
release build, local unit tests, and monitored full CPU-prover initialization
pass on the 16-GiB validation host. It has not yet produced the canonical
Ethereum proof or passed identity-setup and differential-proof runtime gates.

This is a host-prover resource blocker, not a proof-verification or consensus
exception. The prover must not disable intermediate verification, recursion
verification-key verification, or any raw-verifier check to work around it.

## Pinned-source evidence

At SP1 tag `v6.3.1`, commit
`8252c2905ce32964df68248117015c61ebb854db`:

1. `sp1-sdk/src/cpu/prove.rs` passes `pk.elf` to
   `SP1LocalNode::prove_with_mode`; it does not pass `pk.vk`.
2. `sp1-prover/src/worker/node/full/mod.rs` creates a fresh ELF artifact for
   each proof.
3. `sp1-prover/src/worker/controller/mod.rs` owns a private
   `setup_cache: LruCache<Artifact, SP1VerifyingKey>`. A miss submits
   `TaskType::SetupVkey` and only then inserts the result.
4. `SP1LocalNode::setup` submits a setup task directly and deletes its temporary
   ELF artifact. It does not populate the controller cache.
5. The light client and CPU client are distinct nodes with distinct workers,
   artifact stores, and caches.

Consequently, constructing an `SP1ProvingKey` from the light client's vkey and
the ELF does not seed the CPU proof. Calling `CpuProver::setup` on the CPU client
also does not seed the controller cache consulted by `prove`.

## Implemented pinned upstream patch

Provide the exact per-proof ELF artifact through a separate one-shot hint map
without changing the serialized controller request or any circuit:

1. Add a cloneable, crate-private one-shot hint map to `SP1Controller` and
   retain that handle in `SP1NodeInner` during `SP1LocalNodeBuilder::build`.
2. Add `SP1LocalNode::prove_with_mode_and_vkey`. After it creates the fresh ELF
   artifact, insert the caller-supplied `SP1VerifyingKey` under that exact
   artifact key before submitting the controller task. Keep the existing
   `prove_with_mode` entry point and behavior unchanged.
3. Remove the seeded entry on every success and failure path so concurrent or
   repeated proofs cannot observe stale hints.
4. In every core-shard path, compare the verifying key returned while deriving
   proving data from the actual ELF with the seeded key and fail on any
   difference. Retain intermediate-proof verification. This keeps an explicit
   ELF-to-vkey binding instead of trusting host input.
5. Make `CpuProveBuilder::run` call the new entry point with `pk.vk.clone()` and
   `pk.elf`. The key remains a checked hint; it is not authority.

This removes the redundant controller-wide setup. It does not remove the
per-shard proving-data work when `SP1_WORKER_USE_FIXED_PK=false`.

The patch also retains only expected compose/deferred vkeys after serial setup.
It rebuilds a proving key for the required recursion program on demand,
requires the newly derived vkey to equal the retained full key, and drops the
proving key after that task. This reduces retained memory without changing the
recursion programs or accepted vkey root.

Passing the vkey as a new serialized `ControllerInputs` field would also work,
but it changes the distributed task request layout and canonical parsing. The
dedicated one-shot hint map is the narrower local-host patch.

## Security and compatibility requirements

The patched host must:

- treat the typed `SP1VerifyingKey` as an untrusted hint and, if it is ever
  persisted, accept only its canonical serialization;
- require the supplied vkey hash to equal the frozen program ID before proving;
- reject a vkey derived from any other ELF;
- retain intermediate-proof and recursion-vkey verification;
- use the standard SP1 6.3.1 recursion programs, FRI parameters, transcript,
  proof nonce, and compressed-proof serialization; and
- verify the result with both the SDK verifier and
  `SP1CompressedVerifierRaw` before emitting an Elements annex.

Because this is host orchestration only, a conforming patch does not change the
guest ELF, program ID, recursion-vkey root, target soundness, public values, or
`SP1Proof::Compressed` wire format. Proof bytes need not match those from the
stock host; successful raw verification is the compatibility criterion.

## Required tests before adoption

1. Instrument task submission and prove that the supplied-vkey path submits
   zero standalone `SetupVkey` tasks, while the stock path still submits one.
2. Prove a small pinned guest through both paths and require equal program IDs
   and public values and successful SDK and raw-compressed verification.
3. Reject a valid vkey from a different ELF. If a persistent vkey format is
   added, also reject bit-flipped and noncanonical encodings.
4. Force a mismatch between the supplied vkey and the vkey recomputed by a core
   shard and require failure before any final proof is emitted.
5. Prove with the frozen nonzero nonce and require that the verified proof
   carries that nonce instead of the stock slot-mismatch zero value.
6. Compare eager and on-demand recursion-key paths on a small guest, including
   deliberate derived-vkey mismatch rejection.
7. Run the canonical Ethereum guest on a suitably provisioned host and record
   peak memory, proof size, and verification results. Do not assert byte-for-
   byte proof equality across the stock and patched orchestration paths.

The exact archives, transformer, and pre/post source hashes are frozen under
`toolchain/`. Source transformation, a release compile, local unit tests,
monitored CPU-prover initialization, and bounded frozen-guest identity setup
pass. Small-guest stock/patched differential proving, deliberate wrong-vkey
rejection during a real shard, nonzero-nonce proof verification, and the
canonical Ethereum proof remain required before deployment.
