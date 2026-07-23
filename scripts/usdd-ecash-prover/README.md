# Slot-24 recursive eCash prover

This permissionless host produces transparent SP1 6.3.1 proofs for the two
frozen guests:

- `ECASH_SEGMENT_V1` replays consecutive raw eCash blocks from the exact prior
  recursive state and tracks only Drivechain slot 24;
- `ECASH_FOLD_V1` verifies two segment/fold child proofs inside SP1 and folds
  only exactly adjacent states.

The host has no signing key or protocol authority. It independently executes
every segment before proving, verifies every child and final proof with the SP1
SDK, rejects TEE/Groth16/PLONK variants as recursive source proofs, and writes
both the resumable SP1 proof container and fixed-integer raw compressed proof.
The separate `wrap-groth16` command accepts only that authenticated compressed
form and produces the final Ethereum proof envelope.

The config fields named `segment_program_id` and `fold_program_id` contain the
SP1 verification-key digest as eight little-endian `u32` words. This is the
exact representation consumed by the recursive verification syscall. Release
manifests must additionally publish SP1's `hash_bytes()` program ID and
`bytes32()` BN254 representation so the encodings cannot be confused.

Commands:

```text
usdd-ecash-prover setup <segment.elf> <fold.elf>
usdd-ecash-prover prepare-genesis-segment <segment.elf> <fold.elf> <spec.json> <genesis.raw> <successor.raw> <new-output-dir>
usdd-ecash-prover prepare-segment <segment.elf> <fold.elf> <config.bin> <prior-state.bin> <spec.json> <new-output-dir>
usdd-ecash-prover prove-segment <segment.elf> <fold.elf> <segment-input.bin> <new-output-dir>
usdd-ecash-prover fold <segment.elf> <fold.elf> <config.bin> <left-proof-dir> <right-proof-dir> <new-output-dir>
usdd-ecash-prover wrap-groth16 <segment.elf> <fold.elf> <compressed-proof-dir> <new-output-dir>
```

`fold` accepts either segment or prior fold proofs as children. Repeated
pairwise folds can therefore compress a long catch-up interval while retaining
one constant-size public journal.

`wrap-groth16` starts from an SDK-verified segment or fold compressed proof,
runs SP1's shrink/wrap recursion and Groth16 BN254 prover without re-executing
the original eCash blocks, verifies the wrapper with the SDK, and emits the
exact proof bytes and arguments accepted by SP1's Ethereum verifier. Wrapping
does not change the guest program or public transition journal. Its artifacts
label the recursive `programIdHashBytes`, fixed-little-endian recursive syscall
digest, and Ethereum `programVKeyBn254` separately; the generated verifier call
uses only `programVKeyBn254`.

`prepare-genesis-segment` derives both guest identities, builds the canonical
proof configuration from a strict JSON spec, bootstraps only from the exact
frozen parent genesis, executes one raw successor block natively, and writes a
canonical config, prior state, segment input, expected journal, and metadata.
The two block arguments may be binary serialized blocks or ASCII `.hex` files;
hex input must contain only one canonical even-length hexadecimal value (apart
from surrounding whitespace).
Hex fields in the spec are fixed-length lowercase strings without `0x`; the
fields are `ethereumChainId`, `relayAddress`, `elementsGenesis`, `usddAsset`,
`vaultId`, `verifierConfigHash`, `finalityDepth`, `maxSegmentBlocks`,
`maxTransitionBlocks`, `maxSegmentBytes`, `maxStateBytes`, and
`rewardRecipient`.

`prepare-segment` accepts the canonical config and exact predecessor state from
the previous preparation. Its strict JSON spec contains `rewardRecipient` and
`blocks`; each block has a `rawBlock` path and an optional
`canonicalM6Artifact` path, resolved relative to the spec. It executes the
complete segment natively and writes the next state, canonical input, expected
journal, and adjacency metadata before any proving is attempted.

`scripts/capture_ecash_segments.py` performs a read-only parent JSON-RPC
capture, independently checks block hashes and consecutive parent links, and
emits checksummed segment specifications. After capture,
`scripts/build_ecash_windows_handoff.py` drives both preparation commands,
requires every native successor state to be exactly adjacent, and emits one
checksummed Windows proving handoff. Generated blocks, states, and proofs stay
outside Git.

Ethereum consumes the output through `SP1Groth16ProofComponentV1`, which pins
the direct SP1 v6.1.0 Groth16 verifier runtime, verifier identity, guest program
vkey, public-values length, and SHA-256 public-values digest. The wrapper also
rejects any output whose 356-byte encoding or verifier selector is not exactly
canonical. Deployment still requires a real folded M6 proof, frozen mainnet
identities, gas measurements, and independent audits; test mocks are never
deployment components.
