# SP1 verifier lock and audit status

V1 freezes SP1 v6.3.1 at git commit
`8252c2905ce32964df68248117015c61ebb854db`, compressed circuit version 1,
and compressed codec version 1. Deployment must also freeze the recursion
verifier constants, guest program IDs, verifier runtime code hash, and verifier
configuration hash in the manifest.

The checked lockfiles use the crates.io `sp1-zkvm` and `sp1-verifier` 6.3.1
packages with exact registry checksums. Their packaged `.cargo_vcs_info.json`
records both resolve to the frozen commit above; the package and provenance-file
hashes are recorded in `sp1-toolchain.lock`. Reproducible release tooling must
assert all four hashes rather than inferring source identity from the version
string alone.

Review of that upstream revision found that the raw compressed verifier accepts
SHA-256 or BLAKE3 public-value digests and checks `is_complete`, but does not
expose the wrapped guest exit code. The implemented USDD host adapter therefore
requires SHA-256, an exact typed journal, the `SUCCESS!` marker, the canonical
program ID, and a canonical raw compressed proof; raw upstream acceptance is
insufficient. Its accepting path still requires a reproducible positive proof
fixture before release.

The official SP1 Turbo memory-argument paper describes the underlying STARK as
roughly 102 bits of a-priori security:
<https://docs.succinct.xyz/assets/files/SP1_Turbo_Memory_Argument-b042ba18b58c4add20a8370f4802f077.pdf>.
That does not independently establish the soundness of the complete v6.3.1
recursion/compression/verifier composition. The independent soundness launch
gate remains BLOCKED.

The pinned release's on-chain API and contract generator support only PLONK
and Groth16. They do not provide an EVM verifier for the raw compressed proof
required by V1. The exact source evidence, hashes, and protocol consequence are
recorded in `SP1_TRANSPARENT_ONCHAIN_BLOCKER.md`. This is a hard implementation
dependency, not a relayer-availability problem.
