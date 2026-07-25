# Patched SP1 host build validation

Validation dates: 2026-07-19 through 2026-07-20

This record covers host compilation, source/unit checks, separately monitored
CPU-prover initialization and frozen-guest identity-setup gates, the initial
bounded attempts, and the corrected canonical proof run. The corrected run
completed and passed SP1 SDK verification, but its raw proof failed the
production adapter's 512-KiB size gate. No annex or authorization was emitted.

## Frozen inputs

- SP1 package release: `v6.3.1`, upstream commit
  `8252c2905ce32964df68248117015c61ebb854db`
- SP1 SDK circuit compatibility tag: exact upstream
  `sp1-prover-6.3.1/SP1_CIRCUIT_VERSION` bytes `v6.1.0`
- Patch transformer SHA-256:
  `fe9d6541f1e4921922de38ad46ef6808dac7ee6aa829297d615f887a8180b266`
- USDD repository commit at validation start:
  `2c9dc7a72052240613deba3d9cf52a43403368d4`
- Rust: `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Cargo: `cargo 1.97.1 (c980f4866 2026-06-30)`

## Host and command envelope

- Host: Apple M4 (`Mac16,10`), 16 GiB RAM
- OS: macOS 26.3.1, build `25D771280a`
- Target: `aarch64-apple-darwin`
- `MACOSX_DEPLOYMENT_TARGET=11.0`
- `CARGO_INCREMENTAL=0`
- release, locked, and offline Cargo mode
- build products stored on `/Volumes/T705`

## Results

- Exact pristine-archive-to-patched-source verification: pass
- Frozen materialized vendor-tree verification: pass
- Locked dependency-tree check selects both patched path crates: pass
- Release build: pass
- Rust formatting check: pass
- Git whitespace check for this subtree: pass
- Local `usdd-sp1-prover` unit tests: 8 passed, 0 failed
- Final incremental release build elapsed time: 32.87 seconds
- Final incremental release build maximum compiler RSS reported by
  `/usr/bin/time -lp`: 3,018,653,696 bytes; zero process swaps
- Linker-reported minimum macOS version: 11.0
- Result: arm64 Mach-O, 50,735,712 bytes
- Result SHA-256:
  `f4f287c426481b4918046a61b7faf96a04e140f73b8b9520bcbab69b18515469`
- The pinned host transformer now exposes the one shared core/recursion/shrink/
  wrap AIR-prover semaphore as `SP1_WORKER_MAX_PROVER_PERMITS`; the USDD profile
  forces it to one and rejects zero. This closes the remaining cross-stage
  concurrency gap without changing circuits, vkeys, recursion arities, or
  verification checks.
- Monitored `preflight-init` on the final one-permit binary: pass in 54.25
  seconds, 3,168,550,912 bytes maximum RSS, zero process swaps. Its JSON report
  records `SP1_WORKER_MAX_PROVER_PERMITS=1`, intermediate verification enabled,
  recursion-vkey verification enabled, and no proof request.
- Monitored `preflight-setup` on the final validated binary: pass in 6.84
  seconds, 711,688,192 bytes maximum RSS, zero process swaps; exact ELF binding,
  frozen program ID, raw vkey hash, and encoding round trip all matched
- Corrected rotating-authority Sepolia fixture execution: pass at 43,848,313
  cycles, 63,299 input bytes, and a 1,001-byte journal with SHA-256
  `cde63ae34aa0bb60bef0d07f9a1fac2b1cd605abbc16554af86608be9f47288c`;
  the independently rerun executor used 742,277,120 bytes maximum RSS and zero
  process swaps
- Bounded full-proof attempt on that fixture using the preceding
  `92606a4ae39dd34f0bbaa5b94954d8ca29c7886632097df164694e4ccbdfb335`
  binary, before the shared semaphore was reduced from four permits to one:
  stopped after less than three
  minutes when internal free space fell below the 2 GiB guard. The largest
  observed prover RSS was 3,405,760 KiB. System swap grew from 9,216 MiB to
  13,312 MiB and reached approximately 12,042 MiB used; internal free space
  reached approximately 331 MiB before interruption. The output directory was
  never created, and both the external temporary directory and proof log
  remained zero bytes. This is a failed resource experiment, not proof
  evidence or a completed verifier peak-memory measurement. Prover RSS and
  host swap are tracked only as non-blocking liveness observations; they cannot
  satisfy the mandatory 256 MiB verifier-memory launch gate.

The validated binary is an external build artifact, not a checked-in protocol
identity. Reproducibility is anchored by the pinned dependency archives,
transformer, post-transform source hashes, Cargo lockfile, and command
envelope. The first bounded attempt above remains useful negative resource
evidence, but it was superseded by the corrected Linux proof run recorded
below. Neither run measures the production verifier's peak memory or latency.

The `preflight-setup <guest.elf>` command shares the exact identity helper
with `prove`, validates the frozen program ID and raw vkey hash, and exits
before CPU-prover initialization or any proof request. The monitored run
emitted `FROZEN_PROGRAM_IDENTITY_VALIDATED_NO_FULL_PROVER_OR_PROOF`.

## 2026-07-20 package/circuit identity correction

The pinned SP1 6.3.1 CPU prover later completed the canonical proof computation,
but the USDD host rejected its SDK wrapper because the host compared
`SP1ProofWithPublicValues.sp1_version` to package release `6.3.1`. Upstream
6.3.1 populates that field from `SP1_CIRCUIT_VERSION`, whose authenticated file
contains exactly `v6.1.0`. The rejection occurred before fixed-integer bincode
serialization, before output-directory creation, and before any raw-proof,
public-values, annex, or metadata write. The in-memory proof was dropped on
process exit and is not recoverable; the full proof computation must be rerun.

The corrected host imports the circuit tag from `sp1-sdk`, independently pins
its exact expected value and source-file SHA-256, and keeps package release and
circuit compatibility in separate schema-2 metadata fields. A circuit-tag
mismatch still fails closed. The raw verifier and its semantic identity were
not changed because the SDK wrapper string is absent from `proof.raw.bin` and
is not a verifier input; the frozen recursion constants and verifying key bind
the cryptographic circuit identity.

The corrected macOS arm64 release build used the same external target and
completed successfully. Its unit suite passed 9 tests with no prover
initialization or proof request. The resulting external binary is 50,704,464
bytes with SHA-256
`7e1a42aad049c8f1a61b6ccd98ec54016473556e7443303e06f406fedf1432a1`.
The frozen guest ELF remains 1,350,544 bytes with unchanged SHA-256
`2c6181591a9483b0f00dd256a7e661649694c2beb0508dbfb638e6fc2b9c4b77`
and unchanged program ID
`2ed186d31dbd9cd628fe0e333e80af5952b3deba32f7625f399fca2902bc7747`.

That Mach-O binary is not a Linux artifact. The corrected source was therefore
rebuilt in the isolated Linux proving environment with the pinned vendor
transformer and locked dependencies before the canonical rerun below; the
guest itself was not rebuilt or refrozen.

## 2026-07-20 corrected canonical proof outcome

The corrected SP1 6.3.1 host completed the canonical proof computation in an
isolated Linux VM on the 16-GiB host. The VM was capped at 6 GiB RAM and used an
external-backed 28-GiB swap allocation. The Linux release unit suite passed,
setup matched the frozen ELF/program identity, and SP1 SDK verification of the
compressed proof and exact public values passed before the production adapter
ran.

The production USDD adapter then rejected the proof at its size guard:

- `proof.raw.bin`: `1,272,546` bytes; SHA-256
  `0b6d8b1216be8e61b86507259d4c913f941790e4b75c07576a55ae9f9e684a59`
- `public-values.bin`: `1,001` bytes; SHA-256
  `cde63ae34aa0bb60bef0d07f9a1fac2b1cd605abbc16554af86608be9f47288c`
- first production guard: `524,288` raw-proof bytes
- result at that guard: proof-size gate failed by `748,258` bytes

Had packaging proceeded, the 55-byte versioned annex header and 1,001 public
bytes would make the candidate annex `1,273,602` bytes. That is `749,314` bytes
over the separate `524,288`-byte total-annex cap and 31.84% of a 4,000,000-WU
block (`3,185` bps rounded upward) before any other transaction bytes. It also
fails the 25% block-weight gate independently of the first size rejection.

The run deliberately retained the raw proof, public values, program ID, and raw
vkey hash for audit. It wrote neither `annex.bin` nor `proof-metadata.json`, so
there is no Elements mint-authorizing artifact. The production adapter's
SHA-256-only raw verification was not reached because its size check precedes
parsing.

### Non-authorizing strict audit

The explicitly fenced audit-only verifier subsequently processed the preserved
oversized proof under a separate `2,097,152`-byte diagnostic maximum. It
verified all of the following without changing production acceptance:

- canonical compressed-proof encoding;
- the exact 1,001-byte typed journal and expected program identity;
- strict SHA-256-only binding of the public values; and
- SP1's upstream raw compressed verifier.

The report is
`/Volumes/T705/usdd-linux-proof/proof-output-v2/proof-audit-non-authorizing.json`
with SHA-256
`36e369486ed62bf1cec019072af09961d09c51d2edec8e0b769cce7ffd0a8f0b`.
The timing sidecar has SHA-256
`909cf60250d219a29f10bc9ebe91b7ae3cc6f340b936c1d8956df2863c49865d`.
The audit-only source
`crates/usdd-sp1-verifier/examples/audit_oversize.rs` has SHA-256
`545d1a2bb563b458fc584dd9b073d63c5420aaa1b8a3c5eef9dbded34c1ecc39`.
It is excluded from the production C ABI and Elements authorization path; the
frozen verifier semantic identity and normalized source closure are unchanged.
It records status `AUDIT_VERIFIED_OVERSIZE_NON_AUTHORIZING`, production
acceptance `REJECTED_PROOF_TOO_LARGE`, `annexEmitted: false`, and
`authorizesElements: false`.

One ARM64 audit invocation recorded 30 ms inside verification. The surrounding
process took 0.33 seconds and `/usr/bin/time` reported 9,142,272 bytes maximum
RSS. These figures are one non-authorizing diagnostic, not P99, repeated-run,
in-node, x86/ARM parity, deterministic-consensus-cost, or independent
performance evidence. No latency, memory, or cost gate is marked `PASS` from
this run.

This result establishes that the canonical computation is feasible on the
current 16-GiB machine when external-backed swap is available. It does not make
the proof production-usable: the 512-KiB proof-size gate has failed, no
proof-carrying Elements transaction can be authorized, the candidate annex also
fails the 25% block-weight gate, verifier latency/RSS remain open, and
independent reproduction is still absent.
