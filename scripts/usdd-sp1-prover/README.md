# USDD raw-compressed SP1 prover

This standalone, pinned SP1 package release 6.3.1 binary turns one canonical five-record
Ethereum guest fixture into a canonical raw compressed proof and Taproot annex
consumed by Elements. It has no mock, Groth16, PLONK, TEE, watcher, signature,
or trusted-network fallback.

SP1's SDK proof wrapper calls its compatibility field `sp1_version`, but in
package release 6.3.1 the value is the upstream circuit tag `v6.1.0` from
`sp1-prover-6.3.1/SP1_CIRCUIT_VERSION`. The host checks that exact upstream
constant and records the package release and circuit tag in separate metadata
fields. Substituting `6.3.1` for the wrapper tag is rejected, as is any circuit
tag other than the authenticated `v6.1.0` value.

Run it with a release build and an external Cargo target directory:

    CARGO_TARGET_DIR=/external/path/usdd-sp1-prover-target \
      scripts/usdd-sp1-prover/toolchain/cargo-patched.sh \
      run --release --locked --manifest-path scripts/usdd-sp1-prover/Cargo.toml -- \
      prove artifacts/sp1/ethereum-state-v1.elf \
      artifacts/sp1/ethereum-deposit-fixture-v1 \
      /new/output/directory

The output directory must not already exist. A successful run writes:

- proof.raw.bin: canonical fixed-integer bincode SP1Proof::Compressed;
- public-values.bin: the exact typed USDD journal;
- program-id.bin and raw-vkey-hash.bin: the two frozen SP1 vkey encodings;
- annex.bin: the strict, at-most-1,310,720-byte complete Elements annex; and
- proof-metadata.json: hashes, byte counts, and local timing.

`proof-metadata.json` schema 2 names `sp1PackageRelease` and
`sp1CircuitVersion` separately. The circuit tag is wrapper metadata and is not
part of `proof.raw.bin`; SDK verification and the SHA-256-only raw verifier must
still both accept before an annex is emitted.

The command first verifies the result with SP1's SDK, then passes it to the
production USDD SHA-256-only adapter. That adapter enforces the complete-annex
cap, including the header and public values, before cryptographic raw
verification, so an oversized envelope is rejected without being called
production-adapter-verified. The command deliberately
retains the raw proof and public values after that failure while emitting no
annex, leaving auditable computation evidence without creating a
mint-authorizing artifact. The separately fenced, non-authorizing oversized-
proof audit may exercise the same canonical journal/program/SHA-256/raw-
verifier checks under a 2-MiB diagnostic ceiling, but it cannot emit an annex or
return production authorization.

The prover uses a deterministic low-concurrency CPU profile. It sets SP1's
`shard_size` record-allocation hint to 1,048,576 cycles and limits each pipeline
stage to one worker with one buffered item. In SP1 6.3.1 that field sizes common
event-vector reservations (`shard_size >> 3`); it does not set proof-shard
boundaries. Actual shard boundaries remain governed by the pinned element and
height thresholds. A patched shared prover semaphore has one permit, so core,
recursion, shrink, and wrap AIR proving cannot overlap across those otherwise
independent stages. Rayon also uses one thread. On SP1's native
x86-64 Linux executor the trace-ring slot settings reduce retained native ring
buffers and the 4-GiB executor memory value participates in child-RSS
accounting. Apple ARM uses SP1's portable executor instead: it ignores the ring
slot counts, and the 4-GiB value budgets created guest-memory entries rather
than capping host RSS. The separate gas-trace cadence stays at SP1's calibrated
134,217,728 entries because changing that threshold changes standalone
execution's gas report; gas calculation is not performed during proving.
These settings preserve the standard recursion arities and verification-key
set, and both recursion-vkey and intermediate-proof verification remain
enabled. The 88,832,479-cycle fixture remains a large proof workload; the
allocation hint must not be described or relied on as a cycle-sharding control.

SP1's light client derives and validates the program identity before the full
CPU prover is initialized. The frozen host-only patch passes that typed full
vkey into a one-shot controller hint keyed by the fresh artifact containing the
same ELF. Every core shard still derives its own vkey from the ELF and rejects
an exact-key mismatch. This removes the repeated controller `SetupVkey`
without making host input authoritative.

The same patch fixes SP1 6.3.1's local-node nonce slot mismatch: controller
slot 3 is the optional cycle limit and slot 4 is the nonce artifact. The stock
local node placed the nonce in slot 3, causing every nonzero proof nonce to be
discarded. The patched request includes the slot-3 placeholder and a tiny
decoder regression test freezes that layout. The canonical proof deliberately
uses the fixed nonzero words `55534444 45544831 00000001 a11d6e5e`, which are
recorded in proof metadata, so the first real proof exercises this path.

To lower retained memory, initialization derives the expected compose vkeys
for arities 1 through 4 and the deferred vkey one at a time, then immediately
drops each large proving key. A proving key is rebuilt for one recursion task,
required to derive that exact retained vkey, used with normal intermediate and
recursion-vkey verification, and dropped. The single shared prover permit
serializes these derivations and every other AIR proving operation. This changes
host orchestration only; it does not change any recursion program, vkey root,
circuit, transcript, or proof encoding.

The archives, every edited upstream-source hash, the exact transformer, and
the resulting hashes are frozen in
[toolchain/manifest.json](toolchain/manifest.json). Validate the complete
transformation without compiling or initializing a prover with:

    python3 scripts/usdd-sp1-prover/toolchain/prepare.py --verify-only

Before attempting any guest proof, the real local CPU-prover initialization
can be measured in isolation. This command uses the exact builder and
low-memory profile used by `prove`, keeps intermediate and recursion-vkey
verification enabled, and exits before guest setup, execution, or proving:

    /usr/bin/time -lp \
      /Volumes/T705/usdd-sp1-patched-release/release/usdd-sp1-prover \
      preflight-init

Run that command only under live system-memory and disk monitoring. A process
exit without the JSON status
`FULL_CPU_PROVER_INITIALIZED_NO_PROOF_ATTEMPTED` is a failed gate. On the
16-GiB Apple M4 validation host, the one-permit binary passed in 54.25 seconds
with 3,168,550,912 bytes maximum RSS and zero process swaps.

The independent light-client setup used by `prove` has its own bounded gate.
It reads the exact ELF, generates its full SP1 verifying key, requires both
frozen identity encodings, checks that the setup key retains the exact ELF,
drops all setup material, and exits before full-prover initialization, guest
execution, or proving:

    /usr/bin/time -lp \
      /Volumes/T705/usdd-sp1-patched-release/release/usdd-sp1-prover \
      preflight-setup \
      /Users/lukekensik/Documents/Codex/2026-07-17/fi/work/usdd-protocol/artifacts/sp1/ethereum-state-v1.elf

Success emits
`FROZEN_PROGRAM_IDENTITY_VALIDATED_NO_FULL_PROVER_OR_PROOF`, program ID
`4f0511103dab14b61dd5b1403d077ba10d28a89a06dbb54d43e9683542c1df08`,
and raw little-endian vkey hash
`1011054fb614ab3d40b1d51da17b073d9aa8280d4db5db063568e94308dfc142`.
The monitored run recorded in `BUILD_VALIDATION.md` belongs to the retired V6
guest; V7 setup and proving measurements must be produced afresh.

There remains a material memory floor: one compose proving key, the active
trace/proof data, verifier data, and runtime allocations must coexist. Lowering
`SP1_WORKER_MAX_COMPOSE_ARITY` is not supported because the pinned shape loader
requires the standard arity-four reduce shape, and disabling recursion-vkey
checks is forbidden. The pinned host passed historical V6 release compilation,
local unit tests, monitored full-prover initialization, and canonical proof
computation on the 16-GiB Apple M4 using an isolated 6-GiB Linux VM with
external-backed 28-GiB swap. SP1 SDK verification passed for that retired
identity, and the resulting raw proof is
`1,272,546` bytes with SHA-256
`0b6d8b1216be8e61b86507259d4c913f941790e4b75c07576a55ae9f9e684a59`.
Together with the 1,001-byte public values and 55-byte header, it produced a
1,273,602-byte annex within the 1,310,720-byte cap. It does not verify under or
authorize the current V7 program identity. The prior V4 adapter
rejected this artifact under its then-active 524,288-byte ceiling; a fresh V7
proof and production packaging run are still required. A subsequent
non-authorizing audit
passed canonical encoding, journal/program identity, strict SHA-256 binding,
and upstream raw compressed verification. Its report
SHA-256 is
`36e369486ed62bf1cec019072af09961d09c51d2edec8e0b769cce7ffd0a8f0b`.
One ARM64 invocation reported 30 ms internal verification, 0.33 seconds process
elapsed, and 9,142,272 bytes maximum RSS; that single audit-only diagnostic is
not a P99 or performance-gate pass. The proof-size codec gate is aligned, but
proof-transaction weight and the remaining production gates still require
fresh V7 evidence. See `BUILD_VALIDATION.md` for the preserved V4/V6 evidence and
earlier failed-attempt history.

A newly produced annex for the current identity can be checked independently:

    scripts/usdd-sp1-prover/toolchain/cargo-patched.sh \
      run --release --locked --manifest-path scripts/usdd-sp1-prover/Cargo.toml -- \
      verify 4f0511103dab14b61dd5b1403d077ba10d28a89a06dbb54d43e9683542c1df08 \
      /path/to/annex.bin

The expected program ID is mandatory and must come from the frozen deployment
manifest (the example above is the tracked Ethereum-state V1 fixture ID). It
must be exactly 64 lowercase hexadecimal characters. The command compares it
with the annex identity before raw proof verification; an annex cannot choose
its own accepted program.

Local CPU proving of the full Helios transition is resource-intensive. The
tool does not silently switch to a remote prover. A permissionless prover may
run it on any sufficiently capable machine and publish the resulting annex.
