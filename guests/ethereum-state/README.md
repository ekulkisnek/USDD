# USDD Ethereum state SP1 guest

This is the pinned SP1 6.3.1 source entrypoint for the Sepolia inbound path. It
reads five separate private records in this order:

1. one-byte statement tag (`1` deposit, `2` heartbeat);
2. canonical schema-2 protocol manifest, at most 4 KiB;
3. canonical schema-2 claim, at most 128 KiB;
4. canonical Sepolia finality witness, at most 512 KiB and two committee
   updates; and
5. canonical vault MPT witness, empty for a heartbeat and at most 4 MiB plus
   codec overhead for a deposit.

It executes the same pinned Helios consensus, BLS, SSZ, execution-payload, and
vault MPT verification used by host preflight and commits only the canonical
`StrictJournal` bytes. A panic or any decode/verification failure produces no
successful journal.

The dependency is exactly `sp1-zkvm = 6.3.1`; the guest lockfile pins its
registry checksum, and the package's Cargo VCS provenance resolves to the frozen
SP1 commit `8252c2905ce32964df68248117015c61ebb854db`. SP1 patch sources are also
pinned in that lockfile. This source compiles on the host, but the workspace does not
currently have the Succinct zkVM Rust toolchain or `cargo prove`. Consequently
there is no claimed RISC-V build, reproducible ELF, program ID, executor run, or
raw-compressed positive proof yet. Those remain mandatory release blockers.
