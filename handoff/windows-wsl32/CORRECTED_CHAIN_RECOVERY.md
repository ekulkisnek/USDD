# Corrected slot-24 chain recovery

## Why the 0–628 capture is rejected

The original proof guest pinned the stale internal proposal hash
`4960458d2502e27346fbd042634259734607be4e5d03ac47264506c3d0a2be8c`.
The captured chain instead activates the current Elements proposal
`b8aaccf53b31e14e31e2de2daaf5aded6b48056d302006f27dc5b3c34d8a9a16`
at height 8. At height 109, the stale proposal replaces the current proposal.
No single Elements identity is therefore continuous from activation through the
M6 at height 498.

The capture is useful failure evidence but cannot authorize a withdrawal.
Never trim it, reset replay state, weaken continuity, or prove only the suffix.

All recovery identities and public test credentials are frozen in
`specs/ecash-corrected-chain-v1.json`.

## Correct recovery

Generate a fresh private-Signet history from the pinned genesis. The current
Elements proposal must be the first and only slot-24 activation and must remain
active through the accepted M6 and its finality period.

The old segment and fold ELFs must remain preserved as evidence, but they must
not be used. Updating the required proposal changes the guest program identity.
Rebuild both guests reproducibly and freeze their new ELFs, raw vkey hashes,
program IDs, toolchain provenance, and checksums before preparing segments.

## Self-contained Windows procedure

1. Preserve every existing failed run and the original `507c569` checkout.
2. Use a fresh WSL-native checkout of the corrected USDD commit.
3. Validate `specs/ecash-corrected-chain-v1.json`, including recomputing the
   proposal SHA256d in both internal and display order.
4. Build the pinned Bitcoin Signet miner and enforcer sources named by the
   recovery specification.
5. Create a brand-new datadir. Never reuse the invalid chain database.
6. Start private Signet with the frozen challenge and test-only WIF.
7. Start the enforcer with the frozen test-only mnemonic.
8. Before submitting any other slot-24 proposal, submit this exact declaration
   through `BlockProducerService.SubmitSidechainProposal`:

```text
sidechain_id: 24
title: Elements
description: Blockstreams elements, enabling simplicity script
hash_id_1: 5883560531f013b9b27b2f9cfbac4f64ee5062b95ad3e21593a8f6916530b74b
hash_id_2: b2b7b20f3fbc4baf50e9d39f58661c6168e279d4
```

9. Mine the M1 and explicitly ACK only that proposal. Mine until the enforcer
   reports slot 24 active with the exact internal proposal hash. Do not enable
   or alter `ack_all_proposals`.
10. Assert from genesis replay that no other slot-24 proposal was introduced,
    ACKed, or activated.
11. Create a real slot-24 deposit through the enforcer wallet so the chain has
    a consensus-valid CTIP.
12. Construct a canonical USDD accumulator-root M6 spending that CTIP, submit
    it through `WalletService.BroadcastWithdrawalBundle`, mine its M3 and M4
    approvals, and require the enforcer to include the actual M6 transaction.
13. Confirm that the M6 successor treasury output is `vout 0`, that its CTIP
    transition is exact, and that the M6 commits to the intended vault,
    Elements genesis, USDD asset, prior root, and next root.
14. Mine at least 100 blocks after M6 inclusion without introducing any
    replacement slot-24 proposal.
15. Capture every raw block from genesis through finality, plus the exact M6
    artifact and all proposal/vote/CTIP evidence.
16. Split the capture into bounded consecutive segments. Put the M6 artifact
    only beside its actual inclusion block.
17. Rebuild the SP1 guests and host from the corrected clean commit. Record the
    new program identities; never reuse the old `507c569` identities.
18. Run native preparation and replay for every segment. Require exact height,
    tip, state-commitment, proposal-continuity, CTIP, M6, and journal adjacency.
19. Only after native replay succeeds, run segment proofs sequentially, verify
    each result, fold adjacent proofs, Groth16-wrap the final fold, and
    SDK-verify the wrapper.
20. Package source identities, raw inputs, expected journals, proofs, public
    values, Ethereum verifier arguments, logs, timings, peak resources, and
    checksums. Generated proofs stay outside Git.

## Mandatory negative checks

- Replaying the original 0–628 capture must fail deterministically.
- Introducing the stale `496045…be8c` proposal anywhere in the corrected
  history must fail.
- Any proposal replacement after the current proposal activates must fail.
- Any M6 with the wrong CTIP, vault, roots, asset, transaction, inclusion
  height, or confirmation depth must fail.
- Any attempt to use an old ELF, program ID, vkey, prepared input, or Ethereum
  verifier identity must fail.

## Ethereum consequence

The corrected guest produces a new SP1 program identity. The immutable
Ethereum proof component and relay deployment must pin that new identity.
The earlier single-segment Groth16 wrapper remains test evidence only and
cannot authorize the corrected production transition.
