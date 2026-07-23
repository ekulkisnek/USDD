# Mac-to-Windows proof handoff status — 2026-07-23

## Completed and reproducible

- Captured 629 consecutive private-Signet blocks, heights 0 through 628.
- Captured the accepted slot-24 M6 at height 498 and more than 100 following
  confirmations.
- Split the chain into four consecutive proof segments: `1..1`, `2..257`,
  `258..513`, and `514..628`.
- Frozen the private-Signet challenge, chain identities, M6 artifact, CTIP
  transition, reward recipient, and every input checksum.
- Added the Mac handoff builder and Windows runner for segment proving,
  recursive folding, Groth16 wrapping, independent result verification, and
  checksummed packaging.
- Made handoff publication atomic. A failed native preparation remains under a
  visibly incomplete `.NAME.building` directory and cannot be confused with a
  completed handoff.
- Added tests proving successful publication and fail-closed behavior when the
  native prover exits unsuccessfully.
- Independently validated the existing current-V7 Ethereum compressed proof
  and the returned eCash segment Groth16 wrapper against their frozen
  identities.
- Exercised the Solidity M6 authorization and payout path, including replay,
  competing-M6, malformed-proof, CTIP, and missing-vote rejection tests.

## Authentic fixture limitation

The accepted private-Signet M6 commits to vault ID
`14763a538e170c96288a1aa50890393622b6c93ab64fb72f9839e5cc9f79e628`.
It is valid evidence for the captured test-chain transition, but it does not
authorize a payout from a differently identified Sepolia deployment. It must
not be represented as a live withdrawal from the current Sepolia vault.

## Windows-first preparation decision

The stopped Mac VM exposed only 6 GiB of RAM, and its previously built host
predated successor-segment preparation. The preparation gate therefore moves
to the 32 GiB Windows/WSL machine. This does not change any cryptographic
assumption: all blocks, identities, ELFs, checksums, expected M6 evidence, and
the exact source commit remain frozen before transfer.

The raw handoff contains:

- `artifacts/testnet/ecash-private-signet-0-628-m6-v1`
- `artifacts/testnet/private-signet-m6-genesis-spec.json`
- the frozen `ecash-segment-v1.elf`
- the frozen `ecash-fold-v1.elf`
- the exact source commit used to build the matching eCash prover host

Windows must natively execute all four captured inputs and verify state
commitment, block tip, and height adjacency before it may start proving.

## Next Windows work

Windows should receive the immutable raw handoff and run
`handoff/windows-wsl32/start-transition-handoff.sh`. Windows will then produce:

1. a native-preflighted prepared handoff with exact expected journals;
2. one compressed-transparent proof for each of the four adjacent segments;
3. the recursive fold covering heights 1 through 628;
4. the folded-M6 Groth16 proof and Ethereum verifier arguments;
5. proof metadata, public values, logs, and checksums.

No generated proof belongs in Git. The reproducible runner and non-secret
inputs may be pushed before proving because native preflight is now a mandatory,
fail-closed first stage of the Windows worker.

## Release gates that remain after Windows

- Bind and exercise an accepted M6 produced for the exact deployment vault,
  rather than the foreign test vault captured here.
- Freeze final mainnet chain, contract, asset, verifier, and program identities.
- Complete independent Solidity, SP1, protocol, and Elements/Simplicity audits.
- Measure production gas and establish adequate prover-bounty economics.
- Complete public adversarial testing and the required long-running soak.
- Validate the final deployment and reserve-accounting lifecycle without mocks
  or test-only identities.

These are production release gates, not tasks that can be satisfied by
generating another proof on either local computer.
