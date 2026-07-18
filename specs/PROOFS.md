# Proof statements and verifier boundary

## Ethereum state statement

A valid production proof must establish, from the manifest-pinned Ethereum
light-client bootstrap checkpoint and consensus rules:

1. continuous light-client transitions from the prior authenticated state,
   spanning no more than 4096 slots, prove the asserted beacon block finalized;
2. the execution payload belongs to that finalized consensus state;
3. the execution header and state root are valid under Ethereum execution
   rules;
4. the configured vault address contains the pinned runtime code hash;
5. the configured USDT contract and append-only vault storage prove the exact
   deposit record;
6. the record's chain ID, vault, nonce, amount, and Elements recipient equal the
   canonical public claim;
7. the nonce equals the controller's public expected-next nonce;
8. a mint batch contains 1..64 consecutive deposits beginning at the prior
   controller nonce, with every mint amount exactly micro-USDT times 100;
9. the finalized execution timestamp differs from authenticated BMM parent MTP
   by no more than six hours in either direction, and unsupported forks fail
   closed.

A zero-mint heartbeat proves the same light-client transition while preserving
the nonce and minted total. It exists so a gap larger than 4096 slots does not
brick later deposits.

An RPC response, log index, Merkle branch without a verified header, multisig
attestation, or watcher quorum does not satisfy this statement.

## Elements state-transition and burn-append statement

A valid production proof must establish, from the manifest-pinned Bitcoin and
Elements genesis values and consensus rules:

1. full consensus validity of every Elements transition needed to reach the
   asserted state, including UTXOs, scripts/Simplicity, issuance, confidential
   commitments, and conservation;
2. existence and correctness of the exact native-asset burn event;
3. binding of the burn outpoint, amount, vault, USDD asset, and Ethereum
   destination;
4. Bitcoin headers satisfy PoW, difficulty, cumulative-work fork choice, and
   slot-24 BMM ancestry;
5. each burn is at least 100 authenticated Bitcoin-parent confirmations deep;
6. a redemption ID bound to Elements genesis and the display-order burn
   outpoint;
7. the exact prior-to-next Solidity Elements state transition, including tip,
   chainwork, cumulative burn count, and depth-64 burn root;
8. every appended burn occupies the next contiguous index and has a valid
   empty-leaf replacement branch against the evolving root.

A Bitcoin/BMM commitment alone does not prove that the committed Elements block
or its state transition is valid.

## Implemented verifier boundary

`usdd-proof-core` provides deterministic claim validation, output construction,
strict journals, and traits that production proof engines must implement. The
traits document the full obligations above. Tests use exact-match mock verifiers
only under `cfg(test)` to test plumbing; no accept-all production verifier is
shipped.

## Not implemented here

This workspace currently contains no complete Ethereum light-client/execution
guest, no complete Elements/Bitcoin/BMM validity guest, no reproducible
production SP1 ELF/program-ID pipeline, and no measured EVM verifier. SP1 is
pinned to v6.3.1 commit `8252c2905ce32964df68248117015c61ebb854db`;
the strict adapter must additionally enforce SHA-256-only public values and an
explicit `SUCCESS!` marker. Until those systems exist and all launch gates pass
with reproducible evidence, the bridge is not production-ready.
