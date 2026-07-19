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
   controller nonce, with every mint amount exactly micro-USDT times 100 and
   aggregate principal no greater than 20,000,000 USDT so the Elements
   transaction retains explicit-output headroom;
9. the finalized execution timestamp is exposed in the canonical public output,
   and unsupported forks fail closed.

The Ethereum proof does not receive or authenticate Bitcoin parent time. The
Elements controller obtains current BMM-parent MTP from the block-validation
environment, compares it with the proved execution timestamp, and rejects an
absolute difference above six hours. A prover-supplied parent MTP is invalid by
construction in schema 2.

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
   an advancing full-consensus/UTXO-state digest, chainwork, cumulative burn
   count, and depth-64 burn root;
8. every appended burn occupies the next contiguous index and has a valid
   empty-leaf replacement branch against the evolving root.

A Bitcoin/BMM commitment alone does not prove that the committed Elements block
or its state transition is valid.

## Implemented verifier boundary

`usdd-proof-core` provides deterministic claim validation, output construction,
strict typed journals, and traits that production proof engines must implement.
The traits document the full obligations above. One cumulative state proof
advances the vault root; per-burn proof journals are not an authorization path,
and ordinary 64-sibling membership branches authorize individual payouts. No
accept-all production verifier is shipped.

`usdd-ethereum-inbound` now implements the bounded vault account, immutable
code-hash, and consecutive deposit-storage MPT checks plus a pinned native
Sepolia Helios SSZ/BLS/finality verifier. `ETHEREUM_GUEST.md` freezes its exact
SP1-Helios reference, finality-composition commitment, real fixture,
implemented scope, and remaining zkVM artifact work. It ships no permissive
finality verifier.

`usdd-bitcoin-bmm` implements a no-std, vector-tested subset of the outbound
parent proof: canonical headers and block/transaction parsing, SHA256d IDs,
legacy and SegWit txids, context-free transaction checks, block weight,
non-mutated Merkle-root and BIP141 witness-commitment validation, compact
targets, PoW, exact block work, overflow-safe cumulative work, the LayerTwo
Signet difficulty schedule and frozen P2WPKH/BIP143 solution, parent linkage,
and the Elements node's strict slot-24 M7 encoding. It also ports the fork's
bounded slot-24 M1/M2 activation and positive-only CTIP replay, and binds exact
M8 requests to the M7 child hash and predecessor. The standalone M7 parser
still returns `UnboundCanonicalM7`; the strongest integrated exact-block API is
the only route to a Signet-authorized, PoW/Merkle-bound result, while the replay
API emits an `ElementsSlot24BmmEdge` only for an active frozen proposal and
minimal M7.

The replay's 1,222,221 pending-proposal ceiling is derived from the parser's
111,111-output block bound and the eleven live proposal ages; it does not evict
live state. Every CTIP decrease is rejected because M3/M4/M6 voting is absent.
The production guest must still compose all contextual/UTXO and script Bitcoin
rules, all-slot/global BIP300 validity, M3/M4/M6, continuous best-work ancestry,
reorg/finality tracking, and 100-confirmation depth. A Merkle-bound replay
result alone is not bridge authorization.

## Not implemented here

This workspace currently contains no complete Ethereum light-client guest, no
complete Elements/Bitcoin/BMM validity guest, no reproducible production SP1
ELF/program-ID pipeline, no generated Simplicity verifier jet, and no measured
EVM verifier. SP1 is pinned to v6.3.1 commit
`8252c2905ce32964df68248117015c61ebb854db`. The host adapter enforces
SHA-256-only public values, exact typed journals, an explicit `SUCCESS!`
marker, canonical raw compressed proof encoding, and wrapper-proof rejection,
but its success path still lacks a reproducible positive proof fixture. Until
the missing proof programs and all launch gates pass with reproducible
evidence, the bridge is not production-ready.
