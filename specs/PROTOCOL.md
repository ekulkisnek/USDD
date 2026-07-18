# USDD V1 protocol

## Scope and honest terminology

V1 is an asynchronous, proof-authorized two-way bridge between an Ethereum
USDT vault and one native Elements asset. It is not a synchronous atomic swap:
Ethereum and Elements do not commit their state transitions in one shared
consensus transaction. V1 obtains cryptographic safety by making each source
transition final first and allowing any party to relay a validity proof to the
destination. Relayers and proof builders affect liveness, not authorization.

Ethereum is V1's sole canonical reserve and issuance domain. Tron cannot mint
USDD. A future Tron integration is limited to an inventory swap whose safety is
specified independently; it cannot alter Elements issuance or Ethereum backing.

## Immutable deployment manifest

Every accepted statement binds the canonical manifest commitment. The
manifest fixes:

- Ethereum, Bitcoin, and Elements genesis commitments;
- Drivechain slot 24;
- the Ethereum chain ID, USDT contract, vault address, and vault code hash;
- the native Elements USDD asset, reissuance token, public ABF, issuance
  outpoint/entropy, controller CMR/configuration hash, and initial state hash;
- the proof-program IDs, SP1 toolchain identity, verifier address/code/config,
  recursion constants, SHA-256-only mode, and domain table;
- bootstrap Ethereum light-client state, maximum 4096-slot transition, maximum
  absolute six-hour execution-timestamp/BMM-parent-MTP difference;
- at least 100 Bitcoin confirmations, activation chainwork, and liability cap;
- six USDT decimals, eight USDD decimals, and the exact multiplier 100;
- the first sequential deposit nonce.

V1 has one singleton controller state per vault and one sequential nonce.

## Mint path: finalized USDT deposit to native USDD

1. A user transfers USDT into the immutable vault through its deposit entry
   point. The vault records the amount, Elements recipient, and the next
   sequential per-vault nonce. The deposit is permanent; it has no timeout or
   unilateral refund after acceptance.
2. Any prover constructs a proof of finalized Ethereum consensus and execution
   state rooted at the manifest's Ethereum genesis. The proved state must show
   the exact vault code and exact deposit record.
3. The proof journal binds the manifest ID, 1..64 consecutive deposit
   records, the prior controller state, and the currently expected nonce. The strict envelope requires SHA-256, the
   fixed success marker, the manifest's program ID, canonical encoding, and no
   trailing bytes.
4. An Elements mint transaction spends the unique controller UTXO. Its
   Simplicity policy accepts only consecutive nonces beginning at `N`, creates
   each exact `amount_micro × 100` native USDD output, and recreates the
   controller state with `N + batch_length`.
5. Because the controller UTXO is unique and the nonce advances exactly once,
   replayed and out-of-order deposits cannot mint.

Permissionless zero-mint heartbeats can advance the authenticated Ethereum
light-client state by at most 4096 slots without changing the nonce or supply.
The nonce rule is deliberately sequential. If proof for nonce `N` is not
published, later deposits wait. Anyone can produce the missing proof, so there
is no trusted operator, but availability engineering must be measured before
launch.

## Redemption path: irreversible USDD burn to USDT payout

1. A holder creates the prescribed Elements burn output/transaction committing
   the native USDD asset, an amount exactly divisible by 100 base units, the
   Ethereum destination, vault, and burn outpoint.
2. The burn is irreversible once canonical. There is no claim that the burn and
   Ethereum payout happen simultaneously.
3. Any prover proves Elements block validity and canonical ancestry, including
   the Bitcoin/BMM relation and the manifest's required Bitcoin confirmations.
   A BMM commitment alone proves neither the Elements state transition nor the
   burn.
4. The proof advances the Ethereum vault's authenticated Elements state and
   cumulative depth-64 burn root. A claim supplies the exact 64-sibling branch;
   the vault verifies membership and pays exactly `usdd_base / 100`
   micro-USDT to the committed destination. Contiguous burn indices and the
   paid bitmap prevent replay.
5. If submission or gas payment fails, any party can retry. A failed relay must
   not make a second burn necessary. Once paid, the consumed redemption ID
   prevents a second payout.

## Safety and liveness boundaries

Safety depends on all of the following, not on a relayer:

- immutable correct vault and Elements policy;
- exact amount conversion and strict token transfer accounting;
- finalized Ethereum consensus/execution proof soundness;
- full Elements validity plus Bitcoin/BMM ancestry proof soundness;
- strict proof-envelope verification and pinned program IDs;
- unique controller UTXO plus sequential nonce consumption;
- one-time redemption consumption on Ethereum.

Provers, relayers, RPC endpoints, indexers, and user interfaces are replaceable
and permissionless. They can delay progress or present bad data, but their data
must never authorize minting or payout without a verified proof.

USDD can become useful across other Drivechains only through separately proven
asset-transfer or swap paths on those chains. Calling it ecosystem-wide does
not itself create cryptographic interoperability.
