# USDD Elements/Simplicity V1 scaffold

Status: **fail closed and not deployable**.

See [`BUILD_BLOCKERS.md`](BUILD_BLOCKERS.md) for the mandatory new-network,
consensus-verifier, proof-guest, policy, and activation checklist.

This directory covers the locked Ethereum-only V1 and one separate
inventory-swap HTLC. It does not define a Tron vault, Tron mint path, Tron
redemption path, controller shards, upgrade path, lending, or yield.

Canonical V1 is an asynchronous proof bridge:

1. USDT is permanently deposited into the immutable Ethereum vault under a
   sequential vault nonce and an Elements recipient.
2. Any prover proves a finalized Ethereum consensus/execution-state transition.
3. One Elements controller UTXO consumes a batch of 1 through 64 consecutive
   vault nonces, reissues `amountUSDT6 * 100` units of the native eight-decimal
   USDD asset, and recreates itself with the exact next state.
4. A holder redeems by creating the canonical Elements USDD burn output.
5. Any prover proves the valid, BIP301-anchored Elements burn to Ethereum. The
   vault pays the payload's fixed recipient once for the `txid:vout` burn.

Relayers and proof builders are replaceable and permissionless. They affect
liveness, never authorization. The two chain transitions are not simultaneous,
so “atomic swap” is not accurate for the canonical bridge.

Tron is inventory-only in V1: counterparties may use independent HTLCs to swap
existing USDD against existing Tron USDT. That flow cannot mint USDD, release
the Ethereum vault, or share the canonical controller. See
`INVENTORY_HTLC_V1.md`.

## Locked monetary and state rules

- Ethereum USDT has six decimals; native USDD has eight decimals.
- `USDD8 = USDT6 * 100`, checked in `u64` arithmetic.
- Exactly one controller exists.
- A mint transition consumes 1..64 deposits whose vault nonces are consecutive,
  start at `nextMintNonce`, and appear in increasing order.
- A separate permissionless heartbeat consumes no deposit and mints nothing. It
  advances only verified Ethereum light-client/finality state plus `sequence`,
  leaving `nextMintNonce` and `totalMinted` unchanged. This prevents an idle
  controller from falling more than one Ethereum sync-committee period behind.
- Controller state contains exactly: `version`, `sequence`, `nextMintNonce`,
  Ethereum light-client digest, finalized beacon slot and root, execution root,
  `totalMinted`, and configuration hash. It has no `totalBurned` field.
- Burns do not spend or update the mint controller.

## Hard blockers before activation

- **No SP1 verifier jet:** envelope parsing is not proof verification. A verifier
  must be added as a real upstream Simplicity jet with a specified type, CMR,
  generated C/Haskell identifiers and dispatch, deterministic cost, activation,
  and independent vectors. A local C helper is not sufficient.
- **Raw annex bytes are unavailable to jets:** `rawElementsInput` receives an
  annex, but `simplicity_elements_mallocTransaction`/`copyInput` keeps only its
  hash. The environment must own a bounded copy (maximum 512 KiB), bind it to
  `annexHash`, define allocation/lifetime behavior, and charge deterministic
  memory and verification cost.
- **Authenticated block context:** `current_bmm_parent_mtp` may be marked present
  only after the node ties the mainchain parent to the sidechain block through a
  mined BIP301 commitment. Block script-cache keys must include it. Mempool and
  template validation need an explicit candidate-parent context; wall clock
  time and an unbound RPC response are invalid substitutes.
- **Controller state commitment:** a prototype must demonstrate that released
  Elements introspection jets can authenticate the current state, all mint
  outputs, and one exact successor while keeping every reissuance-token unit in
  that successor.
- **Production guests:** there is no complete Ethereum finality/execution-state
  guest and no complete Elements/Bitcoin/BIP301 validity guest. The Elements
  annex accepts only the Ethereum-state transition statement. Redemption proof is an
  Ethereum input, not a second Elements annex kind.
- **Relay/mining policy:** all Taproot annexes are currently non-standard and a
  512 KiB witness can exceed standard transaction weight. Any exception must be
  USDD-envelope-specific, fully proof-verified, fee/weight charged, and capped so
  one proof transaction uses at most 25% of block capacity. It must not make
  arbitrary large annexes standard.
- **Cross-language identity:** burn script bytes, `burnId`, manifest/config hash,
  journals, state encoding, asset IDs, CMR, and program IDs must match C++,
  Simplicity, Rust, Solidity, and Python vectors byte for byte.

`usdd_formats.py` includes a non-consensus issuance-review record for checking
basic bootstrap identifiers. Its JSON digest is not the protocol manifest ID or
controller `configHash`. Only the non-circular controller projection computed
by the canonical Rust manifest may define `configHash`; the full manifest also
binds verifier address/codehash, SP1 build identity and constants, bootstrap
checkpoint/digest, activation chainwork, public ABF, and domain/config tables.

The base protocol keeps USDT idle. USDT itself remains issuer-controlled and
freezable; cryptography can remove a bridge custodian but cannot remove that
underlying asset risk.
