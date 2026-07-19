# USDD Elements V1 canonical formats

Status: scaffold formats for cross-language review. No proof is accepted by the
current Elements code.

All multibyte integers are unsigned big-endian. Fixed hashes are raw 32 bytes;
Ethereum addresses are raw 20-byte VM addresses. Decoders reject trailing
bytes, unknown versions/flags, alternate widths, and zero required identifiers.

## Ethereum-state SP1 Taproot annex

The annex includes its Taproot annex tag. Maximum total size is 512 KiB and
public values are 1..16 KiB.

| Offset | Size | Field | V1 |
|---:|---:|---|---|
| 0 | 1 | annex tag | `50` |
| 1 | 8 | magic | ASCII `USDDSP1\0` |
| 9 | 1 | envelope version | `1` |
| 10 | 1 | proof system | `1` = SP1 compressed |
| 11 | 1 | statement kind | `1` = `ETH_STATE_V1` only |
| 12 | 1 | digest mode | `1` = SHA-256 |
| 13 | 2 | flags | `0` |
| 15 | 4 | public-values length | `1..16384` |
| 19 | 4 | proof length | nonzero |
| 23 | 32 | Ethereum guest program ID (`HashableKey::hash_bytes`) | nonzero |
| 55 | variable | public values | exact declared length |
| ... | variable | opaque proof | exact declared length |

`ETH_STATE_V1` contains either a 1..64-deposit mint transition or a state-only
heartbeat transition. That choice is part of the strict verified journal, not a
second annex kind. `0x50 || "USDD"` reserves the namespace. Kind 2 is rejected: an Elements burn
proof is submitted to Ethereum and has no reason to be consumed by Elements.
Successful parsing is never proof authorization.

### Timestamp authorization boundary

The strictly typed `ETH_STATE_V1` journal includes the finalized Ethereum
execution-block timestamp proved by the Ethereum guest. Neither the Ethereum
claim nor its public output includes a BMM parent MTP. A field supplied by the
prover or guest host and labelled as BMM MTP is noncanonical.

At controller execution, `current_bmm_parent_mtp` comes only from the Elements
environment jet after block validation authenticates the BIP301 parent context.
The controller requires the absolute difference between that value and the
journal's proved execution timestamp to be at most `21,600` seconds, using
checked unsigned arithmetic. Wall-clock time and an unbound RPC response are not
authorization.

## Controller state record

The proposed fixed-width state bytes are 164 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | `version = 1` |
| 4 | 8 | `sequence` |
| 12 | 8 | `nextMintNonce` |
| 20 | 32 | `ethLightClientDigest` |
| 52 | 8 | `finalizedBeaconSlot` |
| 60 | 32 | `finalizedBeaconRoot` |
| 92 | 32 | `executionRoot` |
| 124 | 8 | `totalMinted` in USDD8 |
| 132 | 32 | immutable `configHash` |

This record has no `totalBurned`, rail, shard, or upgrade field. The final
on-chain commitment construction remains blocked until Elements introspection
can authenticate current and exact successor state.

## Amount and batch rules

USDT uses six decimal contract units and USDD uses eight decimal asset units:

```
amountUSDD8 = amountUSDT6 * 100
```

Both the per-deposit multiplication and batch sum use checked `u64`. One
deposit and one aggregate batch are capped at 20,000,000 USDT /
2,000,000,000,000,000 USDD base units, leaving
100,000,000,000,000 units of Elements transaction-wide explicit-output
headroom. A mint batch has 1..64 nonces and the exact list is
`nextMintNonce .. nextMintNonce + count - 1`.

## Canonical Elements burn

The burn data is exactly 65 bytes:

| Offset | Size | Field | V1 |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `USDD` |
| 4 | 1 | version | `1` |
| 5 | 32 | Ethereum `vaultId` | nonzero |
| 37 | 20 | Ethereum recipient | nonzero |
| 57 | 8 | `amountUSDT6` | `1..20,000,000e6` |

The exact script is 67 bytes:

```
6a 41 <65-byte burn data>
```

`6a` is `OP_RETURN`; `41` is the minimal direct push for 65 bytes. The output
asset is the explicit configured native USDD asset. The explicit output value
is `amountUSDT6 * 100` USDD8. The proof rejects other push encodings,
confidential fields, value mismatch, extra payload fields, and trailing bytes.

There is no caller-selected redemption ID. For a canonical display transaction
ID and a `u32` output index:

```
BURN_ID_DOMAIN = SHA256(ASCII "USDD_BURN_ID_V1")
burnId = SHA256(
    BURN_ID_DOMAIN || elementsGenesis[32] || burnTxidDisplay[32] || vout:u32be
)
```

`burnTxidDisplay` is the canonical 64-character RPC/display txid hex decoded
left-to-right. Every implementation must explicitly convert from any internal
`uint256` or consensus-serialization order before this boundary.

### Burn accumulator empty nodes

The burn accumulator has fixed depth 64. Burns occupy exactly indices
`[0, burnCount)` in append order and every index at or above `burnCount` is
empty. The full Elements guest enforces that prefix invariant.

```
EMPTY[0]   = SHA256(0x00)
EMPTY[h+1] = SHA256(0x01 || EMPTY[h] || EMPTY[h])
NODE(l,r)  = SHA256(0x01 || l || r)
```

`EMPTY[64]` is the root of a completely empty tree. Branch entries are ordered
bottom-up; index bit `h` selects left/right at height `h`. A membership verifier
does not by itself prove append-only construction.

## Bootstrap issuance-review record (non-consensus)

The Python scaffold accepts one exact, Ethereum-only JSON subset for reviewing
basic issuance/controller identifiers. Lowercase hex has no `0x` prefix.
Required fields are:

```
protocol = "USDD"
version = 1
ethereum_chain_id:u64 > 0
ethereum_genesis:bytes32
bitcoin_genesis:bytes32
elements_genesis:bytes32
drivechain_slot = 24
usdt:bytes20
vault:bytes20
vault_code_hash:bytes32
usdd_asset_id:bytes32
reissuance_token_id:bytes32
issuance_txid:bytes32
issuance_vout:u32
asset_entropy:bytes32
controller_cmr:bytes32
controller_initial_state_hash:bytes32
ethereum_guest_program_id:bytes32
elements_guest_program_id:bytes32
minimum_bitcoin_confirmations:u32 >= 100
first_mint_nonce:u64
usdt_decimals = 6
usdd_decimals = 8
usdd_units_per_usdt_micro = 100
max_mint_batch = 64
```

Canonical review bytes use sorted keys and compact UTF-8 JSON with no newline;
`reviewDigest` is SHA-256 of those bytes. **`reviewDigest` must never be used as
the protocol manifest ID or controller `configHash`.** This subset deliberately
does not duplicate the finalized Rust manifest, which additionally binds the
verifier address/codehash, SP1 commit/circuit/codec/constants, bootstrap
checkpoint and digest, minimum activation chainwork, public ABF, and complete
domain/config tables. The review tool also does not derive asset IDs, create an
issuance transaction, or prove that a CMR is deployable.

## Inventory HTLC parameters

The inventory HTLC has no canonical bridge payload. Its source-template
parameters are validated as described in `INVENTORY_HTLC_V1.md`: one nonzero
SHA-256 secret hash, distinct valid claimant/refund x-only secp256k1 public
keys, an Elements absolute timestamp refund deadline, and an external refund
timestamp at least 86,400 seconds later. Asset and amount belong to the funded
Elements UTXO; both branches require the appropriate fixed key to sign the
complete transaction's `sig_all_hash`.
