# Canonical encoding and commitments

All consensus-facing encodings are fixed and language-neutral:

- unsigned integers are big-endian;
- fixed hashes are 32 bytes and Ethereum addresses are 20 bytes;
- variable byte strings are prefixed by a big-endian `u32` byte length;
- records start with `schema:u16 || type_tag:u16`, except the controller state
  below, whose consensus encoding is exactly 164 bytes with no prefix;
- schema 1 is the only accepted schema;
- a decoder must consume every input byte;
- no field is JSON, ABI dynamic data, native-endian, or implicitly typed.

## Domain-separated SHA-256 record commitments

Rust record commitments in the following table use:

```text
SHA256(
  "USDD" ||
  schema:u16 ||
  domain_length:u16 || domain_utf8 ||
  payload_length:u32 || payload
)
```

Schema-1 domains are:

| Purpose | Domain |
|---|---|
| Merkle leaf | `USDD/1/merkle-leaf` |
| empty Merkle root | `USDD/1/merkle-empty-leaf` |
| Merkle internal node | `USDD/1/merkle-node` |
| deployment manifest | `USDD/1/manifest` |
| non-circular controller configuration | `USDD/1/controller-config` |
| Ethereum proof claim | `USDD/1/claim/ethereum-state` |
| Elements proof claim and bound burn payload | `USDD/1/claim/elements-event` |
| deposit public output | `USDD/1/public/deposit` |
| redemption public output | `USDD/1/public/redemption` |

The Ethereum-compatible vault ID, deposit ID, Elements-state chain,
Elements-state verifier statement, burn ID, and burn leaf do **not** use that
generic wrapper. They use their exact fixed-width `abi.encodePacked`-compatible
formulas and frozen `USDD_*_V1` constants documented in
`contracts/ENCODING.md`. The manifest's domain-table commitment covers all of
those constants as well; the two families must never be substituted for one
another.

## Strict proof journal

The public-values journal is exactly:

```text
magic[8]              = ASCII "USDDJNL1"
schema:u16            = 1
digest_algorithm:u8   = 1 (SHA-256 only)
success_marker[8]     = ASCII "SUCCESS!"
statement_kind:u8     = 1 Ethereum state, 2 Elements state/burn append
program_id[32]
payload_sha256[32]    = SHA256(payload)
payload_length:u32
payload[payload_length]
```

The wrapper must reject a BLAKE3/alternate digest tag, absent or changed
success marker, wrong program ID, wrong statement kind, payload hash mismatch,
unknown schema, noncanonical record, and every trailing byte. These checks are
mandatory even when an underlying raw SP1 verifier is more permissive about
public-value digest algorithms or does not expose an explicit guest exit-code
check.

## Native amount rule

USDT contract amounts use six-decimal micro-units. The Elements USDD asset uses
eight display decimals. The only valid conversion is:

```text
USDD base units = USDT micro-units × 100
```

Mint multiplication must not overflow `u64`. Redemption amounts must be
exactly divisible by 100; sub-micro-USDT dust cannot be redeemed.

## Mint controller state

The singleton controller UTXO commits exactly these 164 bytes:

```text
version:u32 || sequence:u64 || next_mint_nonce:u64 ||
ethereum_light_client_digest[32] || finalized_beacon_slot:u64 ||
finalized_beacon_root[32] || finalized_execution_state_root[32] ||
total_minted_usdd_base:u64 || configuration_hash[32]
```

`configuration_hash` is the `USDD/1/controller-config` hash of the fixed
mint-proof projection specified by
`ProtocolManifest::compute_controller_configuration_hash`. It deliberately
excludes the full manifest ID, controller CMR, issuance identities, and initial
controller-state hash to avoid a self-referential commitment. Those values are
still independently frozen by the full manifest.

## Redemption burn accumulator

The Solidity-compatible accumulator has depth 64. Occupied leaves are the
contiguous prefix `[0,burn_count)` and every later leaf is empty:

```text
EMPTY[0]   = SHA256(0x00)
EMPTY[h+1] = SHA256(0x01 || EMPTY[h] || EMPTY[h])
NODE(L,R)  = SHA256(0x01 || L || R)
```

A branch is exactly 64 sibling hashes in bottom-up order, with no count prefix.
Branches of length 63 or 65 are invalid. The Solidity burn leaf is:

```text
SHA256(0x00 || keccak256("USDD_BURN_LEAF_V1") || version:u32 ||
       elements_genesis[32] || asset[32] || vault_id[32] || burn_id[32] ||
       burn_index:u64 || amount_usdt_micro:u64 || recipient[20])
```

The burn ID is `SHA256(SHA256("USDD_BURN_ID_V1") || elements_genesis ||
burn_txid_display || vout:u32)`. Transaction-ID bytes are RPC/display order,
left to right; internal consensus-order hashes must be reversed first.

## General-purpose ordered Merkle tree (not redemption consensus)

Leaves and internal nodes use the domains above. Left/right order is committed.
At a level with an odd final node, that node is paired with itself. The empty
tree root is the empty-root domain hash. Proofs encode
`leaf_index:u64 || leaf_count:u64 || sibling_count:u32 || siblings[32]*` and
must have the exact depth implied by `leaf_count`.
