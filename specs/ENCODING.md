# Canonical encoding and commitments

All consensus-facing encodings are fixed and language-neutral:

- unsigned integers are big-endian;
- fixed hashes are 32 bytes and Ethereum addresses are 20 bytes;
- variable byte strings are prefixed by a big-endian `u32` byte length;
- records start with `schema:u16 || type_tag:u16`, except the controller state
  below, whose consensus encoding is exactly 164 bytes with no prefix;
- schema 2 is the only accepted schema; schema 1 is permanently rejected
  because it allowed a prover-supplied BMM-parent timestamp in Ethereum claims;
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

Protocol-V1 domains under encoding schema 2 are:

| Purpose | Domain |
|---|---|
| Merkle leaf | `USDD/1/merkle-leaf` |
| empty Merkle root | `USDD/1/merkle-empty-leaf` |
| Merkle internal node | `USDD/1/merkle-node` |
| deployment manifest | `USDD/1/manifest` |
| non-circular controller configuration | `USDD/1/controller-config` |
| non-circular outbound verifier configuration | `USDD/1/outbound-verifier-config` |
| Ethereum proof claim | `USDD/1/claim/ethereum-state` |
| Elements proof claim and bound burn payload | `USDD/1/claim/elements-event` |
| deposit public output | `USDD/1/public/deposit` |

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
schema:u16            = 2
digest_algorithm:u8   = 1 (SHA-256 only)
success_marker[8]     = ASCII "SUCCESS!"
statement_kind:u8     = 1 Ethereum state, 2 Elements state
program_id[32]
payload_sha256[32]    = SHA256(payload)
payload_length:u32
payload[payload_length]
```

The payload is not opaque. Kind 1 accepts exactly one canonical deposit public
output (tag `0x5201`) or heartbeat public output (tag `0x5204`). Kind 2 accepts
exactly one canonical cumulative Elements-state public output (tag `0x5203`).
The per-burn diagnostic journal from the earlier draft is not an authorization
path and is not part of the production API.

Both Ethereum public outputs carry the finalized execution block timestamp
proved by Ethereum consensus. They never carry BMM parent MTP. The Elements
controller obtains parent MTP only from its authenticated block-validation
environment and enforces `abs(execution_timestamp - parent_mtp) <= 21600`.

The wrapper must reject a BLAKE3/alternate digest tag, absent or changed
success marker, wrong program ID, wrong statement kind, payload hash mismatch,
unknown schema, noncanonical record, and every trailing byte. These checks are
mandatory even when an underlying raw SP1 verifier is more permissive about
public-value digest algorithms or does not expose an explicit guest exit-code
check.

The 32-byte SP1 program ID is exactly `HashableKey::hash_bytes`: eight
canonical KoalaBear field words encoded big-endian. It is not
`SHA256(serialized_vkey)`. SP1's raw compressed-verifier API consumes the same
eight words as fixed-width little-endian bincode bytes; the verifier adapter
performs and checks that wordwise conversion.

## Native amount rule

USDT contract amounts use six-decimal micro-units. The Elements USDD asset uses
eight display decimals. The only valid conversion is:

```text
USDD base units = USDT micro-units × 100
```

Mint multiplication must not overflow `u64`. Redemption amounts must be
exactly divisible by 100; sub-micro-USDT dust cannot be redeemed.
A canonical deposit amount is no greater than `20_000_000_000_000`
micro-USDT, matching the immutable vault's 20,000,000-USDT per-deposit limit.
A mint batch has the same aggregate cap. The resulting
`2_000_000_000_000_000` USDD base units leave
`100_000_000_000_000` explicit-value units below Elements' cross-asset,
transaction-wide `MAX_MONEY` sum for the singleton reissuance-token output,
fees, and non-protocol change. A canonical burn uses the same 20,000,000-USDT
ceiling so the burn transaction can include an explicit fee; larger
redemptions are split into multiple burns.

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

## Outbound Elements bridge state

The Solidity-compatible state contents are exactly 200 packed bytes:

```text
sequence:u64 || burn_count:u64 || elements_tip_hash[32] ||
elements_consensus_state_digest[32] || cumulative_burn_root[32] ||
finalized_bitcoin_block_hash[32] || bitcoin_height:u64 ||
elements_height:u64 || bitcoin_median_time_past:u64 ||
bitcoin_chainwork:u256
```

`elements_consensus_state_digest` commits the deterministic full state needed
to validate the next Elements transition incrementally, including the UTXO set
and consensus/activation context at the committed tip. A tip hash alone is not
an incremental validity state. Every non-bootstrap transition must advance this
digest.

## General-purpose ordered Merkle tree (not redemption consensus)

Leaves and internal nodes use the domains above. Left/right order is committed.
At a level with an odd final node, that node is paired with itself. The empty
tree root is the empty-root domain hash. Proofs encode
`leaf_index:u64 || leaf_count:u64 || sibling_count:u32 || siblings[32]*` and
must have the exact depth implied by `leaf_count`.
