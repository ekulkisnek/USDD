# Singleton USDD mint controller V1

Status: normative plan scaffold; no deployable program exists.

## State

The unique controller commits exactly this fixed-width state:

| Field | Type | Rule |
|---|---|---|
| `version` | `u32` | exactly 1 |
| `sequence` | `u64` | increments by exactly 1 per mint batch |
| `nextMintNonce` | `u64` | first Ethereum vault nonce eligible to mint |
| `ethLightClientDigest` | `bytes32` | nonzero commitment to the proved Ethereum light-client state |
| `finalizedBeaconSlot` | `u64` | never decreases |
| `finalizedBeaconRoot` | `bytes32` | nonzero root at that slot |
| `executionRoot` | `bytes32` | nonzero finalized execution-state root |
| `totalMinted` | `u64` | cumulative native USDD eight-decimal base units |
| `configHash` | `bytes32` | immutable V1 deployment/configuration commitment |

There is no shard identifier, deposit-nullifier tree, `totalBurned`, recovery
key, administrator, alternate mint branch, or upgrade branch. Burn accounting
belongs to the separately proved Elements history and Ethereum replay set; it
must not serialize redemptions through the mint controller.

The state encoding/commitment location is not selected here. Before activation,
an executable prototype must prove that current and successor commitments are
fully visible to released Simplicity introspection primitives. A design that
requires an unavailable covenant or hidden off-chain state is invalid.

`configHash` is the `USDD/1/controller-config` hash of the exact non-circular
mint-proof projection defined by `ProtocolManifest::compute_controller_configuration_hash`.
It is not the full manifest ID (which contains this field and the initial state
hash), and it is not the SHA-256 of the Python issuance-review JSON. The full
manifest separately freezes the controller CMR, issuance identities, outbound
guest, and this configuration hash.

## Ethereum proof batch

One annex carries one canonical version-1 SP1 envelope. Its only allowed
statement kind is `ETH_STATE_V1 = 1`. The verified journal commits:

- the immutable `configHash` and pinned Ethereum guest program/VK;
- the prior and next Ethereum light-client digests;
- the prior and next finalized beacon slot/root and execution root;
- `count:u8` in the inclusive range 1..64;
- exactly `count` Ethereum vault deposits in nonce order; and
- the resulting `nextMintNonce` and `totalMinted`.

The same statement also supports a state-only heartbeat, distinguished inside
the strictly decoded journal. This is necessary because Ethereum light-client
updates cannot safely wait indefinitely for deposits: after more than one
4096-slot sync-committee period without a mint, a mint-only controller can lose
the update path needed to prove the next deposit.

Each proved deposit record contains at least the configured chain/vault/USDT,
its vault nonce, exact six-decimal `amountUSDT6`, and exact Elements recipient
script commitment. The guest proves finalized Ethereum consensus, the execution
state transition, the immutable vault code, exact USDT balance movement, and the
vault's deposit record. Logs or RPC responses alone are not authorization.

For a current `nextMintNonce = N`, valid nonces are exactly
`N, N+1, ..., N+count-1`. No sorting, skipping, duplicate, range proof, or
caller-selected partition is accepted. The transition fails on nonce, amount,
sum, multiplication, sequence, or state overflow.

## Mint transaction

After cryptographic proof verification, the Simplicity policy must enforce all
of the following in one transaction:

1. exactly one current controller input is spent;
2. no other input performs issuance or reissuance;
3. the current state equals the journal's prior controller/light-client state;
4. the envelope is canonical, at most 512 KiB, SHA-256-bound, and uses the one
   pinned Ethereum-state guest VK;
5. the batch contains 1..64 exact consecutive nonces starting at
   `nextMintNonce`;
6. for every deposit, mint amount is `amountUSDT6 * 100`, positive and within
   `u64`; the batch sum is also within `u64`;
7. native USDD reissuance equals exactly that batch sum and pays each amount to
   its proved Elements recipient (deterministically coalescing identical
   recipients only if the frozen transaction template explicitly permits it);
8. `sequence' = sequence + 1` and
   `nextMintNonce' = nextMintNonce + count`;
9. `totalMinted' = totalMinted + batchUSDD8`;
10. the successor uses the journal's next light-client digest, beacon
    slot/root, and execution root, with unchanged version/config hash;
11. exactly one successor controller output exists; and
12. every reissuance-token unit returns to that exact successor, with no USDD or
    token inflation elsewhere.

Parsing success cannot satisfy item 4. The current Elements scaffold returns
`SCRIPT_ERR_USDD_SP1_VERIFIER_UNAVAILABLE` even for a canonical proof envelope.

## Permissionless heartbeat transaction

A heartbeat uses a verified `ETH_STATE_V1` light-client proof but contains no
deposit batch. It must enforce all of the following:

1. exactly one current controller input and one exact successor;
2. `sequence' = sequence + 1`;
3. `nextMintNonce' = nextMintNonce` and `totalMinted' = totalMinted`;
4. unchanged version and `configHash`;
5. a strictly newer proved finalized beacon slot and its exact root, execution
   root, and Ethereum light-client digest;
6. zero asset issuance or reissuance in every input;
7. zero USDD recipient outputs and zero reissuance-token leakage; and
8. the reissuance token returns unchanged to the one successor.

Anyone may submit a heartbeat. Strictly newer finalized state prevents replayed
heartbeats from endlessly bumping the sequence and front-running a mint. A
deployment monitor should heartbeat well before the 4096-slot boundary; the
consensus branch is permissionless and does not trust that monitor.

## Canonical burn and payout

Redemption creates one explicit, unspendable USDD output:

```
scriptPubKey = 0x6a || 0x41 ||
               "USDD" || version:u8 || vaultId:bytes32 ||
               ethereumRecipient:bytes20 || amountUSDT6:u64be
asset        = configured native USDD asset (explicit)
value        = amountUSDT6 * 100 USDD8 (explicit)
```

Version is 1; vault ID and recipient are nonzero; amount is positive; and the
multiply must fit `u64`. The 65-byte data push is minimally encoded by `0x41`.
No arbitrary intent nonce, rail tag, Tron address, or config blob is present.

The canonical burn identity is:

```
BURN_ID_DOMAIN = SHA256(ASCII "USDD_BURN_ID_V1")
burnId = SHA256(
    BURN_ID_DOMAIN || elementsGenesis:bytes32 ||
    burnTxidDisplay:bytes32 || burnVout:u32be
)
```

`burnTxidDisplay` is the canonical 64-character RPC/display transaction ID
decoded from hex left-to-right. Code holding an internal `uint256` or
consensus-serialization byte array must convert to this display order first.

Ethereum commits proven burns in one fixed-depth-64 append-only tree. Occupied
leaves are exactly the contiguous prefix `[0, burnCount)`; every later leaf is
empty. The Elements guest must prove this append-only transition, not merely
membership under an arbitrary root. Empty nodes are deterministic:

```
EMPTY[0]   = SHA256(0x00)
EMPTY[h+1] = SHA256(0x01 || EMPTY[h] || EMPTY[h])  for h = 0..63
```

Internal nodes use `SHA256(0x01 || left || right)`. A Solidity membership branch
by itself cannot prove that the committed tree has no gaps or overwritten
leaves; that obligation remains inside the full Elements-validity guest.

The Elements-validity guest submitted to Ethereum proves the exact outpoint,
asset, explicit value, script bytes, valid Elements history, and Bitcoin/BIP301
ancestry/finality. Anyone may submit it. The Ethereum vault consumes `burnId`
before paying exactly `amountUSDT6` to the payload recipient. The submitter
cannot redirect or resize the payout.

This outbound proof never appears as an Elements annex and does not update the
mint controller.

## Required tests before activation

- exact state, mint-journal, and heartbeat-journal vectors across every implementation;
- counts 0, 1, 64, and 65; gaps, duplicates, reordering, wrong first nonce;
- heartbeat with issuance, USDD output, changed nonce/total/config, unchanged or
  decreasing finalized slot, and replayed light-client state;
- every `u64` multiplication/sum/sequence/nonce overflow boundary;
- wrong config, guest VK, chain, vault, token, light-client root, recipient,
  issuance asset, reissuance token, controller CMR, and successor count;
- raw-annex hash mismatch, truncation, trailing bytes, and 512 KiB boundary;
- absent/different authenticated BMM parent context and script-cache isolation;
- burn script nonminimal push, confidential asset/value, value mismatch,
  sub-micro dust, wrong outpoint/vault/recipient, and replay;
- invalid Elements block with a valid-looking BMM commitment; and
- deterministic worst-case verifier cost, memory, block share, and relay policy.
