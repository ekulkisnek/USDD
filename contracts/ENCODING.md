# USDD V1 byte and ABI encoding

This document is normative for the Solidity/Rust boundary. All concatenations below are raw byte concatenation with no length prefixes. All final commitment, state, leaf, and node hashes use SHA-256.

## Primitive encodings

- `u32be(x)`, `u64be(x)`, and `u256be(x)` are unsigned integers in exactly 4, 8, and 32 bytes, big-endian.
- `address20(x)` is the raw 20-byte EVM address, with no 12-byte ABI padding.
- `bytes32` is exactly 32 bytes.
- `script` is the unmodified raw Elements `scriptPubKey` byte sequence.
- Solidity implements these concatenations with `abi.encodePacked` over fixed-size values.
- Domain constants are Ethereum Keccak-256 (not NIST SHA3-256) of the exact ASCII labels below. Consumers should either compute them once or read the public constant from the deployed vault.

| Constant | ASCII label |
|---|---|
| `VAULT_ID_DOMAIN` | `USDD_VAULT_ID_V1` |
| `DEPOSIT_ID_DOMAIN` | `USDD_DEPOSIT_ID_V1` |
| `ELEMENTS_STATE_DOMAIN` | `USDD_ELEMENTS_STATE_V1` |
| `ELEMENTS_STATEMENT_DOMAIN` | `USDD_ELEMENTS_STATEMENT_V1` |
| `BURN_LEAF_DOMAIN` | `USDD_BURN_LEAF_V1` |

`BURN_ID_DOMAIN` is different by explicit protocol agreement: it is SHA-256 of ASCII `USDD_BURN_ID_V1`, equal to `5811f3ff8b8f31fb49ffb91afab13197c3d72e926549ae29dbda46c6998a3e45`.

USDT amounts use six-decimal micro-units (`amountUSDT6`) and are encoded as
`uint64` at the bridge boundary. Elements USDD uses eight-decimal base units;
the exact corresponding output value is `amountUSDT6 * 100`. One deposit and
one mint batch may contain at most 20,000,000 USDT. This retains
100,000,000,000,000 explicit-value units below Elements' transaction-wide
21,000,000 × 10^8 sum for the authority-token successor, fees, and change.
One canonical burn has the same 20,000,000-USDT ceiling so its transaction can
also include an explicit fee output.

## Vault ID

```text
vaultId = SHA256(
    VAULT_ID_DOMAIN
 || u256be(evmChainId)
 || address20(vault)
 || address20(usdt)
 || address20(proofVerifier)
 || verifierProgramId
 || verifierConfigHash
 || elementsGenesisHash
 || usddAssetId
 || u256be(1_000_000_000e6)
 || u256be(minimumActivationChainwork)
)
```

## Deposit commitment

The nonce is zero-based and increments by exactly one. `deposit(amountUSDT6, elementsScript, userSalt)` returns `(nonce, depositId)` and writes the exact `depositId` to `depositCommitmentByNonce[nonce]`.

```text
scriptHash = SHA256(script)

depositId = SHA256(
    DEPOSIT_ID_DOMAIN
 || u32be(1)
 || u256be(evmChainId)
 || address20(vault)
 || address20(usdt)
 || u64be(nonce)
 || address20(depositor)
 || u64be(amountUSDT6)
 || scriptHash
 || userSalt
)
```

The V1 mapping is at Solidity storage slot 12. Its storage-proof key is:

```text
keccak256(abi.encode(uint64(nonce), uint256(12)))
```

Here `abi.encode`, unlike `abi.encodePacked`, pads both mapping-key inputs to 32 bytes. The value at that key is the 32-byte `depositId`. This slot number is specific to the immutable `USDDVaultV1` source/layout and must be checked again if the source or compiler layout changes. The `DepositAccepted` event also emits the raw script, its SHA-256 hash, the salt, amount, nonce, depositor, and commitment.

## Elements state and verifier statement

`ElementsBridgeState` has this exact ABI field order:

```text
(uint64 sequence,
 uint64 burnCount,
 bytes32 elementsTipHash,
 bytes32 elementsConsensusStateDigest,
 bytes32 cumulativeBurnRoot,
 bytes32 finalizedBitcoinBlockHash,
 uint64 bitcoinHeight,
 uint64 elementsHeight,
 uint64 bitcoinMedianTimePast,
 uint256 bitcoinChainwork)
```

Its content hash is:

```text
contents(s) = SHA256(
    u64be(s.sequence)
 || u64be(s.burnCount)
 || s.elementsTipHash
 || s.elementsConsensusStateDigest
 || s.cumulativeBurnRoot
 || s.finalizedBitcoinBlockHash
 || u64be(s.bitcoinHeight)
 || u64be(s.elementsHeight)
 || u64be(s.bitcoinMedianTimePast)
 || u256be(s.bitcoinChainwork)
)
```

For the initial transition, `oldBridgeStateHash` is 32 zero bytes and `oldContentsHash` is `contents` of the all-zero state.

```text
nextBridgeStateHash = SHA256(
    ELEMENTS_STATE_DOMAIN
 || oldBridgeStateHash
 || contents(next)
)

statement = SHA256(
    ELEMENTS_STATEMENT_DOMAIN
 || u256be(evmChainId)
 || address20(vault)
 || vaultId
 || verifierProgramId
 || verifierConfigHash
 || elementsGenesisHash
 || usddAssetId
 || oldBridgeStateHash
 || contents(oldState)
 || nextBridgeStateHash
 || contents(next)
)
```

The ABI is:

```text
advanceElementsState(
  (uint64,uint64,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint256) next,
  bytes proof
)
```

The contract requires `next.sequence == old.sequence + 1`, burn-count growth of at most 64, the canonical `EMPTY[64]` root whenever `burnCount == 0`, a nonzero consensus-state digest, increasing heights/chainwork, and a valid immutable-verifier proof. `elementsConsensusStateDigest` is the proof-program-defined commitment to the complete finalized Elements consensus state needed to continue validation; it is distinct from the block hash and must never be zero. Solidity invokes the `view` verifier through `STATICCALL`; before every call it rechecks that the verifier's `EXTCODEHASH` equals the hash pinned in the constructor.

The verifier interface additionally exposes `verifierProgramId()` and `verifierConfigHash()`. The vault requires both to equal constructor-supplied expected values at deployment and rechecks both before every proof. The config hash must commit every proof parameter not already captured by the program ID. This identity binding does not make proxies, `DELEGATECALL` targets, mutable storage, or external verifier dependencies immutable; production remains blocked until the pinned verifier is a self-contained audited wrapper without those paths.

## Burn leaf and append-only Merkle branch

`BurnClaim` has this exact ABI field order:

```text
(uint32 protocolVersion,
 bytes32 elementsGenesisHash,
 bytes32 usddAssetId,
 bytes32 vaultId,
 bytes32 burnTxid,
 uint32 burnVout,
 bytes32 burnId,
 uint64 amountUSDT6,
 address recipient)
```

`burnTxid` is the 32 raw bytes obtained by decoding the canonical RPC/display `txid` hex from left to right; do not reverse it. `burnVout` is four-byte big-endian. The vault recomputes and requires:

```text
burnId = SHA256(
    BURN_ID_DOMAIN
 || elementsGenesisHash
 || burnTxid
 || u32be(burnVout)
)
```

Normative vector:

```text
elementsGenesisHash = 0000000000000000000000000000000000000000000000000000000000002002
burnTxid             = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
burnVout             = 7
burnId               = fd47b4bc4ac0d628728b00e0acefe61eee1da05c530ea02bb73df8619897278a
```

The separately supplied `burnIndex` is both committed inside the leaf and used as its append-only tree position:

```text
leaf = SHA256(
    0x00
 || BURN_LEAF_DOMAIN
 || u32be(protocolVersion)
 || elementsGenesisHash
 || usddAssetId
 || vaultId
 || burnId
 || u64be(burnIndex)
 || u64be(amountUSDT6)
 || address20(recipient)
)

node = SHA256(0x01 || leftChild || rightChild)
```

The accumulator is a depth-64 tree with this exact empty-subtree convention:

```text
EMPTY[0]   = SHA256(0x00)
EMPTY[h+1] = SHA256(0x01 || EMPTY[h] || EMPTY[h])
empty root = EMPTY[64]
```

Occupied leaves are contiguous append positions `[0, burnCount)`; indices greater than or equal to `burnCount` are empty. There are no holes and an existing leaf never changes. The vault verifies a branch against the finalized root and checks `burnIndex < burnCount`; the full Elements proof guest is responsible for proving the append-only contiguous-prefix transition.

The Merkle branch is exactly 64 `bytes32` entries ordered leaf-to-root. At `level` from 0 through 63, use bit `level` of `burnIndex`:

```text
if ((burnIndex >> level) & 1) == 0:
    node = SHA256(0x01 || node || branch[level])
else:
    node = SHA256(0x01 || branch[level] || node)
```

The resulting node must equal `cumulativeBurnRoot`, and `burnIndex < burnCount` must hold. The redemption ABI is:

```text
redeem(
  (uint32,bytes32,bytes32,bytes32,bytes32,uint32,bytes32,uint64,address) claim,
  uint64 burnIndex,
  bytes32[64] merkleBranch
)
```

The Elements burn output payload proved by the guest is exactly 65 bytes:

```text
0x55534444                 // ASCII "USDD", 4 bytes
|| 0x01                   // payload version, u8
|| vaultId                // 32 bytes
|| address20(recipient)   // 20 bytes
|| u64be(amountUSDT6)     // 8 bytes
```

The burn transaction outpoint supplies `burnTxid:burnVout`; the payload supplies the vault, fixed recipient, and amount. The proof guest must validate both before appending the leaf.

Normative one-leaf accumulator vector (`burnCount = 1`, occupied index `0`):

```text
BURN_LEAF_DOMAIN = b15e96910e56013406f4167f79c8b6e369c3abf0b409d50a63e99e095b25fb94
elementsGenesis  = 0000000000000000000000000000000000000000000000000000000000002002
usddAssetId      = 0000000000000000000000000000000000000000000000000000000000003003
vaultId          = 101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
burnId           = fd47b4bc4ac0d628728b00e0acefe61eee1da05c530ea02bb73df8619897278a
amountUSDT6      = 777000
recipient        = 000000000000000000000000000000000000beef
leaf             = a5dbda1c39b86efacc5e41ca36f91ce27ddfeccae1df8b8e49edf2a966f66374
EMPTY[0]         = 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
EMPTY[64]        = c13fcc5e95b202155d131894da01dff87c8ac722937c76415daab46e53ed40db
root             = 5e918d5b43c826d7809189f6863a9c1b94b2327d9e1d01ffa01ccac9eb60bc73
```

## HTLC secret and deadlines

`USDTHTLC` accepts a fixed 32-byte secret preimage:

```text
secretHash = SHA256(secret32)
```

The constructor ABI is:

```text
USDTHTLC(
  address usdt,
  address funder,
  address claimRecipient,
  address refundRecipient,
  uint256 amount,
  bytes32 secretHash,
  uint32 elementsRefundTimestamp,
  uint64 externalRefundTimestamp
)
```

It rejects deployment if a fixed endpoint is the escrow itself or if the claim and refund recipients are identical. The Elements timestamp is a `uint32`, matching the absolute timestamp representation enforced on the Elements side. It also rejects deployment unless:

```text
externalRefundTimestamp >= elementsRefundTimestamp + 24 hours
```

Funding closes at the earlier `elementsRefundTimestamp`; a revealed-secret claim remains available until the later external deadline; refund becomes available at that later deadline. Anyone may execute each transition, but token source and recipients are immutable. Direct token donations have no sweep path.
