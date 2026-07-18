# Inventory-only Elements HTLC V1

Status: fail-closed design artifact; not compiled or deployable.

This HTLC swaps already existing inventory. Its intended V1 use is an
independent swap between native Elements USDD and Tron USDT. It is not part of
the canonical Ethereum vault, cannot mint or reissue USDD, cannot redeem the
Ethereum reserve, and does not make Tron a canonical rail.

## Immutable parameters

One HTLC instance commits:

```
version                    u32 = 1
secretHash                 bytes32 = SHA256(secret[32])
claimantScriptHash         bytes32
refundScriptHash           bytes32
assetId                    bytes32
amount                     u64, positive
elementsRefundDeadline     u32 absolute locktime
externalRefundDeadline     u64
```

The secret is exactly 32 bytes. All hash/script/asset commitments are nonzero;
claimant and refund scripts are fixed and distinct. `externalRefundDeadline`
must be at least 86,400 seconds later than the Elements deadline. Deployments
must add a larger measured margin if either chain's finality and relay latency
requires it; 24 hours is only the hard floor.

The external-chain HTLC must use the same SHA-256 digest and exact 32-byte
preimage. Keccak, HASH160, text hex, padded ABI values, and variable-length
secrets are different contracts and are rejected.

## Claim branch

Before the Elements refund path becomes valid, anyone may provide the exact
32-byte preimage. The Simplicity policy verifies `SHA256(secret) == secretHash`
and forces an explicit output of exactly `assetId` and `amount` to the immutable
claimant script. Permissionless execution is safe because the executor cannot
change the destination or amount.

## Refund branch

At or after `elementsRefundDeadline`, anyone may execute the refund branch. It
enforces the absolute Elements locktime/sequence rule and forces an explicit
output of exactly `assetId` and `amount` to the immutable refund script. No
secret is accepted as a substitute after selecting this branch.

The Elements claimant reveals the secret while claiming Elements first. The
counterparty learns it from Elements and then has at least the configured gap
to claim the external-chain inventory before the later external refund.
Transaction construction must not reverse this ordering.

## Transaction restrictions

Both branches enforce:

- the HTLC input asset and amount equal the immutable values;
- the protected asset amount goes to exactly one fixed branch output;
- no input or output issues, reissues, or burns any asset;
- fees are paid from separate policy-asset inputs and cannot reduce the HTLC
  amount;
- no confidential asset/value is used for the protected input or output; and
- additional inputs/outputs cannot create an alternative path for the protected
  asset or alter the claimant/refund scripts.

An implementation may choose a stricter exact transaction template. It may not
relax asset/amount conservation or introduce a signer, watcher, admin, or
controller dependency.

## Tests required for the compiled program

- correct and wrong 32-byte preimages; 31/33-byte and alternate-hash preimages;
- claim just before/at/after the Elements deadline;
- refund just before/at/after the Elements deadline;
- external deadline gaps of 86,399 and 86,400 seconds;
- wrong asset, amount, claimant/refund script, confidential value, and fee
  subtraction;
- every issuance, reissuance, and OP_RETURN/burn attempt;
- non-final input sequence and wrong locktime units; and
- same-secret end-to-end vectors in the external HTLC implementation.

`usdd_formats.py` and `test_usdd_formats.py` cover parameter-level bounds. They
do not substitute for executing a compiled Simplicity program against real
Elements transactions.
