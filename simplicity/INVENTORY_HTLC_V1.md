# Inventory-only Elements HTLC V1

Status: source-only, syntax-testable, and **not deployable**. No compiled
program, CMR, control block, or address is canonical yet.

This HTLC swaps already-existing Elements inventory. Its intended V1 use is an
independent swap between native Elements USDD and USDT on an external chain.
It is not part of the canonical Ethereum vault, cannot issue or reissue USDD,
cannot redeem the Ethereum reserve, and does not verify Tron or Ethereum.

## Committed source parameters

Each rendered SimplicityHL program commits these values as source constants:

```
secretHash                 bytes32 = SHA256(secret[32])
claimantXOnlyPubkey        valid, nonzero secp256k1 x coordinate
refundXOnlyPubkey          valid, nonzero secp256k1 x coordinate
elementsRefundTimestamp   u32 absolute timestamp, at least 500,000,000
```

The claimant and refund keys must be distinct. The separate external-chain
HTLC must use the same SHA-256 digest and exact 32-byte preimage. Keccak,
HASH160, text hex, padded ABI values, and variable-length secrets are different
contracts.

`render_inventory_htlc.py` also requires an external refund timestamp. That
timestamp is metadata for validating swap construction; it is deliberately not
embedded in or observed by the Elements program. The renderer requires:

```
externalRefundTimestamp >= elementsRefundTimestamp + 86,400 seconds
```

Thus the Elements refund is strictly earlier. Twenty-four hours is a hard
minimum, not an operational recommendation; deployments must use a larger
measured margin when either chain's finality or relay latency requires it.

## Claim branch

The claimant provides exactly one `u256` witness, which encodes a 32-byte
preimage, and one BIP340 signature. The program computes SHA-256 over those 32
bytes, compares it with the fixed secret hash, and verifies the signature from
the fixed claimant x-only key over Elements' `sig_all_hash`.

The signature commits the spending transaction, including its outputs. Merely
learning the preimage is therefore insufficient to redirect the inventory.
The claimant must sign the exact transaction it intends to publish.

## Refund branch

The refund party provides one BIP340 signature from the fixed refund x-only
key over `sig_all_hash`. The program additionally calls
`check_lock_time(Time(elementsRefundTimestamp))`. The spending transaction
must use timestamp-form absolute `nLockTime` at or after the fixed deadline and
must have the non-final input sequence required for locktime enforcement.

Like a conventional CLTV-style HTLC, the claim branch does not become invalid
at the refund timestamp. After that timestamp, a valid claim and a valid refund
can race. The refund party must remain available, or use non-custodial
automation, to publish and confirm its pre-signed refund promptly. This is a
liveness requirement on the swap participants, not a trusted authorization
role.

## Atomic-swap ordering

The party holding the preimage claims the Elements inventory before its earlier
refund timestamp. Publication reveals the exact 32-byte preimage. The
counterparty then claims the external-chain inventory before that chain's later
refund timestamp. Reversing the deadlines creates a theft window and is
rejected by the renderer.

The 24-hour ordering window limits the time for the external claim; it does not
make an offline refund party safe forever. If the Elements refund is not
confirmed before the external refund and the external side is refunded, the
still-valid Elements claim branch could be used later. Production operation
therefore needs reliable chain monitoring and pre-signed refunds. Monitoring
may be performed by anyone and holds no key, but the refund signature must be
prepared by the fixed refund participant.

Both transactions must be fully prepared and checked before either asset is
funded. A party must not accept a funding output based only on a source file;
it must verify the final program encoding, CMR, Taproot commitment, keys, hash,
asset, amount, and both chain deadlines.

## Scope and limitations

The Simplicity program has no issuance, reissuance, burn, bridge, oracle,
proof-verifier, watcher, administrator, or fee path. The locked asset and
amount come from the funded Elements UTXO, while each participant's
`sig_all_hash` signature authorizes the complete branch transaction. Consensus
still enforces ordinary Elements asset conservation.

The program does not inspect every unrelated input for issuance and does not
force a particular destination script in Simplicity. A signer can authorize
additional transaction activity or any destination by signing it. Production
swap tooling should construct a minimal transaction and display every input,
output, asset, value, fee, issuance, and burn before requesting the signature.

## Reproducible source check

Render to standard output and syntax-check against the pinned official
SimplicityHL checkout:

```sh
python3 simplicity/render_inventory_htlc.py \
  --secret-hash <64-hex-character-sha256> \
  --claimant-xonly-pubkey <64-hex-character-key> \
  --refund-xonly-pubkey <64-hex-character-key> \
  --elements-refund-timestamp <u32-unix-time> \
  --external-refund-timestamp <later-u64-unix-time> \
  --check-with-simplicityhl /Volumes/T705/space-relief/research/simplicityhl-main
```

The syntax check is pinned to official SimplicityHL commit
`f62adf11e16816dd8f33f16edb5ff9f4c4b45e36`, package version `0.6.0`, which
depends on `simplicity-lang 0.8.0` and `simplicity-sys 0.7.0`. The compiled
bytes are discarded on purpose.

The Elements fork vendors a separately generated C Simplicity subtree and is
also receiving a new network-specific environment jet. This repository has not
yet demonstrated, byte for byte, that a program emitted by that Rust compiler
decodes to the same jets, CMR, types, and costs in the exact Elements node.
Consequently no encoded program or CMR is recorded here. That compatibility
must be proven by decoding, typechecking, CMR comparison, and execution in the
node's vendored C implementation before an artifact can be called deployable.

## Required transaction-level tests before deployment

- correct and wrong 32-byte preimages and a signature from the wrong key;
- mutation of every `sig_all_hash`-committed transaction field;
- claim succeeds before, at, and after the Elements deadline;
- refund fails before and succeeds at/after the Elements deadline;
- final and non-final input sequences and height-form versus time-form locktime;
- external deadline gaps of 86,399 and 86,400 seconds;
- wrong asset, amount, CMR, claimant key, refund key, and secret hash; and
- same-secret end-to-end vectors for each external HTLC implementation.

`test_inventory_htlc.py` covers source rendering, key validity, hash width, and
deadline bounds. It does not substitute for transaction-level node execution.
