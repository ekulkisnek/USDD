# USDD V1 internal security review

Date: 2026-07-18

Decision: **BLOCKED FOR DEPLOYMENT**

This is an internal adversarial engineering review of the current uncommitted
worktrees. It is not an independent audit and does not satisfy any independent
audit launch gate. Its purpose is to prevent incomplete proof plumbing from
being mistaken for a production bridge and to record findings fixed during the
implementation pass.

## Scope and method

The review covered the immutable Ethereum vault and HTLC, Rust and TypeScript
consensus codecs, reserve reconstruction, Ethereum MPT verification, pinned
Sepolia Helios light-client transition, SP1 guest source and host adapter,
Bitcoin block/Signet validation, the bounded slot-24 BIP300 replay, the
Simplicity controller transaction model, Elements annex/parent-MTP plumbing,
deployment freezing, and verifier preflight.

Review techniques included cross-language fixed vectors, source-to-node rule
comparison, malformed/canonical encoding tests, state-transition and replay
analysis, value-conservation analysis, adversarial proof-boundary review,
runtime-bytecode scanning, real Sepolia BLS/SSZ verification, and real
LayerTwo Signet block verification.

## Resolved findings

### SR-01 — HIGH — A maximum-size deposit could be permanently unmintable

The old 21,000,000-USDT deposit maximum converted to exactly Elements
`MAX_MONEY` in USDD base units. A mint transaction must also create the
explicit one-unit reissuance-token successor, and Elements sums all explicit
output values across assets. The resulting transaction was necessarily
consensus-invalid, while V1 deposits have no refund path.

Resolution: the per-deposit and per-mint-batch maximum is now 20,000,000 USDT.
This leaves 100,000,000,000,000 explicit-value units below the Elements limit.
Rust, Solidity, TypeScript, Python/controller modeling, tests, specifications,
and generated Solidity artifacts enforce the same limits. Canonical burns use
the same 20,000,000-USDT ceiling so their transactions also retain explicit
fee headroom; larger redemptions split into multiple burns.

### SR-02 — MEDIUM — An arbitrary proposal cap could halt valid BIP300 replay

The initial replay draft capped live proposals at 16,384 even though the parent
consensus has no such cap. A valid maximum-weight parent block can exceed that
number, allowing a miner to halt the proof chain without violating Bitcoin.

Resolution: the cap is now derived from proved resource rules without evicting
live state: at most 111,111 coinbase outputs per block times eleven live
creation heights under the frozen ten-block age, or 1,222,221 entries. Tests
bind the derivation. This is a permissive consensus-safe ceiling, not a new
network rule.

### SR-03 — HIGH — Free-form verifier dependency records could create false assurance

Verifier preflight v1 permitted `STATICCALL` and other external-dependency
opcodes when accompanied by prose and any syntactically valid evidence hash.
That did not prove the target address, code hash, or absence of mutable state.
An immutable wrapper could therefore delegate proof acceptance to a mutable
callee.

Resolution: preflight schema v2 rejects every `STATICCALL`, `EXTCODE*`, and
`BALANCE` occurrence, in addition to storage, calls, delegation, creation, and
destruction. Documentation alone cannot create an exception. A future verifier
that needs protocol precompiles remains blocked until target extraction and
identity enforcement are machine-verifiable and independently audited.

## Open critical boundaries

These are not accepted risks or deferred polish. Each prevents deployment:

1. Stock SP1 6.3.1 has no raw-compressed EVM verifier; its generated on-chain
   contracts use the forbidden Groth16/PLONK wrappers. The Elements raw proof
   verifier jet also does not exist.
2. The outbound guest does not yet prove full Elements validity, contextual
   Bitcoin UTXO/script rules, full all-slot BIP300 including M3/M4/M6, best-work
   fork choice/reorgs, or 100 confirmations.
3. The singleton mint controller is a fail-closed transaction model and
   non-deployable Simplicity scaffold, not a compiled covenant with a frozen
   CMR.
4. The Ethereum guest source is host-tested, but no pinned zkVM ELF, program
   ID, executor trace, raw-compressed proof, proof-size measurement, or gas/cost
   measurement exists.
5. Independent Solidity, proof-system/guest, and Elements/Simplicity audits,
   differential-client evidence, fuzz evidence, 100,000 public transitions,
   and the 90-day soak have not occurred.

No watcher, multisig, proxy, trusted checkpoint updater, optimistic committee,
or wrapped-proof fallback was added to bypass these boundaries.

## Residual inherited controls

Even after every implementation and audit gate passes, USDD inherits Tether's
ability to freeze or change USDT, Ethereum weak subjectivity and hard-fork
risk, Bitcoin/Drivechain consensus, Elements consensus, and the independently
confirmed soundness level of the chosen proof system. The immutable V1 design
has no administrative recovery if those dependencies halt; deposits and burns
can be stranded. This behavior must remain explicit in deployment disclosures.

The authoritative machine-readable decision remains `specs/launch-gates.tsv`.
Every required row is currently `BLOCKED`.
