# USDD Bitcoin/BIP300 approval-proof foundation

This no-std crate ports a narrow, independently testable subset of the parent
consensus path used by the Elements Drivechain fork:

- exact 80-byte Bitcoin header decoding and double-SHA256 block IDs;
- Bitcoin Core-compatible compact-target range checks and proof of work;
- exact block-work and overflow-safe cumulative-work arithmetic;
- the actual LayerTwo-Labs Signet 2016-block retarget rule;
- exact parent linkage;
- exact Bitcoin block and transaction parsing with canonical CompactSize rules;
- legacy and SegWit txid derivation, context-free input/output checks, canonical
  coinbase placement, and consensus block-weight enforcement;
- non-mutated transaction-Merkle-root and BIP141 witness-commitment
  verification;
- exact verification of the sole-network Elements parent-Signet P2WPKH challenge,
  including the node's Signet-section rewrite, solution codec, strict DER,
  high-S normalization, BIP143 sighash, and secp256k1 signature; and
- the fork's unique, minimal slot-24 M7 parser and child-hash byte order, now
  cryptographically bound through the coinbase txid and Merkle root to the
  proof-of-work successor header;
- bounded slot-24 M1/M2 proposal replay with the fork's exact same-block ACK,
  strict `votes > threshold` activation, live used/unused threshold selection,
  proposal-expiry, and immutable-required-proposal replacement rules;
- ordered slot-24 M3/M4 replay with the enforcer's exact non-mainnet `SHORT`
  constants, score-one proposals, chronological bundle indexes, abstain/alarm,
  competitor downvotes, RepeatPrevious effective-action semantics,
  LeadingBy50, and age-greater-than-ten expiry;
- the exact slot-24 OP_DRIVECHAIN treasury chain for positive CTIP transitions,
  including parallel-output, drain, zero-delta, missing-address, and multiple
  treasury-output rejection; and
- exact M8 request binding to the slot-24 M7 child hash and predecessor `P`.
  A nonminimal M7 can satisfy the enforcer's M8 parser but cannot produce the
  Elements fork's strict BMM edge;
- exact 11-header median-time-past state and an optional two-hour future-time
  bound that requires a cryptographically authenticated current time;
- one genesis-derived, functional transition API which atomically applies the
  exact block/Merkle/BIP141, pinned Signet, contextual header/PoW/difficulty/
  work/time, ordered sole-slot-24 replay, and optional canonical M6 artifact
  checks to the same block and branch;
- an opaque, branch-bound approved-M6 finality tracker which advances both
  contextual and replay state together and emits its root only at the frozen
  100-confirmation depth (the inclusion block counts as one); and
- a separate opaque, exact-genesis all-slot path which replays M1/M2/M3/M4,
  active-slot-ordered voting, per-slot M5/M6 CTIPs and sequences, and per-slot
  M7/M8 for all 256 slot identifiers. Generic M6s remain available for other
  slots; slot 24 alone can consume the canonical USDD artifact, and a generic
  slot-24 M6 irreversibly invalidates USDD continuity; and
- an all-slot branch-bound finality tracker which keeps an earlier exact
  approval immutable while continuity loss permanently halts later USDD roots;
  and
- a bounded unique-greatest-work candidate selector that rejects equal-work
  ties, duplicate tips, and mismatched fork anchors.

With a manifest-bound accumulator identity/checkpoint and an untrusted
canonical `MinerBundleArtifact`, the ordered replay accepts a CTIP decrease
only when the M6id is pending with score greater than five, the exact actual
transaction matches `m6.rs`, the successor is vout 0, the decrease is exactly
one satoshi plus the committed fee, and the domain-separated prior root
transitions to the committed next root. It rejects a second accumulator M6 in
the same slot and parent block while leaving unrelated pending M3s intact.

The M7 parser fails closed above consensus-safe resource ceilings derived from
Bitcoin's 4,000,000 maximum block weight: at most 1,000,000 base bytes,
111,111 outputs (each serialized output needs at least nine base bytes), and
1,000,000 aggregate output-script bytes. These bounds are deliberately
permissive because a real coinbase must also serialize its inputs, values,
length prefixes, transaction fields, and enclosing block.

The low-level
`verify_header_pow_against_caller_supplied_bits` entry point does not derive
or authenticate its expected difficulty. Production transitions must use
`verify_successor`. Likewise,
`from_unverified_checkpoint_requires_manifest_binding` only checks internal
chainwork consistency; every bootstrap field must be compared to the frozen
manifest before the state is accepted.

The tests include the complete Bitcoin genesis block, legacy and SegWit txid
derivation, mutated-Merkle rejection, proof-of-work/Merkle/M7 end-to-end
binding, the running parent Signet's block 218 ECDSA solution, tampered
signed-header rejection, the node's malformed-tail Signet rewrite behavior,
and the exact cross-codec M7 vector from `src/test/pegin_witness_tests.cpp`.
The replay tests mirror the fork's proposal, activation, expiry, replacement,
ordered M3/M4 votes, CTIP increase/decrease, exact canonical M6, competing
bundles, one-M6-per-block, and fabricated-transition cases. Every failed
transition leaves the prior state unchanged, and sibling branches advance from
independent state clones.

The replay's 1,333,332-entry transition ceiling is consensus-derived rather
than an arbitrary availability cap: at most 111,111 coinbase outputs per block
times twelve creation heights. Eleven heights can remain live after the prior
block; the twelfth is required because the checked-in enforcer inserts the
current block's M1/M3 messages before expiring age-eleven entries. The bound is
deliberately loose, but a history accepted by the implemented block parser and
frozen replay cannot exceed it. No live proposal is evicted.

## Legacy sole-slot safety restriction

The legacy sole-slot replay API is safe only as an explicitly sole-slot-24 state machine
derived from the exact frozen parent genesis. Before applying any coinbase
state change, it recognizes the same complete M1, M2, and M3 script forms as
the checked-in enforcer and rejects the entire block if the encoded slot is not
24. M1 accepts an arbitrary, possibly empty description; M2 and M3 require the
exact 32-byte body; non-minimal data pushes are recognized; malformed lengths,
unknown versions/tags, extra script instructions, and message-shaped outputs
outside the coinbase remain ordinary data exactly as in the enforcer parser.

This rule prevents any other slot from activating on an accepted
genesis-derived history. Consequently the global active-slot-ordered M4 vector
has zero entries before slot 24 activates and exactly one afterwards. Exact
`OP_DRIVECHAIN <other-slot> OP_TRUE` outputs remain ordinary anyone-can-spend
outputs, matching the enforcer's inactive-slot rule; they neither alter the
slot-24 CTIP nor count as an M5/M6. A transaction that actually spends the
slot-24 CTIP still must create its exact slot-24 replacement, even if it creates
another slot's treasury-shaped output.

The diagnostic checkpoint constructors cannot prove that another slot was not
activated in omitted history and therefore cannot establish this invariant.
They must not bootstrap production authorization. This conservative API still
rejects otherwise valid multi-drivechain histories and must remain labeled as
such. The separate genesis-derived multi-slot API now implements deterministic
state for all 256 slots, including active-slot M4 indexes and per-slot CTIPs;
it does not silently broaden the legacy sole-slot API and is not yet declared
cross-implementation-equivalent without the differential gate below.

## Canonical slot-24 M6 artifacts

The crate also implements the keyless, permissionless USDD accumulator-M6
format for slot 24. A canonical `MinerBundleArtifact` is a constant-size
checkpoint containing the prior and next `u64` count/root, all frozen
cross-domain identities, and the fee. An optional `ClaimBatchWitness` carries
up to 64 complete claims and empty-leaf proofs so builders can independently
derive a checkpoint; that resource bound is tooling-only and does not constrain
the canonical M6 count delta. Validation derives the exact 241-byte
domain-separated commitment preimage. The resulting blinded M6 has exactly two
outputs: the enforcer-compatible zero-value `OP_RETURN <u64be fee>` marker at
vout 0 and a one-satoshi `OP_RETURN "USDDM6" <version> <root commitment>`
payout at vout 1.

Both Bitcoin Core's legacy zero-input transport and rust-bitcoin's unambiguous
BIP144 zero-input transport are decoded strictly. The M6id is always the txid
of the legacy/non-witness serialization, matching the checked-in enforcer's
`BlindedM6::compute_m6id` and `compute_m6id` transformation. An
`ActualM6Artifact` binds that bundle to the exact prior CTIP and reconstructs
the one-input M6 with the successor slot-24 CTIP at vout 0. Its verifier reparses
the submitted bytes, derives the fee from the CTIP delta, reconstructs the
blinded M6id, and rejects noncanonical or mismatched transactions. The
successor artifact always identifies the preceding M6's txid:vout0. USDD policy
permits at most one processed accumulator M6 per parent block; an inclusion
proof alone cannot prove no second sequential M6 was omitted.

The binary artifact codecs and deterministic CLI JSON/hex exports contain no
authority or embedded network endpoint. They may be copied through any
untrusted public channel. The CLI has explicit local-process adapters for the
current enforcer WalletService M3 endpoint and Bitcoin transaction broadcast;
those adapters accept only caller-supplied loopback/local clients, reverify all
deterministic IDs, and do not treat transport success as M4 approval or
finality. See `docs/PHASE3_OPERATIONS.md` for the remaining version and live
integration gates.

## Composed branch and finality API

`initialize_layer_two_signet_genesis_replay` accepts only the exact frozen
LayerTwo Signet genesis. The accumulator variant additionally requires the
caller to supply the four identities already authenticated against its frozen
deployment manifest and forces the initial root to the canonical empty depth-64
root. Neither constructor accepts a caller-selected header, chainwork, replay,
or approved-root checkpoint.

`advance_genesis_derived_layer_two_signet_replay` is the single composed block
transition. It accepts the prior opaque genesis-derived state by reference and
derives a new state only if the same exact serialized block passes transaction
structure, non-mutated Merkle and BIP141 commitments, the pinned Signet
signature, linkage, expected difficulty, proof of work, cumulative work,
median-time-past/future-time, sole-slot rules, ordered M3/M4/CTIP replay, and
the optional canonical M6 artifact. It clones into a candidate state, so an
error cannot partially advance either half and callers retain the complete
prior branch snapshot.

`verify_and_track_layer_two_signet_approved_slot24_accumulator_m6` is the only
public constructor for `ApprovedSlot24AccumulatorM6FinalityTracker`. It first
runs that composed transition and requires an exact approved accumulator M6 in
the resulting effects. Later `advance` calls run the same composed transition,
including optional later M6 artifacts. `finalized_root` fails before 100
confirmations and returns an opaque record binding the root and M6 to its
inclusion block and finalization tip at or after that depth. The threshold is
not a caller argument.

The parallel all-slot entry points are
`initialize_layer_two_signet_multislot_genesis_replay`,
`advance_genesis_derived_layer_two_signet_multislot_replay`, and
`verify_and_track_layer_two_signet_multislot_approved_slot24_accumulator_m6`.
Their state and tracker have no checkpoint constructor. They replay generic
enforcer state for every slot while reserving the USDD artifact for slot 24.
The all-slot tracker requires `Slot24UsddContinuity::Active` when the exact
approval is bound. Other-slot activity does not affect it. A later generic
slot-24 M6 or incompatible slot-24 replacement permanently prevents new USDD
approvals, but does not revoke the already-bound immutable root; doing so would
strand burns proven by the earlier inclusion. That root still needs 100
confirmations on the same continuously replayed branch.

This is finality on one continuously verified branch, not proof that the caller
supplied every competing public fork. The outer relay still must authenticate
its fork-availability model and select the best-work branch. The
`authenticated_current_time` argument likewise must come from the proof or
relay's authenticated consensus input, not local RPC or wall-clock trust.

## Deliberate authorization boundary

This crate is not an Elements-validity verifier. Its reduced role is to support
an ownerless, stateful Bitcoin/BIP300 relay which advances incrementally and
authorizes a specific withdrawal-bundle M6id after approval on the selected
parent-chain history. A submission proves only the next relay transition; it
must not carry or re-execute the entire historical M4 voting window on every
redemption. Before that approval boundary can authorize an Ethereum redemption,
the wider system still has to close these independent obligations:

1. The outer relay's authenticated fork-availability/best-work/reorg model and
   authenticated current-time source. This crate is an SPV/PoW authorization
   model and does not independently execute every Bitcoin UTXO/script or
   activation rule.
2. Cryptographic validation that each committed accumulator leaf came from a
   valid canonical Elements USDD burn. Miner approval and the implemented root
   transition do not prove Elements transaction, script, issuance, confidential
   asset-conservation, or burn validity. Until that separate proof exists, a
   fabricated root can still fabricate an otherwise validly approved payout.
3. Independent cross-implementation review and adversarial testing of the full
   approval relay. The checked-in unit vectors already freeze fee byte order,
   both zero-input encodings, M6id display order, actual-transaction bytes,
   CTIP vout 0, nonzero payout, domain separation, and the one-processed-M6
   checkpoint shape. Full-block completeness remains a separate blocker.

`extract_elements_slot24_m7` still intentionally returns
`UnboundCanonicalM7` because its standalone scripts are caller-provided. The
generic binding API is `verify_pow_merkle_bound_elements_m7_successor`, which
is useful for non-Signet test vectors but is not a production path. The
production-direction API is
`verify_layer_two_signet_pow_merkle_bound_elements_m7_successor`; it accepts
the exact serialized block and an already manifest-bound parent state, derives
every txid, both Merkle commitments, the frozen Signet solution, successor PoW,
and M7 output itself. Its result still does not imply BIP300 state, best-chain
membership, confirmation depth, contextual/UTXO Bitcoin validity, or Elements
validity.

`apply_merkle_bound_elements_slot24_parent_block` advances the bounded BIP300
state and emits an `ElementsSlot24BmmEdge` only after the frozen proposal is
active and the exact successor contains a minimal M7. The `_with_m6_artifact`
variant additionally enables the canonical accumulator decrease described
above. Their names deliberately say `merkle_bound`: input-value conservation,
scripts, Signet, PoW/fork choice, and best-chain membership still have to be
composed around them. The owned variants avoid cloning the potentially large
pending maps; ordinary mutable wrappers clone first so every error is atomic.

## Exact scope and unproven equivalence

The M1-through-M8 rules were ported from the checked-in enforcer source,
including coinbase-vout ordering, ascending active-slot M4 indexes, generic
blinded-M6 construction, transaction-order CTIP updates, and post-M4 expiry.
Adversarial unit tests cover cross-slot activation/M4 order, multi-slot atomic
M5s, missing and parallel CTIPs, per-slot BMM, generic non-24 M6 isolation,
same-block alarm-plus-M6 behavior, generic slot-24 continuity loss, sibling
branches, and finality boundaries. A separately built, offline differential
harness now drives the exact production enforcer transition and this replay
through a 4,156-block deterministic long trace plus a 14-block boundary trace
with all 256 slots active, comparing accepted state and effects after every
transition and atomicity after every rejection. The long trace's frozen result
is 3,300 accepted and 856 rejected transitions. See
[`docs/ENFORCER_DIFFERENTIAL.md`](../../docs/ENFORCER_DIFFERENTIAL.md) for the
oracle fingerprints, exact coverage, reproduction command, and explicit proof
limits. The frozen aggregate is supplemented by focused exact-native,
generic-invalidation, expiry, and paid-M6 disconnect/alternate-connect traces.
The latter exercises the enforcer's production LMDB diff/undo path while the
USDD replay restores the corresponding immutable checkpoint. This is bounded
reorg evidence, not a claim about arbitrary live-network forks.

The legacy genesis-derived path remains intentionally sole-slot and rejects
every well-formed non-24 M1/M2/M3. The separate multi-slot path accepts those
histories. Canonical USDD accumulator policy is deliberately stricter than a
generic slot-24 M6: generic slot-24 acceptance is faithfully replayed but
permanently disables USDD authorization on that branch.

Finally, the low-level Merkle-bound replay helpers authenticate bytes but do
not themselves prove contextual headers, Signet, or branch finality; only the
genesis-derived composed API adds those checks. Even that API does not prove
global best-work fork availability or Elements burn validity. Artifact
publication affects liveness only because its M6id and exact transaction/root
commitment are recomputed locally.

There is no accept-all verifier and no trusted fallback in this crate.
