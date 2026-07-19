# Deployment manifest

`ProtocolManifest` is a canonical binary record (schema 2, tag `0x4001`). It is
committed with the `USDD/1/manifest` domain hash. Every proof claim and public
output carries that commitment; verifiers must compare it with the immutable
deployment value.

The field order and binary widths are listed in `manifest-fields.tsv`.

V1 invariants enforced by decoding are:

- Drivechain slot is exactly 24;
- Ethereum chain ID and all genesis/code/program/asset commitments are nonzero;
- USDT and vault addresses are nonzero;
- Bitcoin confirmation depth is at least 100;
- maximum Ethereum transition is 4096 slots and maximum absolute finalized
  execution timestamp/BMM-parent-MTP difference is six hours;
- the SP1 version/commit, compressed proof circuit/codec, recursion constants,
  SHA-256 tag, verifier address/code/config, bootstrap light-client state,
  issuance anchors, controller policy/state, domain table, liability cap, and
  minimum activation chainwork are immutable and nonzero where required;
- USDT decimals are 6, USDD decimals are 8, and conversion multiplier is 100.
- the singleton controller starts at deposit nonce zero, matching a fresh
  immutable vault, so no irreversible deposit is skipped at activation.

The controller configuration hash is derived from a fixed, non-circular
projection of the Ethereum mint-proof configuration. It is not the full
manifest ID: the full manifest includes that hash and the initial controller
state hash. `ProtocolManifest::validate` recomputes both the controller
configuration hash and initial state hash before accepting the manifest.

The outbound verifier configuration hash is also derived, never merely
nonzero. Its non-circular projection binds the Bitcoin and Elements genesis
identities, slot 24, Ethereum chain/vault address, USDD asset, Elements guest
program, SP1 circuit/codec/recursion identity, SHA-256 mode, domain table,
activation chainwork, confirmation depth, and the fixed depth-64/64-append burn
policy. The verifier runtime address and code hash are pinned separately to
avoid a runtime-literal self-reference.

No production manifest is included because the required guest program IDs and
deployment code hashes have not been built and measured. Publishing placeholder
values as a deployable manifest would create false assurance.
