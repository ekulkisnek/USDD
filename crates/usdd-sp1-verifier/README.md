# USDD SP1 raw compressed verifier adapter

This crate is the host-side, fail-closed adapter around SP1 `6.3.1`'s raw
compressed verifier. It accepts only a complete fixed-int bincode
`SP1Proof::Compressed` enum value. Core, PLONK, and Groth16 proof modes are
always rejected and no wrapper-verifier feature is enabled.

## Program ID and raw vkey-hash encoding

The manifest program ID is exactly SP1 `HashableKey::hash_bytes()`: eight
canonical KoalaBear field words, each encoded as a big-endian `u32`,
concatenated in field-array order. The byte string passed to
`SP1CompressedVerifierRaw` is the fixed-int bincode encoding of the same
`[SP1Field; 8]`: the same eight canonical words encoded as little-endian
`u32`s, again in field-array order.

`program_id_from_raw_vkey_hash` validates and converts raw-verifier bytes to
the manifest form. `raw_vkey_hash_from_program_id` performs the exact inverse.
Both reject field words greater than or equal to the KoalaBear modulus
`0x7f000001`, and zero is not a valid USDD program ID. There is therefore no
second, hidden vkey identity outside the manifest.

The adapter also requires a canonical typed `StrictJournal`, permits only a
SHA-256 public-values commitment, rejects trailing/noncanonical proof bytes,
and enforces the complete 512 KiB annex budget including its 55-byte header.
It deliberately calls `SP1CompressedVerifierRaw::verify`, not SP1 6.3.1's
`verify_with_public_values`, because the latter also accepts BLAKE3.

## Integration status

The rejection and format paths are tested without assuming a valid proof.
A reproducible production guest ELF and success-path compressed proof fixture
have not yet been supplied, so the successful cryptographic path is not yet
covered by a fixture. This host adapter is also not yet wired into the Elements
consensus verifier jet or an EVM raw-proof verifier. Those integrations,
differential tests, performance measurements, and their independent review
remain mandatory launch blockers; this crate alone is not a deployable bridge.
