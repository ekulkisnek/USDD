//! Fail-closed adapter for SP1 v6.3.1 raw compressed proofs.
//!
//! SP1 v6.3.1's `verify_with_public_values` accepts either a SHA-256 or a
//! BLAKE3 commitment. USDD V1 permits SHA-256 only. This adapter therefore:
//!
//! 1. validates the exact raw bincode formats consumed by
//!    [`SP1CompressedVerifierRaw`],
//! 2. accepts only [`SP1Proof::Compressed`],
//! 3. binds a canonical, typed [`StrictJournal`] to the SP1 program ID,
//! 4. checks the proof's committed public-values digest against SHA-256 only,
//!    and
//! 5. invokes the pinned compressed verifier without its dual-hash public
//!    values helper.
//!
//! The adapter deliberately exposes no Groth16 or PLONK verification path.

use core::borrow::Borrow;
use std::panic::{catch_unwind, AssertUnwindSafe};

use bincode::Options;
use slop_algebra::PrimeField32;
use sp1_hypercube::PROOF_MAX_NUM_PVS;
use sp1_recursion_executor::RecursionPublicValues;
use sp1_verifier::{
    compressed::{CompressedError, SP1CompressedVerifierRaw},
    SP1Proof,
};
use usdd_core::{hash_bytes, Hash32};
use usdd_proof_core::{
    JournalError, StatementKind, StrictJournal, SP1_ANNEX_HEADER_SIZE, SP1_ANNEX_MAX_SIZE,
    SP1_PUBLIC_VALUES_MAX_SIZE,
};

/// Exact SP1 release whose serialized types and verifier constants this
/// adapter is compiled against.
pub const SP1_VERSION: &str = "6.3.1";

/// Raw compressed proofs larger than the consensus annex ceiling are rejected
/// before deserialization.
pub const MAX_RAW_COMPRESSED_PROOF_SIZE: usize = SP1_ANNEX_MAX_SIZE;

/// `bincode::serialize(&vk.hash_koalabear())` is eight fixed-width little-
/// endian `u32` values and therefore exactly 32 bytes.
pub const RAW_VKEY_HASH_SIZE: usize = 32;

/// KoalaBear's field modulus (`2^31 - 2^24 + 1`).
pub const KOALA_BEAR_MODULUS: u32 = 0x7f00_0001;

/// A proof mode that USDD V1 always rejects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectedProofMode {
    Core,
    Plonk,
    Groth16,
}

/// A fail-closed verifier rejection.
#[derive(Debug)]
pub enum VerificationError {
    EmptyProof,
    ProofTooLarge { actual: usize, maximum: usize },
    PublicValuesTooLarge { actual: usize, maximum: usize },
    AnnexSizeOverflow,
    AnnexTooLarge { actual: usize, maximum: usize },
    MalformedProof,
    NonCanonicalProof,
    UnsupportedProofMode(RejectedProofMode),
    WrongVkeyHashLength { actual: usize },
    NonCanonicalVkeyWord { index: usize, value: u32 },
    NonCanonicalProgramIdWord { index: usize, value: u32 },
    ZeroProgramId,
    VkeyProgramIdMismatch,
    Journal(JournalError),
    InvalidRecursionPublicValuesLength { actual: usize, expected: usize },
    NonByteCommittedDigestLimb { index: usize, value: u32 },
    PublicValuesDigestMismatch,
    ProofRejected(CompressedError),
    VerifierPanicked,
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyProof => f.write_str("SP1 proof is empty"),
            Self::ProofTooLarge { actual, maximum } => {
                write!(f, "SP1 proof is {actual} bytes; maximum is {maximum}")
            }
            Self::PublicValuesTooLarge { actual, maximum } => write!(
                f,
                "SP1 public values are {actual} bytes; maximum is {maximum}"
            ),
            Self::AnnexSizeOverflow => f.write_str("SP1 annex size arithmetic overflow"),
            Self::AnnexTooLarge { actual, maximum } => write!(
                f,
                "combined SP1 annex is {actual} bytes; maximum is {maximum}"
            ),
            Self::MalformedProof => f.write_str("malformed SP1 proof encoding"),
            Self::NonCanonicalProof => f.write_str("noncanonical SP1 proof encoding"),
            Self::UnsupportedProofMode(mode) => {
                write!(f, "unsupported SP1 proof mode: {mode:?}")
            }
            Self::WrongVkeyHashLength { actual } => write!(
                f,
                "raw SP1 vkey hash is {actual} bytes; expected {RAW_VKEY_HASH_SIZE}"
            ),
            Self::NonCanonicalVkeyWord { index, value } => write!(
                f,
                "raw SP1 vkey hash word {index} is noncanonical: {value:#010x}"
            ),
            Self::NonCanonicalProgramIdWord { index, value } => write!(
                f,
                "SP1 program ID word {index} is noncanonical: {value:#010x}"
            ),
            Self::ZeroProgramId => f.write_str("SP1 program ID is zero"),
            Self::VkeyProgramIdMismatch => {
                f.write_str("raw SP1 vkey hash does not match the expected program ID")
            }
            Self::Journal(error) => write!(f, "invalid USDD public-values journal: {error}"),
            Self::InvalidRecursionPublicValuesLength { actual, expected } => write!(
                f,
                "compressed proof has {actual} recursion public values; expected {expected}"
            ),
            Self::NonByteCommittedDigestLimb { index, value } => write!(
                f,
                "compressed proof digest limb {index} is not a canonical byte: {value}"
            ),
            Self::PublicValuesDigestMismatch => {
                f.write_str("compressed proof does not commit to SHA-256(public values)")
            }
            Self::ProofRejected(error) => write!(f, "SP1 compressed proof rejected: {error}"),
            Self::VerifierPanicked => {
                f.write_str("SP1 verifier panicked while processing untrusted input")
            }
        }
    }
}

impl std::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            Self::ProofRejected(error) => Some(error),
            _ => None,
        }
    }
}

impl From<JournalError> for VerificationError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

/// Converts the exact raw vkey-hash encoding consumed by
/// [`SP1CompressedVerifierRaw`] into SP1's canonical 32-byte program ID.
///
/// The raw verifier consumes eight bincode fixed-int, little-endian KoalaBear
/// field elements. SP1's `HashableKey::hash_bytes`, used as the program ID,
/// renders the same eight canonical words in big-endian order. Values at or
/// above the field modulus are rejected before SP1's deserializer can reduce
/// or debug-panic on them.
pub fn program_id_from_raw_vkey_hash(raw_vkey_hash: &[u8]) -> Result<Hash32, VerificationError> {
    if raw_vkey_hash.len() != RAW_VKEY_HASH_SIZE {
        return Err(VerificationError::WrongVkeyHashLength {
            actual: raw_vkey_hash.len(),
        });
    }

    let mut program_id = [0u8; 32];
    for (index, raw_word) in raw_vkey_hash.chunks_exact(4).enumerate() {
        let value = u32::from_le_bytes(
            raw_word
                .try_into()
                .expect("chunks_exact(4) always yields four bytes"),
        );
        if value >= KOALA_BEAR_MODULUS {
            return Err(VerificationError::NonCanonicalVkeyWord { index, value });
        }
        program_id[index * 4..(index + 1) * 4].copy_from_slice(&value.to_be_bytes());
    }
    let program_id = Hash32(program_id);
    if program_id == Hash32::ZERO {
        return Err(VerificationError::ZeroProgramId);
    }
    Ok(program_id)
}

/// Derives the one canonical raw vkey-hash encoding accepted by the SP1 raw
/// verifier from a manifest program ID.
///
/// This is the inverse of [`program_id_from_raw_vkey_hash`]: each four-byte
/// program-ID word is canonical big-endian and is emitted as the fixed-int
/// little-endian bincode representation of the corresponding KoalaBear field
/// element. This lets callers store only the manifest program ID; the raw
/// verifier encoding carries no additional identity or configuration.
pub fn raw_vkey_hash_from_program_id(
    program_id: Hash32,
) -> Result<[u8; RAW_VKEY_HASH_SIZE], VerificationError> {
    if program_id == Hash32::ZERO {
        return Err(VerificationError::ZeroProgramId);
    }

    let mut raw_vkey_hash = [0u8; RAW_VKEY_HASH_SIZE];
    for (index, program_word) in program_id.0.chunks_exact(4).enumerate() {
        let value = u32::from_be_bytes(
            program_word
                .try_into()
                .expect("chunks_exact(4) always yields four bytes"),
        );
        if value >= KOALA_BEAR_MODULUS {
            return Err(VerificationError::NonCanonicalProgramIdWord { index, value });
        }
        raw_vkey_hash[index * 4..(index + 1) * 4].copy_from_slice(&value.to_le_bytes());
    }
    Ok(raw_vkey_hash)
}

/// Enforces the only public-values commitment algorithm authorized by USDD
/// V1. There is intentionally no fallback digest.
pub fn require_sha256_public_values_digest(
    committed_digest: [u8; 32],
    public_values: &[u8],
) -> Result<(), VerificationError> {
    if committed_digest != hash_bytes(public_values).0 {
        return Err(VerificationError::PublicValuesDigestMismatch);
    }
    Ok(())
}

/// Verifies a raw SP1 v6.3.1 compressed proof and its typed USDD journal.
///
/// `raw_proof` must be the fixed-int bincode encoding of the complete
/// `SP1Proof::Compressed` enum value, not a wrapper proof and not an encoding
/// of only its inner recursion proof. `raw_vkey_hash` must be the exact 32-byte
/// fixed-int bincode encoding of `[SP1Field; 8]` expected by
/// [`SP1CompressedVerifierRaw`].
///
/// Panics from the upstream parser or verifier are converted to a rejection
/// when the build uses unwinding panics. Production consensus builds must not
/// use `panic = "abort"` if process-level fail-closed behavior is required.
pub fn verify_raw_compressed_sha256(
    raw_proof: &[u8],
    public_values: &[u8],
    raw_vkey_hash: &[u8],
    expected_program_id: Hash32,
    expected_statement_kind: StatementKind,
) -> Result<StrictJournal, VerificationError> {
    match catch_unwind(AssertUnwindSafe(|| {
        verify_inner(
            raw_proof,
            public_values,
            raw_vkey_hash,
            expected_program_id,
            expected_statement_kind,
        )
    })) {
        Ok(result) => result,
        Err(_) => Err(VerificationError::VerifierPanicked),
    }
}

fn verify_inner(
    raw_proof: &[u8],
    public_values: &[u8],
    raw_vkey_hash: &[u8],
    expected_program_id: Hash32,
    expected_statement_kind: StatementKind,
) -> Result<StrictJournal, VerificationError> {
    if raw_proof.is_empty() {
        return Err(VerificationError::EmptyProof);
    }
    if raw_proof.len() > MAX_RAW_COMPRESSED_PROOF_SIZE {
        return Err(VerificationError::ProofTooLarge {
            actual: raw_proof.len(),
            maximum: MAX_RAW_COMPRESSED_PROOF_SIZE,
        });
    }
    if public_values.len() > SP1_PUBLIC_VALUES_MAX_SIZE {
        return Err(VerificationError::PublicValuesTooLarge {
            actual: public_values.len(),
            maximum: SP1_PUBLIC_VALUES_MAX_SIZE,
        });
    }
    let annex_size = SP1_ANNEX_HEADER_SIZE
        .checked_add(public_values.len())
        .and_then(|size| size.checked_add(raw_proof.len()))
        .ok_or(VerificationError::AnnexSizeOverflow)?;
    if annex_size > SP1_ANNEX_MAX_SIZE {
        return Err(VerificationError::AnnexTooLarge {
            actual: annex_size,
            maximum: SP1_ANNEX_MAX_SIZE,
        });
    }

    let actual_program_id = program_id_from_raw_vkey_hash(raw_vkey_hash)?;
    if actual_program_id != expected_program_id {
        return Err(VerificationError::VkeyProgramIdMismatch);
    }

    let journal = StrictJournal::verify_expected(
        public_values,
        expected_program_id,
        expected_statement_kind,
    )?;

    reject_noncompressed_tag(raw_proof)?;
    let proof = deserialize_canonical_proof(raw_proof)?;
    let compressed = match &proof {
        SP1Proof::Compressed(proof) => proof,
        // The fixed enum tag was checked before deserialization. Retain an
        // exhaustive match so a future SP1 serde change fails closed.
        _ => return Err(VerificationError::MalformedProof),
    };

    let recursion_values_len = compressed.proof.public_values.len();
    if recursion_values_len != PROOF_MAX_NUM_PVS {
        return Err(VerificationError::InvalidRecursionPublicValuesLength {
            actual: recursion_values_len,
            expected: PROOF_MAX_NUM_PVS,
        });
    }

    let recursion_values: &RecursionPublicValues<_> =
        compressed.proof.public_values.as_slice().borrow();
    let mut committed_digest = [0u8; 32];
    let mut digest_index = 0usize;
    for word in &recursion_values.committed_value_digest {
        for limb in word {
            let value = limb.as_canonical_u32();
            if value > u8::MAX as u32 {
                return Err(VerificationError::NonByteCommittedDigestLimb {
                    index: digest_index,
                    value,
                });
            }
            committed_digest[digest_index] = value as u8;
            digest_index += 1;
        }
    }
    require_sha256_public_values_digest(committed_digest, public_values)?;

    // Do not call `verify_with_public_values`: in v6.3.1 it accepts BLAKE3 in
    // addition to SHA-256. The SHA-only binding above precedes this raw proof
    // verification and the strict decoder ensures this second parse sees the
    // same canonical bytes.
    SP1CompressedVerifierRaw::verify(raw_proof, raw_vkey_hash)
        .map_err(VerificationError::ProofRejected)?;

    Ok(journal)
}

fn reject_noncompressed_tag(raw_proof: &[u8]) -> Result<(), VerificationError> {
    let raw_tag: [u8; 4] = raw_proof
        .get(..4)
        .ok_or(VerificationError::MalformedProof)?
        .try_into()
        .expect("slice length checked");
    match u32::from_le_bytes(raw_tag) {
        1 => Ok(()),
        0 => Err(VerificationError::UnsupportedProofMode(
            RejectedProofMode::Core,
        )),
        2 => Err(VerificationError::UnsupportedProofMode(
            RejectedProofMode::Plonk,
        )),
        3 => Err(VerificationError::UnsupportedProofMode(
            RejectedProofMode::Groth16,
        )),
        _ => Err(VerificationError::MalformedProof),
    }
}

fn deserialize_canonical_proof(raw_proof: &[u8]) -> Result<SP1Proof, VerificationError> {
    let proof: SP1Proof = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_RAW_COMPRESSED_PROOF_SIZE as u64)
        .deserialize(raw_proof)
        .map_err(|_| VerificationError::MalformedProof)?;

    let canonical = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&proof)
        .map_err(|_| VerificationError::MalformedProof)?;
    if canonical != raw_proof {
        return Err(VerificationError::NonCanonicalProof);
    }
    Ok(proof)
}
