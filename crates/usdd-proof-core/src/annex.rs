use alloc::vec::Vec;
use core::fmt;

use usdd_core::{CanonicalEncode, Decoder, Hash32};

use crate::{JournalError, StatementKind, StrictJournal};

pub const SP1_ANNEX_TAG: u8 = 0x50;
pub const SP1_ANNEX_MAGIC: [u8; 8] = *b"USDDSP1\0";
pub const SP1_ANNEX_HEADER_SIZE: usize = 55;
pub const SP1_ANNEX_MAX_SIZE: usize = 512 * 1024;
pub const SP1_PUBLIC_VALUES_MAX_SIZE: usize = 16 * 1024;

/// Exact counterpart of Elements `script/usdd_sp1_annex.h`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sp1ProofAnnex {
    statement_kind: StatementKind,
    guest_vkey_hash: Hash32,
    public_values: Vec<u8>,
    proof: Vec<u8>,
}

impl Sp1ProofAnnex {
    pub fn new(
        statement_kind: StatementKind,
        guest_vkey_hash: Hash32,
        public_values: Vec<u8>,
        proof: Vec<u8>,
    ) -> Result<Self, AnnexError> {
        let value = Self {
            statement_kind,
            guest_vkey_hash,
            public_values,
            proof,
        };
        if value.statement_kind != StatementKind::EthereumState {
            return Err(AnnexError::WrongStatementKind);
        }
        value.validate()?;
        Ok(value)
    }

    pub fn decode_strict(bytes: &[u8]) -> Result<Self, AnnexError> {
        if bytes.len() > SP1_ANNEX_MAX_SIZE {
            return Err(AnnexError::TooLarge);
        }
        if bytes.len() < SP1_ANNEX_HEADER_SIZE {
            return Err(AnnexError::Truncated);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.u8()? != SP1_ANNEX_TAG {
            return Err(AnnexError::WrongTag);
        }
        if decoder.fixed::<8>()? != SP1_ANNEX_MAGIC {
            return Err(AnnexError::WrongMagic);
        }
        if decoder.u8()? != 1 {
            return Err(AnnexError::WrongVersion);
        }
        if decoder.u8()? != 1 {
            return Err(AnnexError::WrongProofSystem);
        }
        let statement_kind = match decoder.u8()? {
            1 => StatementKind::EthereumState,
            _ => return Err(AnnexError::WrongStatementKind),
        };
        if decoder.u8()? != 1 {
            return Err(AnnexError::WrongDigestMode);
        }
        if decoder.u16()? != 0 {
            return Err(AnnexError::NonzeroFlags);
        }
        let public_values_len = decoder.u32()? as usize;
        let proof_len = decoder.u32()? as usize;
        let guest_vkey_hash = Hash32(decoder.fixed()?);
        let expected_len = SP1_ANNEX_HEADER_SIZE
            .checked_add(public_values_len)
            .and_then(|value| value.checked_add(proof_len))
            .ok_or(AnnexError::LengthMismatch)?;
        if expected_len != bytes.len() {
            return Err(AnnexError::LengthMismatch);
        }
        let public_values = decoder.take(public_values_len)?.to_vec();
        let proof = decoder.take(proof_len)?.to_vec();
        if decoder.remaining() != 0 {
            return Err(AnnexError::LengthMismatch);
        }
        let value = Self {
            statement_kind,
            guest_vkey_hash,
            public_values,
            proof,
        };
        value.validate()?;
        if value.encode() != bytes {
            return Err(AnnexError::NonCanonicalEncoding);
        }
        Ok(value)
    }

    pub fn verify_strict_journal(
        bytes: &[u8],
        expected_program_id: Hash32,
        expected_kind: StatementKind,
    ) -> Result<(Self, StrictJournal), AnnexError> {
        let annex = Self::decode_strict(bytes)?;
        if annex.statement_kind != expected_kind {
            return Err(AnnexError::WrongStatementKind);
        }
        if annex.guest_vkey_hash != expected_program_id {
            return Err(AnnexError::WrongGuestVkey);
        }
        let journal = StrictJournal::verify_expected(
            &annex.public_values,
            expected_program_id,
            expected_kind,
        )
        .map_err(AnnexError::Journal)?;
        Ok((annex, journal))
    }

    pub const fn statement_kind(&self) -> StatementKind {
        self.statement_kind
    }

    pub const fn guest_vkey_hash(&self) -> Hash32 {
        self.guest_vkey_hash
    }

    pub fn public_values(&self) -> &[u8] {
        &self.public_values
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    fn validate(&self) -> Result<(), AnnexError> {
        if self.guest_vkey_hash == Hash32::ZERO {
            return Err(AnnexError::ZeroGuestVkey);
        }
        if self.public_values.is_empty() {
            return Err(AnnexError::EmptyPublicValues);
        }
        if self.public_values.len() > SP1_PUBLIC_VALUES_MAX_SIZE {
            return Err(AnnexError::PublicValuesTooLarge);
        }
        if self.proof.is_empty() {
            return Err(AnnexError::EmptyProof);
        }
        let size = SP1_ANNEX_HEADER_SIZE
            .checked_add(self.public_values.len())
            .and_then(|value| value.checked_add(self.proof.len()))
            .ok_or(AnnexError::TooLarge)?;
        if size > SP1_ANNEX_MAX_SIZE {
            return Err(AnnexError::TooLarge);
        }
        Ok(())
    }
}

impl CanonicalEncode for Sp1ProofAnnex {
    fn encode_to(&self, out: &mut Vec<u8>) {
        SP1_ANNEX_TAG.encode_to(out);
        SP1_ANNEX_MAGIC.encode_to(out);
        1u8.encode_to(out);
        1u8.encode_to(out);
        (self.statement_kind as u8).encode_to(out);
        1u8.encode_to(out);
        0u16.encode_to(out);
        let public_len =
            u32::try_from(self.public_values.len()).expect("public values length fits u32");
        let proof_len = u32::try_from(self.proof.len()).expect("proof length fits u32");
        public_len.encode_to(out);
        proof_len.encode_to(out);
        self.guest_vkey_hash.encode_to(out);
        out.extend_from_slice(&self.public_values);
        out.extend_from_slice(&self.proof);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnnexError {
    Decode(usdd_core::DecodeError),
    TooLarge,
    Truncated,
    WrongTag,
    WrongMagic,
    WrongVersion,
    WrongProofSystem,
    WrongStatementKind,
    WrongDigestMode,
    NonzeroFlags,
    EmptyPublicValues,
    PublicValuesTooLarge,
    EmptyProof,
    ZeroGuestVkey,
    WrongGuestVkey,
    LengthMismatch,
    NonCanonicalEncoding,
    Journal(JournalError),
}

impl From<usdd_core::DecodeError> for AnnexError {
    fn from(value: usdd_core::DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl fmt::Display for AnnexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AnnexError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded() -> Vec<u8> {
        let program = Hash32([7; 32]);
        let journal =
            StrictJournal::new(StatementKind::EthereumState, program, vec![1, 2, 3]).unwrap();
        Sp1ProofAnnex::new(
            StatementKind::EthereumState,
            program,
            journal.encode(),
            vec![9, 8, 7],
        )
        .unwrap()
        .encode()
    }

    #[test]
    fn matches_cxx_header_layout_and_strict_journal() {
        let bytes = encoded();
        assert_eq!(bytes[0], 0x50);
        assert_eq!(&bytes[1..9], b"USDDSP1\0");
        assert_eq!(bytes[12], 1);
        let (_, journal) = Sp1ProofAnnex::verify_strict_journal(
            &bytes,
            Hash32([7; 32]),
            StatementKind::EthereumState,
        )
        .unwrap();
        assert_eq!(journal.payload(), [1, 2, 3]);
    }

    #[test]
    fn alternate_digest_and_length_mismatch_fail() {
        let mut digest = encoded();
        digest[12] = 2;
        assert_eq!(
            Sp1ProofAnnex::decode_strict(&digest),
            Err(AnnexError::WrongDigestMode)
        );

        let mut trailing = encoded();
        trailing.push(0);
        assert_eq!(
            Sp1ProofAnnex::decode_strict(&trailing),
            Err(AnnexError::LengthMismatch)
        );
    }

    #[test]
    fn outbound_kind_is_not_accepted_in_elements_annex() {
        let mut bytes = encoded();
        bytes[11] = 2;
        assert_eq!(
            Sp1ProofAnnex::decode_strict(&bytes),
            Err(AnnexError::WrongStatementKind)
        );
    }
}
