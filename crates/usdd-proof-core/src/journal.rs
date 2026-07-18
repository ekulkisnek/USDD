use alloc::vec::Vec;
use core::fmt;

use usdd_core::{hash_bytes, CanonicalEncode, DecodeError, Decoder, Hash32, ENCODING_SCHEMA};

pub const JOURNAL_MAGIC: [u8; 8] = *b"USDDJNL1";
pub const JOURNAL_SUCCESS_MARKER: [u8; 8] = *b"SUCCESS!";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DigestAlgorithm {
    Sha256 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StatementKind {
    EthereumState = 1,
    ElementsBurn = 2,
}

impl StatementKind {
    fn decode(tag: u8) -> Result<Self, JournalError> {
        match tag {
            1 => Ok(Self::EthereumState),
            2 => Ok(Self::ElementsBurn),
            _ => Err(JournalError::UnsupportedStatementKind(tag)),
        }
    }
}

/// Canonical public-values envelope required around every accepted proof.
///
/// This wrapper deliberately narrows raw SP1 verifier behavior: the digest
/// tag must be SHA-256, the fixed success marker must be present, and the
/// entire byte string must be consumed. An alternate digest, an unsuccessful
/// guest, or trailing bytes is a hard failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictJournal {
    statement_kind: StatementKind,
    program_id: Hash32,
    payload_sha256: Hash32,
    payload: Vec<u8>,
}

impl StrictJournal {
    pub fn new(
        statement_kind: StatementKind,
        program_id: Hash32,
        payload: Vec<u8>,
    ) -> Result<Self, JournalError> {
        if program_id == Hash32::ZERO {
            return Err(JournalError::ZeroProgramId);
        }
        if payload.is_empty() {
            return Err(JournalError::EmptyPayload);
        }
        Ok(Self {
            statement_kind,
            program_id,
            payload_sha256: hash_bytes(&payload),
            payload,
        })
    }

    pub fn decode_strict(bytes: &[u8]) -> Result<Self, JournalError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.fixed::<8>()? != JOURNAL_MAGIC {
            return Err(JournalError::WrongMagic);
        }
        let schema = decoder.u16()?;
        if schema != ENCODING_SCHEMA {
            return Err(JournalError::UnsupportedSchema(schema));
        }
        let digest_tag = decoder.u8()?;
        if digest_tag != DigestAlgorithm::Sha256 as u8 {
            return Err(JournalError::UnsupportedDigest(digest_tag));
        }
        if decoder.fixed::<8>()? != JOURNAL_SUCCESS_MARKER {
            return Err(JournalError::GuestNotSuccessful);
        }
        let statement_kind = StatementKind::decode(decoder.u8()?)?;
        let program_id = Hash32(decoder.fixed()?);
        if program_id == Hash32::ZERO {
            return Err(JournalError::ZeroProgramId);
        }
        let payload_sha256 = Hash32(decoder.fixed()?);
        let payload = decoder.bytes()?;
        if payload.is_empty() {
            return Err(JournalError::EmptyPayload);
        }
        if decoder.remaining() != 0 {
            return Err(JournalError::TrailingBytes(decoder.remaining()));
        }
        if hash_bytes(&payload) != payload_sha256 {
            return Err(JournalError::PayloadDigestMismatch);
        }
        let value = Self {
            statement_kind,
            program_id,
            payload_sha256,
            payload,
        };
        if value.encode() != bytes {
            return Err(JournalError::NonCanonicalEncoding);
        }
        Ok(value)
    }

    pub const fn statement_kind(&self) -> StatementKind {
        self.statement_kind
    }

    pub const fn program_id(&self) -> Hash32 {
        self.program_id
    }

    pub const fn payload_sha256(&self) -> Hash32 {
        self.payload_sha256
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn verify_expected(
        bytes: &[u8],
        expected_program_id: Hash32,
        expected_statement_kind: StatementKind,
    ) -> Result<Self, JournalError> {
        let journal = Self::decode_strict(bytes)?;
        if journal.program_id != expected_program_id {
            return Err(JournalError::WrongProgramId);
        }
        if journal.statement_kind != expected_statement_kind {
            return Err(JournalError::WrongStatementKind);
        }
        Ok(journal)
    }
}

impl CanonicalEncode for StrictJournal {
    fn encode_to(&self, out: &mut Vec<u8>) {
        JOURNAL_MAGIC.encode_to(out);
        ENCODING_SCHEMA.encode_to(out);
        (DigestAlgorithm::Sha256 as u8).encode_to(out);
        JOURNAL_SUCCESS_MARKER.encode_to(out);
        (self.statement_kind as u8).encode_to(out);
        self.program_id.encode_to(out);
        self.payload_sha256.encode_to(out);
        self.payload.encode_to(out);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalError {
    Decode(DecodeError),
    WrongMagic,
    UnsupportedSchema(u16),
    UnsupportedDigest(u8),
    GuestNotSuccessful,
    UnsupportedStatementKind(u8),
    ZeroProgramId,
    EmptyPayload,
    PayloadDigestMismatch,
    TrailingBytes(usize),
    NonCanonicalEncoding,
    WrongProgramId,
    WrongStatementKind,
}

impl From<DecodeError> for JournalError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(f),
            Self::WrongMagic => f.write_str("wrong journal magic"),
            Self::UnsupportedSchema(value) => write!(f, "unsupported journal schema {value}"),
            Self::UnsupportedDigest(value) => {
                write!(
                    f,
                    "unsupported journal digest tag {value}; SHA-256 is required"
                )
            }
            Self::GuestNotSuccessful => f.write_str("guest success marker is absent"),
            Self::UnsupportedStatementKind(value) => {
                write!(f, "unsupported statement kind {value}")
            }
            Self::ZeroProgramId => f.write_str("journal program ID is zero"),
            Self::EmptyPayload => f.write_str("journal payload is empty"),
            Self::PayloadDigestMismatch => f.write_str("journal payload SHA-256 mismatch"),
            Self::TrailingBytes(value) => write!(f, "journal has {value} trailing bytes"),
            Self::NonCanonicalEncoding => f.write_str("journal encoding is noncanonical"),
            Self::WrongProgramId => f.write_str("journal program ID does not match manifest"),
            Self::WrongStatementKind => f.write_str("journal statement kind is wrong"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for JournalError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded() -> Vec<u8> {
        StrictJournal::new(StatementKind::EthereumState, Hash32([7; 32]), vec![1, 2, 3])
            .unwrap()
            .encode()
    }

    #[test]
    fn strict_round_trip() {
        let bytes = encoded();
        let journal =
            StrictJournal::verify_expected(&bytes, Hash32([7; 32]), StatementKind::EthereumState)
                .unwrap();
        assert_eq!(journal.payload(), [1, 2, 3]);
    }

    #[test]
    fn alternate_digest_is_rejected() {
        let mut bytes = encoded();
        bytes[10] = 2; // BLAKE3-style alternate tag is never accepted.
        assert_eq!(
            StrictJournal::decode_strict(&bytes),
            Err(JournalError::UnsupportedDigest(2))
        );
    }

    #[test]
    fn absent_success_is_rejected() {
        let mut bytes = encoded();
        bytes[11] = 0;
        assert_eq!(
            StrictJournal::decode_strict(&bytes),
            Err(JournalError::GuestNotSuccessful)
        );
    }

    #[test]
    fn changed_payload_and_trailing_bytes_are_rejected() {
        let mut changed = encoded();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(
            StrictJournal::decode_strict(&changed),
            Err(JournalError::PayloadDigestMismatch)
        );

        let mut trailing = encoded();
        trailing.push(0);
        assert_eq!(
            StrictJournal::decode_strict(&trailing),
            Err(JournalError::TrailingBytes(1))
        );
    }

    #[test]
    fn expected_program_and_kind_are_enforced() {
        let bytes = encoded();
        assert_eq!(
            StrictJournal::verify_expected(&bytes, Hash32([8; 32]), StatementKind::EthereumState),
            Err(JournalError::WrongProgramId)
        );
        assert_eq!(
            StrictJournal::verify_expected(&bytes, Hash32([7; 32]), StatementKind::ElementsBurn),
            Err(JournalError::WrongStatementKind)
        );
    }
}
