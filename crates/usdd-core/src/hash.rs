use alloc::vec::Vec;
use core::{fmt, str::FromStr};

use sha2::{Digest, Sha256};

use crate::encoding::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder};

#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> alloc::string::String {
        encode_hex(&self.0)
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({self})")
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl From<[u8; 32]> for Hash32 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl FromStr for Hash32 {
    type Err = HexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = decode_hex(value)?;
        if bytes.len() != 32 {
            return Err(HexError::WrongLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.try_into().expect("length checked")))
    }
}

impl CanonicalEncode for Hash32 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.0.encode_to(out);
    }
}

impl CanonicalDecode for Hash32 {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self(decoder.fixed()?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HexError {
    OddLength,
    InvalidDigit { index: usize },
    WrongLength { expected: usize, actual: usize },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength => f.write_str("hex input has odd length"),
            Self::InvalidDigit { index } => write!(f, "invalid hex digit at byte {index}"),
            Self::WrongLength { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HexError {}

pub fn decode_hex(value: &str) -> Result<Vec<u8>, HexError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() % 2 != 0 {
        return Err(HexError::OddLength);
    }
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 2);
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let high = hex_digit(pair[0]).ok_or(HexError::InvalidDigit { index: i * 2 })?;
        let low = hex_digit(pair[1]).ok_or(HexError::InvalidDigit { index: i * 2 + 1 })?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

pub fn encode_hex(value: &[u8]) -> alloc::string::String {
    let mut output = alloc::string::String::with_capacity(value.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub fn hash_bytes(bytes: &[u8]) -> Hash32 {
    Hash32(Sha256::digest(bytes).into())
}

/// Canonical newline-delimited registry committed by every deployment
/// manifest. Changing any line requires a new protocol version.
pub const DOMAIN_SEPARATOR_TABLE_V1: &str = concat!(
    "USDD/1/merkle-leaf\n",
    "USDD/1/merkle-empty-leaf\n",
    "USDD/1/merkle-node\n",
    "USDD/1/manifest\n",
    "USDD/1/controller-config\n",
    "USDD/1/claim/ethereum-state\n",
    "USDD/1/claim/elements-event\n",
    "USDD/1/public/deposit\n",
    "USDD/1/public/redemption\n",
    "keccak256:USDD_VAULT_ID_V1\n",
    "keccak256:USDD_DEPOSIT_ID_V1\n",
    "keccak256:USDD_ELEMENTS_STATE_V1\n",
    "keccak256:USDD_ELEMENTS_STATEMENT_V1\n",
    "keccak256:USDD_BURN_LEAF_V1\n",
    "sha256:USDD_BURN_ID_V1\n",
);

pub fn domain_separator_table_hash() -> Hash32 {
    hash_bytes(DOMAIN_SEPARATOR_TABLE_V1.as_bytes())
}

/// Hash a typed protocol payload without ambiguous concatenation.
///
/// Preimage: `"USDD" || schema:u16 || domain_len:u16 || domain ||
/// payload_len:u32 || payload`.
pub fn domain_hash(domain: Domain, payload: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(b"USDD");
    hasher.update(crate::ENCODING_SCHEMA.to_be_bytes());
    let domain_bytes = domain.as_str().as_bytes();
    let domain_len = u16::try_from(domain_bytes.len()).expect("fixed domain fits u16");
    hasher.update(domain_len.to_be_bytes());
    hasher.update(domain_bytes);
    let payload_len = u32::try_from(payload.len()).expect("protocol payload exceeds u32");
    hasher.update(payload_len.to_be_bytes());
    hasher.update(payload);
    Hash32(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Domain {
    MerkleLeaf,
    MerkleEmptyLeaf,
    MerkleNode,
    Manifest,
    ControllerConfig,
    EthereumStateClaim,
    ElementsEventClaim,
    DepositPublicOutput,
    RedemptionPublicOutput,
}

impl Domain {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MerkleLeaf => "USDD/1/merkle-leaf",
            Self::MerkleEmptyLeaf => "USDD/1/merkle-empty-leaf",
            Self::MerkleNode => "USDD/1/merkle-node",
            Self::Manifest => "USDD/1/manifest",
            Self::ControllerConfig => "USDD/1/controller-config",
            Self::EthereumStateClaim => "USDD/1/claim/ethereum-state",
            Self::ElementsEventClaim => "USDD/1/claim/elements-event",
            Self::DepositPublicOutput => "USDD/1/public/deposit",
            Self::RedemptionPublicOutput => "USDD/1/public/redemption",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash32_hex_round_trip() {
        let hash = hash_bytes(b"USDD");
        assert_eq!(hash.to_string().parse::<Hash32>().unwrap(), hash);
        assert_eq!(format!("0x{hash}").parse::<Hash32>().unwrap(), hash);
    }

    #[test]
    fn strict_hex_round_trip() {
        let bytes = [0, 1, 15, 16, 254, 255];
        assert_eq!(decode_hex(&encode_hex(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn domain_and_payload_boundaries_matter() {
        assert_ne!(
            domain_hash(Domain::EthereumStateClaim, b"ab"),
            domain_hash(Domain::ElementsEventClaim, b"ab")
        );
        assert_ne!(
            domain_hash(Domain::EthereumStateClaim, b"ab"),
            domain_hash(Domain::EthereumStateClaim, b"a")
        );
    }
}
