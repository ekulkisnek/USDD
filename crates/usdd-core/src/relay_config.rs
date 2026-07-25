//! Exact no-std Solidity ABI identity for `BitcoinBip300RelayV1.RelayConfig`.

use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};

use crate::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder, EthAddress, Hash32};

/// `keccak256("USDD_BITCOIN_BIP300_RELAY_CONFIG_V1")`.
pub const BITCOIN_BIP300_RELAY_CONFIG_DOMAIN: Hash32 = Hash32([
    0xbf, 0xa1, 0xb0, 0x28, 0x9d, 0x9c, 0x3b, 0x05, 0xcb, 0x44, 0x8b, 0x10, 0x08, 0x6b, 0x7d, 0xa0,
    0x9c, 0x47, 0xfb, 0xa5, 0xc2, 0xa3, 0xe3, 0x08, 0xad, 0x6c, 0xce, 0x3e, 0xf9, 0x5c, 0xf9, 0xef,
]);

pub const BITCOIN_BIP300_RELAY_CONFIG_FIELD_WORDS: usize = 36;
pub const BITCOIN_BIP300_RELAY_CONFIG_ABI_WORDS: usize = 37;
pub const BITCOIN_BIP300_RELAY_CONFIG_ABI_LENGTH: usize =
    BITCOIN_BIP300_RELAY_CONFIG_ABI_WORDS * 32;
/// The sole Elements/LayerTwo Signet network uses the enforcer's SHORT rules.
pub const BIP300_WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD: u16 = 5;
/// The sole Elements/LayerTwo Signet network uses the enforcer's SHORT rules.
pub const BIP300_WITHDRAWAL_BUNDLE_MAX_AGE: u32 = 10;

/// A Solidity `uint256` represented by its exact big-endian ABI word.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AbiUint256(pub [u8; 32]);

impl AbiUint256 {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }

    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < 32 {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}

pub const SLOT_24_ACTIVE_BITMAP: AbiUint256 = AbiUint256([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
]);

/// Exact field order of the Solidity `RelayConfig` tuple.
///
/// The three cross-chain identity fields are canonical RPC/display-order IDs
/// because they enter application commitments in that order. The current
/// Solidity candidate indexes parent headers and CTIP outpoints with bytes read
/// directly from Bitcoin serialization, so its two checkpoint IDs are
/// explicitly named `*_wire` and must not be silently reversed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bip300RelayConfig {
    pub program_id: Hash32,
    pub bitcoin_genesis_hash_display: Hash32,
    pub elements_genesis_hash_display: Hash32,
    pub usdd_asset_id_display: Hash32,
    pub drivechain_slot: u8,
    pub active_slots_bitmap: AbiUint256,
    pub checkpoint_block_hash_wire: Hash32,
    pub checkpoint_height: u32,
    /// Checkpoint block time followed by its ten ancestors, newest first.
    pub checkpoint_mtp_timestamps_newest_first: [u32; 11],
    pub checkpoint_bits: u32,
    pub checkpoint_epoch_start_time: u32,
    pub checkpoint_chainwork: AbiUint256,
    pub checkpoint_ctip_txid_wire: Hash32,
    pub checkpoint_ctip_vout: u32,
    pub checkpoint_ctip_value: u64,
    pub finality_depth: u32,
    pub max_headers_per_batch: u32,
    pub retarget_interval: u32,
    pub target_timespan: u32,
    pub pow_limit: AbiUint256,
    pub withdrawal_bundle_inclusion_threshold: u16,
    pub withdrawal_bundle_max_age: u32,
    pub max_pending_bundles: u16,
    pub transaction_stream: EthAddress,
    pub transaction_stream_codehash: Hash32,
    pub transaction_stream_config_hash: Hash32,
}

impl Bip300RelayConfig {
    /// Solidity `abi.encode(RELAY_CONFIG_DOMAIN, config)`: exactly 37 words.
    pub fn abi_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BITCOIN_BIP300_RELAY_CONFIG_ABI_LENGTH);
        self.abi_encode_to(&mut out);
        out
    }

    pub fn abi_encode_to(&self, out: &mut Vec<u8>) {
        push_hash(out, BITCOIN_BIP300_RELAY_CONFIG_DOMAIN);
        push_hash(out, self.program_id);
        push_hash(out, self.bitcoin_genesis_hash_display);
        push_hash(out, self.elements_genesis_hash_display);
        push_hash(out, self.usdd_asset_id_display);
        push_uint(out, u64::from(self.drivechain_slot));
        push_u256(out, self.active_slots_bitmap);
        push_hash(out, self.checkpoint_block_hash_wire);
        push_uint(out, u64::from(self.checkpoint_height));
        for timestamp in self.checkpoint_mtp_timestamps_newest_first {
            push_uint(out, u64::from(timestamp));
        }
        push_uint(out, u64::from(self.checkpoint_bits));
        push_uint(out, u64::from(self.checkpoint_epoch_start_time));
        push_u256(out, self.checkpoint_chainwork);
        push_hash(out, self.checkpoint_ctip_txid_wire);
        push_uint(out, u64::from(self.checkpoint_ctip_vout));
        push_uint(out, self.checkpoint_ctip_value);
        push_uint(out, u64::from(self.finality_depth));
        push_uint(out, u64::from(self.max_headers_per_batch));
        push_uint(out, u64::from(self.retarget_interval));
        push_uint(out, u64::from(self.target_timespan));
        push_u256(out, self.pow_limit);
        push_uint(out, u64::from(self.withdrawal_bundle_inclusion_threshold));
        push_uint(out, u64::from(self.withdrawal_bundle_max_age));
        push_uint(out, u64::from(self.max_pending_bundles));
        push_address(out, self.transaction_stream);
        push_hash(out, self.transaction_stream_codehash);
        push_hash(out, self.transaction_stream_config_hash);
    }

    pub fn abi_decode(bytes: &[u8]) -> Result<Self, RelayConfigCodecError> {
        if bytes.len() != BITCOIN_BIP300_RELAY_CONFIG_ABI_LENGTH {
            return Err(RelayConfigCodecError::WrongLength {
                expected: BITCOIN_BIP300_RELAY_CONFIG_ABI_LENGTH,
                actual: bytes.len(),
            });
        }
        if word(bytes, 0) != *BITCOIN_BIP300_RELAY_CONFIG_DOMAIN.as_bytes() {
            return Err(RelayConfigCodecError::WrongDomain);
        }
        let mut checkpoint_mtp_timestamps_newest_first = [0u32; 11];
        for (index, timestamp) in checkpoint_mtp_timestamps_newest_first
            .iter_mut()
            .enumerate()
        {
            *timestamp = decode_u32(bytes, 9 + index)?;
        }
        Ok(Self {
            program_id: Hash32(word(bytes, 1)),
            bitcoin_genesis_hash_display: Hash32(word(bytes, 2)),
            elements_genesis_hash_display: Hash32(word(bytes, 3)),
            usdd_asset_id_display: Hash32(word(bytes, 4)),
            drivechain_slot: decode_u8(bytes, 5)?,
            active_slots_bitmap: AbiUint256::from_be_bytes(word(bytes, 6)),
            checkpoint_block_hash_wire: Hash32(word(bytes, 7)),
            checkpoint_height: decode_u32(bytes, 8)?,
            checkpoint_mtp_timestamps_newest_first,
            checkpoint_bits: decode_u32(bytes, 20)?,
            checkpoint_epoch_start_time: decode_u32(bytes, 21)?,
            checkpoint_chainwork: AbiUint256::from_be_bytes(word(bytes, 22)),
            checkpoint_ctip_txid_wire: Hash32(word(bytes, 23)),
            checkpoint_ctip_vout: decode_u32(bytes, 24)?,
            checkpoint_ctip_value: decode_u64(bytes, 25)?,
            finality_depth: decode_u32(bytes, 26)?,
            max_headers_per_batch: decode_u32(bytes, 27)?,
            retarget_interval: decode_u32(bytes, 28)?,
            target_timespan: decode_u32(bytes, 29)?,
            pow_limit: AbiUint256::from_be_bytes(word(bytes, 30)),
            withdrawal_bundle_inclusion_threshold: decode_u16(bytes, 31)?,
            withdrawal_bundle_max_age: decode_u32(bytes, 32)?,
            max_pending_bundles: decode_u16(bytes, 33)?,
            transaction_stream: decode_address(bytes, 34)?,
            transaction_stream_codehash: Hash32(word(bytes, 35)),
            transaction_stream_config_hash: Hash32(word(bytes, 36)),
        })
    }

    pub fn config_hash(&self) -> Hash32 {
        Hash32(Sha256::digest(self.abi_encode()).into())
    }

    /// Constructor-shape checks that do not impose the protocol's canonical
    /// slot, finality, or voting constants. Test helpers may therefore exercise
    /// other values without being accepted by `ProtocolManifest::validate`.
    pub fn has_valid_constructor_shape(&self) -> bool {
        self.program_id != Hash32::ZERO
            && self.bitcoin_genesis_hash_display != Hash32::ZERO
            && self.elements_genesis_hash_display != Hash32::ZERO
            && self.usdd_asset_id_display != Hash32::ZERO
            && self.checkpoint_block_hash_wire != Hash32::ZERO
            && !self.checkpoint_chainwork.is_zero()
            && self.checkpoint_ctip_txid_wire != Hash32::ZERO
            && self.finality_depth != 0
            && self.max_headers_per_batch != 0
            && self.retarget_interval != 0
            && self.target_timespan != 0
            && !self.pow_limit.is_zero()
            && self.withdrawal_bundle_max_age != 0
            && self.max_pending_bundles != 0
            && !self.transaction_stream.is_zero()
            && self.transaction_stream_codehash != Hash32::ZERO
            && self.transaction_stream_config_hash != Hash32::ZERO
            && self.withdrawal_bundle_inclusion_threshold < u16::MAX
            && self.checkpoint_ctip_value != 0
            && self.checkpoint_height >= 10
            && self
                .checkpoint_mtp_timestamps_newest_first
                .iter()
                .all(|timestamp| *timestamp != 0)
            && self.checkpoint_epoch_start_time <= self.checkpoint_mtp_timestamps_newest_first[0]
            && compact_target_is_nonzero_and_lte(self.checkpoint_bits, self.pow_limit)
    }
}

/// Match `BitcoinBip300RelayV1._compactToTarget` and its constructor bound
/// without introducing a big-integer dependency into the no-std core crate.
fn compact_target_is_nonzero_and_lte(bits: u32, limit: AbiUint256) -> bool {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    if mantissa == 0 || bits & 0x0080_0000 != 0 || exponent > 32 {
        return false;
    }

    let mut target = [0u8; 32];
    if exponent <= 3 {
        let shifted = mantissa >> (8 * (3 - exponent));
        if shifted == 0 {
            return false;
        }
        target[28..].copy_from_slice(&shifted.to_be_bytes());
    } else {
        let start = 32 - exponent;
        target[start..start + 3].copy_from_slice(&mantissa.to_be_bytes()[1..]);
    }
    target <= limit.0
}

impl CanonicalEncode for Bip300RelayConfig {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.abi_encode_to(out);
    }
}

impl CanonicalDecode for Bip300RelayConfig {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::abi_decode(decoder.take(BITCOIN_BIP300_RELAY_CONFIG_ABI_LENGTH)?)
            .map_err(|_| DecodeError::InvalidValue("invalid BIP300 relay config ABI"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayConfigCodecError {
    WrongLength { expected: usize, actual: usize },
    WrongDomain,
    NoncanonicalIntegerPadding { word: usize },
}

impl fmt::Display for RelayConfigCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(f, "relay config ABI must be {expected} bytes, got {actual}")
            }
            Self::WrongDomain => f.write_str("wrong relay config ABI domain"),
            Self::NoncanonicalIntegerPadding { word } => {
                write!(f, "nonzero ABI integer padding in word {word}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RelayConfigCodecError {}

fn push_hash(out: &mut Vec<u8>, value: Hash32) {
    out.extend_from_slice(value.as_bytes());
}

fn push_u256(out: &mut Vec<u8>, value: AbiUint256) {
    out.extend_from_slice(value.as_bytes());
}

fn push_address(out: &mut Vec<u8>, value: EthAddress) {
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&value.0);
}

fn push_uint(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&[0; 24]);
    out.extend_from_slice(&value.to_be_bytes());
}

fn word(bytes: &[u8], index: usize) -> [u8; 32] {
    bytes[index * 32..(index + 1) * 32]
        .try_into()
        .expect("length checked before word access")
}

fn decode_suffix<const N: usize>(
    bytes: &[u8],
    index: usize,
) -> Result<[u8; N], RelayConfigCodecError> {
    let value = word(bytes, index);
    if value[..32 - N].iter().any(|byte| *byte != 0) {
        return Err(RelayConfigCodecError::NoncanonicalIntegerPadding { word: index });
    }
    Ok(value[32 - N..].try_into().expect("fixed suffix"))
}

fn decode_u8(bytes: &[u8], index: usize) -> Result<u8, RelayConfigCodecError> {
    Ok(decode_suffix::<1>(bytes, index)?[0])
}

fn decode_u16(bytes: &[u8], index: usize) -> Result<u16, RelayConfigCodecError> {
    Ok(u16::from_be_bytes(decode_suffix(bytes, index)?))
}

fn decode_u32(bytes: &[u8], index: usize) -> Result<u32, RelayConfigCodecError> {
    Ok(u32::from_be_bytes(decode_suffix(bytes, index)?))
}

fn decode_u64(bytes: &[u8], index: usize) -> Result<u64, RelayConfigCodecError> {
    Ok(u64::from_be_bytes(decode_suffix(bytes, index)?))
}

fn decode_address(bytes: &[u8], index: usize) -> Result<EthAddress, RelayConfigCodecError> {
    Ok(EthAddress(decode_suffix::<20>(bytes, index)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    pub(crate) fn vector() -> Bip300RelayConfig {
        Bip300RelayConfig {
            program_id: hash(0x11),
            bitcoin_genesis_hash_display: hash(0x22),
            elements_genesis_hash_display: hash(0x33),
            usdd_asset_id_display: hash(0x44),
            drivechain_slot: 24,
            active_slots_bitmap: SLOT_24_ACTIVE_BITMAP,
            checkpoint_block_hash_wire: hash(0x55),
            checkpoint_height: 123_456,
            checkpoint_mtp_timestamps_newest_first: [
                1_700_000_000,
                1_699_999_900,
                1_699_999_800,
                1_699_999_700,
                1_699_999_600,
                1_699_999_500,
                1_699_999_400,
                1_699_999_300,
                1_699_999_200,
                1_699_999_100,
                1_699_999_000,
            ],
            checkpoint_bits: 0x207f_ffff,
            checkpoint_epoch_start_time: 1_699_990_000,
            checkpoint_chainwork: AbiUint256::from_u64(0x0123_4567_89ab_cdef),
            checkpoint_ctip_txid_wire: hash(0x66),
            checkpoint_ctip_vout: 7,
            checkpoint_ctip_value: 5_000_000_000,
            finality_depth: 100,
            max_headers_per_batch: 32,
            retarget_interval: 2_016,
            target_timespan: 1_209_600,
            pow_limit: AbiUint256([
                0x7f, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
            ]),
            withdrawal_bundle_inclusion_threshold: BIP300_WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD,
            withdrawal_bundle_max_age: BIP300_WITHDRAWAL_BUNDLE_MAX_AGE,
            max_pending_bundles: 1_024,
            transaction_stream: EthAddress([0x77; 20]),
            transaction_stream_codehash: hash(0x88),
            transaction_stream_config_hash: hash(0x99),
        }
    }

    #[test]
    fn solidity_relay_config_hash_vector_is_frozen() {
        let config = vector();
        let encoded = config.abi_encode();
        assert_eq!(encoded.len(), 1_184);
        assert_eq!(Bip300RelayConfig::abi_decode(&encoded).unwrap(), config);
        assert_eq!(
            config.config_hash().to_string(),
            "21665d983827f1fc60faf34b5a303d3a8835e322d0fb880047004c57ec86d5ad"
        );

        let mut noncanonical = encoded;
        noncanonical[5 * 32] = 1;
        assert_eq!(
            Bip300RelayConfig::abi_decode(&noncanonical),
            Err(RelayConfigCodecError::NoncanonicalIntegerPadding { word: 5 })
        );
    }

    #[test]
    fn constructor_shape_matches_checkpoint_compact_target_rules() {
        let config = vector();
        assert!(config.has_valid_constructor_shape());

        let mut negative = config;
        negative.checkpoint_bits = 0x2080_0001;
        assert!(!negative.has_valid_constructor_shape());

        let mut above_limit = config;
        above_limit.checkpoint_bits = 0x207f_ffff;
        above_limit.pow_limit = AbiUint256::from_u64(1);
        assert!(!above_limit.has_valid_constructor_shape());

        let mut rounds_to_zero = config;
        rounds_to_zero.checkpoint_bits = 0x0100_0001;
        assert!(!rounds_to_zero.has_valid_constructor_shape());
    }
}
