#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod audit;
pub mod burn_accumulator;
pub mod encoding;
#[cfg(feature = "std")]
pub mod gates;
pub mod hash;
pub mod manifest;
pub mod merkle;
pub mod types;

pub use audit::{AuditError, AuditReport, AuditSnapshot};
pub use burn_accumulator::{
    burn_accumulator_empty, burn_accumulator_node, BurnAccumulator, BurnAccumulatorError,
    BurnProof, BURN_ACCUMULATOR_DEPTH,
};
pub use encoding::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder};
#[cfg(feature = "std")]
pub use gates::{GateEntry, GateError, GateReport, GateStatus, REQUIRED_LAUNCH_GATES};
pub use hash::{
    decode_hex, domain_hash, domain_separator_table_hash, encode_hex, hash_bytes, Domain, Hash32,
    HexError, DOMAIN_SEPARATOR_TABLE_V1,
};
pub use manifest::{ManifestError, ProtocolManifest};
pub use merkle::{
    empty_merkle_root, merkle_leaf, merkle_node, merkle_proof, merkle_root, MerkleError,
    MerkleProof,
};
pub use types::*;

/// Canonical protocol encoding schema.
pub const ENCODING_SCHEMA: u16 = 1;

/// The eCash Elements Drivechain slot committed by this protocol.
pub const DRIVECHAIN_SLOT: u8 = 24;

/// USDT contract display precision.
pub const USDT_SCALE: u64 = 1_000_000;

/// Elements display precision for the USDD asset.
pub const USDD_SCALE: u64 = 100_000_000;

/// Exact base-unit multiplier between six-decimal USDT and eight-decimal USDD.
pub const USDD_UNITS_PER_USDT_MICRO: u64 = 100;

pub const SP1_VERSION_MAJOR: u16 = 6;
pub const SP1_VERSION_MINOR: u16 = 3;
pub const SP1_VERSION_PATCH: u16 = 1;
pub const SP1_GIT_COMMIT: [u8; 20] = [
    0x82, 0x52, 0xc2, 0x90, 0x5c, 0xe3, 0x29, 0x64, 0xdf, 0x68, 0x24, 0x81, 0x17, 0x01, 0x5c, 0x61,
    0xeb, 0xb8, 0x54, 0xdb,
];
pub const SP1_COMPRESSED_CIRCUIT_VERSION: u16 = 1;
pub const SP1_COMPRESSED_CODEC_VERSION: u16 = 1;
pub const SHA256_DIGEST_TAG: u8 = 1;
pub const MAX_ETHEREUM_FINALITY_SLOT_GAP: u64 = 4_096;
pub const MAX_FINALIZED_TO_BMM_MTP_AGE_SECONDS: u64 = 6 * 60 * 60;
pub const MINIMUM_BITCOIN_CONFIRMATIONS: u32 = 100;
pub const ACTIVE_LIABILITY_CAP_USDT_MICRO: u64 = 1_000_000_000_000_000;

pub fn usdt_micro_to_usdd_base(amount: u64) -> Option<u64> {
    amount.checked_mul(USDD_UNITS_PER_USDT_MICRO)
}

pub fn usdd_base_to_usdt_micro(amount: u64) -> Option<u64> {
    if amount % USDD_UNITS_PER_USDT_MICRO != 0 {
        return None;
    }
    Some(amount / USDD_UNITS_PER_USDT_MICRO)
}
