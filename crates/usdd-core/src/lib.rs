#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod audit;
pub mod bip301_checkpoint;
pub mod burn_accumulator;
pub mod encoding;
#[cfg(feature = "std")]
pub mod gates;
pub mod hash;
pub mod manifest;
pub mod merkle;
pub mod relay_config;
pub mod types;

pub use audit::{
    reconstruct_audit_snapshot, AuditError, AuditReport, AuditSnapshot, AuditedBurn,
    AuditedDeposit, AuditedMint, AuditedPayout,
};
pub use bip301_checkpoint::{
    Bip301CheckpointError, Bip301CheckpointTransition, BIP301_CHECKPOINT_DOMAIN,
    BIP301_CHECKPOINT_PREIMAGE_LENGTH, BIP301_CHECKPOINT_VERSION,
};
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
pub use relay_config::{
    AbiUint256, Bip300RelayConfig, RelayConfigCodecError,
    BIP300_WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD, BIP300_WITHDRAWAL_BUNDLE_MAX_AGE,
    BITCOIN_BIP300_RELAY_CONFIG_ABI_LENGTH, BITCOIN_BIP300_RELAY_CONFIG_ABI_WORDS,
    BITCOIN_BIP300_RELAY_CONFIG_DOMAIN, BITCOIN_BIP300_RELAY_CONFIG_FIELD_WORDS,
    SLOT_24_ACTIVE_BITMAP,
};
pub use types::*;

/// Canonical protocol encoding schema.
///
/// Schema 2 removes caller-supplied Bitcoin parent time from Ethereum proof
/// claims, adds the Ethereum-proved execution timestamp to public values, and
/// is also the fixed-width envelope used by the reduced BIP300-approved
/// redemption records. Schema 1 is intentionally rejected to prevent old claim
/// bytes being reinterpreted under the corrected authorization boundary.
pub const ENCODING_SCHEMA: u16 = 2;

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
pub const MAX_APPROVED_CLAIMS_PER_ROOT_UPDATE: usize = 64;
/// Compatibility name for the unchanged per-batch sparse-Merkle append cap.
pub const MAX_BURN_APPENDS_PER_STATE_TRANSITION: usize = MAX_APPROVED_CLAIMS_PER_ROOT_UPDATE;
/// Elements' context-free transaction rule caps the sum of every explicit
/// output value, across all assets, at 21 million eight-decimal base units.
pub const ELEMENTS_MAX_EXPLICIT_OUTPUT_TOTAL_BASE: u64 = 21_000_000 * USDD_SCALE;
/// Reserve one million display units of transaction-wide explicit-value
/// headroom for the singleton reissuance token, fees, and non-protocol change.
pub const MINT_TRANSACTION_EXPLICIT_HEADROOM_BASE: u64 = 1_000_000 * USDD_SCALE;
/// Maximum USDD that one controller transaction may reissue.
pub const MAX_MINT_BATCH_USDD_BASE: u64 =
    ELEMENTS_MAX_EXPLICIT_OUTPUT_TOTAL_BASE - MINT_TRANSACTION_EXPLICIT_HEADROOM_BASE;
/// Equivalent six-decimal USDT principal represented by the batch cap.
pub const MAX_MINT_BATCH_USDT_MICRO: u64 = MAX_MINT_BATCH_USDD_BASE / USDD_UNITS_PER_USDT_MICRO;
/// An immutable deposit must fit by itself in a valid mint transaction.
pub const MAX_DEPOSIT_AMOUNT_USDT_MICRO: u64 = MAX_MINT_BATCH_USDT_MICRO;
/// A canonical burn must also leave transaction-wide room for an explicit fee.
pub const MAX_BURN_AMOUNT_USDD_BASE: u64 = MAX_MINT_BATCH_USDD_BASE;
pub const MAX_BURN_AMOUNT_USDT_MICRO: u64 = MAX_MINT_BATCH_USDT_MICRO;
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
