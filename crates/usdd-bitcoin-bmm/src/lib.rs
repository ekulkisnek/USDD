#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

//! Narrow, deterministic primitives needed by the BIP300 redemption-approval
//! verifier.
//!
//! The crate validates Bitcoin headers, proof of work, cumulative work, the
//! LayerTwo Signet difficulty rule, exact parent linkage, exact block/transaction
//! serialization, context-free transaction structure, block weight, a
//! non-mutated txid Merkle tree, coinbase placement, and the Elements fork's
//! canonical slot-24 M7 encoding. It also verifies BIP141 witness commitments
//! and the sole-network Elements parent-Signet P2WPKH solution. The strongest
//! integrated genesis-derived APIs apply those checks, contextual
//! PoW/difficulty/work/time, and either deliberately fail-closed sole-slot-24
//! replay or source-faithful all-256-slot M1-through-M8 replay to the same exact
//! block and branch. Slot 24 alone may consume the optional canonical USDD
//! accumulator artifact. Opaque trackers keep an approved M6 on the selected
//! composed branch and expose its root only after the frozen 100-confirmation
//! depth. All-slot continuity loss halts future approvals without revoking an
//! earlier exact approval already bound to that branch.
//! Deterministic selection over an explicitly enumerated bounded fork set
//! remains available to the outer relay.
//!
//! It deliberately does **not** claim full Bitcoin, Signet, BIP300, or Elements
//! validity. The outer relay must still authenticate fork availability and
//! best-work selection, and the wider system must prove Elements burn validity.
//! No API in this crate treats miner approval or an accumulator commitment as
//! proof that an Elements burn transaction or block was valid.

use core::cmp::Ordering;

use sha2::{Digest, Sha256};

mod block;
mod finality;
mod m6;
mod operations;

pub use block::{
    advance_genesis_derived_layer_two_signet_multislot_replay,
    advance_genesis_derived_layer_two_signet_replay,
    advance_layer_two_signet_bmm_confirmation_tracker,
    apply_merkle_bound_elements_slot24_parent_block,
    apply_merkle_bound_elements_slot24_parent_block_owned,
    apply_merkle_bound_elements_slot24_parent_block_owned_with_m6_artifact,
    apply_merkle_bound_elements_slot24_parent_block_with_m6_artifact,
    initialize_layer_two_signet_genesis_replay,
    initialize_layer_two_signet_genesis_replay_with_manifest_bound_accumulator,
    initialize_layer_two_signet_multislot_genesis_replay,
    initialize_layer_two_signet_multislot_genesis_replay_with_manifest_bound_accumulator,
    verify_and_bind_layer_two_signet_bmm_confirmation_tracker,
    verify_and_track_layer_two_signet_approved_slot24_accumulator_m6,
    verify_and_track_layer_two_signet_multislot_approved_slot24_accumulator_m6,
    verify_layer_two_signet_block_solution, verify_layer_two_signet_contextual_successor,
    verify_layer_two_signet_mtp_successor,
    verify_layer_two_signet_pow_merkle_bound_elements_m7_successor,
    verify_pow_merkle_bound_elements_m7_successor, verify_serialized_block_merkle,
    ApprovedMultiSlotM6, ApprovedSlot24AccumulatorM6, ApprovedSlot24AccumulatorM6FinalityTracker,
    ApprovedSlot24NativeWithdrawalM6, BlockStructureError, ContextualSignetBlockTransition,
    ContextualSignetError, EffectiveSlot24M4, ElementsSlot24BlockEffects, ElementsSlot24BmmEdge,
    ElementsSlot24ReplayConfig, ElementsSlot24ReplayError, ElementsSlot24ReplayState,
    FinalizedSlot24AccumulatorRoot, GenesisDerivedLayerTwoSignetMultiSlotReplayState,
    GenesisDerivedLayerTwoSignetReplayState, LayerTwoSignetError, MerkleVerifiedBitcoinBlock,
    MintableSlot24Deposit, MultiSlotActivation,
    MultiSlotApprovedSlot24AccumulatorM6FinalityTracker, MultiSlotBlockEffects,
    MultiSlotBmmCommitment, MultiSlotCtip, MultiSlotDeposit, MultiSlotEffectiveM4,
    MultiSlotEffectiveM4Action, MultiSlotPendingM6id, MultiSlotProposal, MultiSlotReplayError,
    ParentBlockM7Error, PendingSlot24M6id, PendingSlot24Proposal, PowMerkleBoundM7,
    PowMerkleBoundM7Transition, ProofCheckpointError, SignetPowMerkleBoundM7Transition,
    Slot24AccumulatorIdentity, Slot24ApprovedRoot, Slot24Ctip, Slot24UsddContinuity,
    ECASH_PROOF_CHECKPOINT_DOMAIN, ECASH_PROOF_CHECKPOINT_MAGIC, ECASH_PROOF_CHECKPOINT_SCHEMA,
    ELEMENTS_V1_MAX_LIVE_PROPOSAL_BLOCKS, ELEMENTS_V1_REQUIRED_PROPOSAL_HASH_INTERNAL,
    MAX_PENDING_SLOT24_M6IDS, MAX_PENDING_SLOT24_PROPOSALS,
    SLOT24_ACCUMULATOR_M6_FINALITY_CONFIRMATIONS, SLOT24_M6_INCLUSION_THRESHOLD, SLOT24_M6_MAX_AGE,
    SLOT24_M6_REQUIRED_SCORE,
};
#[cfg(feature = "enforcer-differential")]
pub use block::{
    EnforcerDifferentialActiveSlot, EnforcerDifferentialReplay, EnforcerDifferentialSnapshot,
};
pub use finality::{
    bitcoin_block_confirmations, select_unique_best_work_tip, verify_contextual_successor,
    verify_mtp_successor, BmmConfirmationError, BmmConfirmationTracker, ContextualHeaderChainState,
    ContextualHeaderError, ForkChoiceError, MedianTimePastWindow, WorkForkCandidate,
    BITCOIN_MAX_FUTURE_BLOCK_TIME_SECONDS, BITCOIN_MEDIAN_TIME_SPAN,
};
pub use m6::{
    ActualM6Artifact, ApprovedClaimAppend, BlindedM6, ClaimBatchWitness, Ctip, M6Error,
    MinerBundleArtifact, NativeWithdrawalM6, NativeWithdrawalReference, RootTransition,
    ACTUAL_M6_MAGIC, BITCOIN_MAX_MONEY_SATS, BITCOIN_TRANSACTION_VERSION,
    BURN_PROOF_ENCODED_LENGTH, M6_ARTIFACT_CODEC_VERSION, M6_ROOT_DOMAIN, M6_ROOT_DOMAIN_PREIMAGE,
    M6_ROOT_PAYOUT_MAGIC, M6_ROOT_PAYOUT_SATS, M6_ROOT_PAYOUT_VERSION,
    MAX_APPROVED_CLAIMS_PER_AUDIT_WITNESS, MAX_MINER_BUNDLE_ARTIFACT_SIZE,
    MINER_BUNDLE_ARTIFACT_ENCODED_LENGTH, MINER_BUNDLE_MAGIC,
    NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE, NATIVE_WITHDRAWAL_MAX_LEGACY_M6_SIZE,
    NATIVE_WITHDRAWAL_REFERENCE_LENGTH, NATIVE_WITHDRAWAL_REFERENCE_MAGIC,
    NATIVE_WITHDRAWAL_REFERENCE_VERSION, REDEMPTION_CLAIM_ENCODED_LENGTH,
};
pub use operations::{
    ctip_from_replay, evaluate_bundle_operation, m3_proposal_script, BundleOperationError,
    BundleOperationalAction, BundleOperationalSnapshot, PendingM6Observation,
    M3_PROPOSE_BUNDLE_TAG,
};
pub use usdd_core::{
    AbiUint256, Bip300RelayConfig, RelayConfigCodecError,
    BIP300_WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD, BIP300_WITHDRAWAL_BUNDLE_MAX_AGE,
    BITCOIN_BIP300_RELAY_CONFIG_ABI_LENGTH, BITCOIN_BIP300_RELAY_CONFIG_ABI_WORDS,
    BITCOIN_BIP300_RELAY_CONFIG_DOMAIN, BITCOIN_BIP300_RELAY_CONFIG_FIELD_WORDS,
    SLOT_24_ACTIVE_BITMAP,
};

/// Immutable BIP300/301 slot selected by the sole Elements Drivechain network.
pub const ELEMENTS_DRIVECHAIN_SLOT: u8 = 24;

/// Frozen LayerTwo-Labs Signet genesis difficulty from the exact local fork.
pub const LAYER_TWO_SIGNET_GENESIS_BITS: u32 = 0x1e03_77ae;

/// Frozen LayerTwo-Labs Signet genesis display-order block hash.
pub const LAYER_TWO_SIGNET_GENESIS_DISPLAY: [u8; 32] = [
    0x00, 0x00, 0x00, 0x08, 0x81, 0x98, 0x73, 0xe9, 0x25, 0x42, 0x2c, 0x1f, 0xf0, 0xf9, 0x9f, 0x7c,
    0xc9, 0xbb, 0xb2, 0x32, 0xaf, 0x63, 0xa0, 0x77, 0xa4, 0x80, 0xa3, 0x63, 0x3b, 0xee, 0x1e, 0xf6,
];

/// P2WPKH program committed by the sole Elements network's parent-Signet
/// challenge (`0014 || program`). This intentionally follows the current
/// network identity rather than the superseded public LayerTwo challenge.
pub const ELEMENTS_PARENT_SIGNET_P2WPKH: [u8; 20] = [
    0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
    0xf1, 0x43, 0x3b, 0xd6,
];

/// Bitcoin block headers are always exactly 80 bytes on the wire.
pub const BITCOIN_HEADER_LEN: usize = 80;

/// BIP141 consensus maximum block weight inherited by the Bitcoin parent.
pub const BITCOIN_MAX_BLOCK_WEIGHT: usize = 4_000_000;

/// Every non-witness byte contributes four weight units.
pub const BITCOIN_WITNESS_SCALE_FACTOR: usize = 4;

/// Maximum base-serialized bytes in a consensus-valid Bitcoin block.
pub const BITCOIN_MAX_BLOCK_BASE_BYTES: usize =
    BITCOIN_MAX_BLOCK_WEIGHT / BITCOIN_WITNESS_SCALE_FACTOR;

/// A Bitcoin `CTxOut` needs an eight-byte value and at least a one-byte empty
/// script length. This intentionally ignores all other transaction/block bytes,
/// making the derived output-count bound permissive but consensus-safe.
pub const BITCOIN_MIN_SERIALIZED_TXOUT_BASE_BYTES: usize = 9;

/// No consensus-valid coinbase can contain more outputs than this: its outputs
/// alone would exceed the parent block's maximum base size.
pub const BITCOIN_MAX_COINBASE_OUTPUTS: usize =
    BITCOIN_MAX_BLOCK_BASE_BYTES / BITCOIN_MIN_SERIALIZED_TXOUT_BASE_BYTES;

/// Likewise, the aggregate raw script bytes cannot exceed the whole block's
/// maximum base-serialized size. Script length prefixes and every other field
/// make the real limit strictly smaller.
pub const BITCOIN_MAX_COINBASE_OUTPUT_SCRIPT_BYTES: usize = BITCOIN_MAX_BLOCK_BASE_BYTES;

const OP_RETURN: u8 = 0x6a;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const M7_TAG: [u8; 4] = [0xd1, 0x61, 0x73, 0x68];
const M7_PAYLOAD_LEN: usize = 4 + 1 + 32;
const M7_CANONICAL_SCRIPT_LEN: usize = 1 + 1 + M7_PAYLOAD_LEN;

/// Unsigned 256-bit integer represented as four little-endian 64-bit limbs.
///
/// Numeric ordering therefore starts at limb 3, not limb 0. This matches
/// Bitcoin Core's `arith_uint256` interpretation of internal hash bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Uint256([u64; 4]);

impl Uint256 {
    pub const ZERO: Self = Self([0; 4]);
    pub const MAX: Self = Self([u64::MAX; 4]);

    pub const fn from_limbs_le(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        let mut i = 0;
        while i < 4 {
            let start = i * 8;
            limbs[i] = u64::from_le_bytes(
                bytes[start..start + 8]
                    .try_into()
                    .expect("fixed eight-byte limb"),
            );
            i += 1;
        }
        Self(limbs)
    }

    pub fn from_be_bytes(mut bytes: [u8; 32]) -> Self {
        bytes.reverse();
        Self::from_le_bytes(bytes)
    }

    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = self.to_le_bytes();
        out.reverse();
        out
    }

    pub const fn is_zero(self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = false;
        for (i, slot) in out.iter_mut().enumerate() {
            let (sum, first_carry) = self.0[i].overflowing_add(rhs.0[i]);
            let (sum, second_carry) = sum.overflowing_add(u64::from(carry));
            *slot = sum;
            carry = first_carry || second_carry;
        }
        (!carry).then_some(Self(out))
    }

    fn checked_add_one(self) -> Option<Self> {
        self.checked_add(Self::from_limbs_le([1, 0, 0, 0]))
    }

    fn bit(self, bit: usize) -> bool {
        ((self.0[bit / 64] >> (bit % 64)) & 1) != 0
    }

    fn set_bit(&mut self, bit: usize) {
        self.0[bit / 64] |= 1u64 << (bit % 64);
    }

    fn bit_len(self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return (i as u32) * 64 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }

    fn low_u64(self) -> u64 {
        self.0[0]
    }

    fn shr(self, shift: u32) -> Self {
        if shift >= 256 {
            return Self::ZERO;
        }
        let word_shift = (shift / 64) as usize;
        let bit_shift = shift % 64;
        let mut out = [0u64; 4];
        for (dst, slot) in out.iter_mut().enumerate() {
            let src = dst + word_shift;
            if src >= 4 {
                break;
            }
            *slot = self.0[src] >> bit_shift;
            if bit_shift != 0 && src + 1 < 4 {
                *slot |= self.0[src + 1] << (64 - bit_shift);
            }
        }
        Self(out)
    }

    fn checked_shl(self, shift: u32) -> Option<Self> {
        if shift >= 256 {
            return self.is_zero().then_some(Self::ZERO);
        }
        if shift != 0 && self.bit_len() > 256 - shift {
            return None;
        }
        let word_shift = (shift / 64) as usize;
        let bit_shift = shift % 64;
        let mut out = [0u64; 4];
        for src in 0..4 {
            let dst = src + word_shift;
            if dst >= 4 {
                break;
            }
            out[dst] |= self.0[src] << bit_shift;
            if bit_shift != 0 && dst + 1 < 4 {
                out[dst + 1] |= self.0[src] >> (64 - bit_shift);
            }
        }
        Some(Self(out))
    }

    fn checked_mul_u64(self, rhs: u64) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (i, slot) in out.iter_mut().enumerate() {
            let product = (self.0[i] as u128) * (rhs as u128) + carry;
            *slot = product as u64;
            carry = product >> 64;
        }
        (carry == 0).then_some(Self(out))
    }

    fn div_u64(self, rhs: u64) -> Option<Self> {
        if rhs == 0 {
            return None;
        }
        let mut out = [0u64; 4];
        let mut remainder = 0u128;
        for i in (0..4).rev() {
            let dividend = (remainder << 64) | self.0[i] as u128;
            out[i] = (dividend / rhs as u128) as u64;
            remainder = dividend % rhs as u128;
        }
        Some(Self(out))
    }

    fn wrapping_not(self) -> Self {
        Self([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    /// Divide a 256-bit numerator by a nonzero 256-bit denominator using a
    /// 257-bit remainder. The extra limb prevents a silent overflow during
    /// the shift-and-subtract step.
    fn div(self, denominator: Self) -> Option<Self> {
        if denominator.is_zero() {
            return None;
        }
        let mut remainder = [0u64; 5];
        let mut divisor = [0u64; 5];
        divisor[..4].copy_from_slice(&denominator.0);
        let mut quotient = Self::ZERO;

        for bit in (0..256).rev() {
            let mut carry = u64::from(self.bit(bit));
            for limb in &mut remainder {
                let next = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
            if cmp_320(&remainder, &divisor) != Ordering::Less {
                sub_320(&mut remainder, &divisor);
                quotient.set_bit(bit);
            }
        }
        Some(quotient)
    }

    /// Bitcoin Core-compatible positive compact encoding (`GetCompact(false)`).
    pub fn to_compact(self) -> u32 {
        let mut size = self.bit_len().div_ceil(8);
        let mut compact = if size <= 3 {
            (self.low_u64() << (8 * (3 - size))) as u32
        } else {
            self.shr(8 * (size - 3)).low_u64() as u32
        };
        if compact & 0x0080_0000 != 0 {
            compact >>= 8;
            size += 1;
        }
        debug_assert_eq!(compact & !0x007f_ffff, 0);
        compact | (size << 24)
    }
}

impl Ord for Uint256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for Uint256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn cmp_320(lhs: &[u64; 5], rhs: &[u64; 5]) -> Ordering {
    for i in (0..5).rev() {
        match lhs[i].cmp(&rhs[i]) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    Ordering::Equal
}

fn sub_320(lhs: &mut [u64; 5], rhs: &[u64; 5]) {
    let mut borrow = false;
    for i in 0..5 {
        let (difference, first_borrow) = lhs[i].overflowing_sub(rhs[i]);
        let (difference, second_borrow) = difference.overflowing_sub(u64::from(borrow));
        lhs[i] = difference;
        borrow = first_borrow || second_borrow;
    }
    debug_assert!(!borrow);
}

/// A Bitcoin hash in internal/wire byte order.
///
/// Bitcoin RPC/display hex reverses these bytes. M7 serializes these internal
/// bytes directly, exactly like the Elements fork's `uint256::begin()` copy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockHash([u8; 32]);

impl BlockHash {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn from_internal_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_internal_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn from_display_bytes(mut bytes: [u8; 32]) -> Self {
        bytes.reverse();
        Self(bytes)
    }

    pub fn to_display_bytes(self) -> [u8; 32] {
        let mut out = self.0;
        out.reverse();
        out
    }

    fn as_number(self) -> Uint256 {
        Uint256::from_le_bytes(self.0)
    }
}

/// Canonically decoded 80-byte Bitcoin header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitcoinHeader {
    pub version: i32,
    pub previous_block: BlockHash,
    pub merkle_root: BlockHash,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
    raw: [u8; BITCOIN_HEADER_LEN],
}

impl BitcoinHeader {
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, HeaderError> {
        if bytes.len() != BITCOIN_HEADER_LEN {
            return Err(HeaderError::InvalidLength);
        }
        let raw: [u8; BITCOIN_HEADER_LEN] =
            bytes.try_into().map_err(|_| HeaderError::InvalidLength)?;
        let mut previous = [0u8; 32];
        previous.copy_from_slice(&raw[4..36]);
        let mut merkle = [0u8; 32];
        merkle.copy_from_slice(&raw[36..68]);
        Ok(Self {
            version: i32::from_le_bytes(raw[0..4].try_into().expect("fixed field")),
            previous_block: BlockHash::from_internal_bytes(previous),
            merkle_root: BlockHash::from_internal_bytes(merkle),
            time: u32::from_le_bytes(raw[68..72].try_into().expect("fixed field")),
            bits: u32::from_le_bytes(raw[72..76].try_into().expect("fixed field")),
            nonce: u32::from_le_bytes(raw[76..80].try_into().expect("fixed field")),
            raw,
        })
    }

    pub const fn raw(self) -> [u8; BITCOIN_HEADER_LEN] {
        self.raw
    }

    pub fn block_hash(self) -> BlockHash {
        BlockHash(double_sha256(&self.raw))
    }
}

pub(crate) fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    Sha256::digest(first).into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactTargetError {
    Negative,
    Zero,
    Overflow,
    AbovePowLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderError {
    InvalidLength,
    InvalidTarget(CompactTargetError),
    UnexpectedDifficultyBits,
    InsufficientProofOfWork,
    BrokenParentLink,
    InvalidCheckpointChainwork,
    HeightOverflow,
    ChainworkOverflow,
    InvalidDifficultyParameters,
    UnsupportedMinDifficultyRule,
    RetargetArithmeticOverflow,
}

/// Exact positive `arith_uint256::SetCompact` decoding plus Bitcoin's range
/// checks against the configured proof-of-work limit.
pub fn decode_and_validate_target(
    bits: u32,
    pow_limit: Uint256,
) -> Result<Uint256, CompactTargetError> {
    let size = bits >> 24;
    let mut word = bits & 0x007f_ffff;
    if size <= 3 {
        word >>= 8 * (3 - size);
    }
    // Bitcoin Core computes both flags from nWord *after* the small-exponent
    // right shift in arith_uint256::SetCompact.
    let negative = word != 0 && (bits & 0x0080_0000) != 0;
    let overflow =
        word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
    if negative {
        return Err(CompactTargetError::Negative);
    }
    if overflow {
        return Err(CompactTargetError::Overflow);
    }
    let target = if size <= 3 {
        Uint256::from_limbs_le([word as u64, 0, 0, 0])
    } else {
        Uint256::from_limbs_le([word as u64, 0, 0, 0])
            .checked_shl(8 * (size - 3))
            .ok_or(CompactTargetError::Overflow)?
    };
    if target.is_zero() {
        return Err(CompactTargetError::Zero);
    }
    if target > pow_limit {
        return Err(CompactTargetError::AbovePowLimit);
    }
    Ok(target)
}

/// Exact Bitcoin block proof: `(~target / (target + 1)) + 1`.
pub fn block_work(target: Uint256) -> Result<Uint256, HeaderError> {
    let denominator = target
        .checked_add_one()
        .ok_or(HeaderError::RetargetArithmeticOverflow)?;
    target
        .wrapping_not()
        .div(denominator)
        .and_then(Uint256::checked_add_one)
        .ok_or(HeaderError::RetargetArithmeticOverflow)
}

/// Parent-chain proof-of-work parameters frozen by the Elements fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowParameters {
    pub pow_limit: Uint256,
    pub target_timespan: u32,
    pub target_spacing: u32,
    pub allow_min_difficulty_blocks: bool,
    pub no_retargeting: bool,
}

impl PowParameters {
    /// LayerTwo-Labs Signet parameters used by the sole Elements network.
    pub const LAYER_TWO_SIGNET: Self = Self {
        pow_limit: Uint256::from_limbs_le([0, 0, 0, 0x0000_0377_ae00_0000]),
        target_timespan: 14 * 24 * 60 * 60,
        target_spacing: 10 * 60,
        allow_min_difficulty_blocks: false,
        no_retargeting: false,
    };

    pub fn interval(self) -> Result<u32, HeaderError> {
        if self.target_spacing == 0
            || self.target_timespan == 0
            || self.target_timespan % self.target_spacing != 0
        {
            return Err(HeaderError::InvalidDifficultyParameters);
        }
        let interval = self.target_timespan / self.target_spacing;
        if interval == 0 {
            return Err(HeaderError::InvalidDifficultyParameters);
        }
        Ok(interval)
    }
}

/// A proof-of-work-checked header. It is not a full Bitcoin-valid header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowVerifiedHeader {
    pub header: BitcoinHeader,
    pub hash: BlockHash,
    pub target: Uint256,
    pub work: Uint256,
}

/// Verify one header against difficulty bits supplied by the caller.
///
/// `caller_supplied_bits` is not authenticated by this function. Production
/// chain transitions must use [`verify_successor`], which derives the only
/// acceptable value from manifest-bound chain state. This lower-level entry
/// point exists for verifying the frozen bootstrap header and test vectors.
pub fn verify_header_pow_against_caller_supplied_bits(
    bytes: &[u8],
    caller_supplied_bits: u32,
    params: PowParameters,
) -> Result<PowVerifiedHeader, HeaderError> {
    let header = BitcoinHeader::decode_exact(bytes)?;
    if header.bits != caller_supplied_bits {
        return Err(HeaderError::UnexpectedDifficultyBits);
    }
    let target = decode_and_validate_target(header.bits, params.pow_limit)
        .map_err(HeaderError::InvalidTarget)?;
    let hash = header.block_hash();
    if hash.as_number() > target {
        return Err(HeaderError::InsufficientProofOfWork);
    }
    let work = block_work(target)?;
    Ok(PowVerifiedHeader {
        header,
        hash,
        target,
        work,
    })
}

/// Minimal state required to extend one parent header chain.
///
/// This state is authenticated only after the bootstrap fields are bound to the
/// frozen manifest. Every later value must then be derived through
/// [`verify_successor`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderChainState {
    pub height: u32,
    pub tip: PowVerifiedHeader,
    pub cumulative_work: Uint256,
    /// Timestamp of the first block in `height`'s 2016-block interval.
    pub interval_start_time: u32,
}

impl HeaderChainState {
    /// Construct state from fields that this function does not authenticate.
    ///
    /// Every argument, including `interval_start_time`, must first be bound to
    /// the frozen manifest (or derived continuously from an already-bound
    /// predecessor state). Treating private witness values as a checkpoint
    /// would let a prover choose chainwork and the next retarget result.
    pub fn from_unverified_checkpoint_requires_manifest_binding(
        height: u32,
        tip: PowVerifiedHeader,
        cumulative_work: Uint256,
        interval_start_time: u32,
    ) -> Result<Self, HeaderError> {
        if cumulative_work < tip.work {
            return Err(HeaderError::InvalidCheckpointChainwork);
        }
        Ok(Self {
            height,
            tip,
            cumulative_work,
            interval_start_time,
        })
    }
}

/// Faithful `GetNextWorkRequired` subset for the LayerTwo Signet rule.
///
/// The actual network has `allow_min_difficulty_blocks=false`; enabling that
/// testnet-only branch fails closed because it requires additional history.
pub fn next_work_required(
    state: &HeaderChainState,
    params: PowParameters,
) -> Result<u32, HeaderError> {
    let next_height = state
        .height
        .checked_add(1)
        .ok_or(HeaderError::HeightOverflow)?;
    let interval = params.interval()?;
    if next_height % interval != 0 {
        if params.allow_min_difficulty_blocks {
            return Err(HeaderError::UnsupportedMinDifficultyRule);
        }
        return Ok(state.tip.header.bits);
    }
    if params.no_retargeting {
        return Ok(state.tip.header.bits);
    }
    let old_target = decode_and_validate_target(state.tip.header.bits, params.pow_limit)
        .map_err(HeaderError::InvalidTarget)?;
    let mut actual_timespan =
        i64::from(state.tip.header.time) - i64::from(state.interval_start_time);
    let target_timespan = i64::from(params.target_timespan);
    actual_timespan = actual_timespan.clamp(target_timespan / 4, target_timespan * 4);
    let next_target = old_target
        .checked_mul_u64(actual_timespan as u64)
        .and_then(|value| value.div_u64(params.target_timespan as u64))
        .ok_or(HeaderError::RetargetArithmeticOverflow)?;
    Ok(core::cmp::min(next_target, params.pow_limit).to_compact())
}

/// Verify the next exact header, parent link, expected difficulty, proof of
/// work, and overflow-safe cumulative chainwork transition.
pub fn verify_successor(
    state: &HeaderChainState,
    bytes: &[u8],
    params: PowParameters,
) -> Result<HeaderChainState, HeaderError> {
    let expected_bits = next_work_required(state, params)?;
    let successor = verify_header_pow_against_caller_supplied_bits(bytes, expected_bits, params)?;
    if successor.header.previous_block != state.tip.hash {
        return Err(HeaderError::BrokenParentLink);
    }
    let height = state
        .height
        .checked_add(1)
        .ok_or(HeaderError::HeightOverflow)?;
    let cumulative_work = state
        .cumulative_work
        .checked_add(successor.work)
        .ok_or(HeaderError::ChainworkOverflow)?;
    let interval = params.interval()?;
    let interval_start_time = if height % interval == 0 {
        successor.header.time
    } else {
        state.interval_start_time
    };
    Ok(HeaderChainState {
        height,
        tip: successor,
        cumulative_work,
        interval_start_time,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum M7Error {
    Missing,
    Duplicate,
    NonCanonical,
    TooManyOutputs,
    AggregateScriptBytesExceeded,
    OutputIndexOverflow,
    WrongChildHash,
}

/// Canonical slot-24 M7 parsed from caller-provided coinbase output scripts.
///
/// This value remains **unbound to a Bitcoin header**. The future guest must
/// first prove that these are exactly the authenticated successor block's
/// coinbase outputs and that the coinbase is committed by its Merkle root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnboundCanonicalM7 {
    pub output_index: u32,
    pub committed_child_hash: BlockHash,
}

impl UnboundCanonicalM7 {
    /// Bind the M7 bytes to the expected Elements child hash. This still does
    /// not prove coinbase/Merkle inclusion.
    pub fn require_child_hash(self, expected: BlockHash) -> Result<Self, M7Error> {
        if self.committed_child_hash != expected {
            return Err(M7Error::WrongChildHash);
        }
        Ok(self)
    }
}

/// Mirror `ExtractCanonicalDrivechainBmmCommitmentInBlock` from the Elements
/// fork for its immutable slot 24.
pub fn extract_elements_slot24_m7(
    coinbase_output_scripts: &[&[u8]],
) -> Result<UnboundCanonicalM7, M7Error> {
    if coinbase_output_scripts.len() > BITCOIN_MAX_COINBASE_OUTPUTS {
        return Err(M7Error::TooManyOutputs);
    }
    let mut matches = 0usize;
    let mut noncanonical = 0usize;
    let mut matched_index = 0u32;
    let mut child_hash = BlockHash::ZERO;
    let mut aggregate_script_bytes = 0usize;

    for (index, script) in coinbase_output_scripts.iter().enumerate() {
        aggregate_script_bytes = aggregate_script_bytes
            .checked_add(script.len())
            .ok_or(M7Error::AggregateScriptBytesExceeded)?;
        if aggregate_script_bytes > BITCOIN_MAX_COINBASE_OUTPUT_SCRIPT_BYTES {
            return Err(M7Error::AggregateScriptBytesExceeded);
        }
        let Some(payload) = extract_single_op_return_push(script) else {
            continue;
        };
        if payload.len() != M7_PAYLOAD_LEN
            || payload[..4] != M7_TAG
            || payload[4] != ELEMENTS_DRIVECHAIN_SLOT
        {
            continue;
        }
        matches += 1;
        if script.len() != M7_CANONICAL_SCRIPT_LEN
            || script[0] != OP_RETURN
            || script[1] as usize != M7_PAYLOAD_LEN
        {
            noncanonical += 1;
        }
        matched_index = u32::try_from(index).map_err(|_| M7Error::OutputIndexOverflow)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[5..37]);
        child_hash = BlockHash::from_internal_bytes(hash);
    }

    if noncanonical != 0 {
        return Err(M7Error::NonCanonical);
    }
    match matches {
        0 => Err(M7Error::Missing),
        1 => Ok(UnboundCanonicalM7 {
            output_index: matched_index,
            committed_child_hash: child_hash,
        }),
        _ => Err(M7Error::Duplicate),
    }
}

fn extract_single_op_return_push(script: &[u8]) -> Option<&[u8]> {
    if script.len() < 2 || script[0] != OP_RETURN {
        return None;
    }
    let opcode = script[1];
    let (payload_start, payload_len) = match opcode {
        0 => (2usize, 0usize),
        1..=75 => (2usize, opcode as usize),
        OP_PUSHDATA1 => {
            let length = *script.get(2)? as usize;
            (3, length)
        }
        OP_PUSHDATA2 => {
            let length = u16::from_le_bytes([*script.get(2)?, *script.get(3)?]) as usize;
            (4, length)
        }
        OP_PUSHDATA4 => {
            let length = u32::from_le_bytes([
                *script.get(2)?,
                *script.get(3)?,
                *script.get(4)?,
                *script.get(5)?,
            ]);
            let length = usize::try_from(length).ok()?;
            (6, length)
        }
        _ => return None,
    };
    let payload_end = payload_start.checked_add(payload_len)?;
    if payload_end != script.len() {
        return None;
    }
    script.get(payload_start..payload_end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => panic!("non-hex test fixture"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    fn array32(input: &str) -> [u8; 32] {
        hex(input).try_into().expect("32-byte fixture")
    }

    fn display_hash(input: &str) -> BlockHash {
        BlockHash::from_display_bytes(array32(input))
    }

    fn mine_easy_header(previous: BlockHash, start_nonce: u32) -> [u8; 80] {
        let mut raw = [0u8; 80];
        raw[0..4].copy_from_slice(&1i32.to_le_bytes());
        raw[4..36].copy_from_slice(&previous.to_internal_bytes());
        raw[36..68].copy_from_slice(&[7u8; 32]);
        raw[68..72].copy_from_slice(&1_700_000_000u32.to_le_bytes());
        raw[72..76].copy_from_slice(&0x207f_ffffu32.to_le_bytes());
        for nonce in start_nonce..=u32::MAX {
            raw[76..80].copy_from_slice(&nonce.to_le_bytes());
            let header = BitcoinHeader::decode_exact(&raw).expect("test header");
            let target = decode_and_validate_target(
                header.bits,
                Uint256::from_limbs_le([u64::MAX, u64::MAX, u64::MAX, 0x7fff_ffff_ffff_ffff]),
            )
            .expect("easy target");
            if header.block_hash().as_number() <= target {
                return raw;
            }
        }
        panic!("no easy nonce found")
    }

    fn easy_params() -> PowParameters {
        PowParameters {
            pow_limit: Uint256::from_limbs_le([
                u64::MAX,
                u64::MAX,
                u64::MAX,
                0x7fff_ffff_ffff_ffff,
            ]),
            target_timespan: 100,
            target_spacing: 10,
            allow_min_difficulty_blocks: false,
            no_retargeting: true,
        }
    }

    #[test]
    fn bitcoin_genesis_header_hash_target_and_work_match_core() {
        let raw = hex(concat!(
            "01000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "29ab5f49",
            "ffff001d",
            "1dac2b7c"
        ));
        let params = PowParameters {
            pow_limit: Uint256::from_be_bytes(array32(
                "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )),
            target_timespan: 14 * 24 * 60 * 60,
            target_spacing: 10 * 60,
            allow_min_difficulty_blocks: false,
            no_retargeting: false,
        };
        let verified = verify_header_pow_against_caller_supplied_bits(&raw, 0x1d00_ffff, params)
            .expect("Bitcoin genesis");
        assert_eq!(
            verified.hash,
            display_hash("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
        );
        assert_eq!(
            verified.target.to_be_bytes(),
            array32("00000000ffff0000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(
            verified.work.to_be_bytes(),
            array32("0000000000000000000000000000000000000000000000000000000100010001")
        );
    }

    #[test]
    fn elements_parent_signet_block_218_header_matches_running_network_vector() {
        // First 80 bytes of sole-network parent-Signet block 218.
        let raw = hex(concat!(
            "00000020",
            "4ce0fa42ef5db70645d0a7477cf5f0a6a6c11c582caa2378322be20262010000",
            "215bd43642993a5d2930a576baccf213eb8de9f4304cd843b4a81f32c138a440",
            "c6265d6a",
            "ae77031e",
            "65476000"
        ));
        let verified = verify_header_pow_against_caller_supplied_bits(
            &raw,
            0x1e03_77ae,
            PowParameters::LAYER_TWO_SIGNET,
        )
        .expect("Elements parent-Signet block 218 PoW");
        assert_eq!(
            verified.hash,
            display_hash("0000034429ad7d70526abf86c3dcf328a5678f4122b827f266b4a095434410c7")
        );
    }

    #[test]
    fn compact_targets_reject_negative_zero_overflow_and_above_limit() {
        let limit = Uint256::MAX;
        assert_eq!(
            decode_and_validate_target(0x1d80_ffff, limit),
            Err(CompactTargetError::Negative)
        );
        assert_eq!(
            decode_and_validate_target(0, limit),
            Err(CompactTargetError::Zero)
        );
        assert_eq!(
            decode_and_validate_target(0xff12_3456, limit),
            Err(CompactTargetError::Overflow)
        );
        assert_eq!(
            decode_and_validate_target(
                0x207f_ffff,
                Uint256::from_be_bytes(array32(
                    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                )),
            ),
            Err(CompactTargetError::AbovePowLimit)
        );

        // Cross-check the small-exponent behavior in Elements'
        // bignum_SetCompact vectors: the right shift occurs before flags.
        assert_eq!(
            decode_and_validate_target(0x0180_3456, limit),
            Err(CompactTargetError::Zero)
        );
        let small = decode_and_validate_target(0x0112_3456, limit).expect("positive 0x12");
        assert_eq!(small.to_be_bytes()[31], 0x12);
        assert_eq!(small.to_compact(), 0x0112_0000);
    }

    #[test]
    fn signet_retarget_math_uses_the_manifest_bound_interval_start() {
        let params = PowParameters {
            pow_limit: Uint256::from_be_bytes(array32(
                "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )),
            target_timespan: 1_000,
            target_spacing: 100,
            allow_min_difficulty_blocks: false,
            no_retargeting: false,
        };
        let raw = hex(concat!(
            "01000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "29ab5f49",
            "ffff001d",
            "1dac2b7c"
        ));
        let tip = verify_header_pow_against_caller_supplied_bits(&raw, 0x1d00_ffff, params)
            .expect("PoW fixture");
        let mut state = HeaderChainState::from_unverified_checkpoint_requires_manifest_binding(
            9,
            tip,
            tip.work,
            tip.header.time.saturating_sub(250),
        )
        .expect("checkpoint");
        let next_bits = next_work_required(&state, params).expect("retarget");
        let next_target =
            decode_and_validate_target(next_bits, params.pow_limit).expect("retarget target");
        assert_eq!(next_target, tip.target.div_u64(4).expect("divide by four"));

        // Four-times clamp followed by the network pow-limit cap.
        state.interval_start_time = tip.header.time.saturating_sub(10_000);
        assert_eq!(
            next_work_required(&state, params).expect("capped retarget"),
            params.pow_limit.to_compact()
        );
    }

    #[test]
    fn linkage_pow_and_chainwork_fail_closed() {
        let params = easy_params();
        let first_raw = mine_easy_header(BlockHash::ZERO, 0);
        let first = verify_header_pow_against_caller_supplied_bits(&first_raw, 0x207f_ffff, params)
            .expect("first PoW");
        let state = HeaderChainState::from_unverified_checkpoint_requires_manifest_binding(
            1,
            first,
            first.work,
            first.header.time,
        )
        .expect("checkpoint");

        let linked_raw = mine_easy_header(first.hash, 0);
        let linked = verify_successor(&state, &linked_raw, params).expect("linked successor");
        assert_eq!(linked.height, 2);
        assert_eq!(
            linked.cumulative_work,
            first.work.checked_add(linked.tip.work).expect("small work")
        );

        let broken_raw = mine_easy_header(BlockHash::ZERO, 10);
        assert_eq!(
            verify_successor(&state, &broken_raw, params),
            Err(HeaderError::BrokenParentLink)
        );

        let mut insufficient = linked_raw;
        let mut found = false;
        for nonce in 0..1000u32 {
            insufficient[76..80].copy_from_slice(&nonce.to_le_bytes());
            let header = BitcoinHeader::decode_exact(&insufficient).expect("header");
            let target = decode_and_validate_target(header.bits, params.pow_limit).expect("target");
            if header.block_hash().as_number() > target {
                found = true;
                break;
            }
        }
        assert!(found, "easy target should still have failing nonces");
        assert_eq!(
            verify_successor(&state, &insufficient, params),
            Err(HeaderError::InsufficientProofOfWork)
        );

        let overflow_state = HeaderChainState {
            cumulative_work: Uint256::MAX,
            ..state
        };
        assert_eq!(
            verify_successor(&overflow_state, &linked_raw, params),
            Err(HeaderError::ChainworkOverflow)
        );
    }

    #[test]
    fn elements_slot24_m7_matches_fork_vector_and_internal_byte_order() {
        // Fixed cross-codec vector from Elements pegin_witness_tests.cpp.
        let script =
            hex("6a25d1617368188070605040302010ffeeddccbbaa99887766554433221100efcdab8967452301");
        let parsed = extract_elements_slot24_m7(&[script.as_slice()]).expect("canonical M7");
        assert_eq!(parsed.output_index, 0);
        let expected =
            display_hash("0123456789abcdef00112233445566778899aabbccddeeff1020304050607080");
        assert_eq!(parsed.committed_child_hash, expected);
        assert_eq!(parsed.require_child_hash(expected), Ok(parsed));
        assert_eq!(
            parsed.require_child_hash(BlockHash::ZERO),
            Err(M7Error::WrongChildHash)
        );
    }

    #[test]
    fn m7_rejects_wrong_slot_duplicates_nonminimal_and_malformed_scripts() {
        let canonical =
            hex("6a25d1617368188070605040302010ffeeddccbbaa99887766554433221100efcdab8967452301");
        let mut wrong_slot = canonical.clone();
        wrong_slot[6] = 23;
        assert_eq!(
            extract_elements_slot24_m7(&[wrong_slot.as_slice()]),
            Err(M7Error::Missing)
        );
        assert_eq!(
            extract_elements_slot24_m7(&[canonical.as_slice(), canonical.as_slice()]),
            Err(M7Error::Duplicate)
        );

        let mut nonminimal = Vec::with_capacity(40);
        nonminimal.extend_from_slice(&[OP_RETURN, OP_PUSHDATA1, M7_PAYLOAD_LEN as u8]);
        nonminimal.extend_from_slice(&canonical[2..]);
        assert_eq!(
            extract_elements_slot24_m7(&[nonminimal.as_slice()]),
            Err(M7Error::NonCanonical)
        );
        assert_eq!(
            extract_elements_slot24_m7(&[canonical.as_slice(), nonminimal.as_slice()]),
            Err(M7Error::NonCanonical)
        );

        let mut trailing = canonical.clone();
        trailing.push(0x51);
        assert_eq!(
            extract_elements_slot24_m7(&[trailing.as_slice()]),
            Err(M7Error::Missing)
        );
        assert_eq!(
            extract_elements_slot24_m7(&[&[OP_RETURN, OP_PUSHDATA4, 0xff]]),
            Err(M7Error::Missing)
        );
    }

    #[test]
    fn m7_resource_bounds_are_derived_from_bitcoin_consensus_weight() {
        assert_eq!(BITCOIN_MAX_BLOCK_BASE_BYTES, 1_000_000);
        assert_eq!(BITCOIN_MIN_SERIALIZED_TXOUT_BASE_BYTES, 9);
        assert_eq!(BITCOIN_MAX_COINBASE_OUTPUTS, 111_111);

        let empty: &[u8] = &[];
        let at_output_bound = vec![empty; BITCOIN_MAX_COINBASE_OUTPUTS];
        assert_eq!(
            extract_elements_slot24_m7(&at_output_bound),
            Err(M7Error::Missing)
        );
        let over_output_bound = vec![empty; BITCOIN_MAX_COINBASE_OUTPUTS + 1];
        assert_eq!(
            extract_elements_slot24_m7(&over_output_bound),
            Err(M7Error::TooManyOutputs)
        );

        let at_script_bound = vec![0u8; BITCOIN_MAX_COINBASE_OUTPUT_SCRIPT_BYTES];
        assert_eq!(
            extract_elements_slot24_m7(&[at_script_bound.as_slice()]),
            Err(M7Error::Missing)
        );
        let over_script_bound = vec![0u8; BITCOIN_MAX_COINBASE_OUTPUT_SCRIPT_BYTES + 1];
        assert_eq!(
            extract_elements_slot24_m7(&[over_script_bound.as_slice()]),
            Err(M7Error::AggregateScriptBytesExceeded)
        );
    }

    #[test]
    fn compact_boundary_vectors_match_elements_arith_uint256() {
        let limit = Uint256::MAX;
        let positive_vectors = [
            (0x0112_3456, "12", 0x0112_0000),
            (0x0200_8000, "80", 0x0200_8000),
            (0x0212_3456, "1234", 0x0212_3400),
            (0x0312_3456, "123456", 0x0312_3456),
            (0x0412_3456, "12345600", 0x0412_3456),
            (0x0500_9234, "92340000", 0x0500_9234),
        ];
        for (bits, expected_suffix, canonical) in positive_vectors {
            let decoded = decode_and_validate_target(bits, limit).expect("positive Core vector");
            let expected = hex(expected_suffix);
            assert!(decoded.to_be_bytes().ends_with(&expected));
            assert_eq!(decoded.to_compact(), canonical);
        }

        assert!(decode_and_validate_target(0x2100_ffff, limit).is_ok());
        assert_eq!(
            decode_and_validate_target(0x2101_0000, limit),
            Err(CompactTargetError::Overflow)
        );
        assert!(decode_and_validate_target(0x2200_00ff, limit).is_ok());
        assert_eq!(
            decode_and_validate_target(0x2200_0100, limit),
            Err(CompactTargetError::Overflow)
        );
        assert_eq!(
            decode_and_validate_target(0x2300_0001, limit),
            Err(CompactTargetError::Overflow)
        );
    }

    #[test]
    fn compact_roundtrips_hold_for_deterministic_256_bit_corpus() {
        let mut state = 0x6a09_e667_f3bc_c909u64;
        for _ in 0..4_096 {
            let mut limbs = [0u64; 4];
            for limb in &mut limbs {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *limb = state;
            }
            let value = Uint256::from_limbs_le(limbs);
            let compact = value.to_compact();
            let decoded = decode_and_validate_target(compact, Uint256::MAX)
                .expect("compact produced from a positive nonzero value");
            assert!(decoded <= value, "compact encoding must round down");
            assert_eq!(decoded.to_compact(), compact, "canonical compact drift");
        }
    }

    #[test]
    fn block_work_known_vectors_exercise_full_width_division() {
        let vectors = [
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "8000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "5555555555555555555555555555555555555555555555555555555555555555",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000003",
                "4000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000080",
                "01fc07f01fc07f01fc07f01fc07f01fc07f01fc07f01fc07f01fc07f01fc07f0",
            ),
            (
                "00000377ae000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000000000000000000000000000000000000049d414",
            ),
        ];
        for (target, expected_work) in vectors {
            let target = Uint256::from_be_bytes(array32(target));
            assert_eq!(
                block_work(target).expect("positive target"),
                Uint256::from_be_bytes(array32(expected_work))
            );
        }
    }

    #[test]
    fn exact_header_length_and_expected_bits_are_mandatory() {
        assert_eq!(
            BitcoinHeader::decode_exact(&[0u8; 79]),
            Err(HeaderError::InvalidLength)
        );
        assert_eq!(
            BitcoinHeader::decode_exact(&[0u8; 81]),
            Err(HeaderError::InvalidLength)
        );
        let raw = mine_easy_header(BlockHash::ZERO, 0);
        assert_eq!(
            verify_header_pow_against_caller_supplied_bits(&raw, 0x1d00_ffff, easy_params(),),
            Err(HeaderError::UnexpectedDifficultyBits)
        );
    }
}
