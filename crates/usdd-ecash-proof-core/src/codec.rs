use alloc::vec::Vec;
use core::fmt;

use usdd_bitcoin_bmm::{
    GenesisDerivedLayerTwoSignetReplayState, Slot24AccumulatorIdentity,
    LAYER_TWO_SIGNET_GENESIS_DISPLAY, SLOT24_ACCUMULATOR_M6_FINALITY_CONFIRMATIONS,
};
use usdd_core::{
    hash_bytes, CanonicalDecode, CanonicalEncode, DecodeError, Decoder, Hash32, ENCODING_SCHEMA,
};

use crate::{ApprovalAccumulator, APPROVAL_TREE_DEPTH};

pub const ECASH_SEGMENT_JOURNAL_DOMAIN: &[u8] = b"USDD_ECASH_SEGMENT_JOURNAL_V1";
pub const ECASH_FOLD_JOURNAL_DOMAIN: &[u8] = b"USDD_ECASH_FOLD_JOURNAL_V1";
const CONFIG_MAGIC: [u8; 8] = *b"ECASHCF1";
const STATE_MAGIC: [u8; 8] = *b"ECASHPS1";
const INPUT_MAGIC: [u8; 8] = *b"ECASHIN1";
const OUTPUT_MAGIC: [u8; 8] = *b"ECASHOU1";
pub const MAX_PENDING_APPROVALS: usize = 128;
pub const ABSOLUTE_MAX_SEGMENT_BLOCKS: u32 = 256;
pub const ABSOLUTE_MAX_TRANSITION_BLOCKS: u32 = 30_000;
pub const ABSOLUTE_MAX_SEGMENT_BYTES: u32 = 32 * 1024 * 1024;
pub const ABSOLUTE_MAX_STATE_BYTES: u32 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcashProofConfig {
    pub ethereum_chain_id: u64,
    pub relay_address: [u8; 20],
    pub parent_genesis: Hash32,
    pub elements_genesis: Hash32,
    pub usdd_asset: Hash32,
    pub vault_id: Hash32,
    pub segment_program_id: Hash32,
    pub fold_program_id: Hash32,
    pub verifier_config_hash: Hash32,
    pub finality_depth: u32,
    pub max_segment_blocks: u32,
    pub max_transition_blocks: u32,
    pub max_segment_bytes: u32,
    pub max_state_bytes: u32,
}

impl EcashProofConfig {
    pub fn validate(&self) -> Result<(), ProofCodecError> {
        if self.ethereum_chain_id == 0
            || self.relay_address == [0; 20]
            || self.parent_genesis != Hash32(LAYER_TWO_SIGNET_GENESIS_DISPLAY)
            || self.elements_genesis == Hash32::ZERO
            || self.usdd_asset == Hash32::ZERO
            || self.vault_id == Hash32::ZERO
            || self.segment_program_id == Hash32::ZERO
            || self.fold_program_id == Hash32::ZERO
            || self.verifier_config_hash == Hash32::ZERO
            || self.finality_depth != SLOT24_ACCUMULATOR_M6_FINALITY_CONFIRMATIONS
            || self.max_segment_blocks == 0
            || self.max_segment_blocks > ABSOLUTE_MAX_SEGMENT_BLOCKS
            || self.max_transition_blocks < self.max_segment_blocks
            || self.max_transition_blocks > ABSOLUTE_MAX_TRANSITION_BLOCKS
            || self.max_segment_bytes == 0
            || self.max_segment_bytes > ABSOLUTE_MAX_SEGMENT_BYTES
            || self.max_state_bytes == 0
            || self.max_state_bytes > ABSOLUTE_MAX_STATE_BYTES
        {
            return Err(ProofCodecError::InvalidConfig);
        }
        Ok(())
    }

    pub fn config_hash(&self) -> Result<Hash32, ProofCodecError> {
        self.validate()?;
        Ok(hash_bytes(&self.encode()))
    }

    pub const fn accumulator_identity(&self) -> Slot24AccumulatorIdentity {
        Slot24AccumulatorIdentity {
            bitcoin_genesis: self.parent_genesis,
            elements_genesis: self.elements_genesis,
            usdd_asset: self.usdd_asset,
            vault_id: self.vault_id,
        }
    }
}

impl CanonicalEncode for EcashProofConfig {
    fn encode_to(&self, out: &mut Vec<u8>) {
        CONFIG_MAGIC.encode_to(out);
        ENCODING_SCHEMA.encode_to(out);
        self.ethereum_chain_id.encode_to(out);
        self.relay_address.encode_to(out);
        self.parent_genesis.encode_to(out);
        self.elements_genesis.encode_to(out);
        self.usdd_asset.encode_to(out);
        self.vault_id.encode_to(out);
        self.segment_program_id.encode_to(out);
        self.fold_program_id.encode_to(out);
        self.verifier_config_hash.encode_to(out);
        self.finality_depth.encode_to(out);
        self.max_segment_blocks.encode_to(out);
        self.max_transition_blocks.encode_to(out);
        self.max_segment_bytes.encode_to(out);
        self.max_state_bytes.encode_to(out);
    }
}

impl CanonicalDecode for EcashProofConfig {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        require_header(decoder, CONFIG_MAGIC)?;
        let value = Self {
            ethereum_chain_id: decoder.u64()?,
            relay_address: decoder.fixed()?,
            parent_genesis: Hash32(decoder.fixed()?),
            elements_genesis: Hash32(decoder.fixed()?),
            usdd_asset: Hash32(decoder.fixed()?),
            vault_id: Hash32(decoder.fixed()?),
            segment_program_id: Hash32(decoder.fixed()?),
            fold_program_id: Hash32(decoder.fixed()?),
            verifier_config_hash: Hash32(decoder.fixed()?),
            finality_depth: decoder.u32()?,
            max_segment_blocks: decoder.u32()?,
            max_transition_blocks: decoder.u32()?,
            max_segment_bytes: decoder.u32()?,
            max_state_bytes: decoder.u32()?,
        };
        value
            .validate()
            .map_err(|_| DecodeError::InvalidValue("invalid eCash proof config"))?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingApproval {
    pub m6id: Hash32,
    pub vault_id: Hash32,
    pub prior_claim_count: u64,
    pub prior_claim_root: Hash32,
    pub next_claim_count: u64,
    pub next_claim_root: Hash32,
    pub inclusion_block_hash: Hash32,
    pub inclusion_height: u64,
}

impl PendingApproval {
    pub fn validate(&self) -> Result<(), ProofCodecError> {
        if self.m6id == Hash32::ZERO
            || self.vault_id == Hash32::ZERO
            || self.prior_claim_root == Hash32::ZERO
            || self.next_claim_root == Hash32::ZERO
            || self.inclusion_block_hash == Hash32::ZERO
            || self.next_claim_count <= self.prior_claim_count
            || self.next_claim_root == self.prior_claim_root
        {
            return Err(ProofCodecError::InvalidApproval);
        }
        Ok(())
    }
}

impl CanonicalEncode for PendingApproval {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.m6id.encode_to(out);
        self.vault_id.encode_to(out);
        self.prior_claim_count.encode_to(out);
        self.prior_claim_root.encode_to(out);
        self.next_claim_count.encode_to(out);
        self.next_claim_root.encode_to(out);
        self.inclusion_block_hash.encode_to(out);
        self.inclusion_height.encode_to(out);
    }
}

impl CanonicalDecode for PendingApproval {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            m6id: Hash32(decoder.fixed()?),
            vault_id: Hash32(decoder.fixed()?),
            prior_claim_count: decoder.u64()?,
            prior_claim_root: Hash32(decoder.fixed()?),
            next_claim_count: decoder.u64()?,
            next_claim_root: Hash32(decoder.fixed()?),
            inclusion_block_hash: Hash32(decoder.fixed()?),
            inclusion_height: decoder.u64()?,
        };
        value
            .validate()
            .map_err(|_| DecodeError::InvalidValue("invalid pending M6 approval"))?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalEvent {
    pub m6id: Hash32,
    pub vault_id: Hash32,
    pub prior_claim_count: u64,
    pub prior_claim_root: Hash32,
    pub next_claim_count: u64,
    pub next_claim_root: Hash32,
    pub inclusion_block_hash: Hash32,
    pub inclusion_height: u64,
    pub finalization_tip_hash: Hash32,
    pub finalization_height: u64,
    pub finalization_median_time_past: u64,
    pub finalization_chainwork: Hash32,
}

impl ApprovalEvent {
    pub fn validate(&self) -> Result<(), ProofCodecError> {
        PendingApproval {
            m6id: self.m6id,
            vault_id: self.vault_id,
            prior_claim_count: self.prior_claim_count,
            prior_claim_root: self.prior_claim_root,
            next_claim_count: self.next_claim_count,
            next_claim_root: self.next_claim_root,
            inclusion_block_hash: self.inclusion_block_hash,
            inclusion_height: self.inclusion_height,
        }
        .validate()?;
        if self.finalization_tip_hash == Hash32::ZERO
            || self.finalization_chainwork == Hash32::ZERO
            || self.finalization_height < self.inclusion_height
            || self.finalization_median_time_past == 0
        {
            return Err(ProofCodecError::InvalidApproval);
        }
        Ok(())
    }
}

impl CanonicalEncode for ApprovalEvent {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.m6id.encode_to(out);
        self.vault_id.encode_to(out);
        self.prior_claim_count.encode_to(out);
        self.prior_claim_root.encode_to(out);
        self.next_claim_count.encode_to(out);
        self.next_claim_root.encode_to(out);
        self.inclusion_block_hash.encode_to(out);
        self.inclusion_height.encode_to(out);
        self.finalization_tip_hash.encode_to(out);
        self.finalization_height.encode_to(out);
        self.finalization_median_time_past.encode_to(out);
        self.finalization_chainwork.encode_to(out);
    }
}

impl CanonicalDecode for ApprovalEvent {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            m6id: Hash32(decoder.fixed()?),
            vault_id: Hash32(decoder.fixed()?),
            prior_claim_count: decoder.u64()?,
            prior_claim_root: Hash32(decoder.fixed()?),
            next_claim_count: decoder.u64()?,
            next_claim_root: Hash32(decoder.fixed()?),
            inclusion_block_hash: Hash32(decoder.fixed()?),
            inclusion_height: decoder.u64()?,
            finalization_tip_hash: Hash32(decoder.fixed()?),
            finalization_height: decoder.u64()?,
            finalization_median_time_past: decoder.u64()?,
            finalization_chainwork: Hash32(decoder.fixed()?),
        };
        value
            .validate()
            .map_err(|_| DecodeError::InvalidValue("invalid finalized M6 approval"))?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcashProofState {
    pub config_hash: Hash32,
    pub replay_checkpoint: Vec<u8>,
    pub pending_approvals: Vec<PendingApproval>,
    pub finalized_approvals: ApprovalAccumulator,
    pub finalized_claim_count: u64,
    pub finalized_claim_root: Hash32,
    pub total_blocks: u64,
    pub ordered_block_transcript: Hash32,
}

impl EcashProofState {
    pub fn validate(&self, config: &EcashProofConfig) -> Result<(), ProofCodecError> {
        if self.config_hash != config.config_hash()?
            || self.replay_checkpoint.is_empty()
            || self.replay_checkpoint.len() > config.max_state_bytes as usize
            || self.pending_approvals.len() > MAX_PENDING_APPROVALS
            || self.finalized_claim_root == Hash32::ZERO
            || (self.total_blocks == 0) != (self.ordered_block_transcript == Hash32::ZERO)
        {
            return Err(ProofCodecError::InvalidState);
        }
        GenesisDerivedLayerTwoSignetReplayState::decode_untrusted_proof_checkpoint(
            &self.replay_checkpoint,
        )
        .map_err(|_| ProofCodecError::InvalidState)?;
        self.finalized_approvals.validate()?;
        let mut expected_count = self.finalized_claim_count;
        let mut expected_root = self.finalized_claim_root;
        let mut prior_height = 0;
        for pending in &self.pending_approvals {
            pending.validate()?;
            if pending.vault_id != config.vault_id
                || pending.prior_claim_count != expected_count
                || pending.prior_claim_root != expected_root
                || pending.inclusion_height < prior_height
            {
                return Err(ProofCodecError::InvalidState);
            }
            expected_count = pending.next_claim_count;
            expected_root = pending.next_claim_root;
            prior_height = pending.inclusion_height;
        }
        Ok(())
    }

    pub fn commitment(&self, config: &EcashProofConfig) -> Result<Hash32, ProofCodecError> {
        self.validate(config)?;
        Ok(hash_bytes(&self.encode()))
    }

    pub fn replay_state(&self) -> Result<GenesisDerivedLayerTwoSignetReplayState, ProofCodecError> {
        GenesisDerivedLayerTwoSignetReplayState::decode_untrusted_proof_checkpoint(
            &self.replay_checkpoint,
        )
        .map_err(|_| ProofCodecError::InvalidState)
    }
}

impl CanonicalEncode for EcashProofState {
    fn encode_to(&self, out: &mut Vec<u8>) {
        STATE_MAGIC.encode_to(out);
        ENCODING_SCHEMA.encode_to(out);
        self.config_hash.encode_to(out);
        self.replay_checkpoint.encode_to(out);
        (self.pending_approvals.len() as u16).encode_to(out);
        for pending in &self.pending_approvals {
            pending.encode_to(out);
        }
        self.finalized_approvals.count.encode_to(out);
        self.finalized_approvals.root.encode_to(out);
        for frontier in self.finalized_approvals.frontier {
            frontier.encode_to(out);
        }
        self.finalized_claim_count.encode_to(out);
        self.finalized_claim_root.encode_to(out);
        self.total_blocks.encode_to(out);
        self.ordered_block_transcript.encode_to(out);
    }
}

impl CanonicalDecode for EcashProofState {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        require_header(decoder, STATE_MAGIC)?;
        let config_hash = Hash32(decoder.fixed()?);
        let replay_checkpoint = decoder.bytes()?;
        let pending_count = usize::from(decoder.u16()?);
        if pending_count > MAX_PENDING_APPROVALS {
            return Err(DecodeError::InvalidLength {
                expected: MAX_PENDING_APPROVALS,
                actual: pending_count,
            });
        }
        let mut pending_approvals = Vec::with_capacity(pending_count);
        for _ in 0..pending_count {
            pending_approvals.push(PendingApproval::decode_from(decoder)?);
        }
        let count = decoder.u64()?;
        let root = Hash32(decoder.fixed()?);
        let mut frontier = [Hash32::ZERO; APPROVAL_TREE_DEPTH];
        for value in &mut frontier {
            *value = Hash32(decoder.fixed()?);
        }
        Ok(Self {
            config_hash,
            replay_checkpoint,
            pending_approvals,
            finalized_approvals: ApprovalAccumulator {
                count,
                root,
                frontier,
            },
            finalized_claim_count: decoder.u64()?,
            finalized_claim_root: Hash32(decoder.fixed()?),
            total_blocks: decoder.u64()?,
            ordered_block_transcript: Hash32(decoder.fixed()?),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockWitness {
    pub raw_block: Vec<u8>,
    pub canonical_m6_artifact: Option<Vec<u8>>,
}

impl CanonicalEncode for BlockWitness {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.raw_block.encode_to(out);
        self.canonical_m6_artifact.encode_to(out);
    }
}

impl CanonicalDecode for BlockWitness {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            raw_block: decoder.bytes()?,
            canonical_m6_artifact: Option::<Vec<u8>>::decode_from(decoder)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentInput {
    pub config: EcashProofConfig,
    pub prior_state: EcashProofState,
    pub expected_prior_state_commitment: Hash32,
    pub blocks: Vec<BlockWitness>,
    pub maximum_parent_block_time: u64,
    pub reward_recipient: [u8; 20],
}

impl CanonicalEncode for SegmentInput {
    fn encode_to(&self, out: &mut Vec<u8>) {
        INPUT_MAGIC.encode_to(out);
        ENCODING_SCHEMA.encode_to(out);
        self.config.encode_to(out);
        self.prior_state.encode_to(out);
        self.expected_prior_state_commitment.encode_to(out);
        (self.blocks.len() as u16).encode_to(out);
        for block in &self.blocks {
            block.encode_to(out);
        }
        self.maximum_parent_block_time.encode_to(out);
        self.reward_recipient.encode_to(out);
    }
}

impl CanonicalDecode for SegmentInput {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        require_header(decoder, INPUT_MAGIC)?;
        let config = EcashProofConfig::decode_from(decoder)?;
        let prior_state = EcashProofState::decode_from(decoder)?;
        let expected_prior_state_commitment = Hash32(decoder.fixed()?);
        let block_count = usize::from(decoder.u16()?);
        if block_count == 0 || block_count > config.max_segment_blocks as usize {
            return Err(DecodeError::InvalidValue("invalid segment block count"));
        }
        let mut blocks = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            blocks.push(BlockWitness::decode_from(decoder)?);
        }
        Ok(Self {
            config,
            prior_state,
            expected_prior_state_commitment,
            blocks,
            maximum_parent_block_time: decoder.u64()?,
            reward_recipient: decoder.fixed()?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentOutput {
    pub config_hash: Hash32,
    pub prior_state_commitment: Hash32,
    pub next_state_commitment: Hash32,
    pub prior_tip_hash: Hash32,
    pub next_tip_hash: Hash32,
    pub prior_height: u64,
    pub next_height: u64,
    pub prior_median_time_past: u64,
    pub next_median_time_past: u64,
    pub prior_chainwork: Hash32,
    pub next_chainwork: Hash32,
    pub block_count: u32,
    pub prior_ordered_block_transcript: Hash32,
    pub next_ordered_block_transcript: Hash32,
    pub maximum_parent_block_time: u64,
    pub prior_approval_count: u64,
    pub prior_approval_root: Hash32,
    pub next_approval_count: u64,
    pub next_approval_root: Hash32,
    pub prior_finalized_claim_count: u64,
    pub prior_finalized_claim_root: Hash32,
    pub next_finalized_claim_count: u64,
    pub next_finalized_claim_root: Hash32,
    pub reward_recipient: [u8; 20],
}

impl SegmentOutput {
    pub fn validate(&self, config: &EcashProofConfig) -> Result<(), ProofCodecError> {
        if self.config_hash != config.config_hash()?
            || self.prior_state_commitment == Hash32::ZERO
            || self.next_state_commitment == Hash32::ZERO
            || self.prior_tip_hash == Hash32::ZERO
            || self.next_tip_hash == Hash32::ZERO
            || self.prior_chainwork == Hash32::ZERO
            || self.next_chainwork == Hash32::ZERO
            || self.block_count == 0
            || self.block_count > config.max_transition_blocks
            || self.next_height <= self.prior_height
            || self.next_height - self.prior_height != u64::from(self.block_count)
            || self.next_approval_count < self.prior_approval_count
            || self.next_approval_root == Hash32::ZERO
            || self.prior_finalized_claim_root == Hash32::ZERO
            || self.next_finalized_claim_count < self.prior_finalized_claim_count
            || self.next_finalized_claim_root == Hash32::ZERO
            || (self.next_finalized_claim_count == self.prior_finalized_claim_count
                && self.next_finalized_claim_root != self.prior_finalized_claim_root)
            || self.reward_recipient == [0; 20]
            || self.maximum_parent_block_time == 0
        {
            return Err(ProofCodecError::InvalidOutput);
        }
        Ok(())
    }

    pub fn journal(&self, fold: bool) -> Vec<u8> {
        let encoded = self.encode();
        let domain = if fold {
            ECASH_FOLD_JOURNAL_DOMAIN
        } else {
            ECASH_SEGMENT_JOURNAL_DOMAIN
        };
        let mut out = Vec::with_capacity(domain.len() + encoded.len());
        out.extend_from_slice(domain);
        out.extend_from_slice(&encoded);
        out
    }

    pub fn journal_hash(&self, fold: bool) -> Hash32 {
        hash_bytes(&self.journal(fold))
    }
}

impl CanonicalEncode for SegmentOutput {
    fn encode_to(&self, out: &mut Vec<u8>) {
        OUTPUT_MAGIC.encode_to(out);
        ENCODING_SCHEMA.encode_to(out);
        self.config_hash.encode_to(out);
        self.prior_state_commitment.encode_to(out);
        self.next_state_commitment.encode_to(out);
        self.prior_tip_hash.encode_to(out);
        self.next_tip_hash.encode_to(out);
        self.prior_height.encode_to(out);
        self.next_height.encode_to(out);
        self.prior_median_time_past.encode_to(out);
        self.next_median_time_past.encode_to(out);
        self.prior_chainwork.encode_to(out);
        self.next_chainwork.encode_to(out);
        self.block_count.encode_to(out);
        self.prior_ordered_block_transcript.encode_to(out);
        self.next_ordered_block_transcript.encode_to(out);
        self.maximum_parent_block_time.encode_to(out);
        self.prior_approval_count.encode_to(out);
        self.prior_approval_root.encode_to(out);
        self.next_approval_count.encode_to(out);
        self.next_approval_root.encode_to(out);
        self.prior_finalized_claim_count.encode_to(out);
        self.prior_finalized_claim_root.encode_to(out);
        self.next_finalized_claim_count.encode_to(out);
        self.next_finalized_claim_root.encode_to(out);
        self.reward_recipient.encode_to(out);
    }
}

impl CanonicalDecode for SegmentOutput {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        require_header(decoder, OUTPUT_MAGIC)?;
        Ok(Self {
            config_hash: Hash32(decoder.fixed()?),
            prior_state_commitment: Hash32(decoder.fixed()?),
            next_state_commitment: Hash32(decoder.fixed()?),
            prior_tip_hash: Hash32(decoder.fixed()?),
            next_tip_hash: Hash32(decoder.fixed()?),
            prior_height: decoder.u64()?,
            next_height: decoder.u64()?,
            prior_median_time_past: decoder.u64()?,
            next_median_time_past: decoder.u64()?,
            prior_chainwork: Hash32(decoder.fixed()?),
            next_chainwork: Hash32(decoder.fixed()?),
            block_count: decoder.u32()?,
            prior_ordered_block_transcript: Hash32(decoder.fixed()?),
            next_ordered_block_transcript: Hash32(decoder.fixed()?),
            maximum_parent_block_time: decoder.u64()?,
            prior_approval_count: decoder.u64()?,
            prior_approval_root: Hash32(decoder.fixed()?),
            next_approval_count: decoder.u64()?,
            next_approval_root: Hash32(decoder.fixed()?),
            prior_finalized_claim_count: decoder.u64()?,
            prior_finalized_claim_root: Hash32(decoder.fixed()?),
            next_finalized_claim_count: decoder.u64()?,
            next_finalized_claim_root: Hash32(decoder.fixed()?),
            reward_recipient: decoder.fixed()?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofCodecError {
    Decode(DecodeError),
    InvalidConfig,
    InvalidState,
    InvalidApproval,
    InvalidAccumulator,
    InvalidOutput,
}

impl From<DecodeError> for ProofCodecError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl fmt::Display for ProofCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(f),
            Self::InvalidConfig => f.write_str("invalid eCash proof config"),
            Self::InvalidState => f.write_str("invalid eCash proof state"),
            Self::InvalidApproval => f.write_str("invalid M6 approval record"),
            Self::InvalidAccumulator => f.write_str("invalid approval accumulator"),
            Self::InvalidOutput => f.write_str("invalid segment/fold output"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProofCodecError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FoldError {
    InvalidChild,
    NonAdjacent,
    Overflow,
}

fn require_header(decoder: &mut Decoder<'_>, magic: [u8; 8]) -> Result<(), DecodeError> {
    if decoder.fixed::<8>()? != magic || decoder.u16()? != ENCODING_SCHEMA {
        return Err(DecodeError::InvalidValue("wrong eCash proof record header"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repeated(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    #[test]
    fn config_rejects_an_arbitrary_parent_genesis() {
        let config = EcashProofConfig {
            ethereum_chain_id: 11_155_111,
            relay_address: [8; 20],
            parent_genesis: Hash32([1; 32]),
            elements_genesis: Hash32([2; 32]),
            usdd_asset: Hash32([3; 32]),
            vault_id: Hash32([4; 32]),
            segment_program_id: Hash32([5; 32]),
            fold_program_id: Hash32([6; 32]),
            verifier_config_hash: Hash32([7; 32]),
            finality_depth: 100,
            max_segment_blocks: 256,
            max_transition_blocks: 30_000,
            max_segment_bytes: ABSOLUTE_MAX_SEGMENT_BYTES,
            max_state_bytes: ABSOLUTE_MAX_STATE_BYTES,
        };
        assert_eq!(config.validate(), Err(ProofCodecError::InvalidConfig));
    }

    #[test]
    fn config_sha256_matches_the_solidity_fixed_vector() {
        let config = EcashProofConfig {
            ethereum_chain_id: 11_155_111,
            relay_address: [0x11; 20],
            parent_genesis: Hash32(LAYER_TWO_SIGNET_GENESIS_DISPLAY),
            elements_genesis: repeated(0x22),
            usdd_asset: repeated(0x33),
            vault_id: repeated(0x44),
            segment_program_id: repeated(0x55),
            fold_program_id: repeated(0x66),
            verifier_config_hash: repeated(0x77),
            finality_depth: 100,
            max_segment_blocks: 256,
            max_transition_blocks: 30_000,
            max_segment_bytes: ABSOLUTE_MAX_SEGMENT_BYTES,
            max_state_bytes: ABSOLUTE_MAX_STATE_BYTES,
        };
        assert_eq!(
            config.config_hash().unwrap(),
            Hash32([
                0x1e, 0x2a, 0xff, 0xb5, 0x3d, 0x4e, 0x2b, 0xe0, 0x6a, 0x45, 0x1f, 0x7d, 0xec, 0x87,
                0x4b, 0x5d, 0x42, 0xb6, 0x80, 0x8e, 0x51, 0xae, 0xb0, 0x02, 0xdd, 0xd9, 0xdc, 0xa3,
                0xe9, 0xf5, 0xfb, 0x17,
            ])
        );
    }

    #[test]
    fn fold_journal_sha256_matches_the_solidity_fixed_vector() {
        let output = SegmentOutput {
            config_hash: repeated(1),
            prior_state_commitment: repeated(2),
            next_state_commitment: repeated(3),
            prior_tip_hash: repeated(4),
            next_tip_hash: repeated(5),
            prior_height: 10,
            next_height: 12,
            prior_median_time_past: 100,
            next_median_time_past: 101,
            prior_chainwork: repeated(6),
            next_chainwork: repeated(7),
            block_count: 2,
            prior_ordered_block_transcript: repeated(8),
            next_ordered_block_transcript: repeated(9),
            maximum_parent_block_time: 200,
            prior_approval_count: 0,
            prior_approval_root: repeated(10),
            next_approval_count: 1,
            next_approval_root: repeated(11),
            prior_finalized_claim_count: 0,
            prior_finalized_claim_root: repeated(12),
            next_finalized_claim_count: 1,
            next_finalized_claim_root: repeated(13),
            reward_recipient: [14; 20],
        };
        assert_eq!(
            output.journal_hash(true),
            Hash32([
                0x83, 0xc7, 0x5f, 0xe9, 0x22, 0x29, 0x84, 0xc6, 0x52, 0x27, 0x58, 0x58, 0xb3, 0xd8,
                0x15, 0x67, 0xf8, 0x62, 0x16, 0xa2, 0x46, 0xd1, 0x59, 0x49, 0xb9, 0xfc, 0xe3, 0xec,
                0xe9, 0xe9, 0x40, 0x73,
            ])
        );
    }
}
