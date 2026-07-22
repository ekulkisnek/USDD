use alloc::vec::Vec;
use core::fmt;

use usdd_bitcoin_bmm::{
    advance_genesis_derived_layer_two_signet_replay, bitcoin_block_confirmations,
    initialize_layer_two_signet_genesis_replay_with_manifest_bound_accumulator,
    BmmConfirmationError, GenesisDerivedLayerTwoSignetReplayState, MinerBundleArtifact,
};
use usdd_core::{burn_accumulator_empty, hash_bytes, Hash32};

use crate::{
    approval_event_leaf, ApprovalAccumulator, ApprovalEvent, EcashProofConfig, EcashProofState,
    FoldError, PendingApproval, ProofCodecError, SegmentInput, SegmentOutput,
    MAX_PENDING_APPROVALS,
};

const BLOCK_TRANSCRIPT_DOMAIN: &[u8] = b"USDD_ECASH_ORDERED_BLOCK_V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SegmentError {
    Codec(ProofCodecError),
    WrongPriorCommitment,
    InvalidBlockCount,
    InputTooLarge,
    InvalidParentTime,
    InvalidArtifact,
    ReplayRejected,
    UsddContinuityLost,
    PendingApprovalLimit,
    ApprovalOrder,
    HeightOverflow,
}

impl From<ProofCodecError> for SegmentError {
    fn from(value: ProofCodecError) -> Self {
        Self::Codec(value)
    }
}

impl fmt::Display for SegmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => error.fmt(f),
            Self::WrongPriorCommitment => f.write_str("segment prior state commitment mismatch"),
            Self::InvalidBlockCount => f.write_str("invalid segment block count"),
            Self::InputTooLarge => f.write_str("segment witness exceeds its frozen byte bound"),
            Self::InvalidParentTime => f.write_str("segment maximum parent time is not exact"),
            Self::InvalidArtifact => f.write_str("canonical M6 artifact is malformed"),
            Self::ReplayRejected => {
                f.write_str("eCash/BIP300 replay rejected the block transition")
            }
            Self::UsddContinuityLost => f.write_str("slot-24 USDD continuity was lost"),
            Self::PendingApprovalLimit => f.write_str("too many unfinalized USDD approvals"),
            Self::ApprovalOrder => f.write_str("finalized approval chain is nonconsecutive"),
            Self::HeightOverflow => f.write_str("height or block counter overflow"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SegmentError {}

/// Create the only allowed initial recursive state from the exact frozen
/// parent genesis and the manifest-bound empty USDD accumulator.
pub fn bootstrap_state(
    config: &EcashProofConfig,
    serialized_genesis: &[u8],
) -> Result<EcashProofState, SegmentError> {
    config.validate()?;
    let replay = initialize_layer_two_signet_genesis_replay_with_manifest_bound_accumulator(
        serialized_genesis,
        config.accumulator_identity(),
    )
    .map_err(|_| SegmentError::ReplayRejected)?;
    let state = EcashProofState {
        config_hash: config.config_hash()?,
        replay_checkpoint: replay.encode_proof_checkpoint(),
        pending_approvals: Vec::new(),
        finalized_approvals: ApprovalAccumulator::empty(),
        finalized_claim_count: 0,
        finalized_claim_root: burn_accumulator_empty(64)
            .map_err(|_| ProofCodecError::InvalidState)?,
        total_blocks: 0,
        ordered_block_transcript: Hash32::ZERO,
    };
    state.validate(config)?;
    Ok(state)
}

/// Apply one bounded consecutive raw-block segment and produce the public
/// values committed by `ECASH_SEGMENT_V1`.
pub fn execute_segment(
    input: &SegmentInput,
) -> Result<(EcashProofState, SegmentOutput), SegmentError> {
    input.config.validate()?;
    input.prior_state.validate(&input.config)?;
    if input.reward_recipient == [0; 20] {
        return Err(SegmentError::Codec(ProofCodecError::InvalidOutput));
    }
    if input.blocks.is_empty() || input.blocks.len() > input.config.max_segment_blocks as usize {
        return Err(SegmentError::InvalidBlockCount);
    }
    let total_bytes = input.blocks.iter().try_fold(0usize, |total, block| {
        total.checked_add(block.raw_block.len()).and_then(|value| {
            value.checked_add(block.canonical_m6_artifact.as_ref().map_or(0, Vec::len))
        })
    });
    if !matches!(total_bytes, Some(value) if value <= input.config.max_segment_bytes as usize) {
        return Err(SegmentError::InputTooLarge);
    }

    let prior_state_commitment = input.prior_state.commitment(&input.config)?;
    if prior_state_commitment != input.expected_prior_state_commitment {
        return Err(SegmentError::WrongPriorCommitment);
    }
    let prior_replay = input.prior_state.replay_state()?;
    let prior_context = prior_replay.contextual();
    let prior_approval_count = input.prior_state.finalized_approvals.count;
    let prior_approval_root = input.prior_state.finalized_approvals.root;
    let prior_finalized_claim_count = input.prior_state.finalized_claim_count;
    let prior_finalized_claim_root = input.prior_state.finalized_claim_root;

    let mut next_state = input.prior_state.clone();
    let mut replay = prior_replay.clone();
    let mut exact_maximum_time = 0u64;

    for block in &input.blocks {
        if block.raw_block.len() < 80 {
            return Err(SegmentError::ReplayRejected);
        }
        let header_time = u64::from(u32::from_le_bytes(
            block.raw_block[68..72]
                .try_into()
                .expect("length checked parent header"),
        ));
        exact_maximum_time = core::cmp::max(exact_maximum_time, header_time);
        if header_time > input.maximum_parent_block_time {
            return Err(SegmentError::InvalidParentTime);
        }

        let artifact = block
            .canonical_m6_artifact
            .as_deref()
            .map(MinerBundleArtifact::decode_artifact)
            .transpose()
            .map_err(|_| SegmentError::InvalidArtifact)?;
        let (advanced, effects) = advance_genesis_derived_layer_two_signet_replay(
            &replay,
            &block.raw_block,
            input.maximum_parent_block_time,
            artifact.as_ref(),
        )
        .map_err(map_replay_error)?;
        replay = advanced;
        if replay.slot24_active_proposal_hash().is_some()
            && !replay.slot24_required_proposal_is_active()
        {
            return Err(SegmentError::UsddContinuityLost);
        }

        if let Some(approval) = effects.approved_accumulator_m6 {
            if next_state.pending_approvals.len() == MAX_PENDING_APPROVALS {
                return Err(SegmentError::PendingApprovalLimit);
            }
            next_state.pending_approvals.push(PendingApproval {
                m6id: approval.m6id,
                vault_id: input.config.vault_id,
                prior_claim_count: approval.prior_root.claim_count,
                prior_claim_root: approval.prior_root.claim_root,
                next_claim_count: approval.next_root.claim_count,
                next_claim_root: approval.next_root.claim_root,
                inclusion_block_hash: Hash32(approval.block_hash.to_display_bytes()),
                inclusion_height: u64::from(approval.block_height),
            });
        }

        finalize_mature_approvals(&input.config, &replay, &mut next_state)?;
        next_state.ordered_block_transcript = extend_block_transcript(
            next_state.ordered_block_transcript,
            u64::from(replay.tip_height()),
            &block.raw_block,
            block.canonical_m6_artifact.as_deref(),
        )?;
        next_state.total_blocks = next_state
            .total_blocks
            .checked_add(1)
            .ok_or(SegmentError::HeightOverflow)?;
    }

    if exact_maximum_time != input.maximum_parent_block_time {
        return Err(SegmentError::InvalidParentTime);
    }
    next_state.replay_checkpoint = replay.encode_proof_checkpoint();
    next_state.validate(&input.config)?;
    let next_state_commitment = next_state.commitment(&input.config)?;
    let next_context = replay.contextual();
    let block_count =
        u32::try_from(input.blocks.len()).map_err(|_| SegmentError::InvalidBlockCount)?;
    let output = SegmentOutput {
        config_hash: input.config.config_hash()?,
        prior_state_commitment,
        next_state_commitment,
        prior_tip_hash: Hash32(prior_replay.tip_hash().to_display_bytes()),
        next_tip_hash: Hash32(replay.tip_hash().to_display_bytes()),
        prior_height: u64::from(prior_replay.tip_height()),
        next_height: u64::from(replay.tip_height()),
        prior_median_time_past: u64::from(prior_context.median_time_past()),
        next_median_time_past: u64::from(next_context.median_time_past()),
        prior_chainwork: Hash32(prior_context.header_chain.cumulative_work.to_be_bytes()),
        next_chainwork: Hash32(next_context.header_chain.cumulative_work.to_be_bytes()),
        block_count,
        prior_ordered_block_transcript: input.prior_state.ordered_block_transcript,
        next_ordered_block_transcript: next_state.ordered_block_transcript,
        maximum_parent_block_time: input.maximum_parent_block_time,
        prior_approval_count,
        prior_approval_root,
        next_approval_count: next_state.finalized_approvals.count,
        next_approval_root: next_state.finalized_approvals.root,
        prior_finalized_claim_count,
        prior_finalized_claim_root,
        next_finalized_claim_count: next_state.finalized_claim_count,
        next_finalized_claim_root: next_state.finalized_claim_root,
        reward_recipient: input.reward_recipient,
    };
    output.validate(&input.config)?;
    Ok((next_state, output))
}

/// Pure adjacency fold used after the SP1 guest has recursively verified both
/// child proofs and decoded their canonical journals.
pub fn fold_outputs(
    config: &EcashProofConfig,
    left: &SegmentOutput,
    right: &SegmentOutput,
) -> Result<SegmentOutput, FoldError> {
    left.validate(config).map_err(|_| FoldError::InvalidChild)?;
    right
        .validate(config)
        .map_err(|_| FoldError::InvalidChild)?;
    if left.config_hash != right.config_hash
        || left.next_state_commitment != right.prior_state_commitment
        || left.next_tip_hash != right.prior_tip_hash
        || left.next_height != right.prior_height
        || left.next_median_time_past != right.prior_median_time_past
        || left.next_chainwork != right.prior_chainwork
        || left.next_ordered_block_transcript != right.prior_ordered_block_transcript
        || left.next_approval_count != right.prior_approval_count
        || left.next_approval_root != right.prior_approval_root
        || left.next_finalized_claim_count != right.prior_finalized_claim_count
        || left.next_finalized_claim_root != right.prior_finalized_claim_root
        || left.reward_recipient != right.reward_recipient
    {
        return Err(FoldError::NonAdjacent);
    }
    let block_count = left
        .block_count
        .checked_add(right.block_count)
        .ok_or(FoldError::Overflow)?;
    if block_count > config.max_transition_blocks {
        return Err(FoldError::Overflow);
    }
    let folded = SegmentOutput {
        config_hash: left.config_hash,
        prior_state_commitment: left.prior_state_commitment,
        next_state_commitment: right.next_state_commitment,
        prior_tip_hash: left.prior_tip_hash,
        next_tip_hash: right.next_tip_hash,
        prior_height: left.prior_height,
        next_height: right.next_height,
        prior_median_time_past: left.prior_median_time_past,
        next_median_time_past: right.next_median_time_past,
        prior_chainwork: left.prior_chainwork,
        next_chainwork: right.next_chainwork,
        block_count,
        prior_ordered_block_transcript: left.prior_ordered_block_transcript,
        next_ordered_block_transcript: right.next_ordered_block_transcript,
        maximum_parent_block_time: core::cmp::max(
            left.maximum_parent_block_time,
            right.maximum_parent_block_time,
        ),
        prior_approval_count: left.prior_approval_count,
        prior_approval_root: left.prior_approval_root,
        next_approval_count: right.next_approval_count,
        next_approval_root: right.next_approval_root,
        prior_finalized_claim_count: left.prior_finalized_claim_count,
        prior_finalized_claim_root: left.prior_finalized_claim_root,
        next_finalized_claim_count: right.next_finalized_claim_count,
        next_finalized_claim_root: right.next_finalized_claim_root,
        reward_recipient: left.reward_recipient,
    };
    folded
        .validate(config)
        .map_err(|_| FoldError::InvalidChild)?;
    Ok(folded)
}

fn finalize_mature_approvals(
    config: &EcashProofConfig,
    replay: &GenesisDerivedLayerTwoSignetReplayState,
    state: &mut EcashProofState,
) -> Result<(), SegmentError> {
    loop {
        let Some(pending) = state.pending_approvals.first() else {
            return Ok(());
        };
        let confirmations = bitcoin_block_confirmations(
            u32::try_from(pending.inclusion_height).map_err(|_| SegmentError::HeightOverflow)?,
            replay.tip_height(),
        )
        .map_err(|_| SegmentError::ReplayRejected)?;
        if confirmations < config.finality_depth {
            return Ok(());
        }
        let pending = state.pending_approvals.remove(0);
        if pending.prior_claim_count != state.finalized_claim_count
            || pending.prior_claim_root != state.finalized_claim_root
        {
            return Err(SegmentError::ApprovalOrder);
        }
        let context = replay.contextual();
        let event = ApprovalEvent {
            m6id: pending.m6id,
            vault_id: pending.vault_id,
            prior_claim_count: pending.prior_claim_count,
            prior_claim_root: pending.prior_claim_root,
            next_claim_count: pending.next_claim_count,
            next_claim_root: pending.next_claim_root,
            inclusion_block_hash: pending.inclusion_block_hash,
            inclusion_height: pending.inclusion_height,
            finalization_tip_hash: Hash32(replay.tip_hash().to_display_bytes()),
            finalization_height: u64::from(replay.tip_height()),
            finalization_median_time_past: u64::from(context.median_time_past()),
            finalization_chainwork: Hash32(context.header_chain.cumulative_work.to_be_bytes()),
        };
        event.validate()?;
        state
            .finalized_approvals
            .append(approval_event_leaf(&event))?;
        state.finalized_claim_count = event.next_claim_count;
        state.finalized_claim_root = event.next_claim_root;
    }
}

fn extend_block_transcript(
    prior: Hash32,
    height: u64,
    raw_block: &[u8],
    artifact: Option<&[u8]>,
) -> Result<Hash32, SegmentError> {
    let length = u32::try_from(raw_block.len()).map_err(|_| SegmentError::InputTooLarge)?;
    let artifact_hash = artifact.map(hash_bytes).unwrap_or(Hash32::ZERO);
    let mut preimage = Vec::with_capacity(BLOCK_TRANSCRIPT_DOMAIN.len() + 32 + 8 + 4 + 32 + 32);
    preimage.extend_from_slice(BLOCK_TRANSCRIPT_DOMAIN);
    preimage.extend_from_slice(prior.as_bytes());
    preimage.extend_from_slice(&height.to_be_bytes());
    preimage.extend_from_slice(&length.to_be_bytes());
    preimage.extend_from_slice(hash_bytes(raw_block).as_bytes());
    preimage.extend_from_slice(artifact_hash.as_bytes());
    Ok(hash_bytes(&preimage))
}

fn map_replay_error(_error: BmmConfirmationError) -> SegmentError {
    SegmentError::ReplayRejected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ABSOLUTE_MAX_SEGMENT_BYTES, ABSOLUTE_MAX_STATE_BYTES};

    fn config() -> EcashProofConfig {
        EcashProofConfig {
            ethereum_chain_id: 11_155_111,
            relay_address: [8; 20],
            parent_genesis: Hash32(usdd_bitcoin_bmm::LAYER_TWO_SIGNET_GENESIS_DISPLAY),
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
        }
    }

    fn hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid fixture hex"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn exact_genesis_bootstrap_is_reproducible() {
        let genesis = hex(concat!(
            "01000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "008f4d5fae77031e8ad2220301",
            "0100000001",
            "0000000000000000000000000000000000000000000000000000000000000000ffffffff",
            "4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73",
            "ffffffff01",
            "00f2052a01000000",
            "43",
            "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
            "00000000"
        ));
        let first = bootstrap_state(&config(), &genesis).unwrap();
        let second = bootstrap_state(&config(), &genesis).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.commitment(&config()).unwrap(),
            second.commitment(&config()).unwrap()
        );
    }
}
