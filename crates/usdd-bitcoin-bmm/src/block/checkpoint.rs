//! Canonical witness codec for recursive slot-24 eCash proof segments.
//!
//! The codec deliberately contains no state for the other 255 Drivechain
//! slots. Decoding is not authentication: a segment guest must bind the prior
//! checkpoint commitment to a verified predecessor, or initialize from the
//! exact frozen genesis.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use usdd_core::{hash_bytes, CanonicalEncode, DecodeError, Decoder, Hash32};

use crate::{
    verify_header_pow_against_caller_supplied_bits, BlockHash, ContextualHeaderChainState,
    EffectiveSlot24M4, ElementsSlot24ReplayConfig, ElementsSlot24ReplayState, HeaderChainState,
    MedianTimePastWindow, PendingSlot24M6id, PendingSlot24Proposal, PowParameters,
    Slot24AccumulatorIdentity, Slot24ApprovedRoot, Slot24Ctip, Uint256, MAX_PENDING_SLOT24_M6IDS,
    MAX_PENDING_SLOT24_PROPOSALS,
};

use super::signet::GenesisDerivedLayerTwoSignetReplayState;

pub const ECASH_PROOF_CHECKPOINT_MAGIC: [u8; 8] = *b"EC24ST01";
pub const ECASH_PROOF_CHECKPOINT_SCHEMA: u16 = 1;
pub const ECASH_PROOF_CHECKPOINT_DOMAIN: &[u8] = b"USDD_ECASH_SLOT24_CHECKPOINT_V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofCheckpointError {
    Decode(DecodeError),
    InvalidHeader,
    InvalidContext,
    InvalidReplay,
    InvalidCount,
    InvalidOrdering,
    InvalidTag,
    InconsistentState,
    NonCanonicalEncoding,
}

impl From<DecodeError> for ProofCheckpointError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl fmt::Display for ProofCheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(f),
            Self::InvalidHeader => f.write_str("invalid slot-24 proof-checkpoint header"),
            Self::InvalidContext => f.write_str("invalid contextual header checkpoint"),
            Self::InvalidReplay => f.write_str("invalid slot-24 replay checkpoint"),
            Self::InvalidCount => f.write_str("checkpoint collection count exceeds its bound"),
            Self::InvalidOrdering => f.write_str("checkpoint collection is not strictly ordered"),
            Self::InvalidTag => f.write_str("checkpoint contains an invalid enum or option tag"),
            Self::InconsistentState => f.write_str("header and slot-24 replay tips disagree"),
            Self::NonCanonicalEncoding => f.write_str("checkpoint encoding is noncanonical"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProofCheckpointError {}

impl GenesisDerivedLayerTwoSignetReplayState {
    pub fn encode_proof_checkpoint(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ECASH_PROOF_CHECKPOINT_MAGIC.encode_to(&mut out);
        ECASH_PROOF_CHECKPOINT_SCHEMA.encode_to(&mut out);
        let header_chain = self.contextual.header_chain;
        out.extend_from_slice(&header_chain.tip.header.raw());
        header_chain.height.encode_to(&mut out);
        header_chain
            .cumulative_work
            .to_be_bytes()
            .encode_to(&mut out);
        header_chain.interval_start_time.encode_to(&mut out);
        let timestamps = self
            .contextual
            .median_time_window
            .timestamps_oldest_to_newest();
        (timestamps.len() as u8).encode_to(&mut out);
        for timestamp in timestamps {
            timestamp.encode_to(&mut out);
        }

        let replay = &self.slot24_replay;
        replay.next_height().encode_to(&mut out);
        replay.tip_hash().to_internal_bytes().encode_to(&mut out);
        encode_hash_option(replay.active_proposal_hash(), &mut out);
        match replay.required_activation() {
            None => 0u8.encode_to(&mut out),
            Some((height, hash)) => {
                1u8.encode_to(&mut out);
                height.encode_to(&mut out);
                hash.to_internal_bytes().encode_to(&mut out);
            }
        }
        let proposals: Vec<_> = replay.pending_proposals().collect();
        (proposals.len() as u32).encode_to(&mut out);
        for proposal in proposals {
            proposal.proposal_hash.encode_to(&mut out);
            proposal.proposal_height.encode_to(&mut out);
            proposal.votes.encode_to(&mut out);
        }
        encode_ctip(replay.ctip(), &mut out);
        let pending: Vec<_> = replay.pending_m6ids().collect();
        (pending.len() as u32).encode_to(&mut out);
        for item in pending {
            item.m6id.encode_to(&mut out);
            item.proposal_height.encode_to(&mut out);
            item.score.encode_to(&mut out);
        }
        match replay.previous_effective_m4() {
            None => 0u8.encode_to(&mut out),
            Some(EffectiveSlot24M4::Upvote { m6id }) => {
                1u8.encode_to(&mut out);
                m6id.encode_to(&mut out);
            }
            Some(EffectiveSlot24M4::Alarm) => 2u8.encode_to(&mut out),
        }
        let identity = replay
            .accumulator_identity()
            .expect("proof checkpoints always bind the USDD identity");
        identity.bitcoin_genesis.encode_to(&mut out);
        identity.elements_genesis.encode_to(&mut out);
        identity.usdd_asset.encode_to(&mut out);
        identity.vault_id.encode_to(&mut out);
        let root = replay
            .approved_root()
            .expect("proof checkpoints always bind the USDD root");
        root.claim_count.encode_to(&mut out);
        root.claim_root.encode_to(&mut out);
        out
    }

    pub fn proof_checkpoint_commitment(&self) -> Hash32 {
        let encoded = self.encode_proof_checkpoint();
        let mut preimage = Vec::with_capacity(ECASH_PROOF_CHECKPOINT_DOMAIN.len() + encoded.len());
        preimage.extend_from_slice(ECASH_PROOF_CHECKPOINT_DOMAIN);
        preimage.extend_from_slice(&encoded);
        hash_bytes(&preimage)
    }

    pub fn decode_untrusted_proof_checkpoint(bytes: &[u8]) -> Result<Self, ProofCheckpointError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.fixed::<8>()? != ECASH_PROOF_CHECKPOINT_MAGIC
            || decoder.u16()? != ECASH_PROOF_CHECKPOINT_SCHEMA
        {
            return Err(ProofCheckpointError::InvalidHeader);
        }
        let raw_header = decoder.fixed::<80>()?;
        let height = decoder.u32()?;
        let cumulative_work = Uint256::from_be_bytes(decoder.fixed()?);
        let interval_start_time = decoder.u32()?;
        let mtp_len = usize::from(decoder.u8()?);
        if mtp_len == 0 || mtp_len > 11 || mtp_len != core::cmp::min(height as usize + 1, 11) {
            return Err(ProofCheckpointError::InvalidContext);
        }
        let mut timestamps = Vec::with_capacity(mtp_len);
        for _ in 0..mtp_len {
            timestamps.push(decoder.u32()?);
        }
        let bits = u32::from_le_bytes(raw_header[72..76].try_into().expect("fixed header"));
        let tip = verify_header_pow_against_caller_supplied_bits(
            &raw_header,
            bits,
            PowParameters::LAYER_TWO_SIGNET,
        )
        .map_err(|_| ProofCheckpointError::InvalidContext)?;
        let header_chain = HeaderChainState::from_unverified_checkpoint_requires_manifest_binding(
            height,
            tip,
            cumulative_work,
            interval_start_time,
        )
        .map_err(|_| ProofCheckpointError::InvalidContext)?;
        let median_time_window =
            MedianTimePastWindow::from_unverified_checkpoint_requires_manifest_binding(
                height,
                &timestamps,
            )
            .map_err(|_| ProofCheckpointError::InvalidContext)?;
        if timestamps.last().copied() != Some(tip.header.time) {
            return Err(ProofCheckpointError::InvalidContext);
        }
        let contextual = ContextualHeaderChainState {
            header_chain,
            median_time_window,
        };

        let next_height = decoder.u32()?;
        let replay_tip = BlockHash::from_internal_bytes(decoder.fixed()?);
        let active_proposal_hash = decode_hash_option(&mut decoder)?;
        let required_activation = match decoder.u8()? {
            0 => None,
            1 => Some((
                decoder.u32()?,
                BlockHash::from_internal_bytes(decoder.fixed()?),
            )),
            _ => return Err(ProofCheckpointError::InvalidTag),
        };
        let proposal_count = decoder.u32()? as usize;
        if proposal_count > MAX_PENDING_SLOT24_PROPOSALS {
            return Err(ProofCheckpointError::InvalidCount);
        }
        let mut pending_proposals = Vec::with_capacity(proposal_count);
        let mut prior_hash = None;
        for _ in 0..proposal_count {
            let proposal = PendingSlot24Proposal {
                proposal_hash: decoder.fixed()?,
                proposal_height: decoder.u32()?,
                votes: decoder.u16()?,
            };
            if prior_hash.is_some_and(|prior| proposal.proposal_hash <= prior) {
                return Err(ProofCheckpointError::InvalidOrdering);
            }
            prior_hash = Some(proposal.proposal_hash);
            pending_proposals.push(proposal);
        }
        let ctip = decode_ctip(&mut decoder)?;
        let pending_count = decoder.u32()? as usize;
        if pending_count > MAX_PENDING_SLOT24_M6IDS {
            return Err(ProofCheckpointError::InvalidCount);
        }
        let mut pending_m6ids = Vec::with_capacity(pending_count);
        for _ in 0..pending_count {
            pending_m6ids.push(PendingSlot24M6id {
                m6id: Hash32(decoder.fixed()?),
                proposal_height: decoder.u32()?,
                score: decoder.u16()?,
            });
        }
        let previous_effective_m4 = match decoder.u8()? {
            0 => None,
            1 => Some(EffectiveSlot24M4::Upvote {
                m6id: Hash32(decoder.fixed()?),
            }),
            2 => Some(EffectiveSlot24M4::Alarm),
            _ => return Err(ProofCheckpointError::InvalidTag),
        };
        let accumulator_identity = Slot24AccumulatorIdentity {
            bitcoin_genesis: Hash32(decoder.fixed()?),
            elements_genesis: Hash32(decoder.fixed()?),
            usdd_asset: Hash32(decoder.fixed()?),
            vault_id: Hash32(decoder.fixed()?),
        };
        let approved_root = Slot24ApprovedRoot {
            claim_count: decoder.u64()?,
            claim_root: Hash32(decoder.fixed()?),
        };
        if decoder.remaining() != 0 || next_height == 0 {
            return Err(ProofCheckpointError::Decode(DecodeError::TrailingBytes(
                decoder.remaining(),
            )));
        }
        let slot24_replay =
            ElementsSlot24ReplayState::from_unverified_usdd_checkpoint_requires_manifest_binding(
                ElementsSlot24ReplayConfig::elements_v1(),
                next_height - 1,
                replay_tip,
                active_proposal_hash,
                required_activation,
                pending_proposals,
                ctip,
                pending_m6ids,
                // Successful M6 IDs are bridge audit history only and have no
                // transition effect; recursive state uses its bounded approval tree.
                Vec::new(),
                previous_effective_m4,
                accumulator_identity,
                approved_root,
            )
            .map_err(|_| ProofCheckpointError::InvalidReplay)?;
        if slot24_replay.tip_hash() != contextual.header_chain.tip.hash
            || slot24_replay.next_height() != contextual.header_chain.height.saturating_add(1)
        {
            return Err(ProofCheckpointError::InconsistentState);
        }
        let state = Self {
            contextual,
            slot24_replay,
        };
        if state.encode_proof_checkpoint() != bytes {
            return Err(ProofCheckpointError::NonCanonicalEncoding);
        }
        Ok(state)
    }
}

fn encode_hash_option(value: Option<[u8; 32]>, out: &mut Vec<u8>) {
    match value {
        None => 0u8.encode_to(out),
        Some(value) => {
            1u8.encode_to(out);
            value.encode_to(out);
        }
    }
}

fn decode_hash_option(decoder: &mut Decoder<'_>) -> Result<Option<[u8; 32]>, ProofCheckpointError> {
    match decoder.u8()? {
        0 => Ok(None),
        1 => Ok(Some(decoder.fixed()?)),
        _ => Err(ProofCheckpointError::InvalidTag),
    }
}

fn encode_ctip(value: Option<Slot24Ctip>, out: &mut Vec<u8>) {
    match value {
        None => 0u8.encode_to(out),
        Some(ctip) => {
            1u8.encode_to(out);
            ctip.txid.to_internal_bytes().encode_to(out);
            ctip.vout.encode_to(out);
            ctip.value_sat.encode_to(out);
        }
    }
}

fn decode_ctip(decoder: &mut Decoder<'_>) -> Result<Option<Slot24Ctip>, ProofCheckpointError> {
    match decoder.u8()? {
        0 => Ok(None),
        1 => Ok(Some(Slot24Ctip {
            txid: BlockHash::from_internal_bytes(decoder.fixed()?),
            vout: decoder.u32()?,
            value_sat: decoder.u64()?,
        })),
        _ => Err(ProofCheckpointError::InvalidTag),
    }
}
