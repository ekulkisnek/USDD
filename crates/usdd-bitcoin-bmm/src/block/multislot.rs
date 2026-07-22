//! Exact-genesis, all-256-slot BIP300 replay.
//!
//! This module is separate from the deliberately restrictive slot-24 replay.
//! Its state has no checkpoint constructor: the public composed wrapper can
//! only initialize it from the frozen parent genesis and then advance it over
//! exact, contextual Signet blocks. Active sidechains are kept in ascending
//! slot order, matching the checked-in enforcer's database-key order used by
//! the global M4 vector.

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use usdd_core::{Hash32, OutPoint};

use crate::{
    double_sha256, extract_single_op_return_push,
    m6::{
        ActualM6Artifact, BlindedM6, Ctip, MinerBundleArtifact, NativeWithdrawalM6,
        M6_ROOT_PAYOUT_SATS,
    },
    BlockHash, ELEMENTS_DRIVECHAIN_SLOT,
};

use super::bip300::{
    ApprovedSlot24AccumulatorM6, ApprovedSlot24NativeWithdrawalM6, Slot24AccumulatorIdentity,
    Slot24ApprovedRoot, ELEMENTS_V1_REQUIRED_PROPOSAL_HASH_INTERNAL, MAX_PENDING_SLOT24_M6IDS,
    MAX_PENDING_SLOT24_PROPOSALS, SLOT24_M6_INCLUSION_THRESHOLD,
};
use super::{
    encode_compact_size, parse_and_verify_block, BlockStructureError, ParsedBlock, ParsedOutput,
    ParsedTransaction,
};

const M1_TAG: [u8; 4] = [0xd5, 0xe0, 0xc4, 0xaf];
const M2_TAG: [u8; 4] = [0xd6, 0xe1, 0xc5, 0xdf];
const M3_TAG: [u8; 4] = [0xd4, 0x5a, 0xa9, 0x43];
const M4_TAG: [u8; 4] = [0xd7, 0x7d, 0x17, 0x76];
const M7_TAG: [u8; 4] = [0xd1, 0x61, 0x73, 0x68];
const M8_TAG: [u8; 3] = [0x00, 0xbf, 0x00];
const OP_DRIVECHAIN: u8 = 0xb4;
const OP_TRUE: u8 = 0x51;
const OP_RETURN: u8 = 0x6a;
const M8_PAYLOAD_LEN: usize = 3 + 1 + 32 + 32;
const M8_SCRIPT_LEN: usize = 1 + 1 + M8_PAYLOAD_LEN;
const MAX_MONEY_SATOSHIS: u64 = 21_000_000 * 100_000_000;
const WITHDRAWAL_MAX_AGE: u32 = 10;
const PROPOSAL_MAX_AGE: u32 = 10;
const PROPOSAL_ACTIVATION_THRESHOLD: u16 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiSlotProposal {
    pub slot: u8,
    pub proposal_hash: [u8; 32],
    pub proposal_height: u32,
    pub votes: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiSlotPendingM6id {
    pub m6id: Hash32,
    pub proposal_height: u32,
    pub score: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiSlotCtip {
    pub txid: BlockHash,
    pub vout: u32,
    pub value_sat: u64,
    /// Number assigned to the transition which created this CTIP.
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultiSlotEffectiveM4Action {
    Upvote { m6id: Hash32 },
    Alarm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiSlotEffectiveM4 {
    pub slot: u8,
    pub action: MultiSlotEffectiveM4Action,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Slot24UsddContinuity {
    /// Slot 24 has never activated.
    Unactivated,
    /// The frozen Elements proposal was the first slot-24 activation and has
    /// never been replaced. Exact native ELWD M6 payments preserve this state.
    Active,
    /// Slot 24 activated or switched to an identity other than the frozen
    /// Elements proposal, so it can no longer authorize a USDD transition.
    Invalidated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiSlotActivation {
    pub slot: u8,
    pub proposal_hash: [u8; 32],
    pub block_height: u32,
    pub replaced_existing: bool,
    pub usdd_continuity: Slot24UsddContinuity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiSlotDeposit {
    pub slot: u8,
    pub outpoint: MultiSlotCtip,
    pub block_hash: BlockHash,
    pub block_height: u32,
    pub value_sat: u64,
    pub address: Vec<u8>,
    /// True only while the first and uninterrupted slot-24 identity is the
    /// frozen Elements proposal. Generic deposits never become USDD mints.
    pub usdd_mintable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovedMultiSlotM6 {
    pub slot: u8,
    pub m6id: Hash32,
    pub transaction_id: BlockHash,
    pub block_hash: BlockHash,
    pub block_height: u32,
    pub sequence: u64,
    pub successor_ctip: MultiSlotCtip,
    /// Only this value can be paired with `approved_slot24_accumulator_m6`.
    pub usdd_special: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiSlotBmmCommitment {
    pub slot: u8,
    pub child_hash: BlockHash,
    pub coinbase_vout: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiSlotBlockEffects {
    pub activations: Vec<MultiSlotActivation>,
    pub deposits: Vec<MultiSlotDeposit>,
    pub successful_m6s: Vec<ApprovedMultiSlotM6>,
    pub approved_slot24_accumulator_m6: Option<ApprovedSlot24AccumulatorM6>,
    pub approved_slot24_native_withdrawal_m6: Option<ApprovedSlot24NativeWithdrawalM6>,
    pub effective_m4: Vec<MultiSlotEffectiveM4>,
    pub expired_m6ids: Vec<(u8, Hash32)>,
    pub bmm_commitments: Vec<MultiSlotBmmCommitment>,
    pub matching_m8_requests: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultiSlotReplayError {
    Block(BlockStructureError),
    BrokenParentLink,
    HeightOverflow,
    MalformedState,
    PendingProposalLimitExceeded,
    PendingM6idLimitExceeded,
    DuplicateM1,
    DuplicateM2,
    DuplicateM4,
    DuplicateM7,
    M3ForInactiveSlot,
    M3BundleAlreadyPending,
    M4InvalidVoteCount,
    M4UpvoteMissingBundle,
    M4TwoBytesWithinByteRange,
    M4RepeatMissingBundle,
    VoteOverflow,
    ProposalHeightAhead,
    ProposalVotesAhead,
    OutputIndexOverflow,
    M8WithoutMatchingM7,
    M8WrongChildHash,
    M8Expired,
    M8CountOverflow,
    MultipleTreasuryOutputs,
    TreasurySpentWithoutReplacement,
    OldCtipUnspent,
    ZeroCtipDelta,
    AmbiguousM5M6,
    M6InputCount,
    M6TreasuryOutputIndex,
    M6AmountOverflow,
    M6MissingPendingBundle,
    M6InsufficientScore,
    /// Bridge authorization policy: upstream may accept sequential M6s, but a
    /// block with more than one slot-24 M6 is not an unambiguous V1 root
    /// transition and therefore fails closed without changing enforcer rules.
    MultipleSlot24M6s,
    InvalidCanonicalM6Artifact,
    CanonicalM6IdentityMismatch,
    CanonicalM6RootMismatch,
    CanonicalM6TransactionMismatch,
    CanonicalM6ContinuityLost,
    NativeWithdrawalIdentityMismatch,
    NativeWithdrawalTransactionMismatch,
    AmbiguousSlot24M6,
    InvalidAccumulatorIdentity,
    AccumulatorAlreadyBound,
    UnexpectedCanonicalM6Artifact,
    MissingDepositAddress,
    AmountOverflow,
}

impl From<BlockStructureError> for MultiSlotReplayError {
    fn from(value: BlockStructureError) -> Self {
        Self::Block(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveSlot {
    proposal_hash: [u8; 32],
    activation_height: u32,
    ctip: Option<MultiSlotCtip>,
    next_treasury_sequence: u64,
    pending_m6ids: Vec<MultiSlotPendingM6id>,
}

/// Internal all-slot state. It is intentionally not re-exported and has no
/// checkpoint constructor; only the exact-genesis composed wrapper owns one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MultiSlotReplayState {
    next_height: u32,
    tip_hash: BlockHash,
    proposals: BTreeMap<(u8, [u8; 32]), MultiSlotProposal>,
    active_slots: BTreeMap<u8, ActiveSlot>,
    previous_effective_m4: BTreeMap<u8, MultiSlotEffectiveM4Action>,
    successful_slot24_m6ids: BTreeSet<Hash32>,
    slot24_usdd_continuity: Slot24UsddContinuity,
    accumulator_identity: Option<Slot24AccumulatorIdentity>,
    approved_root: Option<Slot24ApprovedRoot>,
}

impl MultiSlotReplayState {
    pub(super) fn before_parent_genesis() -> Self {
        Self {
            next_height: 0,
            tip_hash: BlockHash::ZERO,
            proposals: BTreeMap::new(),
            active_slots: BTreeMap::new(),
            previous_effective_m4: BTreeMap::new(),
            successful_slot24_m6ids: BTreeSet::new(),
            slot24_usdd_continuity: Slot24UsddContinuity::Unactivated,
            accumulator_identity: None,
            approved_root: None,
        }
    }

    pub(super) const fn next_height(&self) -> u32 {
        self.next_height
    }

    pub(super) const fn tip_hash(&self) -> BlockHash {
        self.tip_hash
    }

    pub(super) fn active_slot_count(&self) -> usize {
        self.active_slots.len()
    }

    pub(super) fn active_slots(&self) -> impl ExactSizeIterator<Item = u8> + '_ {
        self.active_slots.keys().copied()
    }

    pub(super) fn active_proposal_hash(&self, slot: u8) -> Option<[u8; 32]> {
        self.active_slots
            .get(&slot)
            .map(|active| active.proposal_hash)
    }

    pub(super) fn ctip(&self, slot: u8) -> Option<MultiSlotCtip> {
        self.active_slots.get(&slot).and_then(|active| active.ctip)
    }

    pub(super) fn pending_m6ids(
        &self,
        slot: u8,
    ) -> impl Iterator<Item = MultiSlotPendingM6id> + '_ {
        self.active_slots
            .get(&slot)
            .into_iter()
            .flat_map(|active| active.pending_m6ids.iter())
            .copied()
    }

    #[allow(dead_code)]
    pub(super) fn successful_slot24_m6ids(&self) -> impl ExactSizeIterator<Item = Hash32> + '_ {
        self.successful_slot24_m6ids.iter().copied()
    }

    pub(super) const fn slot24_usdd_continuity(&self) -> Slot24UsddContinuity {
        self.slot24_usdd_continuity
    }

    pub(super) const fn approved_root(&self) -> Option<Slot24ApprovedRoot> {
        self.approved_root
    }

    pub(super) fn bind_empty_accumulator(
        &mut self,
        identity: Slot24AccumulatorIdentity,
    ) -> Result<(), MultiSlotReplayError> {
        if self.accumulator_identity.is_some() || self.approved_root.is_some() {
            return Err(MultiSlotReplayError::AccumulatorAlreadyBound);
        }
        if identity.bitcoin_genesis == Hash32::ZERO
            || identity.elements_genesis == Hash32::ZERO
            || identity.usdd_asset == Hash32::ZERO
            || identity.vault_id == Hash32::ZERO
        {
            return Err(MultiSlotReplayError::InvalidAccumulatorIdentity);
        }
        self.accumulator_identity = Some(identity);
        self.approved_root = Some(Slot24ApprovedRoot::empty());
        self.validate()
    }

    #[cfg(test)]
    pub(super) fn install_exact_slot24_activation_for_test(&mut self) {
        self.active_slots.insert(
            ELEMENTS_DRIVECHAIN_SLOT,
            ActiveSlot {
                proposal_hash: ELEMENTS_V1_REQUIRED_PROPOSAL_HASH_INTERNAL,
                activation_height: self.next_height.saturating_sub(1),
                ctip: None,
                next_treasury_sequence: 0,
                pending_m6ids: Vec::new(),
            },
        );
        self.slot24_usdd_continuity = Slot24UsddContinuity::Active;
        self.validate()
            .expect("test activation is internally valid");
    }

    #[cfg(test)]
    pub(super) fn invalidate_slot24_usdd_for_test(&mut self) {
        self.slot24_usdd_continuity = Slot24UsddContinuity::Invalidated;
        self.validate()
            .expect("invalidated test state remains valid");
    }

    fn validate(&self) -> Result<(), MultiSlotReplayError> {
        if (self.next_height == 0) != (self.tip_hash == BlockHash::ZERO) {
            return Err(MultiSlotReplayError::MalformedState);
        }
        if self.next_height == 0
            && (!self.proposals.is_empty()
                || !self.active_slots.is_empty()
                || !self.previous_effective_m4.is_empty()
                || !self.successful_slot24_m6ids.is_empty())
        {
            return Err(MultiSlotReplayError::MalformedState);
        }
        if self.proposals.len() > MAX_PENDING_SLOT24_PROPOSALS {
            return Err(MultiSlotReplayError::PendingProposalLimitExceeded);
        }
        let tip_height = self.next_height.saturating_sub(1);
        for (key, proposal) in &self.proposals {
            if *key != (proposal.slot, proposal.proposal_hash)
                || proposal.proposal_height > tip_height
                || u32::from(proposal.votes) > tip_height.saturating_sub(proposal.proposal_height)
            {
                return Err(MultiSlotReplayError::MalformedState);
            }
        }
        let mut total_pending = 0usize;
        let mut seen_ctips = BTreeSet::new();
        for active in self.active_slots.values() {
            if active.activation_height > tip_height {
                return Err(MultiSlotReplayError::MalformedState);
            }
            if let Some(ctip) = active.ctip {
                if ctip.value_sat > MAX_MONEY_SATOSHIS
                    || ctip.sequence >= active.next_treasury_sequence
                    || !seen_ctips.insert((ctip.txid.to_internal_bytes(), ctip.vout))
                {
                    return Err(MultiSlotReplayError::MalformedState);
                }
            } else if active.next_treasury_sequence != 0 {
                return Err(MultiSlotReplayError::MalformedState);
            }
            total_pending = total_pending
                .checked_add(active.pending_m6ids.len())
                .ok_or(MultiSlotReplayError::PendingM6idLimitExceeded)?;
            let mut seen = BTreeSet::new();
            for pending in &active.pending_m6ids {
                if !seen.insert(pending.m6id)
                    || pending.proposal_height > tip_height
                    || tip_height.saturating_sub(pending.proposal_height) > WITHDRAWAL_MAX_AGE
                {
                    return Err(MultiSlotReplayError::MalformedState);
                }
            }
        }
        if total_pending > MAX_PENDING_SLOT24_M6IDS {
            return Err(MultiSlotReplayError::PendingM6idLimitExceeded);
        }
        if self
            .previous_effective_m4
            .keys()
            .any(|slot| !self.active_slots.contains_key(slot))
        {
            return Err(MultiSlotReplayError::MalformedState);
        }
        // Upstream permits a paid M6id to be proposed again. Successful IDs
        // are retained only as bridge audit history and may overlap the live
        // pending set.
        if self.successful_slot24_m6ids.contains(&Hash32::ZERO) {
            return Err(MultiSlotReplayError::MalformedState);
        }
        match (self.accumulator_identity, self.approved_root) {
            (None, None) | (Some(_), Some(_)) => {}
            _ => return Err(MultiSlotReplayError::MalformedState),
        }
        match self.slot24_usdd_continuity {
            Slot24UsddContinuity::Unactivated
                if self.active_slots.contains_key(&ELEMENTS_DRIVECHAIN_SLOT) =>
            {
                return Err(MultiSlotReplayError::MalformedState);
            }
            Slot24UsddContinuity::Active
                if match self.active_slots.get(&ELEMENTS_DRIVECHAIN_SLOT) {
                    Some(active) => {
                        active.proposal_hash != ELEMENTS_V1_REQUIRED_PROPOSAL_HASH_INTERNAL
                    }
                    None => true,
                } =>
            {
                return Err(MultiSlotReplayError::MalformedState);
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ParentMessage {
    M1 { slot: u8, proposal_hash: [u8; 32] },
    M2 { slot: u8, proposal_hash: [u8; 32] },
}

fn parse_parent_message(script: &[u8]) -> Option<ParentMessage> {
    let payload = extract_single_op_return_push(script)?;
    if payload.len() < 5 {
        return None;
    }
    if payload[..4] == M1_TAG {
        return Some(ParentMessage::M1 {
            slot: payload[4],
            proposal_hash: double_sha256(&payload[5..]),
        });
    }
    if payload.len() == 37 && payload[..4] == M2_TAG {
        let mut proposal_hash = [0; 32];
        proposal_hash.copy_from_slice(&payload[5..]);
        return Some(ParentMessage::M2 {
            slot: payload[4],
            proposal_hash,
        });
    }
    None
}

fn parse_m3(script: &[u8]) -> Option<(u8, Hash32)> {
    let payload = extract_single_op_return_push(script)?;
    if payload.len() != 37 || payload[..4] != M3_TAG {
        return None;
    }
    let mut display = [0u8; 32];
    display.copy_from_slice(&payload[5..]);
    display.reverse();
    Some((payload[4], Hash32(display)))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum M4Message {
    RepeatPrevious,
    OneByte(Vec<u8>),
    TwoBytes(Vec<u16>),
    LeadingBy50,
}

fn parse_m4(script: &[u8]) -> Option<M4Message> {
    let payload = extract_single_op_return_push(script)?;
    if payload.len() < 5 || payload[..4] != M4_TAG {
        return None;
    }
    let body = &payload[5..];
    match payload[4] {
        0 if body.is_empty() => Some(M4Message::RepeatPrevious),
        1 => Some(M4Message::OneByte(body.to_vec())),
        2 if body.len() % 2 == 0 => Some(M4Message::TwoBytes(
            body.chunks_exact(2)
                .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                .collect(),
        )),
        3 if body.is_empty() => Some(M4Message::LeadingBy50),
        _ => None,
    }
}

fn parse_m7(script: &[u8]) -> Option<(u8, BlockHash)> {
    let payload = extract_single_op_return_push(script)?;
    if payload.len() != 37 || payload[..4] != M7_TAG {
        return None;
    }
    let mut hash = [0; 32];
    hash.copy_from_slice(&payload[5..]);
    Some((payload[4], BlockHash::from_internal_bytes(hash)))
}

fn parse_m8(transaction: &ParsedTransaction<'_>) -> Option<(u8, BlockHash, BlockHash)> {
    let script = transaction.outputs.first()?.script;
    if script.len() != M8_SCRIPT_LEN
        || script[0] != OP_RETURN
        || usize::from(script[1]) != M8_PAYLOAD_LEN
        || script[2..5] != M8_TAG
    {
        return None;
    }
    let mut child = [0; 32];
    child.copy_from_slice(&script[6..38]);
    let mut previous = [0; 32];
    previous.copy_from_slice(&script[38..70]);
    Some((
        script[5],
        BlockHash::from_internal_bytes(child),
        BlockHash::from_internal_bytes(previous),
    ))
}

fn apply_upvote(
    active: &mut ActiveSlot,
    index: usize,
) -> Result<Option<MultiSlotEffectiveM4Action>, MultiSlotReplayError> {
    let target = active
        .pending_m6ids
        .get(index)
        .copied()
        .ok_or(MultiSlotReplayError::M4UpvoteMissingBundle)?;
    if target.score == u16::MAX {
        return Ok(None);
    }
    for (candidate_index, pending) in active.pending_m6ids.iter_mut().enumerate() {
        if candidate_index == index {
            pending.score = pending
                .score
                .checked_add(1)
                .ok_or(MultiSlotReplayError::VoteOverflow)?;
        } else {
            pending.score = pending.score.saturating_sub(1);
        }
    }
    Ok(Some(MultiSlotEffectiveM4Action::Upvote {
        m6id: target.m6id,
    }))
}

fn apply_alarm(active: &mut ActiveSlot) -> Option<MultiSlotEffectiveM4Action> {
    let mut changed = false;
    for pending in &mut active.pending_m6ids {
        changed |= pending.score != 0;
        pending.score = pending.score.saturating_sub(1);
    }
    changed.then_some(MultiSlotEffectiveM4Action::Alarm)
}

fn apply_vote(
    active: &mut ActiveSlot,
    vote: u16,
) -> Result<Option<MultiSlotEffectiveM4Action>, MultiSlotReplayError> {
    match vote {
        0xffff => Ok(None),
        0xfffe => Ok(apply_alarm(active)),
        index => apply_upvote(active, usize::from(index)),
    }
}

fn apply_m4(
    state: &mut MultiSlotReplayState,
    message: &M4Message,
) -> Result<BTreeMap<u8, MultiSlotEffectiveM4Action>, MultiSlotReplayError> {
    let slots = state.active_slots.keys().copied().collect::<Vec<_>>();
    let mut effective = BTreeMap::new();
    match message {
        M4Message::OneByte(votes) => {
            if votes.len() != slots.len() {
                return Err(MultiSlotReplayError::M4InvalidVoteCount);
            }
            for (slot, vote) in slots.into_iter().zip(votes.iter().copied()) {
                let vote = match vote {
                    0xff => 0xffff,
                    0xfe => 0xfffe,
                    value => u16::from(value),
                };
                if let Some(action) = apply_vote(
                    state
                        .active_slots
                        .get_mut(&slot)
                        .expect("slot list came from active map"),
                    vote,
                )? {
                    effective.insert(slot, action);
                }
            }
        }
        M4Message::TwoBytes(votes) => {
            if votes.iter().all(|vote| *vote <= 253) {
                return Err(MultiSlotReplayError::M4TwoBytesWithinByteRange);
            }
            if votes.len() != slots.len() {
                return Err(MultiSlotReplayError::M4InvalidVoteCount);
            }
            for (slot, vote) in slots.into_iter().zip(votes.iter().copied()) {
                if let Some(action) = apply_vote(
                    state
                        .active_slots
                        .get_mut(&slot)
                        .expect("slot list came from active map"),
                    vote,
                )? {
                    effective.insert(slot, action);
                }
            }
        }
        M4Message::LeadingBy50 => {
            for slot in slots {
                let active = state
                    .active_slots
                    .get_mut(&slot)
                    .expect("slot list came from active map");
                let mut leader = None;
                let mut highest = 0u16;
                let mut second = 0u16;
                for (index, pending) in active.pending_m6ids.iter().enumerate() {
                    if pending.score > highest {
                        second = highest;
                        highest = pending.score;
                        leader = Some(index);
                    } else if pending.score > second {
                        second = pending.score;
                    }
                }
                if highest.saturating_sub(second) >= 50 && highest < u16::MAX {
                    if let Some(action) =
                        apply_upvote(active, leader.expect("positive leading score has a bundle"))?
                    {
                        effective.insert(slot, action);
                    }
                }
            }
        }
        M4Message::RepeatPrevious => {
            let previous = state.previous_effective_m4.clone();
            for (slot, prior_action) in previous {
                let active = state
                    .active_slots
                    .get_mut(&slot)
                    .ok_or(MultiSlotReplayError::MalformedState)?;
                let action = match prior_action {
                    MultiSlotEffectiveM4Action::Alarm => apply_alarm(active),
                    MultiSlotEffectiveM4Action::Upvote { m6id } => {
                        let index = active
                            .pending_m6ids
                            .iter()
                            .position(|pending| pending.m6id == m6id)
                            .ok_or(MultiSlotReplayError::M4RepeatMissingBundle)?;
                        apply_upvote(active, index)?
                    }
                };
                if let Some(action) = action {
                    effective.insert(slot, action);
                }
            }
        }
    }
    Ok(effective)
}

fn activate_slot(
    state: &mut MultiSlotReplayState,
    slot: u8,
    proposal_hash: [u8; 32],
    height: u32,
) -> MultiSlotActivation {
    let replaced_existing = state.active_slots.contains_key(&slot);
    state
        .active_slots
        .entry(slot)
        .and_modify(|active| {
            active.proposal_hash = proposal_hash;
            active.activation_height = height;
        })
        .or_insert(ActiveSlot {
            proposal_hash,
            activation_height: height,
            ctip: None,
            next_treasury_sequence: 0,
            pending_m6ids: Vec::new(),
        });

    if slot == ELEMENTS_DRIVECHAIN_SLOT {
        state.slot24_usdd_continuity = match (
            state.slot24_usdd_continuity,
            replaced_existing,
            proposal_hash == ELEMENTS_V1_REQUIRED_PROPOSAL_HASH_INTERNAL,
        ) {
            (Slot24UsddContinuity::Unactivated, false, true) => Slot24UsddContinuity::Active,
            (Slot24UsddContinuity::Active, true, true) => Slot24UsddContinuity::Active,
            _ => Slot24UsddContinuity::Invalidated,
        };
    }
    MultiSlotActivation {
        slot,
        proposal_hash,
        block_height: height,
        replaced_existing,
        usdd_continuity: state.slot24_usdd_continuity,
    }
}

type CoinbaseTransitionEffects = (
    Vec<MultiSlotActivation>,
    Vec<MultiSlotEffectiveM4>,
    Vec<(u8, Hash32)>,
    BTreeMap<u8, (BlockHash, u32)>,
);

fn apply_coinbase_messages(
    state: &mut MultiSlotReplayState,
    parsed: &ParsedBlock<'_>,
    height: u32,
) -> Result<CoinbaseTransitionEffects, MultiSlotReplayError> {
    // `CoinbaseMessages::push` validates all these uniqueness rules before the
    // enforcer applies any message. The candidate state is discarded on every
    // error, preserving the same atomic block boundary.
    let mut m1s = BTreeSet::new();
    let mut m2_slots = BTreeSet::new();
    let mut saw_m4 = false;
    let mut m7_slots = BTreeSet::new();
    let mut activations = Vec::new();
    let mut current_effective_m4 = BTreeMap::new();
    let mut bmm = BTreeMap::new();

    for (vout, output) in parsed.coinbase.outputs.iter().enumerate() {
        match parse_parent_message(output.script) {
            Some(ParentMessage::M1 {
                slot,
                proposal_hash,
            }) => {
                if !m1s.insert((slot, proposal_hash)) {
                    return Err(MultiSlotReplayError::DuplicateM1);
                }
                let id = (slot, proposal_hash);
                if !state.proposals.contains_key(&id) {
                    if state.proposals.len() == MAX_PENDING_SLOT24_PROPOSALS {
                        return Err(MultiSlotReplayError::PendingProposalLimitExceeded);
                    }
                    state.proposals.insert(
                        id,
                        MultiSlotProposal {
                            slot,
                            proposal_hash,
                            proposal_height: height,
                            votes: 0,
                        },
                    );
                }
            }
            Some(ParentMessage::M2 {
                slot,
                proposal_hash,
            }) => {
                if !m2_slots.insert(slot) {
                    return Err(MultiSlotReplayError::DuplicateM2);
                }
                let id = (slot, proposal_hash);
                let Some(mut proposal) = state.proposals.get(&id).copied() else {
                    continue;
                };
                if proposal.proposal_height == height {
                    continue;
                }
                proposal.votes = proposal
                    .votes
                    .checked_add(1)
                    .ok_or(MultiSlotReplayError::VoteOverflow)?;
                let age = height.saturating_sub(proposal.proposal_height);
                if proposal.votes > PROPOSAL_ACTIVATION_THRESHOLD && age <= PROPOSAL_MAX_AGE {
                    state.proposals.remove(&id);
                    activations.push(activate_slot(state, slot, proposal_hash, height));
                } else {
                    state.proposals.insert(id, proposal);
                }
            }
            None => {}
        }

        if let Some((slot, m6id)) = parse_m3(output.script) {
            let total_pending = state
                .active_slots
                .values()
                .map(|active| active.pending_m6ids.len())
                .try_fold(0usize, |sum, count| sum.checked_add(count))
                .ok_or(MultiSlotReplayError::PendingM6idLimitExceeded)?;
            let active = state
                .active_slots
                .get_mut(&slot)
                .ok_or(MultiSlotReplayError::M3ForInactiveSlot)?;
            if active
                .pending_m6ids
                .iter()
                .any(|pending| pending.m6id == m6id)
            {
                return Err(MultiSlotReplayError::M3BundleAlreadyPending);
            }
            if total_pending == MAX_PENDING_SLOT24_M6IDS {
                return Err(MultiSlotReplayError::PendingM6idLimitExceeded);
            }
            active.pending_m6ids.push(MultiSlotPendingM6id {
                m6id,
                proposal_height: height,
                score: 1,
            });
        }

        if let Some(message) = parse_m4(output.script) {
            if saw_m4 {
                return Err(MultiSlotReplayError::DuplicateM4);
            }
            saw_m4 = true;
            current_effective_m4 = apply_m4(state, &message)?;
        }

        if let Some((slot, child_hash)) = parse_m7(output.script) {
            if !m7_slots.insert(slot) {
                return Err(MultiSlotReplayError::DuplicateM7);
            }
            let vout =
                u32::try_from(vout).map_err(|_| MultiSlotReplayError::OutputIndexOverflow)?;
            bmm.insert(slot, (child_hash, vout));
        }
    }

    // The enforcer inserts an implicit all-abstain M4 if none was encoded.
    // Both implicit abstain and an explicit abstain-only message store no diff,
    // so RepeatPrevious in the next block sees an empty action map.
    state.previous_effective_m4 = current_effective_m4.clone();

    let mut failed_proposals = Vec::new();
    for (id, proposal) in &state.proposals {
        let age = height
            .checked_sub(proposal.proposal_height)
            .ok_or(MultiSlotReplayError::ProposalHeightAhead)?;
        if u32::from(proposal.votes) > age {
            return Err(MultiSlotReplayError::ProposalVotesAhead);
        }
        let max_fails = PROPOSAL_MAX_AGE - u32::from(PROPOSAL_ACTIVATION_THRESHOLD);
        let failures = age - u32::from(proposal.votes);
        if age > PROPOSAL_MAX_AGE || (age > max_fails && failures >= max_fails) {
            failed_proposals.push(*id);
        }
    }
    for id in failed_proposals {
        state.proposals.remove(&id);
    }

    let mut expired_m6ids = Vec::new();
    for (slot, active) in &mut state.active_slots {
        active.pending_m6ids.retain(|pending| {
            let live = height.saturating_sub(pending.proposal_height) <= WITHDRAWAL_MAX_AGE;
            if !live {
                expired_m6ids.push((*slot, pending.m6id));
            }
            live
        });
    }

    Ok((
        activations,
        current_effective_m4
            .into_iter()
            .map(|(slot, action)| MultiSlotEffectiveM4 { slot, action })
            .collect(),
        expired_m6ids,
        bmm,
    ))
}

fn treasury_slot(script: &[u8]) -> Option<u8> {
    (script.len() == 4 && script[0] == OP_DRIVECHAIN && script[1] == 1 && script[3] == OP_TRUE)
        .then(|| script[2])
}

fn output_value(output: &ParsedOutput<'_>) -> u64 {
    i64::from_le_bytes(output.value) as u64
}

fn input_spends(input: &[u8; 36], ctip: MultiSlotCtip) -> bool {
    input[..32] == ctip.txid.to_internal_bytes() && input[32..] == ctip.vout.to_le_bytes()
}

fn generic_m6id(
    transaction: &ParsedTransaction<'_>,
    old_value: u64,
    new_value: u64,
) -> Result<(Hash32, u64, Vec<u8>), MultiSlotReplayError> {
    let payout_total = transaction
        .outputs
        .iter()
        .skip(1)
        .try_fold(0u64, |sum, output| {
            sum.checked_add(output_value(output))
                .ok_or(MultiSlotReplayError::M6AmountOverflow)
        })?;
    let total_outputs = new_value
        .checked_add(payout_total)
        .ok_or(MultiSlotReplayError::M6AmountOverflow)?;
    let fee = old_value
        .checked_sub(total_outputs)
        .ok_or(MultiSlotReplayError::M6AmountOverflow)?;

    // Reproduce `compute_m6id`: remove the sole input, replace vout 0 with the
    // big-endian fee OP_RETURN, preserve every payout, version, and locktime,
    // then hash the legacy/non-witness serialization.
    let mut blinded = Vec::new();
    blinded.extend_from_slice(&transaction.version);
    blinded.push(0); // zero inputs, Bitcoin Core legacy serialization
    encode_compact_size(transaction.outputs.len(), &mut blinded)?;
    blinded.extend_from_slice(&0u64.to_le_bytes());
    blinded.extend_from_slice(&[10, OP_RETURN, 8]);
    blinded.extend_from_slice(&fee.to_be_bytes());
    for output in transaction.outputs.iter().skip(1) {
        blinded.extend_from_slice(&output.value);
        encode_compact_size(output.script.len(), &mut blinded)?;
        blinded.extend_from_slice(output.script);
    }
    blinded.extend_from_slice(&transaction.lock_time);
    let txid = BlockHash::from_internal_bytes(double_sha256(&blinded));
    Ok((Hash32(txid.to_display_bytes()), fee, blinded))
}

fn pending_index(active: &ActiveSlot, m6id: Hash32) -> Option<usize> {
    active
        .pending_m6ids
        .iter()
        .position(|pending| pending.m6id == m6id)
}

fn approve_generic_m6(
    state: &mut MultiSlotReplayState,
    slot: u8,
    transaction: &ParsedTransaction<'_>,
    old_ctip: MultiSlotCtip,
    new_value: u64,
    block_hash: BlockHash,
    block_height: u32,
) -> Result<ApprovedMultiSlotM6, MultiSlotReplayError> {
    let (m6id, _, _) = generic_m6id(transaction, old_ctip.value_sat, new_value)?;
    let active = state
        .active_slots
        .get_mut(&slot)
        .ok_or(MultiSlotReplayError::MalformedState)?;
    let index = pending_index(active, m6id).ok_or(MultiSlotReplayError::M6MissingPendingBundle)?;
    if active.pending_m6ids[index].score <= SLOT24_M6_INCLUSION_THRESHOLD {
        return Err(MultiSlotReplayError::M6InsufficientScore);
    }
    active.pending_m6ids.remove(index);
    let sequence = active.next_treasury_sequence;
    active.next_treasury_sequence = active
        .next_treasury_sequence
        .checked_add(1)
        .ok_or(MultiSlotReplayError::AmountOverflow)?;
    let successor_ctip = MultiSlotCtip {
        txid: transaction.txid,
        vout: 0,
        value_sat: new_value,
        sequence,
    };
    active.ctip = Some(successor_ctip);
    if slot == ELEMENTS_DRIVECHAIN_SLOT {
        state.successful_slot24_m6ids.insert(m6id);
        state.slot24_usdd_continuity = Slot24UsddContinuity::Invalidated;
    }
    Ok(ApprovedMultiSlotM6 {
        slot,
        m6id,
        transaction_id: transaction.txid,
        block_hash,
        block_height,
        sequence,
        successor_ctip,
        usdd_special: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn approve_slot24_accumulator_m6(
    state: &mut MultiSlotReplayState,
    transaction: &ParsedTransaction<'_>,
    artifact: &MinerBundleArtifact,
    old_ctip: MultiSlotCtip,
    new_value: u64,
    block_hash: BlockHash,
    block_height: u32,
) -> Result<(ApprovedMultiSlotM6, ApprovedSlot24AccumulatorM6), MultiSlotReplayError> {
    if state.slot24_usdd_continuity != Slot24UsddContinuity::Active {
        return Err(MultiSlotReplayError::CanonicalM6ContinuityLost);
    }
    let identity = state
        .accumulator_identity
        .ok_or(MultiSlotReplayError::InvalidAccumulatorIdentity)?;
    let prior_root = state
        .approved_root
        .ok_or(MultiSlotReplayError::InvalidAccumulatorIdentity)?;
    artifact
        .validate()
        .map_err(|_| MultiSlotReplayError::InvalidCanonicalM6Artifact)?;
    if artifact.bitcoin_genesis != identity.bitcoin_genesis
        || artifact.elements_genesis != identity.elements_genesis
        || artifact.usdd_asset != identity.usdd_asset
        || artifact.vault_id != identity.vault_id
    {
        return Err(MultiSlotReplayError::CanonicalM6IdentityMismatch);
    }
    if artifact.prior_claim_count != prior_root.claim_count
        || artifact.prior_claim_root != prior_root.claim_root
    {
        return Err(MultiSlotReplayError::CanonicalM6RootMismatch);
    }
    let next_root = Slot24ApprovedRoot {
        claim_count: artifact.next_claim_count,
        claim_root: artifact.next_claim_root,
    };
    let required_delta = artifact
        .fee_sats
        .checked_add(M6_ROOT_PAYOUT_SATS)
        .ok_or(MultiSlotReplayError::InvalidCanonicalM6Artifact)?;
    if old_ctip.value_sat.checked_sub(new_value) != Some(required_delta) {
        return Err(MultiSlotReplayError::CanonicalM6TransactionMismatch);
    }
    let actual = ActualM6Artifact::build(
        artifact.clone(),
        Ctip {
            outpoint: OutPoint {
                txid: Hash32(old_ctip.txid.to_display_bytes()),
                vout: old_ctip.vout,
            },
            value_sats: old_ctip.value_sat,
        },
    )
    .map_err(|_| MultiSlotReplayError::InvalidCanonicalM6Artifact)?;
    actual
        .verify_transaction(transaction.serialized)
        .map_err(|_| MultiSlotReplayError::CanonicalM6TransactionMismatch)?;
    let transaction_id = actual
        .transaction_id()
        .map_err(|_| MultiSlotReplayError::CanonicalM6TransactionMismatch)?;
    if transaction_id != Hash32(transaction.txid.to_display_bytes())
        || actual.successor_ctip_value() != new_value
    {
        return Err(MultiSlotReplayError::CanonicalM6TransactionMismatch);
    }
    let m6id = artifact
        .m6id()
        .map_err(|_| MultiSlotReplayError::InvalidCanonicalM6Artifact)?;
    let active = state
        .active_slots
        .get_mut(&ELEMENTS_DRIVECHAIN_SLOT)
        .ok_or(MultiSlotReplayError::CanonicalM6ContinuityLost)?;
    let index = pending_index(active, m6id).ok_or(MultiSlotReplayError::M6MissingPendingBundle)?;
    if active.pending_m6ids[index].score <= SLOT24_M6_INCLUSION_THRESHOLD {
        return Err(MultiSlotReplayError::M6InsufficientScore);
    }
    active.pending_m6ids.remove(index);
    let sequence = active.next_treasury_sequence;
    active.next_treasury_sequence = active
        .next_treasury_sequence
        .checked_add(1)
        .ok_or(MultiSlotReplayError::AmountOverflow)?;
    let successor_ctip = MultiSlotCtip {
        txid: transaction.txid,
        vout: 0,
        value_sat: new_value,
        sequence,
    };
    active.ctip = Some(successor_ctip);
    state.successful_slot24_m6ids.insert(m6id);
    state.approved_root = Some(next_root);
    Ok((
        ApprovedMultiSlotM6 {
            slot: ELEMENTS_DRIVECHAIN_SLOT,
            m6id,
            transaction_id: transaction.txid,
            block_hash,
            block_height,
            sequence,
            successor_ctip,
            usdd_special: true,
        },
        ApprovedSlot24AccumulatorM6 {
            m6id,
            transaction_id: transaction.txid,
            block_hash,
            block_height,
            fee_sats: artifact.fee_sats,
            prior_root,
            next_root,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
fn approve_slot24_native_withdrawal_m6(
    state: &mut MultiSlotReplayState,
    transaction: &ParsedTransaction<'_>,
    native: &NativeWithdrawalM6,
    old_ctip: MultiSlotCtip,
    new_value: u64,
    block_hash: BlockHash,
    block_height: u32,
) -> Result<(ApprovedMultiSlotM6, ApprovedSlot24NativeWithdrawalM6), MultiSlotReplayError> {
    if state.slot24_usdd_continuity != Slot24UsddContinuity::Active {
        return Err(MultiSlotReplayError::CanonicalM6ContinuityLost);
    }
    let identity = state
        .accumulator_identity
        .ok_or(MultiSlotReplayError::InvalidAccumulatorIdentity)?;
    let preserved_usdd_root = state
        .approved_root
        .ok_or(MultiSlotReplayError::InvalidAccumulatorIdentity)?;
    let reference = native.reference();
    if reference.sidechain_slot() != ELEMENTS_DRIVECHAIN_SLOT
        || reference.elements_genesis() != identity.elements_genesis
    {
        return Err(MultiSlotReplayError::NativeWithdrawalIdentityMismatch);
    }

    let prior_ctip = Ctip {
        outpoint: OutPoint {
            txid: Hash32(old_ctip.txid.to_display_bytes()),
            vout: old_ctip.vout,
        },
        value_sats: old_ctip.value_sat,
    };
    native
        .verify_actual_transaction(transaction.serialized, &prior_ctip)
        .map_err(|_| MultiSlotReplayError::NativeWithdrawalTransactionMismatch)?;
    let native_successor = native
        .successor_ctip(&prior_ctip)
        .map_err(|_| MultiSlotReplayError::NativeWithdrawalTransactionMismatch)?;
    if native_successor.value_sats != new_value
        || native_successor.outpoint.txid != Hash32(transaction.txid.to_display_bytes())
        || native_successor.outpoint.vout != 0
    {
        return Err(MultiSlotReplayError::NativeWithdrawalTransactionMismatch);
    }

    let m6id = native.m6id();
    let active = state
        .active_slots
        .get_mut(&ELEMENTS_DRIVECHAIN_SLOT)
        .ok_or(MultiSlotReplayError::CanonicalM6ContinuityLost)?;
    let index = pending_index(active, m6id).ok_or(MultiSlotReplayError::M6MissingPendingBundle)?;
    if active.pending_m6ids[index].score <= SLOT24_M6_INCLUSION_THRESHOLD {
        return Err(MultiSlotReplayError::M6InsufficientScore);
    }
    active.pending_m6ids.remove(index);
    let sequence = active.next_treasury_sequence;
    active.next_treasury_sequence = active
        .next_treasury_sequence
        .checked_add(1)
        .ok_or(MultiSlotReplayError::AmountOverflow)?;
    let successor_ctip = MultiSlotCtip {
        txid: transaction.txid,
        vout: 0,
        value_sat: new_value,
        sequence,
    };
    active.ctip = Some(successor_ctip);
    state.successful_slot24_m6ids.insert(m6id);
    debug_assert_eq!(state.approved_root, Some(preserved_usdd_root));

    Ok((
        ApprovedMultiSlotM6 {
            slot: ELEMENTS_DRIVECHAIN_SLOT,
            m6id,
            transaction_id: transaction.txid,
            block_hash,
            block_height,
            sequence,
            successor_ctip,
            usdd_special: false,
        },
        ApprovedSlot24NativeWithdrawalM6 {
            m6id,
            transaction_id: transaction.txid,
            block_hash,
            block_height,
            elements_genesis: reference.elements_genesis(),
            burn_outpoint: reference.burn_outpoint(),
            parent_fee_sats: native.parent_fee_sats(),
            payout_sats: native.payout_sats(),
            destination_script: native.destination_script().to_vec(),
            preserved_usdd_root,
        },
    ))
}

#[derive(Clone, Copy)]
struct NewCtip {
    vout: usize,
    value_sat: u64,
}

type TransactionTransitionEffects = (
    Vec<MultiSlotDeposit>,
    Vec<ApprovedMultiSlotM6>,
    Option<ApprovedSlot24AccumulatorM6>,
    Option<ApprovedSlot24NativeWithdrawalM6>,
    u32,
);

fn apply_transactions(
    state: &mut MultiSlotReplayState,
    parsed: &ParsedBlock<'_>,
    height: u32,
    bmm: &BTreeMap<u8, (BlockHash, u32)>,
    canonical_m6_artifact: Option<&MinerBundleArtifact>,
) -> Result<TransactionTransitionEffects, MultiSlotReplayError> {
    let mut deposits = Vec::new();
    let mut successful_m6s = Vec::new();
    let mut approved_slot24 = None;
    let mut approved_slot24_native = None;
    let mut matching_m8_requests = 0u32;
    let mut artifact_consumed = false;
    let mut slot24_m6_seen = false;

    for transaction in parsed.transactions.iter().skip(1) {
        if let Some((slot, child_hash, previous_hash)) = parse_m8(transaction) {
            let (accepted, _) = bmm
                .get(&slot)
                .ok_or(MultiSlotReplayError::M8WithoutMatchingM7)?;
            if *accepted != child_hash {
                return Err(MultiSlotReplayError::M8WrongChildHash);
            }
            if previous_hash != parsed.metadata.header.previous_block {
                return Err(MultiSlotReplayError::M8Expired);
            }
            matching_m8_requests = matching_m8_requests
                .checked_add(1)
                .ok_or(MultiSlotReplayError::M8CountOverflow)?;
        }

        let mut spent_ctips = BTreeMap::new();
        for (slot, active) in &state.active_slots {
            let Some(ctip) = active.ctip else {
                continue;
            };
            if transaction
                .inputs
                .iter()
                .any(|input| input_spends(input, ctip))
            {
                spent_ctips.insert(*slot, ctip);
            }
        }

        let mut new_ctips = BTreeMap::new();
        for (vout, output) in transaction.outputs.iter().enumerate() {
            let Some(slot) = treasury_slot(output.script) else {
                continue;
            };
            if !state.active_slots.contains_key(&slot) {
                // Exact inactive-slot enforcer behavior: OP_DRIVECHAIN is an
                // ordinary anyone-can-spend output until the slot activates.
                continue;
            }
            if new_ctips
                .insert(
                    slot,
                    NewCtip {
                        vout,
                        value_sat: output_value(output),
                    },
                )
                .is_some()
            {
                return Err(MultiSlotReplayError::MultipleTreasuryOutputs);
            }
        }

        if spent_ctips.keys().any(|slot| !new_ctips.contains_key(slot)) {
            return Err(MultiSlotReplayError::TreasurySpentWithoutReplacement);
        }
        if new_ctips.is_empty() {
            continue;
        }

        let mut increases = Vec::new();
        let mut decreases = Vec::new();
        for (slot, new_ctip) in &new_ctips {
            let active = state
                .active_slots
                .get(slot)
                .expect("new CTIP was filtered by active slots");
            let old_value = match active.ctip {
                Some(old_ctip) => {
                    if !spent_ctips.contains_key(slot) {
                        return Err(MultiSlotReplayError::OldCtipUnspent);
                    }
                    old_ctip.value_sat
                }
                None => 0,
            };
            if new_ctip.value_sat == old_value {
                return Err(MultiSlotReplayError::ZeroCtipDelta);
            }
            if new_ctip.value_sat > old_value {
                increases.push((*slot, *new_ctip, old_value));
            } else {
                decreases.push((*slot, *new_ctip, old_value));
            }
        }
        if decreases.len() > 1 || (!decreases.is_empty() && !increases.is_empty()) {
            return Err(MultiSlotReplayError::AmbiguousM5M6);
        }

        if let Some((slot, new_ctip, _old_value)) = decreases.first().copied() {
            if transaction.inputs.len() != 1 {
                return Err(MultiSlotReplayError::M6InputCount);
            }
            if new_ctip.vout != 0 {
                return Err(MultiSlotReplayError::M6TreasuryOutputIndex);
            }
            let old_ctip = spent_ctips
                .get(&slot)
                .copied()
                .ok_or(MultiSlotReplayError::MalformedState)?;
            if slot == ELEMENTS_DRIVECHAIN_SLOT {
                if slot24_m6_seen {
                    return Err(MultiSlotReplayError::MultipleSlot24M6s);
                }
                slot24_m6_seen = true;
                let (derived_m6id, _, blinded_legacy) =
                    generic_m6id(transaction, old_ctip.value_sat, new_ctip.value_sat)?;
                let native = NativeWithdrawalM6::decode_legacy(&blinded_legacy).ok();
                let canonical_shape = BlindedM6::decode(&blinded_legacy).is_ok();
                let canonical_artifact_m6id = canonical_m6_artifact
                    .map(|artifact| {
                        artifact
                            .m6id()
                            .map_err(|_| MultiSlotReplayError::InvalidCanonicalM6Artifact)
                    })
                    .transpose()?;
                let artifact_matches = canonical_artifact_m6id == Some(derived_m6id);

                // Once any unrecognized-but-enforcer-valid slot-24 M6 has
                // destroyed USDD continuity, all later slot-24 M6s remain
                // replayable solely as generic enforcer transitions. Exact
                // native or canonical-looking bytes cannot resurrect the
                // trusted lane or advance its last known accumulator root.
                if state.slot24_usdd_continuity != Slot24UsddContinuity::Active {
                    if canonical_m6_artifact.is_some() {
                        if !artifact_matches {
                            return Err(MultiSlotReplayError::UnexpectedCanonicalM6Artifact);
                        }
                        artifact_consumed = true;
                    }
                    successful_m6s.push(approve_generic_m6(
                        state,
                        slot,
                        transaction,
                        old_ctip,
                        new_ctip.value_sat,
                        parsed.metadata.block_hash,
                        height,
                    )?);
                    continue;
                }
                if native.is_some() && artifact_matches {
                    return Err(MultiSlotReplayError::AmbiguousSlot24M6);
                }

                if artifact_matches || (canonical_shape && canonical_m6_artifact.is_some()) {
                    let artifact = canonical_m6_artifact
                        .expect("matching artifact id requires a supplied artifact");
                    let (approved, accumulator_approval) = approve_slot24_accumulator_m6(
                        state,
                        transaction,
                        artifact,
                        old_ctip,
                        new_ctip.value_sat,
                        parsed.metadata.block_hash,
                        height,
                    )?;
                    artifact_consumed = true;
                    successful_m6s.push(approved);
                    approved_slot24 = Some(accumulator_approval);
                } else if let Some(native) = native.as_ref() {
                    let (approved, native_approval) = approve_slot24_native_withdrawal_m6(
                        state,
                        transaction,
                        native,
                        old_ctip,
                        new_ctip.value_sat,
                        parsed.metadata.block_hash,
                        height,
                    )?;
                    successful_m6s.push(approved);
                    approved_slot24_native = Some(native_approval);
                } else {
                    // Exact enforcer parity: every other approved slot-24 M6
                    // still rotates CTIP and consumes its M6id, but it
                    // irreversibly invalidates USDD continuity. Marker-only
                    // ELWD lookalikes therefore never preserve the root lane.
                    successful_m6s.push(approve_generic_m6(
                        state,
                        slot,
                        transaction,
                        old_ctip,
                        new_ctip.value_sat,
                        parsed.metadata.block_hash,
                        height,
                    )?);
                }
            } else {
                successful_m6s.push(approve_generic_m6(
                    state,
                    slot,
                    transaction,
                    old_ctip,
                    new_ctip.value_sat,
                    parsed.metadata.block_hash,
                    height,
                )?);
            }
            continue;
        }

        // Validate all M5 address outputs before mutating any per-slot CTIP.
        let mut validated = Vec::new();
        for (slot, new_ctip, old_value) in increases {
            let address = transaction
                .outputs
                .get(new_ctip.vout + 1)
                .and_then(|output| extract_single_op_return_push(output.script))
                .ok_or(MultiSlotReplayError::MissingDepositAddress)?;
            let value_sat = new_ctip
                .value_sat
                .checked_sub(old_value)
                .ok_or(MultiSlotReplayError::AmountOverflow)?;
            validated.push((slot, new_ctip, value_sat, address.to_vec()));
        }
        for (slot, new_ctip, value_sat, address) in validated {
            let usdd_mintable = slot == ELEMENTS_DRIVECHAIN_SLOT
                && state.slot24_usdd_continuity == Slot24UsddContinuity::Active;
            let active = state
                .active_slots
                .get_mut(&slot)
                .expect("M5 slot remains active");
            let sequence = active.next_treasury_sequence;
            active.next_treasury_sequence = active
                .next_treasury_sequence
                .checked_add(1)
                .ok_or(MultiSlotReplayError::AmountOverflow)?;
            let vout = u32::try_from(new_ctip.vout)
                .map_err(|_| MultiSlotReplayError::OutputIndexOverflow)?;
            let ctip = MultiSlotCtip {
                txid: transaction.txid,
                vout,
                value_sat: new_ctip.value_sat,
                sequence,
            };
            active.ctip = Some(ctip);
            deposits.push(MultiSlotDeposit {
                slot,
                outpoint: ctip,
                block_hash: parsed.metadata.block_hash,
                block_height: height,
                value_sat,
                address,
                usdd_mintable,
            });
        }
    }
    if canonical_m6_artifact.is_some() && !artifact_consumed {
        return Err(if approved_slot24_native.is_some() {
            MultiSlotReplayError::AmbiguousSlot24M6
        } else {
            MultiSlotReplayError::UnexpectedCanonicalM6Artifact
        });
    }
    Ok((
        deposits,
        successful_m6s,
        approved_slot24,
        approved_slot24_native,
        matching_m8_requests,
    ))
}

pub(super) fn apply_multislot_parent_block_owned(
    mut state: MultiSlotReplayState,
    serialized_block: &[u8],
    canonical_m6_artifact: Option<&MinerBundleArtifact>,
) -> Result<(MultiSlotReplayState, MultiSlotBlockEffects), MultiSlotReplayError> {
    state.validate()?;
    let parsed = parse_and_verify_block(serialized_block)?;
    if state.next_height == 0 {
        if parsed.metadata.header.previous_block != BlockHash::ZERO {
            return Err(MultiSlotReplayError::BrokenParentLink);
        }
    } else if parsed.metadata.header.previous_block != state.tip_hash {
        return Err(MultiSlotReplayError::BrokenParentLink);
    }
    let height = state.next_height;
    let (activations, effective_m4, expired_m6ids, bmm) =
        apply_coinbase_messages(&mut state, &parsed, height)?;
    let (
        deposits,
        successful_m6s,
        approved_slot24_accumulator_m6,
        approved_slot24_native_withdrawal_m6,
        matching_m8_requests,
    ) = apply_transactions(&mut state, &parsed, height, &bmm, canonical_m6_artifact)?;
    state.tip_hash = parsed.metadata.block_hash;
    state.next_height = height
        .checked_add(1)
        .ok_or(MultiSlotReplayError::HeightOverflow)?;
    state.validate()?;
    let bmm_commitments = bmm
        .into_iter()
        .map(
            |(slot, (child_hash, coinbase_vout))| MultiSlotBmmCommitment {
                slot,
                child_hash,
                coinbase_vout,
            },
        )
        .collect();
    Ok((
        state,
        MultiSlotBlockEffects {
            activations,
            deposits,
            successful_m6s,
            approved_slot24_accumulator_m6,
            approved_slot24_native_withdrawal_m6,
            effective_m4,
            expired_m6ids,
            bmm_commitments,
            matching_m8_requests,
        },
    ))
}

/// Test-only state adapter for differential execution against the pinned
/// `bip300301_enforcer` implementation.
///
/// The feature-gated adapter deliberately starts only before parent genesis,
/// applies exact serialized blocks through the same transition function used
/// by the production exact-genesis wrapper, and commits state only on success.
/// It does not expose a caller-selected checkpoint or mutable internal state.
#[cfg(feature = "enforcer-differential")]
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcerDifferentialReplay {
    state: MultiSlotReplayState,
}

/// One active-slot row in a deterministic differential snapshot.
#[cfg(feature = "enforcer-differential")]
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcerDifferentialActiveSlot {
    pub slot: u8,
    pub proposal_hash: [u8; 32],
    pub activation_height: u32,
    pub ctip: Option<MultiSlotCtip>,
    pub next_treasury_sequence: u64,
    pub pending_m6ids: Vec<MultiSlotPendingM6id>,
}

/// Canonically ordered replay state used for equality with an independent
/// enforcer snapshot after every generated block.
#[cfg(feature = "enforcer-differential")]
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcerDifferentialSnapshot {
    pub next_height: u32,
    pub tip_hash: BlockHash,
    pub proposals: Vec<MultiSlotProposal>,
    pub active_slots: Vec<EnforcerDifferentialActiveSlot>,
    pub previous_effective_m4: Vec<MultiSlotEffectiveM4>,
    pub slot24_usdd_continuity: Slot24UsddContinuity,
}

#[cfg(feature = "enforcer-differential")]
impl Default for EnforcerDifferentialReplay {
    fn default() -> Self {
        Self::before_parent_genesis()
    }
}

#[cfg(feature = "enforcer-differential")]
impl EnforcerDifferentialReplay {
    pub fn before_parent_genesis() -> Self {
        Self {
            state: MultiSlotReplayState::before_parent_genesis(),
        }
    }

    /// Attach the same explicit accumulator identity supplied by the external
    /// differential fixture. This chooses no production identity and exists
    /// only so ELWD classification can be compared against an independently
    /// configured enforcer using identical vector inputs.
    pub fn bind_manifest_bound_slot24_accumulator(
        &mut self,
        bitcoin_genesis: [u8; 32],
        elements_genesis: [u8; 32],
        usdd_asset: [u8; 32],
        vault_id: [u8; 32],
    ) -> Result<(), MultiSlotReplayError> {
        self.state
            .bind_empty_accumulator(Slot24AccumulatorIdentity {
                bitcoin_genesis: Hash32(bitcoin_genesis),
                elements_genesis: Hash32(elements_genesis),
                usdd_asset: Hash32(usdd_asset),
                vault_id: Hash32(vault_id),
            })
    }

    /// Apply one exact parent block. Because the candidate is cloned and only
    /// installed after success, every error preserves the complete snapshot.
    pub fn apply_parent_block(
        &mut self,
        serialized_block: &[u8],
    ) -> Result<MultiSlotBlockEffects, MultiSlotReplayError> {
        let (next, effects) =
            apply_multislot_parent_block_owned(self.state.clone(), serialized_block, None)?;
        self.state = next;
        Ok(effects)
    }

    pub fn snapshot(&self) -> EnforcerDifferentialSnapshot {
        let proposals = self.state.proposals.values().copied().collect();
        let active_slots = self
            .state
            .active_slots
            .iter()
            .map(|(slot, active)| EnforcerDifferentialActiveSlot {
                slot: *slot,
                proposal_hash: active.proposal_hash,
                activation_height: active.activation_height,
                ctip: active.ctip,
                next_treasury_sequence: active.next_treasury_sequence,
                pending_m6ids: active.pending_m6ids.clone(),
            })
            .collect();
        let previous_effective_m4 = self
            .state
            .previous_effective_m4
            .iter()
            .map(|(slot, action)| MultiSlotEffectiveM4 {
                slot: *slot,
                action: *action,
            })
            .collect();
        EnforcerDifferentialSnapshot {
            next_height: self.state.next_height,
            tip_hash: self.state.tip_hash,
            proposals,
            active_slots,
            previous_effective_m4,
            slot24_usdd_continuity: self.state.slot24_usdd_continuity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BITCOIN_MAX_COINBASE_OUTPUTS;

    fn push(payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() <= u8::MAX as usize);
        let mut script = vec![OP_RETURN];
        if payload.len() <= 75 {
            script.push(payload.len() as u8);
        } else {
            script.extend_from_slice(&[0x4c, payload.len() as u8]);
        }
        script.extend_from_slice(payload);
        script
    }

    fn m1(slot: u8, description: &[u8]) -> Vec<u8> {
        let mut payload = Vec::from(M1_TAG);
        payload.push(slot);
        payload.extend_from_slice(description);
        push(&payload)
    }

    fn m2(slot: u8, proposal_hash: [u8; 32]) -> Vec<u8> {
        let mut payload = Vec::from(M2_TAG);
        payload.push(slot);
        payload.extend_from_slice(&proposal_hash);
        push(&payload)
    }

    fn m3(slot: u8, m6id: Hash32) -> Vec<u8> {
        let mut payload = Vec::from(M3_TAG);
        payload.push(slot);
        let mut wire = m6id.0;
        wire.reverse();
        payload.extend_from_slice(&wire);
        push(&payload)
    }

    fn m4_one(votes: &[u8]) -> Vec<u8> {
        let mut payload = Vec::from(M4_TAG);
        payload.push(1);
        payload.extend_from_slice(votes);
        push(&payload)
    }

    fn m4_repeat() -> Vec<u8> {
        let mut payload = Vec::from(M4_TAG);
        payload.push(0);
        push(&payload)
    }

    fn m7(slot: u8, child: BlockHash) -> Vec<u8> {
        let mut payload = Vec::from(M7_TAG);
        payload.push(slot);
        payload.extend_from_slice(&child.to_internal_bytes());
        push(&payload)
    }

    fn m8(slot: u8, child: BlockHash, previous: BlockHash) -> Vec<u8> {
        let mut payload = Vec::from(M8_TAG);
        payload.push(slot);
        payload.extend_from_slice(&child.to_internal_bytes());
        payload.extend_from_slice(&previous.to_internal_bytes());
        push(&payload)
    }

    fn treasury(slot: u8) -> Vec<u8> {
        vec![OP_DRIVECHAIN, 1, slot, OP_TRUE]
    }

    fn transaction(inputs: &[(BlockHash, u32)], outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        assert!(!inputs.is_empty());
        assert!(inputs.len() < 253 && outputs.len() < 253);
        let mut tx = Vec::new();
        tx.extend_from_slice(&2i32.to_le_bytes());
        tx.push(inputs.len() as u8);
        for (txid, vout) in inputs {
            tx.extend_from_slice(&txid.to_internal_bytes());
            tx.extend_from_slice(&vout.to_le_bytes());
            tx.push(0);
            tx.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        tx.push(outputs.len() as u8);
        for (value, script) in outputs {
            tx.extend_from_slice(&value.to_le_bytes());
            tx.push(script.len() as u8);
            tx.extend_from_slice(script);
        }
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx
    }

    fn coinbase(outputs: &[Vec<u8>]) -> Vec<u8> {
        let outputs: Vec<(u64, Vec<u8>)> = if outputs.is_empty() {
            vec![(0, Vec::new())]
        } else {
            outputs.iter().cloned().map(|script| (0, script)).collect()
        };
        let mut tx = Vec::new();
        tx.extend_from_slice(&2i32.to_le_bytes());
        tx.push(1);
        tx.extend_from_slice(&[0; 32]);
        tx.extend_from_slice(&u32::MAX.to_le_bytes());
        tx.push(2);
        tx.extend_from_slice(&[1, 1]);
        tx.extend_from_slice(&u32::MAX.to_le_bytes());
        tx.push(outputs.len() as u8);
        for (value, script) in outputs {
            tx.extend_from_slice(&value.to_le_bytes());
            tx.push(script.len() as u8);
            tx.extend_from_slice(&script);
        }
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx
    }

    fn merkle_root(mut hashes: Vec<BlockHash>) -> BlockHash {
        while hashes.len() > 1 {
            if hashes.len() % 2 != 0 {
                hashes.push(*hashes.last().expect("nonempty Merkle level"));
            }
            let mut next = Vec::new();
            for pair in hashes.chunks_exact(2) {
                let mut bytes = [0; 64];
                bytes[..32].copy_from_slice(&pair[0].to_internal_bytes());
                bytes[32..].copy_from_slice(&pair[1].to_internal_bytes());
                next.push(BlockHash::from_internal_bytes(double_sha256(&bytes)));
            }
            hashes = next;
        }
        hashes[0]
    }

    fn block(previous: BlockHash, nonce: u32, transactions: &[Vec<u8>]) -> Vec<u8> {
        let root = merkle_root(
            transactions
                .iter()
                .map(|tx| BlockHash::from_internal_bytes(double_sha256(tx)))
                .collect(),
        );
        let mut header = [0u8; 80];
        header[..4].copy_from_slice(&1i32.to_le_bytes());
        header[4..36].copy_from_slice(&previous.to_internal_bytes());
        header[36..68].copy_from_slice(&root.to_internal_bytes());
        header[68..72].copy_from_slice(&(1_700_000_000 + nonce).to_le_bytes());
        header[72..76].copy_from_slice(&0x207f_ffffu32.to_le_bytes());
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        let mut bytes = Vec::from(header);
        bytes.push(transactions.len() as u8);
        for transaction in transactions {
            bytes.extend_from_slice(transaction);
        }
        bytes
    }

    fn apply(
        state: &mut MultiSlotReplayState,
        coinbase_outputs: &[Vec<u8>],
        ordinary: &[Vec<u8>],
        artifact: Option<&MinerBundleArtifact>,
    ) -> Result<MultiSlotBlockEffects, MultiSlotReplayError> {
        let mut transactions = vec![coinbase(coinbase_outputs)];
        transactions.extend_from_slice(ordinary);
        let raw = block(state.tip_hash(), state.next_height(), &transactions);
        let (next, effects) = apply_multislot_parent_block_owned(state.clone(), &raw, artifact)?;
        *state = next;
        Ok(effects)
    }

    fn activate(
        state: &mut MultiSlotReplayState,
        slot: u8,
        description: &[u8],
    ) -> Result<(), MultiSlotReplayError> {
        let proposal_hash = double_sha256(description);
        apply(
            state,
            &[m1(slot, description), m2(slot, proposal_hash)],
            &[],
            None,
        )?;
        for _ in 0..6 {
            apply(state, &[m2(slot, proposal_hash)], &[], None)?;
        }
        Ok(())
    }

    fn exact_elements_description() -> Vec<u8> {
        let fixture = concat!(
            "0008456c656d656e7473456c656d656e7473204472697665636861696e207631",
            "3b206e617469766520555344443b207265706c61792076343b206f6e65204d36",
            "2070657220706172656e7420626c6f636b3b207769746864726177616c206163",
            "63756d756c61746f722076313b2053696d706c6963697479206163746976653b",
            "20736c6f74203234f29aa8f8f41516ea0aa9845173f3d0d30144d4493495e749",
            "891310d419f4cf59d0552b4c7cacc18ce49532f6cb09fc877f56bafe"
        );
        fixture
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("lowercase hex fixture"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    fn hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn native_withdrawal_vector() -> NativeWithdrawalM6 {
        NativeWithdrawalM6::decode_legacy(
            &usdd_core::decode_hex(concat!(
                "02000000000300000000000000000a6a0800000000000003e8",
                "00000000000000004c6a4a",
                "454c5744013f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120",
                "185f5e5d5c5b5a595857565554535251504f4e4d4c4b4a4948474645444342414000000007",
                "b882010000000000160014606162636465666768696a6b6c6d6e6f7071727300000000"
            ))
            .unwrap(),
        )
        .unwrap()
    }

    fn identity() -> Slot24AccumulatorIdentity {
        Slot24AccumulatorIdentity {
            bitcoin_genesis: hash(1),
            elements_genesis: native_withdrawal_vector().reference().elements_genesis(),
            usdd_asset: hash(3),
            vault_id: hash(4),
        }
    }

    fn approve_m6id(state: &mut MultiSlotReplayState, slot: u8, m6id: Hash32) {
        apply(state, &[m3(slot, m6id)], &[], None).expect("M3");
        for _ in 0..5 {
            let index = state
                .active_slots
                .get(&slot)
                .expect("active")
                .pending_m6ids
                .iter()
                .position(|pending| pending.m6id == m6id)
                .expect("pending");
            assert!(index <= 253);
            let votes = state
                .active_slots()
                .map(|active_slot| {
                    if active_slot == slot {
                        index as u8
                    } else {
                        0xff
                    }
                })
                .collect::<Vec<_>>();
            apply(state, &[m4_one(&votes)], &[], None).expect("M4");
        }
        assert_eq!(
            state
                .pending_m6ids(slot)
                .find(|pending| pending.m6id == m6id)
                .expect("approved")
                .score,
            6
        );
    }

    fn generic_withdrawal(
        state: &MultiSlotReplayState,
        slot: u8,
        new_value: u64,
        payouts: &[(u64, Vec<u8>)],
    ) -> (Hash32, Vec<u8>) {
        let old = state.ctip(slot).expect("funded CTIP");
        let payout_total = payouts.iter().map(|(value, _)| *value).sum::<u64>();
        let fee = old
            .value_sat
            .checked_sub(new_value + payout_total)
            .expect("non-overspending withdrawal");
        let mut blinded = Vec::new();
        blinded.extend_from_slice(&2i32.to_le_bytes());
        blinded.push(0);
        blinded.push((payouts.len() + 1) as u8);
        blinded.extend_from_slice(&0u64.to_le_bytes());
        blinded.extend_from_slice(&[10, OP_RETURN, 8]);
        blinded.extend_from_slice(&fee.to_be_bytes());
        for (value, script) in payouts {
            blinded.extend_from_slice(&value.to_le_bytes());
            blinded.push(script.len() as u8);
            blinded.extend_from_slice(script);
        }
        blinded.extend_from_slice(&0u32.to_le_bytes());
        let blinded_txid = BlockHash::from_internal_bytes(double_sha256(&blinded));
        let m6id = Hash32(blinded_txid.to_display_bytes());

        let mut outputs = vec![(new_value, treasury(slot))];
        outputs.extend_from_slice(payouts);
        let actual = transaction(&[(old.txid, old.vout)], &outputs);
        (m6id, actual)
    }

    #[test]
    fn transition_caps_cover_pre_expiry_coinbase_state() {
        assert_eq!(
            MAX_PENDING_SLOT24_PROPOSALS,
            BITCOIN_MAX_COINBASE_OUTPUTS * 12
        );
        assert_eq!(MAX_PENDING_SLOT24_M6IDS, BITCOIN_MAX_COINBASE_OUTPUTS * 12);
    }

    #[test]
    fn active_slot_order_and_same_block_activation_define_m4_indices() {
        let mut state = MultiSlotReplayState::before_parent_genesis();
        activate(&mut state, 200, b"slot-200").expect("activate 200");
        let bundle = hash(0x20);
        apply(&mut state, &[m3(200, bundle)], &[], None).expect("M3");

        let description = b"slot-2";
        let proposal_hash = double_sha256(description);
        apply(&mut state, &[m1(2, description)], &[], None).expect("M1");
        for _ in 0..5 {
            apply(&mut state, &[m2(2, proposal_hash)], &[], None).expect("M2");
        }
        let branch_point = state.clone();

        let before = state.clone();
        assert_eq!(
            apply(&mut state, &[m2(2, proposal_hash), m4_one(&[0])], &[], None,),
            Err(MultiSlotReplayError::M4InvalidVoteCount)
        );
        assert_eq!(state, before);

        let effects = apply(
            &mut state,
            &[m2(2, proposal_hash), m4_one(&[0xff, 0])],
            &[],
            None,
        )
        .expect("activation before M4 expands sorted vector");
        assert_eq!(state.active_slots().collect::<Vec<_>>(), vec![2, 200]);
        assert_eq!(effects.effective_m4[0].slot, 200);
        assert_eq!(state.pending_m6ids(200).next().expect("pending").score, 2);

        let mut reversed = branch_point;
        let before = reversed.clone();
        assert_eq!(
            apply(
                &mut reversed,
                &[m4_one(&[0xff, 0]), m2(2, proposal_hash)],
                &[],
                None,
            ),
            Err(MultiSlotReplayError::M4InvalidVoteCount)
        );
        assert_eq!(reversed, before);
        apply(
            &mut reversed,
            &[m4_one(&[0]), m2(2, proposal_hash)],
            &[],
            None,
        )
        .expect("M4 before activation uses the old one-slot vector");
        assert_eq!(reversed.active_slots().collect::<Vec<_>>(), vec![2, 200]);
        assert_eq!(
            reversed.pending_m6ids(200).next().expect("pending").score,
            2
        );
    }

    #[test]
    fn multi_slot_ctips_update_together_and_fail_atomically() {
        let mut state = MultiSlotReplayState::before_parent_genesis();
        activate(&mut state, 2, b"two").expect("activate 2");
        activate(&mut state, 200, b"two-hundred").expect("activate 200");
        let funding = transaction(
            &[(BlockHash::from_internal_bytes([1; 32]), 0)],
            &[
                (10_000, treasury(2)),
                (0, push(b"two-address")),
                (20_000, treasury(200)),
                (0, push(b"two-hundred-address")),
            ],
        );
        let effects = apply(&mut state, &[], &[funding], None).expect("multi-slot M5");
        assert_eq!(effects.deposits.len(), 2);
        assert_eq!(effects.deposits[0].slot, 2);
        assert_eq!(effects.deposits[1].slot, 200);
        assert_eq!(state.ctip(2).expect("slot 2").vout, 0);
        assert_eq!(state.ctip(200).expect("slot 200").vout, 2);

        let two = state.ctip(2).expect("slot 2");
        let two_hundred = state.ctip(200).expect("slot 200");
        let missing_replacement = transaction(
            &[(two.txid, two.vout), (two_hundred.txid, two_hundred.vout)],
            &[(11_000, treasury(2)), (0, push(b"next-two"))],
        );
        let before = state.clone();
        assert_eq!(
            apply(&mut state, &[], &[missing_replacement], None),
            Err(MultiSlotReplayError::TreasurySpentWithoutReplacement)
        );
        assert_eq!(state, before);

        let parallel = transaction(
            &[(BlockHash::from_internal_bytes([2; 32]), 0)],
            &[(21_000, treasury(200)), (0, push(b"parallel"))],
        );
        assert_eq!(
            apply(&mut state, &[], &[parallel], None),
            Err(MultiSlotReplayError::OldCtipUnspent)
        );
        assert_eq!(state, before);

        let valid = transaction(
            &[(two.txid, two.vout), (two_hundred.txid, two_hundred.vout)],
            &[
                (11_000, treasury(2)),
                (0, push(b"next-two")),
                (22_000, treasury(200)),
                (0, push(b"next-two-hundred")),
            ],
        );
        let effects = apply(&mut state, &[], &[valid], None).expect("atomic multi M5");
        assert_eq!(effects.deposits.len(), 2);
        assert_eq!(state.ctip(2).expect("slot 2").value_sat, 11_000);
        assert_eq!(state.ctip(200).expect("slot 200").value_sat, 22_000);
    }

    #[test]
    fn other_slot_m6_does_not_poison_slot24_usdd_continuity() {
        let mut state = MultiSlotReplayState::before_parent_genesis();
        activate(
            &mut state,
            ELEMENTS_DRIVECHAIN_SLOT,
            &exact_elements_description(),
        )
        .expect("exact Elements activation");
        activate(&mut state, 7, b"slot-seven").expect("activate 7");
        state.bind_empty_accumulator(identity()).expect("identity");
        let funding = transaction(
            &[(BlockHash::from_internal_bytes([3; 32]), 0)],
            &[
                (50_000, treasury(ELEMENTS_DRIVECHAIN_SLOT)),
                (0, push(b"elements")),
                (20_000, treasury(7)),
                (0, push(b"seven")),
            ],
        );
        apply(&mut state, &[], &[funding], None).expect("fund both");
        let (m6id, actual) = generic_withdrawal(&state, 7, 18_000, &[(1_000, vec![OP_TRUE])]);
        approve_m6id(&mut state, 7, m6id);
        let effects = apply(&mut state, &[], &[actual], None).expect("generic slot-7 M6");
        assert_eq!(effects.successful_m6s.len(), 1);
        assert_eq!(effects.successful_m6s[0].slot, 7);
        assert!(!effects.successful_m6s[0].usdd_special);
        assert_eq!(state.slot24_usdd_continuity(), Slot24UsddContinuity::Active);
        assert_eq!(state.approved_root(), Some(Slot24ApprovedRoot::empty()));
    }

    #[test]
    fn same_block_alarm_then_m6_can_leave_no_pending_bundles() {
        let mut state = MultiSlotReplayState::before_parent_genesis();
        activate(&mut state, 7, b"slot-seven").expect("activate 7");
        let funding = transaction(
            &[(BlockHash::from_internal_bytes([0x70; 32]), 0)],
            &[(20_000, treasury(7)), (0, push(b"seven"))],
        );
        apply(&mut state, &[], &[funding], None).expect("fund slot 7");
        let (m6id, actual) = generic_withdrawal(&state, 7, 18_000, &[(1_000, vec![OP_TRUE])]);
        approve_m6id(&mut state, 7, m6id);
        apply(&mut state, &[m4_one(&[0])], &[], None).expect("score seven");

        let effects = apply(&mut state, &[m4_one(&[0xfe])], &[actual], None)
            .expect("alarm lowers to six before successful M6");
        assert_eq!(effects.successful_m6s.len(), 1);
        assert_eq!(state.pending_m6ids(7).count(), 0);

        let repeated = apply(&mut state, &[m4_repeat()], &[], None)
            .expect("repeating prior alarm over an empty set is a no-op");
        assert!(repeated.effective_m4.is_empty());
    }

    #[test]
    fn slot24_accepts_only_exact_native_or_canonical_m6_and_preserves_root_correctly() {
        let mut state = MultiSlotReplayState::before_parent_genesis();
        let description = exact_elements_description();
        assert_eq!(
            double_sha256(&description),
            ELEMENTS_V1_REQUIRED_PROPOSAL_HASH_INTERNAL
        );
        activate(&mut state, ELEMENTS_DRIVECHAIN_SLOT, &description).expect("exact activation");
        state.bind_empty_accumulator(identity()).expect("identity");
        let funding = transaction(
            &[(BlockHash::from_internal_bytes([4; 32]), 0)],
            &[
                (1_000_000, treasury(ELEMENTS_DRIVECHAIN_SLOT)),
                (0, push(b"elements")),
            ],
        );
        apply(&mut state, &[], &[funding], None).expect("fund slot24");
        let mut generic_state = state.clone();
        let (generic_id, generic_actual) = generic_withdrawal(
            &generic_state,
            ELEMENTS_DRIVECHAIN_SLOT,
            998_000,
            &[(1_000, vec![OP_TRUE])],
        );
        approve_m6id(&mut generic_state, ELEMENTS_DRIVECHAIN_SLOT, generic_id);
        let generic_effects = apply(&mut generic_state, &[], &[generic_actual], None)
            .expect("enforcer-valid generic slot24 M6");
        assert_eq!(generic_effects.successful_m6s.len(), 1);
        assert!(generic_effects
            .approved_slot24_native_withdrawal_m6
            .is_none());
        assert!(generic_effects.approved_slot24_accumulator_m6.is_none());
        assert_eq!(
            generic_state.slot24_usdd_continuity(),
            Slot24UsddContinuity::Invalidated
        );
        assert_eq!(
            generic_state.approved_root(),
            Some(Slot24ApprovedRoot::empty())
        );
        assert!(generic_state
            .successful_slot24_m6ids()
            .any(|m6id| m6id == generic_id));
        apply(
            &mut generic_state,
            &[m3(ELEMENTS_DRIVECHAIN_SLOT, generic_id)],
            &[],
            None,
        )
        .expect("upstream permits reproposing a paid M6id");
        assert!(generic_state
            .active_slots
            .get(&ELEMENTS_DRIVECHAIN_SLOT)
            .expect("active slot")
            .pending_m6ids
            .iter()
            .any(|pending| pending.m6id == generic_id));

        let invalidated_root = generic_state.approved_root().expect("preserved root");
        let native_after_generic = native_withdrawal_vector();
        approve_m6id(
            &mut generic_state,
            ELEMENTS_DRIVECHAIN_SLOT,
            native_after_generic.m6id(),
        );
        let invalidated_ctip = generic_state
            .ctip(ELEMENTS_DRIVECHAIN_SLOT)
            .expect("invalidated CTIP");
        let native_after_generic_actual = native_after_generic
            .actual_transaction_bytes(&Ctip {
                outpoint: OutPoint {
                    txid: Hash32(invalidated_ctip.txid.to_display_bytes()),
                    vout: invalidated_ctip.vout,
                },
                value_sats: invalidated_ctip.value_sat,
            })
            .expect("native actual after generic");
        let native_after_generic_effects = apply(
            &mut generic_state,
            &[],
            &[native_after_generic_actual],
            None,
        )
        .expect("native-looking M6 remains generic after invalidation");
        assert_eq!(native_after_generic_effects.successful_m6s.len(), 1);
        assert!(!native_after_generic_effects.successful_m6s[0].usdd_special);
        assert!(native_after_generic_effects
            .approved_slot24_native_withdrawal_m6
            .is_none());
        assert!(native_after_generic_effects
            .approved_slot24_accumulator_m6
            .is_none());
        assert_eq!(
            generic_state.slot24_usdd_continuity(),
            Slot24UsddContinuity::Invalidated
        );
        assert_eq!(generic_state.approved_root(), Some(invalidated_root));

        let id = identity();
        let canonical_after_generic = MinerBundleArtifact {
            bitcoin_genesis: id.bitcoin_genesis,
            elements_genesis: id.elements_genesis,
            usdd_asset: id.usdd_asset,
            vault_id: id.vault_id,
            prior_claim_count: invalidated_root.claim_count,
            prior_claim_root: invalidated_root.claim_root,
            next_claim_count: invalidated_root.claim_count + 1,
            next_claim_root: hash(0x9a),
            fee_sats: 1_000,
        };
        let canonical_after_generic_id = canonical_after_generic.m6id().expect("canonical M6id");
        approve_m6id(
            &mut generic_state,
            ELEMENTS_DRIVECHAIN_SLOT,
            canonical_after_generic_id,
        );
        let invalidated_ctip = generic_state
            .ctip(ELEMENTS_DRIVECHAIN_SLOT)
            .expect("post-native CTIP");
        let canonical_after_generic_actual = ActualM6Artifact::build(
            canonical_after_generic.clone(),
            Ctip {
                outpoint: OutPoint {
                    txid: Hash32(invalidated_ctip.txid.to_display_bytes()),
                    vout: invalidated_ctip.vout,
                },
                value_sats: invalidated_ctip.value_sat,
            },
        )
        .expect("canonical actual after generic")
        .transaction_bytes()
        .expect("canonical transaction bytes");
        let canonical_after_generic_effects = apply(
            &mut generic_state,
            &[],
            &[canonical_after_generic_actual],
            Some(&canonical_after_generic),
        )
        .expect("canonical-looking M6 remains generic after invalidation");
        assert_eq!(canonical_after_generic_effects.successful_m6s.len(), 1);
        assert!(!canonical_after_generic_effects.successful_m6s[0].usdd_special);
        assert!(canonical_after_generic_effects
            .approved_slot24_native_withdrawal_m6
            .is_none());
        assert!(canonical_after_generic_effects
            .approved_slot24_accumulator_m6
            .is_none());
        assert_eq!(
            generic_state.slot24_usdd_continuity(),
            Slot24UsddContinuity::Invalidated
        );
        assert_eq!(generic_state.approved_root(), Some(invalidated_root));
        assert!(generic_state
            .successful_slot24_m6ids()
            .any(|m6id| m6id == canonical_after_generic_id));

        assert_eq!(state.slot24_usdd_continuity(), Slot24UsddContinuity::Active);
        assert_eq!(state.approved_root(), Some(Slot24ApprovedRoot::empty()));

        let native = native_withdrawal_vector();
        let before_native_m3 = state.clone();
        approve_m6id(&mut state, ELEMENTS_DRIVECHAIN_SLOT, native.m6id());
        let ctip = state.ctip(ELEMENTS_DRIVECHAIN_SLOT).expect("CTIP");
        let native_actual = native
            .actual_transaction_bytes(&Ctip {
                outpoint: OutPoint {
                    txid: Hash32(ctip.txid.to_display_bytes()),
                    vout: ctip.vout,
                },
                value_sats: ctip.value_sat,
            })
            .unwrap();
        let native_root = state.approved_root().unwrap();
        let native_effects =
            apply(&mut state, &[], &[native_actual], None).expect("exact native M6");
        assert_eq!(native_effects.successful_m6s.len(), 1);
        assert!(!native_effects.successful_m6s[0].usdd_special);
        assert_eq!(
            native_effects
                .approved_slot24_native_withdrawal_m6
                .as_ref()
                .expect("native effect")
                .preserved_usdd_root,
            native_root
        );
        assert!(native_effects.approved_slot24_accumulator_m6.is_none());
        assert_eq!(state.approved_root(), Some(native_root));
        assert_eq!(state.slot24_usdd_continuity(), Slot24UsddContinuity::Active);
        assert!(state
            .successful_slot24_m6ids()
            .any(|m6id| m6id == native.m6id()));
        apply(
            &mut state,
            &[m3(ELEMENTS_DRIVECHAIN_SLOT, native.m6id())],
            &[],
            None,
        )
        .expect("upstream permits reproposing a paid native M6id");
        let mut disconnected = before_native_m3;
        apply(
            &mut disconnected,
            &[m3(ELEMENTS_DRIVECHAIN_SLOT, native.m6id())],
            &[],
            None,
        )
        .expect("alternate branch may repropose unspent M6id");

        let prior = state.approved_root().expect("bound root");
        let id = identity();
        let artifact = MinerBundleArtifact {
            bitcoin_genesis: id.bitcoin_genesis,
            elements_genesis: id.elements_genesis,
            usdd_asset: id.usdd_asset,
            vault_id: id.vault_id,
            prior_claim_count: prior.claim_count,
            prior_claim_root: prior.claim_root,
            next_claim_count: prior.claim_count + 1,
            next_claim_root: hash(0x91),
            fee_sats: 1_000,
        };
        let m6id = artifact.m6id().expect("canonical M6id");
        approve_m6id(&mut state, ELEMENTS_DRIVECHAIN_SLOT, m6id);
        let ctip = state.ctip(ELEMENTS_DRIVECHAIN_SLOT).expect("CTIP");
        let actual = ActualM6Artifact::build(
            artifact.clone(),
            Ctip {
                outpoint: OutPoint {
                    txid: Hash32(ctip.txid.to_display_bytes()),
                    vout: ctip.vout,
                },
                value_sats: ctip.value_sat,
            },
        )
        .expect("canonical actual")
        .transaction_bytes()
        .expect("transaction bytes");
        let canonical_effects = apply(&mut state, &[], &[actual], Some(&artifact))
            .expect("canonical root M6 after native M6");
        assert!(canonical_effects
            .approved_slot24_native_withdrawal_m6
            .is_none());
        assert_eq!(
            state.approved_root(),
            Some(Slot24ApprovedRoot {
                claim_count: artifact.next_claim_count,
                claim_root: artifact.next_claim_root,
            })
        );
    }

    #[test]
    fn bmm_is_per_slot_and_forks_and_failures_are_atomic() {
        let mut state = MultiSlotReplayState::before_parent_genesis();
        let child_two = BlockHash::from_internal_bytes([0x22; 32]);
        let child_two_hundred = BlockHash::from_internal_bytes([0xcc; 32]);
        let previous = state.tip_hash();
        let request_two = transaction(
            &[(BlockHash::from_internal_bytes([5; 32]), 0)],
            &[(0, m8(2, child_two, previous))],
        );
        let request_two_hundred = transaction(
            &[(BlockHash::from_internal_bytes([6; 32]), 0)],
            &[(0, m8(200, child_two_hundred, previous))],
        );
        let effects = apply(
            &mut state,
            &[m7(200, child_two_hundred), m7(2, child_two)],
            &[request_two, request_two_hundred],
            None,
        )
        .expect("two independent BMM requests");
        assert_eq!(effects.matching_m8_requests, 2);
        assert_eq!(
            effects
                .bmm_commitments
                .iter()
                .map(|entry| entry.slot)
                .collect::<Vec<_>>(),
            vec![2, 200]
        );

        let common = state.clone();
        let before = state.clone();
        assert_eq!(
            apply(
                &mut state,
                &[m7(2, child_two), m7(2, child_two_hundred)],
                &[],
                None,
            ),
            Err(MultiSlotReplayError::DuplicateM7)
        );
        assert_eq!(state, before);

        let mut left = common.clone();
        let mut right = common.clone();
        apply(&mut left, &[m7(1, child_two)], &[], None).expect("left branch");
        apply(&mut right, &[m7(1, child_two_hundred)], &[], None).expect("right branch");
        assert_ne!(left.tip_hash(), right.tip_hash());
        assert_eq!(common, state);
    }
}
