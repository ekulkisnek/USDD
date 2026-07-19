//! Bounded slot-24 BIP300/301 replay for the Elements Drivechain identity.
//!
//! This module is a faithful, no-std port of the pure proposal/activation and
//! fail-closed CTIP-increase logic in the local Elements fork's
//! `ApplyDrivechainParentBlockState`. It also checks the exact BIP301 M8
//! relationship implemented by the paired LayerTwo enforcer.
//!
//! The input block is transaction/Merkle-bound, but this layer does not prove
//! contextual Bitcoin validity, Signet authorization, best-work membership, or
//! input-value conservation. Its results therefore cannot authorize a USDD
//! state transition until composed behind those missing checks.

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use crate::{
    double_sha256, extract_single_op_return_push, BlockHash, BITCOIN_MAX_COINBASE_OUTPUTS,
    ELEMENTS_DRIVECHAIN_SLOT,
};

use super::{parse_and_verify_block, BlockStructureError, ParsedBlock, ParsedTransaction};

const M1_TAG: [u8; 4] = [0xd5, 0xe0, 0xc4, 0xaf];
const M2_TAG: [u8; 4] = [0xd6, 0xe1, 0xc5, 0xdf];
const M7_TAG: [u8; 4] = [0xd1, 0x61, 0x73, 0x68];
const M8_TAG: [u8; 3] = [0x00, 0xbf, 0x00];
const OP_DRIVECHAIN: u8 = 0xb4; // OP_NOP5 in the unmodified Bitcoin opcode table.
const OP_TRUE: u8 = 0x51;
const OP_RETURN: u8 = 0x6a;
const MAX_MONEY_SATOSHIS: u64 = 21_000_000 * 100_000_000;
const M7_PAYLOAD_LEN: usize = 4 + 1 + 32;
const M7_CANONICAL_SCRIPT_LEN: usize = 1 + 1 + M7_PAYLOAD_LEN;
const M8_PAYLOAD_LEN: usize = 3 + 1 + 32 + 32;
const M8_CANONICAL_SCRIPT_LEN: usize = 1 + 1 + M8_PAYLOAD_LEN;

/// Frozen internal/wire byte order of the sole Elements V1 proposal hash.
///
/// Reversing these bytes produces the display hash
/// `b27b2b233f9db48be36046b72cac4876efd24a3055bbb0c25392f52e55042f98`
/// from `elements_drivechain_identity.h`.
pub const ELEMENTS_V1_REQUIRED_PROPOSAL_HASH_INTERNAL: [u8; 32] = [
    0x98, 0x2f, 0x04, 0x55, 0x2e, 0xf5, 0x92, 0x53, 0xc2, 0xb0, 0xbb, 0x55, 0x30, 0x4a, 0xd2, 0xef,
    0x76, 0x48, 0xac, 0x2c, 0xb7, 0x46, 0x60, 0xe3, 0x8b, 0xb4, 0x9d, 0x3f, 0x23, 0x2b, 0x7b, 0xb2,
];

/// Maximum creation-height window for a still-live Elements V1 proposal.
pub const ELEMENTS_V1_MAX_LIVE_PROPOSAL_BLOCKS: usize = 10 + 1;

/// Consensus-derived upper bound for every live slot-24 proposal.
///
/// The block parser proves that a coinbase has at most
/// `BITCOIN_MAX_COINBASE_OUTPUTS` outputs. The frozen enforcer age is ten, so a
/// live proposal can come from at most eleven creation heights (age 0..=10).
/// Multiplying those independent maxima is deliberately permissive but cannot
/// be exceeded by a block history accepted by the implemented parser/replay.
pub const MAX_PENDING_SLOT24_PROPOSALS: usize =
    BITCOIN_MAX_COINBASE_OUTPUTS * ELEMENTS_V1_MAX_LIVE_PROPOSAL_BLOCKS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElementsSlot24ReplayConfig {
    required_proposal_hash: [u8; 32],
    unused_proposal_max_age: u16,
    unused_activation_threshold: u16,
    used_proposal_max_age: u16,
    used_activation_threshold: u16,
}

impl ElementsSlot24ReplayConfig {
    /// Exact immutable settings in `elements_drivechain_identity.h`.
    pub const fn elements_v1() -> Self {
        Self {
            required_proposal_hash: ELEMENTS_V1_REQUIRED_PROPOSAL_HASH_INTERNAL,
            unused_proposal_max_age: 10,
            unused_activation_threshold: 5,
            used_proposal_max_age: 10,
            used_activation_threshold: 5,
        }
    }

    /// Construct settings already authenticated against an external manifest.
    ///
    /// This function validates internal consistency only. The caller remains
    /// responsible for binding every argument to the frozen network manifest.
    pub fn from_manifest_bound_identity(
        required_proposal_hash: [u8; 32],
        unused_proposal_max_age: u16,
        unused_activation_threshold: u16,
        used_proposal_max_age: u16,
        used_activation_threshold: u16,
    ) -> Result<Self, ElementsSlot24ReplayError> {
        let config = Self {
            required_proposal_hash,
            unused_proposal_max_age,
            unused_activation_threshold,
            used_proposal_max_age,
            used_activation_threshold,
        };
        config.validate()?;
        Ok(config)
    }

    pub const fn required_proposal_hash(self) -> [u8; 32] {
        self.required_proposal_hash
    }

    fn validate(self) -> Result<(), ElementsSlot24ReplayError> {
        if self.required_proposal_hash == [0; 32]
            || self.unused_proposal_max_age == 0
            || self.unused_activation_threshold == 0
            || self.unused_activation_threshold >= self.unused_proposal_max_age
            || self.used_proposal_max_age == 0
            || self.used_activation_threshold == 0
            || self.used_activation_threshold >= self.used_proposal_max_age
        {
            return Err(ElementsSlot24ReplayError::InvalidConfig);
        }
        self.maximum_pending_proposals()?;
        Ok(())
    }

    fn thresholds(self, slot_is_used: bool) -> (u16, u16) {
        if slot_is_used {
            (self.used_proposal_max_age, self.used_activation_threshold)
        } else {
            (
                self.unused_proposal_max_age,
                self.unused_activation_threshold,
            )
        }
    }

    fn maximum_pending_proposals(self) -> Result<usize, ElementsSlot24ReplayError> {
        let live_blocks = usize::from(core::cmp::max(
            self.unused_proposal_max_age,
            self.used_proposal_max_age,
        ))
        .checked_add(1)
        .ok_or(ElementsSlot24ReplayError::InvalidConfig)?;
        BITCOIN_MAX_COINBASE_OUTPUTS
            .checked_mul(live_blocks)
            .ok_or(ElementsSlot24ReplayError::InvalidConfig)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingSlot24Proposal {
    pub proposal_hash: [u8; 32],
    pub proposal_height: u32,
    pub votes: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot24Ctip {
    pub txid: BlockHash,
    pub vout: u32,
    pub value_sat: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintableSlot24Deposit {
    pub outpoint: Slot24Ctip,
    pub block_hash: BlockHash,
    pub block_height: u32,
    pub value_sat: u64,
    pub elements_address: Vec<u8>,
}

/// Replay state after every block below `next_height` has been applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElementsSlot24ReplayState {
    config: ElementsSlot24ReplayConfig,
    next_height: u32,
    tip_hash: BlockHash,
    active_proposal_hash: Option<[u8; 32]>,
    required_activation: Option<(u32, BlockHash)>,
    pending_proposals: BTreeMap<[u8; 32], PendingSlot24Proposal>,
    ctip: Option<Slot24Ctip>,
}

impl ElementsSlot24ReplayState {
    /// Empty state immediately before the Bitcoin genesis block.
    pub fn before_parent_genesis(
        config: ElementsSlot24ReplayConfig,
    ) -> Result<Self, ElementsSlot24ReplayError> {
        config.validate()?;
        Ok(Self {
            config,
            next_height: 0,
            tip_hash: BlockHash::ZERO,
            active_proposal_hash: None,
            required_activation: None,
            pending_proposals: BTreeMap::new(),
            ctip: None,
        })
    }

    /// Restore a checkpoint whose complete state is already manifest-bound.
    ///
    /// Omitting pending proposals is unsound: an old M1 can be ACKed after the
    /// checkpoint. For that reason this constructor requires the entire live
    /// pending set and advertises that it does not authenticate its inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn from_unverified_checkpoint_requires_manifest_binding(
        config: ElementsSlot24ReplayConfig,
        processed_height: u32,
        tip_hash: BlockHash,
        active_proposal_hash: Option<[u8; 32]>,
        required_activation: Option<(u32, BlockHash)>,
        pending_proposals: Vec<PendingSlot24Proposal>,
        ctip: Option<Slot24Ctip>,
    ) -> Result<Self, ElementsSlot24ReplayError> {
        config.validate()?;
        let next_height = processed_height
            .checked_add(1)
            .ok_or(ElementsSlot24ReplayError::HeightOverflow)?;
        let mut pending = BTreeMap::new();
        for proposal in pending_proposals {
            if pending.insert(proposal.proposal_hash, proposal).is_some() {
                return Err(ElementsSlot24ReplayError::MalformedState);
            }
        }
        let state = Self {
            config,
            next_height,
            tip_hash,
            active_proposal_hash,
            required_activation,
            pending_proposals: pending,
            ctip,
        };
        state.validate()?;
        Ok(state)
    }

    pub const fn next_height(&self) -> u32 {
        self.next_height
    }

    pub const fn tip_hash(&self) -> BlockHash {
        self.tip_hash
    }

    pub const fn active_proposal_hash(&self) -> Option<[u8; 32]> {
        self.active_proposal_hash
    }

    pub const fn required_activation(&self) -> Option<(u32, BlockHash)> {
        self.required_activation
    }

    pub const fn ctip(&self) -> Option<Slot24Ctip> {
        self.ctip
    }

    pub fn pending_proposals(&self) -> impl ExactSizeIterator<Item = PendingSlot24Proposal> + '_ {
        self.pending_proposals.values().copied()
    }

    pub fn required_proposal_is_active(&self) -> bool {
        self.required_activation.is_some()
            && self.active_proposal_hash == Some(self.config.required_proposal_hash)
    }

    fn validate(&self) -> Result<(), ElementsSlot24ReplayError> {
        self.config.validate()?;
        if self.pending_proposals.len() > self.config.maximum_pending_proposals()? {
            return Err(ElementsSlot24ReplayError::PendingProposalLimitExceeded);
        }
        if self.next_height == 0 {
            if self.tip_hash != BlockHash::ZERO
                || self.active_proposal_hash.is_some()
                || self.required_activation.is_some()
                || !self.pending_proposals.is_empty()
                || self.ctip.is_some()
            {
                return Err(ElementsSlot24ReplayError::MalformedState);
            }
            return Ok(());
        }
        if self.tip_hash == BlockHash::ZERO {
            return Err(ElementsSlot24ReplayError::MalformedState);
        }
        if self.active_proposal_hash.is_none() && self.ctip.is_some() {
            return Err(ElementsSlot24ReplayError::MalformedState);
        }
        if (self.active_proposal_hash == Some(self.config.required_proposal_hash))
            != self.required_activation.is_some()
        {
            return Err(ElementsSlot24ReplayError::MalformedState);
        }
        if let Some((height, hash)) = self.required_activation {
            if self.active_proposal_hash != Some(self.config.required_proposal_hash)
                || height >= self.next_height
                || hash == BlockHash::ZERO
            {
                return Err(ElementsSlot24ReplayError::MalformedState);
            }
        }
        if let Some(ctip) = self.ctip {
            if ctip.txid == BlockHash::ZERO
                || ctip.value_sat == 0
                || ctip.value_sat > MAX_MONEY_SATOSHIS
            {
                return Err(ElementsSlot24ReplayError::MalformedState);
            }
        }
        let tip_height = self.next_height - 1;
        let (proposal_max_age, activation_threshold) =
            self.config.thresholds(self.active_proposal_hash.is_some());
        let max_fails = u32::from(proposal_max_age - activation_threshold);
        for (hash, proposal) in &self.pending_proposals {
            let age = tip_height
                .checked_sub(proposal.proposal_height)
                .ok_or(ElementsSlot24ReplayError::MalformedState)?;
            let misses = age
                .checked_sub(u32::from(proposal.votes))
                .ok_or(ElementsSlot24ReplayError::MalformedState)?;
            if *hash == [0; 32]
                || *hash != proposal.proposal_hash
                || proposal.proposal_height > tip_height
                || age > u32::from(proposal_max_age)
                || (age > max_fails && misses >= max_fails)
            {
                return Err(ElementsSlot24ReplayError::MalformedState);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElementsSlot24BmmEdge {
    pub parent_block_hash: BlockHash,
    pub successor_block_hash: BlockHash,
    pub successor_height: u32,
    pub coinbase_txid: BlockHash,
    pub m7_output_index: u32,
    pub committed_child_hash: BlockHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElementsSlot24BlockEffects {
    pub deposits: Vec<MintableSlot24Deposit>,
    pub bmm_edge: Option<ElementsSlot24BmmEdge>,
    pub matching_m8_requests: u32,
    /// True for an enforcer-recognized M7, including a nonminimal encoding
    /// which cannot authorize an Elements edge.
    pub saw_slot24_m7: bool,
    pub required_proposal_active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElementsSlot24ReplayError {
    Block(BlockStructureError),
    InvalidConfig,
    MalformedState,
    BrokenParentLink,
    HeightOverflow,
    PendingProposalLimitExceeded,
    DuplicateProposalMessage,
    MultipleAckMessages,
    VoteOverflow,
    ProposalHeightAhead,
    ProposalVotesAhead,
    RequiredProposalReplaced,
    DuplicateM7,
    OutputIndexOverflow,
    M8WithoutM7,
    M8WrongChildHash,
    M8Expired,
    M8CountOverflow,
    MultipleTreasuryOutputs,
    ParallelTreasuryOutput,
    CtipSpentWithoutReplacement,
    ZeroCtipDelta,
    CtipDecreaseUnsupported,
    MissingDepositAddress,
    AmountOverflow,
}

impl From<BlockStructureError> for ElementsSlot24ReplayError {
    fn from(value: BlockStructureError) -> Self {
        Self::Block(value)
    }
}

#[derive(Clone, Copy)]
enum ParentMessage {
    Proposal([u8; 32]),
    Ack([u8; 32]),
}

fn parse_slot24_parent_message(script: &[u8]) -> Option<ParentMessage> {
    let payload = extract_single_op_return_push(script)?;
    if payload.len() < 5 || payload[4] != ELEMENTS_DRIVECHAIN_SLOT {
        return None;
    }
    if payload[..4] == M1_TAG {
        return Some(ParentMessage::Proposal(double_sha256(&payload[5..])));
    }
    if payload.len() == 4 + 1 + 32 && payload[..4] == M2_TAG {
        let mut hash = [0; 32];
        hash.copy_from_slice(&payload[5..]);
        return Some(ParentMessage::Ack(hash));
    }
    None
}

#[derive(Clone, Copy)]
struct ObservedM7 {
    output_index: u32,
    child_hash: BlockHash,
    canonical_for_elements: bool,
}

fn observe_slot24_m7(
    parsed: &ParsedBlock<'_>,
) -> Result<Option<ObservedM7>, ElementsSlot24ReplayError> {
    let mut observed = None;
    for (index, output) in parsed.coinbase.outputs.iter().enumerate() {
        let Some(payload) = extract_single_op_return_push(output.script) else {
            continue;
        };
        if payload.len() != M7_PAYLOAD_LEN
            || payload[..4] != M7_TAG
            || payload[4] != ELEMENTS_DRIVECHAIN_SLOT
        {
            continue;
        }
        if observed.is_some() {
            return Err(ElementsSlot24ReplayError::DuplicateM7);
        }
        let output_index =
            u32::try_from(index).map_err(|_| ElementsSlot24ReplayError::OutputIndexOverflow)?;
        let mut hash = [0; 32];
        hash.copy_from_slice(&payload[5..]);
        observed = Some(ObservedM7 {
            output_index,
            child_hash: BlockHash::from_internal_bytes(hash),
            canonical_for_elements: output.script.len() == M7_CANONICAL_SCRIPT_LEN
                && output.script[0] == OP_RETURN
                && usize::from(output.script[1]) == M7_PAYLOAD_LEN,
        });
    }
    Ok(observed)
}

fn parse_slot24_m8(transaction: &ParsedTransaction<'_>) -> Option<(BlockHash, BlockHash)> {
    let script = transaction.outputs.first()?.script;
    if script.len() != M8_CANONICAL_SCRIPT_LEN
        || script[0] != OP_RETURN
        || usize::from(script[1]) != M8_PAYLOAD_LEN
        || script[2..5] != M8_TAG
        || script[5] != ELEMENTS_DRIVECHAIN_SLOT
    {
        return None;
    }
    let mut child_hash = [0; 32];
    child_hash.copy_from_slice(&script[6..38]);
    let mut previous_hash = [0; 32];
    previous_hash.copy_from_slice(&script[38..70]);
    Some((
        BlockHash::from_internal_bytes(child_hash),
        BlockHash::from_internal_bytes(previous_hash),
    ))
}

fn is_slot24_treasury(script: &[u8]) -> bool {
    script == [OP_DRIVECHAIN, 0x01, ELEMENTS_DRIVECHAIN_SLOT, OP_TRUE]
}

fn input_spends(input: &[u8; 36], ctip: Slot24Ctip) -> bool {
    input[..32] == ctip.txid.to_internal_bytes() && input[32..] == ctip.vout.to_le_bytes()
}

fn output_value(output: &super::ParsedOutput<'_>) -> u64 {
    // `parse_transaction` has already rejected negative and out-of-range
    // values, so the conversion is infallible here.
    i64::from_le_bytes(output.value) as u64
}

fn apply_coinbase_messages(
    state: &mut ElementsSlot24ReplayState,
    parsed: &ParsedBlock<'_>,
    height: u32,
) -> Result<(), ElementsSlot24ReplayError> {
    let mut created_in_block = BTreeSet::new();
    let mut proposal_messages_in_block = BTreeSet::new();
    let mut saw_ack = false;

    for output in &parsed.coinbase.outputs {
        match parse_slot24_parent_message(output.script) {
            None => {}
            Some(ParentMessage::Proposal(proposal_hash)) => {
                if !proposal_messages_in_block.insert(proposal_hash) {
                    return Err(ElementsSlot24ReplayError::DuplicateProposalMessage);
                }
                if !state.pending_proposals.contains_key(&proposal_hash) {
                    if state.pending_proposals.len() == state.config.maximum_pending_proposals()? {
                        return Err(ElementsSlot24ReplayError::PendingProposalLimitExceeded);
                    }
                    state.pending_proposals.insert(
                        proposal_hash,
                        PendingSlot24Proposal {
                            proposal_hash,
                            proposal_height: height,
                            votes: 0,
                        },
                    );
                    created_in_block.insert(proposal_hash);
                }
            }
            Some(ParentMessage::Ack(proposal_hash)) => {
                if saw_ack {
                    return Err(ElementsSlot24ReplayError::MultipleAckMessages);
                }
                saw_ack = true;
                if created_in_block.contains(&proposal_hash) {
                    continue;
                }
                let Some(proposal) = state.pending_proposals.get_mut(&proposal_hash) else {
                    continue;
                };
                proposal.votes = proposal
                    .votes
                    .checked_add(1)
                    .ok_or(ElementsSlot24ReplayError::VoteOverflow)?;
                let (_, activation_threshold) = state
                    .config
                    .thresholds(state.active_proposal_hash.is_some());
                if proposal.votes > activation_threshold {
                    state.active_proposal_hash = Some(proposal_hash);
                    state.pending_proposals.remove(&proposal_hash);
                    if state.required_activation.is_some()
                        && proposal_hash != state.config.required_proposal_hash
                    {
                        return Err(ElementsSlot24ReplayError::RequiredProposalReplaced);
                    }
                    if state.required_activation.is_none()
                        && proposal_hash == state.config.required_proposal_hash
                    {
                        state.required_activation = Some((height, parsed.metadata.block_hash));
                    }
                }
            }
        }
    }

    // Match the enforcer/fork ordering: activation happens first, then every
    // proposal is aged using the now-live used/unused threshold pair.
    let (proposal_max_age, activation_threshold) = state
        .config
        .thresholds(state.active_proposal_hash.is_some());
    let max_fails = u32::from(proposal_max_age - activation_threshold);
    let mut expired = Vec::new();
    for (hash, proposal) in &state.pending_proposals {
        let age = height
            .checked_sub(proposal.proposal_height)
            .ok_or(ElementsSlot24ReplayError::ProposalHeightAhead)?;
        if u32::from(proposal.votes) > age {
            return Err(ElementsSlot24ReplayError::ProposalVotesAhead);
        }
        let misses = age - u32::from(proposal.votes);
        if age > u32::from(proposal_max_age) || (age > max_fails && misses >= max_fails) {
            expired.push(*hash);
        }
    }
    for hash in expired {
        state.pending_proposals.remove(&hash);
    }
    Ok(())
}

fn apply_transactions(
    state: &mut ElementsSlot24ReplayState,
    parsed: &ParsedBlock<'_>,
    height: u32,
    observed_m7: Option<ObservedM7>,
) -> Result<(Vec<MintableSlot24Deposit>, u32), ElementsSlot24ReplayError> {
    let mut deposits = Vec::new();
    let mut matching_m8_requests = 0u32;
    let required_active_for_transactions = state.required_proposal_is_active();

    for transaction in parsed.transactions.iter().skip(1) {
        if let Some((child_hash, previous_hash)) = parse_slot24_m8(transaction) {
            let m7 = observed_m7.ok_or(ElementsSlot24ReplayError::M8WithoutM7)?;
            if child_hash != m7.child_hash {
                return Err(ElementsSlot24ReplayError::M8WrongChildHash);
            }
            if previous_hash != parsed.metadata.header.previous_block {
                return Err(ElementsSlot24ReplayError::M8Expired);
            }
            matching_m8_requests = matching_m8_requests
                .checked_add(1)
                .ok_or(ElementsSlot24ReplayError::M8CountOverflow)?;
        }

        // OP_DRIVECHAIN bytes have no treasury meaning before any proposal is
        // active in the slot. M8 validation above remains independent.
        if state.active_proposal_hash.is_none() {
            continue;
        }

        let current_ctip_inputs = state.ctip.map_or(0, |ctip| {
            transaction
                .inputs
                .iter()
                .filter(|input| input_spends(input, ctip))
                .count()
        });

        let mut treasury_output = None;
        for (index, output) in transaction.outputs.iter().enumerate() {
            if !is_slot24_treasury(output.script) {
                continue;
            }
            if treasury_output.is_some() {
                return Err(ElementsSlot24ReplayError::MultipleTreasuryOutputs);
            }
            treasury_output = Some((index, output_value(output)));
        }

        if state.ctip.is_some() && current_ctip_inputs == 0 && treasury_output.is_some() {
            return Err(ElementsSlot24ReplayError::ParallelTreasuryOutput);
        }
        if state.ctip.is_some() && current_ctip_inputs == 1 && treasury_output.is_none() {
            return Err(ElementsSlot24ReplayError::CtipSpentWithoutReplacement);
        }
        if (state.ctip.is_some() && current_ctip_inputs == 0)
            || (state.ctip.is_none() && treasury_output.is_none())
        {
            continue;
        }
        // Duplicate transaction inputs were already rejected by the exact
        // parser; retain the explicit check as a state-machine invariant.
        if current_ctip_inputs > 1 {
            return Err(ElementsSlot24ReplayError::MalformedState);
        }

        let old_value = state.ctip.map_or(0, |ctip| ctip.value_sat);
        let (output_index, new_value) = treasury_output
            .expect("a CTIP transition reaching this branch has one treasury output");
        if new_value == old_value {
            return Err(ElementsSlot24ReplayError::ZeroCtipDelta);
        }
        if new_value < old_value {
            // Full M3/M4/M6 vote replay is deliberately absent. A decrease is
            // never guessed or optimistically accepted.
            return Err(ElementsSlot24ReplayError::CtipDecreaseUnsupported);
        }
        let address = transaction
            .outputs
            .get(output_index + 1)
            .and_then(|output| extract_single_op_return_push(output.script))
            .ok_or(ElementsSlot24ReplayError::MissingDepositAddress)?;
        let value_sat = new_value
            .checked_sub(old_value)
            .ok_or(ElementsSlot24ReplayError::AmountOverflow)?;
        let vout = u32::try_from(output_index)
            .map_err(|_| ElementsSlot24ReplayError::OutputIndexOverflow)?;
        let ctip = Slot24Ctip {
            txid: transaction.txid,
            vout,
            value_sat: new_value,
        };
        state.ctip = Some(ctip);
        if required_active_for_transactions && !address.is_empty() && address.len() <= 128 {
            deposits.push(MintableSlot24Deposit {
                outpoint: ctip,
                block_hash: parsed.metadata.block_hash,
                block_height: height,
                value_sat,
                elements_address: address.to_vec(),
            });
        }
    }
    Ok((deposits, matching_m8_requests))
}

/// Apply one exact, Merkle-verified parent block to the bounded slot-24 replay.
///
/// State changes are atomic: every error leaves `state` byte-for-byte
/// unchanged. `bmm_edge` is produced only when the frozen Elements proposal is
/// active *and* the successor coinbase carries the fork's strict minimal M7.
///
/// This function does not prove contextual Bitcoin validity, Signet
/// authorization, best-work membership, full BIP300 withdrawal voting, or
/// Elements validity. A caller must compose all of those checks before using
/// any returned edge or deposit as bridge authorization.
pub fn apply_merkle_bound_elements_slot24_parent_block(
    state: &mut ElementsSlot24ReplayState,
    serialized_block: &[u8],
) -> Result<ElementsSlot24BlockEffects, ElementsSlot24ReplayError> {
    state.validate()?;
    let parsed = parse_and_verify_block(serialized_block)?;
    if state.next_height != 0 && parsed.metadata.header.previous_block != state.tip_hash {
        return Err(ElementsSlot24ReplayError::BrokenParentLink);
    }
    if state.next_height == 0 && parsed.metadata.header.previous_block != BlockHash::ZERO {
        return Err(ElementsSlot24ReplayError::BrokenParentLink);
    }
    let height = state.next_height;
    let mut next = state.clone();

    apply_coinbase_messages(&mut next, &parsed, height)?;
    let observed_m7 = observe_slot24_m7(&parsed)?;
    let (deposits, matching_m8_requests) =
        apply_transactions(&mut next, &parsed, height, observed_m7)?;

    if next.required_activation.is_some()
        && next.active_proposal_hash != Some(next.config.required_proposal_hash)
    {
        return Err(ElementsSlot24ReplayError::RequiredProposalReplaced);
    }

    let required_proposal_active = next.required_proposal_is_active();
    let bmm_edge = observed_m7
        .filter(|m7| required_proposal_active && m7.canonical_for_elements)
        .map(|m7| ElementsSlot24BmmEdge {
            parent_block_hash: parsed.metadata.header.previous_block,
            successor_block_hash: parsed.metadata.block_hash,
            successor_height: height,
            coinbase_txid: parsed.metadata.coinbase_txid,
            m7_output_index: m7.output_index,
            committed_child_hash: m7.child_hash,
        });

    next.tip_hash = parsed.metadata.block_hash;
    next.next_height = height
        .checked_add(1)
        .ok_or(ElementsSlot24ReplayError::HeightOverflow)?;
    next.validate()?;
    *state = next;

    Ok(ElementsSlot24BlockEffects {
        deposits,
        bmm_edge,
        matching_m8_requests,
        saw_slot24_m7: observed_m7.is_some(),
        required_proposal_active,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{double_sha256, BitcoinHeader};

    fn push(payload: &[u8], nonminimal: bool) -> Vec<u8> {
        assert!(payload.len() <= u8::MAX as usize);
        let mut script = vec![OP_RETURN];
        if nonminimal {
            script.extend_from_slice(&[0x4c, payload.len() as u8]);
        } else {
            script.push(payload.len() as u8);
        }
        script.extend_from_slice(payload);
        script
    }

    fn m1(description: &[u8]) -> Vec<u8> {
        let mut payload = Vec::from(M1_TAG);
        payload.push(ELEMENTS_DRIVECHAIN_SLOT);
        payload.extend_from_slice(description);
        push(&payload, false)
    }

    fn m2(proposal_hash: [u8; 32]) -> Vec<u8> {
        let mut payload = Vec::from(M2_TAG);
        payload.push(ELEMENTS_DRIVECHAIN_SLOT);
        payload.extend_from_slice(&proposal_hash);
        push(&payload, false)
    }

    fn m7(child_hash: BlockHash, nonminimal: bool) -> Vec<u8> {
        let mut payload = Vec::from(M7_TAG);
        payload.push(ELEMENTS_DRIVECHAIN_SLOT);
        payload.extend_from_slice(&child_hash.to_internal_bytes());
        push(&payload, nonminimal)
    }

    fn m8(child_hash: BlockHash, previous_hash: BlockHash) -> Vec<u8> {
        let mut payload = Vec::from(M8_TAG);
        payload.push(ELEMENTS_DRIVECHAIN_SLOT);
        payload.extend_from_slice(&child_hash.to_internal_bytes());
        payload.extend_from_slice(&previous_hash.to_internal_bytes());
        push(&payload, false)
    }

    fn treasury() -> Vec<u8> {
        vec![OP_DRIVECHAIN, 1, ELEMENTS_DRIVECHAIN_SLOT, OP_TRUE]
    }

    fn transaction(
        input: (BlockHash, u32),
        script_sig: &[u8],
        outputs: &[(u64, Vec<u8>)],
    ) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&2i32.to_le_bytes());
        tx.push(1);
        tx.extend_from_slice(&input.0.to_internal_bytes());
        tx.extend_from_slice(&input.1.to_le_bytes());
        tx.push(script_sig.len() as u8);
        tx.extend_from_slice(script_sig);
        tx.extend_from_slice(&u32::MAX.to_le_bytes());
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
        let mut outputs = outputs
            .iter()
            .cloned()
            .map(|script| (0, script))
            .collect::<Vec<_>>();
        if outputs.is_empty() {
            outputs.push((0, Vec::new()));
        }
        transaction((BlockHash::ZERO, u32::MAX), &[1, 1], &outputs)
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
        let mut header = [0; 80];
        header[..4].copy_from_slice(&1i32.to_le_bytes());
        header[4..36].copy_from_slice(&previous.to_internal_bytes());
        header[36..68].copy_from_slice(&root.to_internal_bytes());
        header[68..72].copy_from_slice(&(1_700_000_000 + nonce).to_le_bytes());
        header[72..76].copy_from_slice(&0x207f_ffffu32.to_le_bytes());
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        let mut bytes = Vec::from(header);
        bytes.push(transactions.len() as u8);
        for tx in transactions {
            bytes.extend_from_slice(tx);
        }
        bytes
    }

    fn apply(
        state: &mut ElementsSlot24ReplayState,
        coinbase_outputs: &[Vec<u8>],
        ordinary: &[Vec<u8>],
    ) -> Result<ElementsSlot24BlockEffects, ElementsSlot24ReplayError> {
        let mut transactions = vec![coinbase(coinbase_outputs)];
        transactions.extend_from_slice(ordinary);
        let raw = block(state.tip_hash(), state.next_height(), &transactions);
        apply_merkle_bound_elements_slot24_parent_block(state, &raw)
    }

    fn test_state(required_description: &[u8]) -> ElementsSlot24ReplayState {
        let config = ElementsSlot24ReplayConfig::from_manifest_bound_identity(
            double_sha256(required_description),
            10,
            5,
            10,
            5,
        )
        .expect("test config");
        ElementsSlot24ReplayState::before_parent_genesis(config).expect("empty state")
    }

    fn activate(
        state: &mut ElementsSlot24ReplayState,
        description: &[u8],
    ) -> Result<(), ElementsSlot24ReplayError> {
        let proposal_hash = double_sha256(description);
        apply(state, &[m1(description), m2(proposal_hash)], &[])?;
        for _ in 0..6 {
            apply(state, &[m2(proposal_hash)], &[])?;
        }
        Ok(())
    }

    #[test]
    fn frozen_proposal_hash_matches_elements_identity() {
        let description_hex = concat!(
            "0008456c656d656e7473456c656d656e7473204472697665636861696e207631",
            "3b206e617469766520555344443b207265706c61792076323b2053696d706c69",
            "63697479206163746976653b20736c6f74203234a8ec2ac4113afc9f4f964fc2",
            "7439fd0cab5bb556b050a98e62e0a027ac2f5066f49d0cbac06d5a79012d6dc3",
            "43d96b5181a1d00d"
        );
        let description = description_hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let nibble = |byte| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("identity fixture is lowercase hex"),
                };
                (nibble(pair[0]) << 4) | nibble(pair[1])
            })
            .collect::<Vec<_>>();
        assert_eq!(
            double_sha256(&description),
            ELEMENTS_V1_REQUIRED_PROPOSAL_HASH_INTERNAL
        );
    }

    #[test]
    fn pending_proposal_bound_is_derived_from_block_weight_and_age() {
        let config = ElementsSlot24ReplayConfig::elements_v1();
        assert_eq!(ELEMENTS_V1_MAX_LIVE_PROPOSAL_BLOCKS, 11);
        assert_eq!(
            MAX_PENDING_SLOT24_PROPOSALS,
            BITCOIN_MAX_COINBASE_OUTPUTS * 11
        );
        let derived = config.maximum_pending_proposals().expect("derived bound");
        assert_eq!(derived, MAX_PENDING_SLOT24_PROPOSALS);
        assert!(
            derived > 16_384,
            "a valid maximum-weight block must not hit the former arbitrary cap"
        );
        assert!(derived >= BITCOIN_MAX_COINBASE_OUTPUTS);
    }

    #[test]
    fn proposal_activation_matches_elements_differential_vector() {
        // Mirrors `drivechain_parent_proposal_replay_matches_enforcer_rules`:
        // same-block ACK ignored, threshold is strictly greater-than five.
        let description = b"elements";
        let proposal_hash = double_sha256(description);
        let mut state = test_state(description);
        apply(&mut state, &[m1(description), m2(proposal_hash)], &[]).expect("proposal block");
        assert_eq!(state.pending_proposals().next().expect("pending").votes, 0);
        for _ in 0..5 {
            apply(&mut state, &[m2(proposal_hash)], &[]).expect("ACK");
        }
        assert!(!state.required_proposal_is_active());
        apply(&mut state, &[m2(proposal_hash)], &[]).expect("activating ACK");
        assert!(state.required_proposal_is_active());
        assert_eq!(state.required_activation().map(|entry| entry.0), Some(6));
    }

    #[test]
    fn proposal_expiry_and_replacement_fail_closed() {
        let required = b"required";
        let required_hash = double_sha256(required);
        let mut expiring = test_state(required);
        apply(&mut expiring, &[m1(required)], &[]).expect("M1");
        for _ in 0..5 {
            apply(&mut expiring, &[], &[]).expect("age");
        }
        assert_eq!(expiring.pending_proposals().len(), 1);
        apply(&mut expiring, &[], &[]).expect("doomed");
        assert_eq!(expiring.pending_proposals().len(), 0);

        let mut active = test_state(required);
        activate(&mut active, required).expect("activate required");
        let replacement = b"replacement";
        let replacement_hash = double_sha256(replacement);
        apply(&mut active, &[m1(replacement)], &[]).expect("replacement M1");
        for _ in 0..5 {
            apply(&mut active, &[m2(replacement_hash)], &[]).expect("replacement ACK");
        }
        let before = active.clone();
        assert_eq!(
            apply(&mut active, &[m2(replacement_hash)], &[]),
            Err(ElementsSlot24ReplayError::RequiredProposalReplaced)
        );
        assert_eq!(active, before, "failed transition must be atomic");
        assert_eq!(active.active_proposal_hash(), Some(required_hash));
    }

    #[test]
    fn ctip_increase_and_m7_m8_match_real_fork_rules() {
        let required = b"elements";
        let mut state = test_state(required);
        activate(&mut state, required).expect("activate");
        let child = BlockHash::from_internal_bytes([0x42; 32]);
        let prior_tip = state.tip_hash();
        let initial_funding = transaction(
            (BlockHash::from_internal_bytes([1; 32]), 0),
            &[],
            &[(6_000, treasury()), (0, push(b"elements", false))],
        );
        let request = transaction(
            (BlockHash::from_internal_bytes([2; 32]), 0),
            &[],
            &[(0, m8(child, prior_tip))],
        );
        let effects = apply(&mut state, &[m7(child, false)], &[initial_funding, request])
            .expect("CTIP + BMM");
        assert_eq!(effects.matching_m8_requests, 1);
        assert_eq!(effects.deposits.len(), 1);
        assert_eq!(effects.deposits[0].value_sat, 6_000);
        assert_eq!(effects.deposits[0].elements_address, b"elements");
        let edge = effects.bmm_edge.expect("authorized minimal M7");
        assert_eq!(edge.committed_child_hash, child);
        assert_eq!(edge.parent_block_hash, prior_tip);
        assert_eq!(edge.successor_block_hash, state.tip_hash());
    }

    #[test]
    fn m8_and_nonminimal_m7_boundaries_fail_closed() {
        let required = b"elements";
        let child = BlockHash::from_internal_bytes([3; 32]);
        let mut state = test_state(required);
        activate(&mut state, required).expect("activate");

        let request = transaction(
            (BlockHash::from_internal_bytes([4; 32]), 0),
            &[],
            &[(0, m8(child, state.tip_hash()))],
        );
        let before = state.clone();
        assert_eq!(
            apply(&mut state, &[], &[request]),
            Err(ElementsSlot24ReplayError::M8WithoutM7)
        );
        assert_eq!(state, before);

        let request = transaction(
            (BlockHash::from_internal_bytes([5; 32]), 0),
            &[],
            &[(0, m8(child, state.tip_hash()))],
        );
        let effects = apply(&mut state, &[m7(child, true)], &[request])
            .expect("enforcer recognizes nonminimal M7");
        assert!(effects.saw_slot24_m7);
        assert_eq!(effects.matching_m8_requests, 1);
        assert_eq!(effects.bmm_edge, None, "Elements fork requires minimal M7");
    }

    #[test]
    fn fabricated_ctip_transitions_are_rejected_atomically() {
        // Mirrors `drivechain_parent_ctip_replay_rejects_fabricated_transitions`.
        let required = b"elements";
        let mut state = test_state(required);
        activate(&mut state, required).expect("activate");
        let funding = transaction(
            (BlockHash::from_internal_bytes([6; 32]), 0),
            &[],
            &[(5_000, treasury()), (0, push(b"elements", false))],
        );
        apply(&mut state, &[], &[funding]).expect("initial CTIP");
        let ctip = state.ctip().expect("CTIP");

        let parallel = transaction(
            (BlockHash::from_internal_bytes([7; 32]), 0),
            &[],
            &[(6_000, treasury()), (0, push(b"elements", false))],
        );
        let before = state.clone();
        assert_eq!(
            apply(&mut state, &[], &[parallel]),
            Err(ElementsSlot24ReplayError::ParallelTreasuryOutput)
        );
        assert_eq!(state, before);

        let decrease = transaction(
            (ctip.txid, ctip.vout),
            &[],
            &[(4_999, treasury()), (0, push(b"elements", false))],
        );
        assert_eq!(
            apply(&mut state, &[], &[decrease]),
            Err(ElementsSlot24ReplayError::CtipDecreaseUnsupported)
        );
        assert_eq!(state, before);

        let missing_address = transaction((ctip.txid, ctip.vout), &[], &[(6_000, treasury())]);
        assert_eq!(
            apply(&mut state, &[], &[missing_address]),
            Err(ElementsSlot24ReplayError::MissingDepositAddress)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn replay_rejects_wrong_parent_and_malformed_checkpoint() {
        let required = b"elements";
        let mut state = test_state(required);
        let txs = vec![coinbase(&[])];
        let wrong = block(BlockHash::from_internal_bytes([9; 32]), 0, &txs);
        assert_eq!(
            apply_merkle_bound_elements_slot24_parent_block(&mut state, &wrong),
            Err(ElementsSlot24ReplayError::BrokenParentLink)
        );

        assert_eq!(
            ElementsSlot24ReplayState::from_unverified_checkpoint_requires_manifest_binding(
                state.config,
                1,
                BlockHash::from_internal_bytes([1; 32]),
                None,
                None,
                vec![PendingSlot24Proposal {
                    proposal_hash: [2; 32],
                    proposal_height: 2,
                    votes: 0,
                }],
                None,
            ),
            Err(ElementsSlot24ReplayError::MalformedState)
        );

        // Keep a direct decode assertion so test fixtures cannot accidentally
        // build non-80-byte headers while still satisfying the block helper.
        assert!(BitcoinHeader::decode_exact(&wrong[..80]).is_ok());
    }
}
