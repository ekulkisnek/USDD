//! Bounded slot-24 BIP300/301 replay for the Elements Drivechain identity.
//!
//! This module is a bounded, no-std replay of the slot-24 path in the checked-in
//! LayerTwo enforcer. It covers M1/M2 activation, ordered M3/M4 withdrawal
//! voting, M5 deposits, exact native Elements withdrawals, canonical USDD
//! accumulator M6 withdrawals, and M7/M8.
//! It is deliberately restricted to histories replayed from the exact parent
//! genesis: every enforcer-recognized M1, M2, or M3 for another slot rejects the
//! whole block. That restriction keeps the global M4 vector exactly one entry
//! after activation; it is not a replacement for an all-256-slot replay.
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

use usdd_core::{burn_accumulator_empty, Hash32, OutPoint};

use crate::{
    double_sha256, extract_single_op_return_push,
    m6::{
        ActualM6Artifact, BlindedM6, Ctip, MinerBundleArtifact, NativeWithdrawalM6,
        M6_ROOT_PAYOUT_SATS,
    },
    BlockHash, BITCOIN_MAX_COINBASE_OUTPUTS, ELEMENTS_DRIVECHAIN_SLOT,
};

use super::{parse_and_verify_block, BlockStructureError, ParsedBlock, ParsedTransaction};

const M1_TAG: [u8; 4] = [0xd5, 0xe0, 0xc4, 0xaf];
const M2_TAG: [u8; 4] = [0xd6, 0xe1, 0xc5, 0xdf];
const M3_TAG: [u8; 4] = [0xd4, 0x5a, 0xa9, 0x43];
const M4_TAG: [u8; 4] = [0xd7, 0x7d, 0x17, 0x76];
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

/// Exact non-mainnet `Thresholds::SHORT` values in the checked-in enforcer.
pub const SLOT24_M6_MAX_AGE: u16 = 10;
pub const SLOT24_M6_INCLUSION_THRESHOLD: u16 = 5;
pub const SLOT24_M6_REQUIRED_SCORE: u16 = SLOT24_M6_INCLUSION_THRESHOLD + 1;

/// During coinbase processing, the enforcer adds this block's M3 messages
/// before expiring entries which have just reached age eleven. The temporary
/// transition state can therefore span twelve creation heights even though the
/// persisted post-block state spans only ages `0..=10`. Every M3 occupies one
/// coinbase output, so this is a history-derived ceiling rather than an
/// arbitrary eviction limit.
pub const MAX_PENDING_SLOT24_M6IDS: usize =
    BITCOIN_MAX_COINBASE_OUTPUTS * (SLOT24_M6_MAX_AGE as usize + 2);

/// Frozen internal/wire byte order of the sole installed Elements V7 proposal.
///
/// Reversing these bytes produces the display hash
/// `169a8a4dc3b3c57df20620306d05486bedadf5aa2ddee2314ee1313bf5ccaab8`
/// from `elements_drivechain_identity.h`.
pub const ELEMENTS_V1_REQUIRED_PROPOSAL_HASH_INTERNAL: [u8; 32] = [
    0xb8, 0xaa, 0xcc, 0xf5, 0x3b, 0x31, 0xe1, 0x4e, 0x31, 0xe2, 0xde, 0x2d, 0xaa, 0xf5, 0xad, 0xed,
    0x6b, 0x48, 0x05, 0x6d, 0x30, 0x20, 0x06, 0xf2, 0x7d, 0xc5, 0xb3, 0xc3, 0x4d, 0x8a, 0x9a, 0x16,
];

/// Maximum creation-height window for a still-live Elements V1 proposal.
pub const ELEMENTS_V1_MAX_LIVE_PROPOSAL_BLOCKS: usize = 10 + 1;

/// Consensus-derived upper bound while processing slot-24 proposals.
///
/// The block parser proves that a coinbase has at most
/// `BITCOIN_MAX_COINBASE_OUTPUTS` outputs. The frozen enforcer inserts current
/// M1s before its failure pass removes age-eleven proposals, so a transition
/// can temporarily span twelve creation heights. Multiplying those independent
/// maxima is deliberately permissive but cannot be exceeded by a valid parsed
/// history.
pub const MAX_PENDING_SLOT24_PROPOSALS: usize =
    BITCOIN_MAX_COINBASE_OUTPUTS * (ELEMENTS_V1_MAX_LIVE_PROPOSAL_BLOCKS + 1);

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
        // The enforcer inserts this block's M1s before expiring proposals, so
        // the in-transition bound needs one height beyond the persisted live
        // window `0..=max_age`.
        .checked_add(2)
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

/// An M6id uses RPC/display byte order, matching `MinerBundleArtifact::m6id`.
/// The M3 wire payload is reversed exactly once when it enters this state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingSlot24M6id {
    pub m6id: Hash32,
    pub proposal_height: u32,
    pub score: u16,
}

/// Effective slot-24 action stored for BIP300 M4 `RepeatPrevious`.
///
/// The checked-in enforcer stores the prior block's effective diff, not merely
/// its encoded M4. An upvote therefore remains here even if that block later
/// spent or expired its target; repeating it then fails closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveSlot24M4 {
    Upvote { m6id: Hash32 },
    Alarm,
}

/// Immutable cross-domain identity against which every accumulator artifact is
/// checked. The caller must bind these values to the frozen deployment
/// manifest before attaching them to replay state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot24AccumulatorIdentity {
    pub bitcoin_genesis: Hash32,
    pub elements_genesis: Hash32,
    pub usdd_asset: Hash32,
    pub vault_id: Hash32,
}

impl Slot24AccumulatorIdentity {
    fn validate(self) -> Result<(), ElementsSlot24ReplayError> {
        if self.bitcoin_genesis == Hash32::ZERO
            || self.elements_genesis == Hash32::ZERO
            || self.usdd_asset == Hash32::ZERO
            || self.vault_id == Hash32::ZERO
        {
            return Err(ElementsSlot24ReplayError::InvalidAccumulatorIdentity);
        }
        Ok(())
    }

    fn matches(self, artifact: &MinerBundleArtifact) -> bool {
        artifact.bitcoin_genesis == self.bitcoin_genesis
            && artifact.elements_genesis == self.elements_genesis
            && artifact.usdd_asset == self.usdd_asset
            && artifact.vault_id == self.vault_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot24ApprovedRoot {
    pub claim_count: u64,
    pub claim_root: Hash32,
}

impl Slot24ApprovedRoot {
    pub fn empty() -> Self {
        Self {
            claim_count: 0,
            claim_root: burn_accumulator_empty(64).expect("fixed burn-tree depth"),
        }
    }

    fn validate(self) -> Result<(), ElementsSlot24ReplayError> {
        if self.claim_root == Hash32::ZERO
            || (self.claim_count == 0) != (self.claim_root == Self::empty().claim_root)
        {
            return Err(ElementsSlot24ReplayError::InvalidApprovedRoot);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovedSlot24AccumulatorM6 {
    pub m6id: Hash32,
    pub transaction_id: BlockHash,
    pub block_hash: BlockHash,
    pub block_height: u32,
    pub fee_sats: u64,
    pub prior_root: Slot24ApprovedRoot,
    pub next_root: Slot24ApprovedRoot,
}

/// One miner-approved native Elements pegged-coin withdrawal. The replay
/// authenticates the exact `ELWD` transaction and approved M6id. It does not
/// validate the referenced Elements burn; the miner threshold is the accepted
/// BIP300 authorization boundary for this transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedSlot24NativeWithdrawalM6 {
    pub m6id: Hash32,
    pub transaction_id: BlockHash,
    pub block_hash: BlockHash,
    pub block_height: u32,
    pub elements_genesis: Hash32,
    pub burn_outpoint: OutPoint,
    pub parent_fee_sats: u64,
    pub payout_sats: u64,
    pub destination_script: Vec<u8>,
    /// Native pegged-coin withdrawals never change the USDD root.
    pub preserved_usdd_root: Slot24ApprovedRoot,
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
    pending_m6ids: Vec<PendingSlot24M6id>,
    successful_m6ids: BTreeSet<Hash32>,
    previous_effective_m4: Option<EffectiveSlot24M4>,
    accumulator_identity: Option<Slot24AccumulatorIdentity>,
    approved_root: Option<Slot24ApprovedRoot>,
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
            pending_m6ids: Vec::new(),
            successful_m6ids: BTreeSet::new(),
            previous_effective_m4: None,
            accumulator_identity: None,
            approved_root: None,
        })
    }

    /// Restore a checkpoint whose complete state is already manifest-bound.
    ///
    /// Omitting pending proposals is unsound: an old M1 can be ACKed after the
    /// checkpoint. For that reason this constructor requires the entire live
    /// pending set and advertises that it does not authenticate its inputs.
    /// It also cannot prove that no other sidechain slot was activated before
    /// the checkpoint, so it cannot establish the sole-slot production
    /// invariant. Production authorization must use the genesis-derived API.
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
            pending_m6ids: Vec::new(),
            successful_m6ids: BTreeSet::new(),
            previous_effective_m4: None,
            accumulator_identity: None,
            approved_root: None,
        };
        state.validate()?;
        Ok(state)
    }

    /// Restore the complete slot-24 replay, including ordered withdrawal vote
    /// state and accumulator checkpoint. Every field is unauthenticated until
    /// compared with a frozen manifest and an authenticated ancestor history.
    /// Even a manifest-bound value cannot prove the omitted state of the other
    /// 255 slots; this constructor is therefore diagnostic, not a production
    /// bootstrap for the sole-slot replay.
    #[allow(clippy::too_many_arguments)]
    pub fn from_unverified_usdd_checkpoint_requires_manifest_binding(
        config: ElementsSlot24ReplayConfig,
        processed_height: u32,
        tip_hash: BlockHash,
        active_proposal_hash: Option<[u8; 32]>,
        required_activation: Option<(u32, BlockHash)>,
        pending_proposals: Vec<PendingSlot24Proposal>,
        ctip: Option<Slot24Ctip>,
        pending_m6ids: Vec<PendingSlot24M6id>,
        successful_m6ids: Vec<Hash32>,
        previous_effective_m4: Option<EffectiveSlot24M4>,
        accumulator_identity: Slot24AccumulatorIdentity,
        approved_root: Slot24ApprovedRoot,
    ) -> Result<Self, ElementsSlot24ReplayError> {
        let mut state = Self::from_unverified_checkpoint_requires_manifest_binding(
            config,
            processed_height,
            tip_hash,
            active_proposal_hash,
            required_activation,
            pending_proposals,
            ctip,
        )?;
        accumulator_identity.validate()?;
        approved_root.validate()?;
        state.pending_m6ids = pending_m6ids;
        let successful_m6id_count = successful_m6ids.len();
        state.successful_m6ids = successful_m6ids.into_iter().collect();
        if state.successful_m6ids.len() != successful_m6id_count {
            return Err(ElementsSlot24ReplayError::MalformedState);
        }
        state.previous_effective_m4 = previous_effective_m4;
        state.accumulator_identity = Some(accumulator_identity);
        state.approved_root = Some(approved_root);
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

    pub fn pending_m6ids(&self) -> impl ExactSizeIterator<Item = PendingSlot24M6id> + '_ {
        self.pending_m6ids.iter().copied()
    }

    pub fn successful_m6ids(&self) -> impl ExactSizeIterator<Item = Hash32> + '_ {
        self.successful_m6ids.iter().copied()
    }

    pub const fn previous_effective_m4(&self) -> Option<EffectiveSlot24M4> {
        self.previous_effective_m4
    }

    pub const fn accumulator_identity(&self) -> Option<Slot24AccumulatorIdentity> {
        self.accumulator_identity
    }

    pub const fn approved_root(&self) -> Option<Slot24ApprovedRoot> {
        self.approved_root
    }

    /// Attach a manifest-authenticated accumulator checkpoint to a replay
    /// clone. This is not a chain transition and therefore has an explicit
    /// trust-boundary name. It is accepted only before any M3/M4 state exists.
    pub fn bind_usdd_accumulator_checkpoint_requires_manifest_binding(
        &mut self,
        identity: Slot24AccumulatorIdentity,
        approved_root: Slot24ApprovedRoot,
    ) -> Result<(), ElementsSlot24ReplayError> {
        identity.validate()?;
        approved_root.validate()?;
        if self.accumulator_identity.is_some()
            || self.approved_root.is_some()
            || !self.pending_m6ids.is_empty()
            || self.previous_effective_m4.is_some()
        {
            return Err(ElementsSlot24ReplayError::AccumulatorAlreadyBound);
        }
        self.accumulator_identity = Some(identity);
        self.approved_root = Some(approved_root);
        self.validate()
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
        if self.pending_m6ids.len() > MAX_PENDING_SLOT24_M6IDS {
            return Err(ElementsSlot24ReplayError::PendingM6idLimitExceeded);
        }
        match (self.accumulator_identity, self.approved_root) {
            (Some(identity), Some(root)) => {
                identity.validate()?;
                root.validate()?;
            }
            (None, None) => {}
            _ => return Err(ElementsSlot24ReplayError::MalformedState),
        }
        if self.next_height == 0 {
            if self.tip_hash != BlockHash::ZERO
                || self.active_proposal_hash.is_some()
                || self.required_activation.is_some()
                || !self.pending_proposals.is_empty()
                || self.ctip.is_some()
                || !self.pending_m6ids.is_empty()
                || !self.successful_m6ids.is_empty()
                || self.previous_effective_m4.is_some()
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
        if self.active_proposal_hash.is_none()
            && (!self.pending_m6ids.is_empty()
                || !self.successful_m6ids.is_empty()
                || self.previous_effective_m4.is_some())
        {
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
            if ctip.txid == BlockHash::ZERO || ctip.value_sat > MAX_MONEY_SATOSHIS {
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

        let mut seen_m6ids = BTreeSet::new();
        let mut prior_proposal_height = None;
        for pending in &self.pending_m6ids {
            if pending.m6id == Hash32::ZERO
                || !seen_m6ids.insert(pending.m6id)
                || pending.proposal_height > tip_height
                || tip_height - pending.proposal_height > u32::from(SLOT24_M6_MAX_AGE)
                || prior_proposal_height.is_some_and(|prior| pending.proposal_height < prior)
            {
                return Err(ElementsSlot24ReplayError::MalformedState);
            }
            prior_proposal_height = Some(pending.proposal_height);
        }
        // Upstream permits an M3 to repropose an M6id that succeeded earlier
        // on the active branch. Keep successful IDs only as bridge audit
        // history; overlap with the live pending set is therefore valid.
        if self.successful_m6ids.contains(&Hash32::ZERO) {
            return Err(ElementsSlot24ReplayError::MalformedState);
        }
        if matches!(
            self.previous_effective_m4,
            Some(EffectiveSlot24M4::Upvote { m6id }) if m6id == Hash32::ZERO
        ) {
            return Err(ElementsSlot24ReplayError::MalformedState);
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
    pub approved_accumulator_m6: Option<ApprovedSlot24AccumulatorM6>,
    pub approved_native_withdrawal_m6: Option<ApprovedSlot24NativeWithdrawalM6>,
    pub bmm_edge: Option<ElementsSlot24BmmEdge>,
    pub matching_m8_requests: u32,
    pub effective_m4: Option<EffectiveSlot24M4>,
    pub expired_m6ids: Vec<Hash32>,
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
    PendingM6idLimitExceeded,
    DuplicateProposalMessage,
    MultipleAckMessages,
    M1ForUnsupportedSlot,
    M2ForUnsupportedSlot,
    M3ForUnsupportedSlot,
    M3ForInactiveSlot,
    M3BundleAlreadyPending,
    DuplicateM4,
    M4InvalidVoteCount,
    M4UpvoteMissingBundle,
    M4TwoBytesWithinByteRange,
    M4RepeatMissingBundle,
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
    MissingCanonicalM6Artifact,
    UnexpectedCanonicalM6Artifact,
    InvalidCanonicalM6Artifact,
    CanonicalM6IdentityMismatch,
    CanonicalM6RootMismatch,
    CanonicalM6TransactionMismatch,
    CanonicalM6NotPending,
    CanonicalM6InsufficientScore,
    RequiredProposalInactiveForM6,
    NativeWithdrawalIdentityMismatch,
    NativeWithdrawalTransactionMismatch,
    NativeWithdrawalM6NotPending,
    NativeWithdrawalM6InsufficientScore,
    UnknownSlot24M6,
    AmbiguousSlot24M6,
    /// Bridge authorization policy, not an enforcer consensus rule. Upstream
    /// may accept sequential M6s; V1 declines to authorize such a block.
    MultipleSuccessfulSlot24M6s,
    InvalidAccumulatorIdentity,
    InvalidApprovedRoot,
    AccumulatorAlreadyBound,
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
    Proposal { slot: u8, proposal_hash: [u8; 32] },
    Ack { slot: u8, proposal_hash: [u8; 32] },
}

impl ParentMessage {
    fn slot(self) -> u8 {
        match self {
            Self::Proposal { slot, .. } | Self::Ack { slot, .. } => slot,
        }
    }

    fn unsupported_slot_error(self) -> ElementsSlot24ReplayError {
        match self {
            Self::Proposal { .. } => ElementsSlot24ReplayError::M1ForUnsupportedSlot,
            Self::Ack { .. } => ElementsSlot24ReplayError::M2ForUnsupportedSlot,
        }
    }
}

/// Parse exactly the M1/M2 forms recognized by the checked-in enforcer.
///
/// M1 consumes a one-byte slot followed by an arbitrary (possibly empty)
/// description. M2 must contain exactly one slot byte and one 32-byte hash.
/// `extract_single_op_return_push` also mirrors the enforcer's acceptance of a
/// non-minimal push while rejecting trailing script instructions.
fn parse_parent_message(script: &[u8]) -> Option<ParentMessage> {
    let payload = extract_single_op_return_push(script)?;
    if payload.len() < 5 {
        return None;
    }
    if payload[..4] == M1_TAG {
        return Some(ParentMessage::Proposal {
            slot: payload[4],
            proposal_hash: double_sha256(&payload[5..]),
        });
    }
    if payload.len() == 4 + 1 + 32 && payload[..4] == M2_TAG {
        let mut hash = [0; 32];
        hash.copy_from_slice(&payload[5..]);
        return Some(ParentMessage::Ack {
            slot: payload[4],
            proposal_hash: hash,
        });
    }
    None
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum M4Message {
    RepeatPrevious,
    OneByte(Vec<u8>),
    TwoBytes(Vec<u16>),
    LeadingBy50,
}

fn parse_m3(script: &[u8]) -> Option<(u8, Hash32)> {
    let payload = extract_single_op_return_push(script)?;
    if payload.len() != 4 + 1 + 32 || payload[..4] != M3_TAG {
        return None;
    }
    let slot = payload[4];
    // `bitcoin::Txid::to_byte_array` is the internal hash byte order carried by
    // M3. Canonical m6.rs artifacts expose RPC/display order.
    let mut display = [0u8; 32];
    display.copy_from_slice(&payload[5..]);
    display.reverse();
    Some((slot, Hash32(display)))
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

/// Enforce the temporary, explicit one-slot model before mutating any replay
/// state. From exact genesis this proves that no accepted history can activate
/// another slot and silently change the enforcer's active-slot-ordered M4
/// vector. Malformed tag-like scripts remain ordinary outputs, as they do in
/// the checked-in enforcer.
fn reject_well_formed_non_slot24_coinbase_messages(
    parsed: &ParsedBlock<'_>,
) -> Result<(), ElementsSlot24ReplayError> {
    for output in &parsed.coinbase.outputs {
        if let Some(message) = parse_parent_message(output.script) {
            if message.slot() != ELEMENTS_DRIVECHAIN_SLOT {
                return Err(message.unsupported_slot_error());
            }
        }
        if let Some((slot, _)) = parse_m3(output.script) {
            if slot != ELEMENTS_DRIVECHAIN_SLOT {
                return Err(ElementsSlot24ReplayError::M3ForUnsupportedSlot);
            }
        }
    }
    Ok(())
}

fn pending_m6_index(state: &ElementsSlot24ReplayState, m6id: Hash32) -> Option<usize> {
    state
        .pending_m6ids
        .iter()
        .position(|pending| pending.m6id == m6id)
}

fn apply_m4_upvote(
    state: &mut ElementsSlot24ReplayState,
    target_index: usize,
) -> Result<Option<EffectiveSlot24M4>, ElementsSlot24ReplayError> {
    let target = state
        .pending_m6ids
        .get(target_index)
        .copied()
        .ok_or(ElementsSlot24ReplayError::M4UpvoteMissingBundle)?;
    if target.score == u16::MAX {
        return Ok(None);
    }
    for (index, pending) in state.pending_m6ids.iter_mut().enumerate() {
        if index == target_index {
            pending.score = pending
                .score
                .checked_add(1)
                .ok_or(ElementsSlot24ReplayError::VoteOverflow)?;
        } else {
            pending.score = pending.score.saturating_sub(1);
        }
    }
    Ok(Some(EffectiveSlot24M4::Upvote { m6id: target.m6id }))
}

fn apply_m4_alarm(state: &mut ElementsSlot24ReplayState) -> Option<EffectiveSlot24M4> {
    let mut changed = false;
    for pending in &mut state.pending_m6ids {
        changed |= pending.score != 0;
        pending.score = pending.score.saturating_sub(1);
    }
    changed.then_some(EffectiveSlot24M4::Alarm)
}

fn apply_m4_vote(
    state: &mut ElementsSlot24ReplayState,
    vote: u16,
) -> Result<Option<EffectiveSlot24M4>, ElementsSlot24ReplayError> {
    match vote {
        0xffff => Ok(None),
        0xfffe => Ok(apply_m4_alarm(state)),
        index => apply_m4_upvote(state, usize::from(index)),
    }
}

fn apply_m4_message(
    state: &mut ElementsSlot24ReplayState,
    message: &M4Message,
) -> Result<Option<EffectiveSlot24M4>, ElementsSlot24ReplayError> {
    // The frozen relay manifest asserts that slot 24 is the sole active slot.
    // This gives the generic enforcer's active-slot-ordered vote vector length
    // exactly zero before activation and exactly one afterwards.
    let expected_votes = usize::from(state.active_proposal_hash.is_some());
    match message {
        M4Message::OneByte(votes) => {
            if votes.len() != expected_votes {
                return Err(ElementsSlot24ReplayError::M4InvalidVoteCount);
            }
            if let Some(vote) = votes.first().copied() {
                let vote = match vote {
                    0xff => 0xffff,
                    0xfe => 0xfffe,
                    value => u16::from(value),
                };
                apply_m4_vote(state, vote)
            } else {
                Ok(None)
            }
        }
        M4Message::TwoBytes(votes) => {
            // Match the enforcer's dispatcher ordering: this encoding rule is
            // checked before the active-sidechain vector length.
            if votes.iter().all(|vote| *vote <= 253) {
                return Err(ElementsSlot24ReplayError::M4TwoBytesWithinByteRange);
            }
            if votes.len() != expected_votes {
                return Err(ElementsSlot24ReplayError::M4InvalidVoteCount);
            }
            if let Some(vote) = votes.first().copied() {
                apply_m4_vote(state, vote)
            } else {
                Ok(None)
            }
        }
        M4Message::LeadingBy50 => {
            if expected_votes == 0 || state.pending_m6ids.is_empty() {
                return Ok(None);
            }
            let mut highest_index = 0usize;
            let mut highest = 0u16;
            let mut second = 0u16;
            for (index, pending) in state.pending_m6ids.iter().enumerate() {
                if pending.score > highest {
                    second = highest;
                    highest = pending.score;
                    highest_index = index;
                } else if pending.score > second {
                    second = pending.score;
                }
            }
            if highest.saturating_sub(second) >= 50 && highest < u16::MAX {
                apply_m4_upvote(state, highest_index)
            } else {
                Ok(None)
            }
        }
        M4Message::RepeatPrevious => match state.previous_effective_m4 {
            None => Ok(None),
            Some(EffectiveSlot24M4::Alarm) => Ok(apply_m4_alarm(state)),
            Some(EffectiveSlot24M4::Upvote { m6id }) => {
                let index = pending_m6_index(state, m6id)
                    .ok_or(ElementsSlot24ReplayError::M4RepeatMissingBundle)?;
                apply_m4_upvote(state, index)
            }
        },
    }
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

fn encode_compact_size(value: usize, out: &mut Vec<u8>) {
    if value < 0xfd {
        out.push(value as u8);
    } else if value <= usize::from(u16::MAX) {
        out.push(0xfd);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        out.push(0xfe);
        out.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&(value as u64).to_le_bytes());
    }
}

/// Reproduce the enforcer's inverse M6 blinding over an already parsed actual
/// transaction. The sole CTIP input is removed and treasury vout zero becomes
/// the zero-valued, eight-byte big-endian fee commitment; every other field is
/// preserved in non-witness serialization.
fn derive_blinded_m6_legacy(
    transaction: &ParsedTransaction<'_>,
    previous_ctip_value: u64,
) -> Result<(Vec<u8>, Hash32), ElementsSlot24ReplayError> {
    if transaction.inputs.len() != 1
        || transaction.outputs.is_empty()
        || !is_slot24_treasury(transaction.outputs[0].script)
    {
        return Err(ElementsSlot24ReplayError::UnknownSlot24M6);
    }
    let new_ctip_value = output_value(&transaction.outputs[0]);
    let payout_total = transaction.outputs[1..]
        .iter()
        .try_fold(0u64, |sum, output| {
            sum.checked_add(output_value(output))
                .ok_or(ElementsSlot24ReplayError::AmountOverflow)
        })?;
    let committed_total = new_ctip_value
        .checked_add(payout_total)
        .ok_or(ElementsSlot24ReplayError::AmountOverflow)?;
    let fee_sats = previous_ctip_value
        .checked_sub(committed_total)
        .ok_or(ElementsSlot24ReplayError::UnknownSlot24M6)?;

    let mut blinded = Vec::new();
    blinded.extend_from_slice(&transaction.version);
    blinded.push(0);
    encode_compact_size(transaction.outputs.len(), &mut blinded);

    blinded.extend_from_slice(&0u64.to_le_bytes());
    blinded.push(10);
    blinded.extend_from_slice(&[OP_RETURN, 8]);
    blinded.extend_from_slice(&fee_sats.to_be_bytes());
    for output in transaction.outputs.iter().skip(1) {
        blinded.extend_from_slice(&output.value);
        encode_compact_size(output.script.len(), &mut blinded);
        blinded.extend_from_slice(output.script);
    }
    blinded.extend_from_slice(&transaction.lock_time);

    let mut m6id = double_sha256(&blinded);
    m6id.reverse();
    Ok((blinded, Hash32(m6id)))
}

fn apply_coinbase_messages(
    state: &mut ElementsSlot24ReplayState,
    parsed: &ParsedBlock<'_>,
    height: u32,
) -> Result<(Option<EffectiveSlot24M4>, Vec<Hash32>), ElementsSlot24ReplayError> {
    let mut created_in_block = BTreeSet::new();
    let mut proposal_messages_in_block = BTreeSet::new();
    let mut saw_ack = false;
    let mut saw_m4 = false;
    let mut effective_m4 = None;

    for output in &parsed.coinbase.outputs {
        match parse_parent_message(output.script) {
            None => {}
            Some(message) if message.slot() != ELEMENTS_DRIVECHAIN_SLOT => {
                // The block-level preflight above makes this unreachable. Keep
                // the local guard so future call-path refactors fail closed.
                return Err(message.unsupported_slot_error());
            }
            Some(ParentMessage::Proposal { proposal_hash, .. }) => {
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
            Some(ParentMessage::Ack { proposal_hash, .. }) => {
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

        if let Some((slot, m6id)) = parse_m3(output.script) {
            if slot != ELEMENTS_DRIVECHAIN_SLOT {
                return Err(ElementsSlot24ReplayError::M3ForUnsupportedSlot);
            }
            if state.active_proposal_hash.is_none() {
                return Err(ElementsSlot24ReplayError::M3ForInactiveSlot);
            }
            if pending_m6_index(state, m6id).is_some() {
                return Err(ElementsSlot24ReplayError::M3BundleAlreadyPending);
            }
            if state.pending_m6ids.len() == MAX_PENDING_SLOT24_M6IDS {
                return Err(ElementsSlot24ReplayError::PendingM6idLimitExceeded);
            }
            state.pending_m6ids.push(PendingSlot24M6id {
                m6id,
                proposal_height: height,
                // Exact `PendingM6idInfo::new` behavior.
                score: 1,
            });
        }

        if let Some(message) = parse_m4(output.script) {
            if saw_m4 {
                return Err(ElementsSlot24ReplayError::DuplicateM4);
            }
            saw_m4 = true;
            effective_m4 = apply_m4_message(state, &message)?;
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

    // The checked-in enforcer applies M4 first and expires M6ids afterwards.
    // Keep the effective action even if its target expires below, because a
    // next-block RepeatPrevious must then reject that missing target.
    let mut expired_m6ids = Vec::new();
    state.pending_m6ids.retain(|pending| {
        let age = height.saturating_sub(pending.proposal_height);
        let live = age <= u32::from(SLOT24_M6_MAX_AGE);
        if !live {
            expired_m6ids.push(pending.m6id);
        }
        live
    });
    state.previous_effective_m4 = effective_m4;
    Ok((effective_m4, expired_m6ids))
}

fn apply_canonical_accumulator_m6(
    state: &mut ElementsSlot24ReplayState,
    transaction: &ParsedTransaction<'_>,
    artifact: &MinerBundleArtifact,
    old_ctip: Slot24Ctip,
    new_ctip_value: u64,
    block_hash: BlockHash,
    block_height: u32,
) -> Result<ApprovedSlot24AccumulatorM6, ElementsSlot24ReplayError> {
    if !state.required_proposal_is_active() {
        return Err(ElementsSlot24ReplayError::RequiredProposalInactiveForM6);
    }
    let identity = state
        .accumulator_identity
        .ok_or(ElementsSlot24ReplayError::InvalidAccumulatorIdentity)?;
    let prior_root = state
        .approved_root
        .ok_or(ElementsSlot24ReplayError::InvalidApprovedRoot)?;
    artifact
        .validate()
        .map_err(|_| ElementsSlot24ReplayError::InvalidCanonicalM6Artifact)?;
    if !identity.matches(artifact) {
        return Err(ElementsSlot24ReplayError::CanonicalM6IdentityMismatch);
    }
    if artifact.prior_claim_count != prior_root.claim_count
        || artifact.prior_claim_root != prior_root.claim_root
    {
        return Err(ElementsSlot24ReplayError::CanonicalM6RootMismatch);
    }
    let next_root = Slot24ApprovedRoot {
        claim_count: artifact.next_claim_count,
        claim_root: artifact.next_claim_root,
    };
    next_root.validate()?;

    let required_delta = artifact
        .fee_sats
        .checked_add(M6_ROOT_PAYOUT_SATS)
        .ok_or(ElementsSlot24ReplayError::InvalidCanonicalM6Artifact)?;
    if old_ctip.value_sat.checked_sub(new_ctip_value) != Some(required_delta) {
        return Err(ElementsSlot24ReplayError::CanonicalM6TransactionMismatch);
    }
    let canonical_prior_ctip = Ctip {
        outpoint: OutPoint {
            txid: Hash32(old_ctip.txid.to_display_bytes()),
            vout: old_ctip.vout,
        },
        value_sats: old_ctip.value_sat,
    };
    let actual = ActualM6Artifact::build(artifact.clone(), canonical_prior_ctip)
        .map_err(|_| ElementsSlot24ReplayError::InvalidCanonicalM6Artifact)?;
    actual
        .verify_transaction(transaction.serialized)
        .map_err(|_| ElementsSlot24ReplayError::CanonicalM6TransactionMismatch)?;
    if actual
        .transaction_id()
        .map_err(|_| ElementsSlot24ReplayError::CanonicalM6TransactionMismatch)?
        != Hash32(transaction.txid.to_display_bytes())
        || actual.successor_ctip_value() != new_ctip_value
    {
        return Err(ElementsSlot24ReplayError::CanonicalM6TransactionMismatch);
    }

    let m6id = artifact
        .m6id()
        .map_err(|_| ElementsSlot24ReplayError::InvalidCanonicalM6Artifact)?;
    let pending_index =
        pending_m6_index(state, m6id).ok_or(ElementsSlot24ReplayError::CanonicalM6NotPending)?;
    if state.pending_m6ids[pending_index].score <= SLOT24_M6_INCLUSION_THRESHOLD {
        return Err(ElementsSlot24ReplayError::CanonicalM6InsufficientScore);
    }

    // Mutate only after all artifact, transaction, vote, and transition checks.
    state.pending_m6ids.remove(pending_index);
    // Audit history only. Upstream does not make a paid M6id permanently
    // unavailable, so a repeated success is not a consensus error here.
    state.successful_m6ids.insert(m6id);
    state.approved_root = Some(next_root);
    Ok(ApprovedSlot24AccumulatorM6 {
        m6id,
        transaction_id: transaction.txid,
        block_hash,
        block_height,
        fee_sats: artifact.fee_sats,
        prior_root,
        next_root,
    })
}

fn apply_native_withdrawal_m6(
    state: &mut ElementsSlot24ReplayState,
    transaction: &ParsedTransaction<'_>,
    native: &NativeWithdrawalM6,
    old_ctip: Slot24Ctip,
    new_ctip_value: u64,
    block_hash: BlockHash,
    block_height: u32,
) -> Result<ApprovedSlot24NativeWithdrawalM6, ElementsSlot24ReplayError> {
    if !state.required_proposal_is_active() {
        return Err(ElementsSlot24ReplayError::RequiredProposalInactiveForM6);
    }
    let identity = state
        .accumulator_identity
        .ok_or(ElementsSlot24ReplayError::InvalidAccumulatorIdentity)?;
    let preserved_usdd_root = state
        .approved_root
        .ok_or(ElementsSlot24ReplayError::InvalidApprovedRoot)?;
    let reference = native.reference();
    if reference.sidechain_slot() != ELEMENTS_DRIVECHAIN_SLOT
        || reference.elements_genesis() != identity.elements_genesis
    {
        return Err(ElementsSlot24ReplayError::NativeWithdrawalIdentityMismatch);
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
        .map_err(|_| ElementsSlot24ReplayError::NativeWithdrawalTransactionMismatch)?;
    let successor = native
        .successor_ctip(&prior_ctip)
        .map_err(|_| ElementsSlot24ReplayError::NativeWithdrawalTransactionMismatch)?;
    if successor.value_sats != new_ctip_value
        || successor.outpoint.vout != 0
        || successor.outpoint.txid != Hash32(transaction.txid.to_display_bytes())
    {
        return Err(ElementsSlot24ReplayError::NativeWithdrawalTransactionMismatch);
    }

    let m6id = native.m6id();
    let pending_index = pending_m6_index(state, m6id)
        .ok_or(ElementsSlot24ReplayError::NativeWithdrawalM6NotPending)?;
    if state.pending_m6ids[pending_index].score <= SLOT24_M6_INCLUSION_THRESHOLD {
        return Err(ElementsSlot24ReplayError::NativeWithdrawalM6InsufficientScore);
    }

    // Root preservation is structural: native withdrawals remove only their
    // approved M6id and rotate CTIP. No accumulator field is assigned here.
    state.pending_m6ids.remove(pending_index);
    // Audit history only; see the accumulator path above.
    state.successful_m6ids.insert(m6id);
    debug_assert_eq!(state.approved_root, Some(preserved_usdd_root));
    Ok(ApprovedSlot24NativeWithdrawalM6 {
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
    })
}

type Slot24TransactionTransitionEffects = (
    Vec<MintableSlot24Deposit>,
    u32,
    Option<ApprovedSlot24AccumulatorM6>,
    Option<ApprovedSlot24NativeWithdrawalM6>,
);

fn apply_transactions(
    state: &mut ElementsSlot24ReplayState,
    parsed: &ParsedBlock<'_>,
    height: u32,
    observed_m7: Option<ObservedM7>,
    canonical_m6_artifact: Option<&MinerBundleArtifact>,
) -> Result<Slot24TransactionTransitionEffects, ElementsSlot24ReplayError> {
    let mut deposits = Vec::new();
    let mut matching_m8_requests = 0u32;
    let mut approved_accumulator_m6 = None;
    let mut approved_native_withdrawal_m6 = None;
    let mut artifact_consumed = false;
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
            if approved_accumulator_m6.is_some() || approved_native_withdrawal_m6.is_some() {
                return Err(ElementsSlot24ReplayError::MultipleSuccessfulSlot24M6s);
            }
            let old_ctip = state
                .ctip
                .ok_or(ElementsSlot24ReplayError::CtipDecreaseUnsupported)?;
            if output_index != 0 || transaction.inputs.len() != 1 {
                return Err(ElementsSlot24ReplayError::UnknownSlot24M6);
            }
            let (blinded_legacy, derived_m6id) =
                derive_blinded_m6_legacy(transaction, old_ctip.value_sat)?;
            let native = NativeWithdrawalM6::decode_legacy(&blinded_legacy).ok();
            let canonical_shape = BlindedM6::decode(&blinded_legacy).is_ok();
            let canonical_artifact_m6id = canonical_m6_artifact
                .map(|artifact| {
                    artifact
                        .m6id()
                        .map_err(|_| ElementsSlot24ReplayError::InvalidCanonicalM6Artifact)
                })
                .transpose()?;
            let artifact_matches = canonical_artifact_m6id == Some(derived_m6id);

            // A hash collision or future codec overlap must not let an actual
            // M6 select two state transitions. Likewise an unrelated supplied
            // artifact is never silently ignored for a native payment.
            if native.is_some() && artifact_matches {
                return Err(ElementsSlot24ReplayError::AmbiguousSlot24M6);
            }
            if artifact_matches || (canonical_shape && canonical_m6_artifact.is_some()) {
                let artifact = canonical_m6_artifact
                    .expect("matching artifact id requires a supplied artifact");
                let approved = apply_canonical_accumulator_m6(
                    state,
                    transaction,
                    artifact,
                    old_ctip,
                    new_value,
                    parsed.metadata.block_hash,
                    height,
                )?;
                approved_accumulator_m6 = Some(approved);
                artifact_consumed = true;
            } else if let Some(native) = native.as_ref() {
                let approved = apply_native_withdrawal_m6(
                    state,
                    transaction,
                    native,
                    old_ctip,
                    new_value,
                    parsed.metadata.block_hash,
                    height,
                )?;
                approved_native_withdrawal_m6 = Some(approved);
            } else if canonical_shape {
                return Err(if canonical_m6_artifact.is_some() {
                    ElementsSlot24ReplayError::CanonicalM6TransactionMismatch
                } else {
                    ElementsSlot24ReplayError::MissingCanonicalM6Artifact
                });
            } else {
                return Err(ElementsSlot24ReplayError::UnknownSlot24M6);
            }

            let ctip = Slot24Ctip {
                txid: transaction.txid,
                vout: u32::try_from(output_index)
                    .map_err(|_| ElementsSlot24ReplayError::OutputIndexOverflow)?,
                value_sat: new_value,
            };
            state.ctip = Some(ctip);
            continue;
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
    if canonical_m6_artifact.is_some() && !artifact_consumed {
        return Err(if approved_native_withdrawal_m6.is_some() {
            ElementsSlot24ReplayError::AmbiguousSlot24M6
        } else {
            ElementsSlot24ReplayError::UnexpectedCanonicalM6Artifact
        });
    }
    Ok((
        deposits,
        matching_m8_requests,
        approved_accumulator_m6,
        approved_native_withdrawal_m6,
    ))
}

/// Apply one exact, Merkle-verified parent block to the bounded slot-24 replay.
///
/// State changes are atomic: every error leaves `state` byte-for-byte
/// unchanged. `bmm_edge` is produced only when the frozen Elements proposal is
/// active *and* the successor coinbase carries the fork's strict minimal M7.
///
/// This function does not prove contextual Bitcoin validity, Signet
/// authorization, best-work membership, or BIP300 withdrawal approval. No
/// returned edge or deposit is USDD redemption authorization.
pub fn apply_merkle_bound_elements_slot24_parent_block(
    state: &mut ElementsSlot24ReplayState,
    serialized_block: &[u8],
) -> Result<ElementsSlot24BlockEffects, ElementsSlot24ReplayError> {
    let (next, effects) = apply_merkle_bound_elements_slot24_parent_block_owned_with_m6_artifact(
        state.clone(),
        serialized_block,
        None,
    )?;
    *state = next;
    Ok(effects)
}

/// Apply one block while supplying the sole canonical accumulator artifact
/// which may authorize a slot-24 CTIP decrease in that block. The artifact is
/// untrusted auxiliary data: its M6id, identity, prior/next root, fee, and exact
/// actual transaction are independently recomputed before state changes.
pub fn apply_merkle_bound_elements_slot24_parent_block_with_m6_artifact(
    state: &mut ElementsSlot24ReplayState,
    serialized_block: &[u8],
    canonical_m6_artifact: &MinerBundleArtifact,
) -> Result<ElementsSlot24BlockEffects, ElementsSlot24ReplayError> {
    let (next, effects) = apply_merkle_bound_elements_slot24_parent_block_owned_with_m6_artifact(
        state.clone(),
        serialized_block,
        Some(canonical_m6_artifact),
    )?;
    *state = next;
    Ok(effects)
}

/// Owned form used by composed consensus primitives. Consuming the prior
/// state avoids an additional full clone of the potentially large pending
/// proposal map. On failure the state is discarded, which is the desired
/// behavior for a proof execution that aborts fail-closed.
pub fn apply_merkle_bound_elements_slot24_parent_block_owned(
    next: ElementsSlot24ReplayState,
    serialized_block: &[u8],
) -> Result<(ElementsSlot24ReplayState, ElementsSlot24BlockEffects), ElementsSlot24ReplayError> {
    apply_merkle_bound_elements_slot24_parent_block_owned_with_m6_artifact(
        next,
        serialized_block,
        None,
    )
}

pub fn apply_merkle_bound_elements_slot24_parent_block_owned_with_m6_artifact(
    mut next: ElementsSlot24ReplayState,
    serialized_block: &[u8],
    canonical_m6_artifact: Option<&MinerBundleArtifact>,
) -> Result<(ElementsSlot24ReplayState, ElementsSlot24BlockEffects), ElementsSlot24ReplayError> {
    next.validate()?;
    let parsed = parse_and_verify_block(serialized_block)?;
    if next.next_height != 0 && parsed.metadata.header.previous_block != next.tip_hash {
        return Err(ElementsSlot24ReplayError::BrokenParentLink);
    }
    if next.next_height == 0 && parsed.metadata.header.previous_block != BlockHash::ZERO {
        return Err(ElementsSlot24ReplayError::BrokenParentLink);
    }
    let height = next.next_height;

    reject_well_formed_non_slot24_coinbase_messages(&parsed)?;
    let (effective_m4, expired_m6ids) = apply_coinbase_messages(&mut next, &parsed, height)?;
    let observed_m7 = observe_slot24_m7(&parsed)?;
    let (deposits, matching_m8_requests, approved_accumulator_m6, approved_native_withdrawal_m6) =
        apply_transactions(
            &mut next,
            &parsed,
            height,
            observed_m7,
            canonical_m6_artifact,
        )?;

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
    Ok((
        next,
        ElementsSlot24BlockEffects {
            deposits,
            approved_accumulator_m6,
            approved_native_withdrawal_m6,
            bmm_edge,
            matching_m8_requests,
            effective_m4,
            expired_m6ids,
            saw_slot24_m7: observed_m7.is_some(),
            required_proposal_active,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m6::NATIVE_WITHDRAWAL_REFERENCE_MAGIC;
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
        m1_for_slot(ELEMENTS_DRIVECHAIN_SLOT, description, false)
    }

    fn m1_for_slot(slot: u8, description: &[u8], nonminimal: bool) -> Vec<u8> {
        let mut payload = Vec::from(M1_TAG);
        payload.push(slot);
        payload.extend_from_slice(description);
        push(&payload, nonminimal)
    }

    fn m2(proposal_hash: [u8; 32]) -> Vec<u8> {
        m2_for_slot(ELEMENTS_DRIVECHAIN_SLOT, proposal_hash, false)
    }

    fn m2_for_slot(slot: u8, proposal_hash: [u8; 32], nonminimal: bool) -> Vec<u8> {
        let mut payload = Vec::from(M2_TAG);
        payload.push(slot);
        payload.extend_from_slice(&proposal_hash);
        push(&payload, nonminimal)
    }

    fn m3(m6id: Hash32) -> Vec<u8> {
        let mut payload = Vec::from(M3_TAG);
        payload.push(ELEMENTS_DRIVECHAIN_SLOT);
        let mut wire = m6id.0;
        wire.reverse();
        payload.extend_from_slice(&wire);
        push(&payload, false)
    }

    fn m3_for_slot(slot: u8, m6id: Hash32) -> Vec<u8> {
        let mut script = m3(m6id);
        // Minimal push: OP_RETURN, length, four-byte tag, then slot.
        script[2 + 4] = slot;
        script
    }

    fn m4_one(votes: &[u8]) -> Vec<u8> {
        let mut payload = Vec::from(M4_TAG);
        payload.push(1);
        payload.extend_from_slice(votes);
        push(&payload, false)
    }

    fn m4_two(votes: &[u16]) -> Vec<u8> {
        let mut payload = Vec::from(M4_TAG);
        payload.push(2);
        for vote in votes {
            payload.extend_from_slice(&vote.to_le_bytes());
        }
        push(&payload, false)
    }

    fn m4_repeat() -> Vec<u8> {
        let mut payload = Vec::from(M4_TAG);
        payload.push(0);
        push(&payload, false)
    }

    fn m4_leading_by_50() -> Vec<u8> {
        let mut payload = Vec::from(M4_TAG);
        payload.push(3);
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
        treasury_for_slot(ELEMENTS_DRIVECHAIN_SLOT)
    }

    fn treasury_for_slot(slot: u8) -> Vec<u8> {
        vec![OP_DRIVECHAIN, 1, slot, OP_TRUE]
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

    fn apply_with_artifact(
        state: &mut ElementsSlot24ReplayState,
        coinbase_outputs: &[Vec<u8>],
        ordinary: &[Vec<u8>],
        artifact: &MinerBundleArtifact,
    ) -> Result<ElementsSlot24BlockEffects, ElementsSlot24ReplayError> {
        let mut transactions = vec![coinbase(coinbase_outputs)];
        transactions.extend_from_slice(ordinary);
        let raw = block(state.tip_hash(), state.next_height(), &transactions);
        apply_merkle_bound_elements_slot24_parent_block_with_m6_artifact(state, &raw, artifact)
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
            .expect("native vector hex"),
        )
        .expect("canonical Elements native-withdrawal vector")
    }

    fn accumulator_identity() -> Slot24AccumulatorIdentity {
        Slot24AccumulatorIdentity {
            bitcoin_genesis: hash(1),
            // Explicit cross-language ELWD vector input, not a new production
            // network pin. The coordinated identity refreeze remains external.
            elements_genesis: native_withdrawal_vector().reference().elements_genesis(),
            usdd_asset: hash(3),
            vault_id: hash(4),
        }
    }

    fn bundle_from(prior: Slot24ApprovedRoot, next_byte: u8) -> MinerBundleArtifact {
        let identity = accumulator_identity();
        MinerBundleArtifact {
            bitcoin_genesis: identity.bitcoin_genesis,
            elements_genesis: identity.elements_genesis,
            usdd_asset: identity.usdd_asset,
            vault_id: identity.vault_id,
            prior_claim_count: prior.claim_count,
            prior_claim_root: prior.claim_root,
            next_claim_count: prior.claim_count + 1,
            next_claim_root: hash(next_byte),
            fee_sats: 1_000,
        }
    }

    fn funded_accumulator_state() -> ElementsSlot24ReplayState {
        let required = b"elements";
        let mut state = test_state(required);
        activate(&mut state, required).expect("activate");
        let funding = transaction(
            (BlockHash::from_internal_bytes([0x71; 32]), 0),
            &[],
            &[(1_000_000, treasury()), (0, push(b"elements", false))],
        );
        apply(&mut state, &[], &[funding]).expect("initial CTIP");
        state
            .bind_usdd_accumulator_checkpoint_requires_manifest_binding(
                accumulator_identity(),
                Slot24ApprovedRoot::empty(),
            )
            .expect("manifest-bound accumulator");
        state
    }

    fn actual_m6_bytes(
        state: &ElementsSlot24ReplayState,
        artifact: &MinerBundleArtifact,
    ) -> Vec<u8> {
        let ctip = state.ctip().expect("funded CTIP");
        ActualM6Artifact::build(
            artifact.clone(),
            Ctip {
                outpoint: OutPoint {
                    txid: Hash32(ctip.txid.to_display_bytes()),
                    vout: ctip.vout,
                },
                value_sats: ctip.value_sat,
            },
        )
        .expect("actual M6")
        .transaction_bytes()
        .expect("actual bytes")
    }

    fn native_actual_m6_bytes(
        state: &ElementsSlot24ReplayState,
        native: &NativeWithdrawalM6,
    ) -> Vec<u8> {
        let ctip = state.ctip().expect("funded CTIP");
        native
            .actual_transaction_bytes(&Ctip {
                outpoint: OutPoint {
                    txid: Hash32(ctip.txid.to_display_bytes()),
                    vout: ctip.vout,
                },
                value_sats: ctip.value_sat,
            })
            .expect("native actual bytes")
    }

    fn approve_m6id(state: &mut ElementsSlot24ReplayState, m6id: Hash32) {
        apply(state, &[m3(m6id)], &[]).expect("M3");
        approve_m6id_from_existing(state, m6id);
    }

    fn approve_m6id_from_existing(state: &mut ElementsSlot24ReplayState, m6id: Hash32) {
        for _ in 0..5 {
            let index = pending_m6_index(state, m6id).expect("M6id pending");
            assert!(index <= u8::MAX as usize, "test M4 uses one-byte index");
            apply(state, &[m4_one(&[index as u8])], &[]).expect("M4 upvote");
        }
        let pending = state
            .pending_m6ids()
            .find(|pending| pending.m6id == m6id)
            .expect("approved pending M6");
        assert_eq!(pending.m6id, m6id);
        assert_eq!(pending.score, SLOT24_M6_REQUIRED_SCORE);
    }

    #[test]
    fn frozen_proposal_hash_matches_elements_identity() {
        let description_hex = concat!(
            "0008456c656d656e7473426c6f636b73747265616d7320656c656d656e74732c",
            "20656e61626c696e672073696d706c6963697479207363726970745883560531",
            "f013b9b27b2f9cfbac4f64ee5062b95ad3e21593a8f6916530b74bb2b7b20f3",
            "fbc4baf50e9d39f58661c6168e279d4"
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
    fn complete_non_slot24_m1_m2_m3_reject_the_whole_block_atomically() {
        let mut state = test_state(b"elements");
        let before = state.clone();
        let cases = [
            (
                m1_for_slot(23, b"another-drivechain", false),
                ElementsSlot24ReplayError::M1ForUnsupportedSlot,
            ),
            // The enforcer accepts non-minimal data pushes at this layer, so
            // the sole-slot preflight must recognize and reject this too.
            (
                m1_for_slot(23, b"", true),
                ElementsSlot24ReplayError::M1ForUnsupportedSlot,
            ),
            (
                m2_for_slot(23, [0x22; 32], false),
                ElementsSlot24ReplayError::M2ForUnsupportedSlot,
            ),
            (
                m3_for_slot(23, hash(0x33)),
                ElementsSlot24ReplayError::M3ForUnsupportedSlot,
            ),
        ];
        for (script, error) in cases {
            assert_eq!(apply(&mut state, &[script], &[]), Err(error));
            assert_eq!(state, before, "rejected block must not mutate replay state");
        }
    }

    #[test]
    fn malformed_or_non_coinbase_other_slot_messages_remain_ordinary_data() {
        // Missing M1's mandatory sidechain byte.
        let short_m1 = push(&M1_TAG, false);

        let mut short_m2 = Vec::from(M2_TAG);
        short_m2.push(23);
        short_m2.extend_from_slice(&[0x42; 31]);
        let short_m2 = push(&short_m2, false);

        let mut long_m3 = Vec::from(M3_TAG);
        long_m3.push(23);
        long_m3.extend_from_slice(&[0x43; 33]);
        let long_m3 = push(&long_m3, false);

        // A complete push followed by another instruction is not a coinbase
        // message in the checked-in enforcer.
        let mut trailing_instruction = m2_for_slot(23, [0x44; 32], false);
        trailing_instruction.push(OP_TRUE);

        let mut state = test_state(b"elements");
        apply(
            &mut state,
            &[short_m1, short_m2, long_m3, trailing_instruction],
            &[],
        )
        .expect("malformed tag-like scripts are ordinary coinbase outputs");

        // Message parsing is coinbase-only. The same complete M1 shape in an
        // ordinary transaction output must not be treated as activation data.
        let ordinary = transaction(
            (BlockHash::from_internal_bytes([0x51; 32]), 0),
            &[],
            &[(0, m1_for_slot(23, b"ordinary-output", false))],
        );
        apply(&mut state, &[], &[ordinary])
            .expect("message-shaped non-coinbase output is ordinary data");
        assert_eq!(state.active_proposal_hash(), None);
        assert_eq!(state.pending_proposals().len(), 0);
    }

    #[test]
    fn rejected_other_slots_cannot_change_the_single_entry_m4_vector() {
        let mut state = test_state(b"elements");
        let before = state.clone();
        assert_eq!(
            apply(
                &mut state,
                &[m1_for_slot(7, b"would-shift-m4-index", false)],
                &[],
            ),
            Err(ElementsSlot24ReplayError::M1ForUnsupportedSlot)
        );
        assert_eq!(state, before);

        activate(&mut state, b"elements").expect("activate sole slot 24");
        apply(&mut state, &[m3(hash(0x61))], &[]).expect("slot-24 M3");
        let before = state.clone();
        assert_eq!(
            apply(&mut state, &[m4_one(&[0, 0xff])], &[]),
            Err(ElementsSlot24ReplayError::M4InvalidVoteCount)
        );
        assert_eq!(state, before);
        apply(&mut state, &[m4_one(&[0])], &[]).expect("exact one-slot vote vector");
    }

    #[test]
    fn inactive_other_slot_treasury_shapes_do_not_change_slot24_ctip() {
        let mut state = funded_accumulator_state();
        let original_ctip = state.ctip().expect("slot-24 CTIP");

        let unrelated_other_slot = transaction(
            (BlockHash::from_internal_bytes([0x62; 32]), 0),
            &[],
            &[(123, treasury_for_slot(23))],
        );
        let effects = apply(&mut state, &[], &[unrelated_other_slot])
            .expect("inactive other-slot treasury shape is ordinary");
        assert!(effects.deposits.is_empty());
        assert_eq!(state.ctip(), Some(original_ctip));

        // An inactive other-slot treasury-shaped output may coexist with a
        // real slot-24 M5 without changing its classification or vout.
        let mixed_m5 = transaction(
            (original_ctip.txid, original_ctip.vout),
            &[],
            &[
                (original_ctip.value_sat + 1_000, treasury()),
                (0, push(b"elements-recipient", false)),
                (321, treasury_for_slot(23)),
            ],
        );
        let effects = apply(&mut state, &[], &[mixed_m5]).expect("slot-24 M5");
        assert_eq!(effects.deposits.len(), 1);
        assert_eq!(effects.deposits[0].value_sat, 1_000);
        assert_eq!(state.ctip().expect("successor CTIP").vout, 0);

        // Conversely, an other-slot shape is never a replacement for a spent
        // slot-24 CTIP.
        let current = state.ctip().expect("current slot-24 CTIP");
        let missing_slot24_replacement = transaction(
            (current.txid, current.vout),
            &[],
            &[(current.value_sat, treasury_for_slot(23))],
        );
        let before = state.clone();
        assert_eq!(
            apply(&mut state, &[], &[missing_slot24_replacement]),
            Err(ElementsSlot24ReplayError::CtipSpentWithoutReplacement)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn pending_proposal_bound_is_derived_from_block_weight_and_age() {
        let config = ElementsSlot24ReplayConfig::elements_v1();
        assert_eq!(ELEMENTS_V1_MAX_LIVE_PROPOSAL_BLOCKS, 11);
        assert_eq!(
            MAX_PENDING_SLOT24_PROPOSALS,
            BITCOIN_MAX_COINBASE_OUTPUTS * 12
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
    fn ordered_m3_m4_votes_match_short_enforcer_semantics() {
        let mut state = funded_accumulator_state();
        let a = hash(0xa1);
        let b = hash(0xb2);
        let proposal_height = state.next_height();
        let proposed = apply(&mut state, &[m3(a), m3(b)], &[]).expect("competing M3s");
        assert_eq!(proposed.effective_m4, None);
        assert_eq!(
            state.pending_m6ids().collect::<Vec<_>>(),
            vec![
                PendingSlot24M6id {
                    m6id: a,
                    proposal_height,
                    score: 1,
                },
                PendingSlot24M6id {
                    m6id: b,
                    proposal_height,
                    score: 1,
                },
            ]
        );

        let upvote = apply(&mut state, &[m4_one(&[0])], &[]).expect("upvote first");
        assert_eq!(
            upvote.effective_m4,
            Some(EffectiveSlot24M4::Upvote { m6id: a })
        );
        assert_eq!(
            state.pending_m6ids().map(|p| p.score).collect::<Vec<_>>(),
            vec![2, 0]
        );

        let repeat = apply(&mut state, &[m4_repeat()], &[]).expect("repeat effective upvote");
        assert_eq!(
            repeat.effective_m4,
            Some(EffectiveSlot24M4::Upvote { m6id: a })
        );
        assert_eq!(
            state.pending_m6ids().map(|p| p.score).collect::<Vec<_>>(),
            vec![3, 0]
        );

        let alarm = apply(&mut state, &[m4_one(&[0xfe])], &[]).expect("alarm");
        assert_eq!(alarm.effective_m4, Some(EffectiveSlot24M4::Alarm));
        assert_eq!(
            state.pending_m6ids().map(|p| p.score).collect::<Vec<_>>(),
            vec![2, 0]
        );
        apply(&mut state, &[m4_repeat()], &[]).expect("repeat alarm");
        assert_eq!(
            state.pending_m6ids().map(|p| p.score).collect::<Vec<_>>(),
            vec![1, 0]
        );

        // An absent M4 is the enforcer's implicit abstain and clears the
        // effective action available to the next block's RepeatPrevious.
        apply(&mut state, &[], &[]).expect("implicit abstain");
        let unchanged = state.clone();
        let repeated_abstain = apply(&mut state, &[m4_repeat()], &[]).expect("repeat abstain");
        assert_eq!(repeated_abstain.effective_m4, None);
        assert_eq!(
            state.pending_m6ids().collect::<Vec<_>>(),
            unchanged.pending_m6ids().collect::<Vec<_>>()
        );

        state.pending_m6ids[0].score = 51;
        state.pending_m6ids[1].score = 1;
        let leading = apply(&mut state, &[m4_leading_by_50()], &[]).expect("leading by 50");
        assert_eq!(
            leading.effective_m4,
            Some(EffectiveSlot24M4::Upvote { m6id: a })
        );
        assert_eq!(
            state.pending_m6ids().map(|p| p.score).collect::<Vec<_>>(),
            vec![52, 0]
        );
    }

    #[test]
    fn m3_m4_order_duplicates_encodings_and_expiry_fail_closed() {
        let mut state = funded_accumulator_state();
        let a = hash(0xa3);
        let before = state.clone();
        assert_eq!(
            apply(&mut state, &[m4_one(&[0]), m3(a)], &[]),
            Err(ElementsSlot24ReplayError::M4UpvoteMissingBundle)
        );
        assert_eq!(state, before);

        // Reversing the two coinbase outputs makes the index valid and starts
        // score 1 before the same-block M4 raises it to 2.
        apply(&mut state, &[m3(a), m4_one(&[0])], &[]).expect("ordered M3 then M4");
        assert_eq!(state.pending_m6ids().next().expect("pending").score, 2);

        for (scripts, error) in [
            (
                vec![m4_one(&[0xff]), m4_repeat()],
                ElementsSlot24ReplayError::DuplicateM4,
            ),
            (
                vec![m3(a)],
                ElementsSlot24ReplayError::M3BundleAlreadyPending,
            ),
            (
                vec![m3_for_slot(23, hash(9))],
                ElementsSlot24ReplayError::M3ForUnsupportedSlot,
            ),
            (
                vec![m4_two(&[0])],
                ElementsSlot24ReplayError::M4TwoBytesWithinByteRange,
            ),
            (
                vec![m4_two(&[254])],
                ElementsSlot24ReplayError::M4UpvoteMissingBundle,
            ),
        ] {
            let before = state.clone();
            assert_eq!(apply(&mut state, &scripts, &[]), Err(error));
            assert_eq!(state, before);
        }

        let proposal_height = state
            .pending_m6ids()
            .next()
            .expect("pending")
            .proposal_height;
        while state.next_height() <= proposal_height + u32::from(SLOT24_M6_MAX_AGE) {
            apply(&mut state, &[], &[]).expect("live through age ten");
        }
        assert_eq!(state.pending_m6ids().len(), 1);
        let expiry = apply(&mut state, &[], &[]).expect("expires at age eleven");
        assert_eq!(expiry.expired_m6ids, vec![a]);
        assert_eq!(state.pending_m6ids().len(), 0);
        apply(&mut state, &[m3(a)], &[]).expect("reproposal after expiry is fresh");
        assert_eq!(state.pending_m6ids().next().expect("fresh").score, 1);
    }

    #[test]
    fn exact_native_elwd_m6_rotates_ctip_and_preserves_usdd_root() {
        let mut state = funded_accumulator_state();
        let native = native_withdrawal_vector();
        assert_eq!(
            native.m6id().to_string(),
            "a7e1da09da7c62eda3f3bcb3902d6a79bb1d4a348858346c4152c10b714d3572"
        );
        assert_eq!(
            native.reference().elements_genesis(),
            accumulator_identity().elements_genesis
        );
        approve_m6id(&mut state, native.m6id());

        let prior_root = state.approved_root().expect("root");
        let prior_ctip = state.ctip().expect("CTIP");
        let actual = native_actual_m6_bytes(&state, &native);
        let effects = apply(&mut state, &[], &[actual]).expect("approved native M6");
        let approved = effects
            .approved_native_withdrawal_m6
            .expect("native approval effect");
        assert!(effects.approved_accumulator_m6.is_none());
        assert_eq!(approved.m6id, native.m6id());
        assert_eq!(approved.preserved_usdd_root, prior_root);
        assert_eq!(state.approved_root(), Some(prior_root));
        assert_eq!(approved.burn_outpoint, native.reference().burn_outpoint());
        assert_eq!(approved.parent_fee_sats, 1_000);
        assert_eq!(approved.payout_sats, 99_000);
        assert_eq!(state.ctip().expect("successor CTIP").vout, 0);
        assert_eq!(
            prior_ctip.value_sat - state.ctip().expect("successor CTIP").value_sat,
            approved.parent_fee_sats + approved.payout_sats
        );
        assert!(state
            .pending_m6ids()
            .all(|pending| pending.m6id != native.m6id()));
        assert!(state.successful_m6ids().any(|m6id| m6id == native.m6id()));

        // Match upstream: a paid M6id may be proposed again. The bridge keeps
        // the prior success only as audit history, while the new proposal
        // re-enters the ordered M4 set with score one.
        apply(&mut state, &[m3(native.m6id())], &[])
            .expect("upstream permits reproposing a paid M6id");
        assert!(state
            .pending_m6ids()
            .any(|pending| pending.m6id == native.m6id()));
    }

    #[test]
    fn native_elwd_marker_aliases_wrong_identity_and_auxiliary_ambiguity_fail_closed() {
        let mut state = funded_accumulator_state();
        let native = native_withdrawal_vector();
        let actual = native_actual_m6_bytes(&state, &native);
        let baseline = state.clone();

        assert_eq!(
            apply(&mut state, &[], core::slice::from_ref(&actual)),
            Err(ElementsSlot24ReplayError::NativeWithdrawalM6NotPending)
        );
        assert_eq!(state, baseline);

        let marker_offset = actual
            .windows(NATIVE_WITHDRAWAL_REFERENCE_MAGIC.len())
            .position(|window| window == NATIVE_WITHDRAWAL_REFERENCE_MAGIC)
            .expect("actual ELWD marker");
        let mut wrong_magic = actual.clone();
        wrong_magic[marker_offset] ^= 1;
        assert_eq!(
            apply(&mut state, &[], &[wrong_magic]),
            Err(ElementsSlot24ReplayError::UnknownSlot24M6)
        );
        assert_eq!(state, baseline);

        let mut wrong_version = actual.clone();
        wrong_version[0] = 1;
        assert_eq!(
            apply(&mut state, &[], &[wrong_version]),
            Err(ElementsSlot24ReplayError::UnknownSlot24M6)
        );
        assert_eq!(state, baseline);

        let mut wrong_genesis = actual.clone();
        wrong_genesis[marker_offset + 5..marker_offset + 37].reverse();
        assert_eq!(
            apply(&mut state, &[], &[wrong_genesis]),
            Err(ElementsSlot24ReplayError::NativeWithdrawalIdentityMismatch)
        );
        assert_eq!(state, baseline);

        let ctip = state.ctip().expect("CTIP");
        let marker_only = transaction(
            (ctip.txid, ctip.vout),
            &[],
            &[
                (ctip.value_sat - 1, treasury()),
                (0, push(b"ELWD\x01marker-only", false)),
            ],
        );
        assert_eq!(
            apply(&mut state, &[], &[marker_only]),
            Err(ElementsSlot24ReplayError::UnknownSlot24M6)
        );
        assert_eq!(state, baseline);

        approve_m6id(&mut state, native.m6id());
        let approved_state = state.clone();
        let actual = native_actual_m6_bytes(&state, &native);
        let unrelated_artifact = bundle_from(state.approved_root().unwrap(), 0xd1);
        assert_eq!(
            apply_with_artifact(&mut state, &[], &[actual], &unrelated_artifact),
            Err(ElementsSlot24ReplayError::AmbiguousSlot24M6)
        );
        assert_eq!(state, approved_state);
    }

    #[test]
    fn native_elwd_connect_disconnect_reorg_and_replay_are_root_safe() {
        let mut branch_point = funded_accumulator_state();
        let native = native_withdrawal_vector();
        let artifact = bundle_from(branch_point.approved_root().unwrap(), 0xd2);
        let height = branch_point.next_height() - 1;
        branch_point.pending_m6ids = vec![
            PendingSlot24M6id {
                m6id: native.m6id(),
                proposal_height: height,
                score: SLOT24_M6_REQUIRED_SCORE,
            },
            PendingSlot24M6id {
                m6id: artifact.m6id().unwrap(),
                proposal_height: height,
                score: SLOT24_M6_REQUIRED_SCORE,
            },
        ];
        branch_point.validate().expect("branch checkpoint");
        let native_actual = native_actual_m6_bytes(&branch_point, &native);
        let canonical_actual = actual_m6_bytes(&branch_point, &artifact);
        let prior_root = branch_point.approved_root().unwrap();

        let mut native_branch = branch_point.clone();
        apply(
            &mut native_branch,
            &[],
            core::slice::from_ref(&native_actual),
        )
        .expect("connect native branch");
        assert_eq!(native_branch.approved_root(), Some(prior_root));

        // Disconnect is represented by restoring the immutable predecessor
        // snapshot. Applying the sibling proves neither child mutated it.
        let disconnected = branch_point.clone();
        let mut canonical_branch = disconnected.clone();
        apply_with_artifact(
            &mut canonical_branch,
            &[],
            core::slice::from_ref(&canonical_actual),
            &artifact,
        )
        .expect("connect canonical sibling");
        assert_eq!(disconnected, branch_point);
        assert_eq!(native_branch.approved_root(), Some(prior_root));
        assert_eq!(
            canonical_branch.approved_root(),
            Some(Slot24ApprovedRoot {
                claim_count: artifact.next_claim_count,
                claim_root: artifact.next_claim_root,
            })
        );
        assert_ne!(native_branch.tip_hash(), canonical_branch.tip_hash());
        assert_ne!(native_branch.ctip(), canonical_branch.ctip());

        let paid_state = native_branch.clone();
        assert_eq!(
            apply(
                &mut native_branch,
                &[],
                core::slice::from_ref(&native_actual)
            ),
            Err(ElementsSlot24ReplayError::ParallelTreasuryOutput)
        );
        assert_eq!(native_branch, paid_state, "paid M6 replay is atomic");
    }

    #[test]
    fn native_elwd_expiry_byte_order_zero_ctip_and_bridge_multi_m6_policy() {
        let native = native_withdrawal_vector();

        let script = m3(native.m6id());
        let mut expected_wire = native.m6id().0;
        expected_wire.reverse();
        assert_eq!(&script[7..39], &expected_wire);

        let mut wrong_order_state = funded_accumulator_state();
        let mut wrong_order_m3 = script;
        wrong_order_m3[7..39].copy_from_slice(native.m6id().as_bytes());
        apply(&mut wrong_order_state, &[wrong_order_m3], &[]).expect("wrong-order M3 parses");
        let wrong_order_before = wrong_order_state.clone();
        let actual = native_actual_m6_bytes(&wrong_order_state, &native);
        assert_eq!(
            apply(&mut wrong_order_state, &[], &[actual]),
            Err(ElementsSlot24ReplayError::NativeWithdrawalM6NotPending)
        );
        assert_eq!(wrong_order_state, wrong_order_before);

        let mut expired_state = funded_accumulator_state();
        apply(&mut expired_state, &[m3(native.m6id())], &[]).expect("native M3");
        let mut expired = Vec::new();
        for _ in 0..=SLOT24_M6_MAX_AGE + 1 {
            expired.extend(
                apply(&mut expired_state, &[], &[])
                    .expect("age native M6")
                    .expired_m6ids,
            );
        }
        assert_eq!(expired, vec![native.m6id()]);
        let expired_before = expired_state.clone();
        let actual = native_actual_m6_bytes(&expired_state, &native);
        assert_eq!(
            apply(&mut expired_state, &[], &[actual]),
            Err(ElementsSlot24ReplayError::NativeWithdrawalM6NotPending)
        );
        assert_eq!(expired_state, expired_before);

        let mut zero_state = funded_accumulator_state();
        let mut draining_bytes = native.legacy_bytes();
        let fee_marker = draining_bytes
            .windows(2)
            .position(|window| window == [OP_RETURN, 8])
            .expect("fee push");
        draining_bytes[fee_marker + 2..fee_marker + 10].copy_from_slice(&901_000u64.to_be_bytes());
        let draining = NativeWithdrawalM6::decode_legacy(&draining_bytes).unwrap();
        approve_m6id(&mut zero_state, draining.m6id());
        let zero_root = zero_state.approved_root();
        let actual = native_actual_m6_bytes(&zero_state, &draining);
        apply(&mut zero_state, &[], &[actual]).expect("zero-valued successor CTIP");
        assert_eq!(zero_state.ctip().unwrap().value_sat, 0);
        assert_eq!(zero_state.approved_root(), zero_root);

        let mut multiple_state = funded_accumulator_state();
        let first = native;
        let mut second_bytes = first.legacy_bytes();
        let marker = second_bytes
            .windows(NATIVE_WITHDRAWAL_REFERENCE_MAGIC.len())
            .position(|window| window == NATIVE_WITHDRAWAL_REFERENCE_MAGIC)
            .unwrap();
        second_bytes[marker + 70..marker + 74].copy_from_slice(&8u32.to_be_bytes());
        let second = NativeWithdrawalM6::decode_legacy(&second_bytes).unwrap();
        let height = multiple_state.next_height() - 1;
        multiple_state.pending_m6ids = vec![
            PendingSlot24M6id {
                m6id: first.m6id(),
                proposal_height: height,
                score: SLOT24_M6_REQUIRED_SCORE,
            },
            PendingSlot24M6id {
                m6id: second.m6id(),
                proposal_height: height,
                score: SLOT24_M6_REQUIRED_SCORE,
            },
        ];
        multiple_state.validate().unwrap();
        let prior = Ctip {
            outpoint: OutPoint {
                txid: Hash32(multiple_state.ctip().unwrap().txid.to_display_bytes()),
                vout: multiple_state.ctip().unwrap().vout,
            },
            value_sats: multiple_state.ctip().unwrap().value_sat,
        };
        let first_actual = first.actual_transaction_bytes(&prior).unwrap();
        let second_actual = second
            .actual_transaction_bytes(&first.successor_ctip(&prior).unwrap())
            .unwrap();
        let multiple_before = multiple_state.clone();
        assert_eq!(
            apply(&mut multiple_state, &[], &[first_actual, second_actual]),
            Err(ElementsSlot24ReplayError::MultipleSuccessfulSlot24M6s)
        );
        assert_eq!(multiple_state, multiple_before);
    }

    #[test]
    fn canonical_accumulator_m6_requires_exact_approval_transaction_and_root() {
        let mut state = funded_accumulator_state();
        let prior = state.approved_root().expect("root");
        let artifact = bundle_from(prior, 0x91);
        let m6id = artifact.m6id().expect("M6id");
        approve_m6id(&mut state, m6id);

        // A competing M3 is allowed and must remain pending after the approved
        // canonical artifact consumes only its own M6id.
        let competitor = hash(0xc1);
        apply(&mut state, &[m3(competitor)], &[]).expect("competing M3");
        let prior_ctip = state.ctip().expect("CTIP");
        let actual = actual_m6_bytes(&state, &artifact);
        let effects = apply_with_artifact(&mut state, &[], &[actual], &artifact)
            .expect("approved canonical actual M6");
        let approved = effects.approved_accumulator_m6.expect("approval event");
        assert_eq!(approved.m6id, m6id);
        assert_eq!(approved.prior_root, prior);
        assert_eq!(approved.next_root.claim_count, 1);
        assert_eq!(approved.next_root.claim_root, hash(0x91));
        assert_eq!(state.approved_root(), Some(approved.next_root));
        assert_eq!(
            prior_ctip.value_sat - state.ctip().expect("successor").value_sat,
            artifact.fee_sats + M6_ROOT_PAYOUT_SATS
        );
        assert_eq!(state.ctip().expect("successor").vout, 0);
        assert_eq!(
            state
                .pending_m6ids()
                .map(|pending| pending.m6id)
                .collect::<Vec<_>>(),
            vec![competitor]
        );
        assert!(state
            .successful_m6ids()
            .any(|successful| successful == m6id));
        apply(&mut state, &[m3(m6id)], &[])
            .expect("upstream permits reproposing a paid accumulator M6id");
        assert!(state.pending_m6ids().any(|pending| pending.m6id == m6id));
    }

    #[test]
    fn canonical_m6_failures_and_forks_leave_prior_state_unchanged() {
        let mut state = funded_accumulator_state();
        let artifact = bundle_from(state.approved_root().expect("root"), 0x92);
        let m6id = artifact.m6id().expect("M6id");
        let actual = actual_m6_bytes(&state, &artifact);
        let without_m3 = state.clone();
        assert_eq!(
            apply_with_artifact(&mut state, &[], core::slice::from_ref(&actual), &artifact,),
            Err(ElementsSlot24ReplayError::CanonicalM6NotPending)
        );
        assert_eq!(state, without_m3);

        apply(&mut state, &[m3(m6id)], &[]).expect("M3 score one");
        let before = state.clone();
        assert_eq!(
            apply_with_artifact(&mut state, &[], core::slice::from_ref(&actual), &artifact),
            Err(ElementsSlot24ReplayError::CanonicalM6InsufficientScore)
        );
        assert_eq!(state, before);

        for _ in 0..4 {
            apply(&mut state, &[m4_one(&[0])], &[]).expect("score to threshold");
        }
        assert_eq!(state.pending_m6ids().next().expect("pending").score, 5);
        let at_threshold = state.clone();
        assert_eq!(
            apply_with_artifact(&mut state, &[], core::slice::from_ref(&actual), &artifact,),
            Err(ElementsSlot24ReplayError::CanonicalM6InsufficientScore)
        );
        assert_eq!(state, at_threshold);
        apply(&mut state, &[m4_one(&[0])], &[]).expect("strictly above threshold");
        assert_eq!(state.pending_m6ids().next().expect("pending").score, 6);
        let branch_point = state.clone();
        assert_eq!(
            apply_with_artifact(&mut state, &[], &[], &artifact),
            Err(ElementsSlot24ReplayError::UnexpectedCanonicalM6Artifact)
        );
        assert_eq!(state, branch_point);

        let mut invalid_identity = artifact.clone();
        invalid_identity.vault_id = hash(0x44);
        assert_eq!(
            apply_with_artifact(
                &mut state,
                &[],
                core::slice::from_ref(&actual),
                &invalid_identity,
            ),
            Err(ElementsSlot24ReplayError::CanonicalM6IdentityMismatch)
        );
        assert_eq!(state, branch_point);

        let mut wrong_prior = artifact.clone();
        wrong_prior.prior_claim_count = 1;
        wrong_prior.prior_claim_root = hash(0x55);
        wrong_prior.next_claim_count = 2;
        assert_eq!(
            apply_with_artifact(
                &mut state,
                &[],
                core::slice::from_ref(&actual),
                &wrong_prior,
            ),
            Err(ElementsSlot24ReplayError::CanonicalM6RootMismatch)
        );
        assert_eq!(state, branch_point);

        let mut tampered = actual.clone();
        let value_offset = 4 + 1 + 32 + 4 + 1 + 4 + 1;
        tampered[value_offset] ^= 1;
        assert_eq!(
            apply_with_artifact(&mut state, &[], &[tampered], &artifact),
            Err(ElementsSlot24ReplayError::CanonicalM6TransactionMismatch)
        );
        assert_eq!(state, branch_point);

        let mut canonical_branch = branch_point.clone();
        apply_with_artifact(&mut canonical_branch, &[], &[actual], &artifact)
            .expect("canonical branch");
        let mut sibling_branch = branch_point.clone();
        apply(&mut sibling_branch, &[], &[]).expect("sibling branch");
        assert_ne!(canonical_branch, sibling_branch);
        assert_eq!(
            state, branch_point,
            "fork clones must not mutate their parent"
        );
    }

    #[test]
    fn canonical_m6_never_authorizes_a_different_slot24_sidechain_identity() {
        let mut state = test_state(b"required-elements-identity");
        activate(&mut state, b"different-slot24-sidechain").expect("activate other identity");
        assert!(!state.required_proposal_is_active());
        let funding = transaction(
            (BlockHash::from_internal_bytes([0x72; 32]), 0),
            &[],
            &[(50_000, treasury()), (0, push(b"other", false))],
        );
        apply(&mut state, &[], &[funding]).expect("generic slot24 CTIP");
        state
            .bind_usdd_accumulator_checkpoint_requires_manifest_binding(
                accumulator_identity(),
                Slot24ApprovedRoot::empty(),
            )
            .expect("manifest accumulator");
        let artifact = bundle_from(state.approved_root().expect("root"), 0x95);
        let m6id = artifact.m6id().expect("M6id");
        approve_m6id(&mut state, m6id);
        let actual = actual_m6_bytes(&state, &artifact);
        let before = state.clone();
        assert_eq!(
            apply_with_artifact(&mut state, &[], &[actual], &artifact),
            Err(ElementsSlot24ReplayError::RequiredProposalInactiveForM6)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn second_accumulator_m6_in_one_parent_block_rejects_atomically() {
        let mut state = funded_accumulator_state();
        let first_bundle = bundle_from(state.approved_root().expect("root"), 0x93);
        let first_next = Slot24ApprovedRoot {
            claim_count: first_bundle.next_claim_count,
            claim_root: first_bundle.next_claim_root,
        };
        let second_bundle = bundle_from(first_next, 0x94);
        let first_actual = ActualM6Artifact::build(
            first_bundle.clone(),
            Ctip {
                outpoint: OutPoint {
                    txid: Hash32(state.ctip().expect("CTIP").txid.to_display_bytes()),
                    vout: state.ctip().expect("CTIP").vout,
                },
                value_sats: state.ctip().expect("CTIP").value_sat,
            },
        )
        .expect("first actual");
        let second_actual = ActualM6Artifact::build(
            second_bundle.clone(),
            first_actual.successor_ctip().expect("first successor"),
        )
        .expect("second actual");

        // A complete checkpoint can contain competing positive scores. The
        // parent-block policy still accepts no sequential second accumulator
        // spend, even when it would otherwise be canonical.
        let height = state.next_height() - 1;
        state.pending_m6ids = vec![
            PendingSlot24M6id {
                m6id: first_bundle.m6id().expect("first id"),
                proposal_height: height,
                score: SLOT24_M6_REQUIRED_SCORE,
            },
            PendingSlot24M6id {
                m6id: second_bundle.m6id().expect("second id"),
                proposal_height: height,
                score: SLOT24_M6_REQUIRED_SCORE,
            },
        ];
        state.validate().expect("bounded checkpoint");
        let before = state.clone();
        assert_eq!(
            apply_with_artifact(
                &mut state,
                &[],
                &[
                    first_actual.transaction_bytes().expect("first bytes"),
                    second_actual.transaction_bytes().expect("second bytes"),
                ],
                &first_bundle,
            ),
            Err(ElementsSlot24ReplayError::MultipleSuccessfulSlot24M6s)
        );
        assert_eq!(state, before);
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
            Err(ElementsSlot24ReplayError::UnknownSlot24M6)
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

        let checkpoint = funded_accumulator_state();
        let duplicate_success = hash(0xd1);
        assert_eq!(
            ElementsSlot24ReplayState::from_unverified_usdd_checkpoint_requires_manifest_binding(
                checkpoint.config,
                checkpoint.next_height - 1,
                checkpoint.tip_hash,
                checkpoint.active_proposal_hash,
                checkpoint.required_activation,
                checkpoint.pending_proposals.values().cloned().collect(),
                checkpoint.ctip,
                checkpoint.pending_m6ids.clone(),
                vec![duplicate_success, duplicate_success],
                checkpoint.previous_effective_m4,
                checkpoint.accumulator_identity.expect("identity"),
                checkpoint.approved_root.expect("root"),
            ),
            Err(ElementsSlot24ReplayError::MalformedState)
        );

        // Keep a direct decode assertion so test fixtures cannot accidentally
        // build non-80-byte headers while still satisfying the block helper.
        assert!(BitcoinHeader::decode_exact(&wrong[..80]).is_ok());
    }
}
