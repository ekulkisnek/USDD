//! Frozen sole-network Elements parent-Signet challenge verification.

extern crate alloc;

use alloc::vec::Vec;

use bitcoin_hashes::{hash160, Hash as BitcoinHash};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature as K256Signature, VerifyingKey};

use super::multislot::{
    apply_multislot_parent_block_owned, MultiSlotBlockEffects, MultiSlotCtip, MultiSlotPendingM6id,
    MultiSlotReplayState, Slot24UsddContinuity,
};
use super::{
    bip300::apply_merkle_bound_elements_slot24_parent_block_owned_with_m6_artifact,
    merkle_root_and_mutation, parse_and_verify_block, witness_commitment_index,
    BlockStructureError, ParsedBlock,
};
use crate::{bitcoin_block_confirmations, m6::MinerBundleArtifact};
use crate::{
    double_sha256, extract_elements_slot24_m7, verify_contextual_successor,
    verify_header_pow_against_caller_supplied_bits, verify_mtp_successor, verify_successor,
    ApprovedSlot24AccumulatorM6, BlockHash, BmmConfirmationError, BmmConfirmationTracker,
    ContextualHeaderChainState, ContextualHeaderError, ElementsSlot24BlockEffects,
    ElementsSlot24ReplayConfig, ElementsSlot24ReplayState, HeaderChainState, HeaderError, M7Error,
    MerkleVerifiedBitcoinBlock, PowMerkleBoundM7, PowParameters, Slot24AccumulatorIdentity,
    Slot24ApprovedRoot, ELEMENTS_PARENT_SIGNET_P2WPKH, LAYER_TWO_SIGNET_GENESIS_BITS,
    LAYER_TWO_SIGNET_GENESIS_DISPLAY,
};

const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];
const LAYER_TWO_SIGNET_GENESIS_INTERNAL: [u8; 32] = [
    0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2, 0xbb, 0xc9,
    0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25, 0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayerTwoSignetError {
    Block(BlockStructureError),
    Header(HeaderError),
    Commitment(M7Error),
    MissingWitnessCommitment,
    MalformedCommitmentScript,
    MissingSolution,
    NonCanonicalSolution,
    NonEmptyScriptSig,
    WrongWitnessStack,
    WrongPublicKeyHash,
    InvalidPublicKey,
    InvalidDerSignature,
    InvalidSignature,
    LengthOverflow,
}

impl From<BlockStructureError> for LayerTwoSignetError {
    fn from(value: BlockStructureError) -> Self {
        Self::Block(value)
    }
}

impl From<HeaderError> for LayerTwoSignetError {
    fn from(value: HeaderError) -> Self {
        Self::Header(value)
    }
}

impl From<M7Error> for LayerTwoSignetError {
    fn from(value: M7Error) -> Self {
        Self::Commitment(value)
    }
}

/// A parent transition that additionally satisfies the immutable
/// Sole-network Elements parent-Signet P2WPKH challenge.
///
/// This still does not assert the selected Bitcoin chain model, BIP300 state,
/// best-chain selection, confirmation depth, or redemption authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignetPowMerkleBoundM7Transition {
    pub next_parent_state: HeaderChainState,
    pub commitment: PowMerkleBoundM7,
}

/// One exact block transition with canonical transaction/Merkle/BIP141,
/// frozen Signet authorization, PoW/difficulty/work, MTP, and authenticated
/// future-time checks. It still omits Bitcoin UTXO/script and activation rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextualSignetBlockTransition {
    pub next_parent_state: ContextualHeaderChainState,
    pub block: MerkleVerifiedBitcoinBlock,
}

/// Parent-header and slot-24 replay state that can only be created from the
/// exact frozen LayerTwo Signet genesis and advanced through the composed
/// verifier below. Unlike the diagnostic checkpoint constructors on its
/// component types, this type cannot be initialized from caller assertions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisDerivedLayerTwoSignetReplayState {
    pub(super) contextual: ContextualHeaderChainState,
    pub(super) slot24_replay: ElementsSlot24ReplayState,
}

/// Opaque all-256-slot BIP300 state bound to the same exact frozen Signet
/// genesis and contextual header branch. Unlike the diagnostic slot-24 state,
/// this type has no caller-selected checkpoint constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisDerivedLayerTwoSignetMultiSlotReplayState {
    contextual: ContextualHeaderChainState,
    multislot_replay: MultiSlotReplayState,
}

impl GenesisDerivedLayerTwoSignetMultiSlotReplayState {
    pub const fn contextual(&self) -> ContextualHeaderChainState {
        self.contextual
    }

    pub const fn next_height(&self) -> u32 {
        self.multislot_replay.next_height()
    }

    pub const fn tip_hash(&self) -> BlockHash {
        self.multislot_replay.tip_hash()
    }

    pub const fn tip_height(&self) -> u32 {
        self.contextual.header_chain.height
    }

    pub fn active_slot_count(&self) -> usize {
        self.multislot_replay.active_slot_count()
    }

    pub fn active_slots(&self) -> impl ExactSizeIterator<Item = u8> + '_ {
        self.multislot_replay.active_slots()
    }

    pub fn active_proposal_hash(&self, slot: u8) -> Option<[u8; 32]> {
        self.multislot_replay.active_proposal_hash(slot)
    }

    pub fn ctip(&self, slot: u8) -> Option<MultiSlotCtip> {
        self.multislot_replay.ctip(slot)
    }

    pub fn pending_m6ids(&self, slot: u8) -> impl Iterator<Item = MultiSlotPendingM6id> + '_ {
        self.multislot_replay.pending_m6ids(slot)
    }

    pub const fn slot24_usdd_continuity(&self) -> Slot24UsddContinuity {
        self.multislot_replay.slot24_usdd_continuity()
    }

    pub const fn approved_slot24_root(&self) -> Option<Slot24ApprovedRoot> {
        self.multislot_replay.approved_root()
    }
}

impl GenesisDerivedLayerTwoSignetReplayState {
    pub const fn contextual(&self) -> ContextualHeaderChainState {
        self.contextual
    }

    pub const fn next_height(&self) -> u32 {
        self.slot24_replay.next_height()
    }

    pub const fn tip_hash(&self) -> BlockHash {
        self.slot24_replay.tip_hash()
    }

    pub const fn tip_height(&self) -> u32 {
        self.contextual.header_chain.height
    }

    pub const fn slot24_active_proposal_hash(&self) -> Option<[u8; 32]> {
        self.slot24_replay.active_proposal_hash()
    }

    pub fn slot24_required_proposal_is_active(&self) -> bool {
        self.slot24_replay.required_proposal_is_active()
    }

    pub const fn approved_slot24_root(&self) -> Option<Slot24ApprovedRoot> {
        self.slot24_replay.approved_root()
    }
}

/// Frozen parent-chain finality rule for an approved slot-24 accumulator M6.
/// The block containing the exact approved M6 is confirmation one.
pub const SLOT24_ACCUMULATOR_M6_FINALITY_CONFIRMATIONS: u32 = 100;

/// A finalized accumulator root emitted only by the opaque branch-bound
/// tracker after the frozen confirmation rule has been met.
///
/// The fields are private so downstream authorization code cannot construct a
/// value by pairing a caller-selected root with an unrelated height.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedSlot24AccumulatorRoot {
    approved_m6id: usdd_core::Hash32,
    root: Slot24ApprovedRoot,
    inclusion_block_hash: BlockHash,
    inclusion_height: u32,
    finalization_tip_hash: BlockHash,
    finalization_tip_height: u32,
}

impl FinalizedSlot24AccumulatorRoot {
    pub const fn approved_m6id(self) -> usdd_core::Hash32 {
        self.approved_m6id
    }

    pub const fn root(self) -> Slot24ApprovedRoot {
        self.root
    }

    pub const fn inclusion_block_hash(self) -> BlockHash {
        self.inclusion_block_hash
    }

    pub const fn inclusion_height(self) -> u32 {
        self.inclusion_height
    }

    pub const fn finalization_tip_hash(self) -> BlockHash {
        self.finalization_tip_hash
    }

    pub const fn finalization_tip_height(self) -> u32 {
        self.finalization_tip_height
    }
}

/// One approved accumulator M6 kept together with the exact genesis-derived
/// Signet/header/BIP300 branch which contained it.
///
/// There is no public field or checkpoint constructor. The only public
/// constructor replays the exact inclusion block through the composed
/// verifier. Later advancement also replays every exact block through both
/// contextual Signet validation and ordered slot-24 state on this same branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedSlot24AccumulatorM6FinalityTracker {
    branch: GenesisDerivedLayerTwoSignetReplayState,
    approval: ApprovedSlot24AccumulatorM6,
}

/// One slot-24 accumulator approval carried by the opaque, exact-genesis
/// all-256-slot branch which contained it.
///
/// Only the exact inclusion-block verifier below can construct this tracker.
/// Later blocks are replayed across every slot before confirmations advance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiSlotApprovedSlot24AccumulatorM6FinalityTracker {
    branch: GenesisDerivedLayerTwoSignetMultiSlotReplayState,
    approval: ApprovedSlot24AccumulatorM6,
}

impl MultiSlotApprovedSlot24AccumulatorM6FinalityTracker {
    fn bind(
        branch: GenesisDerivedLayerTwoSignetMultiSlotReplayState,
        approval: ApprovedSlot24AccumulatorM6,
    ) -> Result<Self, BmmConfirmationError> {
        if approval.block_height != branch.contextual.header_chain.height
            || approval.block_hash != branch.contextual.header_chain.tip.hash
            || approval.block_hash != branch.multislot_replay.tip_hash()
        {
            return Err(BmmConfirmationError::ApprovalNotAtTrackedTip);
        }
        if branch.multislot_replay.approved_root() != Some(approval.next_root) {
            return Err(BmmConfirmationError::ApprovalRootMismatch);
        }
        if branch.multislot_replay.slot24_usdd_continuity() != Slot24UsddContinuity::Active {
            return Err(BmmConfirmationError::Slot24UsddContinuityLost);
        }
        Ok(Self { branch, approval })
    }

    pub const fn approval(&self) -> ApprovedSlot24AccumulatorM6 {
        self.approval
    }

    pub const fn tip_hash(&self) -> BlockHash {
        self.branch.contextual.header_chain.tip.hash
    }

    pub const fn tip_height(&self) -> u32 {
        self.branch.contextual.header_chain.height
    }

    pub const fn slot24_usdd_continuity(&self) -> Slot24UsddContinuity {
        self.branch.multislot_replay.slot24_usdd_continuity()
    }

    pub fn confirmations(&self) -> Result<u32, BmmConfirmationError> {
        bitcoin_block_confirmations(self.approval.block_height, self.tip_height())
    }

    /// Return the exact branch-bound approved root after the inclusive fixed
    /// depth is met. Later continuity loss prevents future USDD approvals but
    /// cannot rewrite or revoke this earlier immutable inclusion.
    pub fn finalized_root(&self) -> Result<FinalizedSlot24AccumulatorRoot, BmmConfirmationError> {
        finalize_approved_slot24_accumulator_root(self.approval, self.tip_hash(), self.tip_height())
    }

    /// Replay one exact later block across contextual Signet validation and
    /// all 256 BIP300 slots. A generic slot-24 M6 remains replayable, but it
    /// permanently changes continuity to `Invalidated`, preventing any later
    /// canonical approval without revoking this already-bound root.
    pub fn advance(
        &self,
        serialized_block: &[u8],
        authenticated_current_time: u64,
        canonical_m6_artifact: Option<&MinerBundleArtifact>,
    ) -> Result<(Self, MultiSlotBlockEffects), BmmConfirmationError> {
        let (branch, effects) = advance_genesis_derived_layer_two_signet_multislot_replay(
            &self.branch,
            serialized_block,
            authenticated_current_time,
            canonical_m6_artifact,
        )?;
        Ok((
            Self {
                branch,
                approval: self.approval,
            },
            effects,
        ))
    }
}

impl ApprovedSlot24AccumulatorM6FinalityTracker {
    fn bind(
        branch: GenesisDerivedLayerTwoSignetReplayState,
        approval: ApprovedSlot24AccumulatorM6,
    ) -> Result<Self, BmmConfirmationError> {
        if approval.block_height != branch.contextual.header_chain.height
            || approval.block_hash != branch.contextual.header_chain.tip.hash
            || approval.block_hash != branch.slot24_replay.tip_hash()
        {
            return Err(BmmConfirmationError::ApprovalNotAtTrackedTip);
        }
        if branch.slot24_replay.approved_root() != Some(approval.next_root) {
            return Err(BmmConfirmationError::ApprovalRootMismatch);
        }
        Ok(Self { branch, approval })
    }

    pub const fn approval(&self) -> ApprovedSlot24AccumulatorM6 {
        self.approval
    }

    pub const fn tip_hash(&self) -> BlockHash {
        self.branch.contextual.header_chain.tip.hash
    }

    pub const fn tip_height(&self) -> u32 {
        self.branch.contextual.header_chain.height
    }

    pub fn confirmations(&self) -> Result<u32, BmmConfirmationError> {
        bitcoin_block_confirmations(self.approval.block_height, self.tip_height())
    }

    /// Return the exact approved next root only after 100 confirmations on the
    /// continuously replayed branch. Callers cannot lower this threshold.
    pub fn finalized_root(&self) -> Result<FinalizedSlot24AccumulatorRoot, BmmConfirmationError> {
        finalize_approved_slot24_accumulator_root(self.approval, self.tip_hash(), self.tip_height())
    }

    /// Verify one later block and advance both contextual Signet/header state
    /// and ordered slot-24 replay atomically. An optional later canonical M6
    /// artifact is replayed in the same transition. Because `self` is only
    /// borrowed, every error preserves the complete prior branch snapshot.
    pub fn advance(
        &self,
        serialized_block: &[u8],
        authenticated_current_time: u64,
        canonical_m6_artifact: Option<&MinerBundleArtifact>,
    ) -> Result<(Self, ElementsSlot24BlockEffects), BmmConfirmationError> {
        let (branch, effects) = advance_genesis_derived_layer_two_signet_replay(
            &self.branch,
            serialized_block,
            authenticated_current_time,
            canonical_m6_artifact,
        )?;
        Ok((
            Self {
                branch,
                approval: self.approval,
            },
            effects,
        ))
    }
}

fn finalize_approved_slot24_accumulator_root(
    approval: ApprovedSlot24AccumulatorM6,
    finalization_tip_hash: BlockHash,
    finalization_tip_height: u32,
) -> Result<FinalizedSlot24AccumulatorRoot, BmmConfirmationError> {
    let actual = bitcoin_block_confirmations(approval.block_height, finalization_tip_height)?;
    if actual < SLOT24_ACCUMULATOR_M6_FINALITY_CONFIRMATIONS {
        return Err(BmmConfirmationError::InsufficientConfirmations {
            required: SLOT24_ACCUMULATOR_M6_FINALITY_CONFIRMATIONS,
            actual,
        });
    }
    Ok(FinalizedSlot24AccumulatorRoot {
        approved_m6id: approval.m6id,
        root: approval.next_root,
        inclusion_block_hash: approval.block_hash,
        inclusion_height: approval.block_height,
        finalization_tip_hash,
        finalization_tip_height,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextualSignetError {
    Signet(LayerTwoSignetError),
    Contextual(ContextualHeaderError),
}

impl From<LayerTwoSignetError> for ContextualSignetError {
    fn from(value: LayerTwoSignetError) -> Self {
        Self::Signet(value)
    }
}

impl From<ContextualHeaderError> for ContextualSignetError {
    fn from(value: ContextualHeaderError) -> Self {
        Self::Contextual(value)
    }
}

fn read_script_op<'a>(
    script: &'a [u8],
    position: &mut usize,
) -> Result<(u8, Option<&'a [u8]>), LayerTwoSignetError> {
    let opcode = *script
        .get(*position)
        .ok_or(LayerTwoSignetError::MalformedCommitmentScript)?;
    *position += 1;
    let length = match opcode {
        0x01..=0x4b => Some(usize::from(opcode)),
        0x4c => {
            let length = *script
                .get(*position)
                .ok_or(LayerTwoSignetError::MalformedCommitmentScript)?;
            *position += 1;
            Some(usize::from(length))
        }
        0x4d => {
            let end = position
                .checked_add(2)
                .ok_or(LayerTwoSignetError::LengthOverflow)?;
            let bytes = script
                .get(*position..end)
                .ok_or(LayerTwoSignetError::MalformedCommitmentScript)?;
            *position = end;
            Some(usize::from(u16::from_le_bytes(
                bytes.try_into().expect("fixed pushdata length"),
            )))
        }
        0x4e => {
            let end = position
                .checked_add(4)
                .ok_or(LayerTwoSignetError::LengthOverflow)?;
            let bytes = script
                .get(*position..end)
                .ok_or(LayerTwoSignetError::MalformedCommitmentScript)?;
            *position = end;
            Some(
                usize::try_from(u32::from_le_bytes(
                    bytes.try_into().expect("fixed pushdata length"),
                ))
                .map_err(|_| LayerTwoSignetError::LengthOverflow)?,
            )
        }
        _ => None,
    };
    let Some(length) = length else {
        return Ok((opcode, None));
    };
    let end = position
        .checked_add(length)
        .ok_or(LayerTwoSignetError::LengthOverflow)?;
    let data = script
        .get(*position..end)
        .ok_or(LayerTwoSignetError::MalformedCommitmentScript)?;
    *position = end;
    Ok((opcode, Some(data)))
}

fn append_script_push(data: &[u8], output: &mut Vec<u8>) -> Result<(), LayerTwoSignetError> {
    if data.len() < 0x4c {
        output.push(data.len() as u8);
    } else if data.len() <= usize::from(u8::MAX) {
        output.extend_from_slice(&[0x4c, data.len() as u8]);
    } else if data.len() <= usize::from(u16::MAX) {
        output.push(0x4d);
        output.extend_from_slice(&(data.len() as u16).to_le_bytes());
    } else {
        let length = u32::try_from(data.len()).map_err(|_| LayerTwoSignetError::LengthOverflow)?;
        output.push(0x4e);
        output.extend_from_slice(&length.to_le_bytes());
    }
    output.extend_from_slice(data);
    Ok(())
}

/// Faithful `FetchAndClearCommitmentSection` specialization for the Signet
/// header. Like Core, only the first push containing header plus data is used.
fn extract_solution_and_modified_script(
    witness_commitment: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), LayerTwoSignetError> {
    let mut position = 0usize;
    let mut replacement = Vec::new();
    let mut solution = None;
    while position < witness_commitment.len() {
        // Bitcoin Core's GetOp loop stops on a malformed suffix. If the Signet
        // section was already found, FetchAndClearCommitmentSection still
        // returns its replacement prefix. Match that consensus behavior.
        let Ok((opcode, pushdata)) = read_script_op(witness_commitment, &mut position) else {
            break;
        };
        match pushdata {
            Some(data) if !data.is_empty() => {
                if solution.is_none()
                    && data.len() > SIGNET_HEADER.len()
                    && data[..SIGNET_HEADER.len()] == SIGNET_HEADER
                {
                    solution = Some(data[SIGNET_HEADER.len()..].to_vec());
                    append_script_push(&SIGNET_HEADER, &mut replacement)?;
                } else {
                    append_script_push(data, &mut replacement)?;
                }
            }
            _ => replacement.push(opcode),
        }
    }
    let solution = solution.ok_or(LayerTwoSignetError::MissingSolution)?;
    Ok((solution, replacement))
}

fn parse_solution(solution: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), LayerTwoSignetError> {
    let mut cursor = super::Cursor::new(solution, 0);
    let script_sig_size = cursor
        .compact_size()
        .map_err(|_| LayerTwoSignetError::NonCanonicalSolution)?;
    let script_sig = cursor
        .take(script_sig_size)
        .map_err(|_| LayerTwoSignetError::NonCanonicalSolution)?
        .to_vec();
    let item_count = cursor
        .compact_size()
        .map_err(|_| LayerTwoSignetError::NonCanonicalSolution)?;
    if item_count > cursor.remaining() {
        return Err(LayerTwoSignetError::NonCanonicalSolution);
    }
    let mut witness = Vec::with_capacity(item_count);
    for _ in 0..item_count {
        let item_size = cursor
            .compact_size()
            .map_err(|_| LayerTwoSignetError::NonCanonicalSolution)?;
        witness.push(
            cursor
                .take(item_size)
                .map_err(|_| LayerTwoSignetError::NonCanonicalSolution)?
                .to_vec(),
        );
    }
    if cursor.remaining() != 0 {
        return Err(LayerTwoSignetError::NonCanonicalSolution);
    }
    Ok((script_sig, witness))
}

fn virtual_spent_txid(
    parsed: &ParsedBlock<'_>,
    modified_merkle_root: BlockHash,
) -> Result<BlockHash, LayerTwoSignetError> {
    let mut block_data = Vec::with_capacity(72);
    block_data.extend_from_slice(&parsed.metadata.header.version.to_le_bytes());
    block_data.extend_from_slice(&parsed.metadata.header.previous_block.to_internal_bytes());
    block_data.extend_from_slice(&modified_merkle_root.to_internal_bytes());
    block_data.extend_from_slice(&parsed.metadata.header.time.to_le_bytes());
    debug_assert_eq!(block_data.len(), 72);

    let mut transaction = Vec::new();
    transaction.extend_from_slice(&0i32.to_le_bytes());
    transaction.push(1);
    transaction.extend_from_slice(&[0; 32]);
    transaction.extend_from_slice(&u32::MAX.to_le_bytes());
    transaction.push(74);
    transaction.extend_from_slice(&[0x00, 0x48]);
    transaction.extend_from_slice(&block_data);
    transaction.extend_from_slice(&0u32.to_le_bytes());
    transaction.push(1);
    transaction.extend_from_slice(&0i64.to_le_bytes());
    transaction.push(22);
    transaction.extend_from_slice(&[0x00, 0x14]);
    transaction.extend_from_slice(&ELEMENTS_PARENT_SIGNET_P2WPKH);
    transaction.extend_from_slice(&0u32.to_le_bytes());
    Ok(BlockHash::from_internal_bytes(double_sha256(&transaction)))
}

fn strict_der_encoding(signature_with_hash_type: &[u8]) -> bool {
    if !(9..=73).contains(&signature_with_hash_type.len())
        || signature_with_hash_type[0] != 0x30
        || usize::from(signature_with_hash_type[1]) != signature_with_hash_type.len() - 3
        || signature_with_hash_type[2] != 0x02
    {
        return false;
    }
    let len_r = usize::from(signature_with_hash_type[3]);
    if len_r == 0 || 5usize.saturating_add(len_r) >= signature_with_hash_type.len() {
        return false;
    }
    let s_type_index = 4 + len_r;
    if signature_with_hash_type[s_type_index] != 0x02 {
        return false;
    }
    let len_s = usize::from(signature_with_hash_type[s_type_index + 1]);
    if len_r + len_s + 7 != signature_with_hash_type.len()
        || len_s == 0
        || signature_with_hash_type[4] & 0x80 != 0
        || (len_r > 1
            && signature_with_hash_type[4] == 0
            && signature_with_hash_type[5] & 0x80 == 0)
    {
        return false;
    }
    let s_index = s_type_index + 2;
    if signature_with_hash_type[s_index] & 0x80 != 0
        || (len_s > 1
            && signature_with_hash_type[s_index] == 0
            && signature_with_hash_type[s_index + 1] & 0x80 == 0)
    {
        return false;
    }
    true
}

fn signet_bip143_sighash(spent_txid: BlockHash, hash_type: u32) -> [u8; 32] {
    let base_type = hash_type & 0x1f;
    let anyone_can_pay = hash_type & 0x80 != 0;

    let mut outpoint = [0u8; 36];
    outpoint[..32].copy_from_slice(&spent_txid.to_internal_bytes());
    let hash_prevouts = if anyone_can_pay {
        [0; 32]
    } else {
        double_sha256(&outpoint)
    };
    let sequence = 0u32.to_le_bytes();
    let hash_sequence = if anyone_can_pay || base_type == 2 || base_type == 3 {
        [0; 32]
    } else {
        double_sha256(&sequence)
    };
    let output = [
        0, 0, 0, 0, 0, 0, 0, 0, // value
        1, 0x6a, // scriptPubKey
    ];
    let hash_outputs = if base_type == 2 {
        [0; 32]
    } else {
        // The virtual transaction has output zero, so SIGHASH_SINGLE and all
        // non-NONE base types commit to this same output.
        double_sha256(&output)
    };

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&0i32.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    preimage.extend_from_slice(&outpoint);
    preimage.push(25);
    preimage.extend_from_slice(&[0x76, 0xa9, 0x14]);
    preimage.extend_from_slice(&ELEMENTS_PARENT_SIGNET_P2WPKH);
    preimage.extend_from_slice(&[0x88, 0xac]);
    preimage.extend_from_slice(&0i64.to_le_bytes());
    preimage.extend_from_slice(&sequence);
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&0u32.to_le_bytes());
    preimage.extend_from_slice(&hash_type.to_le_bytes());
    double_sha256(&preimage)
}

fn verify_parsed_layer_two_signet(parsed: &ParsedBlock<'_>) -> Result<(), LayerTwoSignetError> {
    if parsed.metadata.block_hash
        == BlockHash::from_internal_bytes(LAYER_TWO_SIGNET_GENESIS_INTERNAL)
    {
        return Ok(());
    }
    let commitment_index = witness_commitment_index(&parsed.coinbase.outputs)
        .ok_or(LayerTwoSignetError::MissingWitnessCommitment)?;
    let (solution, modified_commitment) =
        extract_solution_and_modified_script(parsed.coinbase.outputs[commitment_index].script)?;
    let (script_sig, witness) = parse_solution(&solution)?;
    if !script_sig.is_empty() {
        return Err(LayerTwoSignetError::NonEmptyScriptSig);
    }
    if witness.len() != 2 || witness[0].is_empty() {
        return Err(LayerTwoSignetError::WrongWitnessStack);
    }
    let signature_with_hash_type = &witness[0];
    let public_key = &witness[1];
    if hash160::Hash::hash(public_key).to_byte_array() != ELEMENTS_PARENT_SIGNET_P2WPKH {
        return Err(LayerTwoSignetError::WrongPublicKeyHash);
    }
    if !strict_der_encoding(signature_with_hash_type) {
        return Err(LayerTwoSignetError::InvalidDerSignature);
    }

    let modified_coinbase = parsed
        .coinbase
        .serialized_without_witness_with_replaced_script(commitment_index, &modified_commitment)?;
    let mut modified_txids = parsed.txids.clone();
    modified_txids[0] = BlockHash::from_internal_bytes(double_sha256(&modified_coinbase));
    let (modified_merkle_root, _) = merkle_root_and_mutation(modified_txids);
    let spent_txid = virtual_spent_txid(parsed, modified_merkle_root)?;

    let hash_type = u32::from(
        *signature_with_hash_type
            .last()
            .ok_or(LayerTwoSignetError::InvalidDerSignature)?,
    );
    let sighash = signet_bip143_sighash(spent_txid, hash_type);
    let signature =
        K256Signature::from_der(&signature_with_hash_type[..signature_with_hash_type.len() - 1])
            .map_err(|_| LayerTwoSignetError::InvalidDerSignature)?;
    // Bitcoin's Signet flags require strict DER but do not require LOW_S.
    // k256's verifier does require LOW_S, so normalize the mathematically
    // equivalent high-S form before verification to preserve Core semantics.
    let signature = signature.normalize_s().unwrap_or(signature);
    let key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| LayerTwoSignetError::InvalidPublicKey)?;
    key.verify_prehash(&sighash, &signature)
        .map_err(|_| LayerTwoSignetError::InvalidSignature)
}

/// Verify the exact serialized block, BIP141 witness commitment, and immutable
/// Sole-network Elements parent-Signet P2WPKH solution. This does not verify proof of work or
/// chain position; use the successor transition API for that composition.
pub fn verify_layer_two_signet_block_solution(
    serialized_block: &[u8],
) -> Result<super::MerkleVerifiedBitcoinBlock, LayerTwoSignetError> {
    let parsed = parse_and_verify_block(serialized_block)?;
    verify_parsed_layer_two_signet(&parsed)?;
    Ok(parsed.metadata)
}

/// Compose exact block/Merkle/BIP141 and frozen Signet validation with the
/// contextual header transition. `authenticated_current_time` must itself be
/// proved from a chain source; an RPC clock is not an authorization input.
pub fn verify_layer_two_signet_contextual_successor(
    prior: &ContextualHeaderChainState,
    serialized_block: &[u8],
    authenticated_current_time: u64,
) -> Result<ContextualSignetBlockTransition, ContextualSignetError> {
    let parsed = parse_and_verify_block(serialized_block).map_err(LayerTwoSignetError::from)?;
    verify_parsed_layer_two_signet(&parsed)?;
    let next_parent_state = verify_contextual_successor(
        prior,
        &parsed.metadata.header.raw(),
        PowParameters::LAYER_TWO_SIGNET,
        authenticated_current_time,
    )?;
    Ok(ContextualSignetBlockTransition {
        next_parent_state,
        block: parsed.metadata,
    })
}

/// Exact block/Merkle/BIP141, frozen Signet, difficulty/PoW/work, and MTP
/// transition without pretending that a prover-supplied current time is
/// authenticated. Production Bitcoin validity must additionally enforce the
/// adjusted-time upper bound from an authenticated time source.
pub fn verify_layer_two_signet_mtp_successor(
    prior: &ContextualHeaderChainState,
    serialized_block: &[u8],
) -> Result<ContextualSignetBlockTransition, ContextualSignetError> {
    let parsed = parse_and_verify_block(serialized_block).map_err(LayerTwoSignetError::from)?;
    verify_parsed_layer_two_signet(&parsed)?;
    let next_parent_state = verify_mtp_successor(
        prior,
        &parsed.metadata.header.raw(),
        PowParameters::LAYER_TWO_SIGNET,
    )?;
    Ok(ContextualSignetBlockTransition {
        next_parent_state,
        block: parsed.metadata,
    })
}

/// Advance a BMM confirmation counter only through an exact contextual Signet
/// successor on the branch that originally contained its bound M7 edge.
pub fn advance_layer_two_signet_bmm_confirmation_tracker(
    tracker: &mut BmmConfirmationTracker,
    serialized_block: &[u8],
    authenticated_current_time: u64,
) -> Result<MerkleVerifiedBitcoinBlock, BmmConfirmationError> {
    let transition = verify_layer_two_signet_contextual_successor(
        &tracker.chain(),
        serialized_block,
        authenticated_current_time,
    )
    .map_err(|error| match error {
        ContextualSignetError::Contextual(error) => BmmConfirmationError::ContextualHeader(error),
        ContextualSignetError::Signet(error) => BmmConfirmationError::Signet(error),
    })?;
    tracker.replace_chain(transition.next_parent_state);
    Ok(transition.block)
}

/// Initialize the composed parent/replay state from the exact frozen genesis.
/// No caller-provided header or slot-24 checkpoint can create this type.
pub fn initialize_layer_two_signet_genesis_replay(
    serialized_genesis: &[u8],
) -> Result<GenesisDerivedLayerTwoSignetReplayState, BmmConfirmationError> {
    let parsed = parse_and_verify_block(serialized_genesis)
        .map_err(LayerTwoSignetError::from)
        .map_err(BmmConfirmationError::from)?;
    if parsed.metadata.block_hash
        != BlockHash::from_internal_bytes(LAYER_TWO_SIGNET_GENESIS_INTERNAL)
        || parsed.metadata.header.previous_block != BlockHash::ZERO
        || parsed.metadata.header.bits != LAYER_TWO_SIGNET_GENESIS_BITS
    {
        return Err(BmmConfirmationError::WrongNetworkGenesis);
    }
    verify_parsed_layer_two_signet(&parsed).map_err(BmmConfirmationError::from)?;
    let verified_genesis = verify_header_pow_against_caller_supplied_bits(
        &parsed.metadata.header.raw(),
        LAYER_TWO_SIGNET_GENESIS_BITS,
        PowParameters::LAYER_TWO_SIGNET,
    )
    .map_err(ContextualHeaderError::from)
    .map_err(BmmConfirmationError::from)?;
    let header_chain = HeaderChainState::from_unverified_checkpoint_requires_manifest_binding(
        0,
        verified_genesis,
        verified_genesis.work,
        parsed.metadata.header.time,
    )
    .map_err(ContextualHeaderError::from)
    .map_err(BmmConfirmationError::from)?;
    let contextual =
        ContextualHeaderChainState::from_unverified_checkpoint_requires_manifest_binding(
            header_chain,
            &[parsed.metadata.header.time],
        )?;
    let replay = ElementsSlot24ReplayState::before_parent_genesis(
        ElementsSlot24ReplayConfig::elements_v1(),
    )?;
    let (slot24_replay, _) =
        apply_merkle_bound_elements_slot24_parent_block_owned_with_m6_artifact(
            replay,
            serialized_genesis,
            None,
        )?;
    if slot24_replay.tip_hash() != contextual.header_chain.tip.hash
        || slot24_replay.next_height() != 1
    {
        return Err(BmmConfirmationError::WrongNetworkGenesis);
    }
    Ok(GenesisDerivedLayerTwoSignetReplayState {
        contextual,
        slot24_replay,
    })
}

/// Initialize from the exact frozen Signet genesis and attach the empty USDD
/// accumulator under an identity already authenticated by the deployment
/// manifest. The initial root is forced to the canonical empty depth-64 root;
/// a caller cannot bootstrap an arbitrary approved root through this API.
///
/// This identity argument is not self-authenticating. Deployment code must
/// compare all four fields to its immutable manifest before calling.
pub fn initialize_layer_two_signet_genesis_replay_with_manifest_bound_accumulator(
    serialized_genesis: &[u8],
    accumulator_identity: Slot24AccumulatorIdentity,
) -> Result<GenesisDerivedLayerTwoSignetReplayState, BmmConfirmationError> {
    if accumulator_identity.bitcoin_genesis != usdd_core::Hash32(LAYER_TWO_SIGNET_GENESIS_DISPLAY) {
        return Err(BmmConfirmationError::AccumulatorBitcoinGenesisMismatch);
    }
    let mut state = initialize_layer_two_signet_genesis_replay(serialized_genesis)?;
    state
        .slot24_replay
        .bind_usdd_accumulator_checkpoint_requires_manifest_binding(
            accumulator_identity,
            Slot24ApprovedRoot::empty(),
        )?;
    Ok(state)
}

/// Initialize the all-256-slot replay from the exact frozen Signet genesis.
///
/// This is the production-strength counterpart to the deliberately restricted
/// slot-24 replay. Its opaque state cannot be constructed from a caller-picked
/// header, active-slot set, CTIP, M4 history, or pending withdrawal bundle.
pub fn initialize_layer_two_signet_multislot_genesis_replay(
    serialized_genesis: &[u8],
) -> Result<GenesisDerivedLayerTwoSignetMultiSlotReplayState, BmmConfirmationError> {
    let parsed = parse_and_verify_block(serialized_genesis)
        .map_err(LayerTwoSignetError::from)
        .map_err(BmmConfirmationError::from)?;
    if parsed.metadata.block_hash
        != BlockHash::from_internal_bytes(LAYER_TWO_SIGNET_GENESIS_INTERNAL)
        || parsed.metadata.header.previous_block != BlockHash::ZERO
        || parsed.metadata.header.bits != LAYER_TWO_SIGNET_GENESIS_BITS
    {
        return Err(BmmConfirmationError::WrongNetworkGenesis);
    }
    verify_parsed_layer_two_signet(&parsed).map_err(BmmConfirmationError::from)?;
    let verified_genesis = verify_header_pow_against_caller_supplied_bits(
        &parsed.metadata.header.raw(),
        LAYER_TWO_SIGNET_GENESIS_BITS,
        PowParameters::LAYER_TWO_SIGNET,
    )
    .map_err(ContextualHeaderError::from)
    .map_err(BmmConfirmationError::from)?;
    let header_chain = HeaderChainState::from_unverified_checkpoint_requires_manifest_binding(
        0,
        verified_genesis,
        verified_genesis.work,
        parsed.metadata.header.time,
    )
    .map_err(ContextualHeaderError::from)
    .map_err(BmmConfirmationError::from)?;
    let contextual =
        ContextualHeaderChainState::from_unverified_checkpoint_requires_manifest_binding(
            header_chain,
            &[parsed.metadata.header.time],
        )?;
    let replay = MultiSlotReplayState::before_parent_genesis();
    let (multislot_replay, _) =
        apply_multislot_parent_block_owned(replay, serialized_genesis, None)?;
    if multislot_replay.tip_hash() != contextual.header_chain.tip.hash
        || multislot_replay.next_height() != 1
    {
        return Err(BmmConfirmationError::WrongNetworkGenesis);
    }
    Ok(GenesisDerivedLayerTwoSignetMultiSlotReplayState {
        contextual,
        multislot_replay,
    })
}

/// Initialize the exact-genesis all-slot replay and bind only the canonical
/// empty USDD accumulator under an identity authenticated by the deployment
/// manifest. No arbitrary accumulator checkpoint is accepted.
pub fn initialize_layer_two_signet_multislot_genesis_replay_with_manifest_bound_accumulator(
    serialized_genesis: &[u8],
    accumulator_identity: Slot24AccumulatorIdentity,
) -> Result<GenesisDerivedLayerTwoSignetMultiSlotReplayState, BmmConfirmationError> {
    if accumulator_identity.bitcoin_genesis != usdd_core::Hash32(LAYER_TWO_SIGNET_GENESIS_DISPLAY) {
        return Err(BmmConfirmationError::AccumulatorBitcoinGenesisMismatch);
    }
    let mut state = initialize_layer_two_signet_multislot_genesis_replay(serialized_genesis)?;
    state
        .multislot_replay
        .bind_empty_accumulator(accumulator_identity)?;
    Ok(state)
}

/// Verify and derive the next genesis-derived parent/replay state over one
/// exact block.
///
/// This is the fail-closed composition boundary for parent-chain approval: the
/// same serialized block must pass exact transaction/Merkle/BIP141 parsing,
/// the pinned sole-network Signet authorization, contextual linkage,
/// difficulty, proof of work, cumulative work, MTP/future time, and ordered
/// slot-24 replay. The optional canonical M6 artifact is untrusted auxiliary
/// data and is checked by that same replay transition.
///
/// The prior state is borrowed and cloned into a candidate. Thus every error
/// leaves the caller's complete contextual and replay snapshot unchanged.
pub fn advance_genesis_derived_layer_two_signet_replay(
    state: &GenesisDerivedLayerTwoSignetReplayState,
    serialized_block: &[u8],
    authenticated_current_time: u64,
    canonical_m6_artifact: Option<&MinerBundleArtifact>,
) -> Result<
    (
        GenesisDerivedLayerTwoSignetReplayState,
        ElementsSlot24BlockEffects,
    ),
    BmmConfirmationError,
> {
    let transition = verify_layer_two_signet_contextual_successor(
        &state.contextual,
        serialized_block,
        authenticated_current_time,
    )
    .map_err(|error| match error {
        ContextualSignetError::Contextual(error) => BmmConfirmationError::ContextualHeader(error),
        ContextualSignetError::Signet(error) => BmmConfirmationError::Signet(error),
    })?;
    let (slot24_replay, effects) =
        apply_merkle_bound_elements_slot24_parent_block_owned_with_m6_artifact(
            state.slot24_replay.clone(),
            serialized_block,
            canonical_m6_artifact,
        )?;
    if slot24_replay.tip_hash() != transition.block.block_hash
        || slot24_replay.next_height() != transition.next_parent_state.header_chain.height + 1
    {
        return Err(BmmConfirmationError::EdgeNotAtTrackedTip);
    }
    let next = GenesisDerivedLayerTwoSignetReplayState {
        contextual: transition.next_parent_state,
        slot24_replay,
    };
    Ok((next, effects))
}

/// Verify and derive the next opaque all-256-slot state over one exact block.
///
/// The same bytes must pass the frozen Signet challenge, contextual
/// PoW/difficulty/work/time rules, exact transaction/Merkle/BIP141 parsing,
/// and ordered BIP300 replay for every slot. The borrowed prior snapshot is
/// unchanged on every failure.
pub fn advance_genesis_derived_layer_two_signet_multislot_replay(
    state: &GenesisDerivedLayerTwoSignetMultiSlotReplayState,
    serialized_block: &[u8],
    authenticated_current_time: u64,
    canonical_m6_artifact: Option<&MinerBundleArtifact>,
) -> Result<
    (
        GenesisDerivedLayerTwoSignetMultiSlotReplayState,
        MultiSlotBlockEffects,
    ),
    BmmConfirmationError,
> {
    let transition = verify_layer_two_signet_contextual_successor(
        &state.contextual,
        serialized_block,
        authenticated_current_time,
    )
    .map_err(|error| match error {
        ContextualSignetError::Contextual(error) => BmmConfirmationError::ContextualHeader(error),
        ContextualSignetError::Signet(error) => BmmConfirmationError::Signet(error),
    })?;
    let (multislot_replay, effects) = apply_multislot_parent_block_owned(
        state.multislot_replay.clone(),
        serialized_block,
        canonical_m6_artifact,
    )?;
    if multislot_replay.tip_hash() != transition.block.block_hash
        || multislot_replay.next_height() != transition.next_parent_state.header_chain.height + 1
    {
        return Err(BmmConfirmationError::EdgeNotAtTrackedTip);
    }
    let next = GenesisDerivedLayerTwoSignetMultiSlotReplayState {
        contextual: transition.next_parent_state,
        multislot_replay,
    };
    Ok((next, effects))
}

/// Verify an exact block containing a canonical approved accumulator M6 and
/// begin its unforgeable 100-confirmation tracker on that same branch.
pub fn verify_and_track_layer_two_signet_approved_slot24_accumulator_m6(
    state: &GenesisDerivedLayerTwoSignetReplayState,
    serialized_block: &[u8],
    authenticated_current_time: u64,
    canonical_m6_artifact: &MinerBundleArtifact,
) -> Result<ApprovedSlot24AccumulatorM6FinalityTracker, BmmConfirmationError> {
    let (next, effects) = advance_genesis_derived_layer_two_signet_replay(
        state,
        serialized_block,
        authenticated_current_time,
        Some(canonical_m6_artifact),
    )?;
    let approval = effects
        .approved_accumulator_m6
        .ok_or(BmmConfirmationError::MissingApprovedSlot24AccumulatorM6)?;
    ApprovedSlot24AccumulatorM6FinalityTracker::bind(next, approval)
}

/// Verify the exact all-slot block containing a canonical slot-24 accumulator
/// M6 and bind its approval to an opaque 100-confirmation branch tracker.
pub fn verify_and_track_layer_two_signet_multislot_approved_slot24_accumulator_m6(
    state: &GenesisDerivedLayerTwoSignetMultiSlotReplayState,
    serialized_block: &[u8],
    authenticated_current_time: u64,
    canonical_m6_artifact: &MinerBundleArtifact,
) -> Result<MultiSlotApprovedSlot24AccumulatorM6FinalityTracker, BmmConfirmationError> {
    let (next, effects) = advance_genesis_derived_layer_two_signet_multislot_replay(
        state,
        serialized_block,
        authenticated_current_time,
        Some(canonical_m6_artifact),
    )?;
    let approval = effects
        .approved_slot24_accumulator_m6
        .ok_or(BmmConfirmationError::MissingApprovedSlot24AccumulatorM6)?;
    MultiSlotApprovedSlot24AccumulatorM6FinalityTracker::bind(next, approval)
}

/// Derive a confirmation tracker from a genesis-derived state and one exact
/// serialized parent block. Only a canonical M7 observed while the frozen
/// proposal is active can create the tracker; neither the edge nor its prior
/// replay/header state is accepted from caller assertions.
pub fn verify_and_bind_layer_two_signet_bmm_confirmation_tracker(
    state: &GenesisDerivedLayerTwoSignetReplayState,
    serialized_block: &[u8],
    authenticated_current_time: u64,
    independently_validated_child_hash: BlockHash,
) -> Result<
    (
        GenesisDerivedLayerTwoSignetReplayState,
        BmmConfirmationTracker,
    ),
    BmmConfirmationError,
> {
    let (next, effects) = advance_genesis_derived_layer_two_signet_replay(
        state,
        serialized_block,
        authenticated_current_time,
        None,
    )?;
    let edge = effects
        .bmm_edge
        .ok_or(BmmConfirmationError::MissingCanonicalActiveM7)?;
    let tracker = BmmConfirmationTracker::bind_at_current_tip(
        next.contextual,
        edge,
        independently_validated_child_hash,
    )?;
    Ok((next, tracker))
}

/// Production-direction parent primitive: exact block/Merkle/BIP141 checks,
/// immutable LayerTwo Signet authorization, successor difficulty/PoW/work, and
/// unique canonical slot-24 M7 extraction in one fail-closed transition.
///
/// Exact M3/M4/M6 replay, the selected Bitcoin fork model, confirmation
/// tracking, and M6id-to-redemption-batch binding remain mandatory higher-layer
/// authorization obligations.
pub fn verify_layer_two_signet_pow_merkle_bound_elements_m7_successor(
    prior: &HeaderChainState,
    serialized_block: &[u8],
) -> Result<SignetPowMerkleBoundM7Transition, LayerTwoSignetError> {
    let parsed = parse_and_verify_block(serialized_block)?;
    verify_parsed_layer_two_signet(&parsed)?;
    let next_parent_state = verify_successor(
        prior,
        &parsed.metadata.header.raw(),
        PowParameters::LAYER_TWO_SIGNET,
    )?;
    let output_scripts = parsed
        .coinbase
        .outputs
        .iter()
        .map(|output| output.script)
        .collect::<Vec<_>>();
    let m7 = extract_elements_slot24_m7(&output_scripts)?;
    Ok(SignetPowMerkleBoundM7Transition {
        next_parent_state,
        commitment: PowMerkleBoundM7 {
            parent_block_hash: parsed.metadata.block_hash,
            parent_height: next_parent_state.height,
            coinbase_txid: parsed.metadata.coinbase_txid,
            output_index: m7.output_index,
            committed_child_hash: m7.committed_child_hash,
            transaction_count: parsed.metadata.transaction_count,
            block_weight: parsed.metadata.weight,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    _ => panic!("non-hex fixture"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    fn layer_two_genesis() -> Vec<u8> {
        hex(concat!(
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
        ))
    }

    fn elements_parent_block_218() -> Vec<u8> {
        hex(concat!(
            "000000204ce0fa42ef5db70645d0a7477cf5f0a6a6c11c582caa2378322be20262010000",
            "215bd43642993a5d2930a576baccf213eb8de9f4304cd843b4a81f32c138a440",
            "c6265d6aae77031e6547600001",
            "02000000000101",
            "0000000000000000000000000000000000000000000000000000000000000000ffffffff",
            "0302da00ffffffff04",
            "0000000000000000276a25d161736818bd6d4b20d700608bde9d8fbe416c3497707e3f53d3988c5d26863acdb6c9e6f8",
            "0000000000000000086a06d77d177601ff",
            "00f2052a0100000016001444b2cd80b45f34fb2557b0e224f335be7d3a3097",
            "0000000000000000986a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c70",
            "ecc7daa200024730440220485c74793dfc6c875130f69d7f94dd1309e5143a308637c1dcbf91ece176d751",
            "02205e64b759fbaba19f2141856cbe7ad3c8980f964ea6ad95685bccb5d15bfb976d01",
            "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "01200000000000000000000000000000000000000000000000000000000000000000",
            "00000000"
        ))
    }

    /// Unit-test-only checkpoint immediately before the checked-in real block
    /// 218. Public code cannot construct `GenesisDerivedLayerTwoSignetReplayState`
    /// this way; the production constructor starts at the exact frozen genesis.
    fn private_checkpoint_before_block_218() -> GenesisDerivedLayerTwoSignetReplayState {
        let block = elements_parent_block_218();
        let header = crate::BitcoinHeader::decode_exact(&block[..crate::BITCOIN_HEADER_LEN])
            .expect("block 218 header");
        let target = crate::decode_and_validate_target(
            header.bits,
            crate::PowParameters::LAYER_TWO_SIGNET.pow_limit,
        )
        .expect("frozen target");
        let work = crate::block_work(target).expect("frozen work");
        // The checkpoint constructor explicitly does not authenticate its
        // fields. Fabricating the parent hash here is acceptable only inside
        // this private test helper; the public combined state has no such
        // constructor.
        let parent = crate::PowVerifiedHeader {
            header,
            hash: header.previous_block,
            target,
            work,
        };
        let header_chain =
            crate::HeaderChainState::from_unverified_checkpoint_requires_manifest_binding(
                217,
                parent,
                work,
                header.time.saturating_sub(217 * 600),
            )
            .expect("test checkpoint");
        let mut timestamps = [0u32; crate::BITCOIN_MEDIAN_TIME_SPAN];
        for (index, timestamp) in timestamps.iter_mut().enumerate() {
            *timestamp = header.time - 10 + index as u32;
        }
        let contextual =
            crate::ContextualHeaderChainState::from_unverified_checkpoint_requires_manifest_binding(
                header_chain,
                &timestamps,
            )
            .expect("test MTP checkpoint");
        let config = crate::ElementsSlot24ReplayConfig::elements_v1();
        let replay =
            crate::ElementsSlot24ReplayState::from_unverified_checkpoint_requires_manifest_binding(
                config,
                217,
                header.previous_block,
                Some(config.required_proposal_hash()),
                Some((100, BlockHash::from_internal_bytes([1; 32]))),
                Vec::new(),
                None,
            )
            .expect("test slot-24 checkpoint");
        GenesisDerivedLayerTwoSignetReplayState {
            contextual,
            slot24_replay: replay,
        }
    }

    fn invalid_auxiliary_m6_artifact() -> MinerBundleArtifact {
        MinerBundleArtifact {
            bitcoin_genesis: usdd_core::Hash32([1; 32]),
            elements_genesis: usdd_core::Hash32([2; 32]),
            usdd_asset: usdd_core::Hash32([3; 32]),
            vault_id: usdd_core::Hash32([4; 32]),
            prior_claim_count: 0,
            prior_claim_root: usdd_core::Hash32([5; 32]),
            next_claim_count: 0,
            next_claim_root: usdd_core::Hash32([6; 32]),
            fee_sats: 0,
        }
    }

    #[test]
    fn real_elements_parent_block_218_signature_and_witness_commitment_verify() {
        let block = elements_parent_block_218();
        let verified = verify_layer_two_signet_block_solution(&block).expect("real Signet block");
        assert_eq!(verified.transaction_count, 1);
        assert_eq!(
            verified.block_hash.to_internal_bytes(),
            double_sha256(&block[..80])
        );
    }

    #[test]
    fn composed_replay_state_only_initializes_from_exact_frozen_genesis() {
        let genesis = layer_two_genesis();
        let state =
            initialize_layer_two_signet_genesis_replay(&genesis).expect("frozen LayerTwo genesis");
        assert_eq!(state.next_height(), 1);
        assert_eq!(
            state.tip_hash(),
            BlockHash::from_internal_bytes(LAYER_TWO_SIGNET_GENESIS_INTERNAL)
        );
        assert_eq!(state.contextual().header_chain.height, 0);

        let mut altered = genesis;
        altered[76] ^= 1;
        assert!(initialize_layer_two_signet_genesis_replay(&altered).is_err());

        let identity = Slot24AccumulatorIdentity {
            bitcoin_genesis: usdd_core::Hash32(LAYER_TWO_SIGNET_GENESIS_DISPLAY),
            elements_genesis: usdd_core::Hash32([2; 32]),
            usdd_asset: usdd_core::Hash32([3; 32]),
            vault_id: usdd_core::Hash32([4; 32]),
        };
        let bound = initialize_layer_two_signet_genesis_replay_with_manifest_bound_accumulator(
            &layer_two_genesis(),
            identity,
        )
        .expect("manifest-bound empty accumulator");
        assert_eq!(bound.slot24_replay.accumulator_identity(), Some(identity));
        assert_eq!(
            bound.slot24_replay.approved_root(),
            Some(Slot24ApprovedRoot::empty())
        );

        let mut wrong_parent = identity;
        wrong_parent.bitcoin_genesis = usdd_core::Hash32([1; 32]);
        assert_eq!(
            initialize_layer_two_signet_genesis_replay_with_manifest_bound_accumulator(
                &layer_two_genesis(),
                wrong_parent,
            ),
            Err(BmmConfirmationError::AccumulatorBitcoinGenesisMismatch)
        );
    }

    #[test]
    fn multislot_replay_state_only_initializes_from_exact_frozen_genesis() {
        let genesis = layer_two_genesis();
        let state = initialize_layer_two_signet_multislot_genesis_replay(&genesis)
            .expect("frozen all-slot genesis");
        assert_eq!(state.next_height(), 1);
        assert_eq!(
            state.tip_hash(),
            BlockHash::from_internal_bytes(LAYER_TWO_SIGNET_GENESIS_INTERNAL)
        );
        assert_eq!(state.contextual().header_chain.height, 0);
        assert_eq!(state.active_slot_count(), 0);
        assert_eq!(
            state.slot24_usdd_continuity(),
            Slot24UsddContinuity::Unactivated
        );

        let mut altered = genesis;
        altered[76] ^= 1;
        assert!(initialize_layer_two_signet_multislot_genesis_replay(&altered).is_err());

        let identity = Slot24AccumulatorIdentity {
            bitcoin_genesis: usdd_core::Hash32(LAYER_TWO_SIGNET_GENESIS_DISPLAY),
            elements_genesis: usdd_core::Hash32([2; 32]),
            usdd_asset: usdd_core::Hash32([3; 32]),
            vault_id: usdd_core::Hash32([4; 32]),
        };
        let bound =
            initialize_layer_two_signet_multislot_genesis_replay_with_manifest_bound_accumulator(
                &layer_two_genesis(),
                identity,
            )
            .expect("manifest-bound empty all-slot accumulator");
        assert_eq!(
            bound.approved_slot24_root(),
            Some(Slot24ApprovedRoot::empty())
        );

        let mut wrong_parent = identity;
        wrong_parent.bitcoin_genesis = usdd_core::Hash32([1; 32]);
        assert_eq!(
            initialize_layer_two_signet_multislot_genesis_replay_with_manifest_bound_accumulator(
                &layer_two_genesis(),
                wrong_parent,
            ),
            Err(BmmConfirmationError::AccumulatorBitcoinGenesisMismatch)
        );
    }

    #[test]
    fn composed_transition_rejects_wrong_branch_and_artifact_without_mutating_snapshot() {
        let genesis = layer_two_genesis();
        let genesis_state =
            initialize_layer_two_signet_genesis_replay(&genesis).expect("frozen LayerTwo genesis");
        let untouched_genesis = genesis_state.clone();
        assert!(advance_genesis_derived_layer_two_signet_replay(
            &genesis_state,
            &elements_parent_block_218(),
            2_000_000_000,
            None,
        )
        .is_err());
        assert_eq!(genesis_state, untouched_genesis);

        // The real block is a valid exact/Merkle/BIP141/Signet/PoW successor
        // of this private pre-218 scaffold. With no CTIP decrease, supplying
        // any M6 artifact must fail at the ordered replay boundary.
        let checkpoint = private_checkpoint_before_block_218();
        let untouched_checkpoint = checkpoint.clone();
        let error = advance_genesis_derived_layer_two_signet_replay(
            &checkpoint,
            &elements_parent_block_218(),
            2_000_000_000,
            Some(&invalid_auxiliary_m6_artifact()),
        )
        .expect_err("artifact without an exact M6 transition");
        assert_eq!(
            error,
            BmmConfirmationError::Slot24Replay(
                crate::ElementsSlot24ReplayError::UnexpectedCanonicalM6Artifact
            )
        );
        assert_eq!(checkpoint, untouched_checkpoint);

        // A successful transition is functional: independent state copies
        // derive the same branch without modifying the common ancestor.
        let (left, _) = advance_genesis_derived_layer_two_signet_replay(
            &checkpoint,
            &elements_parent_block_218(),
            2_000_000_000,
            None,
        )
        .expect("valid composed block");
        let (right, _) = advance_genesis_derived_layer_two_signet_replay(
            &checkpoint,
            &elements_parent_block_218(),
            2_000_000_000,
            None,
        )
        .expect("same valid composed block");
        assert_eq!(left, right);
        assert_eq!(checkpoint, untouched_checkpoint);
    }

    #[test]
    fn approved_accumulator_root_finalizes_at_exactly_one_hundred_confirmations() {
        let approval = ApprovedSlot24AccumulatorM6 {
            m6id: usdd_core::Hash32([7; 32]),
            transaction_id: BlockHash::from_internal_bytes([8; 32]),
            block_hash: BlockHash::from_internal_bytes([9; 32]),
            block_height: 1_000,
            fee_sats: 42,
            prior_root: Slot24ApprovedRoot::empty(),
            next_root: Slot24ApprovedRoot {
                claim_count: 1,
                claim_root: usdd_core::Hash32([10; 32]),
            },
        };
        let tip = BlockHash::from_internal_bytes([11; 32]);

        assert_eq!(
            finalize_approved_slot24_accumulator_root(approval, tip, 1_000),
            Err(BmmConfirmationError::InsufficientConfirmations {
                required: SLOT24_ACCUMULATOR_M6_FINALITY_CONFIRMATIONS,
                actual: 1,
            })
        );
        assert_eq!(
            finalize_approved_slot24_accumulator_root(approval, tip, 1_098),
            Err(BmmConfirmationError::InsufficientConfirmations {
                required: SLOT24_ACCUMULATOR_M6_FINALITY_CONFIRMATIONS,
                actual: 99,
            })
        );

        let finalized = finalize_approved_slot24_accumulator_root(approval, tip, 1_099)
            .expect("inclusion block plus 99 descendants is 100 confirmations");
        assert_eq!(finalized.root(), approval.next_root);
        assert_eq!(finalized.approved_m6id(), approval.m6id);
        assert_eq!(finalized.inclusion_block_hash(), approval.block_hash);
        assert_eq!(finalized.inclusion_height(), approval.block_height);
        assert_eq!(finalized.finalization_tip_hash(), tip);
        assert_eq!(finalized.finalization_tip_height(), 1_099);
    }

    #[test]
    fn multislot_approved_root_keeps_fixed_inclusive_depth() {
        let approval = ApprovedSlot24AccumulatorM6 {
            m6id: usdd_core::Hash32([0x31; 32]),
            transaction_id: BlockHash::from_internal_bytes([0x32; 32]),
            block_hash: BlockHash::from_internal_bytes([0x33; 32]),
            block_height: 2_000,
            fee_sats: 42,
            prior_root: Slot24ApprovedRoot::empty(),
            next_root: Slot24ApprovedRoot {
                claim_count: 1,
                claim_root: usdd_core::Hash32([0x34; 32]),
            },
        };
        let tip = BlockHash::from_internal_bytes([0x35; 32]);

        for (height, actual) in [(2_000, 1), (2_098, 99)] {
            assert_eq!(
                finalize_approved_slot24_accumulator_root(approval, tip, height),
                Err(BmmConfirmationError::InsufficientConfirmations {
                    required: SLOT24_ACCUMULATOR_M6_FINALITY_CONFIRMATIONS,
                    actual,
                })
            );
        }
        let finalized = finalize_approved_slot24_accumulator_root(approval, tip, 2_099)
            .expect("100 confirmations on the bound branch");
        assert_eq!(finalized.root(), approval.next_root);
    }

    #[test]
    fn multislot_tracker_binding_branch_and_invalidation_fail_closed() {
        let identity = Slot24AccumulatorIdentity {
            bitcoin_genesis: usdd_core::Hash32(LAYER_TWO_SIGNET_GENESIS_DISPLAY),
            elements_genesis: usdd_core::Hash32([0x42; 32]),
            usdd_asset: usdd_core::Hash32([0x43; 32]),
            vault_id: usdd_core::Hash32([0x44; 32]),
        };
        let mut branch =
            initialize_layer_two_signet_multislot_genesis_replay_with_manifest_bound_accumulator(
                &layer_two_genesis(),
                identity,
            )
            .expect("exact genesis branch");
        let root = branch.approved_slot24_root().expect("bound empty root");
        let approval = ApprovedSlot24AccumulatorM6 {
            m6id: usdd_core::Hash32([0x45; 32]),
            transaction_id: BlockHash::from_internal_bytes([0x46; 32]),
            block_hash: branch.tip_hash(),
            block_height: branch.tip_height(),
            fee_sats: 7,
            prior_root: root,
            next_root: root,
        };
        assert_eq!(
            MultiSlotApprovedSlot24AccumulatorM6FinalityTracker::bind(branch.clone(), approval,),
            Err(BmmConfirmationError::Slot24UsddContinuityLost)
        );
        branch
            .multislot_replay
            .install_exact_slot24_activation_for_test();
        let tracker =
            MultiSlotApprovedSlot24AccumulatorM6FinalityTracker::bind(branch.clone(), approval)
                .expect("private bind checks exact branch tip and root");

        let mut wrong_block = approval;
        wrong_block.block_hash = BlockHash::from_internal_bytes([0x47; 32]);
        assert_eq!(
            MultiSlotApprovedSlot24AccumulatorM6FinalityTracker::bind(branch.clone(), wrong_block,),
            Err(BmmConfirmationError::ApprovalNotAtTrackedTip)
        );
        let mut unrelated_root = approval;
        unrelated_root.next_root = Slot24ApprovedRoot {
            claim_count: 1,
            claim_root: usdd_core::Hash32([0x48; 32]),
        };
        assert_eq!(
            MultiSlotApprovedSlot24AccumulatorM6FinalityTracker::bind(
                branch.clone(),
                unrelated_root,
            ),
            Err(BmmConfirmationError::ApprovalRootMismatch)
        );

        // A block from an unrelated branch cannot advance the tracker, and the
        // borrowed tracker remains byte-for-byte unchanged on failure.
        let untouched = tracker.clone();
        assert!(tracker
            .advance(&elements_parent_block_218(), 2_000_000_000, None)
            .is_err());
        assert_eq!(tracker, untouched);

        // The all-slot replay's generic slot-24 test proves that such an M6
        // produces this irreversible state. It halts later canonical roots but
        // does not revoke the immutable approval already bound above.
        let mut invalidated = tracker.clone();
        invalidated
            .branch
            .multislot_replay
            .invalidate_slot24_usdd_for_test();
        assert_eq!(
            invalidated.finalized_root(),
            Err(BmmConfirmationError::InsufficientConfirmations {
                required: SLOT24_ACCUMULATOR_M6_FINALITY_CONFIRMATIONS,
                actual: 1,
            })
        );
    }

    #[test]
    fn signet_signature_commits_header_time_and_modified_merkle_root() {
        let mut changed_time = elements_parent_block_218();
        changed_time[68] ^= 1;
        assert_eq!(
            verify_layer_two_signet_block_solution(&changed_time),
            Err(LayerTwoSignetError::InvalidSignature)
        );

        let mut changed_solution = elements_parent_block_218();
        let signature_byte = changed_solution
            .windows(4)
            .position(|window| window == SIGNET_HEADER)
            .expect("Signet header")
            + SIGNET_HEADER.len()
            + 8;
        changed_solution[signature_byte] ^= 1;
        assert!(matches!(
            verify_layer_two_signet_block_solution(&changed_solution),
            Err(LayerTwoSignetError::InvalidDerSignature)
                | Err(LayerTwoSignetError::InvalidSignature)
                | Err(LayerTwoSignetError::Block(
                    BlockStructureError::WitnessCommitmentMismatch
                        | BlockStructureError::MerkleRootMismatch
                ))
        ));
    }

    #[test]
    fn strict_der_matches_bitcoin_core_boundary_rules() {
        let valid = hex(
            "30440220485c74793dfc6c875130f69d7f94dd1309e5143a308637c1dcbf91ece176d75102205e64b759fbaba19f2141856cbe7ad3c8980f964ea6ad95685bccb5d15bfb976d01",
        );
        assert!(strict_der_encoding(&valid));
        let mut trailing = valid.clone();
        trailing.push(1);
        assert!(!strict_der_encoding(&trailing));
        let mut negative_r = valid;
        negative_r[4] |= 0x80;
        assert!(!strict_der_encoding(&negative_r));
    }

    #[test]
    fn solution_codec_rejects_noncanonical_lengths_and_trailing_data() {
        assert_eq!(
            parse_solution(&[0xfd, 0, 0, 0]),
            Err(LayerTwoSignetError::NonCanonicalSolution)
        );
        assert_eq!(
            parse_solution(&[0, 0, 1]),
            Err(LayerTwoSignetError::NonCanonicalSolution)
        );
    }

    #[test]
    fn fetch_and_clear_matches_core_on_malformed_trailing_script() {
        let script = [0x05, 0xec, 0xc7, 0xda, 0xa2, 0x99, 0x4c];
        let (solution, replacement) = extract_solution_and_modified_script(&script)
            .expect("header precedes malformed suffix");
        assert_eq!(solution, [0x99]);
        assert_eq!(replacement, [0x04, 0xec, 0xc7, 0xda, 0xa2]);

        assert_eq!(
            extract_solution_and_modified_script(&[0x4c]),
            Err(LayerTwoSignetError::MissingSolution)
        );
    }
}
