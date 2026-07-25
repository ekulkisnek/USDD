//! Contextual parent-header and BMM confirmation tracking.
//!
//! These types make two authorization obligations non-optional for the
//! incremental Bitcoin/BIP300 relay: Bitcoin median-time-past and the
//! configured BMM confirmation depth.
//! They deliberately do not claim that the complete Bitcoin block/UTXO/script
//! rules or a globally complete set of competing forks has been proved.

use crate::{
    verify_successor, BitcoinHeader, BlockHash, ElementsSlot24BmmEdge, ElementsSlot24ReplayError,
    HeaderChainState, HeaderError, LayerTwoSignetError, MultiSlotReplayError, PowParameters,
};

/// Bitcoin Core's median-time-past window (`nMedianTimeSpan`).
pub const BITCOIN_MEDIAN_TIME_SPAN: usize = 11;

/// Bitcoin Core rejects a header more than two hours ahead of adjusted time.
pub const BITCOIN_MAX_FUTURE_BLOCK_TIME_SECONDS: u32 = 2 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextualHeaderError {
    Header(HeaderError),
    InvalidCheckpoint,
    TimestampNotAfterMedian,
    TimestampTooFarInFuture,
    AuthenticatedTimeOverflow,
}

impl From<HeaderError> for ContextualHeaderError {
    fn from(value: HeaderError) -> Self {
        Self::Header(value)
    }
}

/// The last one-to-eleven parent timestamps in oldest-to-newest order.
///
/// A checkpoint constructor cannot authenticate these values. Production code
/// must bind the entire value to a manifest/genesis-derived consensus-state
/// commitment before extending it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MedianTimePastWindow {
    timestamps: [u32; BITCOIN_MEDIAN_TIME_SPAN],
    len: u8,
}

impl MedianTimePastWindow {
    pub fn from_unverified_checkpoint_requires_manifest_binding(
        height: u32,
        timestamps_oldest_to_newest: &[u32],
    ) -> Result<Self, ContextualHeaderError> {
        let expected = core::cmp::min(
            usize::try_from(height)
                .map_err(|_| ContextualHeaderError::InvalidCheckpoint)?
                .checked_add(1)
                .ok_or(ContextualHeaderError::InvalidCheckpoint)?,
            BITCOIN_MEDIAN_TIME_SPAN,
        );
        if timestamps_oldest_to_newest.len() != expected || timestamps_oldest_to_newest.contains(&0)
        {
            return Err(ContextualHeaderError::InvalidCheckpoint);
        }
        let mut timestamps = [0u32; BITCOIN_MEDIAN_TIME_SPAN];
        timestamps[..expected].copy_from_slice(timestamps_oldest_to_newest);
        Ok(Self {
            timestamps,
            len: u8::try_from(expected).expect("median-time span fits u8"),
        })
    }

    pub const fn len(self) -> u8 {
        self.len
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    pub fn timestamps_oldest_to_newest(&self) -> &[u32] {
        &self.timestamps[..usize::from(self.len)]
    }

    /// Match `CBlockIndex::GetMedianTimePast`: sort a copy and select the
    /// middle element (the upper middle for an even-sized early-chain window).
    pub fn median(self) -> u32 {
        let len = usize::from(self.len);
        let mut sorted = self.timestamps;
        sorted[..len].sort_unstable();
        sorted[len / 2]
    }

    fn push(&mut self, timestamp: u32) {
        let len = usize::from(self.len);
        if len < BITCOIN_MEDIAN_TIME_SPAN {
            self.timestamps[len] = timestamp;
            self.len += 1;
        } else {
            self.timestamps.copy_within(1..BITCOIN_MEDIAN_TIME_SPAN, 0);
            self.timestamps[BITCOIN_MEDIAN_TIME_SPAN - 1] = timestamp;
        }
    }
}

/// A continuously derived parent-header state with authenticated MTP context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextualHeaderChainState {
    pub header_chain: HeaderChainState,
    pub median_time_window: MedianTimePastWindow,
}

impl ContextualHeaderChainState {
    pub fn from_unverified_checkpoint_requires_manifest_binding(
        header_chain: HeaderChainState,
        timestamps_oldest_to_newest: &[u32],
    ) -> Result<Self, ContextualHeaderError> {
        let median_time_window =
            MedianTimePastWindow::from_unverified_checkpoint_requires_manifest_binding(
                header_chain.height,
                timestamps_oldest_to_newest,
            )?;
        if median_time_window
            .timestamps_oldest_to_newest()
            .last()
            .copied()
            != Some(header_chain.tip.header.time)
        {
            return Err(ContextualHeaderError::InvalidCheckpoint);
        }
        Ok(Self {
            header_chain,
            median_time_window,
        })
    }

    pub fn median_time_past(self) -> u32 {
        self.median_time_window.median()
    }
}

/// Verify linkage, expected difficulty, PoW, cumulative work, MTP, and the
/// two-hour future-time bound against an externally authenticated current time.
///
/// The current time must come from a cryptographically authenticated input;
/// an RPC/wall-clock value is not sufficient for a validity proof. This is
/// still not complete contextual Bitcoin block validation.
pub fn verify_contextual_successor(
    state: &ContextualHeaderChainState,
    header_bytes: &[u8],
    params: PowParameters,
    authenticated_current_time: u64,
) -> Result<ContextualHeaderChainState, ContextualHeaderError> {
    let header = BitcoinHeader::decode_exact(header_bytes)?;
    let maximum_time = authenticated_current_time
        .checked_add(u64::from(BITCOIN_MAX_FUTURE_BLOCK_TIME_SECONDS))
        .ok_or(ContextualHeaderError::AuthenticatedTimeOverflow)?;
    if u64::from(header.time) > maximum_time {
        return Err(ContextualHeaderError::TimestampTooFarInFuture);
    }
    verify_mtp_successor(state, header_bytes, params)
}

/// Verify the continuously authenticated header transition and Bitcoin's MTP
/// lower bound, but not the adjusted-time upper bound. This split exists so a
/// proof scaffold cannot disguise a prover-supplied clock as authenticated.
pub fn verify_mtp_successor(
    state: &ContextualHeaderChainState,
    header_bytes: &[u8],
    params: PowParameters,
) -> Result<ContextualHeaderChainState, ContextualHeaderError> {
    let header = BitcoinHeader::decode_exact(header_bytes)?;
    if header.time <= state.median_time_past() {
        return Err(ContextualHeaderError::TimestampNotAfterMedian);
    }
    let header_chain = verify_successor(&state.header_chain, header_bytes, params)?;
    let mut median_time_window = state.median_time_window;
    median_time_window.push(header.time);
    Ok(ContextualHeaderChainState {
        header_chain,
        median_time_window,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BmmConfirmationError {
    WrongNetworkGenesis,
    AccumulatorBitcoinGenesisMismatch,
    EdgeNotAtTrackedTip,
    WrongCommittedChild,
    MissingApprovedSlot24AccumulatorM6,
    ApprovalNotAtTrackedTip,
    ApprovalRootMismatch,
    Slot24UsddContinuityLost,
    HeightOverflow,
    TipBeforeCommitment,
    InsufficientConfirmations { required: u32, actual: u32 },
    ContextualHeader(ContextualHeaderError),
    Signet(LayerTwoSignetError),
    Slot24Replay(ElementsSlot24ReplayError),
    MultiSlotReplay(MultiSlotReplayError),
    MissingCanonicalActiveM7,
}

impl From<ContextualHeaderError> for BmmConfirmationError {
    fn from(value: ContextualHeaderError) -> Self {
        Self::ContextualHeader(value)
    }
}

impl From<LayerTwoSignetError> for BmmConfirmationError {
    fn from(value: LayerTwoSignetError) -> Self {
        Self::Signet(value)
    }
}

impl From<ElementsSlot24ReplayError> for BmmConfirmationError {
    fn from(value: ElementsSlot24ReplayError) -> Self {
        Self::Slot24Replay(value)
    }
}

impl From<MultiSlotReplayError> for BmmConfirmationError {
    fn from(value: MultiSlotReplayError) -> Self {
        Self::MultiSlotReplay(value)
    }
}

/// Bitcoin's confirmation count for a block on one continuously authenticated
/// branch. The commitment block itself has one confirmation.
pub fn bitcoin_block_confirmations(
    commitment_height: u32,
    tip_height: u32,
) -> Result<u32, BmmConfirmationError> {
    tip_height
        .checked_sub(commitment_height)
        .and_then(|depth| depth.checked_add(1))
        .ok_or(BmmConfirmationError::TipBeforeCommitment)
}

/// A slot-24 BMM edge kept together with the exact branch that contained it.
///
/// Construction requires the edge to be at the tracked tip. Every later tip
/// can only be obtained by applying a contextual successor to this object, so
/// confirmation depth cannot be fabricated by supplying an unrelated height.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BmmConfirmationTracker {
    chain: ContextualHeaderChainState,
    edge: ElementsSlot24BmmEdge,
}

impl BmmConfirmationTracker {
    /// This constructor is deliberately crate-private. An edge is a plain
    /// decoded fact and its public fields can be fabricated by a caller. The
    /// public integrated constructor must derive it from the exact serialized
    /// block while applying the slot-24 replay and contextual Signet checks.
    pub(crate) fn bind_at_current_tip(
        chain: ContextualHeaderChainState,
        edge: ElementsSlot24BmmEdge,
        independently_validated_child_hash: BlockHash,
    ) -> Result<Self, BmmConfirmationError> {
        if edge.successor_height != chain.header_chain.height
            || edge.successor_block_hash != chain.header_chain.tip.hash
        {
            return Err(BmmConfirmationError::EdgeNotAtTrackedTip);
        }
        if edge.committed_child_hash != independently_validated_child_hash {
            return Err(BmmConfirmationError::WrongCommittedChild);
        }
        Ok(Self { chain, edge })
    }

    pub const fn chain(&self) -> ContextualHeaderChainState {
        self.chain
    }

    pub const fn edge(&self) -> ElementsSlot24BmmEdge {
        self.edge
    }

    pub fn confirmations(&self) -> Result<u32, BmmConfirmationError> {
        bitcoin_block_confirmations(self.edge.successor_height, self.chain.header_chain.height)
    }

    pub fn require_confirmations(&self, required: u32) -> Result<(), BmmConfirmationError> {
        let actual = self.confirmations()?;
        if required == 0 || actual < required {
            return Err(BmmConfirmationError::InsufficientConfirmations { required, actual });
        }
        Ok(())
    }

    /// Advance on the same authenticated branch. The caller must separately
    /// prove exact block/Merkle and Signet authorization; the integrated
    /// Signet helper composes those checks around this contextual transition.
    pub(crate) fn replace_chain(&mut self, next: ContextualHeaderChainState) {
        self.chain = next;
    }
}

/// One fully validated candidate tip relative to a common authenticated fork
/// anchor. The validation that produced each candidate is outside this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkForkCandidate {
    pub common_anchor_hash: BlockHash,
    pub common_anchor_height: u32,
    pub tip_hash: BlockHash,
    pub tip_height: u32,
    pub cumulative_work: crate::Uint256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkChoiceError {
    NoCandidates,
    TooManyCandidates,
    MismatchedAnchor,
    InvalidCandidate,
    DuplicateTip,
    EqualBestWork,
}

/// Select the unique greatest-work tip among an explicitly enumerated bounded
/// candidate set. Equal-work ties fail closed instead of using arrival order.
///
/// This function cannot prove that a prover supplied every public fork. It is
/// only a deterministic final step after the future guest has authenticated a
/// complete candidate set under its fork-availability model.
pub fn select_unique_best_work_tip(
    candidates: &[WorkForkCandidate],
) -> Result<WorkForkCandidate, ForkChoiceError> {
    const MAX_CANDIDATES: usize = 64;
    let first = *candidates.first().ok_or(ForkChoiceError::NoCandidates)?;
    if candidates.len() > MAX_CANDIDATES {
        return Err(ForkChoiceError::TooManyCandidates);
    }
    let mut best = first;
    let mut best_is_tied = false;
    for (index, candidate) in candidates.iter().copied().enumerate() {
        if candidate.common_anchor_hash != first.common_anchor_hash
            || candidate.common_anchor_height != first.common_anchor_height
        {
            return Err(ForkChoiceError::MismatchedAnchor);
        }
        if candidate.common_anchor_hash == BlockHash::ZERO
            || candidate.tip_hash == BlockHash::ZERO
            || candidate.tip_height < candidate.common_anchor_height
            || candidate.cumulative_work.is_zero()
        {
            return Err(ForkChoiceError::InvalidCandidate);
        }
        if candidates[..index]
            .iter()
            .any(|prior| prior.tip_hash == candidate.tip_hash)
        {
            return Err(ForkChoiceError::DuplicateTip);
        }
        match candidate.cumulative_work.cmp(&best.cumulative_work) {
            core::cmp::Ordering::Greater => {
                best = candidate;
                best_is_tied = false;
            }
            core::cmp::Ordering::Equal if candidate.tip_hash != best.tip_hash => {
                best_is_tied = true;
            }
            core::cmp::Ordering::Less | core::cmp::Ordering::Equal => {}
        }
    }
    if best_is_tied {
        return Err(ForkChoiceError::EqualBestWork);
    }
    Ok(best)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block_work, verify_header_pow_against_caller_supplied_bits, CompactTargetError, Uint256,
    };

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_internal_bytes([byte; 32])
    }

    fn candidate(tip: u8, work: u64) -> WorkForkCandidate {
        WorkForkCandidate {
            common_anchor_hash: hash(9),
            common_anchor_height: 100,
            tip_hash: hash(tip),
            tip_height: 101,
            cumulative_work: Uint256::from_limbs_le([work, 0, 0, 0]),
        }
    }

    #[test]
    fn median_time_uses_upper_middle_and_rolls_exactly_eleven() {
        let mut window =
            MedianTimePastWindow::from_unverified_checkpoint_requires_manifest_binding(
                3,
                &[40, 10, 30, 20],
            )
            .expect("checkpoint");
        assert_eq!(window.median(), 30);
        for value in [50, 60, 70, 80, 90, 100, 110, 120] {
            window.push(value);
        }
        assert_eq!(window.len(), 11);
        assert_eq!(
            window.timestamps_oldest_to_newest(),
            &[10, 30, 20, 50, 60, 70, 80, 90, 100, 110, 120]
        );
    }

    #[test]
    fn checkpoint_requires_exact_height_window_and_tip_timestamp() {
        assert_eq!(
            MedianTimePastWindow::from_unverified_checkpoint_requires_manifest_binding(10, &[1]),
            Err(ContextualHeaderError::InvalidCheckpoint)
        );
    }

    #[test]
    fn confirmations_include_commitment_block_and_reject_underflow() {
        assert_eq!(bitcoin_block_confirmations(50, 50), Ok(1));
        assert_eq!(bitcoin_block_confirmations(50, 148), Ok(99));
        assert_eq!(bitcoin_block_confirmations(50, 149), Ok(100));
        assert_eq!(
            bitcoin_block_confirmations(51, 50),
            Err(BmmConfirmationError::TipBeforeCommitment)
        );
    }

    #[test]
    fn fork_choice_requires_unique_best_and_common_anchor() {
        assert_eq!(
            select_unique_best_work_tip(&[candidate(1, 10), candidate(2, 11)]),
            Ok(candidate(2, 11))
        );
        assert_eq!(
            select_unique_best_work_tip(&[candidate(1, 11), candidate(2, 11)]),
            Err(ForkChoiceError::EqualBestWork)
        );
        let mut wrong_anchor = candidate(2, 12);
        wrong_anchor.common_anchor_hash = hash(8);
        assert_eq!(
            select_unique_best_work_tip(&[candidate(1, 11), wrong_anchor]),
            Err(ForkChoiceError::MismatchedAnchor)
        );
        assert_eq!(
            select_unique_best_work_tip(&[candidate(1, 11), candidate(1, 12)]),
            Err(ForkChoiceError::DuplicateTip)
        );
    }

    #[test]
    fn compact_work_helper_still_fails_on_zero_target() {
        let _ = block_work(Uint256::from_limbs_le([1, 0, 0, 0])).expect("nonzero target");
        let header = [0u8; 80];
        assert!(matches!(
            verify_header_pow_against_caller_supplied_bits(
                &header,
                0,
                PowParameters::LAYER_TWO_SIGNET
            ),
            Err(HeaderError::InvalidTarget(CompactTargetError::Zero))
                | Err(HeaderError::UnexpectedDifficultyBits)
        ));
    }
}
