#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

//! Deterministic state and public journals for recursive eCash proofs.
//!
//! This crate does not contain a mock proof verifier. It is the pure transition
//! program shared by native tests and the SP1 segment guest. The relay may only
//! trust its output after the immutable production verifier authenticates the
//! frozen segment/fold program IDs.

extern crate alloc;

mod accumulator;
mod codec;
mod segment;

pub use accumulator::{
    approval_event_leaf, approval_node, empty_approval_root, ApprovalAccumulator,
    APPROVAL_TREE_DEPTH,
};
pub use codec::{
    ApprovalEvent, BlockWitness, EcashProofConfig, EcashProofState, FoldError, PendingApproval,
    ProofCodecError, SegmentInput, SegmentOutput, ABSOLUTE_MAX_SEGMENT_BLOCKS,
    ABSOLUTE_MAX_SEGMENT_BYTES, ABSOLUTE_MAX_STATE_BYTES, ABSOLUTE_MAX_TRANSITION_BLOCKS,
    ECASH_FOLD_JOURNAL_DOMAIN, ECASH_SEGMENT_JOURNAL_DOMAIN, MAX_PENDING_APPROVALS,
};
pub use segment::{bootstrap_state, execute_segment, fold_outputs, SegmentError};
