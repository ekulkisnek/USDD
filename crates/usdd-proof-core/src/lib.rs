#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod annex;
pub mod claims;
pub mod guest;
pub mod journal;

pub use annex::{
    AnnexError, Sp1ProofAnnex, SP1_ANNEX_HEADER_SIZE, SP1_ANNEX_MAGIC, SP1_ANNEX_MAX_SIZE,
    SP1_ANNEX_TAG, SP1_PUBLIC_VALUES_MAX_SIZE,
};
pub use claims::{
    BurnAppend, DepositPublicOutput, ElementsBurnClaim, ElementsStatePublicOutput,
    ElementsStateTransitionClaim, EthereumDepositClaim, EthereumHeartbeatClaim,
    HeartbeatPublicOutput, RedemptionPublicOutput,
};
pub use guest::{
    build_deposit_journal, build_elements_state_journal, build_heartbeat_journal,
    build_redemption_journal, ElementsValidityProofVerifier, EthereumStateProofVerifier,
    GuestError, VerificationError,
};
pub use journal::{
    DigestAlgorithm, JournalError, StatementKind, StrictJournal, JOURNAL_MAGIC,
    JOURNAL_SUCCESS_MARKER,
};
