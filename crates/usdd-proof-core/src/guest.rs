use core::fmt;

use usdd_core::{
    burn_accumulator_empty, hash_bytes, CanonicalEncode, ElementsEventKind, Hash32, MintBatch,
    ProtocolManifest,
};

use crate::{
    claims::{
        DepositPublicOutput, ElementsBurnClaim, ElementsStatePublicOutput,
        ElementsStateTransitionClaim, EthereumDepositClaim, EthereumHeartbeatClaim,
        HeartbeatPublicOutput, RedemptionPublicOutput,
    },
    journal::{JournalError, StatementKind, StrictJournal},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
    InvalidProof(&'static str),
}

/// Production implementations must verify continuous Ethereum light-client
/// transitions, supported forks, finality, execution, vault code/storage, and
/// exact deposits from the manifest bootstrap. RPC data is not proof.
pub trait EthereumStateProofVerifier {
    type Proof;

    fn verify_finalized_deposits(
        &self,
        manifest: &ProtocolManifest,
        claim: &EthereumDepositClaim,
        proof: &Self::Proof,
    ) -> Result<(), VerificationError>;

    fn verify_finalized_heartbeat(
        &self,
        manifest: &ProtocolManifest,
        claim: &EthereumHeartbeatClaim,
        proof: &Self::Proof,
    ) -> Result<(), VerificationError>;
}

/// Production implementations must verify full Elements consensus and state,
/// Bitcoin PoW/difficulty/work/fork choice, and slot-24 BMM ancestry. A BMM
/// commitment or transaction inclusion branch alone is not a validity proof.
pub trait ElementsValidityProofVerifier {
    type Proof;

    fn verify_canonical_burn(
        &self,
        manifest: &ProtocolManifest,
        claim: &ElementsBurnClaim,
        proof: &Self::Proof,
    ) -> Result<(), VerificationError>;

    fn verify_elements_state_transition(
        &self,
        manifest: &ProtocolManifest,
        claim: &ElementsStateTransitionClaim,
        proof: &Self::Proof,
    ) -> Result<(), VerificationError>;
}

const ELEMENTS_STATE_DOMAIN: Hash32 = Hash32([
    0x33, 0x60, 0x66, 0x45, 0xc4, 0x53, 0x27, 0x8a, 0xa6, 0x4c, 0x7b, 0x45, 0xb3, 0xf1, 0x76, 0x05,
    0xcf, 0x89, 0x15, 0x56, 0xe0, 0x07, 0xfc, 0xfc, 0x5b, 0x9b, 0x1d, 0xaa, 0xe4, 0xf6, 0x4d, 0x5b,
]);
const ELEMENTS_STATEMENT_DOMAIN: Hash32 = Hash32([
    0xe3, 0x7b, 0xee, 0x57, 0xc2, 0x73, 0xe8, 0x57, 0x55, 0x23, 0x3d, 0x97, 0x2a, 0xff, 0xf1, 0x8d,
    0xfe, 0x20, 0x82, 0x34, 0xea, 0xb0, 0x44, 0xe5, 0x88, 0xee, 0xc5, 0x32, 0x9f, 0x3e, 0x8d, 0xa6,
]);

pub fn build_deposit_journal<V: EthereumStateProofVerifier>(
    verifier: &V,
    manifest: &ProtocolManifest,
    claim: &EthereumDepositClaim,
    proof: &V::Proof,
) -> Result<StrictJournal, GuestError> {
    manifest
        .validate()
        .map_err(|_| GuestError::InvalidManifest)?;
    let manifest_id = manifest
        .manifest_id()
        .map_err(|_| GuestError::InvalidManifest)?;
    if claim.manifest_id != manifest_id {
        return Err(GuestError::ManifestMismatch);
    }
    claim
        .prior_state
        .validate()
        .map_err(|_| GuestError::InvalidControllerState)?;
    if claim.prior_state.configuration_hash != manifest.controller_configuration_hash {
        return Err(GuestError::ConfigurationMismatch);
    }
    for deposit in &claim.deposits {
        if deposit.ethereum_chain_id != manifest.ethereum_chain_id
            || deposit.vault != manifest.vault
            || deposit.usdt != manifest.usdt
        {
            return Err(GuestError::DepositTargetsWrongVault);
        }
    }
    let mint_batch =
        MintBatch::from_deposits(&claim.deposits).map_err(|_| GuestError::InvalidDepositBatch)?;
    if mint_batch.first_nonce != claim.prior_state.next_mint_nonce {
        return Err(GuestError::DepositNonceNotNext);
    }
    let next_state = claim
        .prior_state
        .apply_mint_batch(
            &mint_batch,
            &claim.finality,
            claim.authenticated_bmm_parent_mtp,
        )
        .map_err(|_| GuestError::InvalidControllerTransition)?;

    verifier
        .verify_finalized_deposits(manifest, claim, proof)
        .map_err(GuestError::VerifierRejected)?;

    let output = DepositPublicOutput {
        manifest_id,
        claim_id: claim.claim_id(),
        prior_state: claim.prior_state.clone(),
        next_state,
        mint_batch,
    };
    StrictJournal::new(
        StatementKind::EthereumState,
        manifest.ethereum_guest_program_id,
        output.encode(),
    )
    .map_err(GuestError::Journal)
}

pub fn build_heartbeat_journal<V: EthereumStateProofVerifier>(
    verifier: &V,
    manifest: &ProtocolManifest,
    claim: &EthereumHeartbeatClaim,
    proof: &V::Proof,
) -> Result<StrictJournal, GuestError> {
    manifest
        .validate()
        .map_err(|_| GuestError::InvalidManifest)?;
    let manifest_id = manifest
        .manifest_id()
        .map_err(|_| GuestError::InvalidManifest)?;
    if claim.manifest_id != manifest_id {
        return Err(GuestError::ManifestMismatch);
    }
    if claim.prior_state.configuration_hash != manifest.controller_configuration_hash {
        return Err(GuestError::ConfigurationMismatch);
    }
    let next_state = claim
        .prior_state
        .apply_heartbeat(&claim.finality, claim.authenticated_bmm_parent_mtp)
        .map_err(|_| GuestError::InvalidControllerTransition)?;
    verifier
        .verify_finalized_heartbeat(manifest, claim, proof)
        .map_err(GuestError::VerifierRejected)?;
    let output = HeartbeatPublicOutput {
        manifest_id,
        claim_id: claim.claim_id(),
        prior_state: claim.prior_state.clone(),
        next_state,
    };
    StrictJournal::new(
        StatementKind::EthereumState,
        manifest.ethereum_guest_program_id,
        output.encode(),
    )
    .map_err(GuestError::Journal)
}

pub fn build_redemption_journal<V: ElementsValidityProofVerifier>(
    verifier: &V,
    manifest: &ProtocolManifest,
    claim: &ElementsBurnClaim,
    proof: &V::Proof,
) -> Result<StrictJournal, GuestError> {
    manifest
        .validate()
        .map_err(|_| GuestError::InvalidManifest)?;
    let manifest_id = manifest
        .manifest_id()
        .map_err(|_| GuestError::InvalidManifest)?;
    if claim.manifest_id != manifest_id {
        return Err(GuestError::ManifestMismatch);
    }
    claim.burn.validate().map_err(|_| GuestError::InvalidBurn)?;
    if claim.burn.vault_id != manifest.vault_id || claim.burn.usdd_asset != manifest.usdd_asset {
        return Err(GuestError::BurnTargetsWrongAssetOrVault);
    }
    let redemption_id = claim.burn.redemption_id(manifest.elements_genesis);
    let expected_payload_commitment = hash_bytes(&claim.burn.burn_payload().encode());
    if claim.event.kind != ElementsEventKind::Burn
        || claim.event.event_id != redemption_id
        || claim.event.outpoint != claim.burn.burn_outpoint
        || claim.event.usdd_amount_base != claim.burn.usdd_amount_base
        || claim.event.payload_commitment != expected_payload_commitment
    {
        return Err(GuestError::ElementsEventMismatch);
    }
    if claim.event.bitcoin_confirmations < manifest.minimum_bitcoin_confirmations {
        return Err(GuestError::InsufficientBitcoinConfirmations);
    }

    verifier
        .verify_canonical_burn(manifest, claim, proof)
        .map_err(GuestError::VerifierRejected)?;

    let output = RedemptionPublicOutput {
        manifest_id,
        claim_id: claim.claim_id(),
        redemption_id,
        burn: claim.burn.clone(),
        elements_block_hash: claim.event.elements_block_hash,
        bitcoin_bmm_block_hash: claim.event.bitcoin_bmm_block_hash,
        bitcoin_confirmations: claim.event.bitcoin_confirmations,
    };
    StrictJournal::new(
        StatementKind::ElementsBurn,
        manifest.elements_guest_program_id,
        output.encode(),
    )
    .map_err(GuestError::Journal)
}

/// Build the exact old-to-next Elements state statement consumed by
/// `USDDVaultV1.advanceElementsState`. Per-burn redemption records remain
/// auxiliary; this cumulative transition is the vault-authorizing proof.
pub fn build_elements_state_journal<V: ElementsValidityProofVerifier>(
    verifier: &V,
    manifest: &ProtocolManifest,
    claim: &ElementsStateTransitionClaim,
    proof: &V::Proof,
) -> Result<StrictJournal, GuestError> {
    manifest
        .validate()
        .map_err(|_| GuestError::InvalidManifest)?;
    let manifest_id = manifest
        .manifest_id()
        .map_err(|_| GuestError::InvalidManifest)?;
    if claim.manifest_id != manifest_id {
        return Err(GuestError::ManifestMismatch);
    }
    if claim.prior_state.is_zero() != (claim.prior_bridge_state_hash == Hash32::ZERO) {
        return Err(GuestError::InvalidElementsStateTransition);
    }
    claim
        .prior_state
        .validate_successor(&claim.next_state)
        .map_err(|_| GuestError::InvalidElementsStateTransition)?;
    if claim.prior_bridge_state_hash == Hash32::ZERO
        && claim.next_state.bitcoin_chainwork < manifest.minimum_activation_chainwork
    {
        return Err(GuestError::ActivationChainworkNotReached);
    }
    let append_count = u64::try_from(claim.appended_burns.len())
        .map_err(|_| GuestError::InvalidElementsStateTransition)?;
    let expected_burn_count = claim
        .prior_state
        .burn_count
        .checked_add(append_count)
        .ok_or(GuestError::InvalidElementsStateTransition)?;
    if claim.next_state.burn_count != expected_burn_count {
        return Err(GuestError::InvalidElementsStateTransition);
    }

    let mut root = if claim.prior_state.is_zero() {
        burn_accumulator_empty(64).map_err(|_| GuestError::InvalidElementsStateTransition)?
    } else {
        claim.prior_state.cumulative_burn_root
    };
    let empty_leaf =
        burn_accumulator_empty(0).map_err(|_| GuestError::InvalidElementsStateTransition)?;
    for (offset, append) in claim.appended_burns.iter().enumerate() {
        append
            .burn
            .validate()
            .map_err(|_| GuestError::InvalidBurn)?;
        if append.burn.vault_id != manifest.vault_id
            || append.burn.usdd_asset != manifest.usdd_asset
        {
            return Err(GuestError::BurnTargetsWrongAssetOrVault);
        }
        let index = claim
            .prior_state
            .burn_count
            .checked_add(offset as u64)
            .ok_or(GuestError::InvalidElementsStateTransition)?;
        if !append.empty_branch.verify(root, empty_leaf, index) {
            return Err(GuestError::BurnAccumulatorMismatch);
        }
        let leaf = append
            .burn
            .solidity_claim(manifest.elements_genesis)
            .burn_leaf(index)
            .map_err(|_| GuestError::InvalidBurn)?;
        root = append.empty_branch.compute_root(leaf, index);
    }
    if root != claim.next_state.cumulative_burn_root {
        return Err(GuestError::BurnAccumulatorMismatch);
    }

    verifier
        .verify_elements_state_transition(manifest, claim, proof)
        .map_err(GuestError::VerifierRejected)?;

    let current_contents_hash = claim.prior_state.contents_hash();
    let next_contents_hash = claim.next_state.contents_hash();
    let mut next_hash_preimage = alloc::vec::Vec::with_capacity(96);
    ELEMENTS_STATE_DOMAIN.encode_to(&mut next_hash_preimage);
    claim
        .prior_bridge_state_hash
        .encode_to(&mut next_hash_preimage);
    next_contents_hash.encode_to(&mut next_hash_preimage);
    let next_bridge_state_hash = hash_bytes(&next_hash_preimage);

    let mut statement_preimage = alloc::vec::Vec::with_capacity(340);
    ELEMENTS_STATEMENT_DOMAIN.encode_to(&mut statement_preimage);
    let mut chain_id = [0u8; 32];
    chain_id[24..].copy_from_slice(&manifest.ethereum_chain_id.to_be_bytes());
    chain_id.encode_to(&mut statement_preimage);
    manifest.vault.encode_to(&mut statement_preimage);
    manifest.vault_id.encode_to(&mut statement_preimage);
    manifest
        .elements_guest_program_id
        .encode_to(&mut statement_preimage);
    manifest
        .verifier_config_hash
        .encode_to(&mut statement_preimage);
    manifest.elements_genesis.encode_to(&mut statement_preimage);
    manifest.usdd_asset.encode_to(&mut statement_preimage);
    claim
        .prior_bridge_state_hash
        .encode_to(&mut statement_preimage);
    current_contents_hash.encode_to(&mut statement_preimage);
    next_bridge_state_hash.encode_to(&mut statement_preimage);
    next_contents_hash.encode_to(&mut statement_preimage);
    let verifier_statement = hash_bytes(&statement_preimage);

    let output = ElementsStatePublicOutput {
        manifest_id,
        claim_id: claim.claim_id(),
        prior_bridge_state_hash: claim.prior_bridge_state_hash,
        next_bridge_state_hash,
        verifier_statement,
        prior_state: claim.prior_state.clone(),
        next_state: claim.next_state.clone(),
    };
    StrictJournal::new(
        StatementKind::ElementsBurn,
        manifest.elements_guest_program_id,
        output.encode(),
    )
    .map_err(GuestError::Journal)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestError {
    InvalidManifest,
    ManifestMismatch,
    InvalidControllerState,
    ConfigurationMismatch,
    DepositTargetsWrongVault,
    DepositNonceNotNext,
    InvalidDepositBatch,
    InvalidControllerTransition,
    InvalidBurn,
    BurnTargetsWrongAssetOrVault,
    ElementsEventMismatch,
    InsufficientBitcoinConfirmations,
    InvalidElementsStateTransition,
    ActivationChainworkNotReached,
    BurnAccumulatorMismatch,
    VerifierRejected(VerificationError),
    Journal(JournalError),
}

impl fmt::Display for GuestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest => f.write_str("invalid protocol manifest"),
            Self::ManifestMismatch => f.write_str("claim manifest does not match"),
            Self::InvalidControllerState => f.write_str("invalid prior controller state"),
            Self::ConfigurationMismatch => f.write_str("controller configuration mismatch"),
            Self::DepositTargetsWrongVault => {
                f.write_str("deposit targets the wrong Ethereum chain, vault, or USDT")
            }
            Self::DepositNonceNotNext => f.write_str("deposit nonce is not next"),
            Self::InvalidDepositBatch => f.write_str("invalid 1..64 deposit batch"),
            Self::InvalidControllerTransition => f.write_str("invalid controller transition"),
            Self::InvalidBurn => f.write_str("invalid burn record"),
            Self::BurnTargetsWrongAssetOrVault => {
                f.write_str("burn targets the wrong USDD asset or vault")
            }
            Self::ElementsEventMismatch => f.write_str("Elements event does not bind the burn"),
            Self::InsufficientBitcoinConfirmations => {
                f.write_str("fewer than the manifest's Bitcoin confirmations")
            }
            Self::InvalidElementsStateTransition => {
                f.write_str("invalid old-to-next Elements bridge state")
            }
            Self::ActivationChainworkNotReached => {
                f.write_str("minimum activation chainwork not reached")
            }
            Self::BurnAccumulatorMismatch => {
                f.write_str("burn append proof or cumulative root mismatch")
            }
            Self::VerifierRejected(error) => write!(f, "proof verifier rejected claim: {error:?}"),
            Self::Journal(error) => error.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GuestError {}
