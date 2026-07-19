//! Pinned, fail-closed Sepolia beacon light-client transition verification.
//!
//! The witness contains the actual sync committees because BLS verification
//! needs their public keys. Their tree-hash roots, the prior finalized beacon
//! header, and the optional next committee are all bound by the controller's
//! light-client digest before any prover-supplied update is evaluated.

use alloc::vec::Vec;
use core::fmt;

use alloy_primitives::{B256, FixedBytes};
use helios_consensus_core::{
    apply_finality_update, apply_update,
    consensus_spec::{ConsensusSpec, MainnetConsensusSpec},
    get_bits,
    types::{
        FinalityUpdate, Fork, Forks, LightClientHeader, LightClientStore, SyncCommittee, Update,
    },
    verify_finality_update, verify_update,
};
use serde::{Deserialize, Serialize};
use tree_hash::TreeHash;
use usdd_core::{
    CanonicalEncode, ENCODING_SCHEMA, EthereumFinalityWitness, Hash32,
    MAX_ETHEREUM_FINALITY_SLOT_GAP, MintControllerState, ProtocolManifest, hash_bytes,
};

use crate::{
    EthereumFinalityTransition, EthereumFinalityTransitionVerifier, FinalityVerificationError,
};

pub const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
pub const SEPOLIA_EXECUTION_GENESIS_HASH: Hash32 = Hash32([
    0x25, 0xa5, 0xcc, 0x10, 0x6e, 0xea, 0x71, 0x38, 0xac, 0xab, 0x33, 0x23, 0x1d, 0x71, 0x60, 0xd6,
    0x9c, 0xb7, 0x77, 0xee, 0x0c, 0x2c, 0x55, 0x3f, 0xcd, 0xdf, 0x51, 0x38, 0x99, 0x3e, 0x6d, 0xd9,
]);
pub const SEPOLIA_GENESIS_VALIDATORS_ROOT: Hash32 = Hash32([
    0xd8, 0xea, 0x17, 0x1f, 0x3c, 0x94, 0xae, 0xa2, 0x1e, 0xbc, 0x42, 0xa1, 0xed, 0x61, 0x05, 0x2a,
    0xcf, 0x3f, 0x92, 0x09, 0xc0, 0x0e, 0x4e, 0xfb, 0xaa, 0xdd, 0xac, 0x09, 0xed, 0x9b, 0x80, 0x78,
]);

/// A 4096-slot transition can cross at most one 8192-slot committee period.
/// Two generic updates leave one explicit spare while bounding guest work.
pub const MAX_COMMITTEE_UPDATES: usize = 2;
pub const MAX_FINALITY_WITNESS_BYTES: usize = 512 * 1024;

const LIGHT_CLIENT_STATE_DOMAIN: &[u8] = b"USDD_SEPOLIA_LIGHT_CLIENT_STATE_V1";

/// Private finality witness consumed by the Ethereum state guest.
///
/// `prior_next_sync_committee` is not cleared. It is accepted only when its
/// tree-hash root is already present in the prior controller digest, closing
/// the under-constrained-next-committee class of bugs.
#[derive(Clone, Debug, Serialize)]
pub struct SepoliaFinalityProof {
    pub prior_finalized_header: LightClientHeader,
    pub prior_current_sync_committee: SyncCommittee<MainnetConsensusSpec>,
    pub prior_next_sync_committee: Option<SyncCommittee<MainnetConsensusSpec>>,
    pub updates: Vec<Update<MainnetConsensusSpec>>,
    pub finality_update: FinalityUpdate<MainnetConsensusSpec>,
}

impl SepoliaFinalityProof {
    /// Canonical private-witness codec used at the future SP1 guest boundary.
    /// Alternate CBOR spellings and trailing bytes are rejected on decode.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, SepoliaFinalityError> {
        if self.updates.len() > MAX_COMMITTEE_UPDATES {
            return Err(SepoliaFinalityError::TooManyCommitteeUpdates);
        }
        let bytes =
            serde_cbor::to_vec(self).map_err(|_| SepoliaFinalityError::WitnessCodecRejected)?;
        if bytes.len() > MAX_FINALITY_WITNESS_BYTES {
            return Err(SepoliaFinalityError::WitnessTooLarge);
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SepoliaFinalityError> {
        if bytes.is_empty() || bytes.len() > MAX_FINALITY_WITNESS_BYTES {
            return Err(SepoliaFinalityError::WitnessTooLarge);
        }
        let mut decoder = serde_cbor::Deserializer::from_slice(bytes);
        let value = Self::deserialize(&mut decoder)
            .map_err(|_| SepoliaFinalityError::WitnessCodecRejected)?;
        decoder
            .end()
            .map_err(|_| SepoliaFinalityError::WitnessCodecRejected)?;
        if value.encode_canonical()?.as_slice() != bytes {
            return Err(SepoliaFinalityError::NonCanonicalWitness);
        }
        Ok(value)
    }
}

impl<'de> Deserialize<'de> for SepoliaFinalityProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireProof {
            prior_finalized_header: LightClientHeader,
            prior_current_sync_committee: SyncCommittee<MainnetConsensusSpec>,
            prior_next_sync_committee: Option<SyncCommittee<MainnetConsensusSpec>>,
            updates: BoundedUpdates,
            finality_update: FinalityUpdate<MainnetConsensusSpec>,
        }

        let wire = WireProof::deserialize(deserializer)?;
        Ok(Self {
            prior_finalized_header: wire.prior_finalized_header,
            prior_current_sync_committee: wire.prior_current_sync_committee,
            prior_next_sync_committee: wire.prior_next_sync_committee,
            updates: wire.updates.0,
            finality_update: wire.finality_update,
        })
    }
}

struct BoundedUpdates(Vec<Update<MainnetConsensusSpec>>);

impl<'de> Deserialize<'de> for BoundedUpdates {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct UpdatesVisitor;

        impl<'de> serde::de::Visitor<'de> for UpdatesVisitor {
            type Value = BoundedUpdates;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "at most {MAX_COMMITTEE_UPDATES} committee updates"
                )
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                if sequence.size_hint().unwrap_or(0) > MAX_COMMITTEE_UPDATES {
                    return Err(serde::de::Error::custom("too many committee updates"));
                }
                let mut updates = Vec::with_capacity(MAX_COMMITTEE_UPDATES);
                while let Some(update) = sequence.next_element()? {
                    if updates.len() == MAX_COMMITTEE_UPDATES {
                        return Err(serde::de::Error::custom("too many committee updates"));
                    }
                    updates.push(update);
                }
                Ok(BoundedUpdates(updates))
            }
        }

        deserializer.deserialize_seq(UpdatesVisitor)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SepoliaFinalityError {
    InvalidManifest,
    InvalidPriorState,
    WrongNetwork,
    PriorHeaderMismatch,
    PriorExecutionPayloadRejected,
    PriorStateDigestMismatch,
    TooManyCommitteeUpdates,
    UpdateWithoutSupermajority(usize),
    UpdateRejected(usize),
    FinalityWithoutSupermajority,
    FinalityRejected,
    FinalizedStateDidNotAdvance,
    FinalizedHeaderNotCheckpoint,
    MissingExecutionPayload,
    OutputMismatch,
    WitnessTooLarge,
    WitnessCodecRejected,
    NonCanonicalWitness,
}

impl fmt::Display for SepoliaFinalityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest => formatter.write_str("invalid USDD manifest"),
            Self::InvalidPriorState => formatter.write_str("invalid prior controller state"),
            Self::WrongNetwork => formatter.write_str("finality proof is not for pinned Sepolia"),
            Self::PriorHeaderMismatch => {
                formatter.write_str("prior beacon header does not match controller state")
            }
            Self::PriorExecutionPayloadRejected => formatter
                .write_str("prior execution payload is not bound to the prior beacon header"),
            Self::PriorStateDigestMismatch => {
                formatter.write_str("prior sync committees do not match controller digest")
            }
            Self::TooManyCommitteeUpdates => formatter.write_str("too many sync-committee updates"),
            Self::UpdateWithoutSupermajority(index) => {
                write!(
                    formatter,
                    "sync-committee update {index} lacks a two-thirds quorum"
                )
            }
            Self::UpdateRejected(index) => {
                write!(
                    formatter,
                    "sync-committee update {index} failed consensus verification"
                )
            }
            Self::FinalityWithoutSupermajority => {
                formatter.write_str("finality update lacks a two-thirds quorum")
            }
            Self::FinalityRejected => {
                formatter.write_str("finality update failed consensus verification")
            }
            Self::FinalizedStateDidNotAdvance => {
                formatter.write_str("verified finality did not advance the finalized header")
            }
            Self::FinalizedHeaderNotCheckpoint => {
                formatter.write_str("finalized header is not an epoch checkpoint")
            }
            Self::MissingExecutionPayload => {
                formatter.write_str("finalized beacon header has no execution payload")
            }
            Self::OutputMismatch => {
                formatter.write_str("derived finalized state differs from the requested output")
            }
            Self::WitnessTooLarge => formatter.write_str("finality witness exceeds 512 KiB"),
            Self::WitnessCodecRejected => formatter.write_str("finality witness codec rejected"),
            Self::NonCanonicalWitness => {
                formatter.write_str("finality witness encoding is not canonical")
            }
        }
    }
}

impl std::error::Error for SepoliaFinalityError {}

#[derive(Clone, Copy, Debug, Default)]
pub struct SepoliaHeliosFinalityVerifier;

impl EthereumFinalityTransitionVerifier for SepoliaHeliosFinalityVerifier {
    type Proof = SepoliaFinalityProof;

    fn verify_finalized_transition(
        &self,
        transition: EthereumFinalityTransition<'_>,
        proof: &Self::Proof,
    ) -> Result<(), FinalityVerificationError> {
        self.verify_transition(transition, proof)
            .map_err(|_| FinalityVerificationError::Rejected)
    }
}

impl SepoliaHeliosFinalityVerifier {
    /// Verify a complete beacon light-client transition and match every
    /// execution field used by the USDD controller.
    pub fn verify_transition(
        &self,
        transition: EthereumFinalityTransition<'_>,
        proof: &SepoliaFinalityProof,
    ) -> Result<(), SepoliaFinalityError> {
        let derived = self.derive_transition(transition.manifest, transition.prior_state, proof)?;
        if &derived != transition.next {
            return Err(SepoliaFinalityError::OutputMismatch);
        }
        Ok(())
    }

    /// Derive, rather than accept, every public finality and execution field.
    /// This is useful to construct the public claim after local preflight; the
    /// guest still reruns this method before committing that claim.
    pub fn derive_transition(
        &self,
        manifest: &ProtocolManifest,
        prior_state: &MintControllerState,
        proof: &SepoliaFinalityProof,
    ) -> Result<EthereumFinalityWitness, SepoliaFinalityError> {
        manifest
            .validate()
            .map_err(|_| SepoliaFinalityError::InvalidManifest)?;
        prior_state
            .validate()
            .map_err(|_| SepoliaFinalityError::InvalidPriorState)?;
        if prior_state.configuration_hash != manifest.controller_configuration_hash {
            return Err(SepoliaFinalityError::InvalidPriorState);
        }
        if manifest.ethereum_chain_id != SEPOLIA_CHAIN_ID
            || manifest.ethereum_genesis != SEPOLIA_EXECUTION_GENESIS_HASH
        {
            return Err(SepoliaFinalityError::WrongNetwork);
        }

        let prior_beacon = proof.prior_finalized_header.beacon();
        let prior_beacon_root = Hash32(prior_beacon.tree_hash_root().0);
        if prior_beacon.slot != prior_state.finalized_beacon_slot
            || prior_beacon_root != prior_state.finalized_beacon_root
        {
            return Err(SepoliaFinalityError::PriorHeaderMismatch);
        }
        let prior_execution = proof
            .prior_finalized_header
            .execution()
            .map_err(|_| SepoliaFinalityError::PriorExecutionPayloadRejected)?;
        if Hash32(prior_execution.state_root().0) != prior_state.finalized_execution_state_root
            || !execution_payload_is_bound(&proof.prior_finalized_header)
        {
            return Err(SepoliaFinalityError::PriorExecutionPayloadRejected);
        }
        let prior_digest = light_client_state_digest(
            prior_beacon.slot,
            prior_beacon_root,
            &proof.prior_current_sync_committee,
            proof.prior_next_sync_committee.as_ref(),
        );
        if prior_digest != prior_state.ethereum_light_client_digest {
            return Err(SepoliaFinalityError::PriorStateDigestMismatch);
        }
        if proof.updates.len() > MAX_COMMITTEE_UPDATES {
            return Err(SepoliaFinalityError::TooManyCommitteeUpdates);
        }

        let mut store = LightClientStore {
            finalized_header: proof.prior_finalized_header.clone(),
            current_sync_committee: proof.prior_current_sync_committee.clone(),
            next_sync_committee: proof.prior_next_sync_committee.clone(),
            optimistic_header: proof.prior_finalized_header.clone(),
            previous_max_active_participants: 0,
            current_max_active_participants: 0,
            best_valid_update: None,
        };
        let forks = sepolia_forks();
        let genesis_root = B256::new(SEPOLIA_GENESIS_VALIDATORS_ROOT.0);
        // This is consensus-relative, not wall-clock-relative: no prover can
        // extend acceptance by choosing a future local time.
        let expected_current_slot = *proof.finality_update.signature_slot();

        for (index, update) in proof.updates.iter().enumerate() {
            require_supermajority(update.sync_aggregate(), index)?;
            verify_update(update, expected_current_slot, &store, genesis_root, &forks)
                .map_err(|_| SepoliaFinalityError::UpdateRejected(index))?;
            apply_update(&mut store, update);
        }

        let finality_participants = get_bits::<MainnetConsensusSpec>(
            &proof.finality_update.sync_aggregate().sync_committee_bits,
        );
        if finality_participants * 3 < MainnetConsensusSpec::sync_committee_size() * 2 {
            return Err(SepoliaFinalityError::FinalityWithoutSupermajority);
        }
        verify_finality_update(
            &proof.finality_update,
            expected_current_slot,
            &store,
            genesis_root,
            &forks,
        )
        .map_err(|_| SepoliaFinalityError::FinalityRejected)?;
        apply_finality_update(&mut store, &proof.finality_update);

        let finalized = store.finalized_header.beacon();
        if !finalized_slot_advances(prior_beacon.slot, finalized.slot) {
            return Err(SepoliaFinalityError::FinalizedStateDidNotAdvance);
        }
        if finalized.slot % MainnetConsensusSpec::slots_per_epoch() != 0 {
            return Err(SepoliaFinalityError::FinalizedHeaderNotCheckpoint);
        }
        let execution = store
            .finalized_header
            .execution()
            .map_err(|_| SepoliaFinalityError::MissingExecutionPayload)?;
        let finalized_root = Hash32(finalized.tree_hash_root().0);
        Ok(EthereumFinalityWitness {
            ethereum_light_client_digest: light_client_state_digest(
                finalized.slot,
                finalized_root,
                &store.current_sync_committee,
                store.next_sync_committee.as_ref(),
            ),
            finalized_beacon_slot: finalized.slot,
            finalized_beacon_root: finalized_root,
            finalized_execution_block: Hash32(execution.block_hash().0),
            finalized_execution_state_root: Hash32(execution.state_root().0),
            execution_block_number: *execution.block_number(),
            execution_block_timestamp: *execution.timestamp(),
        })
    }
}

fn finalized_slot_advances(prior: u64, next: u64) -> bool {
    matches!(
        next.checked_sub(prior),
        Some(gap) if gap != 0 && gap <= MAX_ETHEREUM_FINALITY_SLOT_GAP
    )
}

fn require_supermajority(
    aggregate: &helios_consensus_core::types::SyncAggregate<MainnetConsensusSpec>,
    index: usize,
) -> Result<(), SepoliaFinalityError> {
    let participants = get_bits::<MainnetConsensusSpec>(&aggregate.sync_committee_bits);
    if participants * 3 < MainnetConsensusSpec::sync_committee_size() * 2 {
        return Err(SepoliaFinalityError::UpdateWithoutSupermajority(index));
    }
    Ok(())
}

fn execution_payload_is_bound(header: &LightClientHeader) -> bool {
    let Ok(execution) = header.execution() else {
        return false;
    };
    let Ok(branch) = header.execution_branch() else {
        return false;
    };
    if branch.len() != 4 {
        return false;
    }
    // BeaconBlockBody.execution_payload has generalized index 25: depth 4,
    // zero-based leaf index 9. This is the Altair light-client specification
    // proof checked by Helios for every newly supplied header.
    let mut derived = Hash32(execution.tree_hash_root().0);
    for (depth, node) in branch.iter().enumerate() {
        let node = Hash32(node.0);
        let mut pair = Vec::with_capacity(64);
        if ((9usize >> depth) & 1) == 1 {
            node.encode_to(&mut pair);
            derived.encode_to(&mut pair);
        } else {
            derived.encode_to(&mut pair);
            node.encode_to(&mut pair);
        }
        derived = hash_bytes(&pair);
    }
    derived == Hash32(header.beacon().body_root.0)
}

/// Frozen controller commitment for the security-relevant Helios store.
///
/// Participant counters, optimistic headers, and `best_valid_update` are
/// intentionally excluded: this verifier never force-updates and requires a
/// fresh two-thirds quorum for every applied update. Reconstructed stores set
/// those non-authorizing fields to deterministic zero/empty values.
pub fn light_client_state_digest(
    finalized_slot: u64,
    finalized_beacon_root: Hash32,
    current_sync_committee: &SyncCommittee<MainnetConsensusSpec>,
    next_sync_committee: Option<&SyncCommittee<MainnetConsensusSpec>>,
) -> Hash32 {
    let mut preimage = Vec::with_capacity(256);
    preimage.extend_from_slice(LIGHT_CLIENT_STATE_DOMAIN);
    ENCODING_SCHEMA.encode_to(&mut preimage);
    encode_sepolia_config(&mut preimage);
    finalized_slot.encode_to(&mut preimage);
    finalized_beacon_root.encode_to(&mut preimage);
    Hash32(current_sync_committee.tree_hash_root().0).encode_to(&mut preimage);
    match next_sync_committee {
        Some(committee) => {
            1u8.encode_to(&mut preimage);
            Hash32(committee.tree_hash_root().0).encode_to(&mut preimage);
        }
        None => 0u8.encode_to(&mut preimage),
    }
    hash_bytes(&preimage)
}

fn encode_sepolia_config(out: &mut Vec<u8>) {
    SEPOLIA_CHAIN_ID.encode_to(out);
    SEPOLIA_EXECUTION_GENESIS_HASH.encode_to(out);
    SEPOLIA_GENESIS_VALIDATORS_ROOT.encode_to(out);
    for (epoch, version) in SEPOLIA_FORKS {
        epoch.encode_to(out);
        out.extend_from_slice(&version);
    }
}

const SEPOLIA_FORKS: [(u64, [u8; 4]); 7] = [
    (0, [0x90, 0x00, 0x00, 0x69]),
    (50, [0x90, 0x00, 0x00, 0x70]),
    (100, [0x90, 0x00, 0x00, 0x71]),
    (56_832, [0x90, 0x00, 0x00, 0x72]),
    (132_608, [0x90, 0x00, 0x00, 0x73]),
    (222_464, [0x90, 0x00, 0x00, 0x74]),
    (272_640, [0x90, 0x00, 0x00, 0x75]),
];

fn sepolia_forks() -> Forks {
    let fork = |(epoch, version): (u64, [u8; 4])| Fork {
        epoch,
        fork_version: FixedBytes::new(version),
    };
    Forks {
        genesis: fork(SEPOLIA_FORKS[0]),
        altair: fork(SEPOLIA_FORKS[1]),
        bellatrix: fork(SEPOLIA_FORKS[2]),
        capella: fork(SEPOLIA_FORKS[3]),
        deneb: fork(SEPOLIA_FORKS[4]),
        electra: fork(SEPOLIA_FORKS[5]),
        fulu: fork(SEPOLIA_FORKS[6]),
    }
}

#[cfg(test)]
mod tests {
    use super::finalized_slot_advances;
    use usdd_core::MAX_ETHEREUM_FINALITY_SLOT_GAP;

    #[test]
    fn finalized_slot_gap_is_enforced_at_the_helios_boundary() {
        assert!(!finalized_slot_advances(100, 99));
        assert!(!finalized_slot_advances(100, 100));
        assert!(finalized_slot_advances(
            100,
            100 + MAX_ETHEREUM_FINALITY_SLOT_GAP
        ));
        assert!(!finalized_slot_advances(
            100,
            101 + MAX_ETHEREUM_FINALITY_SLOT_GAP
        ));
    }
}
