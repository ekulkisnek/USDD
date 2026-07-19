#![cfg(feature = "helios-finality")]

use alloy_primitives::B256;
use helios_consensus_core::{
    consensus_spec::MainnetConsensusSpec,
    types::{FinalityUpdate, Forks, LightClientStore, Update},
};
use serde::Deserialize;
use tree_hash::TreeHash;
use usdd_core::{
    ACTIVE_LIABILITY_CAP_USDT_MICRO, EthAddress, Hash32, MAX_ETHEREUM_FINALITY_SLOT_GAP,
    MAX_FINALIZED_TO_BMM_MTP_AGE_SECONDS, MINIMUM_BITCOIN_CONFIRMATIONS, MintControllerState,
    ProtocolManifest, SHA256_DIGEST_TAG, SP1_COMPRESSED_CIRCUIT_VERSION,
    SP1_COMPRESSED_CODEC_VERSION, SP1_GIT_COMMIT, SP1_VERSION_MAJOR, SP1_VERSION_MINOR,
    SP1_VERSION_PATCH, domain_separator_table_hash, hash_bytes,
};
use usdd_ethereum_inbound::{
    EthereumFinalityTransition,
    helios::{
        SEPOLIA_CHAIN_ID, SEPOLIA_EXECUTION_GENESIS_HASH, SEPOLIA_GENESIS_VALIDATORS_ROOT,
        SepoliaFinalityError, SepoliaFinalityProof, SepoliaHeliosFinalityVerifier,
        light_client_state_digest,
    },
};

const FIXTURE: &[u8] = include_bytes!("fixtures/sepolia-light-client-10723712-10724224.cbor");

/// Exact upstream SP1-Helios input envelope used only to import the real
/// witness. Network parameters below are checked for provenance, then omitted
/// from `SepoliaFinalityProof`: production verification uses compiled values.
#[derive(Deserialize)]
struct UpstreamProofInputs {
    updates: Vec<Update<MainnetConsensusSpec>>,
    finality_update: FinalityUpdate<MainnetConsensusSpec>,
    expected_current_slot: u64,
    store: LightClientStore<MainnetConsensusSpec>,
    genesis_root: B256,
    forks: Forks,
    contract_storage: Vec<serde::de::IgnoredAny>,
}

fn hash(byte: u8) -> Hash32 {
    Hash32([byte; 32])
}

fn manifest_for_bootstrap(
    slot: u64,
    beacon_root: Hash32,
    execution_state_root: Hash32,
    light_client_digest: Hash32,
) -> ProtocolManifest {
    let mut manifest = ProtocolManifest {
        ethereum_chain_id: SEPOLIA_CHAIN_ID,
        ethereum_genesis: SEPOLIA_EXECUTION_GENESIS_HASH,
        bitcoin_genesis: hash(2),
        elements_genesis: hash(3),
        drivechain_slot: 24,
        usdt: EthAddress([4; 20]),
        usdd_asset: hash(5),
        usdd_reissuance_token: hash(6),
        usdd_public_abf: hash(7),
        vault: EthAddress([8; 20]),
        vault_id: hash(9),
        vault_code_hash: hash(10),
        proof_verifier: EthAddress([11; 20]),
        proof_verifier_runtime_code_hash: hash(12),
        verifier_config_hash: hash(13),
        ethereum_guest_program_id: hash(14),
        elements_guest_program_id: hash(15),
        sp1_version_major: SP1_VERSION_MAJOR,
        sp1_version_minor: SP1_VERSION_MINOR,
        sp1_version_patch: SP1_VERSION_PATCH,
        sp1_git_commit: SP1_GIT_COMMIT,
        compressed_proof_circuit_version: SP1_COMPRESSED_CIRCUIT_VERSION,
        compressed_proof_codec_version: SP1_COMPRESSED_CODEC_VERSION,
        recursion_verifier_constants_hash: hash(16),
        public_digest_tag: SHA256_DIGEST_TAG,
        bootstrap_finalized_beacon_slot: slot,
        bootstrap_finalized_beacon_root: beacon_root,
        bootstrap_execution_state_root: execution_state_root,
        bootstrap_eth_light_client_digest: light_client_digest,
        controller_cmr: hash(20),
        controller_configuration_hash: hash(21),
        domain_separator_table_hash: domain_separator_table_hash(),
        issuance_txid_display: hash(22),
        issuance_vout: 0,
        asset_entropy: hash(23),
        initial_controller_state_hash: hash(24),
        active_liability_cap_usdt_micro: ACTIVE_LIABILITY_CAP_USDT_MICRO,
        minimum_activation_chainwork: hash(25),
        max_ethereum_finality_slot_gap: MAX_ETHEREUM_FINALITY_SLOT_GAP,
        max_finalized_to_bmm_mtp_age_seconds: MAX_FINALIZED_TO_BMM_MTP_AGE_SECONDS,
        minimum_bitcoin_confirmations: MINIMUM_BITCOIN_CONFIRMATIONS,
        first_deposit_nonce: 0,
        usdt_display_decimals: 6,
        usdd_display_decimals: 8,
        usdd_units_per_usdt_micro: 100,
    };
    manifest.verifier_config_hash = manifest.compute_outbound_verifier_config_hash();
    manifest.controller_configuration_hash = manifest.compute_controller_configuration_hash();
    manifest.vault_id = manifest.compute_vault_id();
    manifest.initial_controller_state_hash = manifest.compute_initial_controller_state_hash();
    manifest
}

fn real_fixture() -> (ProtocolManifest, MintControllerState, SepoliaFinalityProof) {
    assert_eq!(
        hash_bytes(FIXTURE).to_string(),
        "2661ef34f4b5277fe7e3457586c64f802f789a7fd9d6d5a394e08324f4e944f0"
    );
    let upstream: UpstreamProofInputs = serde_cbor::from_slice(FIXTURE).unwrap();
    assert_eq!(upstream.updates.len(), 1);
    assert!(upstream.contract_storage.is_empty());
    assert_eq!(
        upstream.genesis_root,
        B256::new(SEPOLIA_GENESIS_VALIDATORS_ROOT.0)
    );
    // Provenance checks only. Neither value is carried into the accepted proof.
    assert_eq!(upstream.forks.fulu.epoch, 272_640);
    assert!(upstream.expected_current_slot >= 10_724_224);

    let prior_header = upstream.store.finalized_header;
    let prior_current = upstream.store.current_sync_committee;
    let prior_next = upstream.store.next_sync_committee;
    let prior_beacon = prior_header.beacon();
    let prior_root = Hash32(prior_beacon.tree_hash_root().0);
    let prior_execution = prior_header.execution().unwrap();
    let prior_digest = light_client_state_digest(
        prior_beacon.slot,
        prior_root,
        &prior_current,
        prior_next.as_ref(),
    );
    let manifest = manifest_for_bootstrap(
        prior_beacon.slot,
        prior_root,
        Hash32(prior_execution.state_root().0),
        prior_digest,
    );
    let prior_state = MintControllerState {
        version: 1,
        sequence: 0,
        next_mint_nonce: 0,
        ethereum_light_client_digest: prior_digest,
        finalized_beacon_slot: prior_beacon.slot,
        finalized_beacon_root: prior_root,
        finalized_execution_state_root: Hash32(prior_execution.state_root().0),
        total_minted_usdd_base: 0,
        configuration_hash: manifest.controller_configuration_hash,
    };
    let proof = SepoliaFinalityProof {
        prior_finalized_header: prior_header,
        prior_current_sync_committee: prior_current,
        prior_next_sync_committee: prior_next,
        updates: upstream.updates,
        finality_update: upstream.finality_update,
    };
    (manifest, prior_state, proof)
}

#[test]
fn verifies_real_sepolia_ssz_branches_bls_and_execution_payload() {
    let (manifest, prior, proof) = real_fixture();
    let canonical_witness = proof.encode_canonical().unwrap();
    assert_eq!(
        SepoliaFinalityProof::decode_canonical(&canonical_witness)
            .unwrap()
            .updates
            .len(),
        1
    );
    let mut trailing = canonical_witness;
    trailing.push(0);
    assert!(SepoliaFinalityProof::decode_canonical(&trailing).is_err());

    let verifier = SepoliaHeliosFinalityVerifier;
    let derived = verifier
        .derive_transition(&manifest, &prior, &proof)
        .unwrap();
    assert_eq!(prior.finalized_beacon_slot, 10_723_712);
    assert_eq!(derived.finalized_beacon_slot, 10_724_224);
    assert!(derived.execution_block_number > 0);
    assert!(derived.execution_block_timestamp > 0);
    assert_ne!(
        derived.ethereum_light_client_digest,
        prior.ethereum_light_client_digest
    );
    verifier
        .verify_transition(
            EthereumFinalityTransition {
                manifest: &manifest,
                prior_state: &prior,
                next: &derived,
            },
            &proof,
        )
        .unwrap();
}

#[test]
fn caller_cannot_substitute_a_committee_or_public_output() {
    let (manifest, prior, mut proof) = real_fixture();
    proof.prior_next_sync_committee = Some(proof.prior_current_sync_committee.clone());
    assert_eq!(
        SepoliaHeliosFinalityVerifier.derive_transition(&manifest, &prior, &proof),
        Err(SepoliaFinalityError::PriorStateDigestMismatch)
    );

    let (_, _, proof) = real_fixture();
    let verifier = SepoliaHeliosFinalityVerifier;
    let mut derived = verifier
        .derive_transition(&manifest, &prior, &proof)
        .unwrap();
    derived.execution_block_number += 1;
    assert_eq!(
        verifier.verify_transition(
            EthereumFinalityTransition {
                manifest: &manifest,
                prior_state: &prior,
                next: &derived,
            },
            &proof,
        ),
        Err(SepoliaFinalityError::OutputMismatch)
    );
}

#[test]
fn wrong_execution_genesis_is_rejected_before_consensus_verification() {
    let (mut manifest, mut prior, proof) = real_fixture();
    manifest.ethereum_genesis = hash(99);
    manifest.verifier_config_hash = manifest.compute_outbound_verifier_config_hash();
    manifest.controller_configuration_hash = manifest.compute_controller_configuration_hash();
    manifest.vault_id = manifest.compute_vault_id();
    manifest.initial_controller_state_hash = manifest.compute_initial_controller_state_hash();
    prior.configuration_hash = manifest.controller_configuration_hash;
    assert_eq!(
        SepoliaHeliosFinalityVerifier.derive_transition(&manifest, &prior, &proof),
        Err(SepoliaFinalityError::WrongNetwork)
    );
}
