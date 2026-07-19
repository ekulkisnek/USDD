use alloy_primitives::{B256, Bytes, U256, keccak256};
use alloy_rlp::Encodable;
use alloy_trie::{Nibbles, TrieAccount, nodes::LeafNode};
use usdd_core::{
    ACTIVE_LIABILITY_CAP_USDT_MICRO, CanonicalDecode, CanonicalEncode, EthAddress,
    EthereumFinalityWitness, Hash32, MAX_DEPOSIT_AMOUNT_USDT_MICRO, MAX_ETHEREUM_FINALITY_SLOT_GAP,
    MAX_FINALIZED_TO_BMM_MTP_AGE_SECONDS, MINIMUM_BITCOIN_CONFIRMATIONS, MintControllerState,
    ProtocolManifest, SHA256_DIGEST_TAG, SP1_COMPRESSED_CIRCUIT_VERSION,
    SP1_COMPRESSED_CODEC_VERSION, SP1_GIT_COMMIT, SP1_VERSION_MAJOR, SP1_VERSION_MINOR,
    SP1_VERSION_PATCH, VaultDeposit, domain_separator_table_hash,
};
use usdd_ethereum_inbound::{
    DepositStorageProof, EthereumFinalityTransition, EthereumFinalityTransitionVerifier,
    FinalityVerificationError, InboundVerificationError, MAX_MPT_NODE_BYTES, MAX_MPT_PROOF_NODES,
    MAX_MPT_WITNESS_BYTES, VaultAccountWitness, VaultStorageWitness,
    deposit_commitment_storage_key, verify_finalized_deposit_batch,
};

fn hash(byte: u8) -> Hash32 {
    Hash32([byte; 32])
}

fn valid_manifest() -> ProtocolManifest {
    let mut manifest = ProtocolManifest {
        ethereum_chain_id: 1,
        ethereum_genesis: hash(1),
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
        bootstrap_finalized_beacon_slot: 16,
        bootstrap_finalized_beacon_root: hash(17),
        bootstrap_execution_state_root: hash(18),
        bootstrap_eth_light_client_digest: hash(19),
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

fn prior_state(manifest: &ProtocolManifest) -> MintControllerState {
    MintControllerState {
        version: 1,
        sequence: 0,
        next_mint_nonce: 0,
        ethereum_light_client_digest: manifest.bootstrap_eth_light_client_digest,
        finalized_beacon_slot: manifest.bootstrap_finalized_beacon_slot,
        finalized_beacon_root: manifest.bootstrap_finalized_beacon_root,
        finalized_execution_state_root: manifest.bootstrap_execution_state_root,
        total_minted_usdd_base: 0,
        configuration_hash: manifest.controller_configuration_hash,
    }
}

fn encode_leaf(path: B256, value: Vec<u8>) -> Vec<u8> {
    let leaf = LeafNode::new(
        Nibbles::unpack(Bytes::copy_from_slice(path.as_slice())),
        value,
    );
    let mut encoded = Vec::new();
    leaf.encode(&mut encoded);
    encoded
}

struct TestFinality;

impl EthereumFinalityTransitionVerifier for TestFinality {
    type Proof = ();

    fn verify_finalized_transition(
        &self,
        _transition: EthereumFinalityTransition<'_>,
        _proof: &Self::Proof,
    ) -> Result<(), FinalityVerificationError> {
        Ok(())
    }
}

struct RejectFinality;

impl EthereumFinalityTransitionVerifier for RejectFinality {
    type Proof = ();

    fn verify_finalized_transition(
        &self,
        _transition: EthereumFinalityTransition<'_>,
        _proof: &Self::Proof,
    ) -> Result<(), FinalityVerificationError> {
        Err(FinalityVerificationError::Rejected)
    }
}

fn valid_fixture_with_amount(
    amount: u64,
) -> (
    ProtocolManifest,
    MintControllerState,
    EthereumFinalityWitness,
    Vec<VaultDeposit>,
    VaultStorageWitness,
) {
    let manifest = valid_manifest();
    let prior = prior_state(&manifest);
    let deposit = VaultDeposit {
        ethereum_chain_id: manifest.ethereum_chain_id,
        vault: manifest.vault,
        usdt: manifest.usdt,
        nonce: 0,
        depositor: EthAddress([42; 20]),
        usdt_amount_micro: amount,
        elements_script: vec![0x51, 0x20, 0x77],
        user_salt: hash(43),
    };
    let deposit_id = deposit.deposit_id();
    let storage_key = deposit_commitment_storage_key(deposit.nonce);
    let storage_path = keccak256(storage_key.0);
    let storage_value = alloy_rlp::encode(U256::from_be_bytes(deposit_id.0));
    let storage_leaf = encode_leaf(storage_path, storage_value);
    let storage_root = Hash32(keccak256(&storage_leaf).0);

    let account = TrieAccount {
        nonce: 7,
        balance: U256::from(123u64),
        storage_root: B256::new(storage_root.0),
        code_hash: B256::new(manifest.vault_code_hash.0),
    };
    let account_path = keccak256(manifest.vault.0);
    let account_leaf = encode_leaf(account_path, alloy_rlp::encode(account));
    let state_root = Hash32(keccak256(&account_leaf).0);
    let finality = EthereumFinalityWitness {
        ethereum_light_client_digest: hash(30),
        finalized_beacon_slot: 32,
        finalized_beacon_root: hash(31),
        finalized_execution_block: hash(32),
        finalized_execution_state_root: state_root,
        execution_block_number: 1_234_567,
        execution_block_timestamp: 1_800_000_000,
    };
    let witness = VaultStorageWitness {
        account: VaultAccountWitness {
            nonce: account.nonce,
            balance_be: account.balance.to_be_bytes(),
            storage_root,
            code_hash: manifest.vault_code_hash,
            proof_nodes: vec![account_leaf],
        },
        deposits: vec![DepositStorageProof {
            proof_nodes: vec![storage_leaf],
        }],
    };
    (manifest, prior, finality, vec![deposit], witness)
}

fn valid_fixture() -> (
    ProtocolManifest,
    MintControllerState,
    EthereumFinalityWitness,
    Vec<VaultDeposit>,
    VaultStorageWitness,
) {
    valid_fixture_with_amount(12_345_678)
}

#[test]
fn verifies_account_code_hash_and_deposit_storage_inclusion() {
    let (manifest, prior, finality, deposits, witness) = valid_fixture();
    let verified = verify_finalized_deposit_batch(
        &TestFinality,
        &manifest,
        &prior,
        &finality,
        &deposits,
        &(),
        &witness,
    )
    .unwrap();
    assert_eq!(verified.first_nonce, 0);
    assert_eq!(verified.next_nonce, 1);
    assert_eq!(verified.total_usdt_micro, 12_345_678);
    assert_eq!(verified.deposit_ids, vec![deposits[0].deposit_id()]);
    assert_eq!(
        verified.storage_keys,
        vec![deposit_commitment_storage_key(0)]
    );
}

#[test]
fn mapping_slot_key_matches_independent_fixed_vectors() {
    assert_eq!(
        deposit_commitment_storage_key(0).to_string(),
        "13649b2456f1b42fef0f0040b3aaeabcd21a76a0f3f5defd4f583839455116e8"
    );
    assert_eq!(
        deposit_commitment_storage_key(0x0102_0304_0506_0708).to_string(),
        "725ec9c80d087f54f0d24ac77ac21ef4ae955160e3483faca2269437201096b4"
    );
}

#[test]
fn wrong_code_hash_and_tampered_storage_are_rejected() {
    let (manifest, prior, finality, deposits, mut witness) = valid_fixture();
    witness.account.code_hash = hash(99);
    assert_eq!(
        verify_finalized_deposit_batch(
            &TestFinality,
            &manifest,
            &prior,
            &finality,
            &deposits,
            &(),
            &witness,
        ),
        Err(InboundVerificationError::VaultCodeHashMismatch)
    );

    let (_, _, _, _, mut witness) = valid_fixture();
    witness.deposits[0].proof_nodes[0][0] ^= 1;
    assert_eq!(
        verify_finalized_deposit_batch(
            &TestFinality,
            &manifest,
            &prior,
            &finality,
            &deposits,
            &(),
            &witness,
        ),
        Err(InboundVerificationError::StorageProofRejected(0))
    );
}

#[test]
fn witness_codec_is_exact_and_bounded() {
    let (_, _, _, _, witness) = valid_fixture();
    let encoded = witness.encode();
    assert_eq!(
        VaultStorageWitness::decode_exact(&encoded).unwrap(),
        witness
    );

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(VaultStorageWitness::decode_exact(&trailing).is_err());

    let mut oversized = witness;
    oversized.account.proof_nodes = vec![vec![0; MAX_MPT_NODE_BYTES + 1]];
    assert_eq!(
        oversized.validate_limits(),
        Err(InboundVerificationError::ProofLimitsExceeded)
    );
}

#[test]
fn wrong_nonce_and_unproved_extra_deposit_fail_closed() {
    let (manifest, prior, finality, mut deposits, witness) = valid_fixture();
    deposits[0].nonce = 1;
    assert_eq!(
        verify_finalized_deposit_batch(
            &TestFinality,
            &manifest,
            &prior,
            &finality,
            &deposits,
            &(),
            &witness,
        ),
        Err(InboundVerificationError::NonConsecutiveDepositNonce)
    );

    let (_, _, _, mut deposits, witness) = valid_fixture();
    let mut second = deposits[0].clone();
    second.nonce = 1;
    deposits.push(second);
    assert_eq!(
        verify_finalized_deposit_batch(
            &TestFinality,
            &manifest,
            &prior,
            &finality,
            &deposits,
            &(),
            &witness,
        ),
        Err(InboundVerificationError::StorageProofCountMismatch)
    );
}

#[test]
fn deposit_amount_limit_is_enforced_by_the_inbound_path() {
    let (manifest, prior, finality, deposits, witness) =
        valid_fixture_with_amount(MAX_DEPOSIT_AMOUNT_USDT_MICRO);
    assert!(
        verify_finalized_deposit_batch(
            &TestFinality,
            &manifest,
            &prior,
            &finality,
            &deposits,
            &(),
            &witness,
        )
        .is_ok()
    );

    let (manifest, prior, finality, mut deposits, witness) = valid_fixture();
    deposits[0].usdt_amount_micro = MAX_DEPOSIT_AMOUNT_USDT_MICRO + 1;
    assert_eq!(
        verify_finalized_deposit_batch(
            &TestFinality,
            &manifest,
            &prior,
            &finality,
            &deposits,
            &(),
            &witness,
        ),
        Err(InboundVerificationError::InvalidDeposit)
    );
}

#[test]
fn same_slot_requires_the_exact_committed_state_and_gap_is_bounded() {
    let (mut manifest, _, mut finality, deposits, witness) = valid_fixture();
    manifest.bootstrap_execution_state_root = finality.finalized_execution_state_root;
    manifest.controller_configuration_hash = manifest.compute_controller_configuration_hash();
    manifest.vault_id = manifest.compute_vault_id();
    manifest.initial_controller_state_hash = manifest.compute_initial_controller_state_hash();
    let prior = prior_state(&manifest);
    finality.ethereum_light_client_digest = prior.ethereum_light_client_digest;
    finality.finalized_beacon_slot = prior.finalized_beacon_slot;
    finality.finalized_beacon_root = prior.finalized_beacon_root;
    finality.finalized_execution_state_root = prior.finalized_execution_state_root;

    assert!(
        verify_finalized_deposit_batch(
            &TestFinality,
            &manifest,
            &prior,
            &finality,
            &deposits,
            &(),
            &witness,
        )
        .is_ok()
    );

    let mut changed = finality.clone();
    changed.finalized_beacon_root = hash(99);
    assert_eq!(
        verify_finalized_deposit_batch(
            &TestFinality,
            &manifest,
            &prior,
            &changed,
            &deposits,
            &(),
            &witness,
        ),
        Err(InboundVerificationError::InvalidFinality)
    );

    let mut too_far = finality;
    too_far.finalized_beacon_slot = prior.finalized_beacon_slot + 4_097;
    too_far.ethereum_light_client_digest = hash(98);
    assert_eq!(
        verify_finalized_deposit_batch(
            &TestFinality,
            &manifest,
            &prior,
            &too_far,
            &deposits,
            &(),
            &witness,
        ),
        Err(InboundVerificationError::InvalidFinality)
    );
}

#[test]
fn finality_rejection_and_wrong_chain_vault_or_token_fail_closed() {
    let (manifest, prior, finality, deposits, witness) = valid_fixture();
    assert_eq!(
        verify_finalized_deposit_batch(
            &RejectFinality,
            &manifest,
            &prior,
            &finality,
            &deposits,
            &(),
            &witness,
        ),
        Err(InboundVerificationError::FinalityRejected)
    );

    for mutation in 0..3 {
        let mut wrong = deposits.clone();
        match mutation {
            0 => wrong[0].ethereum_chain_id += 1,
            1 => wrong[0].vault = EthAddress([77; 20]),
            2 => wrong[0].usdt = EthAddress([78; 20]),
            _ => unreachable!(),
        }
        assert_eq!(
            verify_finalized_deposit_batch(
                &TestFinality,
                &manifest,
                &prior,
                &finality,
                &wrong,
                &(),
                &witness,
            ),
            Err(InboundVerificationError::WrongDepositTarget)
        );
    }
}

#[test]
fn zero_and_sixty_five_deposit_batches_are_rejected() {
    let (manifest, prior, finality, deposits, witness) = valid_fixture();
    assert_eq!(
        verify_finalized_deposit_batch(
            &TestFinality,
            &manifest,
            &prior,
            &finality,
            &[],
            &(),
            &witness,
        ),
        Err(InboundVerificationError::EmptyDepositBatch)
    );

    let mut too_many = Vec::new();
    for nonce in 0..65 {
        let mut deposit = deposits[0].clone();
        deposit.nonce = nonce;
        too_many.push(deposit);
    }
    assert_eq!(
        verify_finalized_deposit_batch(
            &TestFinality,
            &manifest,
            &prior,
            &finality,
            &too_many,
            &(),
            &witness,
        ),
        Err(InboundVerificationError::TooManyDeposits)
    );
}

#[test]
fn account_proof_and_all_resource_boundaries_fail_closed() {
    let (manifest, prior, finality, deposits, mut witness) = valid_fixture();
    witness.account.proof_nodes[0][0] ^= 1;
    assert_eq!(
        verify_finalized_deposit_batch(
            &TestFinality,
            &manifest,
            &prior,
            &finality,
            &deposits,
            &(),
            &witness,
        ),
        Err(InboundVerificationError::AccountProofRejected)
    );

    let (_, _, _, _, mut witness) = valid_fixture();
    witness.account.proof_nodes.clear();
    assert_eq!(
        witness.validate_limits(),
        Err(InboundVerificationError::ProofLimitsExceeded)
    );

    witness.account.proof_nodes = vec![vec![1]; MAX_MPT_PROOF_NODES];
    assert!(witness.validate_limits().is_ok());
    witness.account.proof_nodes.push(vec![1]);
    assert_eq!(
        witness.validate_limits(),
        Err(InboundVerificationError::ProofLimitsExceeded)
    );

    let mut exact = VaultStorageWitness {
        account: VaultAccountWitness {
            nonce: 0,
            balance_be: [0; 32],
            storage_root: hash(1),
            code_hash: hash(2),
            proof_nodes: vec![vec![0; MAX_MPT_NODE_BYTES]; 64],
        },
        deposits: Vec::new(),
    };
    for _ in 0..15 {
        exact.deposits.push(DepositStorageProof {
            proof_nodes: vec![vec![0; MAX_MPT_NODE_BYTES]; 64],
        });
    }
    assert_eq!(64 * 16 * MAX_MPT_NODE_BYTES, MAX_MPT_WITNESS_BYTES);
    assert!(exact.validate_limits().is_ok());

    exact.account.proof_nodes.push(vec![1]);
    assert_eq!(
        exact.validate_limits(),
        Err(InboundVerificationError::ProofLimitsExceeded)
    );
}

#[test]
fn finality_composition_commitment_binds_every_state_record() {
    let (manifest, prior, finality, _, _) = valid_fixture();
    let transition = EthereumFinalityTransition {
        manifest: &manifest,
        prior_state: &prior,
        next: &finality,
    };
    let commitment = transition.commitment().unwrap();
    assert_ne!(commitment, Hash32::ZERO);

    let mut changed = finality;
    changed.execution_block_timestamp += 1;
    assert_ne!(
        commitment,
        EthereumFinalityTransition {
            manifest: &manifest,
            prior_state: &prior,
            next: &changed,
        }
        .commitment()
        .unwrap()
    );
}
