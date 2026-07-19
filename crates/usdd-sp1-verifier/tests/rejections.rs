use slop_algebra::AbstractField;
use sp1_hypercube::{
    create_dummy_recursion_proof, septic_digest::SepticDigest, MachineVerifyingKey,
    SP1VerifyingKey, UntrustedConfig,
};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_verifier::{Groth16Bn254Proof, PlonkBn254Proof, SP1Proof};
use usdd_core::{CanonicalEncode, Hash32, MintControllerState};
use usdd_proof_core::{HeartbeatPublicOutput, StatementKind, StrictJournal};
use usdd_sp1_verifier::{
    program_id_from_raw_vkey_hash, raw_vkey_hash_from_program_id,
    require_sha256_public_values_digest, verify_raw_compressed_sha256, RejectedProofMode,
    VerificationError, KOALA_BEAR_MODULUS, MAX_RAW_COMPRESSED_PROOF_SIZE,
};

fn raw_vkey_hash() -> Vec<u8> {
    (1u32..=8).flat_map(u32::to_le_bytes).collect()
}

fn dummy_compressed_proof() -> Vec<u8> {
    let vk = SP1VerifyingKey {
        vk: MachineVerifyingKey::<SP1GlobalContext> {
            pc_start: [SP1Field::zero(); 3],
            initial_global_cumulative_sum: SepticDigest::zero(),
            preprocessed_commit: [SP1Field::zero(); 8],
            untrusted_config: UntrustedConfig::zero(),
        },
    };
    let proof = SP1Proof::Compressed(Box::new(create_dummy_recursion_proof(&vk)));
    bincode::serialize(&proof).unwrap()
}

fn heartbeat_journal(program_id: Hash32) -> Vec<u8> {
    let prior_state = MintControllerState {
        version: 1,
        sequence: 0,
        next_mint_nonce: 7,
        ethereum_light_client_digest: Hash32([0x11; 32]),
        finalized_beacon_slot: 100,
        finalized_beacon_root: Hash32([0x22; 32]),
        finalized_execution_state_root: Hash32([0x33; 32]),
        total_minted_usdd_base: 123_456_700,
        configuration_hash: Hash32([0x44; 32]),
    };
    let next_state = MintControllerState {
        version: 1,
        sequence: 1,
        next_mint_nonce: 7,
        ethereum_light_client_digest: Hash32([0x55; 32]),
        finalized_beacon_slot: 101,
        finalized_beacon_root: Hash32([0x66; 32]),
        finalized_execution_state_root: Hash32([0x77; 32]),
        total_minted_usdd_base: 123_456_700,
        configuration_hash: Hash32([0x44; 32]),
    };
    let payload = HeartbeatPublicOutput {
        manifest_id: Hash32([0x88; 32]),
        claim_id: Hash32([0x99; 32]),
        prior_state,
        next_state,
        finalized_execution_block_timestamp: 1_700_000_000,
    }
    .encode();
    StrictJournal::new(StatementKind::EthereumState, program_id, payload)
        .unwrap()
        .encode()
}

fn context() -> (Vec<u8>, Hash32, Vec<u8>) {
    let vkey = raw_vkey_hash();
    let program_id = program_id_from_raw_vkey_hash(&vkey).unwrap();
    let journal = heartbeat_journal(program_id);
    (vkey, program_id, journal)
}

#[test]
fn canonical_vkey_hash_maps_to_sp1_hash_bytes_program_id() {
    let fields: [SP1Field; 8] =
        core::array::from_fn(|index| SP1Field::from_canonical_u32(index as u32 + 1));
    assert_eq!(bincode::serialize(&fields).unwrap(), raw_vkey_hash());

    let expected: Vec<u8> = (1u32..=8).flat_map(u32::to_be_bytes).collect();
    assert_eq!(
        program_id_from_raw_vkey_hash(&raw_vkey_hash()).unwrap(),
        Hash32(expected.try_into().unwrap())
    );
}

#[test]
fn program_id_and_raw_vkey_hash_round_trip_without_hidden_identity_bytes() {
    let raw = raw_vkey_hash();
    let program_id = program_id_from_raw_vkey_hash(&raw).unwrap();
    assert_eq!(
        raw_vkey_hash_from_program_id(program_id).unwrap(),
        raw.as_slice()
    );
}

#[test]
fn rejects_noncanonical_program_id_words() {
    let mut program_id = [0u8; 32];
    program_id[..4].copy_from_slice(&KOALA_BEAR_MODULUS.to_be_bytes());
    assert!(matches!(
        raw_vkey_hash_from_program_id(Hash32(program_id)),
        Err(VerificationError::NonCanonicalProgramIdWord {
            index: 0,
            value: KOALA_BEAR_MODULUS
        })
    ));
}

#[test]
fn rejects_vkey_hash_with_trailing_bytes() {
    let mut raw = raw_vkey_hash();
    raw.push(0);
    assert!(matches!(
        program_id_from_raw_vkey_hash(&raw),
        Err(VerificationError::WrongVkeyHashLength { actual: 33 })
    ));
}

#[test]
fn rejects_noncanonical_koalabear_vkey_words() {
    let mut raw = raw_vkey_hash();
    raw[..4].copy_from_slice(&KOALA_BEAR_MODULUS.to_le_bytes());
    assert!(matches!(
        program_id_from_raw_vkey_hash(&raw),
        Err(VerificationError::NonCanonicalVkeyWord {
            index: 0,
            value: KOALA_BEAR_MODULUS
        })
    ));
}

#[test]
fn rejects_blake3_even_though_upstream_accepts_it() {
    let public_values = b"USDD strict public values";
    let blake3_digest = sp1_verifier::blake3_hash(public_values);
    assert!(matches!(
        require_sha256_public_values_digest(blake3_digest, public_values),
        Err(VerificationError::PublicValuesDigestMismatch)
    ));
}

#[test]
fn accepts_sha256_in_the_sha_only_preflight() {
    let public_values = b"USDD strict public values";
    let digest = usdd_core::hash_bytes(public_values).0;
    require_sha256_public_values_digest(digest, public_values).unwrap();
}

#[test]
fn rejects_every_noncompressed_sp1_wrapper() {
    let (vkey, program_id, journal) = context();
    let cases = [
        (SP1Proof::Core(Vec::new()), RejectedProofMode::Core),
        (
            SP1Proof::Plonk(PlonkBn254Proof::default()),
            RejectedProofMode::Plonk,
        ),
        (
            SP1Proof::Groth16(Groth16Bn254Proof::default()),
            RejectedProofMode::Groth16,
        ),
    ];

    for (proof, expected_mode) in cases {
        let raw = bincode::serialize(&proof).unwrap();
        assert!(matches!(
            verify_raw_compressed_sha256(
                &raw,
                &journal,
                &vkey,
                program_id,
                StatementKind::EthereumState,
            ),
            Err(VerificationError::UnsupportedProofMode(mode)) if mode == expected_mode
        ));
    }
}

#[test]
fn rejects_malformed_compressed_encoding_without_a_proof_fixture() {
    let (vkey, program_id, journal) = context();
    let truncated_compressed_enum = 1u32.to_le_bytes();
    assert!(matches!(
        verify_raw_compressed_sha256(
            &truncated_compressed_enum,
            &journal,
            &vkey,
            program_id,
            StatementKind::EthereumState,
        ),
        Err(VerificationError::MalformedProof)
    ));
}

#[test]
fn rejects_trailing_compressed_proof_bytes_without_a_valid_proof_fixture() {
    let (vkey, program_id, journal) = context();
    let mut raw = dummy_compressed_proof();
    raw.push(0);
    assert!(matches!(
        verify_raw_compressed_sha256(
            &raw,
            &journal,
            &vkey,
            program_id,
            StatementKind::EthereumState,
        ),
        Err(VerificationError::MalformedProof)
    ));
}

#[test]
fn rejects_trailing_public_values() {
    let (vkey, program_id, mut journal) = context();
    journal.push(0);
    let core = bincode::serialize(&SP1Proof::Core(Vec::new())).unwrap();
    assert!(matches!(
        verify_raw_compressed_sha256(
            &core,
            &journal,
            &vkey,
            program_id,
            StatementKind::EthereumState,
        ),
        Err(VerificationError::Journal(_))
    ));
}

#[test]
fn rejects_vkey_program_id_mismatch_before_proof_verification() {
    let (vkey, _, journal) = context();
    let core = bincode::serialize(&SP1Proof::Core(Vec::new())).unwrap();
    assert!(matches!(
        verify_raw_compressed_sha256(
            &core,
            &journal,
            &vkey,
            Hash32([0xaa; 32]),
            StatementKind::EthereumState,
        ),
        Err(VerificationError::VkeyProgramIdMismatch)
    ));
}

#[test]
fn rejects_oversized_proof_before_deserialization() {
    let (vkey, program_id, journal) = context();
    let oversized = vec![0u8; MAX_RAW_COMPRESSED_PROOF_SIZE + 1];
    assert!(matches!(
        verify_raw_compressed_sha256(
            &oversized,
            &journal,
            &vkey,
            program_id,
            StatementKind::EthereumState,
        ),
        Err(VerificationError::ProofTooLarge { .. })
    ));
}

#[test]
fn exact_combined_annex_boundary_reaches_proof_mode_validation() {
    let (vkey, program_id, journal) = context();
    let proof_len = usdd_proof_core::SP1_ANNEX_MAX_SIZE
        - usdd_proof_core::SP1_ANNEX_HEADER_SIZE
        - journal.len();
    let proof = vec![0u8; proof_len];
    assert!(matches!(
        verify_raw_compressed_sha256(
            &proof,
            &journal,
            &vkey,
            program_id,
            StatementKind::EthereumState,
        ),
        Err(VerificationError::UnsupportedProofMode(
            RejectedProofMode::Core
        ))
    ));
}

#[test]
fn rejects_one_byte_over_combined_annex_boundary() {
    let (vkey, program_id, journal) = context();
    let proof_len = usdd_proof_core::SP1_ANNEX_MAX_SIZE
        - usdd_proof_core::SP1_ANNEX_HEADER_SIZE
        - journal.len()
        + 1;
    let proof = vec![0u8; proof_len];
    assert!(matches!(
        verify_raw_compressed_sha256(
            &proof,
            &journal,
            &vkey,
            program_id,
            StatementKind::EthereumState,
        ),
        Err(VerificationError::AnnexTooLarge {
            actual,
            maximum: usdd_proof_core::SP1_ANNEX_MAX_SIZE,
        }) if actual == usdd_proof_core::SP1_ANNEX_MAX_SIZE + 1
    ));
}
