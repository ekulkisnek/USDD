use usdd_core::{
    validate_bmm_finality_freshness, CanonicalDecode, CanonicalEncode, EthereumFinalityWitness,
    Hash32, MintControllerState, ENCODING_SCHEMA,
};
use usdd_proof_core::{
    EthereumHeartbeatClaim, HeartbeatPublicOutput, JournalError, StatementKind, StrictJournal,
    TypedPublicValues,
};

fn hash(byte: u8) -> Hash32 {
    Hash32([byte; 32])
}

fn prior_state() -> MintControllerState {
    MintControllerState {
        version: 1,
        sequence: 4,
        next_mint_nonce: 7,
        ethereum_light_client_digest: hash(1),
        finalized_beacon_slot: 100,
        finalized_beacon_root: hash(2),
        finalized_execution_state_root: hash(3),
        total_minted_usdd_base: 1_000,
        configuration_hash: hash(4),
    }
}

fn finality() -> EthereumFinalityWitness {
    EthereumFinalityWitness {
        ethereum_light_client_digest: hash(5),
        finalized_beacon_slot: 101,
        finalized_beacon_root: hash(6),
        finalized_execution_block: hash(7),
        finalized_execution_state_root: hash(8),
        execution_block_number: 20_000_000,
        execution_block_timestamp: 1_700_000_000,
    }
}

#[test]
fn ethereum_claim_has_no_prover_control_over_bmm_time() {
    let claim = EthereumHeartbeatClaim {
        manifest_id: hash(9),
        prior_state: prior_state(),
        finality: finality(),
    };
    let encoded = claim.encode();
    assert_eq!(&encoded[..2], &ENCODING_SCHEMA.to_be_bytes());
    assert_eq!(
        EthereumHeartbeatClaim::decode_exact(&encoded).unwrap(),
        claim
    );

    // Schema 1 encoded the unsafe caller-supplied parent MTP. It is rejected
    // before any record fields are interpreted under schema 2.
    let mut obsolete = encoded;
    obsolete[..2].copy_from_slice(&1u16.to_be_bytes());
    assert!(EthereumHeartbeatClaim::decode_exact(&obsolete).is_err());
}

#[test]
fn typed_journal_commits_the_proved_execution_timestamp() {
    let prior = prior_state();
    let next = prior.apply_heartbeat(&finality()).unwrap();
    let output = HeartbeatPublicOutput {
        manifest_id: hash(9),
        claim_id: hash(10),
        prior_state: prior,
        next_state: next,
        finalized_execution_block_timestamp: finality().execution_block_timestamp,
    };
    let journal =
        StrictJournal::new(StatementKind::EthereumState, hash(11), output.encode()).unwrap();
    match journal.typed_payload() {
        TypedPublicValues::Heartbeat(decoded) => assert_eq!(decoded, output),
        _ => panic!("wrong typed public values"),
    }

    let mut arbitrary = output.encode();
    arbitrary.push(0);
    assert_eq!(
        StrictJournal::new(StatementKind::EthereumState, hash(11), arbitrary),
        Err(JournalError::InvalidPayloadForStatement)
    );
}

#[test]
fn freshness_is_checked_against_the_elements_environment() {
    let timestamp = finality().execution_block_timestamp;
    validate_bmm_finality_freshness(timestamp, timestamp + 21_600).unwrap();
    assert!(validate_bmm_finality_freshness(timestamp, timestamp + 21_601).is_err());
    validate_bmm_finality_freshness(timestamp, timestamp - 21_600).unwrap();
    assert!(validate_bmm_finality_freshness(timestamp, timestamp - 21_601).is_err());
}
