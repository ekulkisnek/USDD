use core::str::FromStr;

use usdd_core::{
    encode_hex, Burn, CanonicalEncode, EthAddress, Hash32, MintControllerState, OutPoint,
    SolidityBurnClaim, VaultDeposit,
};
use usdd_proof_core::{HeartbeatPublicOutput, Sp1ProofAnnex, StatementKind, StrictJournal};

fn heartbeat_public_values() -> Vec<u8> {
    HeartbeatPublicOutput {
        manifest_id: Hash32([0x88; 32]),
        claim_id: Hash32([0x99; 32]),
        prior_state: MintControllerState {
            version: 1,
            sequence: 0,
            next_mint_nonce: 7,
            ethereum_light_client_digest: Hash32([0x11; 32]),
            finalized_beacon_slot: 100,
            finalized_beacon_root: Hash32([0x22; 32]),
            finalized_execution_state_root: Hash32([0x33; 32]),
            total_minted_usdd_base: 123_456_700,
            configuration_hash: Hash32([0x44; 32]),
        },
        next_state: MintControllerState {
            version: 1,
            sequence: 1,
            next_mint_nonce: 7,
            ethereum_light_client_digest: Hash32([0x55; 32]),
            finalized_beacon_slot: 101,
            finalized_beacon_root: Hash32([0x66; 32]),
            finalized_execution_state_root: Hash32([0x77; 32]),
            total_minted_usdd_base: 123_456_700,
            configuration_hash: Hash32([0x44; 32]),
        },
        finalized_execution_block_timestamp: 1_700_000_000,
    }
    .encode()
}

#[test]
fn solidity_deposit_vector() {
    let deposit = VaultDeposit {
        ethereum_chain_id: 1,
        vault: EthAddress::from_str("1111111111111111111111111111111111111111").unwrap(),
        usdt: EthAddress::from_str("2222222222222222222222222222222222222222").unwrap(),
        nonce: 7,
        depositor: EthAddress::from_str("3333333333333333333333333333333333333333").unwrap(),
        usdt_amount_micro: 1_234_567,
        elements_script: usdd_core::decode_hex("00145555555555555555555555555555555555555555")
            .unwrap(),
        user_salt: Hash32::from_str(
            "4444444444444444444444444444444444444444444444444444444444444444",
        )
        .unwrap(),
    };
    assert_eq!(
        deposit.elements_script_hash().to_string(),
        "d737b8b837fbe9ea82598a36460a6c2820587fe94c1f2dfbd6a5252557faa163"
    );
    assert_eq!(
        deposit.deposit_id().to_string(),
        "9e5afdd09d527b20a71fe3b33e938e3a0ce97d4fd60519456ac1c87453e72dfe"
    );
}

#[test]
fn burn_identity_payload_and_solidity_leaf_vector() {
    let elements_genesis = Hash32([0xaa; 32]);
    let burn = Burn {
        vault_id: Hash32([0xcc; 32]),
        usdd_asset: Hash32([0xbb; 32]),
        usdd_amount_base: 123_456_700,
        usdt_amount_micro: 1_234_567,
        burn_outpoint: OutPoint {
            txid: Hash32(core::array::from_fn(|index| index as u8)),
            vout: 9,
        },
        ethereum_destination: EthAddress([0xee; 20]),
    };
    assert_eq!(
        burn.redemption_id(elements_genesis).to_string(),
        "14198b9101f21d79ed522dd15fb9b4d5066f30260dcce38419116af74b76fc17"
    );
    assert_eq!(
        encode_hex(&burn.burn_payload().encode()),
        "5553444401cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccceeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee000000000012d687"
    );
    let claim: SolidityBurnClaim = burn.solidity_claim(elements_genesis);
    assert_eq!(
        claim.burn_leaf(0).unwrap().to_string(),
        "b50719e243c4d3ecb91a683d30af5e7e10baf51d8b568dd2eded5eada069762d"
    );
    let leaf = claim.burn_leaf(0).unwrap();
    let tree = usdd_core::BurnAccumulator::from_leaves(vec![leaf]).unwrap();
    let proof = tree.proof(0).unwrap();
    assert_eq!(
        usdd_core::hash_bytes(&proof.encode()).to_string(),
        "bb0521561f94bb06fea2cc862488d83e7b920fb049d8b84605f75b259eb8e4cc"
    );
    assert_eq!(
        tree.root().to_string(),
        "07c258f2b38e9b37eacefdc3a817d6bed357e5fef9b5e5e067fd183742df178a"
    );
}

#[test]
fn strict_journal_and_cxx_annex_vectors() {
    let program_id = Hash32([0x77; 32]);
    let payload = heartbeat_public_values();
    let journal = StrictJournal::new(StatementKind::EthereumState, program_id, payload).unwrap();
    assert_eq!(
        encode_hex(&journal.encode()),
        "555344444a4e4c310002015355434345535321017777777777777777777777777777777777777777777777777777777777777777457bd4e12e0323774880898f6bb8bd9aa3164e0118555b098399d822df1b76930000019400025204888888888888888888888888888888888888888888888888888888888888888899999999999999999999999999999999999999999999999999999999999999990000000100000000000000000000000000000007111111111111111111111111111111111111111111111111111111111111111100000000000000642222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333300000000075bccbc44444444444444444444444444444444444444444444444444444444444444440000000100000000000000010000000000000007555555555555555555555555555555555555555555555555555555555555555500000000000000656666666666666666666666666666666666666666666666666666666666666666777777777777777777777777777777777777777777777777777777777777777700000000075bccbc4444444444444444444444444444444444444444444444444444444444444444000000006553f100"
    );
    let annex = Sp1ProofAnnex::new(
        StatementKind::EthereumState,
        program_id,
        journal.encode(),
        vec![0x99, 0x9a, 0x9b],
    )
    .unwrap();
    assert_eq!(
        encode_hex(&annex.encode()),
        "505553444453503100010101010000000001ec000000037777777777777777777777777777777777777777777777777777777777777777555344444a4e4c310002015355434345535321017777777777777777777777777777777777777777777777777777777777777777457bd4e12e0323774880898f6bb8bd9aa3164e0118555b098399d822df1b76930000019400025204888888888888888888888888888888888888888888888888888888888888888899999999999999999999999999999999999999999999999999999999999999990000000100000000000000000000000000000007111111111111111111111111111111111111111111111111111111111111111100000000000000642222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333300000000075bccbc44444444444444444444444444444444444444444444444444444444444444440000000100000000000000010000000000000007555555555555555555555555555555555555555555555555555555555555555500000000000000656666666666666666666666666666666666666666666666666666666666666666777777777777777777777777777777777777777777777777777777777777777700000000075bccbc4444444444444444444444444444444444444444444444444444444444444444000000006553f100999a9b"
    );
}
