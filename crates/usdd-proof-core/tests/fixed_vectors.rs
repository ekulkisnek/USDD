use core::str::FromStr;

use usdd_core::{
    encode_hex, Burn, CanonicalEncode, EthAddress, Hash32, OutPoint, SolidityBurnClaim,
    VaultDeposit,
};
use usdd_proof_core::{Sp1ProofAnnex, StatementKind, StrictJournal};

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
    let journal =
        StrictJournal::new(StatementKind::EthereumState, program_id, vec![1, 2, 3, 4]).unwrap();
    assert_eq!(
        encode_hex(&journal.encode()),
        "555344444a4e4c3100010153554343455353210177777777777777777777777777777777777777777777777777777777777777779f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a0000000401020304"
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
        "5055534444535031000101010100000000005c000000037777777777777777777777777777777777777777777777777777777777777777555344444a4e4c3100010153554343455353210177777777777777777777777777777777777777777777777777777777777777779f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a0000000401020304999a9b"
    );
}
