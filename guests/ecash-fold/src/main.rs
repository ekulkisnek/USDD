#![no_main]

sp1_zkvm::entrypoint!(main);

use sp1_zkvm::lib::verify::verify_sp1_proof;
use usdd_core::CanonicalDecode;
use usdd_ecash_fold_guest::{
    child_public_values_digest, fold_verified_children, MAX_CHILD_JOURNAL_BYTES,
};
use usdd_ecash_proof_core::EcashProofConfig;

pub fn main() {
    let config_bytes = read_bounded(4 * 1024);
    let config = EcashProofConfig::decode_exact(&config_bytes).expect("invalid fold config");
    let left_vkey = sp1_zkvm::io::read::<[u32; 8]>();
    let left_journal = read_bounded(MAX_CHILD_JOURNAL_BYTES);
    let right_vkey = sp1_zkvm::io::read::<[u32; 8]>();
    let right_journal = read_bounded(MAX_CHILD_JOURNAL_BYTES);

    // These syscalls consume the next two deferred proofs supplied by the host.
    // A malformed, missing, or wrong-program child proof aborts the fold guest.
    verify_sp1_proof(&left_vkey, &child_public_values_digest(&left_journal));
    verify_sp1_proof(&right_vkey, &child_public_values_digest(&right_journal));

    let journal = fold_verified_children(
        &config,
        &left_vkey,
        &left_journal,
        &right_vkey,
        &right_journal,
    )
    .expect("ECASH_FOLD_V1 rejected child adjacency");
    sp1_zkvm::io::commit_slice(&journal);
}

fn read_bounded(maximum: usize) -> Vec<u8> {
    let announced = sp1_zkvm::syscalls::syscall_hint_len();
    assert!(announced <= maximum, "oversized eCash fold input");
    let bytes = sp1_zkvm::io::read_vec();
    assert_eq!(bytes.len(), announced, "SP1 fold hint length changed");
    bytes
}
