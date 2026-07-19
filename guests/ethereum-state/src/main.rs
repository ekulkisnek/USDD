#![no_main]

sp1_zkvm::entrypoint!(main);

use usdd_ethereum_inbound::helios::MAX_FINALITY_WITNESS_BYTES;
use usdd_ethereum_state_guest::{
    execute_guest_input, MAX_CLAIM_BYTES, MAX_MANIFEST_BYTES, MAX_VAULT_WITNESS_BYTES,
};

pub fn main() {
    let statement_tag = read_bounded(1);
    let manifest = read_bounded(MAX_MANIFEST_BYTES);
    let claim = read_bounded(MAX_CLAIM_BYTES);
    let finality = read_bounded(MAX_FINALITY_WITNESS_BYTES);
    let vault_witness = read_bounded(MAX_VAULT_WITNESS_BYTES);
    let journal = execute_guest_input(&statement_tag, &manifest, &claim, &finality, &vault_witness)
        .expect("USDD Ethereum state guest rejected its private witness");
    sp1_zkvm::io::commit_slice(&journal);
}

/// Check the prover-controlled hint length before SP1 allocates or copies it,
/// then repeat the check through the pure guest decoder.
fn read_bounded(maximum: usize) -> Vec<u8> {
    let announced = sp1_zkvm::syscalls::syscall_hint_len();
    assert!(
        announced <= maximum,
        "SP1 private input record is oversized"
    );
    let bytes = sp1_zkvm::io::read_vec();
    assert_eq!(
        bytes.len(),
        announced,
        "SP1 hint length changed while reading"
    );
    bytes
}
