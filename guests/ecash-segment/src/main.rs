#![no_main]

sp1_zkvm::entrypoint!(main);

use usdd_ecash_segment_guest::{execute_guest_input, MAX_SEGMENT_INPUT_BYTES};

pub fn main() {
    let announced = sp1_zkvm::syscalls::syscall_hint_len();
    assert!(
        announced <= MAX_SEGMENT_INPUT_BYTES,
        "oversized eCash segment input"
    );
    let input = sp1_zkvm::io::read_vec();
    assert_eq!(input.len(), announced, "SP1 segment hint length changed");
    let journal = execute_guest_input(&input).expect("ECASH_SEGMENT_V1 rejected its witness");
    sp1_zkvm::io::commit_slice(&journal);
}
