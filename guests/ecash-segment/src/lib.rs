use usdd_core::{CanonicalDecode, CanonicalEncode};
use usdd_ecash_proof_core::{execute_segment, SegmentInput};

pub const MAX_SEGMENT_INPUT_BYTES: usize = 96 * 1024 * 1024;

pub fn execute_guest_input(input_bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    if input_bytes.is_empty() || input_bytes.len() > MAX_SEGMENT_INPUT_BYTES {
        return Err("segment input exceeds its absolute guest bound");
    }
    let input =
        SegmentInput::decode_exact(input_bytes).map_err(|_| "segment input decode failed")?;
    if input.encode() != input_bytes {
        return Err("segment input is noncanonical");
    }
    let (_, output) = execute_segment(&input).map_err(|_| "segment transition rejected")?;
    Ok(output.journal(false))
}
