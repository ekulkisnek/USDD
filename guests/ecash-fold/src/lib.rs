use sha2::{Digest, Sha256};
use usdd_core::{CanonicalDecode, CanonicalEncode, Hash32};
use usdd_ecash_proof_core::{
    fold_outputs, EcashProofConfig, SegmentOutput, ECASH_FOLD_JOURNAL_DOMAIN,
    ECASH_SEGMENT_JOURNAL_DOMAIN,
};

pub const MAX_CHILD_JOURNAL_BYTES: usize = 4 * 1024;

pub fn decode_child_journal(
    config: &EcashProofConfig,
    vkey: &[u32; 8],
    journal: &[u8],
) -> Result<SegmentOutput, &'static str> {
    if journal.is_empty() || journal.len() > MAX_CHILD_JOURNAL_BYTES {
        return Err("child journal exceeds its bound");
    }
    let vkey_id = Hash32(vkey_bytes(vkey));
    let domain = if vkey_id == config.segment_program_id {
        ECASH_SEGMENT_JOURNAL_DOMAIN
    } else if vkey_id == config.fold_program_id {
        ECASH_FOLD_JOURNAL_DOMAIN
    } else {
        return Err("child verification key is not frozen in config");
    };
    let encoded = journal
        .strip_prefix(domain)
        .ok_or("child journal domain does not match its verification key")?;
    let output = SegmentOutput::decode_exact(encoded).map_err(|_| "invalid child journal")?;
    if output.encode() != encoded {
        return Err("child journal is noncanonical");
    }
    output
        .validate(config)
        .map_err(|_| "invalid child output")?;
    Ok(output)
}

pub fn child_public_values_digest(journal: &[u8]) -> [u8; 32] {
    Sha256::digest(journal).into()
}

pub fn vkey_bytes(vkey: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, word) in vkey.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

pub fn fold_verified_children(
    config: &EcashProofConfig,
    left_vkey: &[u32; 8],
    left_journal: &[u8],
    right_vkey: &[u32; 8],
    right_journal: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let left = decode_child_journal(config, left_vkey, left_journal)?;
    let right = decode_child_journal(config, right_vkey, right_journal)?;
    let output =
        fold_outputs(config, &left, &right).map_err(|_| "child outputs are not adjacent")?;
    Ok(output.journal(true))
}
