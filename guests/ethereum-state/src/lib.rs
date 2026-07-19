use usdd_core::{CanonicalDecode, CanonicalEncode, ProtocolManifest};
use usdd_ethereum_inbound::{
    helios::{SepoliaFinalityProof, SepoliaHeliosFinalityVerifier, MAX_FINALITY_WITNESS_BYTES},
    EthereumInboundProof, EthereumInboundVerifier, VaultStorageWitness,
};
use usdd_proof_core::{
    build_deposit_journal, build_heartbeat_journal, EthereumDepositClaim, EthereumHeartbeatClaim,
};

pub const DEPOSIT_STATEMENT: u8 = 1;
pub const HEARTBEAT_STATEMENT: u8 = 2;
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024;
pub const MAX_CLAIM_BYTES: usize = 128 * 1024;
pub const MAX_VAULT_WITNESS_BYTES: usize = 4 * 1024 * 1024 + 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestInputError {
    WrongStatementTag,
    InputTooLarge,
    UnexpectedVaultWitness,
    DecodeRejected,
    VerificationRejected,
}

/// Execute the exact guest transition over five independently bounded input
/// records and return the canonical strict journal bytes.
///
/// All chain facts in `finality_bytes` remain untrusted until the pinned
/// Sepolia Helios verifier succeeds. The manifest, claim, and MPT witness use
/// their schema-2 exact codecs; the finality witness uses its canonical,
/// re-encoding-checked bounded codec.
pub fn execute_guest_input(
    statement_tag: &[u8],
    manifest_bytes: &[u8],
    claim_bytes: &[u8],
    finality_bytes: &[u8],
    vault_witness_bytes: &[u8],
) -> Result<Vec<u8>, GuestInputError> {
    if statement_tag.len() != 1 {
        return Err(GuestInputError::WrongStatementTag);
    }
    if manifest_bytes.is_empty()
        || manifest_bytes.len() > MAX_MANIFEST_BYTES
        || claim_bytes.is_empty()
        || claim_bytes.len() > MAX_CLAIM_BYTES
        || finality_bytes.is_empty()
        || finality_bytes.len() > MAX_FINALITY_WITNESS_BYTES
        || vault_witness_bytes.len() > MAX_VAULT_WITNESS_BYTES
    {
        return Err(GuestInputError::InputTooLarge);
    }
    match statement_tag[0] {
        DEPOSIT_STATEMENT if vault_witness_bytes.is_empty() => {
            return Err(GuestInputError::DecodeRejected);
        }
        HEARTBEAT_STATEMENT if !vault_witness_bytes.is_empty() => {
            return Err(GuestInputError::UnexpectedVaultWitness);
        }
        DEPOSIT_STATEMENT | HEARTBEAT_STATEMENT => {}
        _ => return Err(GuestInputError::WrongStatementTag),
    }

    let manifest = ProtocolManifest::decode_exact(manifest_bytes)
        .map_err(|_| GuestInputError::DecodeRejected)?;
    let finality = SepoliaFinalityProof::decode_canonical(finality_bytes)
        .map_err(|_| GuestInputError::DecodeRejected)?;
    let verifier = EthereumInboundVerifier::new(SepoliaHeliosFinalityVerifier);

    let journal = match statement_tag[0] {
        DEPOSIT_STATEMENT => {
            let claim = EthereumDepositClaim::decode_exact(claim_bytes)
                .map_err(|_| GuestInputError::DecodeRejected)?;
            let vault_storage = VaultStorageWitness::decode_exact(vault_witness_bytes)
                .map_err(|_| GuestInputError::DecodeRejected)?;
            let proof = EthereumInboundProof::Deposit {
                finality_proof: finality,
                vault_storage,
            };
            build_deposit_journal(&verifier, &manifest, &claim, &proof)
                .map_err(|_| GuestInputError::VerificationRejected)?
        }
        HEARTBEAT_STATEMENT => {
            let claim = EthereumHeartbeatClaim::decode_exact(claim_bytes)
                .map_err(|_| GuestInputError::DecodeRejected)?;
            let proof = EthereumInboundProof::Heartbeat {
                finality_proof: finality,
            };
            build_heartbeat_journal(&verifier, &manifest, &claim, &proof)
                .map_err(|_| GuestInputError::VerificationRejected)?
        }
        _ => unreachable!("statement tag was checked before decoding"),
    };
    Ok(journal.encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_bounds_and_statement_tags_fail_before_decoding() {
        assert_eq!(
            execute_guest_input(&[], &[1], &[1], &[1], &[]),
            Err(GuestInputError::WrongStatementTag)
        );
        assert_eq!(
            execute_guest_input(
                &[HEARTBEAT_STATEMENT],
                &vec![0; MAX_MANIFEST_BYTES + 1],
                &[1],
                &[1],
                &[],
            ),
            Err(GuestInputError::InputTooLarge)
        );
        assert_eq!(
            execute_guest_input(&[HEARTBEAT_STATEMENT], &[1], &[1], &[1], &[1]),
            Err(GuestInputError::UnexpectedVaultWitness)
        );
    }
}
