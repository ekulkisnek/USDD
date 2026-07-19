//! Frozen LayerTwo-Labs Signet challenge verification.

extern crate alloc;

use alloc::vec::Vec;

use bitcoin_hashes::{hash160, Hash as BitcoinHash};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature as K256Signature, VerifyingKey};

use super::{
    merkle_root_and_mutation, parse_and_verify_block, witness_commitment_index,
    BlockStructureError, ParsedBlock,
};
use crate::{
    double_sha256, extract_elements_slot24_m7, verify_successor, BlockHash, HeaderChainState,
    HeaderError, M7Error, PowMerkleBoundM7, PowParameters,
};

const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];
const LAYER_TWO_SIGNET_P2WPKH: [u8; 20] = [
    0x88, 0x35, 0x83, 0x2e, 0x28, 0xc8, 0x16, 0xb7, 0xac, 0xd8, 0xfd, 0xb1, 0x97, 0x72, 0xab, 0x21,
    0x99, 0x60, 0x3a, 0x56,
];
const LAYER_TWO_SIGNET_GENESIS_INTERNAL: [u8; 32] = [
    0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2, 0xbb, 0xc9,
    0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25, 0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayerTwoSignetError {
    Block(BlockStructureError),
    Header(HeaderError),
    Commitment(M7Error),
    MissingWitnessCommitment,
    MalformedCommitmentScript,
    MissingSolution,
    NonCanonicalSolution,
    NonEmptyScriptSig,
    WrongWitnessStack,
    WrongPublicKeyHash,
    InvalidPublicKey,
    InvalidDerSignature,
    InvalidSignature,
    LengthOverflow,
}

impl From<BlockStructureError> for LayerTwoSignetError {
    fn from(value: BlockStructureError) -> Self {
        Self::Block(value)
    }
}

impl From<HeaderError> for LayerTwoSignetError {
    fn from(value: HeaderError) -> Self {
        Self::Header(value)
    }
}

impl From<M7Error> for LayerTwoSignetError {
    fn from(value: M7Error) -> Self {
        Self::Commitment(value)
    }
}

/// A parent transition that additionally satisfies the immutable
/// LayerTwo-Labs P2WPKH Signet challenge.
///
/// This still does not assert all Bitcoin contextual/UTXO rules, BIP300 state,
/// best-chain selection, confirmation depth, or Elements validity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignetPowMerkleBoundM7Transition {
    pub next_parent_state: HeaderChainState,
    pub commitment: PowMerkleBoundM7,
}

fn read_script_op<'a>(
    script: &'a [u8],
    position: &mut usize,
) -> Result<(u8, Option<&'a [u8]>), LayerTwoSignetError> {
    let opcode = *script
        .get(*position)
        .ok_or(LayerTwoSignetError::MalformedCommitmentScript)?;
    *position += 1;
    let length = match opcode {
        0x01..=0x4b => Some(usize::from(opcode)),
        0x4c => {
            let length = *script
                .get(*position)
                .ok_or(LayerTwoSignetError::MalformedCommitmentScript)?;
            *position += 1;
            Some(usize::from(length))
        }
        0x4d => {
            let end = position
                .checked_add(2)
                .ok_or(LayerTwoSignetError::LengthOverflow)?;
            let bytes = script
                .get(*position..end)
                .ok_or(LayerTwoSignetError::MalformedCommitmentScript)?;
            *position = end;
            Some(usize::from(u16::from_le_bytes(
                bytes.try_into().expect("fixed pushdata length"),
            )))
        }
        0x4e => {
            let end = position
                .checked_add(4)
                .ok_or(LayerTwoSignetError::LengthOverflow)?;
            let bytes = script
                .get(*position..end)
                .ok_or(LayerTwoSignetError::MalformedCommitmentScript)?;
            *position = end;
            Some(
                usize::try_from(u32::from_le_bytes(
                    bytes.try_into().expect("fixed pushdata length"),
                ))
                .map_err(|_| LayerTwoSignetError::LengthOverflow)?,
            )
        }
        _ => None,
    };
    let Some(length) = length else {
        return Ok((opcode, None));
    };
    let end = position
        .checked_add(length)
        .ok_or(LayerTwoSignetError::LengthOverflow)?;
    let data = script
        .get(*position..end)
        .ok_or(LayerTwoSignetError::MalformedCommitmentScript)?;
    *position = end;
    Ok((opcode, Some(data)))
}

fn append_script_push(data: &[u8], output: &mut Vec<u8>) -> Result<(), LayerTwoSignetError> {
    if data.len() < 0x4c {
        output.push(data.len() as u8);
    } else if data.len() <= usize::from(u8::MAX) {
        output.extend_from_slice(&[0x4c, data.len() as u8]);
    } else if data.len() <= usize::from(u16::MAX) {
        output.push(0x4d);
        output.extend_from_slice(&(data.len() as u16).to_le_bytes());
    } else {
        let length = u32::try_from(data.len()).map_err(|_| LayerTwoSignetError::LengthOverflow)?;
        output.push(0x4e);
        output.extend_from_slice(&length.to_le_bytes());
    }
    output.extend_from_slice(data);
    Ok(())
}

/// Faithful `FetchAndClearCommitmentSection` specialization for the Signet
/// header. Like Core, only the first push containing header plus data is used.
fn extract_solution_and_modified_script(
    witness_commitment: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), LayerTwoSignetError> {
    let mut position = 0usize;
    let mut replacement = Vec::new();
    let mut solution = None;
    while position < witness_commitment.len() {
        // Bitcoin Core's GetOp loop stops on a malformed suffix. If the Signet
        // section was already found, FetchAndClearCommitmentSection still
        // returns its replacement prefix. Match that consensus behavior.
        let Ok((opcode, pushdata)) = read_script_op(witness_commitment, &mut position) else {
            break;
        };
        match pushdata {
            Some(data) if !data.is_empty() => {
                if solution.is_none()
                    && data.len() > SIGNET_HEADER.len()
                    && data[..SIGNET_HEADER.len()] == SIGNET_HEADER
                {
                    solution = Some(data[SIGNET_HEADER.len()..].to_vec());
                    append_script_push(&SIGNET_HEADER, &mut replacement)?;
                } else {
                    append_script_push(data, &mut replacement)?;
                }
            }
            _ => replacement.push(opcode),
        }
    }
    let solution = solution.ok_or(LayerTwoSignetError::MissingSolution)?;
    Ok((solution, replacement))
}

fn parse_solution(solution: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), LayerTwoSignetError> {
    let mut cursor = super::Cursor::new(solution, 0);
    let script_sig_size = cursor
        .compact_size()
        .map_err(|_| LayerTwoSignetError::NonCanonicalSolution)?;
    let script_sig = cursor
        .take(script_sig_size)
        .map_err(|_| LayerTwoSignetError::NonCanonicalSolution)?
        .to_vec();
    let item_count = cursor
        .compact_size()
        .map_err(|_| LayerTwoSignetError::NonCanonicalSolution)?;
    if item_count > cursor.remaining() {
        return Err(LayerTwoSignetError::NonCanonicalSolution);
    }
    let mut witness = Vec::with_capacity(item_count);
    for _ in 0..item_count {
        let item_size = cursor
            .compact_size()
            .map_err(|_| LayerTwoSignetError::NonCanonicalSolution)?;
        witness.push(
            cursor
                .take(item_size)
                .map_err(|_| LayerTwoSignetError::NonCanonicalSolution)?
                .to_vec(),
        );
    }
    if cursor.remaining() != 0 {
        return Err(LayerTwoSignetError::NonCanonicalSolution);
    }
    Ok((script_sig, witness))
}

fn virtual_spent_txid(
    parsed: &ParsedBlock<'_>,
    modified_merkle_root: BlockHash,
) -> Result<BlockHash, LayerTwoSignetError> {
    let mut block_data = Vec::with_capacity(72);
    block_data.extend_from_slice(&parsed.metadata.header.version.to_le_bytes());
    block_data.extend_from_slice(&parsed.metadata.header.previous_block.to_internal_bytes());
    block_data.extend_from_slice(&modified_merkle_root.to_internal_bytes());
    block_data.extend_from_slice(&parsed.metadata.header.time.to_le_bytes());
    debug_assert_eq!(block_data.len(), 72);

    let mut transaction = Vec::new();
    transaction.extend_from_slice(&0i32.to_le_bytes());
    transaction.push(1);
    transaction.extend_from_slice(&[0; 32]);
    transaction.extend_from_slice(&u32::MAX.to_le_bytes());
    transaction.push(74);
    transaction.extend_from_slice(&[0x00, 0x48]);
    transaction.extend_from_slice(&block_data);
    transaction.extend_from_slice(&0u32.to_le_bytes());
    transaction.push(1);
    transaction.extend_from_slice(&0i64.to_le_bytes());
    transaction.push(22);
    transaction.extend_from_slice(&[0x00, 0x14]);
    transaction.extend_from_slice(&LAYER_TWO_SIGNET_P2WPKH);
    transaction.extend_from_slice(&0u32.to_le_bytes());
    Ok(BlockHash::from_internal_bytes(double_sha256(&transaction)))
}

fn strict_der_encoding(signature_with_hash_type: &[u8]) -> bool {
    if !(9..=73).contains(&signature_with_hash_type.len())
        || signature_with_hash_type[0] != 0x30
        || usize::from(signature_with_hash_type[1]) != signature_with_hash_type.len() - 3
        || signature_with_hash_type[2] != 0x02
    {
        return false;
    }
    let len_r = usize::from(signature_with_hash_type[3]);
    if len_r == 0 || 5usize.saturating_add(len_r) >= signature_with_hash_type.len() {
        return false;
    }
    let s_type_index = 4 + len_r;
    if signature_with_hash_type[s_type_index] != 0x02 {
        return false;
    }
    let len_s = usize::from(signature_with_hash_type[s_type_index + 1]);
    if len_r + len_s + 7 != signature_with_hash_type.len()
        || len_s == 0
        || signature_with_hash_type[4] & 0x80 != 0
        || (len_r > 1
            && signature_with_hash_type[4] == 0
            && signature_with_hash_type[5] & 0x80 == 0)
    {
        return false;
    }
    let s_index = s_type_index + 2;
    if signature_with_hash_type[s_index] & 0x80 != 0
        || (len_s > 1
            && signature_with_hash_type[s_index] == 0
            && signature_with_hash_type[s_index + 1] & 0x80 == 0)
    {
        return false;
    }
    true
}

fn signet_bip143_sighash(spent_txid: BlockHash, hash_type: u32) -> [u8; 32] {
    let base_type = hash_type & 0x1f;
    let anyone_can_pay = hash_type & 0x80 != 0;

    let mut outpoint = [0u8; 36];
    outpoint[..32].copy_from_slice(&spent_txid.to_internal_bytes());
    let hash_prevouts = if anyone_can_pay {
        [0; 32]
    } else {
        double_sha256(&outpoint)
    };
    let sequence = 0u32.to_le_bytes();
    let hash_sequence = if anyone_can_pay || base_type == 2 || base_type == 3 {
        [0; 32]
    } else {
        double_sha256(&sequence)
    };
    let output = [
        0, 0, 0, 0, 0, 0, 0, 0, // value
        1, 0x6a, // scriptPubKey
    ];
    let hash_outputs = if base_type == 2 {
        [0; 32]
    } else {
        // The virtual transaction has output zero, so SIGHASH_SINGLE and all
        // non-NONE base types commit to this same output.
        double_sha256(&output)
    };

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&0i32.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    preimage.extend_from_slice(&outpoint);
    preimage.push(25);
    preimage.extend_from_slice(&[0x76, 0xa9, 0x14]);
    preimage.extend_from_slice(&LAYER_TWO_SIGNET_P2WPKH);
    preimage.extend_from_slice(&[0x88, 0xac]);
    preimage.extend_from_slice(&0i64.to_le_bytes());
    preimage.extend_from_slice(&sequence);
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&0u32.to_le_bytes());
    preimage.extend_from_slice(&hash_type.to_le_bytes());
    double_sha256(&preimage)
}

fn verify_parsed_layer_two_signet(parsed: &ParsedBlock<'_>) -> Result<(), LayerTwoSignetError> {
    if parsed.metadata.block_hash
        == BlockHash::from_internal_bytes(LAYER_TWO_SIGNET_GENESIS_INTERNAL)
    {
        return Ok(());
    }
    let commitment_index = witness_commitment_index(&parsed.coinbase.outputs)
        .ok_or(LayerTwoSignetError::MissingWitnessCommitment)?;
    let (solution, modified_commitment) =
        extract_solution_and_modified_script(parsed.coinbase.outputs[commitment_index].script)?;
    let (script_sig, witness) = parse_solution(&solution)?;
    if !script_sig.is_empty() {
        return Err(LayerTwoSignetError::NonEmptyScriptSig);
    }
    if witness.len() != 2 || witness[0].is_empty() {
        return Err(LayerTwoSignetError::WrongWitnessStack);
    }
    let signature_with_hash_type = &witness[0];
    let public_key = &witness[1];
    if hash160::Hash::hash(public_key).to_byte_array() != LAYER_TWO_SIGNET_P2WPKH {
        return Err(LayerTwoSignetError::WrongPublicKeyHash);
    }
    if !strict_der_encoding(signature_with_hash_type) {
        return Err(LayerTwoSignetError::InvalidDerSignature);
    }

    let modified_coinbase = parsed
        .coinbase
        .serialized_without_witness_with_replaced_script(commitment_index, &modified_commitment)?;
    let mut modified_txids = parsed.txids.clone();
    modified_txids[0] = BlockHash::from_internal_bytes(double_sha256(&modified_coinbase));
    let (modified_merkle_root, _) = merkle_root_and_mutation(modified_txids);
    let spent_txid = virtual_spent_txid(parsed, modified_merkle_root)?;

    let hash_type = u32::from(
        *signature_with_hash_type
            .last()
            .ok_or(LayerTwoSignetError::InvalidDerSignature)?,
    );
    let sighash = signet_bip143_sighash(spent_txid, hash_type);
    let signature =
        K256Signature::from_der(&signature_with_hash_type[..signature_with_hash_type.len() - 1])
            .map_err(|_| LayerTwoSignetError::InvalidDerSignature)?;
    // Bitcoin's Signet flags require strict DER but do not require LOW_S.
    // k256's verifier does require LOW_S, so normalize the mathematically
    // equivalent high-S form before verification to preserve Core semantics.
    let signature = signature.normalize_s().unwrap_or(signature);
    let key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| LayerTwoSignetError::InvalidPublicKey)?;
    key.verify_prehash(&sighash, &signature)
        .map_err(|_| LayerTwoSignetError::InvalidSignature)
}

/// Verify the exact serialized block, BIP141 witness commitment, and immutable
/// LayerTwo-Labs P2WPKH Signet solution. This does not verify proof of work or
/// chain position; use the successor transition API for that composition.
pub fn verify_layer_two_signet_block_solution(
    serialized_block: &[u8],
) -> Result<super::MerkleVerifiedBitcoinBlock, LayerTwoSignetError> {
    let parsed = parse_and_verify_block(serialized_block)?;
    verify_parsed_layer_two_signet(&parsed)?;
    Ok(parsed.metadata)
}

/// Production-direction parent primitive: exact block/Merkle/BIP141 checks,
/// immutable LayerTwo Signet authorization, successor difficulty/PoW/work, and
/// unique canonical slot-24 M7 extraction in one fail-closed transition.
///
/// BIP300 state replay, full contextual/UTXO Bitcoin validity, best-chain
/// selection, 100-confirmation tracking, and full Elements validity remain
/// mandatory higher-layer proof obligations.
pub fn verify_layer_two_signet_pow_merkle_bound_elements_m7_successor(
    prior: &HeaderChainState,
    serialized_block: &[u8],
) -> Result<SignetPowMerkleBoundM7Transition, LayerTwoSignetError> {
    let parsed = parse_and_verify_block(serialized_block)?;
    verify_parsed_layer_two_signet(&parsed)?;
    let next_parent_state = verify_successor(
        prior,
        &parsed.metadata.header.raw(),
        PowParameters::LAYER_TWO_SIGNET,
    )?;
    let output_scripts = parsed
        .coinbase
        .outputs
        .iter()
        .map(|output| output.script)
        .collect::<Vec<_>>();
    let m7 = extract_elements_slot24_m7(&output_scripts)?;
    Ok(SignetPowMerkleBoundM7Transition {
        next_parent_state,
        commitment: PowMerkleBoundM7 {
            parent_block_hash: parsed.metadata.block_hash,
            parent_height: next_parent_state.height,
            coinbase_txid: parsed.metadata.coinbase_txid,
            output_index: m7.output_index,
            committed_child_hash: m7.committed_child_hash,
            transaction_count: parsed.metadata.transaction_count,
            block_weight: parsed.metadata.weight,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => panic!("non-hex fixture"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    fn layer_two_block_5580() -> Vec<u8> {
        hex(concat!(
            "00000020027d89a3fdacc10943565cfdbc1d5a32fb6f3d638e3a5dc0c9b7fd4546020000",
            "f484c8e55e26cd1eb8d279dfbfd56c44a27995cdb4c057344f6b3e0951fc2b3d",
            "b5c65a6a3d77031e24a88a0001",
            "02000000000101",
            "0000000000000000000000000000000000000000000000000000000000000000ffffffff",
            "0302cc15ffffffff09",
            "0000000000000000276a25d161736804554faf2df2135a463ad1fefdf6ecbffd27f2a2bfabba909376d9d628724dfe90",
            "0000000000000000276a25d1617368093f9140f0756e966e730317341a8eb3826d0e9ba86f6e22e5a90f4ba4ad2eed39",
            "0000000000000000276a25d161736862ecce70a22de077e7192456ebfd30ed617fc14eec92782936e5003307a81b2737",
            "0000000000000000276a25d16173686323f3c921f22f6e4a7f9f8be1664028f2dd75ba3cc24a3794fe4c65e622242845",
            "0000000000000000276a25d16173680263c29a2764d747e4d1e94dc4de89aab1a844dcbcbcb0231715656f154a800ad5",
            "0000000000000000276a25d16173680d82352000588a4ea8444ca7e585bfef39382703d2247a29389d01f9f9106c60d9",
            "00000000000000000f6a0dd77d177601ffffffffffffffff",
            "00f2052a01000000160014fae83223f01759582ffe70f5f770eb8462f04da2",
            "0000000000000000986a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c70",
            "ecc7daa2000247304402201e4aef7971e3279353d1c948c0af0a9e6a943a8dc8c9dcc106104c8d782bc096",
            "02206a4aadfeea8f8edf14dea5e158977ce1badf76b4faf4ab776081fab3f68738f801",
            "2103675b73e701c9dab7de809bb0000b4c1205f9a834d669a7f47c107a7d2c199f56",
            "01200000000000000000000000000000000000000000000000000000000000000000",
            "00000000"
        ))
    }

    #[test]
    fn real_layer_two_block_5580_signature_and_witness_commitment_verify() {
        let block = layer_two_block_5580();
        let verified = verify_layer_two_signet_block_solution(&block).expect("real Signet block");
        assert_eq!(verified.transaction_count, 1);
        assert_eq!(
            verified.block_hash.to_internal_bytes(),
            double_sha256(&block[..80])
        );
    }

    #[test]
    fn signet_signature_commits_header_time_and_modified_merkle_root() {
        let mut changed_time = layer_two_block_5580();
        changed_time[68] ^= 1;
        assert_eq!(
            verify_layer_two_signet_block_solution(&changed_time),
            Err(LayerTwoSignetError::InvalidSignature)
        );

        let mut changed_solution = layer_two_block_5580();
        let signature_byte = changed_solution
            .windows(4)
            .position(|window| window == SIGNET_HEADER)
            .expect("Signet header")
            + SIGNET_HEADER.len()
            + 8;
        changed_solution[signature_byte] ^= 1;
        assert!(matches!(
            verify_layer_two_signet_block_solution(&changed_solution),
            Err(LayerTwoSignetError::InvalidDerSignature)
                | Err(LayerTwoSignetError::InvalidSignature)
                | Err(LayerTwoSignetError::Block(
                    BlockStructureError::WitnessCommitmentMismatch
                        | BlockStructureError::MerkleRootMismatch
                ))
        ));
    }

    #[test]
    fn strict_der_matches_bitcoin_core_boundary_rules() {
        let valid = hex(
            "304402201e4aef7971e3279353d1c948c0af0a9e6a943a8dc8c9dcc106104c8d782bc09602206a4aadfeea8f8edf14dea5e158977ce1badf76b4faf4ab776081fab3f68738f801",
        );
        assert!(strict_der_encoding(&valid));
        let mut trailing = valid.clone();
        trailing.push(1);
        assert!(!strict_der_encoding(&trailing));
        let mut negative_r = valid;
        negative_r[4] |= 0x80;
        assert!(!strict_der_encoding(&negative_r));
    }

    #[test]
    fn solution_codec_rejects_noncanonical_lengths_and_trailing_data() {
        assert_eq!(
            parse_solution(&[0xfd, 0, 0, 0]),
            Err(LayerTwoSignetError::NonCanonicalSolution)
        );
        assert_eq!(
            parse_solution(&[0, 0, 1]),
            Err(LayerTwoSignetError::NonCanonicalSolution)
        );
    }

    #[test]
    fn fetch_and_clear_matches_core_on_malformed_trailing_script() {
        let script = [0x05, 0xec, 0xc7, 0xda, 0xa2, 0x99, 0x4c];
        let (solution, replacement) = extract_solution_and_modified_script(&script)
            .expect("header precedes malformed suffix");
        assert_eq!(solution, [0x99]);
        assert_eq!(replacement, [0x04, 0xec, 0xc7, 0xda, 0xa2]);

        assert_eq!(
            extract_solution_and_modified_script(&[0x4c]),
            Err(LayerTwoSignetError::MissingSolution)
        );
    }
}
