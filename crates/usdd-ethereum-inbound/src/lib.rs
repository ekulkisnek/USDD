#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use alloy_primitives::{B256, Bytes, U256, keccak256};
use alloy_trie::{Nibbles, TrieAccount, proof};
use usdd_core::{
    CanonicalDecode, CanonicalEncode, DecodeError, Decoder, ENCODING_SCHEMA,
    EthereumFinalityWitness, Hash32, MAX_ETHEREUM_FINALITY_SLOT_GAP, MAX_MINT_BATCH_SIZE,
    MintBatch, MintControllerState, ProtocolManifest, VaultDeposit, hash_bytes,
};
use usdd_proof_core::{
    EthereumDepositClaim, EthereumHeartbeatClaim, EthereumStateProofVerifier, VerificationError,
};

#[cfg(feature = "helios-finality")]
pub mod helios;

/// Frozen Solidity storage slot of `USDDVaultV1.depositCommitmentByNonce`.
pub const DEPOSIT_COMMITMENT_MAPPING_SLOT: u64 = 12;

/// An Ethereum MPT has at most 64 hashed-key nibbles plus a terminal node.
pub const MAX_MPT_PROOF_NODES: usize = 65;

/// Generous bound above the largest ordinary branch node, enforced before copy.
pub const MAX_MPT_NODE_BYTES: usize = 4_096;

/// Aggregate bound for one account proof and at most 64 storage proofs.
pub const MAX_MPT_WITNESS_BYTES: usize = 4 * 1024 * 1024;

const TAG_VAULT_STORAGE_WITNESS: u16 = 0x6101;
const FINALITY_TRANSITION_COMMITMENT_DOMAIN: &[u8] = b"USDD_ETH_FINALITY_TRANSITION_V1";

/// Prover-supplied account fields and account-inclusion branch.
///
/// The verifier re-encodes these fields as the Ethereum `TrieAccount` value and
/// proves that exact value under the finalized execution state root. In
/// particular, `code_hash` is not trusted merely because it appears here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultAccountWitness {
    pub nonce: u64,
    pub balance_be: [u8; 32],
    pub storage_root: Hash32,
    pub code_hash: Hash32,
    pub proof_nodes: Vec<Vec<u8>>,
}

/// Inclusion branch for one derived deposit-commitment storage key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositStorageProof {
    pub proof_nodes: Vec<Vec<u8>>,
}

/// Exact private witness for the vault account and an ordered deposit batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultStorageWitness {
    pub account: VaultAccountWitness,
    pub deposits: Vec<DepositStorageProof>,
}

/// Finality-proof material and, for a mint proof, vault MPT material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EthereumInboundProof<P> {
    Deposit {
        finality_proof: P,
        vault_storage: VaultStorageWitness,
    },
    Heartbeat {
        finality_proof: P,
    },
}

/// Exact statement a production SP1-Helios port must authenticate.
///
/// The finality implementation must start from `prior_state` (or the
/// manifest bootstrap for the initial controller), verify continuous beacon
/// light-client consensus and finality, and derive every field of `next` from
/// the finalized execution payload. It may not treat these references as
/// authenticated inputs.
#[derive(Clone, Copy, Debug)]
pub struct EthereumFinalityTransition<'a> {
    pub manifest: &'a ProtocolManifest,
    pub prior_state: &'a MintControllerState,
    pub next: &'a EthereumFinalityWitness,
}

impl EthereumFinalityTransition<'_> {
    /// SHA-256 commitment an in-guest implementation or recursively verified
    /// finality subprogram must expose after deriving `next` from consensus.
    ///
    /// Preimage: domain bytes, schema `u16be`, manifest ID, then canonical
    /// length-prefixed prior controller state and finality witness.
    pub fn commitment(&self) -> Result<Hash32, InboundVerificationError> {
        let manifest_id = self
            .manifest
            .manifest_id()
            .map_err(|_| InboundVerificationError::InvalidManifest)?;
        let mut preimage = Vec::new();
        preimage.extend_from_slice(FINALITY_TRANSITION_COMMITMENT_DOMAIN);
        ENCODING_SCHEMA.encode_to(&mut preimage);
        manifest_id.encode_to(&mut preimage);
        self.prior_state.encode().encode_to(&mut preimage);
        self.next.encode().encode_to(&mut preimage);
        Ok(hash_bytes(&preimage))
    }
}

/// Consensus-verification boundary intentionally left without a permissive
/// implementation. Returning `Ok(())` is a security-critical authorization,
/// not a parsing callback: it is valid only after the implementation has
/// cryptographically established the entire transition and exact commitment.
/// RPC agreement, an operator signature, or equality with prover input must
/// never produce `Ok(())`.
pub trait EthereumFinalityTransitionVerifier {
    type Proof;

    fn verify_finalized_transition(
        &self,
        transition: EthereumFinalityTransition<'_>,
        proof: &Self::Proof,
    ) -> Result<(), FinalityVerificationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalityVerificationError {
    Rejected,
}

impl fmt::Display for FinalityVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ethereum finality transition rejected")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FinalityVerificationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundVerificationError {
    InvalidManifest,
    InvalidControllerState,
    InvalidFinality,
    FinalityRejected,
    EmptyDepositBatch,
    TooManyDeposits,
    InvalidDeposit,
    WrongDepositTarget,
    NonConsecutiveDepositNonce,
    ZeroDepositCommitment,
    StorageProofCountMismatch,
    VaultCodeHashMismatch,
    InvalidVaultAccount,
    ProofLimitsExceeded,
    AccountProofRejected,
    StorageProofRejected(usize),
    AmountOverflow,
}

impl fmt::Display for InboundVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest => formatter.write_str("invalid protocol manifest"),
            Self::InvalidControllerState => formatter.write_str("invalid prior controller state"),
            Self::InvalidFinality => formatter.write_str("invalid Ethereum finality transition"),
            Self::FinalityRejected => formatter.write_str("Ethereum finality proof rejected"),
            Self::EmptyDepositBatch => formatter.write_str("deposit batch is empty"),
            Self::TooManyDeposits => formatter.write_str("deposit batch exceeds 64"),
            Self::InvalidDeposit => formatter.write_str("deposit violates a vault invariant"),
            Self::WrongDepositTarget => {
                formatter.write_str("deposit targets the wrong chain, vault, or USDT")
            }
            Self::NonConsecutiveDepositNonce => {
                formatter.write_str("deposit nonces are not the expected consecutive sequence")
            }
            Self::ZeroDepositCommitment => {
                formatter.write_str("derived deposit commitment is zero")
            }
            Self::StorageProofCountMismatch => {
                formatter.write_str("storage proof count does not match the deposit batch")
            }
            Self::VaultCodeHashMismatch => {
                formatter.write_str("vault account code hash does not match the manifest")
            }
            Self::InvalidVaultAccount => formatter.write_str("invalid vault account witness"),
            Self::ProofLimitsExceeded => {
                formatter.write_str("MPT witness exceeds a frozen resource bound")
            }
            Self::AccountProofRejected => formatter.write_str("vault account MPT proof rejected"),
            Self::StorageProofRejected(index) => {
                write!(formatter, "deposit storage MPT proof {index} rejected")
            }
            Self::AmountOverflow => formatter.write_str("deposit amount total overflow"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InboundVerificationError {}

/// Auditable result derived only after finality and every MPT proof pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDepositBatch {
    pub execution_state_root: Hash32,
    pub first_nonce: u64,
    pub next_nonce: u64,
    pub total_usdt_micro: u64,
    pub deposit_ids: Vec<Hash32>,
    pub storage_keys: Vec<Hash32>,
}

/// Generic composition adapter used by `usdd-proof-core` journal builders.
pub struct EthereumInboundVerifier<V> {
    finality: V,
}

impl<V> EthereumInboundVerifier<V> {
    pub const fn new(finality: V) -> Self {
        Self { finality }
    }

    pub const fn finality_verifier(&self) -> &V {
        &self.finality
    }
}

impl<V: EthereumFinalityTransitionVerifier> EthereumStateProofVerifier
    for EthereumInboundVerifier<V>
{
    type Proof = EthereumInboundProof<V::Proof>;

    fn verify_finalized_deposits(
        &self,
        manifest: &ProtocolManifest,
        claim: &EthereumDepositClaim,
        proof: &Self::Proof,
    ) -> Result<(), VerificationError> {
        let EthereumInboundProof::Deposit {
            finality_proof,
            vault_storage,
        } = proof
        else {
            return Err(VerificationError::InvalidProof(
                "heartbeat proof supplied for deposit statement",
            ));
        };
        verify_finalized_deposit_batch(
            &self.finality,
            manifest,
            &claim.prior_state,
            &claim.finality,
            &claim.deposits,
            finality_proof,
            vault_storage,
        )
        .map(|_| ())
        .map_err(map_proof_error)
    }

    fn verify_finalized_heartbeat(
        &self,
        manifest: &ProtocolManifest,
        claim: &EthereumHeartbeatClaim,
        proof: &Self::Proof,
    ) -> Result<(), VerificationError> {
        let EthereumInboundProof::Heartbeat { finality_proof } = proof else {
            return Err(VerificationError::InvalidProof(
                "deposit proof supplied for heartbeat statement",
            ));
        };
        verify_finalized_heartbeat(
            &self.finality,
            manifest,
            &claim.prior_state,
            &claim.finality,
            finality_proof,
        )
        .map_err(map_proof_error)
    }
}

fn map_proof_error(error: InboundVerificationError) -> VerificationError {
    match error {
        InboundVerificationError::FinalityRejected => {
            VerificationError::InvalidProof("Ethereum finality transition rejected")
        }
        InboundVerificationError::AccountProofRejected => {
            VerificationError::InvalidProof("vault account proof rejected")
        }
        InboundVerificationError::StorageProofRejected(_) => {
            VerificationError::InvalidProof("vault deposit storage proof rejected")
        }
        _ => VerificationError::InvalidProof("invalid Ethereum inbound proof witness"),
    }
}

pub fn verify_finalized_heartbeat<V: EthereumFinalityTransitionVerifier>(
    verifier: &V,
    manifest: &ProtocolManifest,
    prior_state: &MintControllerState,
    finality: &EthereumFinalityWitness,
    proof: &V::Proof,
) -> Result<(), InboundVerificationError> {
    validate_transition_shape(manifest, prior_state, finality)?;
    if finality.finalized_beacon_slot <= prior_state.finalized_beacon_slot {
        return Err(InboundVerificationError::InvalidFinality);
    }
    verifier
        .verify_finalized_transition(
            EthereumFinalityTransition {
                manifest,
                prior_state,
                next: finality,
            },
            proof,
        )
        .map_err(|_| InboundVerificationError::FinalityRejected)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_finalized_deposit_batch<V: EthereumFinalityTransitionVerifier>(
    verifier: &V,
    manifest: &ProtocolManifest,
    prior_state: &MintControllerState,
    finality: &EthereumFinalityWitness,
    deposits: &[VaultDeposit],
    finality_proof: &V::Proof,
    witness: &VaultStorageWitness,
) -> Result<VerifiedDepositBatch, InboundVerificationError> {
    validate_transition_shape(manifest, prior_state, finality)?;
    validate_deposit_batch(manifest, prior_state, deposits)?;
    if witness.deposits.len() != deposits.len() {
        return Err(InboundVerificationError::StorageProofCountMismatch);
    }
    witness.validate_limits()?;

    verifier
        .verify_finalized_transition(
            EthereumFinalityTransition {
                manifest,
                prior_state,
                next: finality,
            },
            finality_proof,
        )
        .map_err(|_| InboundVerificationError::FinalityRejected)?;

    verify_vault_account(
        finality.finalized_execution_state_root,
        manifest,
        &witness.account,
    )?;

    let mut deposit_ids = Vec::with_capacity(deposits.len());
    let mut storage_keys = Vec::with_capacity(deposits.len());
    let mut total_usdt_micro = 0u64;
    for (index, (deposit, storage_proof)) in
        deposits.iter().zip(witness.deposits.iter()).enumerate()
    {
        let deposit_id = deposit.deposit_id();
        if deposit_id == Hash32::ZERO {
            return Err(InboundVerificationError::ZeroDepositCommitment);
        }
        let storage_key = deposit_commitment_storage_key(deposit.nonce);
        verify_storage_value(
            witness.account.storage_root,
            storage_key,
            deposit_id,
            &storage_proof.proof_nodes,
        )
        .map_err(|_| InboundVerificationError::StorageProofRejected(index))?;
        total_usdt_micro = total_usdt_micro
            .checked_add(deposit.usdt_amount_micro)
            .ok_or(InboundVerificationError::AmountOverflow)?;
        deposit_ids.push(deposit_id);
        storage_keys.push(storage_key);
    }

    let next_nonce = prior_state
        .next_mint_nonce
        .checked_add(deposits.len() as u64)
        .ok_or(InboundVerificationError::NonConsecutiveDepositNonce)?;
    Ok(VerifiedDepositBatch {
        execution_state_root: finality.finalized_execution_state_root,
        first_nonce: prior_state.next_mint_nonce,
        next_nonce,
        total_usdt_micro,
        deposit_ids,
        storage_keys,
    })
}

fn validate_transition_shape(
    manifest: &ProtocolManifest,
    prior_state: &MintControllerState,
    finality: &EthereumFinalityWitness,
) -> Result<(), InboundVerificationError> {
    manifest
        .validate()
        .map_err(|_| InboundVerificationError::InvalidManifest)?;
    prior_state
        .validate()
        .map_err(|_| InboundVerificationError::InvalidControllerState)?;
    finality
        .validate()
        .map_err(|_| InboundVerificationError::InvalidFinality)?;
    if prior_state.configuration_hash != manifest.controller_configuration_hash
        || finality.finalized_beacon_slot < prior_state.finalized_beacon_slot
        || finality
            .finalized_beacon_slot
            .saturating_sub(prior_state.finalized_beacon_slot)
            > MAX_ETHEREUM_FINALITY_SLOT_GAP
        || (finality.finalized_beacon_slot == prior_state.finalized_beacon_slot
            && (finality.ethereum_light_client_digest != prior_state.ethereum_light_client_digest
                || finality.finalized_beacon_root != prior_state.finalized_beacon_root
                || finality.finalized_execution_state_root
                    != prior_state.finalized_execution_state_root))
        || (finality.finalized_beacon_slot > prior_state.finalized_beacon_slot
            && finality.ethereum_light_client_digest == prior_state.ethereum_light_client_digest)
    {
        return Err(InboundVerificationError::InvalidFinality);
    }
    Ok(())
}

fn validate_deposit_batch(
    manifest: &ProtocolManifest,
    prior_state: &MintControllerState,
    deposits: &[VaultDeposit],
) -> Result<(), InboundVerificationError> {
    if deposits.is_empty() {
        return Err(InboundVerificationError::EmptyDepositBatch);
    }
    if deposits.len() > MAX_MINT_BATCH_SIZE {
        return Err(InboundVerificationError::TooManyDeposits);
    }
    for (offset, deposit) in deposits.iter().enumerate() {
        deposit
            .validate()
            .map_err(|_| InboundVerificationError::InvalidDeposit)?;
        let expected_nonce = prior_state
            .next_mint_nonce
            .checked_add(offset as u64)
            .ok_or(InboundVerificationError::NonConsecutiveDepositNonce)?;
        if deposit.ethereum_chain_id != manifest.ethereum_chain_id
            || deposit.vault != manifest.vault
            || deposit.usdt != manifest.usdt
            || deposit.nonce != expected_nonce
        {
            return Err(if deposit.nonce != expected_nonce {
                InboundVerificationError::NonConsecutiveDepositNonce
            } else {
                InboundVerificationError::WrongDepositTarget
            });
        }
    }
    MintBatch::from_deposits(deposits).map_err(|_| InboundVerificationError::InvalidDeposit)?;
    Ok(())
}

fn verify_vault_account(
    state_root: Hash32,
    manifest: &ProtocolManifest,
    witness: &VaultAccountWitness,
) -> Result<(), InboundVerificationError> {
    if witness.storage_root == Hash32::ZERO || witness.code_hash == Hash32::ZERO {
        return Err(InboundVerificationError::InvalidVaultAccount);
    }
    if witness.code_hash != manifest.vault_code_hash {
        return Err(InboundVerificationError::VaultCodeHashMismatch);
    }
    let account = TrieAccount {
        nonce: witness.nonce,
        balance: U256::from_be_bytes(witness.balance_be),
        storage_root: to_b256(witness.storage_root),
        code_hash: to_b256(witness.code_hash),
    };
    let account_value = alloy_rlp::encode(account);
    let address_hash = keccak256(manifest.vault.0);
    let address_path = Nibbles::unpack(Bytes::copy_from_slice(address_hash.as_slice()));
    let nodes = alloy_nodes(&witness.proof_nodes);
    proof::verify_proof(
        to_b256(state_root),
        address_path,
        Some(account_value),
        nodes.iter(),
    )
    .map_err(|_| InboundVerificationError::AccountProofRejected)
}

fn verify_storage_value(
    storage_root: Hash32,
    storage_key: Hash32,
    value: Hash32,
    proof_nodes: &[Vec<u8>],
) -> Result<(), ()> {
    let trie_key_hash = keccak256(storage_key.0);
    let trie_path = Nibbles::unpack(Bytes::copy_from_slice(trie_key_hash.as_slice()));
    let expected_value = alloy_rlp::encode(U256::from_be_bytes(value.0));
    let nodes = alloy_nodes(proof_nodes);
    proof::verify_proof(
        to_b256(storage_root),
        trie_path,
        Some(expected_value),
        nodes.iter(),
    )
    .map_err(|_| ())
}

fn alloy_nodes(nodes: &[Vec<u8>]) -> Vec<Bytes> {
    nodes
        .iter()
        .map(|node| Bytes::copy_from_slice(node))
        .collect()
}

const fn to_b256(hash: Hash32) -> B256 {
    B256::new(hash.0)
}

/// Solidity `keccak256(abi.encode(uint64(nonce), uint256(12)))`.
pub fn deposit_commitment_storage_key(nonce: u64) -> Hash32 {
    let mut encoded = [0u8; 64];
    encoded[24..32].copy_from_slice(&nonce.to_be_bytes());
    encoded[56..64].copy_from_slice(&DEPOSIT_COMMITMENT_MAPPING_SLOT.to_be_bytes());
    Hash32(keccak256(encoded).0)
}

impl VaultStorageWitness {
    pub fn validate_limits(&self) -> Result<(), InboundVerificationError> {
        if self.deposits.len() > MAX_MINT_BATCH_SIZE {
            return Err(InboundVerificationError::TooManyDeposits);
        }
        let mut total = validate_nodes(&self.account.proof_nodes)?;
        for storage in &self.deposits {
            total = total
                .checked_add(validate_nodes(&storage.proof_nodes)?)
                .ok_or(InboundVerificationError::ProofLimitsExceeded)?;
            if total > MAX_MPT_WITNESS_BYTES {
                return Err(InboundVerificationError::ProofLimitsExceeded);
            }
        }
        Ok(())
    }
}

fn validate_nodes(nodes: &[Vec<u8>]) -> Result<usize, InboundVerificationError> {
    if nodes.is_empty() || nodes.len() > MAX_MPT_PROOF_NODES {
        return Err(InboundVerificationError::ProofLimitsExceeded);
    }
    let mut total = 0usize;
    for node in nodes {
        if node.is_empty() || node.len() > MAX_MPT_NODE_BYTES {
            return Err(InboundVerificationError::ProofLimitsExceeded);
        }
        total = total
            .checked_add(node.len())
            .ok_or(InboundVerificationError::ProofLimitsExceeded)?;
    }
    Ok(total)
}

impl CanonicalEncode for VaultStorageWitness {
    fn encode_to(&self, out: &mut Vec<u8>) {
        ENCODING_SCHEMA.encode_to(out);
        TAG_VAULT_STORAGE_WITNESS.encode_to(out);
        self.account.nonce.encode_to(out);
        self.account.balance_be.encode_to(out);
        self.account.storage_root.encode_to(out);
        self.account.code_hash.encode_to(out);
        encode_nodes(&self.account.proof_nodes, out);
        let count = u8::try_from(self.deposits.len()).expect("deposit proof count fits u8");
        count.encode_to(out);
        for deposit in &self.deposits {
            encode_nodes(&deposit.proof_nodes, out);
        }
    }
}

impl CanonicalDecode for VaultStorageWitness {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder.u16()? != ENCODING_SCHEMA || decoder.u16()? != TAG_VAULT_STORAGE_WITNESS {
            return Err(DecodeError::InvalidValue("invalid vault witness header"));
        }
        let nonce = decoder.u64()?;
        let balance_be = decoder.fixed()?;
        let storage_root = Hash32::decode_from(decoder)?;
        let code_hash = Hash32::decode_from(decoder)?;
        let mut total = 0usize;
        let account_nodes = decode_nodes(decoder, &mut total)?;
        let count = decoder.u8()? as usize;
        if count > MAX_MINT_BATCH_SIZE {
            return Err(DecodeError::InvalidValue("too many deposit storage proofs"));
        }
        let mut deposits = Vec::with_capacity(count);
        for _ in 0..count {
            deposits.push(DepositStorageProof {
                proof_nodes: decode_nodes(decoder, &mut total)?,
            });
        }
        let witness = Self {
            account: VaultAccountWitness {
                nonce,
                balance_be,
                storage_root,
                code_hash,
                proof_nodes: account_nodes,
            },
            deposits,
        };
        witness
            .validate_limits()
            .map_err(|_| DecodeError::InvalidValue("vault witness exceeds resource bounds"))?;
        Ok(witness)
    }
}

fn encode_nodes(nodes: &[Vec<u8>], out: &mut Vec<u8>) {
    let count = u8::try_from(nodes.len()).expect("MPT proof node count fits u8");
    count.encode_to(out);
    for node in nodes {
        let length = u16::try_from(node.len()).expect("MPT proof node length fits u16");
        length.encode_to(out);
        out.extend_from_slice(node);
    }
}

fn decode_nodes(decoder: &mut Decoder<'_>, total: &mut usize) -> Result<Vec<Vec<u8>>, DecodeError> {
    let count = decoder.u8()? as usize;
    if count == 0 || count > MAX_MPT_PROOF_NODES {
        return Err(DecodeError::InvalidValue("invalid MPT proof node count"));
    }
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let length = decoder.u16()? as usize;
        if length == 0 || length > MAX_MPT_NODE_BYTES {
            return Err(DecodeError::InvalidValue("invalid MPT proof node length"));
        }
        *total = total
            .checked_add(length)
            .ok_or(DecodeError::LengthOverflow)?;
        if *total > MAX_MPT_WITNESS_BYTES {
            return Err(DecodeError::InvalidValue("MPT witness exceeds byte limit"));
        }
        nodes.push(decoder.take(length)?.to_vec());
    }
    Ok(nodes)
}
