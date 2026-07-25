//! Exact Bitcoin block/Merkle binding for parent-chain BMM commitments.
//!
//! This module closes the gap between a caller-provided M7 script and the
//! proof-of-work header which commits to it. It deliberately stops short of
//! claiming full Bitcoin Signet or BIP300 validity; see the public API docs.

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::{
    double_sha256, extract_elements_slot24_m7, verify_successor, BitcoinHeader, BlockHash,
    HeaderChainState, HeaderError, M7Error, PowParameters, BITCOIN_HEADER_LEN,
    BITCOIN_MAX_BLOCK_BASE_BYTES, BITCOIN_MAX_BLOCK_WEIGHT, BITCOIN_MAX_COINBASE_OUTPUTS,
    BITCOIN_MAX_COINBASE_OUTPUT_SCRIPT_BYTES, BITCOIN_MIN_SERIALIZED_TXOUT_BASE_BYTES,
};

mod bip300;
mod checkpoint;
mod multislot;
mod signet;

pub use multislot::{
    ApprovedMultiSlotM6, MultiSlotActivation, MultiSlotBlockEffects, MultiSlotBmmCommitment,
    MultiSlotCtip, MultiSlotDeposit, MultiSlotEffectiveM4, MultiSlotEffectiveM4Action,
    MultiSlotPendingM6id, MultiSlotProposal, MultiSlotReplayError, Slot24UsddContinuity,
};

#[cfg(feature = "enforcer-differential")]
pub use multislot::{
    EnforcerDifferentialActiveSlot, EnforcerDifferentialReplay, EnforcerDifferentialSnapshot,
};

pub use bip300::{
    apply_merkle_bound_elements_slot24_parent_block,
    apply_merkle_bound_elements_slot24_parent_block_owned,
    apply_merkle_bound_elements_slot24_parent_block_owned_with_m6_artifact,
    apply_merkle_bound_elements_slot24_parent_block_with_m6_artifact, ApprovedSlot24AccumulatorM6,
    ApprovedSlot24NativeWithdrawalM6, EffectiveSlot24M4, ElementsSlot24BlockEffects,
    ElementsSlot24BmmEdge, ElementsSlot24ReplayConfig, ElementsSlot24ReplayError,
    ElementsSlot24ReplayState, MintableSlot24Deposit, PendingSlot24M6id, PendingSlot24Proposal,
    Slot24AccumulatorIdentity, Slot24ApprovedRoot, Slot24Ctip,
    ELEMENTS_V1_MAX_LIVE_PROPOSAL_BLOCKS, ELEMENTS_V1_REQUIRED_PROPOSAL_HASH_INTERNAL,
    MAX_PENDING_SLOT24_M6IDS, MAX_PENDING_SLOT24_PROPOSALS, SLOT24_M6_INCLUSION_THRESHOLD,
    SLOT24_M6_MAX_AGE, SLOT24_M6_REQUIRED_SCORE,
};
pub use checkpoint::{
    ProofCheckpointError, ECASH_PROOF_CHECKPOINT_DOMAIN, ECASH_PROOF_CHECKPOINT_MAGIC,
    ECASH_PROOF_CHECKPOINT_SCHEMA,
};
pub use signet::{
    advance_genesis_derived_layer_two_signet_multislot_replay,
    advance_genesis_derived_layer_two_signet_replay,
    advance_layer_two_signet_bmm_confirmation_tracker, initialize_layer_two_signet_genesis_replay,
    initialize_layer_two_signet_genesis_replay_with_manifest_bound_accumulator,
    initialize_layer_two_signet_multislot_genesis_replay,
    initialize_layer_two_signet_multislot_genesis_replay_with_manifest_bound_accumulator,
    verify_and_bind_layer_two_signet_bmm_confirmation_tracker,
    verify_and_track_layer_two_signet_approved_slot24_accumulator_m6,
    verify_and_track_layer_two_signet_multislot_approved_slot24_accumulator_m6,
    verify_layer_two_signet_block_solution, verify_layer_two_signet_contextual_successor,
    verify_layer_two_signet_mtp_successor,
    verify_layer_two_signet_pow_merkle_bound_elements_m7_successor,
    ApprovedSlot24AccumulatorM6FinalityTracker, ContextualSignetBlockTransition,
    ContextualSignetError, FinalizedSlot24AccumulatorRoot,
    GenesisDerivedLayerTwoSignetMultiSlotReplayState, GenesisDerivedLayerTwoSignetReplayState,
    LayerTwoSignetError, MultiSlotApprovedSlot24AccumulatorM6FinalityTracker,
    SignetPowMerkleBoundM7Transition, SLOT24_ACCUMULATOR_M6_FINALITY_CONFIRMATIONS,
};

/// A serialized Bitcoin block can never exceed its maximum weight in bytes.
pub const BITCOIN_MAX_SERIALIZED_BLOCK_BYTES: usize = BITCOIN_MAX_BLOCK_WEIGHT;

/// The smallest structurally valid non-witness transaction is 60 base bytes.
const BITCOIN_MIN_TRANSACTION_BASE_BYTES: usize = 60;
const BITCOIN_MIN_SERIALIZED_TXIN_BASE_BYTES: usize = 41;
const BITCOIN_MAX_TRANSACTIONS: usize =
    BITCOIN_MAX_BLOCK_BASE_BYTES / BITCOIN_MIN_TRANSACTION_BASE_BYTES;
const BITCOIN_MAX_INPUTS_PER_TRANSACTION: usize =
    BITCOIN_MAX_BLOCK_BASE_BYTES / BITCOIN_MIN_SERIALIZED_TXIN_BASE_BYTES;
const MAX_MONEY_SATOSHIS: u64 = 21_000_000 * 100_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockStructureError {
    BlockTooShort,
    SerializedBlockTooLarge,
    UnexpectedEnd,
    NonCanonicalCompactSize,
    LengthOverflow,
    TrailingBytes,
    EmptyBlock,
    TooManyTransactions,
    EmptyInputs,
    TooManyInputs,
    EmptyOutputs,
    TooManyOutputs,
    InvalidWitnessFlags,
    SuperfluousWitness,
    FirstTransactionNotCoinbase,
    MultipleCoinbaseTransactions,
    InvalidCoinbaseScriptSize,
    NullPreviousOutput,
    DuplicateInput,
    OutputValueOutOfRange,
    OutputTotalOutOfRange,
    BlockWeightExceeded,
    MerkleRootMismatch,
    MutatedMerkleTree,
    MissingWitnessCommitment,
    InvalidCoinbaseWitness,
    WitnessCommitmentMismatch,
}

/// A block whose exact serialization has a canonical transaction structure,
/// consensus-bounded weight, one correctly placed coinbase, and a
/// non-mutated transaction Merkle root matching its header.
///
/// This type does not assert header proof of work, Signet authorization,
/// contextual Bitcoin validity, best-chain membership, or BIP300 state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MerkleVerifiedBitcoinBlock {
    pub header: BitcoinHeader,
    pub block_hash: BlockHash,
    pub coinbase_txid: BlockHash,
    pub transaction_count: u32,
    pub stripped_size: u32,
    pub total_size: u32,
    pub weight: u32,
}

/// A slot-24 M7 commitment cryptographically bound through the coinbase txid
/// and non-mutated Merkle tree to a proof-of-work-checked successor header.
///
/// The type name intentionally lists the guarantees it provides. It is not a
/// full Signet, BIP300, or Elements-validity proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowMerkleBoundM7 {
    pub parent_block_hash: BlockHash,
    pub parent_height: u32,
    pub coinbase_txid: BlockHash,
    pub output_index: u32,
    pub committed_child_hash: BlockHash,
    pub transaction_count: u32,
    pub block_weight: u32,
}

impl PowMerkleBoundM7 {
    /// Require the commitment to equal an independently supplied child hash.
    /// This equality does not authorize a USDD redemption.
    pub fn require_validated_child_hash(self, child_hash: BlockHash) -> Result<Self, M7Error> {
        if self.committed_child_hash != child_hash {
            return Err(M7Error::WrongChildHash);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowMerkleBoundM7Transition {
    pub next_parent_state: HeaderChainState,
    pub commitment: PowMerkleBoundM7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParentBlockM7Error {
    Header(HeaderError),
    Block(BlockStructureError),
    Commitment(M7Error),
}

impl From<HeaderError> for ParentBlockM7Error {
    fn from(value: HeaderError) -> Self {
        Self::Header(value)
    }
}

impl From<BlockStructureError> for ParentBlockM7Error {
    fn from(value: BlockStructureError) -> Self {
        Self::Block(value)
    }
}

impl From<M7Error> for ParentBlockM7Error {
    fn from(value: M7Error) -> Self {
        Self::Commitment(value)
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], position: usize) -> Self {
        Self { bytes, position }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BlockStructureError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(BlockStructureError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(BlockStructureError::UnexpectedEnd)?;
        self.position = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, BlockStructureError> {
        Ok(self.take(1)?[0])
    }

    fn peek(&self) -> Result<u8, BlockStructureError> {
        self.bytes
            .get(self.position)
            .copied()
            .ok_or(BlockStructureError::UnexpectedEnd)
    }

    fn compact_size(&mut self) -> Result<usize, BlockStructureError> {
        let prefix = self.byte()?;
        let value = match prefix {
            0x00..=0xfc => u64::from(prefix),
            0xfd => {
                let value =
                    u16::from_le_bytes(self.take(2)?.try_into().expect("fixed compact-size field"));
                if value < 0xfd {
                    return Err(BlockStructureError::NonCanonicalCompactSize);
                }
                u64::from(value)
            }
            0xfe => {
                let value =
                    u32::from_le_bytes(self.take(4)?.try_into().expect("fixed compact-size field"));
                if value <= u32::from(u16::MAX) {
                    return Err(BlockStructureError::NonCanonicalCompactSize);
                }
                u64::from(value)
            }
            0xff => {
                let value =
                    u64::from_le_bytes(self.take(8)?.try_into().expect("fixed compact-size field"));
                if value <= u64::from(u32::MAX) {
                    return Err(BlockStructureError::NonCanonicalCompactSize);
                }
                value
            }
        };
        usize::try_from(value).map_err(|_| BlockStructureError::LengthOverflow)
    }
}

#[derive(Clone)]
struct ParsedOutput<'a> {
    value: [u8; 8],
    script: &'a [u8],
}

#[derive(Clone)]
struct ParsedCoinbase<'a> {
    version: [u8; 4],
    inputs_and_output_count: &'a [u8],
    outputs: Vec<ParsedOutput<'a>>,
    witness: Vec<&'a [u8]>,
    lock_time: [u8; 4],
}

impl ParsedCoinbase<'_> {
    fn serialized_without_witness_with_replaced_script(
        &self,
        replacement_index: usize,
        replacement_script: &[u8],
    ) -> Result<Vec<u8>, BlockStructureError> {
        if replacement_index >= self.outputs.len() {
            return Err(BlockStructureError::LengthOverflow);
        }
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.version);
        serialized.extend_from_slice(self.inputs_and_output_count);
        for (index, output) in self.outputs.iter().enumerate() {
            serialized.extend_from_slice(&output.value);
            let script = if index == replacement_index {
                replacement_script
            } else {
                output.script
            };
            encode_compact_size(script.len(), &mut serialized)?;
            serialized.extend_from_slice(script);
        }
        serialized.extend_from_slice(&self.lock_time);
        Ok(serialized)
    }
}

struct ParsedTransaction<'a> {
    version: [u8; 4],
    txid: BlockHash,
    wtxid: BlockHash,
    /// Exact transaction bytes as committed by the block Merkle tree. For a
    /// SegWit transaction this includes marker, flag, and witness data.
    serialized: &'a [u8],
    stripped_size: usize,
    has_witness: bool,
    is_coinbase: bool,
    coinbase: Option<ParsedCoinbase<'a>>,
    inputs: Vec<[u8; 36]>,
    outputs: Vec<ParsedOutput<'a>>,
    lock_time: [u8; 4],
}

fn encode_compact_size(value: usize, out: &mut Vec<u8>) -> Result<(), BlockStructureError> {
    if value < 0xfd {
        out.push(value as u8);
    } else if value <= usize::from(u16::MAX) {
        out.push(0xfd);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        out.push(0xfe);
        out.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        let value = u64::try_from(value).map_err(|_| BlockStructureError::LengthOverflow)?;
        out.push(0xff);
        out.extend_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

fn parse_transaction<'a>(
    cursor: &mut Cursor<'a>,
) -> Result<ParsedTransaction<'a>, BlockStructureError> {
    let transaction_start = cursor.position;
    let version: [u8; 4] = cursor
        .take(4)?
        .try_into()
        .expect("fixed transaction version");
    let after_version = cursor.position;

    let has_witness_encoding = cursor.peek()? == 0;
    let input_count_start = if has_witness_encoding {
        cursor.byte()?;
        let flags = cursor.byte()?;
        if flags != 1 {
            return Err(BlockStructureError::InvalidWitnessFlags);
        }
        cursor.position
    } else {
        after_version
    };

    let input_count = cursor.compact_size()?;
    if input_count == 0 {
        return Err(BlockStructureError::EmptyInputs);
    }
    if input_count > BITCOIN_MAX_INPUTS_PER_TRANSACTION
        || input_count > cursor.remaining() / BITCOIN_MIN_SERIALIZED_TXIN_BASE_BYTES
    {
        return Err(BlockStructureError::TooManyInputs);
    }

    let mut outpoints = Vec::with_capacity(input_count);
    let mut null_previous_outputs = 0usize;
    let mut sole_input_script_size = 0usize;
    for input_index in 0..input_count {
        let outpoint: [u8; 36] = cursor.take(36)?.try_into().expect("fixed outpoint length");
        let is_null = outpoint[..32].iter().all(|byte| *byte == 0)
            && outpoint[32..] == u32::MAX.to_le_bytes();
        if is_null {
            null_previous_outputs += 1;
        }
        outpoints.push(outpoint);
        let script_size = cursor.compact_size()?;
        if script_size > BITCOIN_MAX_COINBASE_OUTPUT_SCRIPT_BYTES {
            return Err(BlockStructureError::LengthOverflow);
        }
        cursor.take(script_size)?;
        if input_index == 0 {
            sole_input_script_size = script_size;
        }
        cursor.take(4)?;
    }

    let is_coinbase = input_count == 1 && null_previous_outputs == 1;
    if !is_coinbase && null_previous_outputs != 0 {
        return Err(BlockStructureError::NullPreviousOutput);
    }
    if is_coinbase && !(2..=100).contains(&sole_input_script_size) {
        return Err(BlockStructureError::InvalidCoinbaseScriptSize);
    }
    if !is_coinbase {
        outpoints.sort_unstable();
        if outpoints.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BlockStructureError::DuplicateInput);
        }
    }

    let output_count = cursor.compact_size()?;
    let outputs_start = cursor.position;
    if output_count == 0 {
        return Err(BlockStructureError::EmptyOutputs);
    }
    if output_count > BITCOIN_MAX_COINBASE_OUTPUTS
        || output_count > cursor.remaining() / BITCOIN_MIN_SERIALIZED_TXOUT_BASE_BYTES
    {
        return Err(BlockStructureError::TooManyOutputs);
    }
    let mut output_total = 0u64;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let value_bytes: [u8; 8] = cursor.take(8)?.try_into().expect("fixed transaction value");
        let value = i64::from_le_bytes(value_bytes);
        let value = u64::try_from(value).map_err(|_| BlockStructureError::OutputValueOutOfRange)?;
        if value > MAX_MONEY_SATOSHIS {
            return Err(BlockStructureError::OutputValueOutOfRange);
        }
        output_total = output_total
            .checked_add(value)
            .ok_or(BlockStructureError::OutputTotalOutOfRange)?;
        if output_total > MAX_MONEY_SATOSHIS {
            return Err(BlockStructureError::OutputTotalOutOfRange);
        }
        let script_size = cursor.compact_size()?;
        if script_size > BITCOIN_MAX_COINBASE_OUTPUT_SCRIPT_BYTES {
            return Err(BlockStructureError::LengthOverflow);
        }
        let script = cursor.take(script_size)?;
        outputs.push(ParsedOutput {
            value: value_bytes,
            script,
        });
    }
    let outputs_end = cursor.position;

    let mut coinbase_witness = Vec::new();
    if has_witness_encoding {
        let mut has_witness = false;
        for input_index in 0..input_count {
            let item_count = cursor.compact_size()?;
            if item_count > cursor.remaining() {
                return Err(BlockStructureError::LengthOverflow);
            }
            has_witness |= item_count != 0;
            for _ in 0..item_count {
                let item_size = cursor.compact_size()?;
                if item_size > BITCOIN_MAX_SERIALIZED_BLOCK_BYTES {
                    return Err(BlockStructureError::LengthOverflow);
                }
                let item = cursor.take(item_size)?;
                if is_coinbase && input_index == 0 {
                    coinbase_witness.push(item);
                }
            }
        }
        if !has_witness {
            return Err(BlockStructureError::SuperfluousWitness);
        }
    }

    let lock_time_start = cursor.position;
    let lock_time: [u8; 4] = cursor
        .take(4)?
        .try_into()
        .expect("fixed transaction lock time");
    let transaction_end = cursor.position;

    let stripped_size = 4usize
        .checked_add(outputs_end - input_count_start)
        .and_then(|value| value.checked_add(4))
        .ok_or(BlockStructureError::LengthOverflow)?;
    let txid = if has_witness_encoding {
        let mut first = Sha256::new();
        first.update(&cursor.bytes[transaction_start..after_version]);
        first.update(&cursor.bytes[input_count_start..outputs_end]);
        first.update(&cursor.bytes[lock_time_start..transaction_end]);
        let first = first.finalize();
        BlockHash::from_internal_bytes(Sha256::digest(first).into())
    } else {
        BlockHash::from_internal_bytes(double_sha256(
            &cursor.bytes[transaction_start..transaction_end],
        ))
    };
    let wtxid = if has_witness_encoding {
        BlockHash::from_internal_bytes(double_sha256(
            &cursor.bytes[transaction_start..transaction_end],
        ))
    } else {
        txid
    };

    let coinbase = is_coinbase.then(|| ParsedCoinbase {
        version,
        inputs_and_output_count: &cursor.bytes[input_count_start..outputs_start],
        outputs: outputs.clone(),
        witness: coinbase_witness,
        lock_time,
    });

    Ok(ParsedTransaction {
        version,
        txid,
        wtxid,
        serialized: &cursor.bytes[transaction_start..transaction_end],
        stripped_size,
        has_witness: has_witness_encoding,
        is_coinbase,
        coinbase,
        inputs: outpoints,
        outputs,
        lock_time,
    })
}

struct ParsedBlock<'a> {
    metadata: MerkleVerifiedBitcoinBlock,
    coinbase: ParsedCoinbase<'a>,
    txids: Vec<BlockHash>,
    transactions: Vec<ParsedTransaction<'a>>,
}

fn merkle_root_and_mutation(mut hashes: Vec<BlockHash>) -> (BlockHash, bool) {
    debug_assert!(!hashes.is_empty());
    let mut mutated = false;
    while hashes.len() > 1 {
        for pair in hashes.chunks_exact(2) {
            mutated |= pair[0] == pair[1];
        }
        if hashes.len() % 2 != 0 {
            hashes.push(*hashes.last().expect("nonempty Merkle level"));
        }
        let next_len = hashes.len() / 2;
        for index in 0..next_len {
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&hashes[index * 2].to_internal_bytes());
            pair[32..].copy_from_slice(&hashes[index * 2 + 1].to_internal_bytes());
            hashes[index] = BlockHash::from_internal_bytes(double_sha256(&pair));
        }
        hashes.truncate(next_len);
    }
    (hashes[0], mutated)
}

fn witness_commitment_index(outputs: &[ParsedOutput<'_>]) -> Option<usize> {
    outputs
        .iter()
        .enumerate()
        .filter(|(_, output)| {
            output.script.len() >= 38 && output.script[..6] == [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]
        })
        .map(|(index, _)| index)
        .next_back()
}

fn verify_witness_commitment(
    coinbase: &ParsedCoinbase<'_>,
    wtxids: &[BlockHash],
    block_has_witness: bool,
) -> Result<(), BlockStructureError> {
    let commitment_index = witness_commitment_index(&coinbase.outputs);
    if !block_has_witness && commitment_index.is_none() {
        return Ok(());
    }
    let commitment_index = commitment_index.ok_or(BlockStructureError::MissingWitnessCommitment)?;
    if coinbase.witness.len() != 1 || coinbase.witness[0].len() != 32 {
        return Err(BlockStructureError::InvalidCoinbaseWitness);
    }
    let mut leaves = wtxids.to_vec();
    leaves[0] = BlockHash::ZERO;
    let (root, _) = merkle_root_and_mutation(leaves);
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&root.to_internal_bytes());
    preimage[32..].copy_from_slice(coinbase.witness[0]);
    let expected = double_sha256(&preimage);
    let script = coinbase.outputs[commitment_index].script;
    if script[6..38] != expected {
        return Err(BlockStructureError::WitnessCommitmentMismatch);
    }
    Ok(())
}

fn parse_and_verify_block(bytes: &[u8]) -> Result<ParsedBlock<'_>, BlockStructureError> {
    if bytes.len() < BITCOIN_HEADER_LEN + 1 {
        return Err(BlockStructureError::BlockTooShort);
    }
    if bytes.len() > BITCOIN_MAX_SERIALIZED_BLOCK_BYTES {
        return Err(BlockStructureError::SerializedBlockTooLarge);
    }
    let header = BitcoinHeader::decode_exact(&bytes[..BITCOIN_HEADER_LEN])
        .map_err(|_| BlockStructureError::BlockTooShort)?;
    let mut cursor = Cursor::new(bytes, BITCOIN_HEADER_LEN);
    let transaction_count_start = cursor.position;
    let transaction_count = cursor.compact_size()?;
    let transaction_count_size = cursor.position - transaction_count_start;
    if transaction_count == 0 {
        return Err(BlockStructureError::EmptyBlock);
    }
    if transaction_count > BITCOIN_MAX_TRANSACTIONS
        || transaction_count > cursor.remaining() / BITCOIN_MIN_TRANSACTION_BASE_BYTES
    {
        return Err(BlockStructureError::TooManyTransactions);
    }

    let mut txids = Vec::with_capacity(transaction_count);
    let mut wtxids = Vec::with_capacity(transaction_count);
    let mut block_has_witness = false;
    let mut stripped_size = BITCOIN_HEADER_LEN
        .checked_add(transaction_count_size)
        .ok_or(BlockStructureError::LengthOverflow)?;
    let mut coinbase_txid = BlockHash::ZERO;
    let mut coinbase = None;
    let mut transactions = Vec::with_capacity(transaction_count);
    for index in 0..transaction_count {
        let transaction = parse_transaction(&mut cursor)?;
        if index == 0 {
            if !transaction.is_coinbase {
                return Err(BlockStructureError::FirstTransactionNotCoinbase);
            }
            coinbase_txid = transaction.txid;
            coinbase = transaction.coinbase.clone();
        } else if transaction.is_coinbase {
            return Err(BlockStructureError::MultipleCoinbaseTransactions);
        }
        stripped_size = stripped_size
            .checked_add(transaction.stripped_size)
            .ok_or(BlockStructureError::LengthOverflow)?;
        txids.push(transaction.txid);
        wtxids.push(transaction.wtxid);
        block_has_witness |= transaction.has_witness;
        transactions.push(transaction);
    }
    if cursor.position != bytes.len() {
        return Err(BlockStructureError::TrailingBytes);
    }
    let weight = stripped_size
        .checked_mul(3)
        .and_then(|value| value.checked_add(bytes.len()))
        .ok_or(BlockStructureError::LengthOverflow)?;
    if weight > BITCOIN_MAX_BLOCK_WEIGHT {
        return Err(BlockStructureError::BlockWeightExceeded);
    }

    let (merkle_root, mutated) = merkle_root_and_mutation(txids.clone());
    if mutated {
        return Err(BlockStructureError::MutatedMerkleTree);
    }
    if merkle_root != header.merkle_root {
        return Err(BlockStructureError::MerkleRootMismatch);
    }
    let coinbase = coinbase.ok_or(BlockStructureError::FirstTransactionNotCoinbase)?;
    verify_witness_commitment(&coinbase, &wtxids, block_has_witness)?;

    Ok(ParsedBlock {
        metadata: MerkleVerifiedBitcoinBlock {
            header,
            block_hash: header.block_hash(),
            coinbase_txid,
            transaction_count: u32::try_from(transaction_count)
                .map_err(|_| BlockStructureError::LengthOverflow)?,
            stripped_size: u32::try_from(stripped_size)
                .map_err(|_| BlockStructureError::LengthOverflow)?,
            total_size: u32::try_from(bytes.len())
                .map_err(|_| BlockStructureError::LengthOverflow)?,
            weight: u32::try_from(weight).map_err(|_| BlockStructureError::LengthOverflow)?,
        },
        coinbase,
        txids,
        transactions,
    })
}

/// Verify exact transaction serialization, basic context-free transaction
/// invariants, coinbase placement, block weight, and the non-mutated txid
/// Merkle root committed by the header.
pub fn verify_serialized_block_merkle(
    bytes: &[u8],
) -> Result<MerkleVerifiedBitcoinBlock, BlockStructureError> {
    Ok(parse_and_verify_block(bytes)?.metadata)
}

/// Extend a manifest-bound proof-of-work header chain using the header in an
/// exact serialized block, prove the block's transaction Merkle tree, and
/// extract the unique canonical slot-24 M7 from its authenticated coinbase.
///
/// No output scripts, txids, Merkle branches, difficulty bits, chainwork, or
/// successor hash are accepted separately from the serialized block and prior
/// chain state. This M7 primitive is not the redemption boundary: authorization
/// requires the exact M3/M4/M6 withdrawal-voting transition and M6id-to-claim
/// binding described in the crate README.
pub fn verify_pow_merkle_bound_elements_m7_successor(
    prior: &HeaderChainState,
    serialized_block: &[u8],
    params: PowParameters,
) -> Result<PowMerkleBoundM7Transition, ParentBlockM7Error> {
    let parsed = parse_and_verify_block(serialized_block)?;
    let next_parent_state = verify_successor(prior, &parsed.metadata.header.raw(), params)?;
    debug_assert_eq!(next_parent_state.tip.hash, parsed.metadata.block_hash);
    let coinbase_output_scripts = parsed
        .coinbase
        .outputs
        .iter()
        .map(|output| output.script)
        .collect::<Vec<_>>();
    let unbound = extract_elements_slot24_m7(&coinbase_output_scripts)?;
    Ok(PowMerkleBoundM7Transition {
        next_parent_state,
        commitment: PowMerkleBoundM7 {
            parent_block_hash: parsed.metadata.block_hash,
            parent_height: next_parent_state.height,
            coinbase_txid: parsed.metadata.coinbase_txid,
            output_index: unbound.output_index,
            committed_child_hash: unbound.committed_child_hash,
            transaction_count: parsed.metadata.transaction_count,
            block_weight: parsed.metadata.weight,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        decode_and_validate_target, verify_header_pow_against_caller_supplied_bits, Uint256,
    };

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
                    _ => panic!("non-hex test fixture"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    fn genesis_block() -> Vec<u8> {
        hex(concat!(
            "01000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "29ab5f49ffff001d1dac2b7c01",
            "0100000001",
            "0000000000000000000000000000000000000000000000000000000000000000ffffffff",
            "4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73",
            "ffffffff01",
            "00f2052a01000000",
            "43",
            "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
            "00000000"
        ))
    }

    fn easy_params() -> PowParameters {
        PowParameters {
            pow_limit: Uint256::from_limbs_le([
                u64::MAX,
                u64::MAX,
                u64::MAX,
                0x7fff_ffff_ffff_ffff,
            ]),
            target_timespan: 100,
            target_spacing: 10,
            allow_min_difficulty_blocks: false,
            no_retargeting: true,
        }
    }

    fn mine_header(previous: BlockHash, merkle_root: BlockHash, time: u32) -> [u8; 80] {
        let mut raw = [0u8; 80];
        raw[0..4].copy_from_slice(&1i32.to_le_bytes());
        raw[4..36].copy_from_slice(&previous.to_internal_bytes());
        raw[36..68].copy_from_slice(&merkle_root.to_internal_bytes());
        raw[68..72].copy_from_slice(&time.to_le_bytes());
        raw[72..76].copy_from_slice(&0x207f_ffffu32.to_le_bytes());
        let target =
            decode_and_validate_target(0x207f_ffff, easy_params().pow_limit).expect("easy target");
        for nonce in 0..=u32::MAX {
            raw[76..80].copy_from_slice(&nonce.to_le_bytes());
            if BitcoinHeader::decode_exact(&raw)
                .expect("header")
                .block_hash()
                .as_number()
                <= target
            {
                return raw;
            }
        }
        panic!("easy header nonce");
    }

    fn transaction(
        previous: [u8; 32],
        index: u32,
        script_sig: &[u8],
        outputs: &[&[u8]],
    ) -> Vec<u8> {
        assert!(script_sig.len() < 0xfd && outputs.len() < 0xfd);
        let mut tx = Vec::new();
        tx.extend_from_slice(&1i32.to_le_bytes());
        tx.push(1);
        tx.extend_from_slice(&previous);
        tx.extend_from_slice(&index.to_le_bytes());
        tx.push(script_sig.len() as u8);
        tx.extend_from_slice(script_sig);
        tx.extend_from_slice(&u32::MAX.to_le_bytes());
        tx.push(outputs.len() as u8);
        for script in outputs {
            tx.extend_from_slice(&0i64.to_le_bytes());
            tx.push(script.len() as u8);
            tx.extend_from_slice(script);
        }
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx
    }

    fn coinbase_with_m7(child: BlockHash) -> Vec<u8> {
        let mut m7 = Vec::from([0x6a, 0x25, 0xd1, 0x61, 0x73, 0x68, 24]);
        m7.extend_from_slice(&child.to_internal_bytes());
        transaction([0; 32], u32::MAX, &[1, 1], &[&m7])
    }

    fn block_with_transactions(previous: BlockHash, transactions: &[Vec<u8>]) -> Vec<u8> {
        assert!(!transactions.is_empty() && transactions.len() < 0xfd);
        let txids = transactions
            .iter()
            .map(|tx| BlockHash::from_internal_bytes(double_sha256(tx)))
            .collect();
        let (root, _) = merkle_root_and_mutation(txids);
        let header = mine_header(previous, root, 1_700_000_001);
        let mut block = Vec::from(header);
        block.push(transactions.len() as u8);
        for tx in transactions {
            block.extend_from_slice(tx);
        }
        block
    }

    fn prior_state() -> HeaderChainState {
        let header = mine_header(
            BlockHash::ZERO,
            BlockHash::from_internal_bytes([7; 32]),
            1_700_000_000,
        );
        let tip =
            verify_header_pow_against_caller_supplied_bits(&header, 0x207f_ffff, easy_params())
                .expect("easy checkpoint");
        HeaderChainState::from_unverified_checkpoint_requires_manifest_binding(
            10,
            tip,
            tip.work,
            tip.header.time,
        )
        .expect("checkpoint")
    }

    #[test]
    fn bitcoin_genesis_full_block_has_its_header_merkle_root() {
        let verified = verify_serialized_block_merkle(&genesis_block()).expect("genesis block");
        assert_eq!(verified.transaction_count, 1);
        assert_eq!(verified.total_size, 285);
        assert_eq!(verified.stripped_size, 285);
        assert_eq!(verified.weight, 1_140);
        assert_eq!(verified.coinbase_txid, verified.header.merkle_root);
    }

    #[test]
    fn exact_block_binds_slot24_m7_to_pow_successor() {
        let prior = prior_state();
        let child = BlockHash::from_internal_bytes([0x42; 32]);
        let block = block_with_transactions(prior.tip.hash, &[coinbase_with_m7(child)]);
        let transition =
            verify_pow_merkle_bound_elements_m7_successor(&prior, &block, easy_params())
                .expect("bound M7");
        assert_eq!(transition.next_parent_state.height, 11);
        assert_eq!(transition.commitment.committed_child_hash, child);
        assert_eq!(
            transition.commitment.parent_block_hash,
            transition.next_parent_state.tip.hash
        );
        assert_eq!(transition.commitment.output_index, 0);
        assert!(transition
            .commitment
            .require_validated_child_hash(child)
            .is_ok());
        assert_eq!(
            transition
                .commitment
                .require_validated_child_hash(BlockHash::ZERO),
            Err(M7Error::WrongChildHash)
        );
    }

    #[test]
    fn changed_transaction_bytes_break_header_merkle_binding() {
        let prior = prior_state();
        let mut block = block_with_transactions(
            prior.tip.hash,
            &[coinbase_with_m7(BlockHash::from_internal_bytes([3; 32]))],
        );
        let last = block.len() - 1;
        block[last] ^= 1;
        assert_eq!(
            verify_serialized_block_merkle(&block),
            Err(BlockStructureError::MerkleRootMismatch)
        );
    }

    #[test]
    fn duplicate_txid_at_a_merkle_level_is_rejected_as_mutated() {
        let prior = prior_state();
        let coinbase = coinbase_with_m7(BlockHash::from_internal_bytes([4; 32]));
        let ordinary_a = transaction([1; 32], 0, &[], &[&[]]);
        let ordinary_b = transaction([2; 32], 0, &[], &[&[]]);
        let block = block_with_transactions(
            prior.tip.hash,
            &[coinbase, ordinary_a, ordinary_b.clone(), ordinary_b],
        );
        assert_eq!(
            verify_serialized_block_merkle(&block),
            Err(BlockStructureError::MutatedMerkleTree)
        );
    }

    #[test]
    fn noncanonical_counts_trailing_bytes_and_bad_coinbase_fail_closed() {
        let mut genesis = genesis_block();
        genesis.splice(80..81, [0xfd, 1, 0]);
        assert_eq!(
            verify_serialized_block_merkle(&genesis),
            Err(BlockStructureError::NonCanonicalCompactSize)
        );

        let mut trailing = genesis_block();
        trailing.push(0);
        assert_eq!(
            verify_serialized_block_merkle(&trailing),
            Err(BlockStructureError::TrailingBytes)
        );

        let prior = prior_state();
        let non_coinbase = transaction([9; 32], 0, &[], &[&[]]);
        let block = block_with_transactions(prior.tip.hash, &[non_coinbase]);
        assert_eq!(
            verify_serialized_block_merkle(&block),
            Err(BlockStructureError::FirstTransactionNotCoinbase)
        );
    }

    #[test]
    fn witness_transaction_txid_omits_marker_flag_and_witness() {
        let block = genesis_block();
        let tx_start = 81;
        let legacy_tx = block[tx_start..].to_vec();
        let mut transaction = legacy_tx.clone();
        let input_count_offset = 4;
        transaction.splice(input_count_offset..input_count_offset, [0, 1]);
        let locktime_start = transaction.len() - 4;
        transaction.splice(locktime_start..locktime_start, [1, 1, 0xaa]);
        let expected_txid = BlockHash::from_internal_bytes(double_sha256(&legacy_tx));
        let mut cursor = Cursor::new(&transaction, 0);
        let parsed = parse_transaction(&mut cursor).expect("witness transaction");
        assert_eq!(cursor.remaining(), 0);
        assert_eq!(parsed.txid, expected_txid);
        assert_ne!(parsed.wtxid, parsed.txid);
    }
}
