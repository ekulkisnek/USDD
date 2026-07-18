use alloc::vec::Vec;
use core::fmt;

use crate::{hash_bytes, CanonicalDecode, CanonicalEncode, DecodeError, Decoder, Hash32};

pub const BURN_ACCUMULATOR_DEPTH: usize = 64;

/// EMPTY[0] = SHA256(0x00); EMPTY[h+1] = SHA256(0x01 || EMPTY[h] || EMPTY[h]).
pub fn burn_accumulator_empty(height: usize) -> Result<Hash32, BurnAccumulatorError> {
    if height > BURN_ACCUMULATOR_DEPTH {
        return Err(BurnAccumulatorError::WrongDepth(height));
    }
    let mut value = hash_bytes(&[0]);
    for _ in 0..height {
        value = burn_accumulator_node(value, value);
    }
    Ok(value)
}

pub fn burn_accumulator_node(left: Hash32, right: Hash32) -> Hash32 {
    let mut preimage = [0u8; 65];
    preimage[0] = 1;
    preimage[1..33].copy_from_slice(left.as_bytes());
    preimage[33..].copy_from_slice(right.as_bytes());
    hash_bytes(&preimage)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BurnProof {
    /// Bottom-up siblings. The caller supplies the separate `uint64` index,
    /// exactly like the Solidity `bytes32[64]` ABI.
    pub siblings: [Hash32; BURN_ACCUMULATOR_DEPTH],
}

impl BurnProof {
    pub fn compute_root(&self, leaf: Hash32, index: u64) -> Hash32 {
        let mut node = leaf;
        for (level, sibling) in self.siblings.iter().enumerate() {
            node = if ((index >> level) & 1) == 0 {
                burn_accumulator_node(node, *sibling)
            } else {
                burn_accumulator_node(*sibling, node)
            };
        }
        node
    }

    pub fn verify(&self, root: Hash32, leaf: Hash32, index: u64) -> bool {
        self.compute_root(leaf, index) == root
    }
}

impl CanonicalEncode for BurnProof {
    fn encode_to(&self, out: &mut Vec<u8>) {
        for sibling in self.siblings {
            sibling.encode_to(out);
        }
    }
}

impl CanonicalDecode for BurnProof {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let mut siblings = [Hash32::ZERO; BURN_ACCUMULATOR_DEPTH];
        for sibling in &mut siblings {
            *sibling = Hash32::decode_from(decoder)?;
        }
        Ok(Self { siblings })
    }
}

/// Deterministic fixed-depth tree whose occupied leaves are exactly the
/// contiguous prefix `[0, burn_count)`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BurnAccumulator {
    leaves: Vec<Hash32>,
}

impl BurnAccumulator {
    pub const fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn from_leaves(leaves: Vec<Hash32>) -> Result<Self, BurnAccumulatorError> {
        if u64::try_from(leaves.len()).is_err() {
            return Err(BurnAccumulatorError::TooManyLeaves);
        }
        Ok(Self { leaves })
    }

    pub fn burn_count(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn append(&mut self, leaf: Hash32) -> Result<u64, BurnAccumulatorError> {
        let index =
            u64::try_from(self.leaves.len()).map_err(|_| BurnAccumulatorError::TooManyLeaves)?;
        self.leaves.push(leaf);
        Ok(index)
    }

    pub fn root(&self) -> Hash32 {
        root_for_leaves(&self.leaves)
    }

    pub fn proof(&self, index: u64) -> Result<BurnProof, BurnAccumulatorError> {
        let index_usize =
            usize::try_from(index).map_err(|_| BurnAccumulatorError::IndexOutOfRange)?;
        if index_usize >= self.leaves.len() {
            return Err(BurnAccumulatorError::IndexOutOfRange);
        }
        let mut layer = self.leaves.clone();
        let mut position = index_usize;
        let mut siblings = [Hash32::ZERO; BURN_ACCUMULATOR_DEPTH];
        for (height, sibling) in siblings.iter_mut().enumerate() {
            let sibling_position = position ^ 1;
            *sibling = if sibling_position < layer.len() {
                layer[sibling_position]
            } else {
                burn_accumulator_empty(height)?
            };
            if layer.len() > 1 {
                let mut next = Vec::with_capacity(layer.len().div_ceil(2));
                for pair in layer.chunks(2) {
                    let right = pair
                        .get(1)
                        .copied()
                        .unwrap_or(burn_accumulator_empty(height)?);
                    next.push(burn_accumulator_node(pair[0], right));
                }
                layer = next;
            } else {
                layer[0] = burn_accumulator_node(layer[0], burn_accumulator_empty(height)?);
            }
            position /= 2;
        }
        Ok(BurnProof { siblings })
    }
}

fn root_for_leaves(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return burn_accumulator_empty(BURN_ACCUMULATOR_DEPTH).expect("fixed depth");
    }
    let mut layer = leaves.to_vec();
    for height in 0..BURN_ACCUMULATOR_DEPTH {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let right = pair
                .get(1)
                .copied()
                .unwrap_or_else(|| burn_accumulator_empty(height).expect("fixed depth"));
            next.push(burn_accumulator_node(pair[0], right));
        }
        layer = next;
    }
    debug_assert_eq!(layer.len(), 1);
    layer[0]
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BurnAccumulatorError {
    WrongDepth(usize),
    TooManyLeaves,
    IndexOutOfRange,
}

impl fmt::Display for BurnAccumulatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongDepth(value) => write!(f, "burn tree depth {value} exceeds 64"),
            Self::TooManyLeaves => f.write_str("burn accumulator exceeds uint64 indices"),
            Self::IndexOutOfRange => f.write_str("burn index is outside finalized prefix"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BurnAccumulatorError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_prefix_leaf_has_solidity_compatible_proof() {
        let mut tree = BurnAccumulator::new();
        for value in 1u8..=5 {
            tree.append(hash_bytes(&[0, value])).unwrap();
        }
        let root = tree.root();
        for (index, leaf) in tree.leaves.iter().enumerate() {
            assert!(tree
                .proof(index as u64)
                .unwrap()
                .verify(root, *leaf, index as u64));
        }
    }

    #[test]
    fn proof_decoder_rejects_63_and_65_siblings() {
        let short = vec![0u8; 63 * 32];
        assert!(BurnProof::decode_exact(&short).is_err());
        let long = vec![0u8; 65 * 32];
        assert!(BurnProof::decode_exact(&long).is_err());
    }
}
