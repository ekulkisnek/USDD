use alloc::vec::Vec;
use core::fmt;

use crate::{
    domain_hash,
    encoding::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder},
    hash::{Domain, Hash32},
};

pub fn merkle_leaf(data: &[u8]) -> Hash32 {
    domain_hash(Domain::MerkleLeaf, data)
}

pub fn empty_merkle_root() -> Hash32 {
    domain_hash(Domain::MerkleEmptyLeaf, &[])
}

pub fn merkle_node(left: Hash32, right: Hash32) -> Hash32 {
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(left.as_bytes());
    payload[32..].copy_from_slice(right.as_bytes());
    domain_hash(Domain::MerkleNode, &payload)
}

/// Root of an ordered binary tree. An odd final node is paired with itself.
pub fn merkle_root(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return empty_merkle_root();
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = *pair.get(1).unwrap_or(&left);
            next.push(merkle_node(left, right));
        }
        level = next;
    }
    level[0]
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub leaf_count: u64,
    /// Leaf-to-root sibling order.
    pub siblings: Vec<Hash32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerkleError {
    EmptyTree,
    IndexOutOfRange,
    MalformedProof,
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTree => f.write_str("cannot prove an empty tree"),
            Self::IndexOutOfRange => f.write_str("Merkle leaf index out of range"),
            Self::MalformedProof => f.write_str("malformed Merkle proof"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MerkleError {}

pub fn merkle_proof(leaves: &[Hash32], index: usize) -> Result<MerkleProof, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyTree);
    }
    if index >= leaves.len() {
        return Err(MerkleError::IndexOutOfRange);
    }
    let mut level = leaves.to_vec();
    let mut position = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling_position = if position % 2 == 0 {
            (position + 1).min(level.len() - 1)
        } else {
            position - 1
        };
        siblings.push(level[sibling_position]);

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = *pair.get(1).unwrap_or(&left);
            next.push(merkle_node(left, right));
        }
        position /= 2;
        level = next;
    }
    Ok(MerkleProof {
        leaf_index: index as u64,
        leaf_count: leaves.len() as u64,
        siblings,
    })
}

impl MerkleProof {
    pub fn verify(&self, leaf: Hash32, expected_root: Hash32) -> Result<bool, MerkleError> {
        if self.leaf_count == 0 || self.leaf_index >= self.leaf_count {
            return Err(MerkleError::MalformedProof);
        }
        let expected_depth = if self.leaf_count <= 1 {
            0
        } else {
            (u64::BITS - (self.leaf_count - 1).leading_zeros()) as usize
        };
        if self.siblings.len() != expected_depth {
            return Err(MerkleError::MalformedProof);
        }
        let mut hash = leaf;
        let mut index = self.leaf_index;
        for sibling in &self.siblings {
            hash = if index % 2 == 0 {
                merkle_node(hash, *sibling)
            } else {
                merkle_node(*sibling, hash)
            };
            index /= 2;
        }
        Ok(hash == expected_root)
    }
}

impl CanonicalEncode for MerkleProof {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.leaf_index.encode_to(out);
        self.leaf_count.encode_to(out);
        let count = u32::try_from(self.siblings.len()).expect("proof depth exceeds u32");
        count.encode_to(out);
        for sibling in &self.siblings {
            sibling.encode_to(out);
        }
    }
}

impl CanonicalDecode for MerkleProof {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let leaf_index = decoder.u64()?;
        let leaf_count = decoder.u64()?;
        let sibling_count = decoder.u32()? as usize;
        if sibling_count > 64 {
            return Err(DecodeError::InvalidLength {
                expected: 64,
                actual: sibling_count,
            });
        }
        let mut siblings = Vec::with_capacity(sibling_count);
        for _ in 0..sibling_count {
            siblings.push(Hash32::decode_from(decoder)?);
        }
        Ok(Self {
            leaf_index,
            leaf_count,
            siblings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_leaf_proves_for_odd_tree() {
        let leaves: Vec<_> = (0u8..7).map(|value| merkle_leaf(&[value])).collect();
        let root = merkle_root(&leaves);
        for (index, leaf) in leaves.iter().enumerate() {
            let proof = merkle_proof(&leaves, index).unwrap();
            assert!(proof.verify(*leaf, root).unwrap());
            assert_eq!(MerkleProof::decode_exact(&proof.encode()).unwrap(), proof);
        }
    }

    #[test]
    fn proof_rejects_changed_leaf_and_truncated_path() {
        let leaves: Vec<_> = (0u8..3).map(|value| merkle_leaf(&[value])).collect();
        let root = merkle_root(&leaves);
        let mut proof = merkle_proof(&leaves, 1).unwrap();
        assert!(!proof.verify(merkle_leaf(b"wrong"), root).unwrap());
        proof.siblings.pop();
        assert_eq!(
            proof.verify(leaves[1], root),
            Err(MerkleError::MalformedProof)
        );
    }
}
