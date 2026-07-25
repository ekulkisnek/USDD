use alloc::vec::Vec;

use usdd_core::{hash_bytes, CanonicalEncode, Hash32};

use crate::{ApprovalEvent, ProofCodecError};

pub const APPROVAL_TREE_DEPTH: usize = 64;
const APPROVAL_EMPTY_DOMAIN: &[u8] = b"USDD_ECASH_APPROVAL_EMPTY_V1";
const APPROVAL_LEAF_DOMAIN: &[u8] = b"USDD_ECASH_APPROVAL_LEAF_V1";
const APPROVAL_NODE_DOMAIN: &[u8] = b"USDD_ECASH_APPROVAL_NODE_V1";

pub fn approval_event_leaf(event: &ApprovalEvent) -> Hash32 {
    let encoded = event.encode();
    let mut preimage = Vec::with_capacity(APPROVAL_LEAF_DOMAIN.len() + encoded.len());
    preimage.extend_from_slice(APPROVAL_LEAF_DOMAIN);
    preimage.extend_from_slice(&encoded);
    hash_bytes(&preimage)
}

pub fn approval_node(left: Hash32, right: Hash32) -> Hash32 {
    let mut preimage = Vec::with_capacity(APPROVAL_NODE_DOMAIN.len() + 64);
    preimage.extend_from_slice(APPROVAL_NODE_DOMAIN);
    preimage.extend_from_slice(left.as_bytes());
    preimage.extend_from_slice(right.as_bytes());
    hash_bytes(&preimage)
}

fn empty_hashes() -> [Hash32; APPROVAL_TREE_DEPTH + 1] {
    let mut hashes = [Hash32::ZERO; APPROVAL_TREE_DEPTH + 1];
    hashes[0] = hash_bytes(APPROVAL_EMPTY_DOMAIN);
    for level in 0..APPROVAL_TREE_DEPTH {
        hashes[level + 1] = approval_node(hashes[level], hashes[level]);
    }
    hashes
}

pub fn empty_approval_root() -> Hash32 {
    empty_hashes()[APPROVAL_TREE_DEPTH]
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalAccumulator {
    pub count: u64,
    pub root: Hash32,
    pub frontier: [Hash32; APPROVAL_TREE_DEPTH],
}

impl ApprovalAccumulator {
    pub fn empty() -> Self {
        Self {
            count: 0,
            root: empty_approval_root(),
            frontier: [Hash32::ZERO; APPROVAL_TREE_DEPTH],
        }
    }

    pub fn validate(&self) -> Result<(), ProofCodecError> {
        if self.root != self.recompute_root() {
            return Err(ProofCodecError::InvalidAccumulator);
        }
        for level in 0..APPROVAL_TREE_DEPTH {
            let occupied = ((self.count >> level) & 1) == 1;
            if occupied != (self.frontier[level] != Hash32::ZERO) {
                return Err(ProofCodecError::InvalidAccumulator);
            }
        }
        Ok(())
    }

    pub fn append(&mut self, leaf: Hash32) -> Result<u64, ProofCodecError> {
        if leaf == Hash32::ZERO || self.count == u64::MAX {
            return Err(ProofCodecError::InvalidAccumulator);
        }
        let index = self.count;
        let mut node = leaf;
        let mut occupied = self.count;
        for level in 0..APPROVAL_TREE_DEPTH {
            if occupied & 1 == 0 {
                self.frontier[level] = node;
                break;
            }
            let left = self.frontier[level];
            if left == Hash32::ZERO {
                return Err(ProofCodecError::InvalidAccumulator);
            }
            self.frontier[level] = Hash32::ZERO;
            node = approval_node(left, node);
            occupied >>= 1;
        }
        self.count += 1;
        self.root = self.recompute_root();
        Ok(index)
    }

    fn recompute_root(&self) -> Hash32 {
        let empty = empty_hashes();
        let mut node = empty[0];
        for (level, empty_at_level) in empty.iter().enumerate().take(APPROVAL_TREE_DEPTH) {
            node = if ((self.count >> level) & 1) == 1 {
                approval_node(self.frontier[level], node)
            } else {
                approval_node(node, *empty_at_level)
            };
        }
        node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_only_root_is_bounded_and_deterministic() {
        let mut first = ApprovalAccumulator::empty();
        let initial = first.root;
        for byte in 1..=8 {
            assert_eq!(
                first.append(Hash32([byte; 32])).unwrap(),
                u64::from(byte - 1)
            );
            first.validate().unwrap();
        }
        let mut second = ApprovalAccumulator::empty();
        for byte in 1..=8 {
            second.append(Hash32([byte; 32])).unwrap();
        }
        assert_ne!(first.root, initial);
        assert_eq!(first, second);
    }
}
