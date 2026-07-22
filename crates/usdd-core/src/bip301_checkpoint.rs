//! Exact cross-language codec for the Elements consensus-derived BIP301 `h*`.
//!
//! The resulting 32 bytes are opaque to BIP301. Elements consensus gives them
//! meaning by deriving them from the normal candidate block hash and the
//! withdrawal-accumulator transition. Parent-chain M7/M8 handling remains the
//! existing BIP301 codec and is intentionally not reimplemented here.

use alloc::vec::Vec;
use core::fmt;

use crate::{hash_bytes, Hash32, DRIVECHAIN_SLOT};

/// Raw ASCII bytes written to SHA-256 without a NUL or length prefix.
pub const BIP301_CHECKPOINT_DOMAIN: &[u8] = b"Elements/USDD/BIP301-checkpoint/v1";
pub const BIP301_CHECKPOINT_VERSION: u32 = 1;
pub const BIP301_CHECKPOINT_PREIMAGE_LENGTH: usize = 183;

/// The exact transition consumed by Elements consensus and the Ethereum relay.
///
/// `elements_genesis` and `candidate_block_hash` are the 32 display-order bytes
/// returned by the node. Roots are raw accumulator digest bytes. No field is
/// reversed by this codec. All integers are unsigned big-endian.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bip301CheckpointTransition {
    pub elements_genesis: Hash32,
    pub candidate_block_hash: Hash32,
    pub prior_count: u64,
    pub prior_root: Hash32,
    pub next_count: u64,
    pub next_root: Hash32,
}

impl Bip301CheckpointTransition {
    pub fn validate(&self) -> Result<(), Bip301CheckpointError> {
        if self.elements_genesis == Hash32::ZERO {
            return Err(Bip301CheckpointError::ZeroField("Elements genesis"));
        }
        if self.candidate_block_hash == Hash32::ZERO {
            return Err(Bip301CheckpointError::ZeroField(
                "candidate Elements block hash",
            ));
        }
        if self.prior_root == Hash32::ZERO {
            return Err(Bip301CheckpointError::ZeroField("prior accumulator root"));
        }
        if self.next_root == Hash32::ZERO {
            return Err(Bip301CheckpointError::ZeroField("next accumulator root"));
        }

        let count_unchanged = self.next_count == self.prior_count;
        let root_unchanged = self.next_root == self.prior_root;
        if count_unchanged != root_unchanged
            || (!count_unchanged && self.next_count < self.prior_count)
        {
            return Err(Bip301CheckpointError::InvalidAccumulatorTransition);
        }
        Ok(())
    }

    /// Exact 183-byte Elements consensus preimage.
    pub fn preimage(&self) -> Result<Vec<u8>, Bip301CheckpointError> {
        self.validate()?;
        let mut out = Vec::with_capacity(BIP301_CHECKPOINT_PREIMAGE_LENGTH);
        out.extend_from_slice(BIP301_CHECKPOINT_DOMAIN);
        out.extend_from_slice(&BIP301_CHECKPOINT_VERSION.to_be_bytes());
        out.extend_from_slice(self.elements_genesis.as_bytes());
        out.push(DRIVECHAIN_SLOT);
        out.extend_from_slice(self.candidate_block_hash.as_bytes());
        out.extend_from_slice(&self.prior_count.to_be_bytes());
        out.extend_from_slice(self.prior_root.as_bytes());
        out.extend_from_slice(&self.next_count.to_be_bytes());
        out.extend_from_slice(self.next_root.as_bytes());
        debug_assert_eq!(out.len(), BIP301_CHECKPOINT_PREIMAGE_LENGTH);
        Ok(out)
    }

    /// The opaque BIP301 critical hash: one SHA-256 of [`Self::preimage`].
    pub fn critical_hash(&self) -> Result<Hash32, Bip301CheckpointError> {
        Ok(hash_bytes(&self.preimage()?))
    }

    /// Strictly decode an exact consensus preimage. This is useful for audit
    /// tooling and cross-language differential tests; consensus normally
    /// constructs the preimage from typed fields.
    pub fn decode_preimage(bytes: &[u8]) -> Result<Self, Bip301CheckpointError> {
        if bytes.len() != BIP301_CHECKPOINT_PREIMAGE_LENGTH {
            return Err(Bip301CheckpointError::WrongPreimageLength(bytes.len()));
        }
        let domain_end = BIP301_CHECKPOINT_DOMAIN.len();
        if &bytes[..domain_end] != BIP301_CHECKPOINT_DOMAIN {
            return Err(Bip301CheckpointError::WrongDomain);
        }
        let mut cursor = domain_end;
        let version = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().expect("fixed"));
        cursor += 4;
        if version != BIP301_CHECKPOINT_VERSION {
            return Err(Bip301CheckpointError::UnsupportedVersion(version));
        }
        let elements_genesis = take_hash(bytes, &mut cursor);
        let slot = bytes[cursor];
        cursor += 1;
        if slot != DRIVECHAIN_SLOT {
            return Err(Bip301CheckpointError::WrongSlot(slot));
        }
        let candidate_block_hash = take_hash(bytes, &mut cursor);
        let prior_count = take_u64(bytes, &mut cursor);
        let prior_root = take_hash(bytes, &mut cursor);
        let next_count = take_u64(bytes, &mut cursor);
        let next_root = take_hash(bytes, &mut cursor);
        debug_assert_eq!(cursor, bytes.len());
        let transition = Self {
            elements_genesis,
            candidate_block_hash,
            prior_count,
            prior_root,
            next_count,
            next_root,
        };
        transition.validate()?;
        Ok(transition)
    }
}

fn take_hash(bytes: &[u8], cursor: &mut usize) -> Hash32 {
    let value = Hash32::new(
        bytes[*cursor..*cursor + 32]
            .try_into()
            .expect("fixed preimage"),
    );
    *cursor += 32;
    value
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> u64 {
    let value = u64::from_be_bytes(
        bytes[*cursor..*cursor + 8]
            .try_into()
            .expect("fixed preimage"),
    );
    *cursor += 8;
    value
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Bip301CheckpointError {
    WrongPreimageLength(usize),
    WrongDomain,
    UnsupportedVersion(u32),
    WrongSlot(u8),
    ZeroField(&'static str),
    InvalidAccumulatorTransition,
}

impl fmt::Display for Bip301CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPreimageLength(actual) => {
                write!(
                    f,
                    "BIP301 critical-hash preimage must be 183 bytes, got {actual}"
                )
            }
            Self::WrongDomain => f.write_str("wrong BIP301 checkpoint domain"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported BIP301 checkpoint version {version}")
            }
            Self::WrongSlot(slot) => write!(f, "wrong BIP301 Drivechain slot {slot}"),
            Self::ZeroField(name) => write!(f, "BIP301 checkpoint {name} is zero"),
            Self::InvalidAccumulatorTransition => {
                f.write_str("invalid BIP301 accumulator transition")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bip301CheckpointError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(value: &str) -> Hash32 {
        value.parse().unwrap()
    }

    fn cxx_vector() -> Bip301CheckpointTransition {
        Bip301CheckpointTransition {
            elements_genesis: h("303ae9429146a90dcb032311c7953578589ff443d3cfc8b56259080567524b1f"),
            candidate_block_hash: h(
                "f86aedd06a22c86b5883df2f3cae7a5c5389f135e378dfbedd6d39922e5e1ab2",
            ),
            prior_count: 0,
            prior_root: h("c13fcc5e95b202155d131894da01dff87c8ac722937c76415daab46e53ed40db"),
            next_count: 2,
            next_root: h("84f03c9c3cc5aff236b244a7e2008bd7a0d3809d3eac40891569c476e0e9567c"),
        }
    }

    #[test]
    fn exact_elements_cpp_consensus_vector() {
        let transition = cxx_vector();
        let preimage = transition.preimage().unwrap();
        assert_eq!(preimage.len(), BIP301_CHECKPOINT_PREIMAGE_LENGTH);
        assert_eq!(
            transition.critical_hash().unwrap().to_string(),
            "4cdba9e60c8109e4688b671a74411c5523224bdd4c1a6a76f60b4339a1428261"
        );
        assert_eq!(
            Bip301CheckpointTransition::decode_preimage(&preimage).unwrap(),
            transition
        );
    }

    #[test]
    fn actual_candidate_block_hash_is_a_variable_input() {
        let first = cxx_vector();
        let second = Bip301CheckpointTransition {
            candidate_block_hash: h(
                "f86aedd06a22c86b5883df2f3cae7a5c5389f135e378dfbedd6d39922e5e1ab3",
            ),
            ..first
        };
        assert_ne!(
            first.critical_hash().unwrap(),
            second.critical_hash().unwrap()
        );
    }

    #[test]
    fn malformed_transition_and_preimage_fail_closed() {
        let transition = cxx_vector();
        let mut count_only = transition;
        count_only.next_root = count_only.prior_root;
        assert_eq!(
            count_only.validate(),
            Err(Bip301CheckpointError::InvalidAccumulatorTransition)
        );
        let mut root_only = transition;
        root_only.next_count = root_only.prior_count;
        assert_eq!(
            root_only.validate(),
            Err(Bip301CheckpointError::InvalidAccumulatorTransition)
        );

        let canonical = transition.preimage().unwrap();
        for index in [
            0usize,
            BIP301_CHECKPOINT_DOMAIN.len(),
            BIP301_CHECKPOINT_DOMAIN.len() + 4 + 32,
        ] {
            let mut malformed = canonical.clone();
            malformed[index] ^= 1;
            assert!(Bip301CheckpointTransition::decode_preimage(&malformed).is_err());
        }
        assert!(Bip301CheckpointTransition::decode_preimage(&canonical[..182]).is_err());
    }
}
