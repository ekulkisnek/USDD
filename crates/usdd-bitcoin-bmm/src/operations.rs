//! Deterministic, keyless operational planning for a slot-24 USDD bundle.
//!
//! This module intentionally does not perform networking.  A caller obtains a
//! snapshot from the genesis-derived BIP300 replay, evaluates it here, and may
//! then submit the returned bytes through any transport.  Transport success is
//! never treated as approval: only the replay snapshot's M4 score and CTIP are
//! authoritative.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use usdd_core::{burn_accumulator_empty, Hash32, OutPoint};

use crate::{
    ActualM6Artifact, Ctip, M6Error, MinerBundleArtifact, BITCOIN_MAX_MONEY_SATS,
    ELEMENTS_DRIVECHAIN_SLOT, SLOT24_M6_INCLUSION_THRESHOLD, SLOT24_M6_MAX_AGE,
};

/// BIP300 M3 message tag used by the pinned enforcer.
pub const M3_PROPOSE_BUNDLE_TAG: [u8; 4] = [0xd4, 0x5a, 0xa9, 0x43];
const OP_RETURN: u8 = 0x6a;
const M3_PAYLOAD_LENGTH: u8 = 4 + 1 + 32;

/// One pending M6 as observed by the fully replayed active Bitcoin branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingM6Observation {
    /// RPC/display-order M6id.
    pub m6id: Hash32,
    pub proposal_height: u32,
    pub score: u16,
}

/// Minimal authenticated state needed to decide the next permissionless
/// operation.  The type does not authenticate itself; production callers must
/// derive it from the genesis-derived all-slot replay, never an RPC assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleOperationalSnapshot {
    /// Parent-chain genesis authenticated by the replay constructor.
    pub bitcoin_genesis: Hash32,
    pub bitcoin_height: u32,
    pub bitcoin_tip: Hash32,
    pub approved_claim_count: u64,
    pub approved_claim_root: Hash32,
    pub ctip: Option<Ctip>,
    /// Chronological enforcer order.  This order determines M4 indexes.
    pub pending_m6ids: Vec<PendingM6Observation>,
}

impl BundleOperationalSnapshot {
    pub fn validate(&self) -> Result<(), BundleOperationError> {
        if self.bitcoin_genesis == Hash32::ZERO
            || self.bitcoin_tip == Hash32::ZERO
            || self.approved_claim_root == Hash32::ZERO
        {
            return Err(BundleOperationError::MalformedSnapshot(
                "zero Bitcoin genesis, tip, or approved root",
            ));
        }
        let empty_root = burn_accumulator_empty(64).expect("fixed burn-tree depth");
        if (self.approved_claim_count == 0) != (self.approved_claim_root == empty_root) {
            return Err(BundleOperationError::MalformedSnapshot(
                "noncanonical empty approved accumulator",
            ));
        }
        if let Some(ctip) = &self.ctip {
            ctip.validate().map_err(BundleOperationError::Bundle)?;
        }
        for (index, pending) in self.pending_m6ids.iter().enumerate() {
            if pending.m6id == Hash32::ZERO || pending.proposal_height > self.bitcoin_height {
                return Err(BundleOperationError::MalformedSnapshot(
                    "invalid pending M6 identity or height",
                ));
            }
            if self.bitcoin_height - pending.proposal_height > u32::from(SLOT24_M6_MAX_AGE) {
                return Err(BundleOperationError::MalformedSnapshot(
                    "expired M6 remains in pending snapshot",
                ));
            }
            if self.pending_m6ids[..index]
                .iter()
                .any(|earlier| earlier.m6id == pending.m6id)
            {
                return Err(BundleOperationError::MalformedSnapshot(
                    "duplicate pending M6 identity",
                ));
            }
        }
        Ok(())
    }
}

/// A deterministic next action.  `SubmitOrRepropose` is deliberately
/// idempotent: if a prior M3 expired or was orphaned, the same canonical
/// blinded bytes are submitted again.  `BroadcastActual` is emitted only after
/// the target score is strictly above the enforcer inclusion threshold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleOperationalAction {
    AlreadyApplied {
        claim_count: u64,
        claim_root: Hash32,
    },
    ReplenishCtip {
        available_sats: u64,
        required_sats: u64,
        deficit_sats: u64,
    },
    SubmitOrRepropose {
        m6id: Hash32,
        m3_script: Vec<u8>,
        blinded_m6_standard: Vec<u8>,
    },
    WaitForApproval {
        m6id: Hash32,
        score: u16,
        age: u32,
        blocks_until_expiry: u32,
        chronological_m4_index: u32,
        competitor_count: u32,
        strongest_competitor_score: u16,
        competition_alarm: bool,
    },
    BroadcastActual {
        m6id: Hash32,
        score: u16,
        chronological_m4_index: u32,
        actual: ActualM6Artifact,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleOperationError {
    Bundle(M6Error),
    MalformedSnapshot(&'static str),
    StaleRoot {
        observed_count: u64,
        observed_root: Hash32,
    },
    WrongParentNetwork {
        bundle_genesis: Hash32,
        replay_genesis: Hash32,
    },
}

impl From<M6Error> for BundleOperationError {
    fn from(value: M6Error) -> Self {
        Self::Bundle(value)
    }
}

impl fmt::Display for BundleOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bundle(error) => error.fmt(f),
            Self::MalformedSnapshot(message) => {
                write!(f, "malformed BIP300 operational snapshot: {message}")
            }
            Self::StaleRoot {
                observed_count,
                observed_root,
            } => write!(
                f,
                "bundle prior root is stale: active approved state is {observed_count}:{observed_root}"
            ),
            Self::WrongParentNetwork {
                bundle_genesis,
                replay_genesis,
            } => write!(
                f,
                "bundle targets Bitcoin genesis {bundle_genesis}, but replay targets {replay_genesis}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BundleOperationError {}

/// Exact minimal M3 coinbase script for the bundle's display-order M6id.
pub fn m3_proposal_script(m6id: Hash32) -> Result<Vec<u8>, BundleOperationError> {
    if m6id == Hash32::ZERO {
        return Err(BundleOperationError::MalformedSnapshot("zero M6id"));
    }
    let mut script = Vec::with_capacity(2 + usize::from(M3_PAYLOAD_LENGTH));
    script.push(OP_RETURN);
    script.push(M3_PAYLOAD_LENGTH);
    script.extend_from_slice(&M3_PROPOSE_BUNDLE_TAG);
    script.push(ELEMENTS_DRIVECHAIN_SLOT);
    // The enforcer's M3 body carries bitcoin::Txid internal bytes.  Public
    // artifacts use RPC/display bytes, so reverse exactly once here.
    script.extend(m6id.as_bytes().iter().rev());
    debug_assert_eq!(script.len(), 39);
    Ok(script)
}

/// Decide the next safe operation using a snapshot derived from exact BIP300
/// replay.  A stale prior root never auto-rebases: claims must be rebuilt from
/// the new approved accumulator state.
pub fn evaluate_bundle_operation(
    bundle: MinerBundleArtifact,
    snapshot: &BundleOperationalSnapshot,
) -> Result<BundleOperationalAction, BundleOperationError> {
    let transition = bundle.validate()?;
    snapshot.validate()?;
    if bundle.bitcoin_genesis != snapshot.bitcoin_genesis {
        return Err(BundleOperationError::WrongParentNetwork {
            bundle_genesis: bundle.bitcoin_genesis,
            replay_genesis: snapshot.bitcoin_genesis,
        });
    }

    if snapshot.approved_claim_count == transition.next_claim_count
        && snapshot.approved_claim_root == transition.next_claim_root
    {
        return Ok(BundleOperationalAction::AlreadyApplied {
            claim_count: transition.next_claim_count,
            claim_root: transition.next_claim_root,
        });
    }
    if snapshot.approved_claim_count != transition.prior_claim_count
        || snapshot.approved_claim_root != transition.prior_claim_root
    {
        return Err(BundleOperationError::StaleRoot {
            observed_count: snapshot.approved_claim_count,
            observed_root: snapshot.approved_claim_root,
        });
    }

    let required_sats = bundle
        .fee_sats
        .checked_add(crate::M6_ROOT_PAYOUT_SATS)
        .filter(|required| *required <= BITCOIN_MAX_MONEY_SATS)
        .ok_or(M6Error::FeeOutOfRange)?;
    let available_sats = snapshot.ctip.as_ref().map_or(0, |ctip| ctip.value_sats);
    if available_sats < required_sats {
        return Ok(BundleOperationalAction::ReplenishCtip {
            available_sats,
            required_sats,
            deficit_sats: required_sats - available_sats,
        });
    }
    let ctip = snapshot
        .ctip
        .clone()
        .ok_or(BundleOperationError::MalformedSnapshot(
            "CTIP disappeared after fuel validation",
        ))?;

    let m6id = bundle.m6id()?;
    let Some((index, target)) = snapshot
        .pending_m6ids
        .iter()
        .enumerate()
        .find(|(_, pending)| pending.m6id == m6id)
    else {
        return Ok(BundleOperationalAction::SubmitOrRepropose {
            m6id,
            m3_script: m3_proposal_script(m6id)?,
            blinded_m6_standard: bundle.blinded_m6()?.standard_bytes(),
        });
    };

    let age = snapshot.bitcoin_height - target.proposal_height;
    let strongest_competitor_score = snapshot
        .pending_m6ids
        .iter()
        .filter(|pending| pending.m6id != m6id)
        .map(|pending| pending.score)
        .max()
        .unwrap_or(0);
    let competitor_count = u32::try_from(snapshot.pending_m6ids.len().saturating_sub(1))
        .map_err(|_| BundleOperationError::MalformedSnapshot("too many pending M6ids"))?;
    let chronological_m4_index = u32::try_from(index)
        .map_err(|_| BundleOperationError::MalformedSnapshot("M4 index exceeds u32"))?;

    if target.score <= SLOT24_M6_INCLUSION_THRESHOLD {
        return Ok(BundleOperationalAction::WaitForApproval {
            m6id,
            score: target.score,
            age,
            blocks_until_expiry: u32::from(SLOT24_M6_MAX_AGE) - age,
            chronological_m4_index,
            competitor_count,
            strongest_competitor_score,
            competition_alarm: strongest_competitor_score >= target.score
                && strongest_competitor_score != 0,
        });
    }

    Ok(BundleOperationalAction::BroadcastActual {
        m6id,
        score: target.score,
        chronological_m4_index,
        actual: ActualM6Artifact::build(bundle, ctip)?,
    })
}

/// Convenience conversion for callers reading the replay's slot-24 CTIP.
pub fn ctip_from_replay(txid_display: Hash32, vout: u32, value_sats: u64) -> Ctip {
    Ctip {
        outpoint: OutPoint {
            txid: txid_display,
            vout,
        },
        value_sats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use usdd_core::burn_accumulator_empty;

    fn hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn bundle() -> MinerBundleArtifact {
        MinerBundleArtifact {
            bitcoin_genesis: hash(1),
            elements_genesis: hash(2),
            usdd_asset: hash(3),
            vault_id: hash(4),
            prior_claim_count: 0,
            prior_claim_root: burn_accumulator_empty(64).unwrap(),
            next_claim_count: 1,
            next_claim_root: hash(5),
            fee_sats: 1_000,
        }
    }

    fn snapshot(bundle: &MinerBundleArtifact) -> BundleOperationalSnapshot {
        BundleOperationalSnapshot {
            bitcoin_genesis: bundle.bitcoin_genesis,
            bitcoin_height: 100,
            bitcoin_tip: hash(9),
            approved_claim_count: bundle.prior_claim_count,
            approved_claim_root: bundle.prior_claim_root,
            ctip: Some(Ctip {
                outpoint: OutPoint {
                    txid: hash(8),
                    vout: 0,
                },
                value_sats: 10_000,
            }),
            pending_m6ids: Vec::new(),
        }
    }

    #[test]
    fn m3_is_exact_minimal_enforcer_encoding() {
        let id = Hash32(core::array::from_fn(|index| index as u8));
        let script = m3_proposal_script(id).unwrap();
        assert_eq!(&script[..7], &[0x6a, 0x25, 0xd4, 0x5a, 0xa9, 0x43, 24]);
        assert_eq!(
            &script[7..],
            id.as_bytes().iter().rev().copied().collect::<Vec<_>>()
        );
        assert_eq!(script.len(), 39);
    }

    #[test]
    fn lifecycle_is_fuel_first_reproposal_vote_then_exact_actual() {
        let bundle = bundle();
        let mut state = snapshot(&bundle);
        state.ctip.as_mut().unwrap().value_sats = 1_000;
        assert_eq!(
            evaluate_bundle_operation(bundle.clone(), &state).unwrap(),
            BundleOperationalAction::ReplenishCtip {
                available_sats: 1_000,
                required_sats: 1_001,
                deficit_sats: 1,
            }
        );

        state.ctip.as_mut().unwrap().value_sats = 10_000;
        let m6id = bundle.m6id().unwrap();
        let submit = evaluate_bundle_operation(bundle.clone(), &state).unwrap();
        assert!(matches!(
            submit,
            BundleOperationalAction::SubmitOrRepropose { m6id: id, .. } if id == m6id
        ));

        state.pending_m6ids = vec![
            PendingM6Observation {
                m6id: hash(7),
                proposal_height: 98,
                score: 3,
            },
            PendingM6Observation {
                m6id,
                proposal_height: 99,
                score: SLOT24_M6_INCLUSION_THRESHOLD,
            },
        ];
        assert!(matches!(
            evaluate_bundle_operation(bundle.clone(), &state).unwrap(),
            BundleOperationalAction::WaitForApproval {
                age: 1,
                chronological_m4_index: 1,
                strongest_competitor_score: 3,
                competition_alarm: false,
                ..
            }
        ));

        state.pending_m6ids[1].score = SLOT24_M6_INCLUSION_THRESHOLD + 1;
        let action = evaluate_bundle_operation(bundle, &state).unwrap();
        let BundleOperationalAction::BroadcastActual { actual, .. } = action else {
            panic!("approved bundle did not become broadcastable")
        };
        let actual_bytes = actual.transaction_bytes().unwrap();
        actual.verify_transaction(&actual_bytes).unwrap();

        // This regression is intentionally redundant with the canonical M6
        // codec test: the current upstream block producer once recorded
        // `output.len() - 1` as the successor.  A two-output USDD actual M6
        // always has its treasury/CTIP at vout 0 and its one-satoshi root
        // commitment at vout 1.
        let output_count_offset = 4 + 1 + 32 + 4 + 1 + 4;
        assert_eq!(actual_bytes[output_count_offset], 2);
        assert_eq!(actual.successor_ctip().unwrap().outpoint.vout, 0);
    }

    #[test]
    fn stale_roots_expiry_duplicates_and_applied_state_fail_closed() {
        let bundle = bundle();
        let mut state = snapshot(&bundle);
        state.approved_claim_count = 2;
        state.approved_claim_root = hash(6);
        assert!(matches!(
            evaluate_bundle_operation(bundle.clone(), &state),
            Err(BundleOperationError::StaleRoot { .. })
        ));

        state.approved_claim_count = bundle.next_claim_count;
        state.approved_claim_root = bundle.next_claim_root;
        assert!(matches!(
            evaluate_bundle_operation(bundle.clone(), &state).unwrap(),
            BundleOperationalAction::AlreadyApplied { .. }
        ));

        state.approved_claim_count = bundle.prior_claim_count;
        state.approved_claim_root = bundle.prior_claim_root;
        let m6id = bundle.m6id().unwrap();
        state.pending_m6ids = vec![PendingM6Observation {
            m6id,
            proposal_height: 89,
            score: 1,
        }];
        assert!(matches!(
            evaluate_bundle_operation(bundle.clone(), &state),
            Err(BundleOperationError::MalformedSnapshot(_))
        ));

        state.pending_m6ids = vec![
            PendingM6Observation {
                m6id,
                proposal_height: 100,
                score: 1,
            },
            PendingM6Observation {
                m6id,
                proposal_height: 100,
                score: 1,
            },
        ];
        assert!(matches!(
            evaluate_bundle_operation(bundle.clone(), &state),
            Err(BundleOperationError::MalformedSnapshot(_))
        ));

        state.pending_m6ids.clear();
        state.bitcoin_genesis = hash(42);
        assert!(matches!(
            evaluate_bundle_operation(bundle, &state),
            Err(BundleOperationError::WrongParentNetwork { .. })
        ));
    }
}
