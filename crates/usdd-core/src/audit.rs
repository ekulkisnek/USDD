use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt;

use crate::{usdd_base_to_usdt_micro, EthAddress, Hash32, USDD_UNITS_PER_USDT_MICRO};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditedDeposit {
    pub nonce: u64,
    pub deposit_id: Hash32,
    pub amount_usdt_micro: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditedMint {
    pub nonce: u64,
    pub deposit_id: Hash32,
    pub amount_usdd_base: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditedBurn {
    pub burn_index: u64,
    pub burn_id: Hash32,
    pub amount_usdd_base: u64,
    pub recipient: EthAddress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditedPayout {
    pub burn_id: Hash32,
    pub amount_usdt_micro: u64,
    pub recipient: EthAddress,
}

/// A cross-chain V1 accounting snapshot. Reserve fields are micro-USDT;
/// Elements supply fields are eight-decimal USDD base units.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuditSnapshot {
    pub actual_vault_usdt_micro: u64,
    pub recorded_backing_usdt_micro: u64,
    pub total_deposited_usdt_micro: u64,
    pub total_paid_usdt_micro: u64,
    pub total_minted_usdd_base: u64,
    pub total_burned_usdd_base: u64,
    pub deposits_unminted_usdt_micro: u64,
    pub burns_unpaid_usdt_micro: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditReport {
    pub expected_backing_usdt_micro: u128,
    pub recorded_backing_usdt_micro: u128,
    pub physical_surplus_usdt_micro: u128,
    pub circulating_usdd_base: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditError {
    NonConvertibleSupply(&'static str),
    BurnExceedsMint,
    PaidExceedsDeposited,
    DepositMintPartitionMismatch { deposited: u128, accounted: u128 },
    BurnPayoutPartitionMismatch { burned: u128, accounted: u128 },
    PhysicalReserveShortfall { required: u128, actual: u128 },
    RecordedBackingMismatch { expected: u128, actual: u128 },
    ConservationUnderflow,
    ZeroAuditIdentifier(&'static str),
    NonSequentialDepositNonce { expected: u64, actual: u64 },
    NonSequentialMintNonce { expected: u64, actual: u64 },
    NonSequentialBurnIndex { expected: u64, actual: u64 },
    DuplicateDepositId,
    DuplicateBurnId,
    MintDoesNotMatchDeposit,
    PayoutWithoutBurn,
    PayoutDoesNotMatchBurn,
    DuplicatePayout,
    AuditTotalOverflow,
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonConvertibleSupply(name) => {
                write!(f, "{name} is not divisible by {USDD_UNITS_PER_USDT_MICRO}")
            }
            Self::BurnExceedsMint => f.write_str("burned USDD exceeds minted USDD"),
            Self::PaidExceedsDeposited => f.write_str("paid USDT exceeds deposited USDT"),
            Self::DepositMintPartitionMismatch {
                deposited,
                accounted,
            } => write!(
                f,
                "deposited USDT {deposited} does not equal minted plus unminted {accounted}"
            ),
            Self::BurnPayoutPartitionMismatch { burned, accounted } => write!(
                f,
                "burned USDD in micro-USDT {burned} does not equal paid plus unpaid {accounted}"
            ),
            Self::PhysicalReserveShortfall { required, actual } => {
                write!(f, "physical reserve {actual} is below required {required}")
            }
            Self::RecordedBackingMismatch { expected, actual } => {
                write!(
                    f,
                    "recorded backing {actual} does not equal expected {expected}"
                )
            }
            Self::ConservationUnderflow => f.write_str("conservation equation underflow"),
            Self::ZeroAuditIdentifier(name) => write!(f, "{name} identifier is zero"),
            Self::NonSequentialDepositNonce { expected, actual } => write!(
                f,
                "deposit nonce {actual} is not the expected consecutive nonce {expected}"
            ),
            Self::NonSequentialMintNonce { expected, actual } => write!(
                f,
                "mint nonce {actual} is not the expected consecutive nonce {expected}"
            ),
            Self::NonSequentialBurnIndex { expected, actual } => write!(
                f,
                "burn index {actual} is not the expected consecutive index {expected}"
            ),
            Self::DuplicateDepositId => f.write_str("duplicate deposit ID"),
            Self::DuplicateBurnId => f.write_str("duplicate burn ID"),
            Self::MintDoesNotMatchDeposit => {
                f.write_str("mint does not exactly consume its deposit")
            }
            Self::PayoutWithoutBurn => f.write_str("payout has no finalized burn"),
            Self::PayoutDoesNotMatchBurn => {
                f.write_str("payout amount or recipient does not match its burn")
            }
            Self::DuplicatePayout => f.write_str("burn was paid more than once"),
            Self::AuditTotalOverflow => f.write_str("audit total overflow"),
        }
    }
}

/// Reconstruct the accounting state from canonical chain-derived records.
/// Inputs must already be obtained from independently validated chain data;
/// this function detects replay, gaps, mismatches, and conservation failures.
pub fn reconstruct_audit_snapshot(
    actual_vault_usdt_micro: u64,
    recorded_backing_usdt_micro: u64,
    deposits: &[AuditedDeposit],
    mints: &[AuditedMint],
    burns: &[AuditedBurn],
    payouts: &[AuditedPayout],
) -> Result<(AuditSnapshot, AuditReport), AuditError> {
    let mut deposits_by_nonce = BTreeMap::new();
    let mut deposit_ids = BTreeSet::new();
    let mut total_deposited = 0u64;
    for (expected, deposit) in deposits.iter().enumerate() {
        let expected = u64::try_from(expected).map_err(|_| AuditError::AuditTotalOverflow)?;
        if deposit.nonce != expected {
            return Err(AuditError::NonSequentialDepositNonce {
                expected,
                actual: deposit.nonce,
            });
        }
        if deposit.deposit_id == Hash32::ZERO {
            return Err(AuditError::ZeroAuditIdentifier("deposit"));
        }
        if !deposit_ids.insert(deposit.deposit_id) {
            return Err(AuditError::DuplicateDepositId);
        }
        if deposit.amount_usdt_micro == 0 {
            return Err(AuditError::MintDoesNotMatchDeposit);
        }
        total_deposited = total_deposited
            .checked_add(deposit.amount_usdt_micro)
            .ok_or(AuditError::AuditTotalOverflow)?;
        deposits_by_nonce.insert(deposit.nonce, *deposit);
    }

    let mut total_minted = 0u64;
    for (expected, mint) in mints.iter().enumerate() {
        let expected = u64::try_from(expected).map_err(|_| AuditError::AuditTotalOverflow)?;
        if mint.nonce != expected {
            return Err(AuditError::NonSequentialMintNonce {
                expected,
                actual: mint.nonce,
            });
        }
        let deposit = deposits_by_nonce
            .get(&mint.nonce)
            .ok_or(AuditError::MintDoesNotMatchDeposit)?;
        let expected_amount = deposit
            .amount_usdt_micro
            .checked_mul(USDD_UNITS_PER_USDT_MICRO)
            .ok_or(AuditError::AuditTotalOverflow)?;
        if mint.deposit_id != deposit.deposit_id || mint.amount_usdd_base != expected_amount {
            return Err(AuditError::MintDoesNotMatchDeposit);
        }
        total_minted = total_minted
            .checked_add(mint.amount_usdd_base)
            .ok_or(AuditError::AuditTotalOverflow)?;
    }

    let mut burns_by_id = BTreeMap::new();
    let mut total_burned = 0u64;
    for (expected, burn) in burns.iter().enumerate() {
        let expected = u64::try_from(expected).map_err(|_| AuditError::AuditTotalOverflow)?;
        if burn.burn_index != expected {
            return Err(AuditError::NonSequentialBurnIndex {
                expected,
                actual: burn.burn_index,
            });
        }
        if burn.burn_id == Hash32::ZERO || burn.recipient.is_zero() {
            return Err(AuditError::ZeroAuditIdentifier("burn"));
        }
        if usdd_base_to_usdt_micro(burn.amount_usdd_base).is_none() {
            return Err(AuditError::NonConvertibleSupply("burned USDD"));
        }
        if burns_by_id.insert(burn.burn_id, *burn).is_some() {
            return Err(AuditError::DuplicateBurnId);
        }
        total_burned = total_burned
            .checked_add(burn.amount_usdd_base)
            .ok_or(AuditError::AuditTotalOverflow)?;
    }

    let mut paid_ids = BTreeSet::new();
    let mut total_paid = 0u64;
    for payout in payouts {
        if payout.burn_id == Hash32::ZERO || payout.recipient.is_zero() {
            return Err(AuditError::ZeroAuditIdentifier("payout"));
        }
        if !paid_ids.insert(payout.burn_id) {
            return Err(AuditError::DuplicatePayout);
        }
        let burn = burns_by_id
            .get(&payout.burn_id)
            .ok_or(AuditError::PayoutWithoutBurn)?;
        let expected_amount = usdd_base_to_usdt_micro(burn.amount_usdd_base)
            .ok_or(AuditError::NonConvertibleSupply("burned USDD"))?;
        if payout.amount_usdt_micro != expected_amount || payout.recipient != burn.recipient {
            return Err(AuditError::PayoutDoesNotMatchBurn);
        }
        total_paid = total_paid
            .checked_add(payout.amount_usdt_micro)
            .ok_or(AuditError::AuditTotalOverflow)?;
    }

    let minted_micro = usdd_base_to_usdt_micro(total_minted)
        .ok_or(AuditError::NonConvertibleSupply("minted USDD"))?;
    let burned_micro = usdd_base_to_usdt_micro(total_burned)
        .ok_or(AuditError::NonConvertibleSupply("burned USDD"))?;
    let snapshot = AuditSnapshot {
        actual_vault_usdt_micro,
        recorded_backing_usdt_micro,
        total_deposited_usdt_micro: total_deposited,
        total_paid_usdt_micro: total_paid,
        total_minted_usdd_base: total_minted,
        total_burned_usdd_base: total_burned,
        deposits_unminted_usdt_micro: total_deposited
            .checked_sub(minted_micro)
            .ok_or(AuditError::MintDoesNotMatchDeposit)?,
        burns_unpaid_usdt_micro: burned_micro
            .checked_sub(total_paid)
            .ok_or(AuditError::PayoutDoesNotMatchBurn)?,
    };
    let report = snapshot.verify()?;
    Ok((snapshot, report))
}

#[cfg(feature = "std")]
impl std::error::Error for AuditError {}

impl AuditSnapshot {
    pub fn verify(&self) -> Result<AuditReport, AuditError> {
        let minted_micro = usdd_base_to_usdt_micro(self.total_minted_usdd_base)
            .ok_or(AuditError::NonConvertibleSupply("minted USDD"))?
            as u128;
        let burned_micro = usdd_base_to_usdt_micro(self.total_burned_usdd_base)
            .ok_or(AuditError::NonConvertibleSupply("burned USDD"))?
            as u128;
        if burned_micro > minted_micro {
            return Err(AuditError::BurnExceedsMint);
        }
        if self.total_paid_usdt_micro > self.total_deposited_usdt_micro {
            return Err(AuditError::PaidExceedsDeposited);
        }

        // Every permanent deposit is in exactly one of two states: consumed by
        // the singleton mint controller or still waiting at the next nonce.
        let deposit_partition = minted_micro + self.deposits_unminted_usdt_micro as u128;
        if deposit_partition != self.total_deposited_usdt_micro as u128 {
            return Err(AuditError::DepositMintPartitionMismatch {
                deposited: self.total_deposited_usdt_micro as u128,
                accounted: deposit_partition,
            });
        }

        // Every finalized unique burn is either paid once or remains payable.
        let burn_partition =
            self.total_paid_usdt_micro as u128 + self.burns_unpaid_usdt_micro as u128;
        if burn_partition != burned_micro {
            return Err(AuditError::BurnPayoutPartitionMismatch {
                burned: burned_micro,
                accounted: burn_partition,
            });
        }

        let backing_from_vault =
            (self.total_deposited_usdt_micro - self.total_paid_usdt_micro) as u128;
        if backing_from_vault != self.recorded_backing_usdt_micro as u128 {
            return Err(AuditError::RecordedBackingMismatch {
                expected: backing_from_vault,
                actual: self.recorded_backing_usdt_micro as u128,
            });
        }

        // R = M - B + D_unminted + X_burned_unpaid.
        let expected = minted_micro
            .checked_sub(burned_micro)
            .and_then(|value| value.checked_add(self.deposits_unminted_usdt_micro as u128))
            .and_then(|value| value.checked_add(self.burns_unpaid_usdt_micro as u128))
            .ok_or(AuditError::ConservationUnderflow)?;
        if expected != backing_from_vault {
            return Err(AuditError::RecordedBackingMismatch {
                expected,
                actual: backing_from_vault,
            });
        }
        if (self.actual_vault_usdt_micro as u128) < backing_from_vault {
            return Err(AuditError::PhysicalReserveShortfall {
                required: backing_from_vault,
                actual: self.actual_vault_usdt_micro as u128,
            });
        }

        Ok(AuditReport {
            expected_backing_usdt_micro: expected,
            recorded_backing_usdt_micro: backing_from_vault,
            physical_surplus_usdt_micro: self.actual_vault_usdt_micro as u128 - backing_from_vault,
            circulating_usdd_base: (minted_micro - burned_micro)
                * USDD_UNITS_PER_USDT_MICRO as u128,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_states_and_pending_states_balance() {
        let deposit_pending = AuditSnapshot {
            actual_vault_usdt_micro: 10,
            recorded_backing_usdt_micro: 10,
            total_deposited_usdt_micro: 10,
            deposits_unminted_usdt_micro: 10,
            ..Default::default()
        };
        assert!(deposit_pending.verify().is_ok());

        let minted = AuditSnapshot {
            total_minted_usdd_base: 1_000,
            deposits_unminted_usdt_micro: 0,
            ..deposit_pending
        };
        assert!(minted.verify().is_ok());

        let burned_unpaid = AuditSnapshot {
            total_burned_usdd_base: 1_000,
            burns_unpaid_usdt_micro: 10,
            ..minted
        };
        assert!(burned_unpaid.verify().is_ok());

        let paid = AuditSnapshot {
            actual_vault_usdt_micro: 0,
            recorded_backing_usdt_micro: 0,
            total_paid_usdt_micro: 10,
            burns_unpaid_usdt_micro: 0,
            ..burned_unpaid
        };
        assert!(paid.verify().is_ok());
    }

    #[test]
    fn sub_micro_supply_is_rejected() {
        let snapshot = AuditSnapshot {
            total_minted_usdd_base: 1,
            ..Default::default()
        };
        assert_eq!(
            snapshot.verify(),
            Err(AuditError::NonConvertibleSupply("minted USDD"))
        );
    }

    #[test]
    fn offsetting_impossible_histories_are_rejected() {
        let payout_without_burn = AuditSnapshot {
            actual_vault_usdt_micro: 0,
            recorded_backing_usdt_micro: 0,
            total_deposited_usdt_micro: 10,
            total_paid_usdt_micro: 10,
            ..Default::default()
        };
        assert!(matches!(
            payout_without_burn.verify(),
            Err(AuditError::DepositMintPartitionMismatch { .. })
                | Err(AuditError::BurnPayoutPartitionMismatch { .. })
        ));

        let fake_pending_offsets = AuditSnapshot {
            actual_vault_usdt_micro: 10,
            recorded_backing_usdt_micro: 10,
            total_deposited_usdt_micro: 10,
            total_minted_usdd_base: 1_000,
            deposits_unminted_usdt_micro: 10,
            burns_unpaid_usdt_micro: 10,
            ..Default::default()
        };
        assert!(matches!(
            fake_pending_offsets.verify(),
            Err(AuditError::DepositMintPartitionMismatch { .. })
        ));
    }

    #[test]
    fn event_reconstruction_detects_replay_and_matches_conservation() {
        let deposits = [
            AuditedDeposit {
                nonce: 0,
                deposit_id: Hash32([1; 32]),
                amount_usdt_micro: 5,
            },
            AuditedDeposit {
                nonce: 1,
                deposit_id: Hash32([2; 32]),
                amount_usdt_micro: 7,
            },
        ];
        let mints = [AuditedMint {
            nonce: 0,
            deposit_id: Hash32([1; 32]),
            amount_usdd_base: 500,
        }];
        let burns = [AuditedBurn {
            burn_index: 0,
            burn_id: Hash32([3; 32]),
            amount_usdd_base: 200,
            recipient: EthAddress([4; 20]),
        }];
        let payouts = [AuditedPayout {
            burn_id: Hash32([3; 32]),
            amount_usdt_micro: 2,
            recipient: EthAddress([4; 20]),
        }];

        let (snapshot, report) =
            reconstruct_audit_snapshot(10, 10, &deposits, &mints, &burns, &payouts).unwrap();
        assert_eq!(snapshot.deposits_unminted_usdt_micro, 7);
        assert_eq!(snapshot.burns_unpaid_usdt_micro, 0);
        assert_eq!(report.circulating_usdd_base, 300);

        let duplicate = [payouts[0], payouts[0]];
        assert_eq!(
            reconstruct_audit_snapshot(10, 10, &deposits, &mints, &burns, &duplicate),
            Err(AuditError::DuplicatePayout)
        );
    }

    #[test]
    fn event_reconstruction_rejects_gaps_and_cross_record_mismatches() {
        let deposits = [AuditedDeposit {
            nonce: 1,
            deposit_id: Hash32([1; 32]),
            amount_usdt_micro: 5,
        }];
        assert!(matches!(
            reconstruct_audit_snapshot(5, 5, &deposits, &[], &[], &[]),
            Err(AuditError::NonSequentialDepositNonce { .. })
        ));

        let deposits = [AuditedDeposit {
            nonce: 0,
            deposit_id: Hash32([1; 32]),
            amount_usdt_micro: 5,
        }];
        let wrong_mint = [AuditedMint {
            nonce: 0,
            deposit_id: Hash32([9; 32]),
            amount_usdd_base: 500,
        }];
        assert_eq!(
            reconstruct_audit_snapshot(5, 5, &deposits, &wrong_mint, &[], &[]),
            Err(AuditError::MintDoesNotMatchDeposit)
        );
    }

    #[test]
    fn conservation_holds_for_all_small_pending_state_partitions() {
        for deposited in 0u64..=12 {
            for minted in 0u64..=deposited {
                for burned in 0u64..=minted {
                    for paid in 0u64..=burned {
                        let backing = deposited - paid;
                        let snapshot = AuditSnapshot {
                            actual_vault_usdt_micro: backing + 3,
                            recorded_backing_usdt_micro: backing,
                            total_deposited_usdt_micro: deposited,
                            total_paid_usdt_micro: paid,
                            total_minted_usdd_base: minted * 100,
                            total_burned_usdd_base: burned * 100,
                            deposits_unminted_usdt_micro: deposited - minted,
                            burns_unpaid_usdt_micro: burned - paid,
                        };
                        let report = snapshot.verify().unwrap();
                        assert_eq!(report.expected_backing_usdt_micro, backing as u128);
                        assert_eq!(report.physical_surplus_usdt_micro, 3);
                        assert_eq!(
                            report.circulating_usdd_base,
                            (minted - burned) as u128 * 100
                        );
                    }
                }
            }
        }
    }
}
