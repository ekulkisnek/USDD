use core::fmt;

use crate::{usdd_base_to_usdt_micro, USDD_UNITS_PER_USDT_MICRO};

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
        }
    }
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
}
