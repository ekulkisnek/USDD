//! Canonical slot-24 USDD BIP300 withdrawal-bundle construction.
//!
//! This module deliberately has no RPC or networking code. Its canonical
//! artifact bytes can be copied through any untrusted dissemination channel;
//! every recipient independently validates the accumulator checkpoint,
//! blinded transaction, M6id, and actual CTIP spend. Complete claim data is an
//! optional audit witness and is never required in the constant-size M6.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use usdd_core::{
    burn_accumulator_empty, hash_bytes, BurnProof, CanonicalEncode, DecodeError, Decoder,
    EthAddress, Hash32, OutPoint, RedemptionClaim,
};

use crate::{double_sha256, ELEMENTS_DRIVECHAIN_SLOT};

pub const M6_ROOT_DOMAIN: Hash32 = Hash32([
    0x06, 0x21, 0x63, 0x3c, 0x45, 0xa9, 0xc0, 0x3e, 0xa6, 0x60, 0x59, 0xa6, 0xae, 0x5a, 0x53, 0x0a,
    0xa8, 0xcb, 0x8a, 0x6b, 0xc3, 0xed, 0x5f, 0xd9, 0x4c, 0xdd, 0x93, 0x2a, 0x71, 0x57, 0x94, 0x44,
]);
pub const M6_ROOT_DOMAIN_PREIMAGE: &str = "USDD_M6_APPROVED_ROOT_V1";
pub const M6_ROOT_PAYOUT_MAGIC: [u8; 6] = *b"USDDM6";
pub const M6_ROOT_PAYOUT_VERSION: u8 = 1;
pub const M6_ROOT_PAYOUT_SATS: u64 = 1;
pub const BITCOIN_TRANSACTION_VERSION: i32 = 2;
pub const BITCOIN_MAX_MONEY_SATS: u64 = 21_000_000 * 100_000_000;
pub const MINER_BUNDLE_MAGIC: [u8; 8] = *b"USDDM6R1";
pub const ACTUAL_M6_MAGIC: [u8; 8] = *b"USDDM6X2";
pub const M6_ARTIFACT_CODEC_VERSION: u16 = 2;
pub const REDEMPTION_CLAIM_ENCODED_LENGTH: usize = 200;
pub const BURN_PROOF_ENCODED_LENGTH: usize = 64 * 32;
pub const MINER_BUNDLE_ARTIFACT_ENCODED_LENGTH: usize = 227;
pub const MAX_MINER_BUNDLE_ARTIFACT_SIZE: usize = 4 * 1024;
pub const MAX_APPROVED_CLAIMS_PER_AUDIT_WITNESS: usize = 64;
pub const NATIVE_WITHDRAWAL_REFERENCE_MAGIC: [u8; 4] = *b"ELWD";
pub const NATIVE_WITHDRAWAL_REFERENCE_VERSION: u8 = 1;
pub const NATIVE_WITHDRAWAL_REFERENCE_LENGTH: usize = 74;
pub const NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE: usize = 128;
pub const NATIVE_WITHDRAWAL_MAX_LEGACY_M6_SIZE: usize = 251;

const OP_RETURN: u8 = 0x6a;
const OP_DRIVECHAIN: u8 = 0xb4; // OP_NOP5 in the deployed enforcer.
const OP_TRUE: u8 = 0x51;
const FINAL_SEQUENCE: u32 = u32::MAX;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedClaimAppend {
    pub claim: RedemptionClaim,
    /// Proof that the next contiguous position is empty under the evolving
    /// root immediately before this claim is appended.
    pub empty_branch: BurnProof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootTransition {
    pub prior_claim_count: u64,
    pub prior_claim_root: Hash32,
    pub next_claim_count: u64,
    pub next_claim_root: Hash32,
}

/// Optional bounded witness used by builders and auditors to derive one
/// accumulator checkpoint from complete claim data. These claims are not
/// carried by the canonical M6 artifact and the 64-record bound is not a
/// consensus limit on the M6 count delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimBatchWitness {
    pub bitcoin_genesis: Hash32,
    pub elements_genesis: Hash32,
    pub usdd_asset: Hash32,
    pub vault_id: Hash32,
    pub prior_claim_count: u64,
    pub prior_claim_root: Hash32,
    pub fee_sats: u64,
    pub claims: Vec<ApprovedClaimAppend>,
}

impl ClaimBatchWitness {
    pub fn derive_root_artifact(&self) -> Result<MinerBundleArtifact, M6Error> {
        if self.bitcoin_genesis == Hash32::ZERO
            || self.elements_genesis == Hash32::ZERO
            || self.usdd_asset == Hash32::ZERO
            || self.vault_id == Hash32::ZERO
            || self.prior_claim_root == Hash32::ZERO
        {
            return Err(M6Error::ZeroIdentity);
        }
        if self.fee_sats > BITCOIN_MAX_MONEY_SATS {
            return Err(M6Error::FeeOutOfRange);
        }
        if self.claims.is_empty() || self.claims.len() > MAX_APPROVED_CLAIMS_PER_AUDIT_WITNESS {
            return Err(M6Error::AuditWitnessClaimCount);
        }
        let empty_root = burn_accumulator_empty(64).expect("fixed burn-tree depth");
        if (self.prior_claim_count == 0) != (self.prior_claim_root == empty_root) {
            return Err(M6Error::NoncanonicalEmptyRoot);
        }

        let empty_leaf = burn_accumulator_empty(0).expect("fixed empty leaf");
        let mut root = self.prior_claim_root;
        for (offset, append) in self.claims.iter().enumerate() {
            append.claim.validate().map_err(|_| M6Error::InvalidClaim)?;
            if append.claim.protocol_version != 1
                || append.claim.elements_genesis_hash != self.elements_genesis
                || append.claim.usdd_asset_id != self.usdd_asset
                || append.claim.vault_id != self.vault_id
            {
                return Err(M6Error::ClaimIdentityMismatch);
            }
            if self.claims[..offset]
                .iter()
                .any(|earlier| earlier.claim.burn_id == append.claim.burn_id)
            {
                return Err(M6Error::DuplicateClaim);
            }
            let index = self
                .prior_claim_count
                .checked_add(offset as u64)
                .ok_or(M6Error::ClaimCountOverflow)?;
            if !append.empty_branch.verify(root, empty_leaf, index) {
                return Err(M6Error::EmptyBranchMismatch);
            }
            let leaf = append
                .claim
                .approved_redemption_leaf(index)
                .map_err(|_| M6Error::InvalidClaim)?;
            root = append.empty_branch.compute_root(leaf, index);
        }
        let next_claim_count = self
            .prior_claim_count
            .checked_add(self.claims.len() as u64)
            .ok_or(M6Error::ClaimCountOverflow)?;
        let transition = RootTransition {
            prior_claim_count: self.prior_claim_count,
            prior_claim_root: self.prior_claim_root,
            next_claim_count,
            next_claim_root: root,
        };
        let artifact = MinerBundleArtifact {
            bitcoin_genesis: self.bitcoin_genesis,
            elements_genesis: self.elements_genesis,
            usdd_asset: self.usdd_asset,
            vault_id: self.vault_id,
            prior_claim_count: transition.prior_claim_count,
            prior_claim_root: transition.prior_claim_root,
            next_claim_count: transition.next_claim_count,
            next_claim_root: transition.next_claim_root,
            fee_sats: self.fee_sats,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Validate the artifact against the immutable Ethereum vault address.
    /// `vault_id` alone cannot reveal that address, so callers constructing or
    /// approving an M6 must supply it from the deployment manifest.
    pub fn validate_for_vault(
        &self,
        expected_vault: EthAddress,
    ) -> Result<MinerBundleArtifact, M6Error> {
        if expected_vault.is_zero() {
            return Err(M6Error::InvalidVaultAddress);
        }
        if self
            .claims
            .iter()
            .any(|append| append.claim.recipient == expected_vault)
        {
            return Err(M6Error::PayoutToVault);
        }
        self.derive_root_artifact()
    }
}

/// Canonical constant-size slot-24 accumulator checkpoint carried into one
/// blinded M6. Claim contents and inclusion branches remain sidechain/audit
/// data; this artifact commits only their prior and successor count/root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinerBundleArtifact {
    pub bitcoin_genesis: Hash32,
    pub elements_genesis: Hash32,
    pub usdd_asset: Hash32,
    pub vault_id: Hash32,
    pub prior_claim_count: u64,
    pub prior_claim_root: Hash32,
    pub next_claim_count: u64,
    pub next_claim_root: Hash32,
    pub fee_sats: u64,
}

impl MinerBundleArtifact {
    pub fn validate(&self) -> Result<RootTransition, M6Error> {
        if self.bitcoin_genesis == Hash32::ZERO
            || self.elements_genesis == Hash32::ZERO
            || self.usdd_asset == Hash32::ZERO
            || self.vault_id == Hash32::ZERO
            || self.prior_claim_root == Hash32::ZERO
            || self.next_claim_root == Hash32::ZERO
        {
            return Err(M6Error::ZeroIdentity);
        }
        if self.fee_sats > BITCOIN_MAX_MONEY_SATS {
            return Err(M6Error::FeeOutOfRange);
        }
        let empty_root = burn_accumulator_empty(64).expect("fixed burn-tree depth");
        if (self.prior_claim_count == 0) != (self.prior_claim_root == empty_root) {
            return Err(M6Error::NoncanonicalEmptyRoot);
        }
        if self.next_claim_count <= self.prior_claim_count {
            return Err(M6Error::NonIncreasingClaimCount);
        }
        if self.next_claim_root == self.prior_claim_root {
            return Err(M6Error::UnchangedRoot);
        }
        Ok(RootTransition {
            prior_claim_count: self.prior_claim_count,
            prior_claim_root: self.prior_claim_root,
            next_claim_count: self.next_claim_count,
            next_claim_root: self.next_claim_root,
        })
    }

    /// Exact 241-byte V1 root-transition commitment preimage.
    pub fn root_commitment_preimage(&self) -> Result<Vec<u8>, M6Error> {
        let transition = self.validate()?;
        let mut preimage = Vec::with_capacity(241);
        preimage.extend_from_slice(M6_ROOT_DOMAIN.as_bytes());
        preimage.push(ELEMENTS_DRIVECHAIN_SLOT);
        preimage.extend_from_slice(self.bitcoin_genesis.as_bytes());
        preimage.extend_from_slice(self.elements_genesis.as_bytes());
        preimage.extend_from_slice(self.usdd_asset.as_bytes());
        preimage.extend_from_slice(self.vault_id.as_bytes());
        preimage.extend_from_slice(&transition.prior_claim_count.to_be_bytes());
        preimage.extend_from_slice(transition.prior_claim_root.as_bytes());
        preimage.extend_from_slice(&transition.next_claim_count.to_be_bytes());
        preimage.extend_from_slice(transition.next_claim_root.as_bytes());
        debug_assert_eq!(preimage.len(), 241);
        Ok(preimage)
    }

    pub fn root_commitment(&self) -> Result<Hash32, M6Error> {
        Ok(hash_bytes(&self.root_commitment_preimage()?))
    }

    pub fn blinded_m6(&self) -> Result<BlindedM6, M6Error> {
        Ok(BlindedM6 {
            fee_sats: self.fee_sats,
            root_commitment: self.root_commitment()?,
        })
    }

    pub fn m6id(&self) -> Result<Hash32, M6Error> {
        Ok(self.blinded_m6()?.m6id())
    }

    pub fn artifact_id(&self) -> Result<Hash32, M6Error> {
        self.validate()?;
        Ok(hash_bytes(&self.encode()))
    }

    pub fn decode_artifact(bytes: &[u8]) -> Result<Self, M6Error> {
        if bytes.len() > MAX_MINER_BUNDLE_ARTIFACT_SIZE {
            return Err(M6Error::ArtifactTooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.fixed::<8>()? != MINER_BUNDLE_MAGIC
            || decoder.u16()? != M6_ARTIFACT_CODEC_VERSION
            || decoder.u8()? != ELEMENTS_DRIVECHAIN_SLOT
        {
            return Err(M6Error::WrongArtifactHeader);
        }
        let bitcoin_genesis = Hash32(decoder.fixed()?);
        let elements_genesis = Hash32(decoder.fixed()?);
        let usdd_asset = Hash32(decoder.fixed()?);
        let vault_id = Hash32(decoder.fixed()?);
        let prior_claim_count = decoder.u64()?;
        let prior_claim_root = Hash32(decoder.fixed()?);
        let next_claim_count = decoder.u64()?;
        let next_claim_root = Hash32(decoder.fixed()?);
        let fee_sats = decoder.u64()?;
        if decoder.remaining() != 0 {
            return Err(M6Error::TrailingBytes);
        }
        let artifact = Self {
            bitcoin_genesis,
            elements_genesis,
            usdd_asset,
            vault_id,
            prior_claim_count,
            prior_claim_root,
            next_claim_count,
            next_claim_root,
            fee_sats,
        };
        artifact.validate()?;
        Ok(artifact)
    }
}

impl CanonicalEncode for MinerBundleArtifact {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&MINER_BUNDLE_MAGIC);
        M6_ARTIFACT_CODEC_VERSION.encode_to(out);
        ELEMENTS_DRIVECHAIN_SLOT.encode_to(out);
        self.bitcoin_genesis.encode_to(out);
        self.elements_genesis.encode_to(out);
        self.usdd_asset.encode_to(out);
        self.vault_id.encode_to(out);
        self.prior_claim_count.encode_to(out);
        self.prior_claim_root.encode_to(out);
        self.next_claim_count.encode_to(out);
        self.next_claim_root.encode_to(out);
        self.fee_sats.encode_to(out);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlindedM6 {
    pub fee_sats: u64,
    pub root_commitment: Hash32,
}

impl BlindedM6 {
    pub fn fee_script(self) -> Vec<u8> {
        let mut script = Vec::with_capacity(10);
        script.extend_from_slice(&[OP_RETURN, 8]);
        script.extend_from_slice(&self.fee_sats.to_be_bytes());
        script
    }

    pub fn root_payout_data(self) -> [u8; 39] {
        let mut data = [0u8; 39];
        data[..6].copy_from_slice(&M6_ROOT_PAYOUT_MAGIC);
        data[6] = M6_ROOT_PAYOUT_VERSION;
        data[7..].copy_from_slice(self.root_commitment.as_bytes());
        data
    }

    pub fn root_payout_script(self) -> Vec<u8> {
        let data = self.root_payout_data();
        let mut script = Vec::with_capacity(41);
        script.extend_from_slice(&[OP_RETURN, data.len() as u8]);
        script.extend_from_slice(&data);
        script
    }

    /// Bitcoin Core-compatible zero-input legacy frame. This is the non-witness
    /// serialization hashed by BIP300's blinded-M6 ID algorithm.
    pub fn legacy_bytes(self) -> Vec<u8> {
        encode_blinded_transaction(self, false)
    }

    /// rust-bitcoin/BIP144 unambiguous zero-input frame:
    /// `version || 00 || 01 || 00 || outputs || locktime`.
    pub fn standard_bytes(self) -> Vec<u8> {
        encode_blinded_transaction(self, true)
    }

    /// Canonical RPC/display-order M6id. The double-SHA256 digest is reversed
    /// exactly once for display; wire outpoints reverse it back exactly once.
    pub fn m6id(self) -> Hash32 {
        txid_display(&self.legacy_bytes())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, M6Error> {
        let mut cursor = TxCursor::new(bytes);
        if cursor.i32_le()? != BITCOIN_TRANSACTION_VERSION {
            return Err(M6Error::MalformedTransaction("wrong transaction version"));
        }
        if cursor.byte()? != 0 {
            return Err(M6Error::MalformedTransaction(
                "blinded M6 inputs must be empty",
            ));
        }
        let next = cursor.byte()?;
        let output_count = if next == 1 {
            if cursor.compact_size()? != 0 {
                return Err(M6Error::MalformedTransaction(
                    "standard zero-input frame has nonzero input count",
                ));
            }
            cursor.compact_size()?
        } else {
            cursor.compact_size_with_prefix(next)?
        };
        if output_count != 2 {
            return Err(M6Error::MalformedTransaction(
                "blinded M6 must have exactly two outputs",
            ));
        }
        let fee_output = cursor.output()?;
        let root_output = cursor.output()?;
        if cursor.u32_le()? != 0 || cursor.remaining() != 0 {
            return Err(M6Error::MalformedTransaction(
                "nonzero locktime or trailing transaction bytes",
            ));
        }
        if fee_output.value_sats != 0
            || fee_output.script.len() != 10
            || fee_output.script[..2] != [OP_RETURN, 8]
        {
            return Err(M6Error::MalformedTransaction(
                "invalid blinded M6 fee output",
            ));
        }
        let fee_sats = u64::from_be_bytes(
            fee_output.script[2..]
                .try_into()
                .expect("fee script length checked"),
        );
        if fee_sats > BITCOIN_MAX_MONEY_SATS {
            return Err(M6Error::FeeOutOfRange);
        }
        let root_commitment = decode_root_output(&root_output)?;
        Ok(Self {
            fee_sats,
            root_commitment,
        })
    }
}

/// Exact, directly parseable Elements burn reference carried by native M6
/// output one. Hash fields use RPC/display order in memory and are reversed
/// exactly once at the Bitcoin-script boundary, matching Elements `uint256`
/// consensus serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeWithdrawalReference {
    elements_genesis: Hash32,
    sidechain_slot: u8,
    burn_outpoint: OutPoint,
}

impl NativeWithdrawalReference {
    pub const fn elements_genesis(self) -> Hash32 {
        self.elements_genesis
    }

    pub const fn sidechain_slot(self) -> u8 {
        self.sidechain_slot
    }

    pub const fn burn_outpoint(self) -> OutPoint {
        self.burn_outpoint
    }

    pub fn script(self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(NATIVE_WITHDRAWAL_REFERENCE_LENGTH);
        payload.extend_from_slice(&NATIVE_WITHDRAWAL_REFERENCE_MAGIC);
        payload.push(NATIVE_WITHDRAWAL_REFERENCE_VERSION);
        payload.extend(self.elements_genesis.0.iter().rev().copied());
        payload.push(self.sidechain_slot);
        payload.extend(self.burn_outpoint.txid.0.iter().rev().copied());
        payload.extend_from_slice(&self.burn_outpoint.vout.to_be_bytes());
        debug_assert_eq!(payload.len(), NATIVE_WITHDRAWAL_REFERENCE_LENGTH);

        let mut script = Vec::with_capacity(2 + payload.len());
        script.extend_from_slice(&[OP_RETURN, NATIVE_WITHDRAWAL_REFERENCE_LENGTH as u8]);
        script.extend_from_slice(&payload);
        script
    }

    fn decode_script(script: &[u8]) -> Result<Self, M6Error> {
        if script.len() != 2 + NATIVE_WITHDRAWAL_REFERENCE_LENGTH
            || script[..2] != [OP_RETURN, NATIVE_WITHDRAWAL_REFERENCE_LENGTH as u8]
            || script[2..6] != NATIVE_WITHDRAWAL_REFERENCE_MAGIC
            || script[6] != NATIVE_WITHDRAWAL_REFERENCE_VERSION
        {
            return Err(M6Error::MalformedTransaction(
                "native withdrawal reference is not the exact ELWD V1 push",
            ));
        }

        let mut elements_genesis: [u8; 32] = script[7..39]
            .try_into()
            .expect("fixed native genesis field");
        elements_genesis.reverse();
        let elements_genesis = Hash32(elements_genesis);
        let sidechain_slot = script[39];
        let mut burn_txid: [u8; 32] = script[40..72]
            .try_into()
            .expect("fixed native burn txid field");
        burn_txid.reverse();
        let burn_outpoint = OutPoint {
            txid: Hash32(burn_txid),
            vout: u32::from_be_bytes(
                script[72..76]
                    .try_into()
                    .expect("fixed native burn vout field"),
            ),
        };
        if elements_genesis == Hash32::ZERO
            || burn_outpoint.txid == Hash32::ZERO
            || burn_outpoint.vout == u32::MAX
        {
            return Err(M6Error::MalformedTransaction(
                "native withdrawal reference contains an unknown identity or outpoint",
            ));
        }

        let reference = Self {
            elements_genesis,
            sidechain_slot,
            burn_outpoint,
        };
        if reference.script() != script {
            return Err(M6Error::MalformedTransaction(
                "native withdrawal reference is noncanonical",
            ));
        }
        Ok(reference)
    }
}

/// Canonical zero-input native Elements withdrawal bundle. This is the exact
/// `ELWD` legacy codec produced by the Elements node and consumed by the
/// enforcer; it is not merely an output-magic detector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeWithdrawalM6 {
    reference: NativeWithdrawalReference,
    parent_fee_sats: u64,
    payout_sats: u64,
    destination_script: Vec<u8>,
}

impl NativeWithdrawalM6 {
    pub fn decode_legacy(bytes: &[u8]) -> Result<Self, M6Error> {
        if !(124..=NATIVE_WITHDRAWAL_MAX_LEGACY_M6_SIZE).contains(&bytes.len()) {
            return Err(M6Error::MalformedTransaction(
                "native withdrawal M6 is outside its bounded legacy frame",
            ));
        }
        let mut cursor = TxCursor::new(bytes);
        if cursor.i32_le()? != BITCOIN_TRANSACTION_VERSION || cursor.compact_size()? != 0 {
            return Err(M6Error::MalformedTransaction(
                "native withdrawal M6 must be version two with zero inputs",
            ));
        }
        if cursor.compact_size()? != 3 {
            return Err(M6Error::MalformedTransaction(
                "native withdrawal M6 must have exactly three outputs",
            ));
        }
        let fee_output = cursor.output()?;
        let reference_output = cursor.output()?;
        let payout_output = cursor.output()?;
        if cursor.u32_le()? != 0 || cursor.remaining() != 0 {
            return Err(M6Error::MalformedTransaction(
                "native withdrawal M6 has nonzero locktime or trailing bytes",
            ));
        }
        if fee_output.value_sats != 0
            || fee_output.script.len() != 10
            || fee_output.script[..2] != [OP_RETURN, 8]
        {
            return Err(M6Error::MalformedTransaction(
                "native withdrawal M6 fee output is not canonical",
            ));
        }
        let parent_fee_sats = u64::from_be_bytes(
            fee_output.script[2..]
                .try_into()
                .expect("fixed native fee field"),
        );
        if reference_output.value_sats != 0 {
            return Err(M6Error::MalformedTransaction(
                "native withdrawal reference output is not zero-valued",
            ));
        }
        let reference = NativeWithdrawalReference::decode_script(&reference_output.script)?;
        let total_spend = parent_fee_sats.checked_add(payout_output.value_sats);
        if payout_output.value_sats == 0
            || payout_output.script.is_empty()
            || payout_output.script.len() > NATIVE_WITHDRAWAL_MAX_DESTINATION_SIZE
            || !matches!(total_spend, Some(total) if total <= BITCOIN_MAX_MONEY_SATS)
        {
            return Err(M6Error::MalformedTransaction(
                "native withdrawal payout or fee is outside canonical bounds",
            ));
        }

        let native = Self {
            reference,
            parent_fee_sats,
            payout_sats: payout_output.value_sats,
            destination_script: payout_output.script,
        };
        if native.legacy_bytes() != bytes {
            return Err(M6Error::MalformedTransaction(
                "native withdrawal M6 uses a noncanonical encoding",
            ));
        }
        Ok(native)
    }

    pub const fn reference(&self) -> NativeWithdrawalReference {
        self.reference
    }

    pub const fn parent_fee_sats(&self) -> u64 {
        self.parent_fee_sats
    }

    pub const fn payout_sats(&self) -> u64 {
        self.payout_sats
    }

    pub fn destination_script(&self) -> &[u8] {
        &self.destination_script
    }

    pub fn legacy_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&BITCOIN_TRANSACTION_VERSION.to_le_bytes());
        out.push(0);
        encode_compact_size(3, &mut out);

        let mut fee_script = Vec::with_capacity(10);
        fee_script.extend_from_slice(&[OP_RETURN, 8]);
        fee_script.extend_from_slice(&self.parent_fee_sats.to_be_bytes());
        encode_output(0, &fee_script, &mut out);
        encode_output(0, &self.reference.script(), &mut out);
        encode_output(self.payout_sats, &self.destination_script, &mut out);
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    pub fn m6id(&self) -> Hash32 {
        txid_display(&self.legacy_bytes())
    }

    pub fn successor_ctip_value(&self, prior_ctip: &Ctip) -> Result<u64, M6Error> {
        prior_ctip.validate()?;
        prior_ctip
            .value_sats
            .checked_sub(self.payout_sats)
            .and_then(|value| value.checked_sub(self.parent_fee_sats))
            .ok_or(M6Error::CtipInsufficient)
    }

    pub fn actual_transaction_bytes(&self, prior_ctip: &Ctip) -> Result<Vec<u8>, M6Error> {
        let successor_value = self.successor_ctip_value(prior_ctip)?;
        let mut out = Vec::new();
        out.extend_from_slice(&BITCOIN_TRANSACTION_VERSION.to_le_bytes());
        encode_compact_size(1, &mut out);
        out.extend(prior_ctip.outpoint.txid.0.iter().rev().copied());
        out.extend_from_slice(&prior_ctip.outpoint.vout.to_le_bytes());
        out.push(0);
        out.extend_from_slice(&FINAL_SEQUENCE.to_le_bytes());
        encode_compact_size(3, &mut out);
        encode_output(successor_value, &op_drivechain_script(), &mut out);
        encode_output(0, &self.reference.script(), &mut out);
        encode_output(self.payout_sats, &self.destination_script, &mut out);
        out.extend_from_slice(&0u32.to_le_bytes());
        Ok(out)
    }

    pub fn verify_actual_transaction(
        &self,
        bytes: &[u8],
        prior_ctip: &Ctip,
    ) -> Result<(), M6Error> {
        if bytes != self.actual_transaction_bytes(prior_ctip)? {
            return Err(M6Error::ActualMismatch(
                "actual native withdrawal differs from the exact ELWD reconstruction",
            ));
        }
        Ok(())
    }

    pub fn successor_ctip(&self, prior_ctip: &Ctip) -> Result<Ctip, M6Error> {
        let transaction = self.actual_transaction_bytes(prior_ctip)?;
        Ok(Ctip {
            outpoint: OutPoint {
                txid: txid_display(&transaction),
                vout: 0,
            },
            value_sats: self.successor_ctip_value(prior_ctip)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ctip {
    /// RPC/display-order txid.
    pub outpoint: OutPoint,
    pub value_sats: u64,
}

impl Ctip {
    pub fn validate(&self) -> Result<(), M6Error> {
        if self.outpoint.txid == Hash32::ZERO || self.value_sats > BITCOIN_MAX_MONEY_SATS {
            return Err(M6Error::InvalidCtip);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActualM6Artifact {
    bundle: MinerBundleArtifact,
    prior_ctip: Ctip,
}

impl ActualM6Artifact {
    pub fn build(bundle: MinerBundleArtifact, prior_ctip: Ctip) -> Result<Self, M6Error> {
        bundle.validate()?;
        prior_ctip.validate()?;
        let required = bundle
            .fee_sats
            .checked_add(M6_ROOT_PAYOUT_SATS)
            .ok_or(M6Error::CtipInsufficient)?;
        if prior_ctip.value_sats < required {
            return Err(M6Error::CtipInsufficient);
        }
        Ok(Self { bundle, prior_ctip })
    }

    pub const fn bundle(&self) -> &MinerBundleArtifact {
        &self.bundle
    }

    pub const fn prior_ctip(&self) -> &Ctip {
        &self.prior_ctip
    }

    pub fn successor_ctip_value(&self) -> u64 {
        self.prior_ctip.value_sats - self.bundle.fee_sats - M6_ROOT_PAYOUT_SATS
    }

    pub fn transaction_bytes(&self) -> Result<Vec<u8>, M6Error> {
        let blinded = self.bundle.blinded_m6()?;
        let mut out = Vec::new();
        out.extend_from_slice(&BITCOIN_TRANSACTION_VERSION.to_le_bytes());
        encode_compact_size(1, &mut out);
        let mut wire_txid = *self.prior_ctip.outpoint.txid.as_bytes();
        wire_txid.reverse();
        out.extend_from_slice(&wire_txid);
        out.extend_from_slice(&self.prior_ctip.outpoint.vout.to_le_bytes());
        out.push(0); // empty scriptSig
        out.extend_from_slice(&FINAL_SEQUENCE.to_le_bytes());
        encode_compact_size(2, &mut out);
        encode_output(
            self.successor_ctip_value(),
            &op_drivechain_script(),
            &mut out,
        );
        encode_output(M6_ROOT_PAYOUT_SATS, &blinded.root_payout_script(), &mut out);
        out.extend_from_slice(&0u32.to_le_bytes());
        Ok(out)
    }

    pub fn transaction_id(&self) -> Result<Hash32, M6Error> {
        Ok(txid_display(&self.transaction_bytes()?))
    }

    /// Every successful M6 creates its successor CTIP at vout 0. This remains
    /// true when a later approved M6 spends it in the same Bitcoin block.
    pub fn successor_ctip(&self) -> Result<Ctip, M6Error> {
        Ok(Ctip {
            outpoint: OutPoint {
                txid: self.transaction_id()?,
                vout: 0,
            },
            value_sats: self.successor_ctip_value(),
        })
    }

    pub fn verify_transaction(&self, bytes: &[u8]) -> Result<(), M6Error> {
        let parsed = parse_actual_m6(bytes)?;
        if parsed.input != self.prior_ctip.outpoint {
            return Err(M6Error::ActualMismatch("actual M6 spends the wrong CTIP"));
        }
        let expected = self.transaction_bytes()?;
        if bytes != expected {
            return Err(M6Error::ActualMismatch(
                "actual M6 differs from canonical reconstruction",
            ));
        }
        if parsed.new_ctip_value != self.successor_ctip_value() {
            return Err(M6Error::ActualMismatch("wrong replacement CTIP value"));
        }
        if parsed.root_commitment != self.bundle.root_commitment()? {
            return Err(M6Error::ActualMismatch("wrong root commitment payout"));
        }

        // Reproduce the deployed enforcer's compute_m6id transformation:
        // remove the sole CTIP input and replace vout 0 with OP_RETURN <u64be fee>.
        let derived_fee = self
            .prior_ctip
            .value_sats
            .checked_sub(parsed.new_ctip_value)
            .and_then(|spent| spent.checked_sub(M6_ROOT_PAYOUT_SATS))
            .ok_or(M6Error::ActualMismatch("actual M6 overspends CTIP"))?;
        let blinded = BlindedM6 {
            fee_sats: derived_fee,
            root_commitment: parsed.root_commitment,
        };
        if blinded.m6id() != self.bundle.m6id()? {
            return Err(M6Error::ActualMismatch(
                "actual M6 reconstructs a different blinded M6id",
            ));
        }
        Ok(())
    }

    pub fn artifact_id(&self) -> Result<Hash32, M6Error> {
        Ok(hash_bytes(&self.encode()))
    }

    pub fn decode_artifact(bytes: &[u8]) -> Result<Self, M6Error> {
        if bytes.len() > MAX_MINER_BUNDLE_ARTIFACT_SIZE + 128 {
            return Err(M6Error::ArtifactTooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.fixed::<8>()? != ACTUAL_M6_MAGIC || decoder.u16()? != M6_ARTIFACT_CODEC_VERSION {
            return Err(M6Error::WrongArtifactHeader);
        }
        let bundle_bytes = decoder.bytes()?;
        let bundle = MinerBundleArtifact::decode_artifact(&bundle_bytes)?;
        let prior_ctip = Ctip {
            outpoint: OutPoint {
                txid: Hash32(decoder.fixed()?),
                vout: decoder.u32()?,
            },
            value_sats: decoder.u64()?,
        };
        if decoder.remaining() != 0 {
            return Err(M6Error::TrailingBytes);
        }
        Self::build(bundle, prior_ctip)
    }
}

impl CanonicalEncode for ActualM6Artifact {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&ACTUAL_M6_MAGIC);
        M6_ARTIFACT_CODEC_VERSION.encode_to(out);
        self.bundle.encode().encode_to(out);
        self.prior_ctip.outpoint.txid.encode_to(out);
        self.prior_ctip.outpoint.vout.encode_to(out);
        self.prior_ctip.value_sats.encode_to(out);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum M6Error {
    Codec(DecodeError),
    ZeroIdentity,
    AuditWitnessClaimCount,
    NonIncreasingClaimCount,
    ClaimCountOverflow,
    NoncanonicalEmptyRoot,
    InvalidClaim,
    ClaimIdentityMismatch,
    InvalidVaultAddress,
    PayoutToVault,
    DuplicateClaim,
    EmptyBranchMismatch,
    UnchangedRoot,
    FeeOutOfRange,
    InvalidCtip,
    CtipInsufficient,
    ArtifactTooLarge,
    WrongArtifactHeader,
    TrailingBytes,
    MalformedTransaction(&'static str),
    ActualMismatch(&'static str),
}

impl From<DecodeError> for M6Error {
    fn from(value: DecodeError) -> Self {
        Self::Codec(value)
    }
}

impl fmt::Display for M6Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => error.fmt(f),
            Self::ZeroIdentity => f.write_str("M6 bundle identity contains zero"),
            Self::AuditWitnessClaimCount => f.write_str("audit witness must contain 1..64 claims"),
            Self::NonIncreasingClaimCount => {
                f.write_str("M6 accumulator claim count must increase")
            }
            Self::ClaimCountOverflow => f.write_str("approved claim count overflow"),
            Self::NoncanonicalEmptyRoot => f.write_str("claim count zero requires EMPTY[64]"),
            Self::InvalidClaim => f.write_str("invalid redemption claim"),
            Self::ClaimIdentityMismatch => {
                f.write_str("redemption claim targets a different genesis, asset, or vault")
            }
            Self::InvalidVaultAddress => f.write_str("configured Ethereum vault address is zero"),
            Self::PayoutToVault => {
                f.write_str("redemption claim pays the configured Ethereum vault")
            }
            Self::DuplicateClaim => f.write_str("duplicate burn ID in M6 bundle"),
            Self::EmptyBranchMismatch => {
                f.write_str("claim does not replace the next empty accumulator leaf")
            }
            Self::UnchangedRoot => f.write_str("M6 accumulator root did not advance"),
            Self::FeeOutOfRange => f.write_str("Bitcoin fee exceeds MAX_MONEY"),
            Self::InvalidCtip => f.write_str("invalid prior slot-24 CTIP"),
            Self::CtipInsufficient => f.write_str("CTIP cannot fund one satoshi plus fee"),
            Self::ArtifactTooLarge => f.write_str("M6 artifact exceeds its fixed bound"),
            Self::WrongArtifactHeader => f.write_str("wrong M6 artifact magic, version, or slot"),
            Self::TrailingBytes => f.write_str("trailing bytes after M6 artifact"),
            Self::MalformedTransaction(message) => write!(f, "malformed M6 transaction: {message}"),
            Self::ActualMismatch(message) => write!(f, "actual M6 verification failed: {message}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for M6Error {}

#[derive(Clone)]
struct ParsedOutput {
    value_sats: u64,
    script: Vec<u8>,
}

struct ParsedActualM6 {
    input: OutPoint,
    new_ctip_value: u64,
    root_commitment: Hash32,
}

fn parse_actual_m6(bytes: &[u8]) -> Result<ParsedActualM6, M6Error> {
    let mut cursor = TxCursor::new(bytes);
    if cursor.i32_le()? != BITCOIN_TRANSACTION_VERSION {
        return Err(M6Error::MalformedTransaction("wrong transaction version"));
    }
    if cursor.compact_size()? != 1 {
        return Err(M6Error::MalformedTransaction(
            "actual M6 must have exactly one input",
        ));
    }
    let mut txid_display = cursor.fixed::<32>()?;
    txid_display.reverse();
    let input = OutPoint {
        txid: Hash32(txid_display),
        vout: cursor.u32_le()?,
    };
    if cursor.compact_size()? != 0 || cursor.u32_le()? != FINAL_SEQUENCE {
        return Err(M6Error::MalformedTransaction(
            "actual M6 input must use empty scriptSig and final sequence",
        ));
    }
    if cursor.compact_size()? != 2 {
        return Err(M6Error::MalformedTransaction(
            "actual M6 must have exactly two outputs",
        ));
    }
    let ctip_output = cursor.output()?;
    let root_output = cursor.output()?;
    if cursor.u32_le()? != 0 || cursor.remaining() != 0 {
        return Err(M6Error::MalformedTransaction(
            "nonzero locktime or trailing transaction bytes",
        ));
    }
    if ctip_output.script != op_drivechain_script() {
        return Err(M6Error::MalformedTransaction(
            "replacement CTIP is not slot 24 at vout 0",
        ));
    }
    let root_commitment = decode_root_output(&root_output)?;
    Ok(ParsedActualM6 {
        input,
        new_ctip_value: ctip_output.value_sats,
        root_commitment,
    })
}

fn decode_root_output(output: &ParsedOutput) -> Result<Hash32, M6Error> {
    if output.value_sats != M6_ROOT_PAYOUT_SATS
        || output.script.len() != 41
        || output.script[..2] != [OP_RETURN, 39]
        || output.script[2..8] != M6_ROOT_PAYOUT_MAGIC
        || output.script[8] != M6_ROOT_PAYOUT_VERSION
    {
        return Err(M6Error::MalformedTransaction(
            "invalid one-satoshi USDD root payout",
        ));
    }
    Ok(Hash32(
        output.script[9..]
            .try_into()
            .expect("root output length checked"),
    ))
}

fn op_drivechain_script() -> [u8; 4] {
    [OP_DRIVECHAIN, 1, ELEMENTS_DRIVECHAIN_SLOT, OP_TRUE]
}

fn encode_blinded_transaction(blinded: BlindedM6, standard_zero_input: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&BITCOIN_TRANSACTION_VERSION.to_le_bytes());
    if standard_zero_input {
        out.extend_from_slice(&[0, 1, 0]); // marker, flag, zero vin count
    } else {
        out.push(0); // legacy zero vin count
    }
    encode_compact_size(2, &mut out);
    encode_output(0, &blinded.fee_script(), &mut out);
    encode_output(M6_ROOT_PAYOUT_SATS, &blinded.root_payout_script(), &mut out);
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

fn encode_output(value_sats: u64, script: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&value_sats.to_le_bytes());
    encode_compact_size(script.len() as u64, out);
    out.extend_from_slice(script);
}

fn encode_compact_size(value: u64, out: &mut Vec<u8>) {
    if value < 0xfd {
        out.push(value as u8);
    } else if value <= u16::MAX.into() {
        out.push(0xfd);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= u32::MAX.into() {
        out.push(0xfe);
        out.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn txid_display(serialized_without_witness: &[u8]) -> Hash32 {
    let mut display = double_sha256(serialized_without_witness);
    display.reverse();
    Hash32(display)
}

struct TxCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> TxCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], M6Error> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(M6Error::MalformedTransaction("length overflow"))?;
        let result = self
            .bytes
            .get(self.position..end)
            .ok_or(M6Error::MalformedTransaction("unexpected end"))?;
        self.position = end;
        Ok(result)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], M6Error> {
        Ok(self.take(N)?.try_into().expect("fixed transaction field"))
    }

    fn byte(&mut self) -> Result<u8, M6Error> {
        Ok(self.take(1)?[0])
    }

    fn u32_le(&mut self) -> Result<u32, M6Error> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }

    fn i32_le(&mut self) -> Result<i32, M6Error> {
        Ok(i32::from_le_bytes(self.fixed()?))
    }

    fn u64_le(&mut self) -> Result<u64, M6Error> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }

    fn compact_size(&mut self) -> Result<u64, M6Error> {
        let prefix = self.byte()?;
        self.compact_size_with_prefix(prefix)
    }

    fn compact_size_with_prefix(&mut self, prefix: u8) -> Result<u64, M6Error> {
        let value = match prefix {
            0..=0xfc => u64::from(prefix),
            0xfd => {
                let value = u16::from_le_bytes(self.fixed()?);
                if value < 0xfd {
                    return Err(M6Error::MalformedTransaction("noncanonical CompactSize"));
                }
                value.into()
            }
            0xfe => {
                let value = u32::from_le_bytes(self.fixed()?);
                if value <= u16::MAX.into() {
                    return Err(M6Error::MalformedTransaction("noncanonical CompactSize"));
                }
                value.into()
            }
            0xff => {
                let value = u64::from_le_bytes(self.fixed()?);
                if value <= u32::MAX.into() {
                    return Err(M6Error::MalformedTransaction("noncanonical CompactSize"));
                }
                value
            }
        };
        Ok(value)
    }

    fn output(&mut self) -> Result<ParsedOutput, M6Error> {
        let value_sats = self.u64_le()?;
        if value_sats > BITCOIN_MAX_MONEY_SATS {
            return Err(M6Error::MalformedTransaction("output exceeds MAX_MONEY"));
        }
        let script_len = usize::try_from(self.compact_size()?)
            .map_err(|_| M6Error::MalformedTransaction("script length overflow"))?;
        if script_len > 128 {
            return Err(M6Error::MalformedTransaction("M6 output script too large"));
        }
        let script = self.take(script_len)?.to_vec();
        Ok(ParsedOutput { value_sats, script })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use usdd_core::{Burn, BurnAccumulator, EthAddress};

    fn hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn claim(seed: u8, index: u64, prior_leaves: &[Hash32]) -> ApprovedClaimAppend {
        let burn = Burn {
            vault_id: hash(4),
            usdd_asset: hash(3),
            usdd_amount_base: 100,
            usdt_amount_micro: 1,
            burn_outpoint: OutPoint {
                txid: hash(seed),
                vout: seed.into(),
            },
            ethereum_destination: EthAddress([seed; 20]),
        };
        let claim = burn.redemption_claim(hash(2));
        let empty = burn_accumulator_empty(0).unwrap();
        let mut leaves = prior_leaves.to_vec();
        leaves.push(empty);
        let tree = BurnAccumulator::from_leaves(leaves).unwrap();
        let empty_branch = tree.proof(index).unwrap();
        ApprovedClaimAppend {
            claim,
            empty_branch,
        }
    }

    fn witness() -> ClaimBatchWitness {
        ClaimBatchWitness {
            bitcoin_genesis: hash(1),
            elements_genesis: hash(2),
            usdd_asset: hash(3),
            vault_id: hash(4),
            prior_claim_count: 0,
            prior_claim_root: burn_accumulator_empty(64).unwrap(),
            fee_sats: 1_000,
            claims: vec![claim(5, 0, &[])],
        }
    }

    fn bundle() -> MinerBundleArtifact {
        witness().derive_root_artifact().unwrap()
    }

    #[test]
    fn root_domain_and_preimage_are_frozen() {
        assert_eq!(
            hash_bytes(M6_ROOT_DOMAIN_PREIMAGE.as_bytes()),
            M6_ROOT_DOMAIN
        );
        let artifact = bundle();
        assert_eq!(artifact.root_commitment_preimage().unwrap().len(), 241);
        let commitment = artifact.root_commitment().unwrap();

        let mut changed = artifact.clone();
        changed.bitcoin_genesis = hash(9);
        assert_ne!(changed.root_commitment().unwrap(), commitment);
        let mut changed = artifact.clone();
        changed.prior_claim_count = 1;
        assert!(changed.validate().is_err());
    }

    #[test]
    fn vault_aware_validation_rejects_unpayable_self_payout() {
        let witness = witness();
        witness.validate_for_vault(EthAddress([9; 20])).unwrap();
        assert_eq!(
            witness.validate_for_vault(EthAddress([5; 20])),
            Err(M6Error::PayoutToVault)
        );
        assert_eq!(
            witness.validate_for_vault(EthAddress([0; 20])),
            Err(M6Error::InvalidVaultAddress)
        );
    }

    #[test]
    fn blinded_codec_matches_enforcer_rules_and_both_zero_input_frames() {
        let blinded = bundle().blinded_m6().unwrap();
        let legacy = blinded.legacy_bytes();
        let standard = blinded.standard_bytes();
        assert_eq!(&legacy[..6], &[2, 0, 0, 0, 0, 2]);
        assert_eq!(&standard[..8], &[2, 0, 0, 0, 0, 1, 0, 2]);
        assert_eq!(BlindedM6::decode(&legacy).unwrap(), blinded);
        assert_eq!(BlindedM6::decode(&standard).unwrap(), blinded);
        assert_eq!(blinded.m6id(), txid_display(&legacy));
        // Frozen against the exact transaction shape consumed by the checked-in
        // enforcer's `BlindedM6` and `compute_m6id` implementations.
        assert_eq!(
            blinded.root_commitment.to_string(),
            "dd6833a6a2db112477ab453d2886af0c9154de56f5e8fc8717e3f7974186b367"
        );
        assert_eq!(
            usdd_core::encode_hex(&legacy),
            "02000000000200000000000000000a6a0800000000000003e80100000000000000296a27555344444d3601dd6833a6a2db112477ab453d2886af0c9154de56f5e8fc8717e3f7974186b36700000000"
        );
        assert_eq!(
            usdd_core::encode_hex(&standard),
            "020000000001000200000000000000000a6a0800000000000003e80100000000000000296a27555344444d3601dd6833a6a2db112477ab453d2886af0c9154de56f5e8fc8717e3f7974186b36700000000"
        );
        assert_eq!(
            blinded.m6id().to_string(),
            "9cf04f94106990b941c4cd437435e376bf4bbd08671ddd8549169f251af6b5a9"
        );

        let mut zero_payout = legacy.clone();
        let payout_value_offset = 4 + 1 + 1 + 8 + 1 + 10;
        zero_payout[payout_value_offset..payout_value_offset + 8].fill(0);
        assert!(BlindedM6::decode(&zero_payout).is_err());

        let mut malformed = standard;
        malformed[5] = 2;
        assert!(BlindedM6::decode(&malformed).is_err());
    }

    #[test]
    fn elements_native_elwd_vector_round_trips_with_exact_byte_order() {
        // Frozen against Elements `drivechain_withdrawal_tests.cpp` and the
        // paired enforcer `native_withdrawal_m6_vector.rs`.
        let bytes = usdd_core::decode_hex(concat!(
            "02000000000300000000000000000a6a0800000000000003e8",
            "00000000000000004c6a4a",
            "454c5744013f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120",
            "185f5e5d5c5b5a595857565554535251504f4e4d4c4b4a4948474645444342414000000007",
            "b882010000000000160014606162636465666768696a6b6c6d6e6f7071727300000000"
        ))
        .expect("native vector hex");
        let native = NativeWithdrawalM6::decode_legacy(&bytes).expect("native vector");
        assert_eq!(native.legacy_bytes(), bytes);
        assert_eq!(native.parent_fee_sats(), 1_000);
        assert_eq!(native.payout_sats(), 99_000);
        assert_eq!(
            usdd_core::encode_hex(native.destination_script()),
            "0014606162636465666768696a6b6c6d6e6f70717273"
        );
        assert_eq!(native.reference().sidechain_slot(), 24);
        assert_eq!(
            native.reference().elements_genesis().to_string(),
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        );
        assert_eq!(
            native.reference().burn_outpoint().txid.to_string(),
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        );
        assert_eq!(native.reference().burn_outpoint().vout, 7);
        assert_eq!(
            native.m6id().to_string(),
            "a7e1da09da7c62eda3f3bcb3902d6a79bb1d4a348858346c4152c10b714d3572"
        );

        let prior = Ctip {
            outpoint: OutPoint {
                txid: Hash32(core::array::from_fn(|index| index as u8)),
                vout: 5,
            },
            value_sats: 1_000_000,
        };
        let actual = native
            .actual_transaction_bytes(&prior)
            .expect("native actual M6");
        native
            .verify_actual_transaction(&actual, &prior)
            .expect("exact actual round trip");
        assert_eq!(native.successor_ctip_value(&prior).unwrap(), 900_000);
        assert_eq!(native.successor_ctip(&prior).unwrap().outpoint.vout, 0);
        assert_eq!(
            &actual[5..37],
            prior
                .outpoint
                .txid
                .0
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn native_elwd_decoder_rejects_marker_only_and_encoding_aliases() {
        let canonical = usdd_core::decode_hex(concat!(
            "02000000000300000000000000000a6a0800000000000003e8",
            "00000000000000004c6a4a",
            "454c5744013f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120",
            "185f5e5d5c5b5a595857565554535251504f4e4d4c4b4a4948474645444342414000000007",
            "b882010000000000160014606162636465666768696a6b6c6d6e6f7071727300000000"
        ))
        .unwrap();
        let reference_offset = canonical
            .windows(NATIVE_WITHDRAWAL_REFERENCE_MAGIC.len())
            .position(|window| window == NATIVE_WITHDRAWAL_REFERENCE_MAGIC)
            .expect("ELWD marker");

        let rejected = |mutated: Vec<u8>| {
            assert!(
                NativeWithdrawalM6::decode_legacy(&mutated).is_err(),
                "marker-only mutation unexpectedly decoded"
            );
        };

        let mut mutated = canonical.clone();
        mutated[0] = 1;
        rejected(mutated);
        let mut mutated = canonical.clone();
        mutated[5] = 2;
        rejected(mutated);
        let mut mutated = canonical.clone();
        mutated[reference_offset] ^= 1;
        rejected(mutated);
        let mut mutated = canonical.clone();
        mutated[reference_offset - 1] = 0x4c;
        rejected(mutated);
        let mut mutated = canonical.clone();
        mutated[reference_offset - 2] = 1;
        rejected(mutated);
        let mut mutated = canonical.clone();
        mutated.extend_from_slice(&[0]);
        rejected(mutated);

        // Internal/display reversal and the big-endian vout are intentional:
        // byte-reversed lookalikes remain syntactically decodable but identify
        // a different chain or burn and therefore cannot satisfy identity
        // matching in the replay.
        let mut wrong_genesis = canonical.clone();
        wrong_genesis[reference_offset + 5..reference_offset + 37].reverse();
        let parsed = NativeWithdrawalM6::decode_legacy(&wrong_genesis).unwrap();
        assert_ne!(
            parsed.reference().elements_genesis(),
            NativeWithdrawalM6::decode_legacy(&canonical)
                .unwrap()
                .reference()
                .elements_genesis()
        );
        let mut wrong_vout = canonical;
        wrong_vout[reference_offset + 70..reference_offset + 74].reverse();
        assert_eq!(
            NativeWithdrawalM6::decode_legacy(&wrong_vout)
                .unwrap()
                .reference()
                .burn_outpoint()
                .vout,
            0x0700_0000
        );
    }

    #[test]
    fn actual_m6_reconstructs_blinded_id_and_tracks_vout_zero_successor() {
        let artifact = bundle();
        let ctip = Ctip {
            outpoint: OutPoint {
                txid: Hash32(core::array::from_fn(|index| index as u8)),
                vout: 7,
            },
            value_sats: 10_000,
        };
        let actual = ActualM6Artifact::build(artifact, ctip.clone()).unwrap();
        let bytes = actual.transaction_bytes().unwrap();
        actual.verify_transaction(&bytes).unwrap();
        assert_eq!(
            usdd_core::encode_hex(&bytes),
            "02000000011f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201000700000000ffffffff02272300000000000004b40118510100000000000000296a27555344444d3601dd6833a6a2db112477ab453d2886af0c9154de56f5e8fc8717e3f7974186b36700000000"
        );
        assert_eq!(
            actual.transaction_id().unwrap().to_string(),
            "641c51cde9625227dd15e9f8482d0c62700b3824d7bef9f5e83a689120f8acca"
        );
        assert_eq!(actual.successor_ctip_value(), 8_999);
        let successor = actual.successor_ctip().unwrap();
        assert_eq!(successor.outpoint.vout, 0);
        assert_eq!(successor.value_sats, 8_999);
        assert_eq!(
            &bytes[5..37],
            ctip.outpoint
                .txid
                .0
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>()
        );

        let mut wrong_vout = bytes.clone();
        let output_zero_index = 4 + 1 + 32 + 4 + 1 + 4 + 1;
        // Change the slot-24 CTIP script at actual vout 0.
        let script_start = output_zero_index + 8 + 1;
        wrong_vout[script_start + 2] = 23;
        assert!(actual.verify_transaction(&wrong_vout).is_err());

        // A distinct same-block successor spend must reference the first M6
        // txid:vout0 while advancing from the first committed root.
        let first_transition = actual.bundle.validate().unwrap();
        let first_leaf = witness().claims[0]
            .claim
            .approved_redemption_leaf(0)
            .unwrap();
        let second_witness = ClaimBatchWitness {
            prior_claim_count: first_transition.next_claim_count,
            prior_claim_root: first_transition.next_claim_root,
            claims: vec![claim(6, 1, &[first_leaf])],
            ..witness()
        };
        let second_bundle = second_witness.derive_root_artifact().unwrap();
        let second = ActualM6Artifact::build(second_bundle, successor.clone()).unwrap();
        let second_bytes = second.transaction_bytes().unwrap();
        second.verify_transaction(&second_bytes).unwrap();
        let parsed = parse_actual_m6(&second_bytes).unwrap();
        assert_eq!(parsed.input, successor.outpoint);
        assert_ne!(second.bundle.m6id().unwrap(), actual.bundle.m6id().unwrap());
    }

    #[test]
    fn claim_bounds_and_actual_parser_fail_closed() {
        let mut empty = witness();
        empty.claims.clear();
        assert_eq!(
            empty.derive_root_artifact(),
            Err(M6Error::AuditWitnessClaimCount)
        );

        let mut oversized = witness();
        oversized.claims =
            vec![oversized.claims[0].clone(); MAX_APPROVED_CLAIMS_PER_AUDIT_WITNESS + 1];
        assert_eq!(
            oversized.derive_root_artifact(),
            Err(M6Error::AuditWitnessClaimCount)
        );

        let mut arbitrary_large_delta = bundle();
        arbitrary_large_delta.next_claim_count = u64::MAX;
        arbitrary_large_delta.next_claim_root = hash(10);
        assert!(arbitrary_large_delta.validate().is_ok());

        let actual = ActualM6Artifact::build(
            bundle(),
            Ctip {
                outpoint: OutPoint {
                    txid: hash(8),
                    vout: 0,
                },
                value_sats: 2_000,
            },
        )
        .unwrap();
        let bytes = actual.transaction_bytes().unwrap();

        let mut wrong_input = bytes.clone();
        wrong_input[5] ^= 1;
        assert!(actual.verify_transaction(&wrong_input).is_err());

        let mut wrong_locktime = bytes.clone();
        *wrong_locktime.last_mut().unwrap() = 1;
        assert!(actual.verify_transaction(&wrong_locktime).is_err());

        let mut trailing = bytes;
        trailing.push(0);
        assert!(actual.verify_transaction(&trailing).is_err());
    }

    #[test]
    fn permissionless_artifacts_round_trip_and_reject_replay_or_corruption() {
        let artifact = bundle();
        let encoded = artifact.encode();
        assert_eq!(
            MinerBundleArtifact::decode_artifact(&encoded).unwrap(),
            artifact
        );
        let id = artifact.artifact_id().unwrap();
        assert_ne!(id, artifact.m6id().unwrap());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            MinerBundleArtifact::decode_artifact(&trailing),
            Err(M6Error::TrailingBytes)
        );

        let actual = ActualM6Artifact::build(
            artifact,
            Ctip {
                outpoint: OutPoint {
                    txid: hash(8),
                    vout: 0,
                },
                value_sats: 2_000,
            },
        )
        .unwrap();
        let actual_bytes = actual.encode();
        assert_eq!(
            ActualM6Artifact::decode_artifact(&actual_bytes).unwrap(),
            actual
        );
    }
}
