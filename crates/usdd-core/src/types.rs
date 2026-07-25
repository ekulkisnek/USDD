use alloc::vec::Vec;
use core::{fmt, str::FromStr};

use crate::{
    encoding::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder},
    hash::{decode_hex, hash_bytes, Hash32, HexError},
    usdd_base_to_usdt_micro, usdt_micro_to_usdd_base, ENCODING_SCHEMA,
    MAX_APPROVED_CLAIMS_PER_ROOT_UPDATE, MAX_BURN_AMOUNT_USDD_BASE, MAX_BURN_AMOUNT_USDT_MICRO,
    MAX_DEPOSIT_AMOUNT_USDT_MICRO, MAX_ETHEREUM_FINALITY_SLOT_GAP,
    MAX_FINALIZED_TO_BMM_MTP_AGE_SECONDS, MAX_MINT_BATCH_USDD_BASE, MAX_MINT_BATCH_USDT_MICRO,
    USDD_UNITS_PER_USDT_MICRO,
};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_MINT_BATCH_SIZE: usize = 64;
pub const MAX_ELEMENTS_SCRIPT_LENGTH: usize = 128;

/// `keccak256("USDD_DEPOSIT_ID_V1")`, matching `USDDVaultV1.sol`.
pub const SOLIDITY_DEPOSIT_ID_DOMAIN: Hash32 = Hash32([
    0xc0, 0xbb, 0x4b, 0x99, 0x2d, 0xdf, 0xe4, 0x2d, 0x70, 0x53, 0x63, 0x46, 0xa5, 0x94, 0xfd, 0x97,
    0x50, 0xdb, 0xf7, 0xe1, 0x05, 0x34, 0xed, 0x34, 0xae, 0xcd, 0xc7, 0x8d, 0x20, 0x3b, 0x88, 0xe0,
]);

/// `keccak256("USDD_BIP300_REDEMPTION_LEAF_V1")`, matching
/// `USDDVaultV1.sol`.
pub const SOLIDITY_APPROVED_REDEMPTION_LEAF_DOMAIN: Hash32 = Hash32([
    0xa2, 0x04, 0x23, 0x80, 0x92, 0x68, 0x79, 0x09, 0x8c, 0x0f, 0x42, 0x3f, 0x49, 0xe3, 0xa0, 0x7a,
    0x12, 0x48, 0xed, 0x08, 0x53, 0x57, 0x93, 0xa4, 0xa1, 0xc4, 0xaf, 0xe6, 0x2d, 0x99, 0x88, 0x69,
]);

/// `SHA256("USDD_BURN_ID_V1")`, shared by Elements, guests, and vaults.
pub const BURN_ID_DOMAIN: Hash32 = Hash32([
    0x58, 0x11, 0xf3, 0xff, 0x8b, 0x8f, 0x31, 0xfb, 0x49, 0xff, 0xb9, 0x1a, 0xfa, 0xb1, 0x31, 0x97,
    0xc3, 0xd7, 0x2e, 0x92, 0x65, 0x49, 0xae, 0x29, 0xdb, 0xda, 0x46, 0xc6, 0x99, 0x8a, 0x3e, 0x45,
]);

const TAG_VAULT_DEPOSIT: u16 = 0x0101;
const TAG_ETHEREUM_FINALITY: u16 = 0x0102;
const TAG_MINT_OUTPUT: u16 = 0x0103;
const TAG_MINT_BATCH: u16 = 0x0104;
const TAG_BURN: u16 = 0x0201;
const TAG_ELEMENTS_EVENT: u16 = 0x0202;
const TAG_REDEMPTION_CLAIM: u16 = 0x0203;
const TAG_APPROVED_REDEMPTION_STATE: u16 = 0x0204;

fn encode_header(tag: u16, out: &mut Vec<u8>) {
    ENCODING_SCHEMA.encode_to(out);
    tag.encode_to(out);
}

fn decode_header(decoder: &mut Decoder<'_>, expected_tag: u16) -> Result<(), DecodeError> {
    if decoder.u16()? != ENCODING_SCHEMA {
        return Err(DecodeError::InvalidValue("unsupported encoding schema"));
    }
    let tag = decoder.u16()?;
    if tag != expected_tag {
        return Err(DecodeError::InvalidTag {
            type_name: "record",
            tag: tag.into(),
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EthAddress(pub [u8; 20]);

impl EthAddress {
    pub const ZERO: Self = Self([0; 20]);

    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 20]
    }

    pub fn to_hex(self) -> alloc::string::String {
        crate::encode_hex(&self.0)
    }
}

impl fmt::Debug for EthAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EthAddress({self})")
    }
}

impl fmt::Display for EthAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

impl FromStr for EthAddress {
    type Err = HexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = decode_hex(value)?;
        if bytes.len() != 20 {
            return Err(HexError::WrongLength {
                expected: 20,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.try_into().expect("length checked")))
    }
}

impl CanonicalEncode for EthAddress {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.0.encode_to(out);
    }
}

impl CanonicalDecode for EthAddress {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self(decoder.fixed()?))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutPoint {
    /// Canonical RPC/display-order txid bytes. Code using an internal
    /// consensus-order hash representation must reverse/convert explicitly.
    pub txid: Hash32,
    pub vout: u32,
}

impl CanonicalEncode for OutPoint {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.txid.encode_to(out);
        self.vout.encode_to(out);
    }
}

impl CanonicalDecode for OutPoint {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            txid: Hash32::decode_from(decoder)?,
            vout: decoder.u32()?,
        })
    }
}

/// Vault-owned deposit fields. Finality headers are deliberately excluded so
/// this record hashes exactly like `USDDVaultV1.depositCommitmentByNonce`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultDeposit {
    pub ethereum_chain_id: u64,
    pub vault: EthAddress,
    pub usdt: EthAddress,
    pub nonce: u64,
    pub depositor: EthAddress,
    pub usdt_amount_micro: u64,
    pub elements_script: Vec<u8>,
    pub user_salt: Hash32,
}

/// Compatibility name for callers that use the shorter protocol term.
pub type Deposit = VaultDeposit;

impl VaultDeposit {
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.ethereum_chain_id == 0 {
            return Err(DecodeError::InvalidValue("Ethereum chain ID is zero"));
        }
        if self.vault.is_zero() || self.usdt.is_zero() || self.depositor.is_zero() {
            return Err(DecodeError::InvalidValue("zero Ethereum address"));
        }
        if self.usdt_amount_micro == 0
            || self.usdt_amount_micro > MAX_DEPOSIT_AMOUNT_USDT_MICRO
            || usdt_micro_to_usdd_base(self.usdt_amount_micro).is_none()
        {
            return Err(DecodeError::InvalidValue(
                "invalid, excessive, or overflowing USDT amount",
            ));
        }
        if self.elements_script.is_empty()
            || self.elements_script.len() > MAX_ELEMENTS_SCRIPT_LENGTH
        {
            return Err(DecodeError::InvalidValue("invalid Elements script length"));
        }
        Ok(())
    }

    pub fn elements_script_hash(&self) -> Hash32 {
        hash_bytes(&self.elements_script)
    }

    /// Solidity-compatible packed commitment:
    ///
    /// `SHA256(keccak256("USDD_DEPOSIT_ID_V1") || uint32(1) ||
    /// uint256(chainid) || vault || USDT || uint64(nonce) || depositor ||
    /// uint64(amount) || SHA256(raw_script) || user_salt)`.
    pub fn deposit_id(&self) -> Hash32 {
        let mut preimage = Vec::with_capacity(208);
        SOLIDITY_DEPOSIT_ID_DOMAIN.encode_to(&mut preimage);
        PROTOCOL_VERSION.encode_to(&mut preimage);
        let mut chain_id_u256 = [0u8; 32];
        chain_id_u256[24..].copy_from_slice(&self.ethereum_chain_id.to_be_bytes());
        chain_id_u256.encode_to(&mut preimage);
        self.vault.encode_to(&mut preimage);
        self.usdt.encode_to(&mut preimage);
        self.nonce.encode_to(&mut preimage);
        self.depositor.encode_to(&mut preimage);
        self.usdt_amount_micro.encode_to(&mut preimage);
        self.elements_script_hash().encode_to(&mut preimage);
        self.user_salt.encode_to(&mut preimage);
        debug_assert_eq!(preimage.len(), 208);
        hash_bytes(&preimage)
    }

    pub fn usdd_amount_base(&self) -> u64 {
        usdt_micro_to_usdd_base(self.usdt_amount_micro).expect("validated deposits cannot overflow")
    }
}

impl CanonicalEncode for VaultDeposit {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_VAULT_DEPOSIT, out);
        self.ethereum_chain_id.encode_to(out);
        self.vault.encode_to(out);
        self.usdt.encode_to(out);
        self.nonce.encode_to(out);
        self.depositor.encode_to(out);
        self.usdt_amount_micro.encode_to(out);
        self.elements_script.encode_to(out);
        self.user_salt.encode_to(out);
    }
}

impl CanonicalDecode for VaultDeposit {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_VAULT_DEPOSIT)?;
        let value = Self {
            ethereum_chain_id: decoder.u64()?,
            vault: EthAddress::decode_from(decoder)?,
            usdt: EthAddress::decode_from(decoder)?,
            nonce: decoder.u64()?,
            depositor: EthAddress::decode_from(decoder)?,
            usdt_amount_micro: decoder.u64()?,
            elements_script: decoder.bytes()?,
            user_salt: Hash32::decode_from(decoder)?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Finality data proved by the Ethereum guest, never included in a vault
/// deposit ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumFinalityWitness {
    pub ethereum_light_client_digest: Hash32,
    pub finalized_beacon_slot: u64,
    pub finalized_beacon_root: Hash32,
    pub finalized_execution_block: Hash32,
    pub finalized_execution_state_root: Hash32,
    pub execution_block_number: u64,
    pub execution_block_timestamp: u64,
}

impl EthereumFinalityWitness {
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.finalized_beacon_slot == 0
            || self.ethereum_light_client_digest == Hash32::ZERO
            || self.finalized_beacon_root == Hash32::ZERO
            || self.finalized_execution_block == Hash32::ZERO
            || self.finalized_execution_state_root == Hash32::ZERO
        {
            return Err(DecodeError::InvalidValue(
                "invalid Ethereum finality witness",
            ));
        }
        Ok(())
    }
}

impl CanonicalEncode for EthereumFinalityWitness {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_ETHEREUM_FINALITY, out);
        self.ethereum_light_client_digest.encode_to(out);
        self.finalized_beacon_slot.encode_to(out);
        self.finalized_beacon_root.encode_to(out);
        self.finalized_execution_block.encode_to(out);
        self.finalized_execution_state_root.encode_to(out);
        self.execution_block_number.encode_to(out);
        self.execution_block_timestamp.encode_to(out);
    }
}

impl CanonicalDecode for EthereumFinalityWitness {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_ETHEREUM_FINALITY)?;
        let value = Self {
            ethereum_light_client_digest: Hash32::decode_from(decoder)?,
            finalized_beacon_slot: decoder.u64()?,
            finalized_beacon_root: Hash32::decode_from(decoder)?,
            finalized_execution_block: Hash32::decode_from(decoder)?,
            finalized_execution_state_root: Hash32::decode_from(decoder)?,
            execution_block_number: decoder.u64()?,
            execution_block_timestamp: decoder.u64()?,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintOutput {
    pub deposit_id: Hash32,
    pub nonce: u64,
    pub usdt_amount_micro: u64,
    pub usdd_amount_base: u64,
    /// Exact script, not only a caller-provided hash. The transaction policy
    /// must pay this script the corresponding amount.
    pub elements_script: Vec<u8>,
}

impl MintOutput {
    pub fn from_deposit(deposit: &VaultDeposit) -> Result<Self, DecodeError> {
        deposit.validate()?;
        Ok(Self {
            deposit_id: deposit.deposit_id(),
            nonce: deposit.nonce,
            usdt_amount_micro: deposit.usdt_amount_micro,
            usdd_amount_base: deposit.usdd_amount_base(),
            elements_script: deposit.elements_script.clone(),
        })
    }

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.deposit_id == Hash32::ZERO {
            return Err(DecodeError::InvalidValue("zero deposit ID"));
        }
        if self.usdt_amount_micro == 0
            || self.usdt_amount_micro > MAX_DEPOSIT_AMOUNT_USDT_MICRO
            || usdt_micro_to_usdd_base(self.usdt_amount_micro) != Some(self.usdd_amount_base)
        {
            return Err(DecodeError::InvalidValue("USDT/USDD conversion mismatch"));
        }
        if self.elements_script.is_empty()
            || self.elements_script.len() > MAX_ELEMENTS_SCRIPT_LENGTH
        {
            return Err(DecodeError::InvalidValue("invalid Elements script length"));
        }
        Ok(())
    }
}

impl CanonicalEncode for MintOutput {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_MINT_OUTPUT, out);
        self.deposit_id.encode_to(out);
        self.nonce.encode_to(out);
        self.usdt_amount_micro.encode_to(out);
        self.usdd_amount_base.encode_to(out);
        self.elements_script.encode_to(out);
    }
}

impl CanonicalDecode for MintOutput {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_MINT_OUTPUT)?;
        let value = Self {
            deposit_id: Hash32::decode_from(decoder)?,
            nonce: decoder.u64()?,
            usdt_amount_micro: decoder.u64()?,
            usdd_amount_base: decoder.u64()?,
            elements_script: decoder.bytes()?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// One controller transition can mint 1..64 consecutive deposits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintBatch {
    pub first_nonce: u64,
    pub next_nonce: u64,
    pub outputs: Vec<MintOutput>,
    pub total_usdt_amount_micro: u64,
    pub total_usdd_amount_base: u64,
}

impl MintBatch {
    pub fn from_deposits(deposits: &[VaultDeposit]) -> Result<Self, DecodeError> {
        if deposits.is_empty() || deposits.len() > MAX_MINT_BATCH_SIZE {
            return Err(DecodeError::InvalidValue("mint batch size must be 1..64"));
        }
        let first = &deposits[0];
        first.validate()?;
        let mut outputs = Vec::with_capacity(deposits.len());
        for (offset, deposit) in deposits.iter().enumerate() {
            deposit.validate()?;
            let offset = u64::try_from(offset)
                .map_err(|_| DecodeError::InvalidValue("batch offset overflow"))?;
            let expected_nonce = first
                .nonce
                .checked_add(offset)
                .ok_or(DecodeError::InvalidValue("batch nonce overflow"))?;
            if deposit.nonce != expected_nonce {
                return Err(DecodeError::InvalidValue(
                    "mint batch deposit nonces are not consecutive",
                ));
            }
            if deposit.ethereum_chain_id != first.ethereum_chain_id
                || deposit.vault != first.vault
                || deposit.usdt != first.usdt
            {
                return Err(DecodeError::InvalidValue(
                    "mint batch mixes chains, vaults, or tokens",
                ));
            }
            outputs.push(MintOutput::from_deposit(deposit)?);
        }
        let next_nonce = first
            .nonce
            .checked_add(deposits.len() as u64)
            .ok_or(DecodeError::InvalidValue("batch next nonce overflow"))?;
        let total_usdt_amount_micro = outputs.iter().try_fold(0u64, |total, output| {
            total
                .checked_add(output.usdt_amount_micro)
                .ok_or(DecodeError::InvalidValue("batch USDT total overflow"))
        })?;
        let total_usdd_amount_base = outputs.iter().try_fold(0u64, |total, output| {
            total
                .checked_add(output.usdd_amount_base)
                .ok_or(DecodeError::InvalidValue("batch USDD total overflow"))
        })?;
        if total_usdt_amount_micro > MAX_MINT_BATCH_USDT_MICRO
            || total_usdd_amount_base > MAX_MINT_BATCH_USDD_BASE
        {
            return Err(DecodeError::InvalidValue(
                "mint batch exceeds Elements explicit-output budget",
            ));
        }
        Ok(Self {
            first_nonce: first.nonce,
            next_nonce,
            outputs,
            total_usdt_amount_micro,
            total_usdd_amount_base,
        })
    }

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.outputs.is_empty() || self.outputs.len() > MAX_MINT_BATCH_SIZE {
            return Err(DecodeError::InvalidValue("mint batch size must be 1..64"));
        }
        let expected_next = self
            .first_nonce
            .checked_add(self.outputs.len() as u64)
            .ok_or(DecodeError::InvalidValue("batch next nonce overflow"))?;
        if self.next_nonce != expected_next {
            return Err(DecodeError::InvalidValue("wrong batch next nonce"));
        }
        let mut usdt_total = 0u64;
        let mut usdd_total = 0u64;
        for (offset, output) in self.outputs.iter().enumerate() {
            output.validate()?;
            let expected_nonce = self
                .first_nonce
                .checked_add(offset as u64)
                .ok_or(DecodeError::InvalidValue("batch nonce overflow"))?;
            if output.nonce != expected_nonce {
                return Err(DecodeError::InvalidValue(
                    "mint output nonces are not consecutive",
                ));
            }
            usdt_total = usdt_total
                .checked_add(output.usdt_amount_micro)
                .ok_or(DecodeError::InvalidValue("batch USDT total overflow"))?;
            usdd_total = usdd_total
                .checked_add(output.usdd_amount_base)
                .ok_or(DecodeError::InvalidValue("batch USDD total overflow"))?;
        }
        if usdt_total != self.total_usdt_amount_micro
            || usdd_total != self.total_usdd_amount_base
            || usdt_micro_to_usdd_base(usdt_total) != Some(usdd_total)
        {
            return Err(DecodeError::InvalidValue("wrong mint batch totals"));
        }
        if usdt_total > MAX_MINT_BATCH_USDT_MICRO || usdd_total > MAX_MINT_BATCH_USDD_BASE {
            return Err(DecodeError::InvalidValue(
                "mint batch exceeds Elements explicit-output budget",
            ));
        }
        Ok(())
    }
}

impl CanonicalEncode for MintBatch {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_MINT_BATCH, out);
        self.first_nonce.encode_to(out);
        self.next_nonce.encode_to(out);
        let count = u8::try_from(self.outputs.len()).expect("mint batch count fits u8");
        count.encode_to(out);
        for output in &self.outputs {
            output.encode_to(out);
        }
        self.total_usdt_amount_micro.encode_to(out);
        self.total_usdd_amount_base.encode_to(out);
    }
}

impl CanonicalDecode for MintBatch {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_MINT_BATCH)?;
        let first_nonce = decoder.u64()?;
        let next_nonce = decoder.u64()?;
        let count = decoder.u8()? as usize;
        if count == 0 || count > MAX_MINT_BATCH_SIZE {
            return Err(DecodeError::InvalidValue("mint batch size must be 1..64"));
        }
        let mut outputs = Vec::with_capacity(count);
        for _ in 0..count {
            outputs.push(MintOutput::decode_from(decoder)?);
        }
        let value = Self {
            first_nonce,
            next_nonce,
            outputs,
            total_usdt_amount_micro: decoder.u64()?,
            total_usdd_amount_base: decoder.u64()?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Compatibility name for one recipient-level mint record.
pub type Mint = MintOutput;

/// Irreversible Elements burn authorizing a retryable Ethereum payout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Burn {
    pub vault_id: Hash32,
    pub usdd_asset: Hash32,
    pub usdd_amount_base: u64,
    pub usdt_amount_micro: u64,
    pub burn_outpoint: OutPoint,
    pub ethereum_destination: EthAddress,
}

impl Burn {
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.vault_id == Hash32::ZERO || self.ethereum_destination.is_zero() {
            return Err(DecodeError::InvalidValue("invalid vault or destination"));
        }
        if self.usdd_asset == Hash32::ZERO
            || self.burn_outpoint.txid == Hash32::ZERO
            || self.usdd_amount_base == 0
        {
            return Err(DecodeError::InvalidValue(
                "invalid burn asset, outpoint, or amount",
            ));
        }
        if usdd_base_to_usdt_micro(self.usdd_amount_base) != Some(self.usdt_amount_micro) {
            return Err(DecodeError::InvalidValue(
                "burn is not exactly convertible to micro-USDT",
            ));
        }
        if self.usdd_amount_base > MAX_BURN_AMOUNT_USDD_BASE {
            return Err(DecodeError::InvalidValue(
                "burn exceeds Elements explicit-output limit",
            ));
        }
        Ok(())
    }

    /// Apply the immutable Ethereum vault's no-self-payout rule when the
    /// deployment address is available.
    pub fn validate_for_vault(&self, expected_vault: EthAddress) -> Result<(), DecodeError> {
        self.validate()?;
        if expected_vault.is_zero() || self.ethereum_destination == expected_vault {
            return Err(DecodeError::InvalidValue(
                "burn destination must not be the configured vault",
            ));
        }
        Ok(())
    }

    pub fn redemption_id(&self, elements_genesis: Hash32) -> Hash32 {
        let mut payload = Vec::with_capacity(100);
        BURN_ID_DOMAIN.encode_to(&mut payload);
        elements_genesis.encode_to(&mut payload);
        self.burn_outpoint.txid.encode_to(&mut payload);
        self.burn_outpoint.vout.encode_to(&mut payload);
        debug_assert_eq!(payload.len(), 100);
        hash_bytes(&payload)
    }

    pub fn burn_payload(&self) -> BurnPayload {
        BurnPayload {
            vault_id: self.vault_id,
            ethereum_recipient: self.ethereum_destination,
            amount_usdt_micro: self.usdt_amount_micro,
        }
    }

    pub fn redemption_claim(&self, elements_genesis: Hash32) -> RedemptionClaim {
        RedemptionClaim {
            protocol_version: PROTOCOL_VERSION,
            elements_genesis_hash: elements_genesis,
            usdd_asset_id: self.usdd_asset,
            vault_id: self.vault_id,
            burn_txid_display: self.burn_outpoint.txid,
            burn_vout: self.burn_outpoint.vout,
            burn_id: self.redemption_id(elements_genesis),
            amount_usdt_micro: self.usdt_amount_micro,
            recipient: self.ethereum_destination,
        }
    }

    /// Backward-compatible constructor name for the same fixed claim fields.
    pub fn solidity_claim(&self, elements_genesis: Hash32) -> RedemptionClaim {
        self.redemption_claim(elements_genesis)
    }
}

/// Exact 65-byte Elements burn payload:
/// `"USDD" || version:u8 || vault_id[32] || recipient[20] || amount:u64be`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BurnPayload {
    pub vault_id: Hash32,
    pub ethereum_recipient: EthAddress,
    pub amount_usdt_micro: u64,
}

impl BurnPayload {
    pub const ENCODED_LENGTH: usize = 65;

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.vault_id == Hash32::ZERO
            || self.ethereum_recipient.is_zero()
            || self.amount_usdt_micro == 0
            || self.amount_usdt_micro > MAX_BURN_AMOUNT_USDT_MICRO
            || usdt_micro_to_usdd_base(self.amount_usdt_micro).is_none()
        {
            return Err(DecodeError::InvalidValue("invalid burn payload"));
        }
        Ok(())
    }
}

impl CanonicalEncode for BurnPayload {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"USDD");
        1u8.encode_to(out);
        self.vault_id.encode_to(out);
        self.ethereum_recipient.encode_to(out);
        self.amount_usdt_micro.encode_to(out);
    }
}

impl CanonicalDecode for BurnPayload {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder.fixed::<4>()? != *b"USDD" || decoder.u8()? != 1 {
            return Err(DecodeError::InvalidValue("invalid burn payload header"));
        }
        let value = Self {
            vault_id: Hash32::decode_from(decoder)?,
            ethereum_recipient: EthAddress::decode_from(decoder)?,
            amount_usdt_micro: decoder.u64()?,
        };
        value.validate()?;
        Ok(value)
    }
}

impl CanonicalEncode for Burn {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_BURN, out);
        self.vault_id.encode_to(out);
        self.usdd_asset.encode_to(out);
        self.usdd_amount_base.encode_to(out);
        self.usdt_amount_micro.encode_to(out);
        self.burn_outpoint.encode_to(out);
        self.ethereum_destination.encode_to(out);
    }
}

impl CanonicalDecode for Burn {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_BURN)?;
        let value = Self {
            vault_id: Hash32::decode_from(decoder)?,
            usdd_asset: Hash32::decode_from(decoder)?,
            usdd_amount_base: decoder.u64()?,
            usdt_amount_micro: decoder.u64()?,
            burn_outpoint: OutPoint::decode_from(decoder)?,
            ethereum_destination: EthAddress::decode_from(decoder)?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Exact fixed-width claim consumed by
/// `USDDVaultV1.hashApprovedRedemptionLeaf` after BIP300 M6 approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedemptionClaim {
    pub protocol_version: u32,
    pub elements_genesis_hash: Hash32,
    pub usdd_asset_id: Hash32,
    pub vault_id: Hash32,
    pub burn_txid_display: Hash32,
    pub burn_vout: u32,
    pub burn_id: Hash32,
    pub amount_usdt_micro: u64,
    pub recipient: EthAddress,
}

impl RedemptionClaim {
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.protocol_version != PROTOCOL_VERSION
            || self.elements_genesis_hash == Hash32::ZERO
            || self.usdd_asset_id == Hash32::ZERO
            || self.vault_id == Hash32::ZERO
            || self.burn_txid_display == Hash32::ZERO
            || self.burn_id == Hash32::ZERO
            || self.amount_usdt_micro == 0
            || self.amount_usdt_micro > MAX_BURN_AMOUNT_USDT_MICRO
            || self.recipient.is_zero()
        {
            return Err(DecodeError::InvalidValue("invalid redemption claim"));
        }
        let mut identity_preimage = Vec::with_capacity(100);
        BURN_ID_DOMAIN.encode_to(&mut identity_preimage);
        self.elements_genesis_hash.encode_to(&mut identity_preimage);
        self.burn_txid_display.encode_to(&mut identity_preimage);
        self.burn_vout.encode_to(&mut identity_preimage);
        if hash_bytes(&identity_preimage) != self.burn_id {
            return Err(DecodeError::InvalidValue("burn ID does not bind outpoint"));
        }
        Ok(())
    }

    /// Apply the Ethereum vault's destination rule when the deployment address
    /// is available. The fixed claim bytes carry `vault_id`, not the address,
    /// so context-free decoding cannot enforce this rule by itself.
    pub fn validate_for_vault(&self, expected_vault: EthAddress) -> Result<(), DecodeError> {
        self.validate()?;
        if expected_vault.is_zero() || self.recipient == expected_vault {
            return Err(DecodeError::InvalidValue(
                "redemption recipient must not be the configured vault",
            ));
        }
        Ok(())
    }

    pub fn approved_redemption_leaf(&self, claim_index: u64) -> Result<Hash32, DecodeError> {
        self.validate()?;
        let mut preimage = Vec::with_capacity(201);
        0u8.encode_to(&mut preimage);
        SOLIDITY_APPROVED_REDEMPTION_LEAF_DOMAIN.encode_to(&mut preimage);
        self.protocol_version.encode_to(&mut preimage);
        self.elements_genesis_hash.encode_to(&mut preimage);
        self.usdd_asset_id.encode_to(&mut preimage);
        self.vault_id.encode_to(&mut preimage);
        self.burn_id.encode_to(&mut preimage);
        claim_index.encode_to(&mut preimage);
        self.amount_usdt_micro.encode_to(&mut preimage);
        self.recipient.encode_to(&mut preimage);
        debug_assert_eq!(preimage.len(), 201);
        Ok(hash_bytes(&preimage))
    }

    /// Backward-compatible method name. The leaf is authorization evidence
    /// from an approved BIP300 bundle, not proof of Elements burn validity.
    pub fn burn_leaf(&self, claim_index: u64) -> Result<Hash32, DecodeError> {
        self.approved_redemption_leaf(claim_index)
    }
}

impl CanonicalEncode for RedemptionClaim {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_REDEMPTION_CLAIM, out);
        self.protocol_version.encode_to(out);
        self.elements_genesis_hash.encode_to(out);
        self.usdd_asset_id.encode_to(out);
        self.vault_id.encode_to(out);
        self.burn_txid_display.encode_to(out);
        self.burn_vout.encode_to(out);
        self.burn_id.encode_to(out);
        self.amount_usdt_micro.encode_to(out);
        self.recipient.encode_to(out);
    }
}

impl CanonicalDecode for RedemptionClaim {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_REDEMPTION_CLAIM)?;
        let value = Self {
            protocol_version: decoder.u32()?,
            elements_genesis_hash: Hash32::decode_from(decoder)?,
            usdd_asset_id: Hash32::decode_from(decoder)?,
            vault_id: Hash32::decode_from(decoder)?,
            burn_txid_display: Hash32::decode_from(decoder)?,
            burn_vout: decoder.u32()?,
            burn_id: Hash32::decode_from(decoder)?,
            amount_usdt_micro: decoder.u64()?,
            recipient: EthAddress::decode_from(decoder)?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Compatibility alias for callers which used the pre-BIP300-approval name.
pub type SolidityBurnClaim = RedemptionClaim;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ElementsEventKind {
    Mint = 1,
    Burn = 2,
}

impl CanonicalEncode for ElementsEventKind {
    fn encode_to(&self, out: &mut Vec<u8>) {
        (*self as u8).encode_to(out);
    }
}

impl CanonicalDecode for ElementsEventKind {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match decoder.u8()? {
            1 => Ok(Self::Mint),
            2 => Ok(Self::Burn),
            tag => Err(DecodeError::InvalidTag {
                type_name: "ElementsEventKind",
                tag: tag.into(),
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElementsEvent {
    pub kind: ElementsEventKind,
    pub event_id: Hash32,
    pub outpoint: OutPoint,
    pub usdd_amount_base: u64,
    pub payload_commitment: Hash32,
    pub elements_block_hash: Hash32,
    pub elements_height: u64,
    pub bitcoin_bmm_block_hash: Hash32,
    pub bitcoin_bmm_height: u64,
    pub bitcoin_confirmations: u32,
}

impl CanonicalEncode for ElementsEvent {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_ELEMENTS_EVENT, out);
        self.kind.encode_to(out);
        self.event_id.encode_to(out);
        self.outpoint.encode_to(out);
        self.usdd_amount_base.encode_to(out);
        self.payload_commitment.encode_to(out);
        self.elements_block_hash.encode_to(out);
        self.elements_height.encode_to(out);
        self.bitcoin_bmm_block_hash.encode_to(out);
        self.bitcoin_bmm_height.encode_to(out);
        self.bitcoin_confirmations.encode_to(out);
    }
}

impl CanonicalDecode for ElementsEvent {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_ELEMENTS_EVENT)?;
        let value = Self {
            kind: ElementsEventKind::decode_from(decoder)?,
            event_id: Hash32::decode_from(decoder)?,
            outpoint: OutPoint::decode_from(decoder)?,
            usdd_amount_base: decoder.u64()?,
            payload_commitment: Hash32::decode_from(decoder)?,
            elements_block_hash: Hash32::decode_from(decoder)?,
            elements_height: decoder.u64()?,
            bitcoin_bmm_block_hash: Hash32::decode_from(decoder)?,
            bitcoin_bmm_height: decoder.u64()?,
            bitcoin_confirmations: decoder.u32()?,
        };
        if value.event_id == Hash32::ZERO
            || value.outpoint.txid == Hash32::ZERO
            || value.usdd_amount_base == 0
            || value.payload_commitment == Hash32::ZERO
            || value.elements_block_hash == Hash32::ZERO
            || value.bitcoin_bmm_block_hash == Hash32::ZERO
        {
            return Err(DecodeError::InvalidValue("invalid Elements event"));
        }
        Ok(value)
    }
}

/// Exact state tuple consumed by `USDDVaultV1.approvedRedemptionStatement`.
///
/// This records a BIP300 withdrawal-bundle approval and an append-only root of
/// the redemption claims in that bundle. It deliberately makes no assertion
/// that an Elements transaction or block was consensus-valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedRedemptionState {
    pub sequence: u64,
    pub approved_claim_count: u64,
    pub cumulative_approved_claim_root: Hash32,
    /// Canonical RPC/display hex bytes, left-to-right with no reversal.
    pub approved_m6id: Hash32,
    /// Canonical RPC/display hex bytes, left-to-right with no reversal.
    pub bitcoin_tip_hash: Hash32,
    pub bitcoin_height: u64,
    pub bitcoin_median_time_past: u64,
    /// Big-endian uint256.
    pub bitcoin_chainwork: Hash32,
}

impl ApprovedRedemptionState {
    pub fn is_zero(&self) -> bool {
        self.sequence == 0
            && self.approved_claim_count == 0
            && self.cumulative_approved_claim_root == Hash32::ZERO
            && self.approved_m6id == Hash32::ZERO
            && self.bitcoin_tip_hash == Hash32::ZERO
            && self.bitcoin_height == 0
            && self.bitcoin_median_time_past == 0
            && self.bitcoin_chainwork == Hash32::ZERO
    }

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.is_zero() {
            return Ok(());
        }
        if self.approved_claim_count == 0
            || self.cumulative_approved_claim_root == Hash32::ZERO
            || self.approved_m6id == Hash32::ZERO
            || self.bitcoin_tip_hash == Hash32::ZERO
            || self.bitcoin_chainwork == Hash32::ZERO
        {
            return Err(DecodeError::InvalidValue(
                "invalid approved redemption state",
            ));
        }
        Ok(())
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), DecodeError> {
        self.validate()?;
        next.validate()?;
        if next.is_zero() {
            return Err(DecodeError::InvalidValue(
                "zero successor approved redemption state",
            ));
        }
        if next.sequence
            != self
                .sequence
                .checked_add(1)
                .ok_or(DecodeError::InvalidValue(
                    "approved redemption sequence overflow",
                ))?
        {
            return Err(DecodeError::InvalidValue(
                "wrong approved redemption state sequence",
            ));
        }
        if next.approved_claim_count <= self.approved_claim_count {
            return Err(DecodeError::InvalidValue("no new approved claims"));
        }
        if next.approved_claim_count - self.approved_claim_count
            > MAX_APPROVED_CLAIMS_PER_ROOT_UPDATE as u64
        {
            return Err(DecodeError::InvalidValue(
                "too many claims in one approved bundle",
            ));
        }
        if next.cumulative_approved_claim_root == self.cumulative_approved_claim_root
            || next.approved_m6id == self.approved_m6id
        {
            return Err(DecodeError::InvalidValue(
                "approved root or M6id did not advance",
            ));
        }
        if next.bitcoin_height <= self.bitcoin_height
            || next.bitcoin_median_time_past < self.bitcoin_median_time_past
            || next.bitcoin_chainwork <= self.bitcoin_chainwork
        {
            return Err(DecodeError::InvalidValue(
                "Bitcoin approval context did not advance",
            ));
        }
        Ok(())
    }

    /// Solidity `abi.encodePacked` state contents (160 bytes, no Rust tag).
    pub fn packed_contents(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        self.sequence.encode_to(&mut out);
        self.approved_claim_count.encode_to(&mut out);
        self.cumulative_approved_claim_root.encode_to(&mut out);
        self.approved_m6id.encode_to(&mut out);
        self.bitcoin_tip_hash.encode_to(&mut out);
        self.bitcoin_height.encode_to(&mut out);
        self.bitcoin_median_time_past.encode_to(&mut out);
        self.bitcoin_chainwork.encode_to(&mut out);
        debug_assert_eq!(out.len(), 160);
        out
    }

    pub fn contents_hash(&self) -> Hash32 {
        hash_bytes(&self.packed_contents())
    }
}

impl CanonicalEncode for ApprovedRedemptionState {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_APPROVED_REDEMPTION_STATE, out);
        out.extend_from_slice(&self.packed_contents());
    }
}

impl CanonicalDecode for ApprovedRedemptionState {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_APPROVED_REDEMPTION_STATE)?;
        let value = Self {
            sequence: decoder.u64()?,
            approved_claim_count: decoder.u64()?,
            cumulative_approved_claim_root: Hash32::decode_from(decoder)?,
            approved_m6id: Hash32::decode_from(decoder)?,
            bitcoin_tip_hash: Hash32::decode_from(decoder)?,
            bitcoin_height: decoder.u64()?,
            bitcoin_median_time_past: decoder.u64()?,
            bitcoin_chainwork: Hash32::decode_from(decoder)?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Immutable post-genesis identities authenticated by the controller's state
/// Taproot sibling and repeated in every inbound proof journal.
///
/// Elements RPC displays asset IDs, entropy, and blinding factors in reverse
/// uint256 order. These fields deliberately use transaction-consensus byte
/// order so Simplicity can compare them directly to transaction jets. The
/// generator x-coordinate is already wire order and is never reversed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerRuntimeConfig {
    pub usdd_asset_consensus: Hash32,
    pub reissuance_token_consensus: Hash32,
    pub public_abf_consensus: Hash32,
    pub issuance_entropy_consensus: Hash32,
    /// Low bit of the serialized 0x0a/0x0b confidential asset prefix.
    pub token_generator_parity: u8,
    pub token_generator_x: Hash32,
    pub policy_asset_consensus: Hash32,
}

impl ControllerRuntimeConfig {
    pub const ENCODED_LEN: usize = 193;

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.usdd_asset_consensus == Hash32::ZERO
            || self.reissuance_token_consensus == Hash32::ZERO
            || self.public_abf_consensus == Hash32::ZERO
            || self.issuance_entropy_consensus == Hash32::ZERO
            || self.token_generator_x == Hash32::ZERO
            || self.policy_asset_consensus == Hash32::ZERO
            || self.token_generator_parity > 1
        {
            return Err(DecodeError::InvalidValue(
                "invalid controller runtime configuration",
            ));
        }
        if self.usdd_asset_consensus == self.reissuance_token_consensus
            || self.usdd_asset_consensus == self.policy_asset_consensus
            || self.reissuance_token_consensus == self.policy_asset_consensus
        {
            return Err(DecodeError::InvalidValue(
                "controller assets must be distinct",
            ));
        }
        Ok(())
    }
}

impl CanonicalEncode for ControllerRuntimeConfig {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.usdd_asset_consensus.encode_to(out);
        self.reissuance_token_consensus.encode_to(out);
        self.public_abf_consensus.encode_to(out);
        self.issuance_entropy_consensus.encode_to(out);
        self.token_generator_parity.encode_to(out);
        self.token_generator_x.encode_to(out);
        self.policy_asset_consensus.encode_to(out);
    }
}

impl CanonicalDecode for ControllerRuntimeConfig {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            usdd_asset_consensus: Hash32::decode_from(decoder)?,
            reissuance_token_consensus: Hash32::decode_from(decoder)?,
            public_abf_consensus: Hash32::decode_from(decoder)?,
            issuance_entropy_consensus: Hash32::decode_from(decoder)?,
            token_generator_parity: decoder.u8()?,
            token_generator_x: Hash32::decode_from(decoder)?,
            policy_asset_consensus: Hash32::decode_from(decoder)?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Exact V1 controller state committed by the spent and successor outputs.
/// Burns do not consume this mint controller, so no burn counter belongs here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintControllerState {
    pub version: u32,
    pub sequence: u64,
    pub next_mint_nonce: u64,
    pub ethereum_light_client_digest: Hash32,
    pub finalized_beacon_slot: u64,
    pub finalized_beacon_root: Hash32,
    pub finalized_execution_state_root: Hash32,
    pub total_minted_usdd_base: u64,
    pub runtime_config: ControllerRuntimeConfig,
    pub configuration_hash: Hash32,
}

impl MintControllerState {
    pub fn bootstrap(
        runtime_config: ControllerRuntimeConfig,
        configuration_hash: Hash32,
        first_mint_nonce: u64,
        finality: &EthereumFinalityWitness,
    ) -> Result<Self, DecodeError> {
        finality.validate()?;
        let value = Self {
            version: PROTOCOL_VERSION,
            sequence: 0,
            next_mint_nonce: first_mint_nonce,
            ethereum_light_client_digest: finality.ethereum_light_client_digest,
            finalized_beacon_slot: finality.finalized_beacon_slot,
            finalized_beacon_root: finality.finalized_beacon_root,
            finalized_execution_state_root: finality.finalized_execution_state_root,
            total_minted_usdd_base: 0,
            runtime_config,
            configuration_hash,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.version != PROTOCOL_VERSION
            || self.configuration_hash == Hash32::ZERO
            || self.ethereum_light_client_digest == Hash32::ZERO
        {
            return Err(DecodeError::InvalidValue("invalid controller identity"));
        }
        self.runtime_config.validate()?;
        if self.finalized_beacon_slot == 0 {
            if self.sequence != 0
                || self.total_minted_usdd_base != 0
                || self.finalized_beacon_root != Hash32::ZERO
                || self.finalized_execution_state_root != Hash32::ZERO
            {
                return Err(DecodeError::InvalidValue(
                    "invalid bootstrap controller state",
                ));
            }
        } else if self.finalized_beacon_root == Hash32::ZERO
            || self.finalized_execution_state_root == Hash32::ZERO
        {
            return Err(DecodeError::InvalidValue("zero finalized state commitment"));
        }
        if self.total_minted_usdd_base % USDD_UNITS_PER_USDT_MICRO != 0 {
            return Err(DecodeError::InvalidValue("nonconvertible minted total"));
        }
        Ok(())
    }

    pub fn apply_mint_batch(
        &self,
        batch: &MintBatch,
        finality: &EthereumFinalityWitness,
    ) -> Result<Self, DecodeError> {
        self.validate()?;
        batch.validate()?;
        finality.validate()?;
        if batch.first_nonce != self.next_mint_nonce {
            return Err(DecodeError::InvalidValue("mint batch nonce is not next"));
        }
        self.validate_finality_advance(finality)?;
        let next = Self {
            version: self.version,
            sequence: self
                .sequence
                .checked_add(1)
                .ok_or(DecodeError::InvalidValue("controller sequence overflow"))?,
            next_mint_nonce: batch.next_nonce,
            ethereum_light_client_digest: finality.ethereum_light_client_digest,
            finalized_beacon_slot: finality.finalized_beacon_slot,
            finalized_beacon_root: finality.finalized_beacon_root,
            finalized_execution_state_root: finality.finalized_execution_state_root,
            total_minted_usdd_base: self
                .total_minted_usdd_base
                .checked_add(batch.total_usdd_amount_base)
                .ok_or(DecodeError::InvalidValue("minted supply overflow"))?,
            runtime_config: self.runtime_config.clone(),
            configuration_hash: self.configuration_hash,
        };
        next.validate()?;
        Ok(next)
    }

    /// Permissionless state-only transition used to keep the continuous light
    /// client within the 4096-slot proof window when there are no deposits.
    pub fn apply_heartbeat(&self, finality: &EthereumFinalityWitness) -> Result<Self, DecodeError> {
        self.validate()?;
        finality.validate()?;
        if finality.finalized_beacon_slot <= self.finalized_beacon_slot {
            return Err(DecodeError::InvalidValue(
                "heartbeat must advance to a strictly newer finalized beacon slot",
            ));
        }
        self.validate_finality_advance(finality)?;
        let next = Self {
            version: self.version,
            sequence: self
                .sequence
                .checked_add(1)
                .ok_or(DecodeError::InvalidValue("controller sequence overflow"))?,
            next_mint_nonce: self.next_mint_nonce,
            ethereum_light_client_digest: finality.ethereum_light_client_digest,
            finalized_beacon_slot: finality.finalized_beacon_slot,
            finalized_beacon_root: finality.finalized_beacon_root,
            finalized_execution_state_root: finality.finalized_execution_state_root,
            total_minted_usdd_base: self.total_minted_usdd_base,
            runtime_config: self.runtime_config.clone(),
            configuration_hash: self.configuration_hash,
        };
        next.validate()?;
        Ok(next)
    }

    fn validate_finality_advance(
        &self,
        finality: &EthereumFinalityWitness,
    ) -> Result<(), DecodeError> {
        if finality.finalized_beacon_slot < self.finalized_beacon_slot {
            return Err(DecodeError::InvalidValue("Ethereum finality regressed"));
        }
        let slot_gap = finality
            .finalized_beacon_slot
            .checked_sub(self.finalized_beacon_slot)
            .ok_or(DecodeError::InvalidValue("Ethereum finality regressed"))?;
        if slot_gap > MAX_ETHEREUM_FINALITY_SLOT_GAP {
            return Err(DecodeError::InvalidValue(
                "Ethereum finalized slot gap exceeds 4096",
            ));
        }
        if finality.finalized_beacon_slot == self.finalized_beacon_slot
            && self.finalized_beacon_slot != 0
            && (finality.finalized_beacon_root != self.finalized_beacon_root
                || finality.finalized_execution_state_root != self.finalized_execution_state_root
                || finality.ethereum_light_client_digest != self.ethereum_light_client_digest)
        {
            return Err(DecodeError::InvalidValue(
                "conflicting Ethereum state at the same finalized slot",
            ));
        }
        if finality.finalized_beacon_slot > self.finalized_beacon_slot
            && finality.ethereum_light_client_digest == self.ethereum_light_client_digest
        {
            return Err(DecodeError::InvalidValue(
                "Ethereum light-client digest did not advance",
            ));
        }
        Ok(())
    }
}

/// Validate the cross-chain freshness check performed by the Elements
/// controller. `execution_block_timestamp` is proved by the Ethereum guest;
/// `authenticated_bmm_parent_mtp` must come from the block-validation
/// environment and must never be supplied by that guest or its prover.
pub fn validate_bmm_finality_freshness(
    execution_block_timestamp: u64,
    authenticated_bmm_parent_mtp: u64,
) -> Result<(), DecodeError> {
    if execution_block_timestamp == 0 || authenticated_bmm_parent_mtp == 0 {
        return Err(DecodeError::InvalidValue(
            "zero Ethereum timestamp or BMM parent MTP",
        ));
    }
    if execution_block_timestamp.abs_diff(authenticated_bmm_parent_mtp)
        > MAX_FINALIZED_TO_BMM_MTP_AGE_SECONDS
    {
        return Err(DecodeError::InvalidValue(
            "Ethereum finalized time differs from BMM parent MTP by over six hours",
        ));
    }
    Ok(())
}

impl CanonicalEncode for MintControllerState {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.version.encode_to(out);
        self.sequence.encode_to(out);
        self.next_mint_nonce.encode_to(out);
        self.ethereum_light_client_digest.encode_to(out);
        self.finalized_beacon_slot.encode_to(out);
        self.finalized_beacon_root.encode_to(out);
        self.finalized_execution_state_root.encode_to(out);
        self.total_minted_usdd_base.encode_to(out);
        self.runtime_config.encode_to(out);
        self.configuration_hash.encode_to(out);
    }
}

impl CanonicalDecode for MintControllerState {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            version: decoder.u32()?,
            sequence: decoder.u64()?,
            next_mint_nonce: decoder.u64()?,
            ethereum_light_client_digest: Hash32::decode_from(decoder)?,
            finalized_beacon_slot: decoder.u64()?,
            finalized_beacon_root: Hash32::decode_from(decoder)?,
            finalized_execution_state_root: Hash32::decode_from(decoder)?,
            total_minted_usdd_base: decoder.u64()?,
            runtime_config: ControllerRuntimeConfig::decode_from(decoder)?,
            configuration_hash: Hash32::decode_from(decoder)?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Backward-compatible name. This is the 357-byte Elements mint-controller
/// state, never the Solidity vault's `ApprovedRedemptionState`.
pub type BridgeState = MintControllerState;

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn address(byte: u8) -> EthAddress {
        EthAddress([byte; 20])
    }

    fn deposit(nonce: u64) -> VaultDeposit {
        VaultDeposit {
            ethereum_chain_id: 1,
            vault: address(1),
            usdt: address(2),
            nonce,
            depositor: address(3),
            usdt_amount_micro: 1_234_567,
            elements_script: vec![0x51, nonce as u8],
            user_salt: hash(4),
        }
    }

    fn finality() -> EthereumFinalityWitness {
        EthereumFinalityWitness {
            ethereum_light_client_digest: hash(5),
            finalized_beacon_slot: 10,
            finalized_beacon_root: hash(6),
            finalized_execution_block: hash(7),
            finalized_execution_state_root: hash(8),
            execution_block_number: 9,
            execution_block_timestamp: 10,
        }
    }

    fn runtime_config() -> ControllerRuntimeConfig {
        ControllerRuntimeConfig {
            usdd_asset_consensus: hash(20),
            reissuance_token_consensus: hash(21),
            public_abf_consensus: hash(22),
            issuance_entropy_consensus: hash(23),
            token_generator_parity: 1,
            token_generator_x: hash(24),
            policy_asset_consensus: hash(25),
        }
    }

    fn controller(first_nonce: u64) -> MintControllerState {
        let mut bootstrap_finality = finality();
        bootstrap_finality.finalized_beacon_slot = 1;
        bootstrap_finality.finalized_beacon_root = hash(11);
        bootstrap_finality.finalized_execution_state_root = hash(12);
        bootstrap_finality.ethereum_light_client_digest = hash(13);
        MintControllerState::bootstrap(runtime_config(), hash(9), first_nonce, &bootstrap_finality)
            .unwrap()
    }

    #[test]
    fn solidity_deposit_id_excludes_finality() {
        let deposit = deposit(0);
        assert_ne!(deposit.deposit_id(), Hash32::ZERO);
        assert_eq!(
            VaultDeposit::decode_exact(&deposit.encode()).unwrap(),
            deposit
        );
    }

    #[test]
    fn deposit_amount_matches_the_immutable_vault_limit() {
        let mut at_limit = deposit(0);
        at_limit.usdt_amount_micro = MAX_DEPOSIT_AMOUNT_USDT_MICRO;
        at_limit.validate().unwrap();

        let mut over_limit = at_limit;
        over_limit.usdt_amount_micro = MAX_DEPOSIT_AMOUNT_USDT_MICRO + 1;
        assert!(over_limit.validate().is_err());
        assert!(VaultDeposit::decode_exact(&over_limit.encode()).is_err());
    }

    #[test]
    fn exact_amount_conversion_is_committed() {
        let batch = MintBatch::from_deposits(&[deposit(0)]).unwrap();
        assert_eq!(batch.total_usdd_amount_base, 123_456_700);
        assert_eq!(MintBatch::decode_exact(&batch.encode()).unwrap(), batch);
    }

    #[test]
    fn mint_batch_preserves_elements_explicit_output_headroom() {
        let mut first = deposit(0);
        first.usdt_amount_micro = MAX_MINT_BATCH_USDT_MICRO / 2;
        let mut second = deposit(1);
        second.usdt_amount_micro = MAX_MINT_BATCH_USDT_MICRO / 2;
        let at_limit = MintBatch::from_deposits(&[first.clone(), second.clone()]).unwrap();
        assert_eq!(at_limit.total_usdd_amount_base, MAX_MINT_BATCH_USDD_BASE);

        let mut over = deposit(2);
        over.usdt_amount_micro = 1;
        assert!(MintBatch::from_deposits(&[first, second, over]).is_err());

        let mut zero = MintOutput::from_deposit(&deposit(0)).unwrap();
        zero.usdt_amount_micro = 0;
        zero.usdd_amount_base = 0;
        assert!(zero.validate().is_err());
    }

    #[test]
    fn batch_size_zero_and_65_are_rejected() {
        assert!(MintBatch::from_deposits(&[]).is_err());
        let deposits: Vec<_> = (0..65).map(deposit).collect();
        assert!(MintBatch::from_deposits(&deposits).is_err());
    }

    #[test]
    fn batch_gap_and_nonce_overflow_are_rejected() {
        assert!(MintBatch::from_deposits(&[deposit(0), deposit(2)]).is_err());
        assert!(MintBatch::from_deposits(&[deposit(u64::MAX)]).is_err());
    }

    #[test]
    fn controller_consumes_batch_once_and_advances_sequence() {
        let batch = MintBatch::from_deposits(&[deposit(4), deposit(5)]).unwrap();
        let state = controller(4);
        let next = state.apply_mint_batch(&batch, &finality()).unwrap();
        assert_eq!(next.sequence, 1);
        assert_eq!(next.next_mint_nonce, 6);
        assert_eq!(next.total_minted_usdd_base, 246_913_400);
        assert!(next.apply_mint_batch(&batch, &finality()).is_err());
    }

    #[test]
    fn sequence_and_supply_overflow_are_rejected() {
        let batch = MintBatch::from_deposits(&[deposit(0)]).unwrap();
        let mut sequence_overflow = controller(0);
        sequence_overflow.sequence = u64::MAX;
        assert!(sequence_overflow
            .apply_mint_batch(&batch, &finality())
            .is_err());

        let mut supply_overflow = controller(0);
        supply_overflow.total_minted_usdd_base = u64::MAX - (u64::MAX % 100);
        assert!(supply_overflow
            .apply_mint_batch(&batch, &finality())
            .is_err());
    }

    #[test]
    fn finality_freshness_uses_only_the_controller_environment() {
        assert!(validate_bmm_finality_freshness(20_000, 20_100).is_ok());
        assert!(validate_bmm_finality_freshness(20_000, 19_900).is_ok());
        assert!(validate_bmm_finality_freshness(20_000, 20_000 + 21_601).is_err());
        assert!(validate_bmm_finality_freshness(30_000, 8_399).is_err());
        assert!(validate_bmm_finality_freshness(0, 1).is_err());
        assert!(validate_bmm_finality_freshness(1, 0).is_err());
    }

    #[test]
    fn heartbeat_prevents_no_deposit_slot_gap_brick() {
        let state = controller(0);
        let mut far = finality();
        far.finalized_beacon_slot = 8_193;
        far.ethereum_light_client_digest = hash(31);
        assert!(state.apply_heartbeat(&far).is_err());

        let mut middle = finality();
        middle.finalized_beacon_slot = 4_097;
        let middle_state = state.apply_heartbeat(&middle).unwrap();
        let final_state = middle_state.apply_heartbeat(&far).unwrap();
        assert_eq!(final_state.sequence, 2);
        assert_eq!(final_state.next_mint_nonce, 0);
        assert_eq!(final_state.total_minted_usdd_base, 0);
    }

    #[test]
    fn heartbeat_requires_newer_slot_but_mint_may_reuse_finalized_state() {
        let witness = finality();
        let state = controller(0);
        let advanced = state.apply_heartbeat(&witness).unwrap();

        assert!(advanced.apply_heartbeat(&witness).is_err());

        let batch = MintBatch::from_deposits(&[deposit(0)]).unwrap();
        let minted = advanced.apply_mint_batch(&batch, &witness).unwrap();
        assert_eq!(minted.finalized_beacon_slot, witness.finalized_beacon_slot);
        assert_eq!(minted.next_mint_nonce, 1);
    }

    #[test]
    fn approved_redemption_state_requires_new_claims_and_m6id() {
        let zero = ApprovedRedemptionState {
            sequence: 0,
            approved_claim_count: 0,
            cumulative_approved_claim_root: Hash32::ZERO,
            approved_m6id: Hash32::ZERO,
            bitcoin_tip_hash: Hash32::ZERO,
            bitcoin_height: 0,
            bitcoin_median_time_past: 0,
            bitcoin_chainwork: Hash32::ZERO,
        };
        let first = ApprovedRedemptionState {
            sequence: 1,
            approved_claim_count: 1,
            cumulative_approved_claim_root: hash(21),
            approved_m6id: hash(22),
            bitcoin_tip_hash: hash(24),
            bitcoin_height: 100,
            bitcoin_median_time_past: 1_700_000_000,
            bitcoin_chainwork: hash(25),
        };
        zero.validate_successor(&first).unwrap();
        assert_eq!(first.packed_contents().len(), 160);

        let mut second = first.clone();
        second.sequence = 2;
        second.approved_claim_count += 1;
        second.cumulative_approved_claim_root = hash(26);
        second.bitcoin_tip_hash = hash(27);
        second.bitcoin_height += 1;
        second.bitcoin_median_time_past += 1;
        second.bitcoin_chainwork = hash(28);
        assert!(first.validate_successor(&second).is_err());
        second.approved_m6id = hash(29);
        first.validate_successor(&second).unwrap();

        let encoded = second.encode();
        assert_eq!(
            ApprovedRedemptionState::decode_exact(&encoded).unwrap(),
            second
        );
    }

    #[test]
    fn burn_rejects_sub_micro_dust() {
        let burn = Burn {
            vault_id: hash(1),
            usdd_asset: hash(2),
            usdd_amount_base: 101,
            usdt_amount_micro: 1,
            burn_outpoint: OutPoint {
                txid: hash(3),
                vout: 0,
            },
            ethereum_destination: address(4),
        };
        assert!(burn.validate().is_err());
    }

    #[test]
    fn burn_preserves_elements_explicit_fee_headroom() {
        let mut burn = Burn {
            vault_id: hash(1),
            usdd_asset: hash(2),
            usdd_amount_base: MAX_BURN_AMOUNT_USDD_BASE,
            usdt_amount_micro: MAX_BURN_AMOUNT_USDT_MICRO,
            burn_outpoint: OutPoint {
                txid: hash(3),
                vout: 0,
            },
            ethereum_destination: address(4),
        };
        burn.validate().unwrap();
        burn.usdd_amount_base += USDD_UNITS_PER_USDT_MICRO;
        burn.usdt_amount_micro += 1;
        assert!(burn.validate().is_err());
        assert!(burn.burn_payload().validate().is_err());
    }

    #[test]
    fn redemption_claim_matches_vault_amount_and_destination_rules() {
        let burn = Burn {
            vault_id: hash(1),
            usdd_asset: hash(2),
            usdd_amount_base: MAX_BURN_AMOUNT_USDD_BASE,
            usdt_amount_micro: MAX_BURN_AMOUNT_USDT_MICRO,
            burn_outpoint: OutPoint {
                txid: hash(3),
                vout: 0,
            },
            ethereum_destination: address(4),
        };
        let mut claim = burn.redemption_claim(hash(5));
        burn.validate_for_vault(address(6)).unwrap();
        assert!(burn.validate_for_vault(address(4)).is_err());
        claim.validate_for_vault(address(6)).unwrap();
        assert!(claim.validate_for_vault(address(4)).is_err());
        claim.amount_usdt_micro += 1;
        assert!(claim.validate().is_err());
        claim.amount_usdt_micro = 1;
        claim.burn_txid_display = Hash32::ZERO;
        assert!(claim.validate().is_err());
    }
}
