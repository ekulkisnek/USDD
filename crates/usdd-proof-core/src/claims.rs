use alloc::vec::Vec;

use usdd_core::{
    domain_hash, Burn, BurnProof, CanonicalDecode, CanonicalEncode, DecodeError, Decoder, Domain,
    EthereumFinalityWitness, Hash32, MintBatch, MintControllerState, SolidityElementsBridgeState,
    VaultDeposit, ENCODING_SCHEMA, MAX_BURN_APPENDS_PER_STATE_TRANSITION, MAX_MINT_BATCH_SIZE,
};

const TAG_ETHEREUM_DEPOSIT_CLAIM: u16 = 0x5101;
const TAG_DEPOSIT_PUBLIC_OUTPUT: u16 = 0x5201;
const TAG_ELEMENTS_STATE_TRANSITION_CLAIM: u16 = 0x5103;
const TAG_BURN_APPEND: u16 = 0x5104;
const TAG_ELEMENTS_STATE_PUBLIC_OUTPUT: u16 = 0x5203;
const TAG_ETHEREUM_HEARTBEAT_CLAIM: u16 = 0x5105;
const TAG_HEARTBEAT_PUBLIC_OUTPUT: u16 = 0x5204;

fn encode_header(tag: u16, out: &mut Vec<u8>) {
    ENCODING_SCHEMA.encode_to(out);
    tag.encode_to(out);
}

fn decode_header(decoder: &mut Decoder<'_>, tag: u16) -> Result<(), DecodeError> {
    if decoder.u16()? != ENCODING_SCHEMA || decoder.u16()? != tag {
        return Err(DecodeError::InvalidValue("invalid proof record header"));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumDepositClaim {
    pub manifest_id: Hash32,
    pub prior_state: MintControllerState,
    pub finality: EthereumFinalityWitness,
    pub deposits: Vec<VaultDeposit>,
}

impl EthereumDepositClaim {
    pub fn claim_id(&self) -> Hash32 {
        domain_hash(Domain::EthereumStateClaim, &self.encode())
    }

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.manifest_id == Hash32::ZERO {
            return Err(DecodeError::InvalidValue("zero manifest ID"));
        }
        self.prior_state.validate()?;
        self.finality.validate()?;
        MintBatch::from_deposits(&self.deposits)?;
        Ok(())
    }
}

impl CanonicalEncode for EthereumDepositClaim {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_ETHEREUM_DEPOSIT_CLAIM, out);
        self.manifest_id.encode_to(out);
        self.prior_state.encode_to(out);
        self.finality.encode_to(out);
        let count = u8::try_from(self.deposits.len()).expect("deposit count fits u8");
        count.encode_to(out);
        for deposit in &self.deposits {
            deposit.encode_to(out);
        }
    }
}

impl CanonicalDecode for EthereumDepositClaim {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_ETHEREUM_DEPOSIT_CLAIM)?;
        let manifest_id = Hash32::decode_from(decoder)?;
        let prior_state = MintControllerState::decode_from(decoder)?;
        let finality = EthereumFinalityWitness::decode_from(decoder)?;
        let count = decoder.u8()? as usize;
        if count == 0 || count > MAX_MINT_BATCH_SIZE {
            return Err(DecodeError::InvalidValue(
                "deposit proof batch must be 1..64",
            ));
        }
        let mut deposits = Vec::with_capacity(count);
        for _ in 0..count {
            deposits.push(VaultDeposit::decode_from(decoder)?);
        }
        let value = Self {
            manifest_id,
            prior_state,
            finality,
            deposits,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumHeartbeatClaim {
    pub manifest_id: Hash32,
    pub prior_state: MintControllerState,
    pub finality: EthereumFinalityWitness,
}

impl EthereumHeartbeatClaim {
    pub fn claim_id(&self) -> Hash32 {
        domain_hash(Domain::EthereumStateClaim, &self.encode())
    }

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.manifest_id == Hash32::ZERO {
            return Err(DecodeError::InvalidValue("zero manifest ID"));
        }
        self.prior_state.validate()?;
        self.finality.validate()?;
        Ok(())
    }
}

impl CanonicalEncode for EthereumHeartbeatClaim {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_ETHEREUM_HEARTBEAT_CLAIM, out);
        self.manifest_id.encode_to(out);
        self.prior_state.encode_to(out);
        self.finality.encode_to(out);
    }
}

impl CanonicalDecode for EthereumHeartbeatClaim {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_ETHEREUM_HEARTBEAT_CLAIM)?;
        let value = Self {
            manifest_id: Hash32::decode_from(decoder)?,
            prior_state: MintControllerState::decode_from(decoder)?,
            finality: EthereumFinalityWitness::decode_from(decoder)?,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BurnAppend {
    pub burn: Burn,
    /// Proves the target index contained EMPTY[0] under the preceding root and
    /// deterministically derives the root after replacing it with this leaf.
    pub empty_branch: BurnProof,
}

impl CanonicalEncode for BurnAppend {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_BURN_APPEND, out);
        self.burn.encode_to(out);
        self.empty_branch.encode_to(out);
    }
}

impl CanonicalDecode for BurnAppend {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_BURN_APPEND)?;
        Ok(Self {
            burn: Burn::decode_from(decoder)?,
            empty_branch: BurnProof::decode_from(decoder)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElementsStateTransitionClaim {
    pub manifest_id: Hash32,
    pub prior_bridge_state_hash: Hash32,
    pub prior_state: SolidityElementsBridgeState,
    pub next_state: SolidityElementsBridgeState,
    pub appended_burns: Vec<BurnAppend>,
}

impl ElementsStateTransitionClaim {
    pub fn claim_id(&self) -> Hash32 {
        domain_hash(Domain::ElementsEventClaim, &self.encode())
    }
}

impl CanonicalEncode for ElementsStateTransitionClaim {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_ELEMENTS_STATE_TRANSITION_CLAIM, out);
        self.manifest_id.encode_to(out);
        self.prior_bridge_state_hash.encode_to(out);
        self.prior_state.encode_to(out);
        self.next_state.encode_to(out);
        let count = u8::try_from(self.appended_burns.len()).expect("burn append count fits u8");
        count.encode_to(out);
        for append in &self.appended_burns {
            append.encode_to(out);
        }
    }
}

impl CanonicalDecode for ElementsStateTransitionClaim {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_ELEMENTS_STATE_TRANSITION_CLAIM)?;
        let manifest_id = Hash32::decode_from(decoder)?;
        let prior_bridge_state_hash = Hash32::decode_from(decoder)?;
        let prior_state = SolidityElementsBridgeState::decode_from(decoder)?;
        let next_state = SolidityElementsBridgeState::decode_from(decoder)?;
        let count = decoder.u8()? as usize;
        if count > MAX_BURN_APPENDS_PER_STATE_TRANSITION {
            return Err(DecodeError::InvalidValue(
                "too many burns in state transition",
            ));
        }
        let mut appended_burns = Vec::with_capacity(count);
        for _ in 0..count {
            appended_burns.push(BurnAppend::decode_from(decoder)?);
        }
        Ok(Self {
            manifest_id,
            prior_bridge_state_hash,
            prior_state,
            next_state,
            appended_burns,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositPublicOutput {
    pub manifest_id: Hash32,
    pub claim_id: Hash32,
    pub prior_state: MintControllerState,
    pub next_state: MintControllerState,
    /// Timestamp authenticated by the finalized Ethereum execution header.
    /// The Elements controller compares this with its own BMM-parent MTP jet.
    pub finalized_execution_block_timestamp: u64,
    pub mint_batch: MintBatch,
}

impl DepositPublicOutput {
    pub fn output_id(&self) -> Hash32 {
        domain_hash(Domain::DepositPublicOutput, &self.encode())
    }

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.manifest_id == Hash32::ZERO
            || self.claim_id == Hash32::ZERO
            || self.finalized_execution_block_timestamp == 0
        {
            return Err(DecodeError::InvalidValue("invalid deposit public output"));
        }
        self.prior_state.validate()?;
        self.next_state.validate()?;
        self.mint_batch.validate()?;
        let expected_total = self
            .prior_state
            .total_minted_usdd_base
            .checked_add(self.mint_batch.total_usdd_amount_base)
            .ok_or(DecodeError::InvalidValue("minted supply overflow"))?;
        if self.next_state.version != self.prior_state.version
            || self.next_state.sequence
                != self
                    .prior_state
                    .sequence
                    .checked_add(1)
                    .ok_or(DecodeError::InvalidValue("controller sequence overflow"))?
            || self.next_state.next_mint_nonce != self.mint_batch.next_nonce
            || self.mint_batch.first_nonce != self.prior_state.next_mint_nonce
            || self.next_state.total_minted_usdd_base != expected_total
            || self.next_state.configuration_hash != self.prior_state.configuration_hash
            || self.next_state.finalized_beacon_slot < self.prior_state.finalized_beacon_slot
            || self
                .next_state
                .finalized_beacon_slot
                .saturating_sub(self.prior_state.finalized_beacon_slot)
                > usdd_core::MAX_ETHEREUM_FINALITY_SLOT_GAP
            || (self.next_state.finalized_beacon_slot == self.prior_state.finalized_beacon_slot
                && (self.next_state.ethereum_light_client_digest
                    != self.prior_state.ethereum_light_client_digest
                    || self.next_state.finalized_beacon_root
                        != self.prior_state.finalized_beacon_root
                    || self.next_state.finalized_execution_state_root
                        != self.prior_state.finalized_execution_state_root))
            || (self.next_state.finalized_beacon_slot > self.prior_state.finalized_beacon_slot
                && self.next_state.ethereum_light_client_digest
                    == self.prior_state.ethereum_light_client_digest)
        {
            return Err(DecodeError::InvalidValue(
                "deposit output does not bind the controller transition",
            ));
        }
        Ok(())
    }
}

impl CanonicalEncode for DepositPublicOutput {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_DEPOSIT_PUBLIC_OUTPUT, out);
        self.manifest_id.encode_to(out);
        self.claim_id.encode_to(out);
        self.prior_state.encode_to(out);
        self.next_state.encode_to(out);
        self.finalized_execution_block_timestamp.encode_to(out);
        self.mint_batch.encode_to(out);
    }
}

impl CanonicalDecode for DepositPublicOutput {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_DEPOSIT_PUBLIC_OUTPUT)?;
        let value = Self {
            manifest_id: Hash32::decode_from(decoder)?,
            claim_id: Hash32::decode_from(decoder)?,
            prior_state: MintControllerState::decode_from(decoder)?,
            next_state: MintControllerState::decode_from(decoder)?,
            finalized_execution_block_timestamp: decoder.u64()?,
            mint_batch: MintBatch::decode_from(decoder)?,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatPublicOutput {
    pub manifest_id: Hash32,
    pub claim_id: Hash32,
    pub prior_state: MintControllerState,
    pub next_state: MintControllerState,
    /// Timestamp authenticated by the finalized Ethereum execution header.
    pub finalized_execution_block_timestamp: u64,
}

impl HeartbeatPublicOutput {
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.manifest_id == Hash32::ZERO
            || self.claim_id == Hash32::ZERO
            || self.finalized_execution_block_timestamp == 0
        {
            return Err(DecodeError::InvalidValue("invalid heartbeat public output"));
        }
        self.prior_state.validate()?;
        self.next_state.validate()?;
        if self.next_state.version != self.prior_state.version
            || self.next_state.sequence
                != self
                    .prior_state
                    .sequence
                    .checked_add(1)
                    .ok_or(DecodeError::InvalidValue("controller sequence overflow"))?
            || self.next_state.next_mint_nonce != self.prior_state.next_mint_nonce
            || self.next_state.total_minted_usdd_base != self.prior_state.total_minted_usdd_base
            || self.next_state.configuration_hash != self.prior_state.configuration_hash
            || self.next_state.finalized_beacon_slot <= self.prior_state.finalized_beacon_slot
            || self.next_state.ethereum_light_client_digest
                == self.prior_state.ethereum_light_client_digest
            || self
                .next_state
                .finalized_beacon_slot
                .saturating_sub(self.prior_state.finalized_beacon_slot)
                > usdd_core::MAX_ETHEREUM_FINALITY_SLOT_GAP
        {
            return Err(DecodeError::InvalidValue(
                "heartbeat output does not bind a state-only transition",
            ));
        }
        Ok(())
    }
}

impl CanonicalEncode for HeartbeatPublicOutput {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_HEARTBEAT_PUBLIC_OUTPUT, out);
        self.manifest_id.encode_to(out);
        self.claim_id.encode_to(out);
        self.prior_state.encode_to(out);
        self.next_state.encode_to(out);
        self.finalized_execution_block_timestamp.encode_to(out);
    }
}

impl CanonicalDecode for HeartbeatPublicOutput {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_HEARTBEAT_PUBLIC_OUTPUT)?;
        let value = Self {
            manifest_id: Hash32::decode_from(decoder)?,
            claim_id: Hash32::decode_from(decoder)?,
            prior_state: MintControllerState::decode_from(decoder)?,
            next_state: MintControllerState::decode_from(decoder)?,
            finalized_execution_block_timestamp: decoder.u64()?,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElementsStatePublicOutput {
    pub manifest_id: Hash32,
    pub claim_id: Hash32,
    pub prior_bridge_state_hash: Hash32,
    pub next_bridge_state_hash: Hash32,
    pub verifier_statement: Hash32,
    pub prior_state: SolidityElementsBridgeState,
    pub next_state: SolidityElementsBridgeState,
}

impl CanonicalEncode for ElementsStatePublicOutput {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_ELEMENTS_STATE_PUBLIC_OUTPUT, out);
        self.manifest_id.encode_to(out);
        self.claim_id.encode_to(out);
        self.prior_bridge_state_hash.encode_to(out);
        self.next_bridge_state_hash.encode_to(out);
        self.verifier_statement.encode_to(out);
        self.prior_state.encode_to(out);
        self.next_state.encode_to(out);
    }
}

impl CanonicalDecode for ElementsStatePublicOutput {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_ELEMENTS_STATE_PUBLIC_OUTPUT)?;
        let value = Self {
            manifest_id: Hash32::decode_from(decoder)?,
            claim_id: Hash32::decode_from(decoder)?,
            prior_bridge_state_hash: Hash32::decode_from(decoder)?,
            next_bridge_state_hash: Hash32::decode_from(decoder)?,
            verifier_statement: Hash32::decode_from(decoder)?,
            prior_state: SolidityElementsBridgeState::decode_from(decoder)?,
            next_state: SolidityElementsBridgeState::decode_from(decoder)?,
        };
        if value.manifest_id == Hash32::ZERO
            || value.claim_id == Hash32::ZERO
            || value.next_bridge_state_hash == Hash32::ZERO
            || value.verifier_statement == Hash32::ZERO
            || value.prior_state.is_zero() != (value.prior_bridge_state_hash == Hash32::ZERO)
        {
            return Err(DecodeError::InvalidValue(
                "invalid Elements state public output",
            ));
        }
        value.prior_state.validate_successor(&value.next_state)?;
        Ok(value)
    }
}
