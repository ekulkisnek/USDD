use alloc::vec::Vec;

use usdd_core::{
    domain_hash, Burn, BurnProof, CanonicalDecode, CanonicalEncode, DecodeError, Decoder, Domain,
    ElementsEvent, EthereumFinalityWitness, Hash32, MintBatch, MintControllerState,
    SolidityElementsBridgeState, VaultDeposit, ENCODING_SCHEMA, MAX_MINT_BATCH_SIZE,
};

const TAG_ETHEREUM_DEPOSIT_CLAIM: u16 = 0x5101;
const TAG_ELEMENTS_BURN_CLAIM: u16 = 0x5102;
const TAG_DEPOSIT_PUBLIC_OUTPUT: u16 = 0x5201;
const TAG_REDEMPTION_PUBLIC_OUTPUT: u16 = 0x5202;
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
    /// Authenticated from the BIP301 mainchain parent used by block validation.
    pub authenticated_bmm_parent_mtp: u64,
    pub deposits: Vec<VaultDeposit>,
}

impl EthereumDepositClaim {
    pub fn claim_id(&self) -> Hash32 {
        domain_hash(Domain::EthereumStateClaim, &self.encode())
    }
}

impl CanonicalEncode for EthereumDepositClaim {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_ETHEREUM_DEPOSIT_CLAIM, out);
        self.manifest_id.encode_to(out);
        self.prior_state.encode_to(out);
        self.finality.encode_to(out);
        self.authenticated_bmm_parent_mtp.encode_to(out);
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
        let authenticated_bmm_parent_mtp = decoder.u64()?;
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
        Ok(Self {
            manifest_id,
            prior_state,
            finality,
            authenticated_bmm_parent_mtp,
            deposits,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumHeartbeatClaim {
    pub manifest_id: Hash32,
    pub prior_state: MintControllerState,
    pub finality: EthereumFinalityWitness,
    pub authenticated_bmm_parent_mtp: u64,
}

impl EthereumHeartbeatClaim {
    pub fn claim_id(&self) -> Hash32 {
        domain_hash(Domain::EthereumStateClaim, &self.encode())
    }
}

impl CanonicalEncode for EthereumHeartbeatClaim {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_ETHEREUM_HEARTBEAT_CLAIM, out);
        self.manifest_id.encode_to(out);
        self.prior_state.encode_to(out);
        self.finality.encode_to(out);
        self.authenticated_bmm_parent_mtp.encode_to(out);
    }
}

impl CanonicalDecode for EthereumHeartbeatClaim {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_ETHEREUM_HEARTBEAT_CLAIM)?;
        Ok(Self {
            manifest_id: Hash32::decode_from(decoder)?,
            prior_state: MintControllerState::decode_from(decoder)?,
            finality: EthereumFinalityWitness::decode_from(decoder)?,
            authenticated_bmm_parent_mtp: decoder.u64()?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElementsBurnClaim {
    pub manifest_id: Hash32,
    pub burn: Burn,
    pub event: ElementsEvent,
}

impl ElementsBurnClaim {
    pub fn claim_id(&self) -> Hash32 {
        domain_hash(Domain::ElementsEventClaim, &self.encode())
    }
}

impl CanonicalEncode for ElementsBurnClaim {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_ELEMENTS_BURN_CLAIM, out);
        self.manifest_id.encode_to(out);
        self.burn.encode_to(out);
        self.event.encode_to(out);
    }
}

impl CanonicalDecode for ElementsBurnClaim {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_ELEMENTS_BURN_CLAIM)?;
        Ok(Self {
            manifest_id: Hash32::decode_from(decoder)?,
            burn: Burn::decode_from(decoder)?,
            event: ElementsEvent::decode_from(decoder)?,
        })
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
        if count > 64 {
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
    pub mint_batch: MintBatch,
}

impl DepositPublicOutput {
    pub fn output_id(&self) -> Hash32 {
        domain_hash(Domain::DepositPublicOutput, &self.encode())
    }
}

impl CanonicalEncode for DepositPublicOutput {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_DEPOSIT_PUBLIC_OUTPUT, out);
        self.manifest_id.encode_to(out);
        self.claim_id.encode_to(out);
        self.prior_state.encode_to(out);
        self.next_state.encode_to(out);
        self.mint_batch.encode_to(out);
    }
}

impl CanonicalDecode for DepositPublicOutput {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_DEPOSIT_PUBLIC_OUTPUT)?;
        Ok(Self {
            manifest_id: Hash32::decode_from(decoder)?,
            claim_id: Hash32::decode_from(decoder)?,
            prior_state: MintControllerState::decode_from(decoder)?,
            next_state: MintControllerState::decode_from(decoder)?,
            mint_batch: MintBatch::decode_from(decoder)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatPublicOutput {
    pub manifest_id: Hash32,
    pub claim_id: Hash32,
    pub prior_state: MintControllerState,
    pub next_state: MintControllerState,
}

impl CanonicalEncode for HeartbeatPublicOutput {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_HEARTBEAT_PUBLIC_OUTPUT, out);
        self.manifest_id.encode_to(out);
        self.claim_id.encode_to(out);
        self.prior_state.encode_to(out);
        self.next_state.encode_to(out);
    }
}

impl CanonicalDecode for HeartbeatPublicOutput {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_HEARTBEAT_PUBLIC_OUTPUT)?;
        Ok(Self {
            manifest_id: Hash32::decode_from(decoder)?,
            claim_id: Hash32::decode_from(decoder)?,
            prior_state: MintControllerState::decode_from(decoder)?,
            next_state: MintControllerState::decode_from(decoder)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedemptionPublicOutput {
    pub manifest_id: Hash32,
    pub claim_id: Hash32,
    pub redemption_id: Hash32,
    pub burn: Burn,
    pub elements_block_hash: Hash32,
    pub bitcoin_bmm_block_hash: Hash32,
    pub bitcoin_confirmations: u32,
}

impl RedemptionPublicOutput {
    pub fn output_id(&self) -> Hash32 {
        domain_hash(Domain::RedemptionPublicOutput, &self.encode())
    }
}

impl CanonicalEncode for RedemptionPublicOutput {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_header(TAG_REDEMPTION_PUBLIC_OUTPUT, out);
        self.manifest_id.encode_to(out);
        self.claim_id.encode_to(out);
        self.redemption_id.encode_to(out);
        self.burn.encode_to(out);
        self.elements_block_hash.encode_to(out);
        self.bitcoin_bmm_block_hash.encode_to(out);
        self.bitcoin_confirmations.encode_to(out);
    }
}

impl CanonicalDecode for RedemptionPublicOutput {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_header(decoder, TAG_REDEMPTION_PUBLIC_OUTPUT)?;
        Ok(Self {
            manifest_id: Hash32::decode_from(decoder)?,
            claim_id: Hash32::decode_from(decoder)?,
            redemption_id: Hash32::decode_from(decoder)?,
            burn: Burn::decode_from(decoder)?,
            elements_block_hash: Hash32::decode_from(decoder)?,
            bitcoin_bmm_block_hash: Hash32::decode_from(decoder)?,
            bitcoin_confirmations: decoder.u32()?,
        })
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
        Ok(Self {
            manifest_id: Hash32::decode_from(decoder)?,
            claim_id: Hash32::decode_from(decoder)?,
            prior_bridge_state_hash: Hash32::decode_from(decoder)?,
            next_bridge_state_hash: Hash32::decode_from(decoder)?,
            verifier_statement: Hash32::decode_from(decoder)?,
            prior_state: SolidityElementsBridgeState::decode_from(decoder)?,
            next_state: SolidityElementsBridgeState::decode_from(decoder)?,
        })
    }
}
