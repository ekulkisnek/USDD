use alloc::vec::Vec;
use core::fmt;

use crate::{
    domain_hash, domain_separator_table_hash,
    encoding::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder},
    hash::{Domain, Hash32},
    hash_bytes,
    relay_config::{
        Bip300RelayConfig, BIP300_WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD,
        BIP300_WITHDRAWAL_BUNDLE_MAX_AGE, SLOT_24_ACTIVE_BITMAP,
    },
    types::{ControllerRuntimeConfig, EthAddress, MintControllerState},
    ACTIVE_LIABILITY_CAP_USDT_MICRO, DRIVECHAIN_SLOT, ENCODING_SCHEMA,
    MAX_ETHEREUM_FINALITY_SLOT_GAP, MAX_FINALIZED_TO_BMM_MTP_AGE_SECONDS,
    MINIMUM_BITCOIN_CONFIRMATIONS, SHA256_DIGEST_TAG, SP1_COMPRESSED_CIRCUIT_VERSION,
    SP1_COMPRESSED_CODEC_VERSION, SP1_GIT_COMMIT, SP1_VERSION_MAJOR, SP1_VERSION_MINOR,
    SP1_VERSION_PATCH, USDD_SCALE, USDD_UNITS_PER_USDT_MICRO, USDT_SCALE,
};

const TAG_MANIFEST: u16 = 0x4001;

/// `keccak256("USDD_VAULT_ID_V1")` from `USDDVaultV1.sol`.
pub const SOLIDITY_VAULT_ID_DOMAIN: Hash32 = Hash32([
    0xfb, 0x55, 0x81, 0xac, 0xfc, 0xed, 0x59, 0xc7, 0x4e, 0x84, 0x98, 0x62, 0x35, 0x0b, 0x68, 0xb4,
    0x7d, 0x96, 0xb0, 0x8d, 0x64, 0xe0, 0x95, 0xa1, 0xcb, 0xd3, 0xb7, 0x8a, 0x12, 0x98, 0xa3, 0x5c,
]);

/// Immutable deployment commitments required by every proof and bridge state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolManifest {
    pub ethereum_chain_id: u64,
    pub ethereum_genesis: Hash32,
    pub bitcoin_genesis: Hash32,
    pub elements_genesis: Hash32,
    pub drivechain_slot: u8,
    pub usdt: EthAddress,
    pub usdd_asset: Hash32,
    pub usdd_reissuance_token: Hash32,
    pub usdd_public_abf: Hash32,
    /// Serialized confidential asset generator (0x0a/0x0b || x), wire order.
    pub usdd_reissuance_token_generator: [u8; 33],
    /// Elements RPC/display uint256 order; runtime state reverses this value.
    pub elements_policy_asset: Hash32,
    pub vault: EthAddress,
    pub vault_id: Hash32,
    pub vault_code_hash: Hash32,
    pub proof_verifier: EthAddress,
    pub proof_verifier_runtime_code_hash: Hash32,
    pub verifier_config_hash: Hash32,
    pub bip300_relay_config: Bip300RelayConfig,
    pub ethereum_guest_program_id: Hash32,
    pub bip300_relay_program_id: Hash32,
    pub sp1_version_major: u16,
    pub sp1_version_minor: u16,
    pub sp1_version_patch: u16,
    pub sp1_git_commit: [u8; 20],
    pub compressed_proof_circuit_version: u16,
    pub compressed_proof_codec_version: u16,
    pub recursion_verifier_constants_hash: Hash32,
    pub public_digest_tag: u8,
    pub bootstrap_finalized_beacon_slot: u64,
    pub bootstrap_finalized_beacon_root: Hash32,
    pub bootstrap_execution_state_root: Hash32,
    pub bootstrap_eth_light_client_digest: Hash32,
    pub controller_cmr: Hash32,
    pub controller_configuration_hash: Hash32,
    pub domain_separator_table_hash: Hash32,
    pub issuance_txid_display: Hash32,
    pub issuance_vout: u32,
    pub asset_entropy: Hash32,
    pub initial_controller_state_hash: Hash32,
    pub active_liability_cap_usdt_micro: u64,
    pub minimum_activation_chainwork: Hash32,
    pub max_ethereum_finality_slot_gap: u64,
    pub max_finalized_to_bmm_mtp_age_seconds: u64,
    pub minimum_bitcoin_confirmations: u32,
    pub first_deposit_nonce: u64,
    pub usdt_display_decimals: u8,
    pub usdd_display_decimals: u8,
    pub usdd_units_per_usdt_micro: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestError {
    ZeroField(&'static str),
    WrongDrivechainSlot { expected: u8, actual: u8 },
    WrongAmountScale,
    WrongSp1Identity,
    WrongDomainSeparatorTable,
    WrongControllerConfiguration,
    WrongBip300RedemptionVerifierConfiguration,
    WrongBip300RelayConfigurationBinding,
    WrongFinalityThresholds,
    WrongVaultId,
    WrongLiabilityCap,
    WrongFirstDepositNonce,
    WrongInitialControllerState,
    Encoding(DecodeError),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroField(name) => write!(f, "manifest field {name} is zero"),
            Self::WrongDrivechainSlot { expected, actual } => {
                write!(f, "Drivechain slot must be {expected}, got {actual}")
            }
            Self::WrongAmountScale => write!(
                f,
                "manifest must encode six-decimal USDT, eight-decimal USDD, and ×100 conversion"
            ),
            Self::WrongSp1Identity => f.write_str(
                "manifest must pin SP1 6.3.1 commit 8252c2905ce32964df68248117015c61ebb854db and SHA-256-only compressed-proof v1",
            ),
            Self::WrongDomainSeparatorTable => {
                f.write_str("manifest domain-separator table hash is wrong")
            }
            Self::WrongControllerConfiguration => {
                f.write_str("controller configuration hash does not match the non-circular V1 projection")
            }
            Self::WrongBip300RedemptionVerifierConfiguration => {
                f.write_str("BIP300 redemption verifier configuration hash does not match the exact Solidity RelayConfig ABI")
            }
            Self::WrongBip300RelayConfigurationBinding => {
                f.write_str("BIP300 RelayConfig does not match the manifest's network, asset, slot, finality, voting, or activation identity")
            }
            Self::WrongFinalityThresholds => f.write_str(
                "V1 requires max 4096 Ethereum slots, max 6h finalized-state age, and at least 100 Bitcoin confirmations",
            ),
            Self::WrongVaultId => f.write_str("manifest vault ID does not match Solidity constructor inputs"),
            Self::WrongLiabilityCap => f.write_str("manifest liability cap does not equal frozen V1 cap"),
            Self::WrongFirstDepositNonce => {
                f.write_str("V1 controller must begin at vault deposit nonce zero")
            }
            Self::WrongInitialControllerState => {
                f.write_str("manifest initial controller state hash is wrong")
            }
            Self::Encoding(error) => error.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ManifestError {}

impl ProtocolManifest {
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.ethereum_chain_id == 0 {
            return Err(ManifestError::ZeroField("ethereum_chain_id"));
        }
        for (name, hash) in [
            ("ethereum_genesis", self.ethereum_genesis),
            ("bitcoin_genesis", self.bitcoin_genesis),
            ("elements_genesis", self.elements_genesis),
            ("usdd_asset", self.usdd_asset),
            ("usdd_reissuance_token", self.usdd_reissuance_token),
            ("usdd_public_abf", self.usdd_public_abf),
            ("elements_policy_asset", self.elements_policy_asset),
            ("vault_id", self.vault_id),
            ("vault_code_hash", self.vault_code_hash),
            (
                "proof_verifier_runtime_code_hash",
                self.proof_verifier_runtime_code_hash,
            ),
            ("verifier_config_hash", self.verifier_config_hash),
            ("ethereum_guest_program_id", self.ethereum_guest_program_id),
            ("bip300_relay_program_id", self.bip300_relay_program_id),
            (
                "recursion_verifier_constants_hash",
                self.recursion_verifier_constants_hash,
            ),
            (
                "bootstrap_finalized_beacon_root",
                self.bootstrap_finalized_beacon_root,
            ),
            (
                "bootstrap_execution_state_root",
                self.bootstrap_execution_state_root,
            ),
            (
                "bootstrap_eth_light_client_digest",
                self.bootstrap_eth_light_client_digest,
            ),
            ("controller_cmr", self.controller_cmr),
            (
                "controller_configuration_hash",
                self.controller_configuration_hash,
            ),
            (
                "domain_separator_table_hash",
                self.domain_separator_table_hash,
            ),
            ("issuance_txid_display", self.issuance_txid_display),
            ("asset_entropy", self.asset_entropy),
            (
                "initial_controller_state_hash",
                self.initial_controller_state_hash,
            ),
            (
                "minimum_activation_chainwork",
                self.minimum_activation_chainwork,
            ),
        ] {
            if hash == Hash32::ZERO {
                return Err(ManifestError::ZeroField(name));
            }
        }
        if self.usdt.is_zero() {
            return Err(ManifestError::ZeroField("usdt"));
        }
        if self.vault.is_zero() {
            return Err(ManifestError::ZeroField("vault"));
        }
        if self.proof_verifier.is_zero() {
            return Err(ManifestError::ZeroField("proof_verifier"));
        }
        if !matches!(self.usdd_reissuance_token_generator[0], 0x0a | 0x0b)
            || !self.usdd_reissuance_token_generator[1..]
                .iter()
                .any(|byte| *byte != 0)
            || self.controller_runtime_config().validate().is_err()
        {
            return Err(ManifestError::WrongControllerConfiguration);
        }
        if self.drivechain_slot != DRIVECHAIN_SLOT {
            return Err(ManifestError::WrongDrivechainSlot {
                expected: DRIVECHAIN_SLOT,
                actual: self.drivechain_slot,
            });
        }
        if self.minimum_bitcoin_confirmations < MINIMUM_BITCOIN_CONFIRMATIONS
            || self.max_ethereum_finality_slot_gap != MAX_ETHEREUM_FINALITY_SLOT_GAP
            || self.max_finalized_to_bmm_mtp_age_seconds != MAX_FINALIZED_TO_BMM_MTP_AGE_SECONDS
        {
            return Err(ManifestError::WrongFinalityThresholds);
        }
        let relay = &self.bip300_relay_config;
        if !relay.has_valid_constructor_shape()
            || relay.program_id != self.bip300_relay_program_id
            || relay.bitcoin_genesis_hash_display != self.bitcoin_genesis
            || relay.elements_genesis_hash_display != self.elements_genesis
            || relay.usdd_asset_id_display != self.usdd_asset
            || relay.drivechain_slot != self.drivechain_slot
            || relay.active_slots_bitmap != SLOT_24_ACTIVE_BITMAP
            || relay.finality_depth != self.minimum_bitcoin_confirmations
            || relay.withdrawal_bundle_inclusion_threshold
                != BIP300_WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD
            || relay.withdrawal_bundle_max_age != BIP300_WITHDRAWAL_BUNDLE_MAX_AGE
            || relay.checkpoint_chainwork.as_bytes() != self.minimum_activation_chainwork.as_bytes()
        {
            return Err(ManifestError::WrongBip300RelayConfigurationBinding);
        }
        if self.bootstrap_finalized_beacon_slot == 0 {
            return Err(ManifestError::ZeroField("bootstrap_finalized_beacon_slot"));
        }
        if self.usdt_display_decimals != 6
            || self.usdd_display_decimals != 8
            || self.usdd_units_per_usdt_micro != USDD_UNITS_PER_USDT_MICRO
            || USDT_SCALE != 1_000_000
            || USDD_SCALE != 100_000_000
        {
            return Err(ManifestError::WrongAmountScale);
        }
        if self.sp1_version_major != SP1_VERSION_MAJOR
            || self.sp1_version_minor != SP1_VERSION_MINOR
            || self.sp1_version_patch != SP1_VERSION_PATCH
            || self.sp1_git_commit != SP1_GIT_COMMIT
            || self.compressed_proof_circuit_version != SP1_COMPRESSED_CIRCUIT_VERSION
            || self.compressed_proof_codec_version != SP1_COMPRESSED_CODEC_VERSION
            || self.public_digest_tag != SHA256_DIGEST_TAG
        {
            return Err(ManifestError::WrongSp1Identity);
        }
        if self.domain_separator_table_hash != domain_separator_table_hash() {
            return Err(ManifestError::WrongDomainSeparatorTable);
        }
        if self.controller_configuration_hash != self.compute_controller_configuration_hash() {
            return Err(ManifestError::WrongControllerConfiguration);
        }
        if self.verifier_config_hash != self.compute_bip300_redemption_verifier_config_hash() {
            return Err(ManifestError::WrongBip300RedemptionVerifierConfiguration);
        }
        if self.active_liability_cap_usdt_micro != ACTIVE_LIABILITY_CAP_USDT_MICRO {
            return Err(ManifestError::WrongLiabilityCap);
        }
        if self.first_deposit_nonce != 0 {
            return Err(ManifestError::WrongFirstDepositNonce);
        }
        if self.vault_id != self.compute_vault_id() {
            return Err(ManifestError::WrongVaultId);
        }
        if self.initial_controller_state_hash != self.compute_initial_controller_state_hash() {
            return Err(ManifestError::WrongInitialControllerState);
        }
        Ok(())
    }

    pub fn manifest_id(&self) -> Result<Hash32, ManifestError> {
        self.validate()?;
        Ok(domain_hash(Domain::Manifest, &self.encode()))
    }

    /// Non-circular identity consumed by inbound Ethereum mint proofs and the
    /// singleton Elements controller. The generic controller CMR is known
    /// before this post-genesis configuration is assembled, so it is included;
    /// only the initial state hash (which derives from this configuration) is
    /// excluded.
    pub fn inbound_mint_domain_id(&self) -> Hash32 {
        domain_hash(
            Domain::InboundMint,
            self.controller_configuration_hash.as_bytes(),
        )
    }

    pub fn compute_vault_id(&self) -> Hash32 {
        let mut preimage = Vec::with_capacity(316);
        SOLIDITY_VAULT_ID_DOMAIN.encode_to(&mut preimage);
        let mut chain_id = [0u8; 32];
        chain_id[24..].copy_from_slice(&self.ethereum_chain_id.to_be_bytes());
        chain_id.encode_to(&mut preimage);
        self.vault.encode_to(&mut preimage);
        self.usdt.encode_to(&mut preimage);
        self.proof_verifier.encode_to(&mut preimage);
        self.bip300_relay_program_id.encode_to(&mut preimage);
        self.verifier_config_hash.encode_to(&mut preimage);
        self.elements_genesis.encode_to(&mut preimage);
        self.usdd_asset.encode_to(&mut preimage);
        let mut liability_cap = [0u8; 32];
        liability_cap[24..].copy_from_slice(&self.active_liability_cap_usdt_micro.to_be_bytes());
        liability_cap.encode_to(&mut preimage);
        self.minimum_activation_chainwork.encode_to(&mut preimage);
        hash_bytes(&preimage)
    }

    /// Derive the exact post-genesis configuration encoded in every
    /// controller state and proof journal. RPC/display uint256 identities are
    /// reversed once here into Elements transaction-consensus byte order.
    pub fn controller_runtime_config(&self) -> ControllerRuntimeConfig {
        fn consensus_bytes(display: Hash32) -> Hash32 {
            let mut bytes = display.0;
            bytes.reverse();
            Hash32(bytes)
        }

        ControllerRuntimeConfig {
            usdd_asset_consensus: consensus_bytes(self.usdd_asset),
            reissuance_token_consensus: consensus_bytes(self.usdd_reissuance_token),
            public_abf_consensus: consensus_bytes(self.usdd_public_abf),
            issuance_entropy_consensus: consensus_bytes(self.asset_entropy),
            token_generator_parity: self.usdd_reissuance_token_generator[0] & 1,
            token_generator_x: Hash32(
                self.usdd_reissuance_token_generator[1..]
                    .try_into()
                    .expect("fixed generator x-coordinate"),
            ),
            policy_asset_consensus: consensus_bytes(self.elements_policy_asset),
        }
    }

    /// Commit the controller's mint-proof configuration without hashing the
    /// full manifest (which itself contains this value and the initial state
    /// hash). The projection binds the complete inbound chain, asset,
    /// controller CMR, and bootstrap issuance identity, but deliberately
    /// excludes the initial controller state to avoid a hash cycle.
    pub fn compute_controller_configuration_hash(&self) -> Hash32 {
        let mut payload = Vec::with_capacity(725);
        self.ethereum_chain_id.encode_to(&mut payload);
        self.ethereum_genesis.encode_to(&mut payload);
        self.bitcoin_genesis.encode_to(&mut payload);
        self.elements_genesis.encode_to(&mut payload);
        self.drivechain_slot.encode_to(&mut payload);
        self.usdt.encode_to(&mut payload);
        self.usdd_asset.encode_to(&mut payload);
        self.usdd_reissuance_token.encode_to(&mut payload);
        self.usdd_public_abf.encode_to(&mut payload);
        self.usdd_reissuance_token_generator.encode_to(&mut payload);
        self.elements_policy_asset.encode_to(&mut payload);
        self.vault.encode_to(&mut payload);
        self.vault_code_hash.encode_to(&mut payload);
        self.ethereum_guest_program_id.encode_to(&mut payload);
        self.controller_cmr.encode_to(&mut payload);
        self.sp1_version_major.encode_to(&mut payload);
        self.sp1_version_minor.encode_to(&mut payload);
        self.sp1_version_patch.encode_to(&mut payload);
        self.sp1_git_commit.encode_to(&mut payload);
        self.compressed_proof_circuit_version
            .encode_to(&mut payload);
        self.compressed_proof_codec_version.encode_to(&mut payload);
        self.recursion_verifier_constants_hash
            .encode_to(&mut payload);
        self.public_digest_tag.encode_to(&mut payload);
        self.bootstrap_finalized_beacon_slot.encode_to(&mut payload);
        self.bootstrap_finalized_beacon_root.encode_to(&mut payload);
        self.bootstrap_execution_state_root.encode_to(&mut payload);
        self.bootstrap_eth_light_client_digest
            .encode_to(&mut payload);
        self.issuance_txid_display.encode_to(&mut payload);
        self.issuance_vout.encode_to(&mut payload);
        self.asset_entropy.encode_to(&mut payload);
        self.domain_separator_table_hash.encode_to(&mut payload);
        self.active_liability_cap_usdt_micro.encode_to(&mut payload);
        self.max_ethereum_finality_slot_gap.encode_to(&mut payload);
        self.max_finalized_to_bmm_mtp_age_seconds
            .encode_to(&mut payload);
        self.first_deposit_nonce.encode_to(&mut payload);
        self.usdt_display_decimals.encode_to(&mut payload);
        self.usdd_display_decimals.encode_to(&mut payload);
        self.usdd_units_per_usdt_micro.encode_to(&mut payload);
        domain_hash(Domain::ControllerConfig, &payload)
    }

    /// Exact Solidity `sha256(abi.encode(RELAY_CONFIG_DOMAIN, RelayConfig))`.
    /// The full static config ABI is embedded separately in this manifest so this
    /// value is never accepted as an opaque self-asserted hash.
    pub fn compute_bip300_redemption_verifier_config_hash(&self) -> Hash32 {
        self.bip300_relay_config.config_hash()
    }

    fn initial_controller_state_unchecked(&self) -> MintControllerState {
        MintControllerState {
            version: 1,
            sequence: 0,
            next_mint_nonce: self.first_deposit_nonce,
            ethereum_light_client_digest: self.bootstrap_eth_light_client_digest,
            finalized_beacon_slot: self.bootstrap_finalized_beacon_slot,
            finalized_beacon_root: self.bootstrap_finalized_beacon_root,
            finalized_execution_state_root: self.bootstrap_execution_state_root,
            total_minted_usdd_base: 0,
            runtime_config: self.controller_runtime_config(),
            configuration_hash: self.controller_configuration_hash,
        }
    }

    /// Return the exact, nonzero-finality bootstrap state committed by a
    /// fully validated manifest. Deployment code must use this method instead
    /// of accepting independently supplied state fields.
    pub fn strict_bootstrap_state(&self) -> Result<MintControllerState, ManifestError> {
        self.validate()?;
        let state = self.initial_controller_state_unchecked();
        state
            .validate()
            .map_err(|_| ManifestError::WrongInitialControllerState)?;
        if hash_bytes(&state.encode()) != self.initial_controller_state_hash {
            return Err(ManifestError::WrongInitialControllerState);
        }
        Ok(state)
    }

    pub fn compute_initial_controller_state_hash(&self) -> Hash32 {
        hash_bytes(&self.initial_controller_state_unchecked().encode())
    }
}

impl CanonicalEncode for ProtocolManifest {
    fn encode_to(&self, out: &mut Vec<u8>) {
        ENCODING_SCHEMA.encode_to(out);
        TAG_MANIFEST.encode_to(out);
        self.ethereum_chain_id.encode_to(out);
        self.ethereum_genesis.encode_to(out);
        self.bitcoin_genesis.encode_to(out);
        self.elements_genesis.encode_to(out);
        self.drivechain_slot.encode_to(out);
        self.usdt.encode_to(out);
        self.usdd_asset.encode_to(out);
        self.usdd_reissuance_token.encode_to(out);
        self.usdd_public_abf.encode_to(out);
        self.usdd_reissuance_token_generator.encode_to(out);
        self.elements_policy_asset.encode_to(out);
        self.vault.encode_to(out);
        self.vault_id.encode_to(out);
        self.vault_code_hash.encode_to(out);
        self.proof_verifier.encode_to(out);
        self.proof_verifier_runtime_code_hash.encode_to(out);
        self.verifier_config_hash.encode_to(out);
        self.bip300_relay_config.encode_to(out);
        self.ethereum_guest_program_id.encode_to(out);
        self.bip300_relay_program_id.encode_to(out);
        self.sp1_version_major.encode_to(out);
        self.sp1_version_minor.encode_to(out);
        self.sp1_version_patch.encode_to(out);
        self.sp1_git_commit.encode_to(out);
        self.compressed_proof_circuit_version.encode_to(out);
        self.compressed_proof_codec_version.encode_to(out);
        self.recursion_verifier_constants_hash.encode_to(out);
        self.public_digest_tag.encode_to(out);
        self.bootstrap_finalized_beacon_slot.encode_to(out);
        self.bootstrap_finalized_beacon_root.encode_to(out);
        self.bootstrap_execution_state_root.encode_to(out);
        self.bootstrap_eth_light_client_digest.encode_to(out);
        self.controller_cmr.encode_to(out);
        self.controller_configuration_hash.encode_to(out);
        self.domain_separator_table_hash.encode_to(out);
        self.issuance_txid_display.encode_to(out);
        self.issuance_vout.encode_to(out);
        self.asset_entropy.encode_to(out);
        self.initial_controller_state_hash.encode_to(out);
        self.active_liability_cap_usdt_micro.encode_to(out);
        self.minimum_activation_chainwork.encode_to(out);
        self.max_ethereum_finality_slot_gap.encode_to(out);
        self.max_finalized_to_bmm_mtp_age_seconds.encode_to(out);
        self.minimum_bitcoin_confirmations.encode_to(out);
        self.first_deposit_nonce.encode_to(out);
        self.usdt_display_decimals.encode_to(out);
        self.usdd_display_decimals.encode_to(out);
        self.usdd_units_per_usdt_micro.encode_to(out);
    }
}

impl CanonicalDecode for ProtocolManifest {
    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder.u16()? != ENCODING_SCHEMA || decoder.u16()? != TAG_MANIFEST {
            return Err(DecodeError::InvalidValue("invalid manifest header"));
        }
        let value = Self {
            ethereum_chain_id: decoder.u64()?,
            ethereum_genesis: Hash32::decode_from(decoder)?,
            bitcoin_genesis: Hash32::decode_from(decoder)?,
            elements_genesis: Hash32::decode_from(decoder)?,
            drivechain_slot: decoder.u8()?,
            usdt: EthAddress::decode_from(decoder)?,
            usdd_asset: Hash32::decode_from(decoder)?,
            usdd_reissuance_token: Hash32::decode_from(decoder)?,
            usdd_public_abf: Hash32::decode_from(decoder)?,
            usdd_reissuance_token_generator: <[u8; 33]>::decode_from(decoder)?,
            elements_policy_asset: Hash32::decode_from(decoder)?,
            vault: EthAddress::decode_from(decoder)?,
            vault_id: Hash32::decode_from(decoder)?,
            vault_code_hash: Hash32::decode_from(decoder)?,
            proof_verifier: EthAddress::decode_from(decoder)?,
            proof_verifier_runtime_code_hash: Hash32::decode_from(decoder)?,
            verifier_config_hash: Hash32::decode_from(decoder)?,
            bip300_relay_config: Bip300RelayConfig::decode_from(decoder)?,
            ethereum_guest_program_id: Hash32::decode_from(decoder)?,
            bip300_relay_program_id: Hash32::decode_from(decoder)?,
            sp1_version_major: decoder.u16()?,
            sp1_version_minor: decoder.u16()?,
            sp1_version_patch: decoder.u16()?,
            sp1_git_commit: decoder.fixed()?,
            compressed_proof_circuit_version: decoder.u16()?,
            compressed_proof_codec_version: decoder.u16()?,
            recursion_verifier_constants_hash: Hash32::decode_from(decoder)?,
            public_digest_tag: decoder.u8()?,
            bootstrap_finalized_beacon_slot: decoder.u64()?,
            bootstrap_finalized_beacon_root: Hash32::decode_from(decoder)?,
            bootstrap_execution_state_root: Hash32::decode_from(decoder)?,
            bootstrap_eth_light_client_digest: Hash32::decode_from(decoder)?,
            controller_cmr: Hash32::decode_from(decoder)?,
            controller_configuration_hash: Hash32::decode_from(decoder)?,
            domain_separator_table_hash: Hash32::decode_from(decoder)?,
            issuance_txid_display: Hash32::decode_from(decoder)?,
            issuance_vout: decoder.u32()?,
            asset_entropy: Hash32::decode_from(decoder)?,
            initial_controller_state_hash: Hash32::decode_from(decoder)?,
            active_liability_cap_usdt_micro: decoder.u64()?,
            minimum_activation_chainwork: Hash32::decode_from(decoder)?,
            max_ethereum_finality_slot_gap: decoder.u64()?,
            max_finalized_to_bmm_mtp_age_seconds: decoder.u64()?,
            minimum_bitcoin_confirmations: decoder.u32()?,
            first_deposit_nonce: decoder.u64()?,
            usdt_display_decimals: decoder.u8()?,
            usdd_display_decimals: decoder.u8()?,
            usdd_units_per_usdt_micro: decoder.u64()?,
        };
        value
            .validate()
            .map_err(|_| DecodeError::InvalidValue("invalid protocol manifest"))?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AbiUint256;

    fn hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    pub(crate) fn valid_manifest() -> ProtocolManifest {
        let relay_config = Bip300RelayConfig {
            program_id: hash(15),
            bitcoin_genesis_hash_display: hash(2),
            elements_genesis_hash_display: hash(3),
            usdd_asset_id_display: hash(5),
            drivechain_slot: DRIVECHAIN_SLOT,
            active_slots_bitmap: SLOT_24_ACTIVE_BITMAP,
            checkpoint_block_hash_wire: hash(26),
            checkpoint_height: 10,
            checkpoint_mtp_timestamps_newest_first: [
                1_700_000_000,
                1_699_999_999,
                1_699_999_998,
                1_699_999_997,
                1_699_999_996,
                1_699_999_995,
                1_699_999_994,
                1_699_999_993,
                1_699_999_992,
                1_699_999_991,
                1_699_999_990,
            ],
            checkpoint_bits: 0x207f_ffff,
            checkpoint_epoch_start_time: 1_699_990_000,
            checkpoint_chainwork: AbiUint256(hash(25).0),
            checkpoint_ctip_txid_wire: hash(27),
            checkpoint_ctip_vout: 0,
            checkpoint_ctip_value: 1_000,
            finality_depth: MINIMUM_BITCOIN_CONFIRMATIONS,
            max_headers_per_batch: 32,
            retarget_interval: 2_016,
            target_timespan: 1_209_600,
            pow_limit: AbiUint256([
                0x7f, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
            ]),
            withdrawal_bundle_inclusion_threshold: BIP300_WITHDRAWAL_BUNDLE_INCLUSION_THRESHOLD,
            withdrawal_bundle_max_age: BIP300_WITHDRAWAL_BUNDLE_MAX_AGE,
            max_pending_bundles: 1_024,
            transaction_stream: EthAddress([29; 20]),
            transaction_stream_codehash: hash(30),
            transaction_stream_config_hash: hash(31),
        };
        let mut manifest = ProtocolManifest {
            ethereum_chain_id: 1,
            ethereum_genesis: hash(1),
            bitcoin_genesis: hash(2),
            elements_genesis: hash(3),
            drivechain_slot: 24,
            usdt: EthAddress([4; 20]),
            usdd_asset: hash(5),
            usdd_reissuance_token: hash(6),
            usdd_public_abf: hash(7),
            usdd_reissuance_token_generator: [0x0b; 33],
            elements_policy_asset: hash(28),
            vault: EthAddress([8; 20]),
            vault_id: hash(9),
            vault_code_hash: hash(10),
            proof_verifier: EthAddress([11; 20]),
            proof_verifier_runtime_code_hash: hash(12),
            verifier_config_hash: hash(13),
            bip300_relay_config: relay_config,
            ethereum_guest_program_id: hash(14),
            bip300_relay_program_id: hash(15),
            sp1_version_major: SP1_VERSION_MAJOR,
            sp1_version_minor: SP1_VERSION_MINOR,
            sp1_version_patch: SP1_VERSION_PATCH,
            sp1_git_commit: SP1_GIT_COMMIT,
            compressed_proof_circuit_version: SP1_COMPRESSED_CIRCUIT_VERSION,
            compressed_proof_codec_version: SP1_COMPRESSED_CODEC_VERSION,
            recursion_verifier_constants_hash: hash(16),
            public_digest_tag: SHA256_DIGEST_TAG,
            bootstrap_finalized_beacon_slot: 16,
            bootstrap_finalized_beacon_root: hash(17),
            bootstrap_execution_state_root: hash(18),
            bootstrap_eth_light_client_digest: hash(19),
            controller_cmr: hash(20),
            controller_configuration_hash: hash(21),
            domain_separator_table_hash: domain_separator_table_hash(),
            issuance_txid_display: hash(22),
            issuance_vout: 0,
            asset_entropy: hash(23),
            initial_controller_state_hash: hash(24),
            active_liability_cap_usdt_micro: ACTIVE_LIABILITY_CAP_USDT_MICRO,
            minimum_activation_chainwork: hash(25),
            max_ethereum_finality_slot_gap: MAX_ETHEREUM_FINALITY_SLOT_GAP,
            max_finalized_to_bmm_mtp_age_seconds: MAX_FINALIZED_TO_BMM_MTP_AGE_SECONDS,
            minimum_bitcoin_confirmations: MINIMUM_BITCOIN_CONFIRMATIONS,
            first_deposit_nonce: 0,
            usdt_display_decimals: 6,
            usdd_display_decimals: 8,
            usdd_units_per_usdt_micro: 100,
        };
        manifest.verifier_config_hash = manifest.compute_bip300_redemption_verifier_config_hash();
        manifest.controller_configuration_hash = manifest.compute_controller_configuration_hash();
        manifest.vault_id = manifest.compute_vault_id();
        manifest.initial_controller_state_hash = manifest.compute_initial_controller_state_hash();
        manifest
    }

    #[test]
    fn manifest_round_trip_and_commitment() {
        let manifest = valid_manifest();
        assert_eq!(
            ProtocolManifest::decode_exact(&manifest.encode()).unwrap(),
            manifest
        );
        assert_ne!(manifest.manifest_id().unwrap(), Hash32::ZERO);
    }

    #[test]
    fn wrong_slot_is_rejected() {
        let mut manifest = valid_manifest();
        manifest.drivechain_slot = 5;
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::WrongDrivechainSlot { .. })
        ));
    }

    #[test]
    fn controller_configuration_is_non_circular_and_enforced() {
        let manifest = valid_manifest();
        let runtime = manifest.controller_runtime_config();
        assert_eq!(runtime.encode().len(), ControllerRuntimeConfig::ENCODED_LEN);
        assert_eq!(runtime.token_generator_parity, 1);
        assert_eq!(runtime.encode()[128], 1);
        assert_eq!(&runtime.encode()[129..161], &[0x0b; 32]);
        let mut reversed_asset = manifest.usdd_asset.0;
        reversed_asset.reverse();
        assert_eq!(runtime.usdd_asset_consensus, Hash32(reversed_asset));
        let configuration_hash = manifest.compute_controller_configuration_hash();
        assert_eq!(manifest.controller_configuration_hash, configuration_hash);
        assert_eq!(
            manifest.inbound_mint_domain_id(),
            domain_hash(Domain::InboundMint, configuration_hash.as_bytes())
        );

        let mut non_circular = manifest.clone();
        non_circular.initial_controller_state_hash = hash(91);
        assert_eq!(
            non_circular.compute_controller_configuration_hash(),
            configuration_hash
        );

        for changed in [
            {
                let mut value = manifest.clone();
                value.bitcoin_genesis = hash(92);
                value
            },
            {
                let mut value = manifest.clone();
                value.elements_genesis = hash(93);
                value
            },
            {
                let mut value = manifest.clone();
                value.usdd_asset = hash(94);
                value
            },
            {
                let mut value = manifest.clone();
                value.usdd_reissuance_token = hash(95);
                value
            },
            {
                let mut value = manifest.clone();
                value.usdd_public_abf = hash(96);
                value
            },
            {
                let mut value = manifest.clone();
                value.usdd_reissuance_token_generator[32] ^= 1;
                value
            },
            {
                let mut value = manifest.clone();
                value.usdd_reissuance_token_generator[0] = 0x0a;
                value
            },
            {
                let mut value = manifest.clone();
                value.elements_policy_asset = hash(89);
                value
            },
            {
                let mut value = manifest.clone();
                value.controller_cmr = hash(90);
                value
            },
            {
                let mut value = manifest.clone();
                value.ethereum_chain_id += 1;
                value
            },
            {
                let mut value = manifest.clone();
                value.vault = EthAddress([88; 20]);
                value
            },
            {
                let mut value = manifest.clone();
                value.usdt = EthAddress([87; 20]);
                value
            },
            {
                let mut value = manifest.clone();
                value.issuance_txid_display = hash(97);
                value
            },
            {
                let mut value = manifest.clone();
                value.issuance_vout = 1;
                value
            },
            {
                let mut value = manifest.clone();
                value.asset_entropy = hash(98);
                value
            },
        ] {
            assert_ne!(
                changed.compute_controller_configuration_hash(),
                configuration_hash
            );
        }

        let mut changed = manifest;
        changed.ethereum_guest_program_id = hash(99);
        assert!(matches!(
            changed.validate(),
            Err(ManifestError::WrongControllerConfiguration)
        ));
    }

    #[test]
    fn bip300_redemption_configuration_binds_network_and_approval_policy() {
        let manifest = valid_manifest();
        assert_eq!(
            manifest.verifier_config_hash,
            manifest.compute_bip300_redemption_verifier_config_hash()
        );

        for mut changed in [
            {
                let mut value = manifest.clone();
                value.bitcoin_genesis = hash(90);
                value
            },
            {
                let mut value = manifest.clone();
                value.elements_genesis = hash(91);
                value
            },
            {
                let mut value = manifest.clone();
                value.minimum_bitcoin_confirmations += 1;
                value
            },
            {
                let mut value = manifest.clone();
                value.minimum_activation_chainwork = hash(92);
                value
            },
        ] {
            // Recompute downstream identities, but deliberately retain the
            // original BIP300 redemption-verifier configuration commitment.
            changed.controller_configuration_hash = changed.compute_controller_configuration_hash();
            changed.vault_id = changed.compute_vault_id();
            changed.initial_controller_state_hash = changed.compute_initial_controller_state_hash();
            assert!(matches!(
                changed.validate(),
                Err(ManifestError::WrongBip300RelayConfigurationBinding)
            ));
        }

        let mut changed = manifest.clone();
        changed.bip300_relay_config.withdrawal_bundle_max_age -= 1;
        changed.verifier_config_hash = changed.compute_bip300_redemption_verifier_config_hash();
        changed.vault_id = changed.compute_vault_id();
        assert!(matches!(
            changed.validate(),
            Err(ManifestError::WrongBip300RelayConfigurationBinding)
        ));

        let mut changed = manifest.clone();
        changed
            .bip300_relay_config
            .withdrawal_bundle_inclusion_threshold -= 1;
        changed.verifier_config_hash = changed.compute_bip300_redemption_verifier_config_hash();
        changed.vault_id = changed.compute_vault_id();
        assert!(matches!(
            changed.validate(),
            Err(ManifestError::WrongBip300RelayConfigurationBinding)
        ));

        let mut changed = manifest;
        changed.verifier_config_hash = hash(99);
        changed.vault_id = changed.compute_vault_id();
        assert!(matches!(
            changed.validate(),
            Err(ManifestError::WrongBip300RedemptionVerifierConfiguration)
        ));
    }

    #[test]
    fn first_deposit_nonce_matches_fresh_vault() {
        let mut manifest = valid_manifest();
        manifest.first_deposit_nonce = 1;
        manifest.controller_configuration_hash = manifest.compute_controller_configuration_hash();
        manifest.initial_controller_state_hash = manifest.compute_initial_controller_state_hash();
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::WrongFirstDepositNonce)
        ));
    }

    #[test]
    fn strict_bootstrap_state_is_exactly_the_nonzero_manifest_state() {
        let manifest = valid_manifest();
        let state = manifest.strict_bootstrap_state().unwrap();
        assert_eq!(state.sequence, 0);
        assert_eq!(state.next_mint_nonce, 0);
        assert_eq!(state.total_minted_usdd_base, 0);
        assert_eq!(
            state.finalized_beacon_slot,
            manifest.bootstrap_finalized_beacon_slot
        );
        assert_eq!(
            state.finalized_beacon_root,
            manifest.bootstrap_finalized_beacon_root
        );
        assert_eq!(
            state.finalized_execution_state_root,
            manifest.bootstrap_execution_state_root
        );
        assert_eq!(
            state.ethereum_light_client_digest,
            manifest.bootstrap_eth_light_client_digest
        );
        assert_ne!(state.finalized_beacon_slot, 0);
        assert_ne!(state.finalized_beacon_root, Hash32::ZERO);
        assert_ne!(state.finalized_execution_state_root, Hash32::ZERO);
        assert_ne!(state.ethereum_light_client_digest, Hash32::ZERO);
        assert_eq!(
            hash_bytes(&state.encode()),
            manifest.initial_controller_state_hash
        );
    }

    #[test]
    fn strict_bootstrap_rejects_zero_finality_and_state_hash_mismatch() {
        let mut zero_slot = valid_manifest();
        zero_slot.bootstrap_finalized_beacon_slot = 0;
        assert!(matches!(
            zero_slot.strict_bootstrap_state(),
            Err(ManifestError::ZeroField("bootstrap_finalized_beacon_slot"))
        ));

        for (name, mutate) in [
            (
                "bootstrap_finalized_beacon_root",
                (|manifest: &mut ProtocolManifest| {
                    manifest.bootstrap_finalized_beacon_root = Hash32::ZERO
                }) as fn(&mut ProtocolManifest),
            ),
            (
                "bootstrap_execution_state_root",
                |manifest: &mut ProtocolManifest| {
                    manifest.bootstrap_execution_state_root = Hash32::ZERO
                },
            ),
            (
                "bootstrap_eth_light_client_digest",
                |manifest: &mut ProtocolManifest| {
                    manifest.bootstrap_eth_light_client_digest = Hash32::ZERO
                },
            ),
        ] {
            let mut manifest = valid_manifest();
            mutate(&mut manifest);
            assert!(matches!(
                manifest.strict_bootstrap_state(),
                Err(ManifestError::ZeroField(actual)) if actual == name
            ));
        }

        let mut mismatch = valid_manifest();
        mismatch.initial_controller_state_hash = hash(99);
        assert!(matches!(
            mismatch.strict_bootstrap_state(),
            Err(ManifestError::WrongInitialControllerState)
        ));
    }
}
