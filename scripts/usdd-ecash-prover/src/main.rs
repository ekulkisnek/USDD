use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{bail, Context, Result};
use bincode::Options;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sp1_core_executor::{
    SP1CoreOpts, ShardingThreshold, ELEMENT_THRESHOLD, GAS_TRACE_CHUNK_THRESHOLD, HEIGHT_THRESHOLD,
};
use sp1_sdk::{
    CpuProver, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Proof,
    SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey, SP1_CIRCUIT_VERSION,
};
use usdd_core::{CanonicalDecode, CanonicalEncode, Hash32};
use usdd_ecash_proof_core::{
    bootstrap_state, execute_segment, BlockWitness, EcashProofConfig, SegmentInput, SegmentOutput,
};

const PACKAGE_RELEASE: &str = "6.3.1";
const SP1_V610_GROTH16_VERIFIER_HASH: [u8; 32] = [
    0x43, 0x88, 0xa2, 0x1c, 0x68, 0x7f, 0xdd, 0x5f, 0x21, 0x8d, 0x7e, 0x3d, 0x13, 0x19, 0x0c, 0xac,
    0x4c, 0x53, 0x55, 0x81, 0x8d, 0x36, 0x05, 0xfd, 0x5f, 0xb8, 0x11, 0xdf, 0x46, 0x8e, 0xe6, 0x96,
];
const SP1_V610_GROTH16_ONCHAIN_PROOF_BYTES: usize = 356;
const SEGMENT_NONCE: [u32; 4] = [0x5553_4444, 0x4543_3234, 0x5345_4731, 0x0000_0001];
const FOLD_NONCE: [u32; 4] = [0x5553_4444, 0x4543_3234, 0x464f_4c44, 0x0000_0001];
const WORKER_ENV: [(&str, &str); 26] = [
    ("RAYON_NUM_THREADS", "1"),
    ("SP1_WORKER_MAX_PROVER_PERMITS", "1"),
    ("SP1_WORKER_NUM_SPLICING_WORKERS", "1"),
    ("SP1_WORKER_SPLICING_BUFFER_SIZE", "1"),
    ("SP1_WORKER_MAX_REDUCE_ARITY", "4"),
    ("SP1_WORKER_NUMBER_OF_SEND_SPLICE_WORKERS_PER_SPLICE", "1"),
    ("SP1_WORKER_SEND_SPLICE_INPUT_BUFFER_SIZE_PER_SPLICE", "1"),
    ("SP1_WORKER_GLOBAL_MEMORY_BUFFER_SIZE", "1"),
    ("SP1_WORKER_USE_FIXED_PK", "false"),
    ("SP1_WORKER_VERIFY_INTERMEDIATES", "true"),
    ("SP1_WORKER_NUM_CORE_WORKERS", "1"),
    ("SP1_WORKER_CORE_BUFFER_SIZE", "1"),
    ("SP1_WORKER_NUM_SETUP_WORKERS", "1"),
    ("SP1_WORKER_SETUP_BUFFER_SIZE", "1"),
    ("SP1_WORKER_NORMALIZE_PROGRAM_CACHE_SIZE", "1"),
    ("SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS", "1"),
    ("SP1_WORKER_PREPARE_REDUCE_BUFFER_SIZE", "1"),
    ("SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS", "1"),
    ("SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE", "1"),
    ("SP1_WORKER_NUM_RECURSION_PROVER_WORKERS", "1"),
    ("SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE", "1"),
    ("SP1_WORKER_MAX_COMPOSE_ARITY", "4"),
    ("SP1_WORKER_NUM_DEFERRED_WORKERS", "1"),
    ("SP1_WORKER_DEFERRED_BUFFER_SIZE", "1"),
    ("SP1_WORKER_NUMBER_OF_GAS_EXECUTORS", "1"),
    ("SP1_WORKER_GAS_EXECUTOR_BUFFER_SIZE", "1"),
];

struct Identity {
    elf: Vec<u8>,
    verifying_key: SP1VerifyingKey,
    program_id: [u8; 32],
    onchain_program_vkey: [u8; 32],
    raw_vkey_hash: [u8; 32],
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenesisSegmentSpec {
    ethereum_chain_id: u64,
    relay_address: String,
    elements_genesis: String,
    usdd_asset: String,
    vault_id: String,
    verifier_config_hash: String,
    finality_depth: u32,
    max_segment_blocks: u32,
    max_transition_blocks: u32,
    max_segment_bytes: u32,
    max_state_bytes: u32,
    reward_recipient: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SuccessorSegmentSpec {
    reward_recipient: String,
    blocks: Vec<SuccessorBlockSpec>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SuccessorBlockSpec {
    raw_block: String,
    canonical_m6_artifact: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    if SP1_CIRCUIT_VERSION != "v6.1.0" {
        bail!("SP1 package {PACKAGE_RELEASE} circuit identity changed");
    }
    install_worker_profile()?;
    let mut args = env::args_os();
    let executable = args.next().unwrap_or_default();
    match args
        .next()
        .and_then(|value| value.into_string().ok())
        .as_deref()
    {
        Some("setup") => {
            let segment = required_path(&mut args, "segment ELF")?;
            let fold = required_path(&mut args, "fold ELF")?;
            reject_trailing(&mut args)?;
            setup(&segment, &fold).await
        }
        Some("prepare-genesis-segment") => {
            let segment = required_path(&mut args, "segment ELF")?;
            let fold = required_path(&mut args, "fold ELF")?;
            let spec = required_path(&mut args, "genesis-segment JSON spec")?;
            let genesis = required_path(&mut args, "raw parent genesis block")?;
            let block = required_path(&mut args, "raw parent successor block")?;
            let output = required_path(&mut args, "new output directory")?;
            reject_trailing(&mut args)?;
            prepare_genesis_segment(&segment, &fold, &spec, &genesis, &block, &output).await
        }
        Some("prepare-segment") => {
            let segment = required_path(&mut args, "segment ELF")?;
            let fold = required_path(&mut args, "fold ELF")?;
            let config = required_path(&mut args, "canonical config")?;
            let prior_state = required_path(&mut args, "canonical prior state")?;
            let spec = required_path(&mut args, "successor-segment JSON spec")?;
            let output = required_path(&mut args, "new output directory")?;
            reject_trailing(&mut args)?;
            prepare_successor_segment(&segment, &fold, &config, &prior_state, &spec, &output).await
        }
        Some("prove-segment") => {
            let segment = required_path(&mut args, "segment ELF")?;
            let fold = required_path(&mut args, "fold ELF")?;
            let input = required_path(&mut args, "canonical segment input")?;
            let output = required_path(&mut args, "new output directory")?;
            reject_trailing(&mut args)?;
            prove_segment(&segment, &fold, &input, &output).await
        }
        Some("fold") => {
            let segment = required_path(&mut args, "segment ELF")?;
            let fold = required_path(&mut args, "fold ELF")?;
            let config = required_path(&mut args, "canonical config")?;
            let left = required_path(&mut args, "left proof directory")?;
            let right = required_path(&mut args, "right proof directory")?;
            let output = required_path(&mut args, "new output directory")?;
            reject_trailing(&mut args)?;
            fold_proofs(&segment, &fold, &config, &left, &right, &output).await
        }
        Some("wrap-groth16") => {
            let segment = required_path(&mut args, "segment ELF")?;
            let fold = required_path(&mut args, "fold ELF")?;
            let proof = required_path(&mut args, "compressed proof directory")?;
            let output = required_path(&mut args, "new output directory")?;
            reject_trailing(&mut args)?;
            wrap_groth16(&segment, &fold, &proof, &output).await
        }
        _ => bail!(usage(&PathBuf::from(executable))),
    }
}

fn usage(executable: &Path) -> String {
    format!(
        "usage:\n  {0} setup <segment.elf> <fold.elf>\n  {0} prepare-genesis-segment <segment.elf> <fold.elf> <spec.json> <genesis.raw> <successor.raw> <new-output-dir>\n  {0} prepare-segment <segment.elf> <fold.elf> <config.bin> <prior-state.bin> <spec.json> <new-output-dir>\n  {0} prove-segment <segment.elf> <fold.elf> <segment-input.bin> <new-output-dir>\n  {0} fold <segment.elf> <fold.elf> <config.bin> <left-proof-dir> <right-proof-dir> <new-output-dir>\n  {0} wrap-groth16 <segment.elf> <fold.elf> <compressed-proof-dir> <new-output-dir>",
        executable.display()
    )
}

async fn prepare_genesis_segment(
    segment_path: &Path,
    fold_path: &Path,
    spec_path: &Path,
    genesis_path: &Path,
    block_path: &Path,
    output: &Path,
) -> Result<()> {
    require_new_output(output)?;
    let spec: GenesisSegmentSpec = serde_json::from_slice(
        &fs::read(spec_path).with_context(|| format!("failed to read {}", spec_path.display()))?,
    )
    .context("invalid genesis-segment JSON spec")?;
    let options = low_memory_options();
    let segment = derive_identity(segment_path, &options).await?;
    let fold = derive_identity(fold_path, &options).await?;
    require_distinct_identities(&segment, &fold)?;
    let config = EcashProofConfig {
        ethereum_chain_id: spec.ethereum_chain_id,
        relay_address: decode_fixed_hex::<20>(&spec.relay_address, "relayAddress")?,
        parent_genesis: Hash32(usdd_bitcoin_bmm::LAYER_TWO_SIGNET_GENESIS_DISPLAY),
        elements_genesis: Hash32(decode_fixed_hex::<32>(
            &spec.elements_genesis,
            "elementsGenesis",
        )?),
        usdd_asset: Hash32(decode_fixed_hex::<32>(&spec.usdd_asset, "usddAsset")?),
        vault_id: Hash32(decode_fixed_hex::<32>(&spec.vault_id, "vaultId")?),
        segment_program_id: Hash32(segment.raw_vkey_hash),
        fold_program_id: Hash32(fold.raw_vkey_hash),
        verifier_config_hash: Hash32(decode_fixed_hex::<32>(
            &spec.verifier_config_hash,
            "verifierConfigHash",
        )?),
        finality_depth: spec.finality_depth,
        max_segment_blocks: spec.max_segment_blocks,
        max_transition_blocks: spec.max_transition_blocks,
        max_segment_bytes: spec.max_segment_bytes,
        max_state_bytes: spec.max_state_bytes,
    };
    config
        .validate()
        .context("invalid genesis-segment config")?;
    let genesis = read_raw_or_hex_block(genesis_path)?;
    let block = read_raw_or_hex_block(block_path)?;
    if block.len() < 80 {
        bail!("successor parent block is shorter than its header");
    }
    let maximum_parent_block_time = u64::from(u32::from_le_bytes(
        block[68..72]
            .try_into()
            .expect("parent header length checked"),
    ));
    let prior_state = bootstrap_state(&config, &genesis).context("genesis bootstrap rejected")?;
    let expected_prior_state_commitment = prior_state.commitment(&config)?;
    let input = SegmentInput {
        config: config.clone(),
        prior_state: prior_state.clone(),
        expected_prior_state_commitment,
        blocks: vec![BlockWitness {
            raw_block: block,
            canonical_m6_artifact: None,
        }],
        maximum_parent_block_time,
        reward_recipient: decode_fixed_hex::<20>(&spec.reward_recipient, "rewardRecipient")?,
    };
    let (next_state, expected) =
        execute_segment(&input).context("native genesis segment execution rejected")?;
    fs::create_dir(output).with_context(|| format!("failed to create {}", output.display()))?;
    fs::write(output.join("config.bin"), config.encode())?;
    fs::write(output.join("prior-state.bin"), prior_state.encode())?;
    fs::write(output.join("next-state.bin"), next_state.encode())?;
    fs::write(output.join("segment-input.bin"), input.encode())?;
    fs::write(
        output.join("expected-public-values.bin"),
        expected.journal(false),
    )?;
    fs::write(
        output.join("metadata.json"),
        serde_json::to_vec_pretty(&json!({
            "schema": "usdd-ecash-genesis-segment-input-v1",
            "configHash": hex::encode(config.config_hash()?.0),
            "priorStateCommitment": hex::encode(expected_prior_state_commitment.0),
            "nextStateCommitment": hex::encode(expected.next_state_commitment.0),
            "nextTip": hex::encode(expected.next_tip_hash.0),
            "nextHeight": expected.next_height,
            "maximumParentBlockTime": maximum_parent_block_time,
            "segmentProgramId": hex::encode(segment.raw_vkey_hash),
            "foldProgramId": hex::encode(fold.raw_vkey_hash),
            "publicValues": artifact_json(&expected.journal(false)),
        }))?,
    )?;
    Ok(())
}

async fn prepare_successor_segment(
    segment_path: &Path,
    fold_path: &Path,
    config_path: &Path,
    prior_state_path: &Path,
    spec_path: &Path,
    output: &Path,
) -> Result<()> {
    require_new_output(output)?;
    let config_bytes = fs::read(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config = EcashProofConfig::decode_exact(&config_bytes).context("invalid proof config")?;
    if config.encode() != config_bytes {
        bail!("proof config is noncanonical");
    }
    let prior_state_bytes = fs::read(prior_state_path)
        .with_context(|| format!("failed to read {}", prior_state_path.display()))?;
    let prior_state = usdd_ecash_proof_core::EcashProofState::decode_exact(&prior_state_bytes)
        .context("invalid prior proof state")?;
    if prior_state.encode() != prior_state_bytes {
        bail!("prior proof state is noncanonical");
    }
    prior_state
        .validate(&config)
        .context("prior proof state does not match config")?;

    let spec_bytes =
        fs::read(spec_path).with_context(|| format!("failed to read {}", spec_path.display()))?;
    let spec: SuccessorSegmentSpec =
        serde_json::from_slice(&spec_bytes).context("invalid successor-segment JSON spec")?;
    if spec.blocks.is_empty() {
        bail!("successor segment must contain at least one block");
    }
    let spec_dir = spec_path.parent().unwrap_or_else(|| Path::new("."));
    let mut blocks = Vec::with_capacity(spec.blocks.len());
    let mut maximum_parent_block_time = 0u64;
    for (index, block_spec) in spec.blocks.iter().enumerate() {
        let raw_path = resolve_spec_path(spec_dir, &block_spec.raw_block);
        let raw_block = read_raw_or_hex_block(&raw_path)
            .with_context(|| format!("invalid raw block at spec index {index}"))?;
        if raw_block.len() < 80 {
            bail!("raw block at spec index {index} is shorter than its header");
        }
        maximum_parent_block_time = maximum_parent_block_time.max(u64::from(u32::from_le_bytes(
            raw_block[68..72]
                .try_into()
                .expect("parent header length checked"),
        )));
        let canonical_m6_artifact = block_spec
            .canonical_m6_artifact
            .as_deref()
            .map(|path| {
                let path = resolve_spec_path(spec_dir, path);
                fs::read(&path)
                    .with_context(|| format!("failed to read M6 artifact {}", path.display()))
            })
            .transpose()?;
        blocks.push(BlockWitness {
            raw_block,
            canonical_m6_artifact,
        });
    }

    let options = low_memory_options();
    let segment = derive_identity(segment_path, &options).await?;
    let fold = derive_identity(fold_path, &options).await?;
    require_config_identities(&config, &segment, &fold)?;
    let expected_prior_state_commitment = prior_state.commitment(&config)?;
    let input = SegmentInput {
        config: config.clone(),
        prior_state: prior_state.clone(),
        expected_prior_state_commitment,
        blocks,
        maximum_parent_block_time,
        reward_recipient: decode_fixed_hex::<20>(&spec.reward_recipient, "rewardRecipient")?,
    };
    let (next_state, expected) =
        execute_segment(&input).context("native successor segment execution rejected")?;

    fs::create_dir(output).with_context(|| format!("failed to create {}", output.display()))?;
    fs::write(output.join("config.bin"), config.encode())?;
    fs::write(output.join("prior-state.bin"), prior_state.encode())?;
    fs::write(output.join("next-state.bin"), next_state.encode())?;
    fs::write(output.join("segment-input.bin"), input.encode())?;
    fs::write(
        output.join("expected-public-values.bin"),
        expected.journal(false),
    )?;
    fs::write(
        output.join("metadata.json"),
        serde_json::to_vec_pretty(&json!({
            "schema": "usdd-ecash-successor-segment-input-v1",
            "configHash": hex::encode(config.config_hash()?.0),
            "priorStateCommitment": hex::encode(expected.prior_state_commitment.0),
            "nextStateCommitment": hex::encode(expected.next_state_commitment.0),
            "priorTip": hex::encode(expected.prior_tip_hash.0),
            "nextTip": hex::encode(expected.next_tip_hash.0),
            "priorHeight": expected.prior_height,
            "nextHeight": expected.next_height,
            "blockCount": expected.block_count,
            "maximumParentBlockTime": maximum_parent_block_time,
            "segmentProgramId": hex::encode(segment.raw_vkey_hash),
            "foldProgramId": hex::encode(fold.raw_vkey_hash),
            "publicValues": artifact_json(&expected.journal(false)),
        }))?,
    )?;
    Ok(())
}

fn resolve_spec_path(spec_dir: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        spec_dir.join(path)
    }
}

async fn setup(segment_path: &Path, fold_path: &Path) -> Result<()> {
    let options = low_memory_options();
    let segment = derive_identity(segment_path, &options).await?;
    let fold = derive_identity(fold_path, &options).await?;
    require_distinct_identities(&segment, &fold)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "usdd-ecash-sp1-identities-v1",
            "sp1PackageRelease": PACKAGE_RELEASE,
            "sp1CircuitVersion": SP1_CIRCUIT_VERSION,
            "segment": identity_json(&segment),
            "fold": identity_json(&fold),
        }))?
    );
    Ok(())
}

async fn prove_segment(
    segment_path: &Path,
    fold_path: &Path,
    input_path: &Path,
    output: &Path,
) -> Result<()> {
    require_new_output(output)?;
    let input_bytes =
        fs::read(input_path).with_context(|| format!("failed to read {}", input_path.display()))?;
    let input = SegmentInput::decode_exact(&input_bytes).context("invalid segment input")?;
    if input.encode() != input_bytes {
        bail!("segment input is noncanonical");
    }
    let (_, expected) = execute_segment(&input).context("native segment replay rejected input")?;
    let expected_journal = expected.journal(false);

    let options = low_memory_options();
    let segment = derive_identity(segment_path, &options).await?;
    let fold = derive_identity(fold_path, &options).await?;
    require_config_identities(&input.config, &segment, &fold)?;
    let prover = build_cpu_prover(&options).await;
    let key = SP1ProvingKey::new(segment.verifying_key.clone(), segment.elf.clone().into());
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input_bytes);
    let started = Instant::now();
    let proof = prover
        .prove(&key, stdin)
        .with_proof_nonce(SEGMENT_NONCE)
        .compressed()
        .await
        .context("SP1 failed to prove slot-24 segment")?;
    let elapsed = started.elapsed().as_millis();
    require_compressed_journal(&proof, &expected_journal)?;
    prover
        .verify(&proof, &segment.verifying_key, None)
        .context("SP1 SDK rejected the segment proof")?;
    write_proof(output, &proof, &segment, "segment", elapsed)
}

async fn fold_proofs(
    segment_path: &Path,
    fold_path: &Path,
    config_path: &Path,
    left_path: &Path,
    right_path: &Path,
    output: &Path,
) -> Result<()> {
    require_new_output(output)?;
    let config_bytes = fs::read(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config = EcashProofConfig::decode_exact(&config_bytes).context("invalid proof config")?;
    if config.encode() != config_bytes {
        bail!("proof config is noncanonical");
    }
    let options = low_memory_options();
    let segment = derive_identity(segment_path, &options).await?;
    let fold = derive_identity(fold_path, &options).await?;
    require_config_identities(&config, &segment, &fold)?;
    let left = load_child(left_path)?;
    let right = load_child(right_path)?;
    let left_identity = child_identity(&left, &segment, &fold)?;
    let right_identity = child_identity(&right, &segment, &fold)?;

    let prover = build_cpu_prover(&options).await;
    prover
        .verify(&left, &left_identity.verifying_key, None)
        .context("left child proof failed SDK verification")?;
    prover
        .verify(&right, &right_identity.verifying_key, None)
        .context("right child proof failed SDK verification")?;
    let left_output = decode_child_output(&left, &config, left_identity)?;
    let right_output = decode_child_output(&right, &config, right_identity)?;
    let expected = usdd_ecash_proof_core::fold_outputs(&config, &left_output, &right_output)
        .map_err(|_| anyhow::anyhow!("child public states are not exactly adjacent"))?;
    let expected_journal = expected.journal(true);

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(config_bytes);
    stdin.write(&left_identity.verifying_key.hash_u32());
    stdin.write_vec(left.public_values.to_vec());
    stdin.write(&right_identity.verifying_key.hash_u32());
    stdin.write_vec(right.public_values.to_vec());
    match &left.proof {
        SP1Proof::Compressed(proof) => {
            stdin.write_proof(*proof.clone(), left_identity.verifying_key.vk.clone());
        }
        _ => unreachable!("load_child requires a compressed proof"),
    }
    match &right.proof {
        SP1Proof::Compressed(proof) => {
            stdin.write_proof(*proof.clone(), right_identity.verifying_key.vk.clone());
        }
        _ => unreachable!("load_child requires a compressed proof"),
    }
    let key = SP1ProvingKey::new(fold.verifying_key.clone(), fold.elf.clone().into());
    let started = Instant::now();
    let proof = prover
        .prove(&key, stdin)
        .with_proof_nonce(FOLD_NONCE)
        .compressed()
        .await
        .context("SP1 failed to recursively fold child proofs")?;
    let elapsed = started.elapsed().as_millis();
    require_compressed_journal(&proof, &expected_journal)?;
    prover
        .verify(&proof, &fold.verifying_key, None)
        .context("SP1 SDK rejected the recursive fold proof")?;
    write_proof(output, &proof, &fold, "fold", elapsed)
}

async fn wrap_groth16(
    segment_path: &Path,
    fold_path: &Path,
    proof_path: &Path,
    output: &Path,
) -> Result<()> {
    require_new_output(output)?;
    let compressed = load_child(proof_path)?;
    let options = low_memory_options();
    let segment = derive_identity(segment_path, &options).await?;
    let fold = derive_identity(fold_path, &options).await?;
    require_distinct_identities(&segment, &fold)?;
    let identity = child_identity(&compressed, &segment, &fold)?;
    let kind = if identity.program_id == segment.program_id {
        "segment"
    } else {
        "fold"
    };

    let prover = build_cpu_prover(&options).await;
    prover
        .verify(&compressed, &identity.verifying_key, None)
        .context("SP1 SDK rejected the compressed proof before wrapping")?;
    let started = Instant::now();
    let groth16 = prover
        .groth16_wrap_compressed(&compressed.proof)
        .await
        .context("SP1 failed to shrink/wrap the compressed proof as Groth16")?;
    let elapsed_millis = started.elapsed().as_millis();
    let wrapped = SP1ProofWithPublicValues::new(
        SP1Proof::Groth16(groth16.clone()),
        compressed.public_values.clone(),
        SP1_CIRCUIT_VERSION.to_owned(),
    );
    prover
        .verify(&wrapped, &identity.verifying_key, None)
        .context("SP1 SDK rejected the generated Groth16 proof")?;

    let onchain_proof = wrapped.bytes();
    if groth16.groth16_vkey_hash != SP1_V610_GROTH16_VERIFIER_HASH {
        bail!(
            "Groth16 wrapper identity mismatch: expected {}, got {}",
            hex::encode(SP1_V610_GROTH16_VERIFIER_HASH),
            hex::encode(groth16.groth16_vkey_hash)
        );
    }
    if onchain_proof.len() != SP1_V610_GROTH16_ONCHAIN_PROOF_BYTES {
        bail!(
            "noncanonical Groth16 on-chain proof length: expected {}, got {}",
            SP1_V610_GROTH16_ONCHAIN_PROOF_BYTES,
            onchain_proof.len()
        );
    }
    if onchain_proof[..4] != SP1_V610_GROTH16_VERIFIER_HASH[..4] {
        bail!("Groth16 on-chain proof does not carry the pinned verifier selector");
    }
    let relay_proof = [
        compressed.public_values.as_slice(),
        onchain_proof.as_slice(),
    ]
    .concat();
    fs::create_dir(output).with_context(|| format!("failed to create {}", output.display()))?;
    wrapped.save(output.join("proof.sp1.bin"))?;
    fs::write(output.join("groth16-proof.bin"), &onchain_proof)?;
    fs::write(output.join("relay-proof.bin"), &relay_proof)?;
    fs::write(
        output.join("public-values.bin"),
        compressed.public_values.as_slice(),
    )?;
    fs::write(output.join("program-id.bin"), identity.program_id)?;
    fs::write(
        output.join("program-vkey-bn254.bin"),
        identity.onchain_program_vkey,
    )?;
    fs::write(
        output.join("groth16-proof.json"),
        serde_json::to_vec_pretty(&groth16)?,
    )?;
    let verifier_arguments = json!({
        "interface": "ISP1Verifier.verifyProof(bytes32 programVKey,bytes publicValues,bytes proofBytes)",
        "programVKey": format!("0x{}", hex::encode(identity.onchain_program_vkey)),
        "publicValues": format!("0x{}", hex::encode(compressed.public_values.as_slice())),
        "proofBytes": format!("0x{}", hex::encode(&onchain_proof)),
        "usddRelayProof": format!("0x{}", hex::encode(&relay_proof)),
    });
    fs::write(
        output.join("ethereum-verifier-arguments.json"),
        serde_json::to_vec_pretty(&verifier_arguments)?,
    )?;
    let metadata = json!({
        "schema": "usdd-ecash-groth16-wrapper-v1",
        "status": "GROTH16_WRAPPER_SDK_VERIFIED",
        "kind": kind,
        "sourceProofMode": "compressed-transparent",
        "outputProofMode": "groth16-bn254",
        "sp1PackageRelease": PACKAGE_RELEASE,
        "sp1CircuitVersion": SP1_CIRCUIT_VERSION,
        "programIdHashBytes": hex::encode(identity.program_id),
        "programVKeyBn254": hex::encode(identity.onchain_program_vkey),
        "rawVkeyHashFixedLittleEndian": hex::encode(identity.raw_vkey_hash),
        "sourceProof": artifact_json(&fs::read(proof_path.join("proof.raw.bin")).context("missing source proof.raw.bin")?),
        "publicValues": artifact_json(compressed.public_values.as_slice()),
        "onchainProof": artifact_json(&onchain_proof),
        "usddRelayProof": artifact_json(&relay_proof),
        "groth16VkeyHash": hex::encode(groth16.groth16_vkey_hash),
        "groth16PublicInputs": groth16.public_inputs,
        "wrapMilliseconds": elapsed_millis,
        "sdkVerifiedBeforeWrap": true,
        "sdkVerifiedAfterWrap": true,
        "tee": false,
    });
    fs::write(
        output.join("wrap-metadata.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&metadata)?);
    Ok(())
}

async fn derive_identity(path: &Path, options: &SP1CoreOpts) -> Result<Identity> {
    let elf = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if elf.is_empty() {
        bail!("guest ELF is empty: {}", path.display());
    }
    let client = ProverClient::builder()
        .light()
        .core_opts(options.clone())
        .build()
        .await;
    let key = client
        .setup(elf.clone().into())
        .await
        .context("SP1 setup rejected guest ELF")?;
    if &key.elf()[..] != elf {
        bail!("SP1 setup returned a key for different ELF bytes");
    }
    let verifying_key = key.verifying_key().clone();
    Ok(Identity {
        elf,
        program_id: verifying_key.hash_bytes(),
        onchain_program_vkey: verifying_key.bytes32_raw(),
        raw_vkey_hash: words_le(verifying_key.hash_u32()),
        verifying_key,
    })
}

async fn build_cpu_prover(options: &SP1CoreOpts) -> CpuProver {
    ProverClient::builder()
        .cpu()
        .core_opts(options.clone())
        .build()
        .await
}

fn require_config_identities(
    config: &EcashProofConfig,
    segment: &Identity,
    fold: &Identity,
) -> Result<()> {
    config.validate().context("invalid eCash proof config")?;
    require_distinct_identities(segment, fold)?;
    if config.segment_program_id != Hash32(segment.raw_vkey_hash)
        || config.fold_program_id != Hash32(fold.raw_vkey_hash)
    {
        bail!(
            "config does not pin the exact segment/fold raw vkey hashes: segment={}, fold={}",
            hex::encode(segment.raw_vkey_hash),
            hex::encode(fold.raw_vkey_hash)
        );
    }
    Ok(())
}

fn require_distinct_identities(segment: &Identity, fold: &Identity) -> Result<()> {
    if segment.program_id == fold.program_id || segment.raw_vkey_hash == fold.raw_vkey_hash {
        bail!("segment and recursive fold guests must have distinct identities");
    }
    Ok(())
}

fn child_identity<'a>(
    proof: &SP1ProofWithPublicValues,
    segment: &'a Identity,
    fold: &'a Identity,
) -> Result<&'a Identity> {
    let journal = proof.public_values.as_slice();
    if journal.starts_with(usdd_ecash_proof_core::ECASH_SEGMENT_JOURNAL_DOMAIN) {
        Ok(segment)
    } else if journal.starts_with(usdd_ecash_proof_core::ECASH_FOLD_JOURNAL_DOMAIN) {
        Ok(fold)
    } else {
        bail!("child proof has an unsupported public-values domain");
    }
}

fn decode_child_output(
    proof: &SP1ProofWithPublicValues,
    config: &EcashProofConfig,
    identity: &Identity,
) -> Result<SegmentOutput> {
    let journal = proof.public_values.as_slice();
    let domain = if identity.raw_vkey_hash == config.segment_program_id.0 {
        usdd_ecash_proof_core::ECASH_SEGMENT_JOURNAL_DOMAIN
    } else {
        usdd_ecash_proof_core::ECASH_FOLD_JOURNAL_DOMAIN
    };
    let encoded = journal
        .strip_prefix(domain)
        .context("child journal domain and vkey disagree")?;
    let output = SegmentOutput::decode_exact(encoded).context("invalid child output")?;
    output
        .validate(config)
        .context("invalid child state transition")?;
    Ok(output)
}

fn load_child(path: &Path) -> Result<SP1ProofWithPublicValues> {
    let proof = SP1ProofWithPublicValues::load(path.join("proof.sp1.bin"))
        .with_context(|| format!("failed to load child proof from {}", path.display()))?;
    if proof.sp1_version != SP1_CIRCUIT_VERSION || proof.tee_proof.is_some() {
        bail!("child proof has the wrong SP1 circuit version or a TEE attachment");
    }
    if !matches!(proof.proof, SP1Proof::Compressed(_)) {
        bail!("child is not a transparent compressed SP1 proof");
    }
    Ok(proof)
}

fn require_compressed_journal(
    proof: &SP1ProofWithPublicValues,
    expected_journal: &[u8],
) -> Result<()> {
    if proof.sp1_version != SP1_CIRCUIT_VERSION || proof.tee_proof.is_some() {
        bail!("proof has the wrong circuit version or a TEE attachment");
    }
    if !matches!(proof.proof, SP1Proof::Compressed(_)) {
        bail!("prover returned a non-compressed proof");
    }
    if proof.public_values.as_slice() != expected_journal {
        bail!("proved public values do not match native canonical execution");
    }
    Ok(())
}

fn write_proof(
    output: &Path,
    proof: &SP1ProofWithPublicValues,
    identity: &Identity,
    kind: &str,
    elapsed_millis: u128,
) -> Result<()> {
    fs::create_dir(output).with_context(|| format!("failed to create {}", output.display()))?;
    proof.save(output.join("proof.sp1.bin"))?;
    let raw = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&proof.proof)
        .context("failed to encode compressed proof canonically")?;
    let journal = proof.public_values.to_vec();
    fs::write(output.join("proof.raw.bin"), &raw)?;
    fs::write(output.join("public-values.bin"), &journal)?;
    fs::write(output.join("program-id.bin"), identity.program_id)?;
    fs::write(
        output.join("program-vkey-bn254.bin"),
        identity.onchain_program_vkey,
    )?;
    fs::write(output.join("raw-vkey-hash.bin"), identity.raw_vkey_hash)?;
    let metadata = json!({
        "schema": "usdd-ecash-proof-artifact-v1",
        "kind": kind,
        "proofMode": "compressed-transparent",
        "sp1PackageRelease": PACKAGE_RELEASE,
        "sp1CircuitVersion": SP1_CIRCUIT_VERSION,
        "programIdHashBytes": hex::encode(identity.program_id),
        "programVKeyBn254": hex::encode(identity.onchain_program_vkey),
        "rawVkeyHashFixedLittleEndian": hex::encode(identity.raw_vkey_hash),
        "elf": artifact_json(&identity.elf),
        "rawProof": artifact_json(&raw),
        "publicValues": artifact_json(&journal),
        "proveMilliseconds": elapsed_millis,
        "tee": false,
        "deferredProofVerification": true,
        "intermediateProofVerification": true,
    });
    fs::write(
        output.join("proof-metadata.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&metadata)?);
    Ok(())
}

fn identity_json(identity: &Identity) -> serde_json::Value {
    json!({
        "programIdHashBytes": hex::encode(identity.program_id),
        "programVKeyBn254": hex::encode(identity.onchain_program_vkey),
        "rawVkeyHashFixedLittleEndian": hex::encode(identity.raw_vkey_hash),
        "elf": artifact_json(&identity.elf),
    })
}

fn artifact_json(bytes: &[u8]) -> serde_json::Value {
    json!({
        "bytes": bytes.len(),
        "sha256": hex::encode(Sha256::digest(bytes)),
    })
}

fn words_le(words: [u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, word) in words.into_iter().enumerate() {
        out[index * 4..(index + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || value.starts_with("0x") || value != value.to_ascii_lowercase() {
        bail!(
            "{label} must be exactly {} lowercase hex characters without 0x",
            N * 2
        );
    }
    let decoded = hex::decode(value).with_context(|| format!("{label} is not hex"))?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} has the wrong decoded length"))
}

fn read_raw_or_hex_block(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if path.extension().and_then(|value| value.to_str()) != Some("hex") {
        return Ok(bytes);
    }
    let text = std::str::from_utf8(&bytes).context("hex block file is not UTF-8")?;
    let canonical = text.strip_suffix('\n').unwrap_or(text);
    if canonical.is_empty()
        || canonical.len() % 2 != 0
        || canonical != canonical.to_ascii_lowercase()
        || !canonical.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("hex block file is not canonical lowercase even-length hex");
    }
    hex::decode(canonical).context("failed to decode hex block file")
}

fn low_memory_options() -> SP1CoreOpts {
    let mut options = SP1CoreOpts::default();
    options.minimal_trace_chunk_threshold = 1 << 20;
    options.trace_chunk_slots = 1;
    options.gas_trace_chunk_threshold = GAS_TRACE_CHUNK_THRESHOLD;
    options.gas_trace_chunk_slots = 1;
    options.memory_limit = 4 * 1024 * 1024 * 1024;
    options.shard_size = 1 << 20;
    options.sharding_threshold = ShardingThreshold {
        element_threshold: ELEMENT_THRESHOLD,
        height_threshold: HEIGHT_THRESHOLD,
    };
    options.global_dependencies_opt = false;
    options.recompute_gkr_trace = false;
    options
}

fn install_worker_profile() -> Result<()> {
    if env::var("WITHOUT_VK_VERIFICATION")
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
    {
        bail!("WITHOUT_VK_VERIFICATION is forbidden");
    }
    for (name, value) in WORKER_ENV {
        env::set_var(name, value);
    }
    Ok(())
}

fn required_path(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    label: &str,
) -> Result<PathBuf> {
    args.next()
        .map(PathBuf::from)
        .with_context(|| format!("missing {label}"))
}

fn reject_trailing(args: &mut impl Iterator<Item = std::ffi::OsString>) -> Result<()> {
    if args.next().is_some() {
        bail!("unexpected trailing argument");
    }
    Ok(())
}

fn require_new_output(path: &Path) -> Result<()> {
    if path.exists() {
        bail!(
            "refusing to overwrite existing output path {}",
            path.display()
        );
    }
    Ok(())
}
