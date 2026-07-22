use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use bincode::Options;
use serde_json::json;
use sha2::{Digest, Sha256};
use sp1_core_executor::{
    SP1CoreOpts, ShardingThreshold, ELEMENT_THRESHOLD, GAS_TRACE_CHUNK_THRESHOLD, HEIGHT_THRESHOLD,
};
use sp1_sdk::{
    CpuProver, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Proof,
    SP1ProvingKey, SP1Stdin, SP1VerifyingKey, SP1_CIRCUIT_VERSION as UPSTREAM_SP1_CIRCUIT_VERSION,
};
use usdd_core::{CanonicalEncode, Hash32};
use usdd_proof_core::{Sp1ProofAnnex, StatementKind};
use usdd_sp1_verifier::{
    verify_raw_compressed_sha256, MAX_RAW_COMPRESSED_PROOF_SIZE, SP1_VERSION as SP1_PACKAGE_RELEASE,
};

#[cfg(not(feature = "usdd-host-patch"))]
compile_error!("usdd-sp1-prover must use its pinned usdd-host-patch dependency workflow");

const INPUT_NAMES: [&str; 5] = [
    "00-statement-tag.bin",
    "01-manifest.bin",
    "02-claim.bin",
    "03-finality.bin",
    "04-vault-witness.bin",
];

// These values change only how the same SP1 statement is partitioned and how
// much work is performed concurrently. They do not disable any proof check or
// change the recursion verification-key set.
const LOW_MEMORY_SHARD_SIZE: usize = 1 << 20;
const LOW_MEMORY_TRACE_CHUNK_ENTRIES: u64 = 1 << 20;
const LOW_MEMORY_TRACE_CHUNK_SLOTS: usize = 1;
const LOW_MEMORY_GAS_TRACE_CHUNK_SLOTS: usize = 1;
const LOW_MEMORY_EXECUTOR_MEMORY_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
// Domain-readable, deterministic, and deliberately nonzero. This freezes the
// first canonical proof's 128-bit SP1 proof nonce and exercises the patched
// local-node nonce path rather than silently accepting the stock zeroing bug.
const CANONICAL_PROOF_NONCE: [u32; 4] = [0x5553_4444, 0x4554_4831, 0x0000_0001, 0xa11d_6e5e];
const FROZEN_ETHEREUM_PROGRAM_ID: &str =
    "4f0511103dab14b61dd5b1403d077ba10d28a89a06dbb54d43e9683542c1df08";
const FROZEN_ETHEREUM_RAW_VKEY_HASH: &str =
    "1011054fb614ab3d40b1d51da17b073d9aa8280d4db5db063568e94308dfc142";
const PINNED_SP1_PACKAGE_RELEASE: &str = "6.3.1";
// `SP1ProofWithPublicValues::sp1_version` is not the Cargo package release.
// SP1 6.3.1 fills it from the exact `sp1-prover/SP1_CIRCUIT_VERSION` file.
// The authenticated 6.3.1 crate contains these six bytes with no newline.
const PINNED_SP1_CIRCUIT_VERSION: &str = "v6.1.0";

#[cfg(feature = "usdd-host-patch")]
const SETUP_CACHE_STATUS: &str = "PINNED_USDD_HOST_PATCH_ONE_SHOT_VKEY_HINT";
#[cfg(not(feature = "usdd-host-patch"))]
const SETUP_CACHE_STATUS: &str = "STOCK_SP1_6_3_1_DUPLICATE_SETUP";

// SP1 6.3.1 exposes worker cardinality only through these process variables.
// Keep both recursion arities at four. The pinned shape catalogue supplies a
// reduce shape only for that standard maximum; a lower compose maximum panics
// during full-prover initialization rather than providing a supported binary
// aggregation profile.
const LOW_MEMORY_WORKER_ENV: [(&str, &str); 26] = [
    ("RAYON_NUM_THREADS", "1"),
    // This patched semaphore is shared across core, recursion, shrink, and
    // wrap proving. One permit prevents those individually single-worker
    // stages from retaining large proving allocations at the same time.
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    require_compiled_sp1_identity()?;
    let mut args = env::args_os();
    let executable = args.next().unwrap_or_default();
    let command = args.next().with_context(|| usage(&executable))?;

    match command.to_str() {
        Some("preflight-init") => {
            reject_trailing(&mut args)?;
            preflight_init().await
        }
        Some("preflight-setup") => {
            let elf = required_path(&mut args, "guest ELF")?;
            reject_trailing(&mut args)?;
            preflight_setup(&elf).await
        }
        Some("prove") => {
            let elf = required_path(&mut args, "guest ELF")?;
            let fixture = required_path(&mut args, "fixture directory")?;
            let output = required_path(&mut args, "output directory")?;
            reject_trailing(&mut args)?;
            prove(&elf, &fixture, &output).await
        }
        Some("verify") => {
            let expected_program_id = args
                .next()
                .context("missing expected program ID")
                .and_then(|value| parse_program_id(&value))?;
            let annex = required_path(&mut args, "annex")?;
            reject_trailing(&mut args)?;
            verify_annex(&annex, expected_program_id)
        }
        _ => bail!(usage(&executable)),
    }
}

fn usage(executable: &std::ffi::OsStr) -> String {
    format!(
        "usage:\n  {} preflight-init\n  {} preflight-setup <guest.elf>\n  {} prove <guest.elf> <fixture-directory> <new-output-directory>\n  {} verify <expected-program-id-hex> <annex.bin>",
        PathBuf::from(executable).display(),
        PathBuf::from(executable).display(),
        PathBuf::from(executable).display(),
        PathBuf::from(executable).display(),
    )
}

fn parse_program_id(encoded: &std::ffi::OsStr) -> Result<Hash32> {
    let encoded = encoded
        .to_str()
        .context("expected program ID must be 64 lowercase hexadecimal characters")?;
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("expected program ID must be 64 lowercase hexadecimal characters");
    }
    let decoded = hex::decode(encoded).context("expected program ID is not hexadecimal")?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected program ID must decode to exactly 32 bytes"))?;
    Ok(Hash32(bytes))
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

async fn build_real_cpu_prover(core_opts: &SP1CoreOpts) -> CpuProver {
    ProverClient::builder()
        .cpu()
        .core_opts(core_opts.clone())
        .build()
        .await
}

struct IdentitySetup {
    verifying_key: SP1VerifyingKey,
    program_id: Hash32,
    raw_vkey_hash: [u8; 32],
    elapsed: Duration,
}

fn read_guest_elf(path: &Path) -> Result<Vec<u8>> {
    let elf = fs::read(path)
        .with_context(|| format!("failed to read guest ELF at {}", path.display()))?;
    if elf.is_empty() {
        bail!("guest ELF is empty");
    }
    Ok(elf)
}

fn frozen_raw_vkey_hash() -> Result<[u8; 32]> {
    let decoded = hex::decode(FROZEN_ETHEREUM_RAW_VKEY_HASH)
        .context("frozen Ethereum raw vkey hash is not hexadecimal")?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("frozen Ethereum raw vkey hash is not exactly 32 bytes"))
}

/// Run the exact independent light-client identity setup used before `prove`.
/// The returned full vkey is a checked hint, not authority: the patched CPU
/// prover later requires every core shard to derive the same key from the ELF.
async fn derive_program_identity(elf: &[u8], core_opts: &SP1CoreOpts) -> Result<IdentitySetup> {
    let started = Instant::now();
    let setup_prover = ProverClient::builder()
        .light()
        .core_opts(core_opts.clone())
        .build()
        .await;
    let setup_key = setup_prover
        .setup(elf.to_vec().into())
        .await
        .context("SP1 setup rejected the guest ELF")?;

    if &setup_key.elf()[..] != elf {
        bail!("SP1 setup key is not bound to the exact supplied ELF bytes");
    }
    let verifying_key = setup_key.verifying_key().clone();
    let program_id = Hash32(verifying_key.hash_bytes());
    if program_id == Hash32::ZERO {
        bail!("SP1 setup produced a zero program ID");
    }
    let expected_program_id = parse_program_id(std::ffi::OsStr::new(FROZEN_ETHEREUM_PROGRAM_ID))?;
    if program_id != expected_program_id {
        bail!(
            "SP1 setup program ID {} does not match frozen Ethereum guest identity {}",
            hex::encode(program_id.0),
            FROZEN_ETHEREUM_PROGRAM_ID,
        );
    }

    let raw_vkey_hash = raw_vkey_hash(verifying_key.hash_u32());
    let expected_raw_vkey_hash = frozen_raw_vkey_hash()?;
    if raw_vkey_hash != expected_raw_vkey_hash {
        bail!(
            "SP1 setup raw vkey hash {} does not match frozen Ethereum raw vkey hash {}",
            hex::encode(raw_vkey_hash),
            FROZEN_ETHEREUM_RAW_VKEY_HASH,
        );
    }
    let roundtrip_raw_vkey_hash = raw_vkey_hash_from_program_id(program_id)?;
    if roundtrip_raw_vkey_hash != raw_vkey_hash {
        bail!("SP1 program-ID and raw-vkey-hash encodings do not identify the same exact key");
    }

    drop(setup_key);
    drop(setup_prover);
    Ok(IdentitySetup {
        verifying_key,
        program_id,
        raw_vkey_hash,
        elapsed: started.elapsed(),
    })
}

/// Construct the exact local CPU prover used by `prove`, then exit before any
/// guest setup, execution, or proof request. This is intentionally a distinct
/// command so resource monitoring can kill initialization without risking a
/// transition into an unbounded proof run.
async fn preflight_init() -> Result<()> {
    install_low_memory_worker_profile()?;
    let core_opts = low_memory_core_opts();
    let started = Instant::now();
    let prover = build_real_cpu_prover(&core_opts).await;
    let elapsed = started.elapsed();
    drop(prover);

    let report = json!({
        "schema": 2,
        "status": "FULL_CPU_PROVER_INITIALIZED_NO_PROOF_ATTEMPTED",
        "sp1PackageRelease": SP1_PACKAGE_RELEASE,
        "sp1CircuitVersion": UPSTREAM_SP1_CIRCUIT_VERSION,
        "hostPatch": SETUP_CACHE_STATUS,
        "elapsedMilliseconds": elapsed.as_millis(),
        "intermediateProofVerification": true,
        "recursionVkeyVerification": true,
        "proofRequested": false,
        "lowMemoryProfile": {
            "shardSizeCycles": core_opts.shard_size,
            "maxReduceArity": 4,
            "maxComposeArity": 4,
            "workerEnvironment": LOW_MEMORY_WORKER_ENV
                .iter()
                .copied()
                .collect::<std::collections::BTreeMap<_, _>>(),
        },
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

/// Derive and validate the frozen Ethereum guest identity, release every
/// setup object, and exit without constructing the full CPU prover.
async fn preflight_setup(elf_path: &Path) -> Result<()> {
    let elf = read_guest_elf(elf_path)?;
    install_low_memory_worker_profile()?;
    let core_opts = low_memory_core_opts();
    let IdentitySetup {
        verifying_key,
        program_id,
        raw_vkey_hash,
        elapsed,
    } = derive_program_identity(&elf, &core_opts).await?;

    let report = json!({
        "schema": 2,
        "status": "FROZEN_PROGRAM_IDENTITY_VALIDATED_NO_FULL_PROVER_OR_PROOF",
        "sp1PackageRelease": SP1_PACKAGE_RELEASE,
        "sp1CircuitVersion": UPSTREAM_SP1_CIRCUIT_VERSION,
        "hostPatch": SETUP_CACHE_STATUS,
        "elf": artifact_json(&elf),
        "programId": hex::encode(program_id.0),
        "rawVkeyHashFixedLittleEndian": hex::encode(raw_vkey_hash),
        "frozenProgramIdentityMatch": true,
        "exactElfBindingMatch": true,
        "programIdRawVkeyEncodingMatch": true,
        "elapsedMilliseconds": elapsed.as_millis(),
        "fullCpuProverInitialized": false,
        "guestExecuted": false,
        "proofRequested": false,
    });
    // Make the resource-lifetime boundary explicit: no setup vkey or ELF
    // allocation is retained while the success report is emitted.
    drop(verifying_key);
    drop(elf);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn prove(elf_path: &Path, fixture_dir: &Path, output_dir: &Path) -> Result<()> {
    if output_dir.exists() {
        bail!(
            "refusing to overwrite existing output path {}",
            output_dir.display()
        );
    }
    let elf = read_guest_elf(elf_path)?;

    install_low_memory_worker_profile()?;
    let core_opts = low_memory_core_opts();

    let mut stdin = SP1Stdin::new();
    let mut input_bytes = 0usize;
    for name in INPUT_NAMES {
        let path = fixture_dir.join(name);
        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read fixture input {}", path.display()))?;
        input_bytes = input_bytes
            .checked_add(bytes.len())
            .context("fixture byte length overflow")?;
        stdin.write_vec(bytes);
    }
    let expected_journal = fs::read(fixture_dir.join("expected-journal.bin"))
        .context("failed to read expected-journal.bin")?;

    // Derive and validate the program identity before entering the expensive
    // CPU prover. The pinned host patch later installs this typed full vkey as
    // a one-shot hint under the controller's fresh artifact for the same ELF.
    let IdentitySetup {
        verifying_key,
        program_id,
        raw_vkey_hash,
        elapsed: identity_setup_elapsed,
    } = derive_program_identity(&elf, &core_opts).await?;

    // This is the real local CPU prover. There is deliberately no mock, TEE,
    // network-attestation, Groth16, or PLONK branch in this binary. Rebuild the
    // minimal SDK proving-key handle from the independently derived vkey and
    // ELF. The hint is not authority: every core shard derives its vkey from
    // the ELF and must equal this full key. The proof is checked against the
    // same independently-derived vkey below.
    let prover_init_started = Instant::now();
    let prover = build_real_cpu_prover(&core_opts).await;
    let prover_init_elapsed = prover_init_started.elapsed();
    let proving_key = SP1ProvingKey::new(verifying_key.clone(), elf.clone().into());

    let prove_started = Instant::now();
    let proof_with_public_values = prover
        .prove(&proving_key, stdin)
        .with_proof_nonce(CANONICAL_PROOF_NONCE)
        .compressed()
        .await
        .context("SP1 failed to produce a compressed proof")?;
    let prove_elapsed = prove_started.elapsed();
    require_proof_circuit_version(&proof_with_public_values.sp1_version)?;
    if !matches!(proof_with_public_values.proof, SP1Proof::Compressed(_)) {
        bail!("SP1 returned a non-compressed proof despite the pinned request");
    }
    let public_values = proof_with_public_values.public_values.to_vec();
    if public_values != expected_journal {
        bail!(
            "proved public values differ from expected journal: got {} bytes, expected {} bytes",
            public_values.len(),
            expected_journal.len()
        );
    }
    let raw_proof = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&proof_with_public_values.proof)
        .context("failed to serialize the raw compressed proof canonically")?;

    // Preserve the expensive raw result before applying the on-chain size
    // gate. If the proof is too large, the measurements remain auditable but
    // no annex is emitted and the command fails closed.
    fs::create_dir(output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;
    fs::write(output_dir.join("proof.raw.bin"), &raw_proof)?;
    fs::write(output_dir.join("public-values.bin"), &public_values)?;
    fs::write(output_dir.join("program-id.bin"), program_id.0)?;
    fs::write(output_dir.join("raw-vkey-hash.bin"), raw_vkey_hash)?;

    let sdk_verify_started = Instant::now();
    prover
        .verify(&proof_with_public_values, &verifying_key, None)
        .context("SP1 SDK rejected the proof it produced")?;
    let sdk_verify_elapsed = sdk_verify_started.elapsed();

    let adapter_verify_started = Instant::now();
    let journal = verify_raw_compressed_sha256(
        &raw_proof,
        &public_values,
        &raw_vkey_hash,
        program_id,
        StatementKind::EthereumState,
    )
    .context("USDD SHA-256-only verifier adapter rejected the proof")?;
    let adapter_verify_elapsed = adapter_verify_started.elapsed();

    let annex = Sp1ProofAnnex::new(
        StatementKind::EthereumState,
        program_id,
        public_values.clone(),
        raw_proof.clone(),
    )
    .context("proof does not fit the canonical USDD Elements annex")?
    .encode();
    fs::write(output_dir.join("annex.bin"), &annex)?;

    let metadata = json!({
        "schema": 2,
        "status": "RAW_COMPRESSED_PROOF_VERIFIED",
        "sp1PackageRelease": SP1_PACKAGE_RELEASE,
        "sp1CircuitVersion": UPSTREAM_SP1_CIRCUIT_VERSION,
        "proofMode": "compressed-transparent",
        "digestMode": "sha256",
        "programId": hex::encode(program_id.0),
        "rawVkeyHashFixedLittleEndian": hex::encode(raw_vkey_hash),
        "elf": artifact_json(&elf),
        "fixtureInputBytes": input_bytes,
        "publicValues": artifact_json(&public_values),
        "rawProof": artifact_json(&raw_proof),
        "annex": artifact_json(&annex),
        "maximumRawProofBytes": MAX_RAW_COMPRESSED_PROOF_SIZE,
        "statementKind": format!("{:?}", journal.statement_kind()),
        "proofNonceU32LittleEndianWords": CANONICAL_PROOF_NONCE,
        "setupBehavior": setup_behavior_json(),
        "lowMemoryProfile": {
            "shardSizeCycles": core_opts.shard_size,
            "minimalTraceChunkEntries": core_opts.minimal_trace_chunk_threshold,
            "traceChunkSlots": core_opts.trace_chunk_slots,
            "gasTraceChunkEntries": core_opts.gas_trace_chunk_threshold,
            "gasTraceChunkSlots": core_opts.gas_trace_chunk_slots,
            "gasChunkCadencePreserved": true,
            "executorMemoryLimitBytes": core_opts.memory_limit,
            "executorMemoryLimitSemantics": executor_memory_limit_semantics(),
            "traceChunkSlotsEffective": trace_chunk_slots_are_effective(),
            "elementThreshold": core_opts.sharding_threshold.element_threshold,
            "heightThreshold": core_opts.sharding_threshold.height_threshold,
            "workerEnvironment": LOW_MEMORY_WORKER_ENV
                .iter()
                .copied()
                .collect::<std::collections::BTreeMap<_, _>>(),
            "intermediateProofVerification": true,
            "recursionVkVerification": true,
            "recursionProvingKeys": "expected-vkeys-retained-proving-keys-derived-serially-on-demand-and-dropped",
            "maxReduceArity": 4,
            "maxComposeArity": 4,
        },
        "timingMilliseconds": {
            "identitySetup": identity_setup_elapsed.as_millis(),
            "fullProverInitialization": prover_init_elapsed.as_millis(),
            // Includes on-demand recursion proving-key derivations. The
            // patched controller does not repeat the ELF SetupVkey task.
            "prove": prove_elapsed.as_millis(),
            "sdkVerify": sdk_verify_elapsed.as_millis(),
            "sha256OnlyAdapterVerify": adapter_verify_elapsed.as_millis(),
        },
    });
    fs::write(
        output_dir.join("proof-metadata.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&metadata)?);
    Ok(())
}

fn setup_behavior_json() -> serde_json::Value {
    let patched = cfg!(feature = "usdd-host-patch");
    json!({
        "identityPreflight": "independent-light-client",
        "identityPreflightSeedsCpuControllerCache": false,
        "identityPreflightProvidesOneShotVkeyHint": patched,
        "cpuControllerRepeatsSetupVkey": !patched,
        "cpuControllerSetupIncludedInProveTiming": !patched,
        "elfVkeyBinding": if patched {
            "one-shot-hint-plus-derived-vkey-equality-per-core-shard"
        } else {
            "stock-controller-setup"
        },
        "proofNoncePropagation": if patched {
            "controller-slot-4-pinned-host-fix"
        } else {
            "stock-6.3.1-slot-mismatch-nonzero-nonce-unsafe"
        },
        "status": SETUP_CACHE_STATUS,
        "sp1PackageRelease": SP1_PACKAGE_RELEASE,
        "sp1CircuitVersion": UPSTREAM_SP1_CIRCUIT_VERSION,
        "sp1CircuitVersionSource": "sp1-prover-6.3.1/SP1_CIRCUIT_VERSION",
        "patchManifest": "scripts/usdd-sp1-prover/toolchain/manifest.json",
    })
}

fn require_compiled_sp1_identity() -> Result<()> {
    if SP1_PACKAGE_RELEASE != PINNED_SP1_PACKAGE_RELEASE {
        bail!(
            "compiled SP1 package release {}, expected pinned {}",
            SP1_PACKAGE_RELEASE,
            PINNED_SP1_PACKAGE_RELEASE,
        );
    }
    if UPSTREAM_SP1_CIRCUIT_VERSION != PINNED_SP1_CIRCUIT_VERSION {
        bail!(
            "compiled SP1 package release {} reports circuit version {}, expected pinned {}",
            SP1_PACKAGE_RELEASE,
            UPSTREAM_SP1_CIRCUIT_VERSION,
            PINNED_SP1_CIRCUIT_VERSION,
        );
    }
    Ok(())
}

fn require_proof_circuit_version(actual: &str) -> Result<()> {
    require_compiled_sp1_identity()?;
    if actual != UPSTREAM_SP1_CIRCUIT_VERSION {
        bail!(
            "proof reports SP1 circuit version {actual}, expected {} from package release {}",
            UPSTREAM_SP1_CIRCUIT_VERSION,
            SP1_PACKAGE_RELEASE,
        );
    }
    Ok(())
}

fn executor_memory_limit_semantics() -> &'static str {
    if cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_endian = "little"
    )) {
        "native-child-rss-accounting"
    } else {
        "portable-created-memory-entry-budget-not-host-rss"
    }
}

fn trace_chunk_slots_are_effective() -> bool {
    cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_endian = "little"
    ))
}

fn install_low_memory_worker_profile() -> Result<()> {
    if env::var("WITHOUT_VK_VERIFICATION")
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
    {
        bail!("WITHOUT_VK_VERIFICATION is forbidden for a USDD proof");
    }

    // This command owns a fresh process and applies the profile before either
    // Rayon or an SP1 prover is initialized. Overriding inherited values makes
    // the peak-memory behavior deterministic and keeps the metadata truthful.
    for (name, value) in LOW_MEMORY_WORKER_ENV {
        env::set_var(name, value);
    }
    Ok(())
}

fn low_memory_core_opts() -> SP1CoreOpts {
    let mut opts = SP1CoreOpts::default();
    opts.minimal_trace_chunk_threshold = LOW_MEMORY_TRACE_CHUNK_ENTRIES;
    opts.trace_chunk_slots = LOW_MEMORY_TRACE_CHUNK_SLOTS;
    // SP1 disables gas accounting during proving. Preserve the separately
    // calibrated gas cadence anyway: changing this threshold changes a
    // standalone execution report. One ring slot lowers native-executor
    // memory without changing gas; the portable executor ignores slot count.
    opts.gas_trace_chunk_threshold = GAS_TRACE_CHUNK_THRESHOLD;
    opts.gas_trace_chunk_slots = LOW_MEMORY_GAS_TRACE_CHUNK_SLOTS;
    opts.memory_limit = LOW_MEMORY_EXECUTOR_MEMORY_LIMIT;
    opts.shard_size = LOW_MEMORY_SHARD_SIZE;
    opts.sharding_threshold = ShardingThreshold {
        element_threshold: ELEMENT_THRESHOLD,
        height_threshold: HEIGHT_THRESHOLD,
    };
    // These are part of the pinned v6.3.1 default proving behavior. Spell them
    // out so inherited process variables or future local experiments cannot
    // silently alter the proof run.
    opts.global_dependencies_opt = false;
    opts.recompute_gkr_trace = false;
    opts
}

fn verify_annex(path: &Path, expected_program_id: Hash32) -> Result<()> {
    let encoded =
        fs::read(path).with_context(|| format!("failed to read annex at {}", path.display()))?;
    let annex = Sp1ProofAnnex::decode_strict(&encoded).context("invalid canonical annex")?;
    require_program_id(annex.guest_program_id(), expected_program_id)?;
    let raw_vkey_hash = raw_vkey_hash_from_program_id(expected_program_id)?;
    let journal = verify_raw_compressed_sha256(
        annex.proof(),
        annex.public_values(),
        &raw_vkey_hash,
        expected_program_id,
        annex.statement_kind(),
    )
    .context("proof verification failed")?;
    let report = json!({
        "status": "VALID",
        "annex": artifact_json(&encoded),
        "programId": hex::encode(expected_program_id.0),
        "statementKind": format!("{:?}", journal.statement_kind()),
        "publicValues": artifact_json(annex.public_values()),
        "rawProof": artifact_json(annex.proof()),
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn require_program_id(actual: Hash32, expected: Hash32) -> Result<()> {
    if actual != expected {
        bail!(
            "annex program ID {} does not match expected deployment program ID {}",
            hex::encode(actual.0),
            hex::encode(expected.0),
        );
    }
    Ok(())
}

fn raw_vkey_hash(words: [u32; 8]) -> [u8; 32] {
    let mut raw = [0u8; 32];
    for (index, word) in words.into_iter().enumerate() {
        raw[index * 4..(index + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    raw
}

fn raw_vkey_hash_from_program_id(program_id: Hash32) -> Result<[u8; 32]> {
    usdd_sp1_verifier::raw_vkey_hash_from_program_id(program_id)
        .context("annex program ID is not a canonical SP1 KoalaBear vkey hash")
}

fn artifact_json(bytes: &[u8]) -> serde_json::Value {
    json!({
        "bytes": bytes.len(),
        "sha256": hex::encode(Sha256::digest(bytes)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn expected_program_id_requires_canonical_lowercase_hex() {
        let canonical = "4f0511103dab14b61dd5b1403d077ba10d28a89a06dbb54d43e9683542c1df08";
        let expected: [u8; 32] = hex::decode(canonical).unwrap().try_into().unwrap();
        assert_eq!(parse_program_id(OsStr::new(canonical)).unwrap().0, expected);
        assert!(parse_program_id(OsStr::new(&canonical.to_uppercase())).is_err());
        assert!(parse_program_id(OsStr::new("00")).is_err());
        assert!(parse_program_id(OsStr::new(
            "zzd186d31dbd9cd628fe0e333e80af5952b3deba32f7625f399fca2902bc7747"
        ))
        .is_err());
    }

    #[test]
    fn annex_identity_must_match_external_expectation() {
        let expected = Hash32([0x11; 32]);
        assert!(require_program_id(expected, expected).is_ok());
        let error = require_program_id(Hash32([0x22; 32]), expected).unwrap_err();
        assert!(error
            .to_string()
            .contains("does not match expected deployment program ID"));
    }

    #[test]
    fn setup_metadata_matches_compiled_host_path() {
        let behavior = setup_behavior_json();
        assert_eq!(behavior["identityPreflightSeedsCpuControllerCache"], false);
        assert_eq!(
            behavior["identityPreflightProvidesOneShotVkeyHint"],
            cfg!(feature = "usdd-host-patch")
        );
        assert_eq!(
            behavior["cpuControllerRepeatsSetupVkey"],
            !cfg!(feature = "usdd-host-patch")
        );
        assert_eq!(
            behavior["cpuControllerSetupIncludedInProveTiming"],
            !cfg!(feature = "usdd-host-patch")
        );
        assert_eq!(behavior["status"], SETUP_CACHE_STATUS);
        assert_eq!(behavior["sp1PackageRelease"], SP1_PACKAGE_RELEASE);
        assert_eq!(behavior["sp1CircuitVersion"], UPSTREAM_SP1_CIRCUIT_VERSION);
    }

    #[test]
    fn package_release_and_upstream_circuit_version_are_distinct() {
        assert_eq!(SP1_PACKAGE_RELEASE, PINNED_SP1_PACKAGE_RELEASE);
        assert_eq!(UPSTREAM_SP1_CIRCUIT_VERSION, "v6.1.0");
        assert_eq!(UPSTREAM_SP1_CIRCUIT_VERSION, PINNED_SP1_CIRCUIT_VERSION);
        assert_ne!(SP1_PACKAGE_RELEASE, UPSTREAM_SP1_CIRCUIT_VERSION);
        assert!(require_compiled_sp1_identity().is_ok());
        assert!(require_proof_circuit_version(UPSTREAM_SP1_CIRCUIT_VERSION).is_ok());
        assert!(require_proof_circuit_version(SP1_PACKAGE_RELEASE).is_err());
        assert!(require_proof_circuit_version("v0.0.0").is_err());
    }

    #[test]
    fn canonical_proof_nonce_is_nonzero() {
        assert_ne!(CANONICAL_PROOF_NONCE, [0; 4]);
    }

    #[test]
    fn low_memory_profile_serializes_all_air_proving() {
        assert!(LOW_MEMORY_WORKER_ENV.contains(&("SP1_WORKER_MAX_PROVER_PERMITS", "1")));
    }

    #[test]
    fn frozen_program_identity_encodings_match_exactly() {
        let program_id = parse_program_id(OsStr::new(FROZEN_ETHEREUM_PROGRAM_ID)).unwrap();
        assert_ne!(program_id, Hash32::ZERO);
        assert_eq!(
            raw_vkey_hash_from_program_id(program_id).unwrap(),
            frozen_raw_vkey_hash().unwrap(),
        );
    }

    #[test]
    fn patched_controller_decodes_nonce_from_slot_four() {
        use sp1_prover::worker::ControllerInputs;

        let inputs = vec![
            "elf".to_string(),
            "stdin".to_string(),
            "2".to_string(), // ProofMode::Compressed in SP1 6.3.1.
            String::new(),   // No cycle limit; the positional slot is retained.
            "nonce-artifact".to_string(),
        ];
        let decoded = ControllerInputs::try_from(inputs.as_slice()).unwrap();
        assert_eq!(decoded.cycle_limit, None);
        assert!(decoded.proof_nonce.is_some());

        // Freeze the stock defect too: putting the nonce artifact in slot
        // three treats it as a failed cycle-limit parse and leaves no nonce.
        let stock_inputs = vec![
            "elf".to_string(),
            "stdin".to_string(),
            "2".to_string(),
            "nonce-artifact".to_string(),
        ];
        let stock_decoded = ControllerInputs::try_from(stock_inputs.as_slice()).unwrap();
        assert_eq!(stock_decoded.cycle_limit, None);
        assert!(stock_decoded.proof_nonce.is_none());
    }

    #[test]
    fn portable_executor_metadata_does_not_call_memory_limit_an_rss_cap() {
        if !cfg!(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_endian = "little"
        )) {
            assert_eq!(
                executor_memory_limit_semantics(),
                "portable-created-memory-entry-budget-not-host-rss"
            );
            assert!(!trace_chunk_slots_are_effective());
        }
    }
}
