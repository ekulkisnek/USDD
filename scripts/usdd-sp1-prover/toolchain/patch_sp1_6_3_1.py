#!/usr/bin/env python3
"""Apply the USDD host-only changes to pristine SP1 6.3.1 crate sources.

Every edit is an exact, single-occurrence replacement. This deliberately
refuses a nearby or future upstream tree instead of fuzzily applying a patch.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def replace_once(root: Path, relative: str, old: str, new: str) -> None:
    path = root / relative
    source = path.read_text(encoding="utf-8")
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"{relative}: expected exactly one source anchor, found {count}: {old[:72]!r}"
        )
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def patch_controller(root: Path) -> None:
    path = "sp1-prover-6.3.1/src/worker/controller/mod.rs"
    replace_once(
        root,
        path,
        "use std::{borrow::Borrow, sync::Arc};",
        "use std::{\n"
        "    borrow::Borrow,\n"
        "    collections::HashMap,\n"
        "    sync::{Arc, Mutex as StdMutex},\n"
        "};",
    )
    replace_once(
        root,
        path,
        "#[derive(Clone)]\npub struct SP1ControllerConfig {",
        "pub(crate) type SetupVkeyHints = Arc<StdMutex<HashMap<Artifact, SP1VerifyingKey>>>;\n\n"
        "#[derive(Clone)]\npub struct SP1ControllerConfig {",
    )
    replace_once(
        root,
        path,
        "    setup_cache: Arc<Mutex<LruCache<Artifact, SP1VerifyingKey>>>,\n"
        "    pub(crate) artifact_client: A,",
        "    setup_cache: Arc<Mutex<LruCache<Artifact, SP1VerifyingKey>>>,\n"
        "    setup_hints: SetupVkeyHints,\n"
        "    pub(crate) artifact_client: A,",
    )
    replace_once(
        root,
        path,
        "            setup_cache: Arc::new(Mutex::new(LruCache::new(20.try_into().unwrap()))),\n"
        "            artifact_client,",
        "            setup_cache: Arc::new(Mutex::new(LruCache::new(20.try_into().unwrap()))),\n"
        "            setup_hints: Arc::new(StdMutex::new(HashMap::new())),\n"
        "            artifact_client,",
    )
    replace_once(
        root,
        path,
        "    #[inline]\n    pub const fn opts(&self) -> &SP1CoreOpts {",
        "    #[inline]\n"
        "    pub(crate) fn setup_hints(&self) -> SetupVkeyHints {\n"
        "        self.setup_hints.clone()\n"
        "    }\n\n"
        "    #[inline]\n"
        "    pub const fn opts(&self) -> &SP1CoreOpts {",
    )
    replace_once(
        root,
        path,
        """            let setup_cache = self.setup_cache.clone();
            let context = context.clone();
            async move {
                let mut lock = setup_cache.lock().await;
                let vkey = lock.get(&elf_clone).cloned();
                drop(lock);
                let vk = if let Some(vkey) = vkey {
                    tracing::debug!("setup cache hit");
                    vkey.clone()
                } else {""",
        """            let setup_cache = self.setup_cache.clone();
            let setup_hints = self.setup_hints.clone();
            let context = context.clone();
            async move {
                // A local caller may provide a one-shot, untrusted vkey hint
                // derived before the full prover is initialized. It is keyed
                // by this proof's fresh ELF artifact and consumed exactly once.
                let hinted_vkey = setup_hints
                    .lock()
                    .map_err(|_| {
                        TaskError::Fatal(anyhow::anyhow!("one-shot setup vkey hint lock poisoned"))
                    })?
                    .remove(&elf_clone);
                let cached_vkey = setup_cache.lock().await.get(&elf_clone).cloned();
                let vk = if let Some(vkey) = hinted_vkey {
                    tracing::debug!("using one-shot setup vkey hint");
                    vkey
                } else if let Some(vkey) = cached_vkey {
                    tracing::debug!("setup cache hit");
                    vkey
                } else {""",
    )
    controller = root / path
    controller.write_text(
        controller.read_text(encoding="utf-8")
        + """

#[cfg(test)]
mod usdd_host_patch_tests {
    use super::*;

    #[test]
    fn empty_cycle_limit_keeps_nonce_in_controller_slot_four() {
        let nonce = Artifact("nonce-artifact".to_string());
        let inputs = vec![
            Artifact("elf".to_string()),
            Artifact("stdin".to_string()),
            Artifact((ProofMode::Compressed as i32).to_string()),
            Artifact(String::new()),
            nonce.clone(),
        ];
        let decoded = ControllerInputs::try_from(inputs.as_slice()).unwrap();
        assert_eq!(decoded.cycle_limit, None);
        assert_eq!(decoded.proof_nonce, Some(nonce));
    }
}
""",
        encoding="utf-8",
    )


def patch_node_builder(root: Path) -> None:
    path = "sp1-prover-6.3.1/src/worker/node/full/init.rs"
    replace_once(
        root,
        path,
        """        let worker_client = worker.worker_client().clone();
        let core = SP1NodeCore::new(verifier, opts);
        let inner =
            Arc::new(SP1NodeInner { artifact_client, worker_client, core, _tasks: join_set });""",
        """        let worker_client = worker.worker_client().clone();
        let setup_hints = worker.controller().setup_hints();
        let core = SP1NodeCore::new(verifier, opts);
        let inner = Arc::new(SP1NodeInner {
            artifact_client,
            worker_client,
            setup_hints,
            core,
            _tasks: join_set,
        });""",
    )


def patch_local_node(root: Path) -> None:
    path = "sp1-prover-6.3.1/src/worker/node/full/mod.rs"
    replace_once(
        root,
        path,
        "        VkeyMapControllerInput, VkeyMapControllerOutput, WorkerClient,",
        "        SetupVkeyHints, VkeyMapControllerInput, VkeyMapControllerOutput, WorkerClient,",
    )
    replace_once(
        root,
        path,
        "    worker_client: LocalWorkerClient,\n    core: SP1NodeCore,",
        "    worker_client: LocalWorkerClient,\n"
        "    setup_hints: SetupVkeyHints,\n"
        "    core: SP1NodeCore,",
    )
    replace_once(
        root,
        path,
        "    _tasks: JoinSet<()>,\n}\n\npub struct SP1LocalNode {",
        """    _tasks: JoinSet<()>,
}

struct SetupVkeyHintGuard {
    hints: SetupVkeyHints,
    artifact: Artifact,
}

impl Drop for SetupVkeyHintGuard {
    fn drop(&mut self) {
        if let Ok(mut hints) = self.hints.lock() {
            hints.remove(&self.artifact);
        }
    }
}

pub struct SP1LocalNode {""",
    )
    replace_once(
        root,
        path,
        """    pub async fn prove_with_mode(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        context: SP1Context<'static>,
        mode: ProofMode,
    ) -> anyhow::Result<ProofFromNetwork> {
        // Allocate the per-proof artifacts and id up front so the cleanup below""",
        """    pub async fn prove_with_mode(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        context: SP1Context<'static>,
        mode: ProofMode,
    ) -> anyhow::Result<ProofFromNetwork> {
        self.prove_with_mode_inner(elf, stdin, context, mode, None).await
    }

    /// Prove using a one-shot verifying-key hint for this exact ELF artifact.
    ///
    /// The hint only avoids a duplicate controller setup. Core-shard setup
    /// still derives a verifying key from the ELF and rejects any mismatch.
    pub async fn prove_with_mode_and_vkey(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        context: SP1Context<'static>,
        mode: ProofMode,
        vkey: SP1VerifyingKey,
    ) -> anyhow::Result<ProofFromNetwork> {
        self.prove_with_mode_inner(elf, stdin, context, mode, Some(vkey)).await
    }

    async fn prove_with_mode_inner(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        context: SP1Context<'static>,
        mode: ProofMode,
        setup_vkey_hint: Option<SP1VerifyingKey>,
    ) -> anyhow::Result<ProofFromNetwork> {
        // Allocate the per-proof artifacts and id up front so the cleanup below""",
    )
    replace_once(
        root,
        path,
        """        let output_artifact = self.inner.artifact_client.create_artifact()?;
        let proof_id = ProofId::new("proof".create_type_id::<V7>().to_string());

        // Run the actual proving.""",
        """        let output_artifact = self.inner.artifact_client.create_artifact()?;
        let proof_id = ProofId::new("proof".create_type_id::<V7>().to_string());
        let cycle_limit_artifact =
            Artifact(context.max_cycles.map(|limit| limit.to_string()).unwrap_or_default());
        let _setup_hint_guard = if let Some(vkey) = setup_vkey_hint {
            let mut hints = self
                .inner
                .setup_hints
                .lock()
                .map_err(|_| anyhow::anyhow!("one-shot setup vkey hint lock poisoned"))?;
            if hints.contains_key(&elf_artifact) {
                return Err(anyhow::anyhow!(
                    "one-shot setup vkey hint collision for fresh ELF artifact"
                ));
            }
            hints.insert(elf_artifact.clone(), vkey);
            drop(hints);
            Some(SetupVkeyHintGuard {
                hints: self.inner.setup_hints.clone(),
                artifact: elf_artifact.clone(),
            })
        } else {
            None
        };

        // Run the actual proving.""",
    )
    replace_once(
        root,
        path,
        """                    stdin_artifact.clone(),
                    mode_artifact,
                    proof_nonce_artifact.clone(),""",
        """                    stdin_artifact.clone(),
                    mode_artifact,
                    cycle_limit_artifact,
                    proof_nonce_artifact.clone(),""",
    )


def patch_core_binding(root: Path) -> None:
    path = "sp1-prover-6.3.1/src/worker/prover/core.rs"
    replace_once(
        root,
        path,
        """                })
                .await;

            tracing::debug!("Using fixed PK");""",
        """                })
                .await;

            if pk.vk != common_input.vk.vk {
                return Err(TaskError::Fatal(anyhow!(
                    "fixed core proving key derived from ELF does not match supplied setup vkey hint"
                )));
            }

            tracing::debug!("Using fixed PK");""",
    )
    replace_once(
        root,
        path,
        "            let (_, proof, permit) = self\n                .core_prover",
        "            let (derived_vk, proof, permit) = self\n                .core_prover",
    )
    replace_once(
        root,
        path,
        """                .instrument(tracing::debug_span!("core setup and prove"))
                .await;
            (proof, permit)""",
        """                .instrument(tracing::debug_span!("core setup and prove"))
                .await;
            if derived_vk != common_input.vk.vk {
                let _ = permit.release();
                return Err(TaskError::Fatal(anyhow!(
                    "core verifying key derived from ELF does not match supplied setup vkey hint"
                )));
            }
            (proof, permit)""",
    )


def patch_lazy_recursion_keys(root: Path) -> None:
    path = "sp1-prover-6.3.1/src/worker/prover/recursion.rs"
    replace_once(
        root,
        path,
        """                let (pk, vk) = self.prover_data.compose_keys.get(&arity).cloned().ok_or(
                    TaskError::Fatal(anyhow::anyhow!("Compose key not found for arity {}", arity)),
                )?;""",
        """                let keys = if let Some((pk, vk)) =
                    self.prover_data.compose_keys.get(&arity).cloned()
                {
                    RecursionKeys::Exists(pk, vk)
                } else {
                    let expected_vk = self.prover_data.compose_vks.get(&arity).cloned().ok_or(
                        TaskError::Fatal(anyhow::anyhow!(
                            "Compose vkey not found for arity {}",
                            arity
                        )),
                    )?;
                    RecursionKeys::ProgramWithExpectedVkey(program.clone(), expected_vk)
                };""",
    )
    replace_once(
        root,
        path,
        "                anyhow::Ok(RecursionKeys::Exists(pk, vk))",
        "                anyhow::Ok(keys)",
    )
    replace_once(
        root,
        path,
        """                let keys = self
                    .prover_data
                    .deferred_keys
                    .clone()
                    .map(|(pk, vk)| RecursionKeys::Exists(pk, vk))
                    .unwrap_or_else(|| {
                        RecursionKeys::Program(self.prover_data.deferred_program.clone())
                    });""",
        """                let keys = if let Some((pk, vk)) = self.prover_data.deferred_keys.clone() {
                    RecursionKeys::Exists(pk, vk)
                } else if let Some(expected_vk) = self.prover_data.deferred_vk.clone() {
                    RecursionKeys::ProgramWithExpectedVkey(
                        self.prover_data.deferred_program.clone(),
                        expected_vk,
                    )
                } else {
                    RecursionKeys::Program(self.prover_data.deferred_program.clone())
                };""",
    )
    replace_once(
        root,
        path,
        """enum RecursionKeys<C: SP1ProverComponents> {
    Exists(Arc<CompressProvingKey<C>>, MachineVerifyingKey<SP1GlobalContext>),
    Program(Arc<RecursionProgram<SP1Field>>),
}""",
        """enum RecursionKeys<C: SP1ProverComponents> {
    Exists(Arc<CompressProvingKey<C>>, MachineVerifyingKey<SP1GlobalContext>),
    Program(Arc<RecursionProgram<SP1Field>>),
    ProgramWithExpectedVkey(
        Arc<RecursionProgram<SP1Field>>,
        MachineVerifyingKey<SP1GlobalContext>,
    ),
}""",
    )
    replace_once(
        root,
        path,
        """            RecursionKeys::Program(program) => {
                let (vk, proof, permit) = self
                    .recursion_prover
                    .setup_and_prove_shard(program, record, None, self.permits.clone())
                    .await;
                let duration = permit.release();""",
        """            RecursionKeys::Program(program) => {
                let (vk, proof, permit) = self
                    .recursion_prover
                    .setup_and_prove_shard(program, record, None, self.permits.clone())
                    .await;
                let duration = permit.release();""",
    )
    # Insert the checked lazy branch immediately after the existing Program arm.
    program_arm_end = """                let vk_merkle_proof = self.prover_data.recursion_vks.open(&vk)?.1;
                SP1RecursionProof { vk, proof, vk_merkle_proof }
            }
        };
        Ok(proof)
    }
}"""
    lazy_arm = """                let vk_merkle_proof = self.prover_data.recursion_vks.open(&vk)?.1;
                SP1RecursionProof { vk, proof, vk_merkle_proof }
            }
            RecursionKeys::ProgramWithExpectedVkey(program, expected_vk) => {
                let (derived_vk, proof, permit) = self
                    .recursion_prover
                    .setup_and_prove_shard(
                        program,
                        record,
                        Some(expected_vk.clone()),
                        self.permits.clone(),
                    )
                    .await;
                let duration = permit.release();
                metrics.increment_permit_time(duration);
                if derived_vk != expected_vk {
                    return Err(TaskError::Fatal(anyhow::anyhow!(
                        "on-demand recursion proving key derived an unexpected vkey"
                    )));
                }
                if self.verify_intermediates {
                    let proof = proof.clone();
                    let vk = derived_vk.clone();
                    let parent = tracing::Span::current();
                    tokio::task::spawn_blocking(move || {
                        let _guard = parent.enter();
                        C::compress_verifier()
                            .verify(&vk, &MachineProof::from(vec![proof]))
                            .map_err(|e| {
                                TaskError::Retryable(anyhow::anyhow!(
                                    "lazy recursion verify failed: {}",
                                    e
                                ))
                            })
                    })
                    .await
                    .map_err(|e| TaskError::Fatal(e.into()))??;
                }
                let vk_merkle_proof =
                    self.prover_data.recursion_vks.open(&derived_vk)?.1;
                SP1RecursionProof { vk: derived_vk, proof, vk_merkle_proof }
            }
        };
        Ok(proof)
    }
}"""
    replace_once(root, path, program_arm_end, lazy_arm)
    replace_once(
        root,
        path,
        """            let mut compose_programs = BTreeMap::new();
            let mut compose_keys = BTreeMap::new();""",
        """            let mut compose_programs = BTreeMap::new();
            let mut compose_vks = BTreeMap::new();""",
    )
    replace_once(
        root,
        path,
        """                let (pk, vk) = rx.blocking_recv().unwrap();
                let pk = unsafe { pk.into_inner() };
                compose_keys.insert(arity, (pk, vk));
                compose_programs.insert(arity, program);""",
        """                let (pk, vk) = rx.blocking_recv().unwrap();
                // Retain only the expected vkey. The large proving key is
                // reconstructed for one recursion task at a time and dropped.
                drop(pk);
                compose_vks.insert(arity, vk);
                compose_programs.insert(arity, program);""",
    )
    replace_once(
        root,
        path,
        """            let (pk, vk) = rx.blocking_recv().unwrap();
            let pk = unsafe { pk.into_inner() };
            let deferred_keys = (pk, vk);""",
        """            let (pk, deferred_vk) = rx.blocking_recv().unwrap();
            drop(pk);""",
    )
    replace_once(
        root,
        path,
        """                compose_programs,
                compose_keys,
                deferred_program,
                deferred_keys: Some(deferred_keys),""",
        """                compose_programs,
                compose_keys: BTreeMap::new(),
                compose_vks,
                deferred_program,
                deferred_keys: None,
                deferred_vk: Some(deferred_vk),""",
    )
    replace_once(
        root,
        path,
        """    compose_programs: BTreeMap<usize, Arc<RecursionProgram<SP1Field>>>,
    compose_keys: BTreeMap<usize, CompressKeys<C>>,
    deferred_program: Arc<RecursionProgram<SP1Field>>,
    deferred_keys: Option<CompressKeys<C>>,""",
        """    compose_programs: BTreeMap<usize, Arc<RecursionProgram<SP1Field>>>,
    compose_keys: BTreeMap<usize, CompressKeys<C>>,
    compose_vks: BTreeMap<usize, MachineVerifyingKey<SP1GlobalContext>>,
    deferred_program: Arc<RecursionProgram<SP1Field>>,
    deferred_keys: Option<CompressKeys<C>>,
    deferred_vk: Option<MachineVerifyingKey<SP1GlobalContext>>,""",
    )


def patch_cpu_prover_permits(root: Path) -> None:
    path = "sp1-prover-6.3.1/src/worker/builder.rs"
    replace_once(
        root,
        path,
        """    // Create the prover permits, setting it to having 4 provers.
    let prover_permits = ProverSemaphore::new(4);""",
        """    // This semaphore is shared by core, recursion, shrink, and wrap proving.
    // A low-memory host can serialize those stages even when each stage has its
    // own worker. Zero would deadlock every proof, so reject it explicitly.
    let max_prover_permits = std::env::var("SP1_WORKER_MAX_PROVER_PERMITS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(4);
    assert!(max_prover_permits > 0, "SP1_WORKER_MAX_PROVER_PERMITS must be nonzero");
    let prover_permits = ProverSemaphore::new(max_prover_permits);""",
    )


def patch_sdk(root: Path) -> None:
    path = "sp1-sdk-6.3.1/src/cpu/prove.rs"
    replace_once(
        root,
        path,
        "        Ok(prover.prover.prove_with_mode(&pk.elf, stdin, context, proof_mode(mode)).await?.into())",
        """        Ok(prover
            .prover
            .prove_with_mode_and_vkey(
                &pk.elf,
                stdin,
                context,
                proof_mode(mode),
                pk.vk.clone(),
            )
            .await?
            .into())""",
    )


def patch_existing_proof_groth16_wrapper(root: Path) -> None:
    node_path = "sp1-prover-6.3.1/src/worker/node/full/mod.rs"
    replace_once(
        root,
        node_path,
        "use crate::{\n    shapes::DEFAULT_ARITY,",
        "use crate::{\n    shapes::DEFAULT_ARITY,\n    Groth16Bn254Proof,",
    )
    replace_once(
        root,
        node_path,
        """            self.inner
                .artifact_client
                .try_delete(&output_artifact, ArtifactType::UnspecifiedArtifactType)
        )?;

        Ok(proof)
    }
}""",
        """            self.inner
                .artifact_client
                .try_delete(&output_artifact, ArtifactType::UnspecifiedArtifactType)
        )?;

        Ok(proof)
    }

    /// Convert an existing compressed proof into the Groth16 proof accepted by
    /// SP1's Ethereum verifier. This deliberately starts from an already
    /// authenticated compressed proof and therefore does not re-execute the
    /// original RISC-V program.
    pub async fn groth16_wrap_compressed(
        &self,
        compressed_proof: &SP1Proof,
    ) -> anyhow::Result<Groth16Bn254Proof> {
        let wrap_proof = self.shrink_wrap(compressed_proof).await?;
        let wrap_proof_artifact = self.inner.artifact_client.create_artifact()?;
        self.inner.artifact_client.upload(&wrap_proof_artifact, wrap_proof).await?;
        let groth16_proof_artifact = self.inner.artifact_client.create_artifact()?;

        let proof_id = ProofId::new(
            "groth16 wrap existing compressed proof"
                .create_type_id::<V7>()
                .to_string(),
        );
        let request = RawTaskRequest {
            inputs: vec![wrap_proof_artifact.clone()],
            outputs: vec![groth16_proof_artifact.clone()],
            context: TaskContext {
                proof_id: proof_id.clone(),
                parent_id: None,
                parent_context: None,
                requester_id: RequesterId::new(format!("local-node-{}", std::process::id())),
            },
        };

        let subscriber = self.inner.worker_client.subscriber(proof_id).await?.per_task();
        let task_id = self.inner.worker_client.submit_task(TaskType::Groth16Wrap, request).await?;
        let status = subscriber.wait_task(task_id).await?;
        if status != TaskStatus::Succeeded {
            return Err(anyhow::anyhow!("Groth16 wrap task failed"));
        }

        let proof = self
            .inner
            .artifact_client
            .download::<Groth16Bn254Proof>(&groth16_proof_artifact)
            .await?;
        tokio::try_join!(
            self.inner
                .artifact_client
                .try_delete(&wrap_proof_artifact, ArtifactType::UnspecifiedArtifactType),
            self.inner
                .artifact_client
                .try_delete(&groth16_proof_artifact, ArtifactType::UnspecifiedArtifactType)
        )?;

        Ok(proof)
    }
}""",
    )

    sdk_path = "sp1-sdk-6.3.1/src/cpu/mod.rs"
    replace_once(
        root,
        sdk_path,
        """use sp1_prover::worker::{
    cpu_worker_builder_with_machine, SP1LocalNode, SP1LocalNodeBuilder, SP1NodeCore, TaskError,
};""",
        """use sp1_prover::worker::{
    cpu_worker_builder_with_machine, SP1LocalNode, SP1LocalNodeBuilder, SP1NodeCore, TaskError,
};
use sp1_prover::Groth16Bn254Proof;""",
    )
    replace_once(
        root,
        sdk_path,
        """use crate::{
    prover::{Prover, SendFutureResult},
    SP1ProvingKey,
};""",
        """use crate::{
    prover::{Prover, SendFutureResult},
    SP1Proof, SP1ProvingKey,
};""",
    )
    replace_once(
        root,
        sdk_path,
        """impl CpuProver {
    /// Creates a new [`CpuProver`], using the default [`LocalProverOpts`].""",
        """impl CpuProver {
    /// Wrap an existing compressed proof for SP1's Groth16 Ethereum verifier
    /// without re-executing or reproving the original RISC-V computation.
    pub async fn groth16_wrap_compressed(
        &self,
        compressed_proof: &SP1Proof,
    ) -> Result<Groth16Bn254Proof, CPUProverError> {
        self.prover
            .groth16_wrap_compressed(compressed_proof)
            .await
            .map_err(Into::into)
    }

    /// Creates a new [`CpuProver`], using the default [`LocalProverOpts`].""",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    patch_controller(root)
    patch_node_builder(root)
    patch_local_node(root)
    patch_core_binding(root)
    patch_lazy_recursion_keys(root)
    patch_cpu_prover_permits(root)
    patch_sdk(root)
    patch_existing_proof_groth16_wrapper(root)


if __name__ == "__main__":
    main()
