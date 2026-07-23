#!/usr/bin/env python3
"""Prove every prepared segment, fold them in order, then wrap for Ethereum."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    return parser.parse_args()


def write_progress(path: Path, **values: object) -> None:
    payload = {"updatedUnix": int(time.time()), **values}
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n")
    temporary.replace(path)


def execute(command: list[str], log: Path) -> None:
    with log.open("wb") as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise RuntimeError(f"command failed with exit {result.returncode}; see {log}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_segment_proof(
    proof: Path, prepared: Path, expected_elf_sha256: str
) -> None:
    metadata_path = proof / "proof-metadata.json"
    public_values = proof / "public-values.bin"
    expected_public_values = prepared / "expected-public-values.bin"
    raw_proof = proof / "proof.raw.bin"
    for required in (
        metadata_path,
        public_values,
        expected_public_values,
        raw_proof,
    ):
        if not required.is_file() or required.stat().st_size == 0:
            raise RuntimeError(f"missing proof output: {required}")
    metadata = json.loads(metadata_path.read_text())
    if metadata.get("schema") != "usdd-ecash-proof-artifact-v1":
        raise RuntimeError(f"wrong segment proof schema: {metadata_path}")
    if metadata.get("kind") != "segment":
        raise RuntimeError(f"wrong proof kind: {metadata_path}")
    if metadata.get("proofMode") != "compressed-transparent":
        raise RuntimeError(f"wrong segment proof mode: {metadata_path}")
    if metadata.get("tee") is not False:
        raise RuntimeError(f"TEE proof is forbidden: {metadata_path}")
    if metadata.get("intermediateProofVerification") is not True:
        raise RuntimeError(f"intermediate verification was disabled: {metadata_path}")
    if metadata.get("deferredProofVerification") is not True:
        raise RuntimeError(f"deferred verification was disabled: {metadata_path}")
    if metadata.get("elf", {}).get("sha256") != expected_elf_sha256:
        raise RuntimeError(f"segment ELF identity mismatch: {metadata_path}")
    if public_values.read_bytes() != expected_public_values.read_bytes():
        raise RuntimeError(f"segment public values mismatch: {proof}")
    if metadata.get("publicValues", {}).get("sha256") != sha256(public_values):
        raise RuntimeError(f"public-values metadata mismatch: {metadata_path}")
    if metadata.get("rawProof", {}).get("sha256") != sha256(raw_proof):
        raise RuntimeError(f"raw-proof metadata mismatch: {metadata_path}")


def validate_wrapper(wrapper: Path, final_fold: Path) -> None:
    metadata_path = wrapper / "wrap-metadata.json"
    source_metadata_path = final_fold / "proof-metadata.json"
    for required in (
        metadata_path,
        source_metadata_path,
        wrapper / "groth16-proof.bin",
        wrapper / "relay-proof.bin",
        wrapper / "public-values.bin",
        wrapper / "ethereum-verifier-arguments.json",
    ):
        if not required.is_file() or required.stat().st_size == 0:
            raise RuntimeError(f"missing wrapper output: {required}")
    metadata = json.loads(metadata_path.read_text())
    source_metadata = json.loads(source_metadata_path.read_text())
    if metadata.get("schema") != "usdd-ecash-groth16-wrapper-v1":
        raise RuntimeError("wrong Groth16 wrapper schema")
    if metadata.get("kind") != "fold":
        raise RuntimeError("final wrapper does not cover the recursive fold")
    if metadata.get("status") != "GROTH16_WRAPPER_SDK_VERIFIED":
        raise RuntimeError("Groth16 wrapper was not SDK verified")
    if metadata.get("sdkVerifiedBeforeWrap") is not True:
        raise RuntimeError("source fold was not SDK verified before wrapping")
    if metadata.get("sdkVerifiedAfterWrap") is not True:
        raise RuntimeError("Groth16 wrapper was not SDK verified after wrapping")
    if metadata.get("tee") is not False:
        raise RuntimeError("TEE wrapper is forbidden")
    if metadata.get("sourceProof", {}).get("sha256") != source_metadata.get(
        "rawProof", {}
    ).get("sha256"):
        raise RuntimeError("wrapper source-proof identity mismatch")
    if metadata.get("publicValues", {}).get("sha256") != sha256(
        wrapper / "public-values.bin"
    ):
        raise RuntimeError("wrapper public-values metadata mismatch")
    if metadata.get("onchainProof", {}).get("sha256") != sha256(
        wrapper / "groth16-proof.bin"
    ):
        raise RuntimeError("Groth16 proof metadata mismatch")
    if metadata.get("usddRelayProof", {}).get("sha256") != sha256(
        wrapper / "relay-proof.bin"
    ):
        raise RuntimeError("relay-proof metadata mismatch")


def main() -> int:
    args = parse_args()
    binary = args.binary.resolve()
    handoff = args.handoff.resolve()
    run_dir = args.run_dir.resolve()
    manifest = json.loads((handoff / "handoff-manifest.json").read_text())
    if manifest.get("schema") != "usdd-ecash-windows-proof-handoff-v2":
        raise ValueError("unsupported handoff schema")
    segments = manifest.get("segments")
    if not isinstance(segments, list) or len(segments) < 2:
        raise ValueError("handoff must contain at least two adjacent segments")
    segment_elf = handoff / "artifacts/ecash-segment-v1.elf"
    fold_elf = handoff / "artifacts/ecash-fold-v1.elf"
    config = handoff / str(segments[0]["directory"]) / "config.bin"
    for required in (binary, segment_elf, fold_elf, config):
        if not required.is_file():
            raise ValueError(f"missing required input: {required}")

    segment_proof_root = run_dir / "segment-proofs"
    fold_root = run_dir / "fold-proofs"
    segment_proof_root.mkdir()
    fold_root.mkdir()
    progress = run_dir / "progress.json"
    proofs: list[Path] = []
    expected_segment_elf_sha256 = str(
        manifest.get("identities", {}).get("segmentElfSha256", "")
    )
    if len(expected_segment_elf_sha256) != 64:
        raise ValueError("handoff is missing the segment ELF identity")

    for index, item in enumerate(segments):
        source = handoff / str(item["directory"]) / "segment-input.bin"
        if not source.is_file():
            raise ValueError(f"missing segment input: {source}")
        label = f"{int(item['firstHeight']):08d}-{int(item['lastHeight']):08d}"
        output = segment_proof_root / label
        write_progress(
            progress,
            status="RUNNING",
            stage="prove-segment",
            stageIndex=index + 1,
            stageCount=len(segments),
            label=label,
        )
        execute(
            [
                str(binary),
                "prove-segment",
                str(segment_elf),
                str(fold_elf),
                str(source),
                str(output),
            ],
            run_dir / f"prove-segment-{label}.log",
        )
        validate_segment_proof(
            output,
            handoff / str(item["directory"]),
            expected_segment_elf_sha256,
        )
        proofs.append(output)

    accumulator = proofs[0]
    for index, right in enumerate(proofs[1:], start=1):
        output = fold_root / f"fold-through-{int(segments[index]['lastHeight']):08d}"
        write_progress(
            progress,
            status="RUNNING",
            stage="fold",
            stageIndex=index,
            stageCount=len(proofs) - 1,
            label=output.name,
        )
        execute(
            [
                str(binary),
                "fold",
                str(segment_elf),
                str(fold_elf),
                str(config),
                str(accumulator),
                str(right),
                str(output),
            ],
            run_dir / f"{output.name}.log",
        )
        accumulator = output

    wrapped = run_dir / "groth16-wrapper"
    write_progress(
        progress,
        status="RUNNING",
        stage="wrap-groth16",
        stageIndex=1,
        stageCount=1,
        label=wrapped.name,
    )
    execute(
        [
            str(binary),
            "wrap-groth16",
            str(segment_elf),
            str(fold_elf),
            str(accumulator),
            str(wrapped),
        ],
        run_dir / "wrap-groth16.log",
    )
    validate_wrapper(wrapped, accumulator)
    write_progress(
        progress,
        status="SUCCESS",
        stage="complete",
        finalCompressedProof=str(accumulator),
        finalGroth16Wrapper=str(wrapped),
    )
    (run_dir / "SUCCESS").touch()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
