#!/usr/bin/env python3
"""Prove every prepared segment, fold them in order, then wrap for Ethereum."""

from __future__ import annotations

import argparse
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
