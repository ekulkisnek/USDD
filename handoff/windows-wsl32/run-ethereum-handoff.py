#!/usr/bin/env python3
"""Prove and strictly validate one frozen V7 Ethereum handoff."""

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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def write_progress(path: Path, **values: object) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps({"updatedUnix": int(time.time()), **values}, indent=2) + "\n"
    )
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
    if manifest.get("schema") != "usdd-ethereum-windows-proof-handoff-v1":
        raise ValueError("unsupported handoff schema")
    if manifest.get("programId") != (
        "4f0511103dab14b61dd5b1403d077ba10d28a89a06dbb54d43e9683542c1df08"
    ):
        raise ValueError("handoff does not target the frozen V7 Ethereum program")

    elf = handoff / "artifacts/ethereum-state-v1.elf"
    fixture = handoff / "fixture"
    expected_journal = fixture / "expected-journal.bin"
    for required in (binary, elf, expected_journal):
        if not required.is_file():
            raise ValueError(f"missing required input: {required}")
    if sha256(elf) != manifest.get("elfSha256"):
        raise ValueError("ELF hash does not match handoff manifest")
    if sha256(expected_journal) != manifest.get("expectedJournalSha256"):
        raise ValueError("journal hash does not match handoff manifest")

    proof = run_dir / "proof"
    progress = run_dir / "progress.json"
    write_progress(progress, status="RUNNING", stage="prove-v7-ethereum")
    execute(
        [str(binary), "prove", str(elf), str(fixture), str(proof)],
        run_dir / "prove-v7-ethereum.log",
    )
    public_values = proof / "public-values.bin"
    annex = proof / "annex.bin"
    metadata_path = proof / "proof-metadata.json"
    for required in (public_values, annex, metadata_path):
        if not required.is_file():
            raise RuntimeError(f"successful prover omitted {required}")
    if public_values.read_bytes() != expected_journal.read_bytes():
        raise RuntimeError("proved public values differ from the frozen expected journal")
    metadata = json.loads(metadata_path.read_text())
    if metadata.get("sp1PackageRelease") != "6.3.1":
        raise RuntimeError("unexpected SP1 package release")
    if metadata.get("sp1CircuitVersion") != "v6.1.0":
        raise RuntimeError("unexpected SP1 circuit version")

    write_progress(progress, status="RUNNING", stage="independent-annex-verification")
    execute(
        [str(binary), "verify", str(manifest["programId"]), str(annex)],
        run_dir / "verify-v7-ethereum.log",
    )
    result = {
        "schema": "usdd-ethereum-windows-proof-result-v1",
        "handoffManifestSha256": sha256(handoff / "handoff-manifest.json"),
        "programId": manifest["programId"],
        "publicValuesSha256": sha256(public_values),
        "annexSha256": sha256(annex),
        "proofMetadataSha256": sha256(metadata_path),
    }
    (run_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    write_progress(progress, status="SUCCESS", stage="complete", **result)
    (run_dir / "SUCCESS").touch()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
