#!/usr/bin/env python3
"""Build a checksummed Windows handoff for one authentic Ethereum fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


INPUT_NAMES = (
    "00-statement-tag.bin",
    "01-manifest.bin",
    "02-claim.bin",
    "03-finality.bin",
    "04-vault-witness.bin",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def require_file(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_file():
        raise ValueError(f"missing {label}: {resolved}")
    return resolved


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def prefixed(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 66 or not value.startswith("0x"):
        raise ValueError(f"invalid {label}")
    return value[2:]


def main() -> int:
    args = parse_args()
    fixture = args.fixture.resolve()
    elf = require_file(args.elf, "Ethereum guest ELF")
    provenance_path = require_file(fixture / "provenance.json", "fixture provenance")
    expected_journal = require_file(fixture / "expected-journal.bin", "expected journal")
    inputs = [require_file(fixture / name, name) for name in INPUT_NAMES]
    provenance = json.loads(provenance_path.read_text())

    if provenance.get("schema") != "usdd-sepolia-live-finalized-deposit-fixture-v1":
        raise ValueError("unsupported fixture provenance schema")
    if provenance.get("status") != "NATIVE_CRYPTOGRAPHIC_PREFLIGHT_PASS_SP1_PROOF_NOT_STARTED":
        raise ValueError("fixture did not pass the native cryptographic preflight")
    if provenance.get("network") != "Sepolia":
        raise ValueError("only the frozen Sepolia V7 fixture is supported")
    expected_program = "4f0511103dab14b61dd5b1403d077ba10d28a89a06dbb54d43e9683542c1df08"
    if prefixed(provenance.get("programId"), "program ID") != expected_program:
        raise ValueError("fixture program ID is not the frozen V7 Ethereum program")
    if sha256(expected_journal) != prefixed(provenance.get("journalSha256"), "journal SHA-256"):
        raise ValueError("expected journal hash does not match provenance")
    if expected_journal.stat().st_size != int(provenance.get("journalBytes", -1)):
        raise ValueError("expected journal length does not match provenance")
    if sum(path.stat().st_size for path in inputs) != int(provenance.get("inputBytes", -1)):
        raise ValueError("fixture input length does not match provenance")

    output = args.output.resolve()
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    output.mkdir(parents=True)
    fixture_output = output / "fixture"
    artifact_output = output / "artifacts"
    fixture_output.mkdir()
    artifact_output.mkdir()
    for source in inputs + [expected_journal, provenance_path]:
        shutil.copyfile(source, fixture_output / source.name)
    copied_elf = artifact_output / "ethereum-state-v1.elf"
    shutil.copyfile(elf, copied_elf)

    repository = Path(__file__).resolve().parent.parent
    commit = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    manifest = {
        "schema": "usdd-ethereum-windows-proof-handoff-v1",
        "repositoryCommit": commit,
        "network": "Sepolia",
        "fixtureSchema": provenance["schema"],
        "fixtureManifestId": provenance["manifestId"],
        "depositTransactionHash": provenance["depositTransactionHash"],
        "depositBlockNumber": provenance["depositBlockNumber"],
        "finalizedExecutionBlockNumber": provenance["finalizedExecutionBlockNumber"],
        "programId": expected_program,
        "elfSha256": sha256(copied_elf),
        "inputBytes": provenance["inputBytes"],
        "expectedJournalBytes": provenance["journalBytes"],
        "expectedJournalSha256": prefixed(provenance["journalSha256"], "journal SHA-256"),
        "proofMode": "compressed-transparent",
        "sp1PackageRelease": "6.3.1",
        "sp1CircuitVersion": "v6.1.0",
    }
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode()
    (output / "handoff-manifest.json").write_bytes(manifest_bytes)

    checksums = []
    for path in sorted(value for value in output.rglob("*") if value.is_file()):
        if path.name == "SHA256SUMS":
            continue
        checksums.append(f"{sha256(path)}  {path.relative_to(output)}")
    (output / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
    print(
        json.dumps(
            {
                "output": str(output),
                "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "programId": expected_program,
                "expectedJournalSha256": manifest["expectedJournalSha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, TypeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
