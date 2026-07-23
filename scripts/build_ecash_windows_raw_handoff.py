#!/usr/bin/env python3
"""Package authentic eCash inputs for preparation and proving on Windows."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

from build_ecash_windows_handoff import require_file, sha256, verify_sha256sums


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--segment-elf", type=Path, required=True)
    parser.add_argument("--fold-elf", type=Path, required=True)
    parser.add_argument("--genesis-spec", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    segment_elf = require_file(args.segment_elf, "segment ELF")
    fold_elf = require_file(args.fold_elf, "fold ELF")
    genesis_spec = require_file(args.genesis_spec, "genesis spec")
    capture = args.capture.resolve()
    capture_manifest_path = require_file(capture / "manifest.json", "capture manifest")
    capture_checksums = require_file(capture / "SHA256SUMS", "capture checksums")
    verify_sha256sums(capture, capture_checksums)
    captured = json.loads(capture_manifest_path.read_text())
    if captured.get("schema") != "usdd-ecash-captured-segments-v1":
        raise ValueError("unsupported captured-segment schema")
    segments = captured.get("segments")
    if not isinstance(segments, list) or len(segments) < 2:
        raise ValueError("capture must contain at least two segments")

    final_output = args.output.resolve()
    building_output = final_output.with_name(f".{final_output.name}.building")
    if final_output.exists() or building_output.exists():
        raise ValueError(f"output or incomplete build already exists: {final_output}")
    building_output.mkdir(parents=True)
    artifacts = building_output / "artifacts"
    artifacts.mkdir()
    shutil.copyfile(segment_elf, artifacts / "ecash-segment-v1.elf")
    shutil.copyfile(fold_elf, artifacts / "ecash-fold-v1.elf")
    shutil.copyfile(genesis_spec, artifacts / "genesis-segment-spec.json")
    shutil.copytree(capture, building_output / "capture")

    repository = Path(__file__).resolve().parent.parent
    repository_commit = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    manifest = {
        "schema": "usdd-ecash-windows-raw-handoff-v1",
        "repositoryCommit": repository_commit,
        "sourceChain": {
            "chain": captured["chain"],
            "signetChallenge": captured["signetChallenge"],
            "startHeight": captured["startHeight"],
            "endHeight": captured["endHeight"],
        },
        "identities": {
            "segmentElfSha256": sha256(artifacts / "ecash-segment-v1.elf"),
            "foldElfSha256": sha256(artifacts / "ecash-fold-v1.elf"),
            "genesisSpecSha256": sha256(artifacts / "genesis-segment-spec.json"),
            "captureManifestSha256": sha256(building_output / "capture/manifest.json"),
            "captureChecksumsSha256": sha256(building_output / "capture/SHA256SUMS"),
        },
        "capture": "capture",
        "segmentCount": len(segments),
        "requiredFirstHeight": 1,
        "requiredLastHeight": captured["endHeight"],
    }
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode()
    (building_output / "handoff-manifest.json").write_bytes(manifest_bytes)
    checksum_lines = []
    for path in sorted(value for value in building_output.rglob("*") if value.is_file()):
        if path.name != "SHA256SUMS" or path.parent != building_output:
            checksum_lines.append(f"{sha256(path)}  {path.relative_to(building_output)}")
    (building_output / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n")
    building_output.rename(final_output)
    print(
        json.dumps(
            {
                "output": str(final_output),
                "segments": len(segments),
                "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, subprocess.CalledProcessError, TypeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
