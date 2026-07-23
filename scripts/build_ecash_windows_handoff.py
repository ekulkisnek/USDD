#!/usr/bin/env python3
"""Build and verify an immutable adjacent eCash proof-input handoff."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prover", type=Path, required=True)
    parser.add_argument("--segment-elf", type=Path, required=True)
    parser.add_argument("--fold-elf", type=Path, required=True)
    parser.add_argument("--genesis-spec", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def require_file(path: Path, label: str) -> Path:
    path = path.resolve()
    if not path.is_file():
        raise ValueError(f"missing {label}: {path}")
    return path


def run(command: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(command, check=True, cwd=cwd)


def metadata(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text())
    if value.get("schema") not in {
        "usdd-ecash-genesis-segment-input-v1",
        "usdd-ecash-successor-segment-input-v1",
    }:
        raise ValueError(f"unsupported prepared segment metadata: {path}")
    return value


def main() -> int:
    args = parse_args()
    prover = require_file(args.prover, "prover")
    segment_elf = require_file(args.segment_elf, "segment ELF")
    fold_elf = require_file(args.fold_elf, "fold ELF")
    genesis_spec = require_file(args.genesis_spec, "genesis spec")
    capture = args.capture.resolve()
    capture_manifest_path = require_file(capture / "manifest.json", "capture manifest")
    capture_checksums = require_file(capture / "SHA256SUMS", "capture checksums")
    final_output = args.output.resolve()
    building_output = final_output.with_name(f".{final_output.name}.building")
    if final_output.exists():
        raise ValueError(f"output already exists: {final_output}")
    if building_output.exists():
        raise ValueError(
            f"incomplete prior build exists: {building_output}; inspect or move it before retrying"
        )

    run(["shasum", "-a", "256", "-c", capture_checksums.name], cwd=capture)
    captured = json.loads(capture_manifest_path.read_text())
    if captured.get("schema") != "usdd-ecash-captured-segments-v1":
        raise ValueError("unsupported captured-segment schema")
    segments = captured.get("segments")
    if not isinstance(segments, list) or len(segments) < 2:
        raise ValueError("capture must contain height 1 and at least one adjacent successor segment")
    first = segments[0]
    if first.get("firstHeight") != 1 or first.get("lastHeight") != 1:
        raise ValueError("first captured segment must contain only height 1")
    genesis_relative = captured.get("genesisBlock")
    if not isinstance(genesis_relative, str):
        raise ValueError("capture does not include the genesis block")
    first_spec_path = require_file(capture / str(first["path"]), "height-1 spec")
    first_spec = json.loads(first_spec_path.read_text())
    first_raw_relative = first_spec["blocks"][0]["rawBlock"]
    first_raw_path = require_file(first_spec_path.parent / first_raw_relative, "height-1 block")
    genesis_path = require_file(capture / genesis_relative, "genesis block")

    output = building_output
    output.mkdir(parents=True)
    artifact_dir = output / "artifacts"
    prepared_dir = output / "prepared-segments"
    artifact_dir.mkdir()
    prepared_dir.mkdir()
    copied_segment = artifact_dir / "ecash-segment-v1.elf"
    copied_fold = artifact_dir / "ecash-fold-v1.elf"
    copied_genesis_spec = artifact_dir / "genesis-segment-spec.json"
    shutil.copyfile(segment_elf, copied_segment)
    shutil.copyfile(fold_elf, copied_fold)
    shutil.copyfile(genesis_spec, copied_genesis_spec)

    prepared: list[dict[str, object]] = []
    first_output = prepared_dir / "segment-00000001-00000001"
    run(
        [
            str(prover),
            "prepare-genesis-segment",
            str(copied_segment),
            str(copied_fold),
            str(copied_genesis_spec),
            str(genesis_path),
            str(first_raw_path),
            str(first_output),
        ]
    )
    first_metadata = metadata(first_output / "metadata.json")
    prepared.append(
        {
            "firstHeight": 1,
            "lastHeight": 1,
            "directory": str(first_output.relative_to(output)),
            "metadata": first_metadata,
        }
    )

    prior_output = first_output
    for captured_segment in segments[1:]:
        first_height = int(captured_segment["firstHeight"])
        last_height = int(captured_segment["lastHeight"])
        spec_path = require_file(capture / str(captured_segment["path"]), "segment spec")
        segment_output = prepared_dir / f"segment-{first_height:08d}-{last_height:08d}"
        run(
            [
                str(prover),
                "prepare-segment",
                str(copied_segment),
                str(copied_fold),
                str(first_output / "config.bin"),
                str(prior_output / "next-state.bin"),
                str(spec_path),
                str(segment_output),
            ]
        )
        current = metadata(segment_output / "metadata.json")
        previous = prepared[-1]["metadata"]
        if current["priorStateCommitment"] != previous["nextStateCommitment"]:
            raise ValueError(f"state commitments are not adjacent at height {first_height}")
        if current["priorTip"] != previous["nextTip"]:
            raise ValueError(f"block tips are not adjacent at height {first_height}")
        if int(current["priorHeight"]) != int(previous["nextHeight"]):
            raise ValueError(f"heights are not adjacent at height {first_height}")
        prepared.append(
            {
                "firstHeight": first_height,
                "lastHeight": last_height,
                "directory": str(segment_output.relative_to(output)),
                "metadata": current,
            }
        )
        prior_output = segment_output

    repository = Path(__file__).resolve().parent.parent
    repository_commit = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    manifest = {
        "schema": "usdd-ecash-windows-proof-handoff-v2",
        "repositoryCommit": repository_commit,
        "sourceChain": {
            "chain": captured["chain"],
            "signetChallenge": captured["signetChallenge"],
            "startHeight": captured["startHeight"],
            "endHeight": captured["endHeight"],
        },
        "identities": {
            "segmentElfSha256": sha256(copied_segment),
            "foldElfSha256": sha256(copied_fold),
            "configSha256": sha256(first_output / "config.bin"),
        },
        "segments": prepared,
        "foldOrder": [
            {
                "left": "accumulator" if index else prepared[0]["directory"],
                "right": item["directory"],
            }
            for index, item in enumerate(prepared[1:])
        ],
    }
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode()
    (output / "handoff-manifest.json").write_bytes(manifest_bytes)

    checksum_lines = []
    for path in sorted(value for value in output.rglob("*") if value.is_file()):
        if path.name == "SHA256SUMS":
            continue
        checksum_lines.append(f"{sha256(path)}  {path.relative_to(output)}")
    (output / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n")
    output.rename(final_output)
    print(
        json.dumps(
            {
                "output": str(final_output),
                "segments": len(prepared),
                "firstHeight": prepared[0]["firstHeight"],
                "lastHeight": prepared[-1]["lastHeight"],
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
