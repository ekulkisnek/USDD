#!/usr/bin/env python3
"""Capture canonical consecutive eCash blocks into SP1 segment specifications.

This tool is intentionally read-only with respect to the parent node. It fetches
raw blocks through Bitcoin Core JSON-RPC, verifies parent linkage and displayed
block hashes locally, and writes deterministic segment-spec JSON files for
`usdd-ecash-prover prepare-segment`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import urllib.error
import urllib.request


def sha256d(value: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()


def display_hash(raw_header: bytes) -> str:
    return sha256d(raw_header)[::-1].hex()


class Rpc:
    def __init__(self, url: str, user: str, password: str) -> None:
        self.url = url
        credentials = f"{user}:{password}".encode()
        import base64

        self.authorization = f"Basic {base64.b64encode(credentials).decode()}"
        self.request_id = 0

    def call(self, method: str, *params: object) -> object:
        self.request_id += 1
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self.request_id,
                "method": method,
                "params": list(params),
            },
            separators=(",", ":"),
        ).encode()
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={
                "Authorization": self.authorization,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
            raise RuntimeError(f"RPC {method} failed: {error}") from error
        if payload.get("error") is not None:
            raise RuntimeError(f"RPC {method} rejected request: {payload['error']}")
        return payload["result"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc-url", default="http://127.0.0.1:38332/")
    parser.add_argument("--rpc-user", default=os.environ.get("BITCOIN_RPC_USER", "user"))
    parser.add_argument(
        "--rpc-password", default=os.environ.get("BITCOIN_RPC_PASSWORD", "password")
    )
    parser.add_argument("--start-height", type=int, required=True)
    parser.add_argument("--end-height", type=int, required=True)
    parser.add_argument("--chunk-size", type=int, default=64)
    parser.add_argument("--reward-recipient", required=True)
    parser.add_argument("--m6-artifacts")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def canonical_hex(value: str, size: int, label: str) -> str:
    if value.startswith("0x"):
        value = value[2:]
    if len(value) != size * 2 or value.lower() != value:
        raise ValueError(f"{label} must be {size} lowercase hexadecimal bytes")
    bytes.fromhex(value)
    return value


def load_m6_artifacts(path: str | None) -> dict[int, bytes]:
    if path is None:
        return {}
    manifest_path = Path(path).resolve()
    payload = json.loads(manifest_path.read_text())
    if payload.get("schema") != "usdd-ecash-m6-artifact-map-v1":
        raise ValueError("unsupported M6 artifact map schema")
    result: dict[int, bytes] = {}
    for item in payload.get("artifacts", []):
        height = int(item["height"])
        has_path = "path" in item
        has_hex = "artifactHex" in item
        if has_path == has_hex:
            raise ValueError(
                f"M6 artifact at height {height} must provide exactly one of path or artifactHex"
            )
        if has_path:
            artifact = Path(item["path"])
            if not artifact.is_absolute():
                artifact = manifest_path.parent / artifact
            artifact = artifact.resolve()
            if not artifact.is_file():
                raise ValueError(f"missing M6 artifact for height {height}: {artifact}")
            artifact_bytes = artifact.read_bytes()
        else:
            try:
                artifact_bytes = bytes.fromhex(item["artifactHex"])
            except (TypeError, ValueError) as error:
                raise ValueError(
                    f"invalid canonical M6 artifact hex at height {height}"
                ) from error
        if not artifact_bytes:
            raise ValueError(f"empty M6 artifact at height {height}")
        if height in result:
            raise ValueError(f"duplicate M6 artifact height {height}")
        result[height] = artifact_bytes
    return result


def main() -> int:
    args = parse_args()
    if args.start_height < 0 or args.end_height < args.start_height:
        raise ValueError("invalid inclusive height range")
    if args.chunk_size < 1 or args.chunk_size > 256:
        raise ValueError("chunk size must be in 1..256")
    reward_recipient = canonical_hex(args.reward_recipient, 20, "reward recipient")
    if args.output.exists():
        raise ValueError(f"output already exists: {args.output}")

    rpc = Rpc(args.rpc_url, args.rpc_user, args.rpc_password)
    info = rpc.call("getblockchaininfo")
    if not isinstance(info, dict) or info.get("chain") != "signet":
        raise ValueError("parent RPC is not Signet")
    if int(info["blocks"]) < args.end_height:
        raise ValueError("requested end height is above the active tip")
    m6_artifacts = load_m6_artifacts(args.m6_artifacts)
    unexpected = sorted(set(m6_artifacts) - set(range(args.start_height, args.end_height + 1)))
    if unexpected:
        raise ValueError(f"M6 artifacts are outside requested range: {unexpected}")

    blocks: list[dict[str, object]] = []
    expected_previous: str | None = None
    for height in range(args.start_height, args.end_height + 1):
        expected_hash = str(rpc.call("getblockhash", height))
        raw = bytes.fromhex(str(rpc.call("getblock", expected_hash, 0)))
        if len(raw) < 81:
            raise ValueError(f"block {height} is too short")
        actual_hash = display_hash(raw[:80])
        if actual_hash != expected_hash:
            raise ValueError(f"block {height} hash mismatch")
        previous = raw[4:36][::-1].hex()
        if expected_previous is not None and previous != expected_previous:
            raise ValueError(f"block {height} does not extend the prior captured block")
        transaction_count_prefix = raw[80]
        timestamp = struct.unpack("<I", raw[68:72])[0]
        blocks.append(
            {
                "height": height,
                "hash": actual_hash,
                "previous": previous,
                "timestamp": timestamp,
                "bytes": len(raw),
                "transactionCountPrefix": transaction_count_prefix,
                "raw": raw,
            }
        )
        expected_previous = actual_hash

    args.output.mkdir(parents=True)
    block_dir = args.output / "blocks"
    artifact_dir = args.output / "m6-artifacts"
    spec_dir = args.output / "segment-specs"
    block_dir.mkdir()
    spec_dir.mkdir()
    if m6_artifacts:
        artifact_dir.mkdir()

    for block in blocks:
        height = int(block["height"])
        (block_dir / f"{height:08d}-{block['hash']}.raw").write_bytes(block.pop("raw"))
    copied_artifacts: dict[int, str] = {}
    for height, artifact_bytes in sorted(m6_artifacts.items()):
        destination = artifact_dir / f"{height:08d}.bin"
        destination.write_bytes(artifact_bytes)
        copied_artifacts[height] = f"../m6-artifacts/{destination.name}"

    specs: list[dict[str, object]] = []
    successor_blocks = [block for block in blocks if int(block["height"]) > 0]
    chunks: list[list[dict[str, object]]] = []
    if blocks and int(blocks[0]["height"]) == 0 and successor_blocks:
        chunks.append(successor_blocks[:1])
        successor_blocks = successor_blocks[1:]
    chunks.extend(
        successor_blocks[index : index + args.chunk_size]
        for index in range(0, len(successor_blocks), args.chunk_size)
    )
    for chunk in chunks:
        first_height = int(chunk[0]["height"])
        last_height = int(chunk[-1]["height"])
        entries = []
        for block in chunk:
            height = int(block["height"])
            entry: dict[str, object] = {
                "rawBlock": (
                    f"../blocks/{height:08d}-{block['hash']}.raw"
                )
            }
            if height in copied_artifacts:
                entry["canonicalM6Artifact"] = copied_artifacts[height]
            entries.append(entry)
        spec_name = f"segment-{first_height:08d}-{last_height:08d}.json"
        spec = {"rewardRecipient": reward_recipient, "blocks": entries}
        (spec_dir / spec_name).write_text(json.dumps(spec, indent=2) + "\n")
        specs.append(
            {
                "path": f"segment-specs/{spec_name}",
                "firstHeight": first_height,
                "lastHeight": last_height,
                "blockCount": len(chunk),
            }
        )

    manifest = {
        "schema": "usdd-ecash-captured-segments-v1",
        "chain": "signet",
        "signetChallenge": info.get("signet_challenge"),
        "startHeight": args.start_height,
        "endHeight": args.end_height,
        "genesisBlock": (
            f"blocks/{int(blocks[0]['height']):08d}-{blocks[0]['hash']}.raw"
            if int(blocks[0]["height"]) == 0
            else None
        ),
        "rewardRecipient": reward_recipient,
        "blocks": blocks,
        "segments": specs,
    }
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode()
    (args.output / "manifest.json").write_bytes(manifest_bytes)

    checksums = []
    for path in sorted(value for value in args.output.rglob("*") if value.is_file()):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        checksums.append(f"{digest}  {path.relative_to(args.output)}")
    (args.output / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "blocks": len(blocks),
                "segments": len(specs),
                "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
