#!/usr/bin/env python3
"""Materialize or verify the pinned USDD SP1 host-only dependency tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path


HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "manifest.json"
VENDOR = HERE / "vendor"
DOWNLOADS = HERE / "downloads"


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def require_digest(path: Path, expected: str, label: str) -> None:
    actual = digest(path)
    if actual != expected:
        raise SystemExit(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")


def load_manifest() -> dict:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    patcher = HERE / manifest["patcher"]["path"]
    require_digest(patcher, manifest["patcher"]["sha256"], "patch transformer")
    return manifest


def safe_extract(archive: Path, destination: Path) -> None:
    destination = destination.resolve()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            if member.issym() or member.islnk():
                raise SystemExit(f"refusing archive link: {member.name}")
            target = (destination / member.name).resolve()
            if target != destination and destination not in target.parents:
                raise SystemExit(f"refusing archive path traversal: {member.name}")
        bundle.extractall(destination, filter="data")


def obtain_archive(name: str, record: dict, cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / f"{name}.crate"
    if not archive.exists():
        print(f"downloading pinned {name}", file=sys.stderr)
        with urllib.request.urlopen(record["url"]) as response, archive.open("xb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
    require_digest(archive, record["sha256"], name)
    return archive


def verify_sources(root: Path, manifest: dict, key: str) -> None:
    for relative, hashes in manifest["modifiedFiles"].items():
        require_digest(root / relative, hashes[key], relative)


def verify_circuit_compatibility(root: Path, manifest: dict) -> None:
    record = manifest["circuitCompatibility"]
    source = root / record["path"]
    require_digest(source, record["sha256"], record["path"])
    value = source.read_bytes()
    expected = record["value"].encode("ascii")
    if value != expected:
        raise SystemExit(
            "SP1 circuit compatibility mismatch: "
            f"expected exact bytes {expected!r}, got {value!r}"
        )


def transform(root: Path, manifest: dict) -> None:
    verify_sources(root, manifest, "upstreamSha256")
    verify_circuit_compatibility(root, manifest)
    subprocess.run(
        [sys.executable, str(HERE / manifest["patcher"]["path"]), str(root)],
        check=True,
    )
    verify_sources(root, manifest, "patchedSha256")
    verify_circuit_compatibility(root, manifest)


def structural_checks(root: Path) -> None:
    builder = (root / "sp1-prover-6.3.1/src/worker/builder.rs").read_text()
    node = (root / "sp1-prover-6.3.1/src/worker/node/full/mod.rs").read_text()
    controller = (root / "sp1-prover-6.3.1/src/worker/controller/mod.rs").read_text()
    core = (root / "sp1-prover-6.3.1/src/worker/prover/core.rs").read_text()
    recursion = (root / "sp1-prover-6.3.1/src/worker/prover/recursion.rs").read_text()
    sdk = (root / "sp1-sdk-6.3.1/src/cpu/prove.rs").read_text()
    sdk_cpu = (root / "sp1-sdk-6.3.1/src/cpu/mod.rs").read_text()
    requirements = {
        "shared prover permit is configurable and nonzero":
            'std::env::var("SP1_WORKER_MAX_PROVER_PERMITS")' in builder
            and "assert!(max_prover_permits > 0" in builder
            and "ProverSemaphore::new(max_prover_permits)" in builder,
        "nonce slot four": "cycle_limit_artifact,\n                    proof_nonce_artifact.clone()" in node,
        "one-shot hint consumed": ".remove(&elf_clone)" in controller
        and "using one-shot setup vkey hint" in controller,
        "one-shot hint cancellation cleanup": "impl Drop for SetupVkeyHintGuard" in node
        and "hints.remove(&self.artifact)" in node,
        "core derived-vkey equality": "derived_vk != common_input.vk.vk" in core,
        "lazy recursion exact-vkey equality": "derived_vk != expected_vk" in recursion,
        "eager recursion PK retention removed": "unsafe { pk.into_inner() }" not in recursion,
        "SDK supplies typed full vkey": "prove_with_mode_and_vkey" in sdk and "pk.vk.clone()" in sdk,
        "compressed proof Groth16 wrapper is exposed":
            "pub async fn groth16_wrap_compressed" in node
            and "TaskType::Groth16Wrap" in node
            and "pub async fn groth16_wrap_compressed" in sdk_cpu,
    }
    failed = [name for name, passed in requirements.items() if not passed]
    if failed:
        raise SystemExit("structural patch checks failed: " + ", ".join(failed))


def build_tree(root: Path, manifest: dict, cache: Path) -> None:
    for name, record in manifest["archives"].items():
        safe_extract(obtain_archive(name, record, cache), root)
    transform(root, manifest)
    structural_checks(root)


def verify_vendor(manifest: dict) -> None:
    if not VENDOR.is_dir():
        raise SystemExit(f"patched vendor tree is absent: run {Path(__file__).name} --materialize")
    verify_sources(VENDOR, manifest, "patchedSha256")
    verify_circuit_compatibility(VENDOR, manifest)
    structural_checks(VENDOR)
    print("PASS: pinned patched SP1 vendor source hashes and invariants")


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify-only", action="store_true")
    mode.add_argument("--materialize", action="store_true")
    mode.add_argument("--check-vendor", action="store_true")
    args = parser.parse_args()
    manifest = load_manifest()

    if args.check_vendor:
        verify_vendor(manifest)
        return

    if args.verify_only:
        with tempfile.TemporaryDirectory(prefix="usdd-sp1-host-patch-") as temporary:
            build_tree(Path(temporary), manifest, DOWNLOADS)
        print("PASS: exact upstream archives transform to the frozen patched hashes")
        return

    if VENDOR.exists():
        verify_vendor(manifest)
        return
    VENDOR.mkdir(parents=True)
    try:
        build_tree(VENDOR, manifest, DOWNLOADS)
    except BaseException:
        print(
            f"materialization failed; remove the incomplete dedicated directory {VENDOR}",
            file=sys.stderr,
        )
        raise
    print(f"PASS: materialized pinned patched SP1 sources at {VENDOR}")


if __name__ == "__main__":
    main()
