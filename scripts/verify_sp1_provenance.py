#!/usr/bin/env python3
"""Fail closed unless locked SP1 registry packages prove the frozen VCS source."""

from __future__ import annotations

import hashlib
import json
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SP1_COMMIT = "8252c2905ce32964df68248117015c61ebb854db"


@dataclass(frozen=True)
class PackageLock:
    name: str
    lockfile: Path
    checksum: str
    vcs_info_sha256: str
    path_in_vcs: str


PACKAGES = (
    PackageLock(
        name="sp1-verifier",
        lockfile=ROOT / "Cargo.lock",
        checksum="b6dbb411abb1ea167f9b0b082c95f62ede26ab7ba72349770292a60dc0e9a673",
        vcs_info_sha256="e24efd25723832aa0031e7421b24c67efdb2cceb4b407c488ad30c4f0a1ec292",
        path_in_vcs="crates/verifier",
    ),
    PackageLock(
        name="sp1-zkvm",
        lockfile=ROOT / "guests/ethereum-state/Cargo.lock",
        checksum="f18fbc79e5a1cc499d3ae3904771104a854493ea12c317ff1407137d86153c26",
        vcs_info_sha256="163bba6e0b92683de4aa077edd5b0c2e19c7ae87ca2a61f2c7d4616ac603bb46",
        path_in_vcs="crates/zkvm/entrypoint",
    ),
)


def locked_package(specification: PackageLock) -> dict[str, object]:
    with specification.lockfile.open("rb") as source:
        lock = tomllib.load(source)
    matches = [
        package
        for package in lock.get("package", [])
        if package.get("name") == specification.name and package.get("version") == "6.3.1"
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one locked {specification.name} 6.3.1 package")
    package = matches[0]
    if package.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
        raise RuntimeError(f"{specification.name} is not from the frozen crates.io registry source")
    if package.get("checksum") != specification.checksum:
        raise RuntimeError(f"{specification.name} registry checksum mismatch")
    return package


def package_directories(specification: PackageLock) -> list[Path]:
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    return sorted((cargo_home / "registry/src").glob(f"*/{specification.name}-6.3.1"))


def verify(specification: PackageLock) -> None:
    locked_package(specification)
    for directory in package_directories(specification):
        vcs_path = directory / ".cargo_vcs_info.json"
        if not vcs_path.is_file():
            continue
        contents = vcs_path.read_bytes()
        if hashlib.sha256(contents).hexdigest() != specification.vcs_info_sha256:
            continue
        provenance = json.loads(contents)
        if (
            provenance.get("git", {}).get("sha1") == SP1_COMMIT
            and provenance.get("path_in_vcs") == specification.path_in_vcs
        ):
            return
    raise RuntimeError(
        f"no installed {specification.name} source has the frozen Cargo VCS provenance"
    )


def main() -> None:
    for specification in PACKAGES:
        verify(specification)
        print(f"PASS {specification.name} 6.3.1 {SP1_COMMIT}")


if __name__ == "__main__":
    main()
