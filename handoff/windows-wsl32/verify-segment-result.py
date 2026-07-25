#!/usr/bin/env python3
import hashlib
import json
import sys
from pathlib import Path

EXPECTED = {
    "programIdHashBytes": "1d9486bc2436fcc30e6c383000e6ba6c6eeee1854814ec6f29581e9b66aef0b9",
    "programVKeyBn254": "003b290d7890dbf30c7361c1800e6ba6cddddc30b2053b1bd4ac0f4de6aef0b9",
    "rawVkeyHashFixedLittleEndian": "bc86941dc3fc362430386c0e6cbae60085e1ee6e6fec14489b1e5829b9f0ae66",
    "rawProofSha256": "3f5b2a2b7621978f4f5da8a6699e6d95def4d26276d89d98dd8c8c75d34511ae",
    "publicValuesSha256": "a6b7b01ea10dac19bc023d93bb7dc6e17b8313c1fbffff9b817888e0bc058872",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <segment-proof-directory>")
    root = Path(sys.argv[1]).resolve()
    metadata = json.loads((root / "proof-metadata.json").read_text(encoding="utf-8"))

    assert metadata["schema"] == "usdd-ecash-proof-artifact-v1"
    assert metadata["kind"] == "segment"
    assert metadata["proofMode"] == "compressed-transparent"
    assert metadata["sp1PackageRelease"] == "6.3.1"
    assert metadata["sp1CircuitVersion"] == "v6.1.0"
    assert metadata["tee"] is False
    assert metadata["intermediateProofVerification"] is True
    assert metadata["deferredProofVerification"] is True
    assert metadata["programIdHashBytes"] == EXPECTED["programIdHashBytes"]
    assert metadata["programVKeyBn254"] == EXPECTED["programVKeyBn254"]
    assert metadata["rawVkeyHashFixedLittleEndian"] == EXPECTED["rawVkeyHashFixedLittleEndian"]

    raw = root / "proof.raw.bin"
    public = root / "public-values.bin"
    assert raw.stat().st_size == 1_272_546
    assert sha256(raw) == EXPECTED["rawProofSha256"] == metadata["rawProof"]["sha256"]
    assert public.stat().st_size == 551
    assert sha256(public) == EXPECTED["publicValuesSha256"] == metadata["publicValues"]["sha256"]
    assert public.read_bytes().startswith(b"USDD_ECASH_SEGMENT_JOURNAL_V1")
    assert (root / "program-id.bin").read_bytes() == bytes.fromhex(EXPECTED["programIdHashBytes"])
    assert (root / "program-vkey-bn254.bin").read_bytes() == bytes.fromhex(EXPECTED["programVKeyBn254"])
    assert (root / "raw-vkey-hash.bin").read_bytes() == bytes.fromhex(EXPECTED["rawVkeyHashFixedLittleEndian"])
    assert (root / "proof.sp1.bin").stat().st_size == 1_273_120
    print("PASS: exact transferred segment proof artifact")


if __name__ == "__main__":
    main()
