#!/usr/bin/env python3
import hashlib
import json
import sys
from pathlib import Path

PROGRAM_ID = "1d9486bc2436fcc30e6c383000e6ba6c6eeee1854814ec6f29581e9b66aef0b9"
PROGRAM_VKEY = "003b290d7890dbf30c7361c1800e6ba6cddddc30b2053b1bd4ac0f4de6aef0b9"
RAW_VKEY = "bc86941dc3fc362430386c0e6cbae60085e1ee6e6fec14489b1e5829b9f0ae66"
SOURCE_PROOF_SHA256 = "3f5b2a2b7621978f4f5da8a6699e6d95def4d26276d89d98dd8c8c75d34511ae"
PUBLIC_VALUES_SHA256 = "a6b7b01ea10dac19bc023d93bb7dc6e17b8313c1fbffff9b817888e0bc058872"
GROTH16_VKEY_HASH = "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696"


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <wrapper-output-directory>")
    root = Path(sys.argv[1]).resolve()
    metadata = json.loads((root / "wrap-metadata.json").read_text(encoding="utf-8"))
    public = (root / "public-values.bin").read_bytes()
    proof = (root / "groth16-proof.bin").read_bytes()
    relay = (root / "relay-proof.bin").read_bytes()

    assert metadata["schema"] == "usdd-ecash-groth16-wrapper-v1"
    assert metadata["status"] == "GROTH16_WRAPPER_SDK_VERIFIED"
    assert metadata["kind"] == "segment"
    assert metadata["sourceProofMode"] == "compressed-transparent"
    assert metadata["outputProofMode"] == "groth16-bn254"
    assert metadata["sp1PackageRelease"] == "6.3.1"
    assert metadata["sp1CircuitVersion"] == "v6.1.0"
    assert metadata["programIdHashBytes"] == PROGRAM_ID
    assert metadata["programVKeyBn254"] == PROGRAM_VKEY
    assert metadata["rawVkeyHashFixedLittleEndian"] == RAW_VKEY
    assert metadata["sourceProof"]["sha256"] == SOURCE_PROOF_SHA256
    assert metadata["publicValues"]["sha256"] == PUBLIC_VALUES_SHA256 == sha256(public)
    assert metadata["groth16VkeyHash"] == GROTH16_VKEY_HASH
    assert metadata["sdkVerifiedBeforeWrap"] is True
    assert metadata["sdkVerifiedAfterWrap"] is True
    assert metadata["tee"] is False

    assert len(public) == 551
    assert len(proof) == 356
    assert proof[:4] == bytes.fromhex(GROTH16_VKEY_HASH[:8])
    assert relay == public + proof
    assert metadata["onchainProof"]["bytes"] == len(proof)
    assert metadata["onchainProof"]["sha256"] == sha256(proof)
    assert metadata["usddRelayProof"]["bytes"] == len(relay)
    assert metadata["usddRelayProof"]["sha256"] == sha256(relay)
    assert (root / "program-id.bin").read_bytes() == bytes.fromhex(PROGRAM_ID)
    assert (root / "program-vkey-bn254.bin").read_bytes() == bytes.fromhex(PROGRAM_VKEY)

    arguments = json.loads((root / "ethereum-verifier-arguments.json").read_text(encoding="utf-8"))
    assert bytes.fromhex(arguments["programVKey"][2:]) == bytes.fromhex(PROGRAM_VKEY)
    assert bytes.fromhex(arguments["publicValues"][2:]) == public
    assert bytes.fromhex(arguments["proofBytes"][2:]) == proof
    assert bytes.fromhex(arguments["usddRelayProof"][2:]) == relay
    print("PASS: SDK-verified canonical SP1 v6.1.0 Groth16 wrapper")


if __name__ == "__main__":
    main()
