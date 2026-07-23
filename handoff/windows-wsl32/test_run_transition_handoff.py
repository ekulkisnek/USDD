import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("run-transition-handoff.py")
SPEC = importlib.util.spec_from_file_location("run_transition_handoff", MODULE_PATH)
runner = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(runner)


class TransitionHandoffValidationTests(unittest.TestCase):
    def test_segment_validation_binds_expected_journal_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proof = root / "proof"
            prepared = root / "prepared"
            proof.mkdir()
            prepared.mkdir()
            public_values = b"canonical journal"
            raw_proof = b"transparent proof"
            (proof / "public-values.bin").write_bytes(public_values)
            (prepared / "expected-public-values.bin").write_bytes(public_values)
            (proof / "proof.raw.bin").write_bytes(raw_proof)
            elf_hash = "11" * 32
            (proof / "proof-metadata.json").write_text(
                json.dumps(
                    {
                        "schema": "usdd-ecash-proof-artifact-v1",
                        "kind": "segment",
                        "proofMode": "compressed-transparent",
                        "tee": False,
                        "intermediateProofVerification": True,
                        "deferredProofVerification": True,
                        "elf": {"sha256": elf_hash},
                        "publicValues": {
                            "sha256": runner.sha256(proof / "public-values.bin")
                        },
                        "rawProof": {
                            "sha256": runner.sha256(proof / "proof.raw.bin")
                        },
                    }
                )
            )
            runner.validate_segment_proof(proof, prepared, elf_hash)
            (prepared / "expected-public-values.bin").write_bytes(b"wrong")
            with self.assertRaisesRegex(RuntimeError, "public values mismatch"):
                runner.validate_segment_proof(proof, prepared, elf_hash)

    def test_wrapper_validation_requires_verified_fold_and_exact_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrapper = root / "wrapper"
            fold = root / "fold"
            wrapper.mkdir()
            fold.mkdir()
            raw_proof_hash = "22" * 32
            (fold / "proof-metadata.json").write_text(
                json.dumps({"rawProof": {"sha256": raw_proof_hash}})
            )
            files = {
                "groth16-proof.bin": b"groth16",
                "relay-proof.bin": b"relay",
                "public-values.bin": b"fold journal",
                "ethereum-verifier-arguments.json": b"{}",
            }
            for name, value in files.items():
                (wrapper / name).write_bytes(value)
            (wrapper / "wrap-metadata.json").write_text(
                json.dumps(
                    {
                        "schema": "usdd-ecash-groth16-wrapper-v1",
                        "kind": "fold",
                        "status": "GROTH16_WRAPPER_SDK_VERIFIED",
                        "sdkVerifiedBeforeWrap": True,
                        "sdkVerifiedAfterWrap": True,
                        "tee": False,
                        "sourceProof": {"sha256": raw_proof_hash},
                        "publicValues": {
                            "sha256": runner.sha256(
                                wrapper / "public-values.bin"
                            )
                        },
                        "onchainProof": {
                            "sha256": runner.sha256(
                                wrapper / "groth16-proof.bin"
                            )
                        },
                        "usddRelayProof": {
                            "sha256": runner.sha256(wrapper / "relay-proof.bin")
                        },
                    }
                )
            )
            runner.validate_wrapper(wrapper, fold)
            metadata = json.loads((wrapper / "wrap-metadata.json").read_text())
            metadata["sdkVerifiedAfterWrap"] = False
            (wrapper / "wrap-metadata.json").write_text(json.dumps(metadata))
            with self.assertRaisesRegex(RuntimeError, "after wrapping"):
                runner.validate_wrapper(wrapper, fold)


if __name__ == "__main__":
    unittest.main()
