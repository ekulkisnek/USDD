from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
BUILDER = ROOT / "scripts/build_ethereum_windows_handoff.py"
PROGRAM_ID = "4f0511103dab14b61dd5b1403d077ba10d28a89a06dbb54d43e9683542c1df08"
INPUT_NAMES = (
    "00-statement-tag.bin",
    "01-manifest.bin",
    "02-claim.bin",
    "03-finality.bin",
    "04-vault-witness.bin",
)


class EthereumHandoffBuilderTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path]:
        fixture = root / "fixture"
        fixture.mkdir()
        for index, name in enumerate(INPUT_NAMES, start=1):
            (fixture / name).write_bytes(bytes([index]) * index)
        journal = b"canonical-v7-journal"
        (fixture / "expected-journal.bin").write_bytes(journal)
        provenance = {
            "schema": "usdd-sepolia-live-finalized-deposit-fixture-v1",
            "status": "NATIVE_CRYPTOGRAPHIC_PREFLIGHT_PASS_SP1_PROOF_NOT_STARTED",
            "network": "Sepolia",
            "programId": f"0x{PROGRAM_ID}",
            "journalSha256": f"0x{hashlib.sha256(journal).hexdigest()}",
            "journalBytes": len(journal),
            "inputBytes": sum(range(1, 6)),
            "manifestId": f"0x{'11' * 32}",
            "depositTransactionHash": f"0x{'22' * 32}",
            "depositBlockNumber": "7",
            "finalizedExecutionBlockNumber": "8",
        }
        (fixture / "provenance.json").write_text(json.dumps(provenance))
        elf = root / "guest.elf"
        elf.write_bytes(b"frozen-elf")
        return fixture, elf

    def run_builder(self, fixture: Path, elf: Path, output: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(BUILDER),
                "--fixture",
                str(fixture),
                "--elf",
                str(elf),
                "--output",
                str(output),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_builds_checksums_and_pins_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, elf = self.fixture(root)
            output = root / "handoff"
            result = self.run_builder(fixture, elf, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "handoff-manifest.json").read_text())
            self.assertEqual(manifest["programId"], PROGRAM_ID)
            self.assertEqual(manifest["inputBytes"], 15)
            verified = subprocess.run(
                ["shasum", "-a", "256", "-c", "SHA256SUMS"],
                cwd=output,
                capture_output=True,
                text=True,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_rejects_journal_provenance_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, elf = self.fixture(root)
            (fixture / "expected-journal.bin").write_bytes(b"fabricated")
            result = self.run_builder(fixture, elf, root / "handoff")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("journal hash does not match provenance", result.stderr)


if __name__ == "__main__":
    unittest.main()
