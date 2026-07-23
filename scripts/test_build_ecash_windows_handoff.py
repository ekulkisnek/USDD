#!/usr/bin/env python3
"""Lightweight tests for atomic eCash Windows handoff publication."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("build_ecash_windows_handoff.py")
SPEC = importlib.util.spec_from_file_location("build_ecash_windows_handoff", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EcashWindowsHandoffBuilderTests(unittest.TestCase):
    def test_require_file_returns_resolved_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "fixture.bin"
            source.write_bytes(b"fixture")
            self.assertEqual(MODULE.require_file(source, "fixture"), source.resolve())

    def test_require_file_rejects_missing_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.bin"
            with self.assertRaisesRegex(ValueError, "missing fixture"):
                MODULE.require_file(missing, "fixture")

    def test_metadata_rejects_untrusted_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metadata = Path(directory) / "metadata.json"
            metadata.write_text('{"schema":"test-only"}\n')
            with self.assertRaisesRegex(ValueError, "unsupported prepared segment"):
                MODULE.metadata(metadata)

    def _fixture(self, root: Path, *, failing_prover: bool = False) -> list[str]:
        capture = root / "capture"
        blocks = capture / "blocks"
        specs = capture / "segments"
        blocks.mkdir(parents=True)
        specs.mkdir()
        (blocks / "genesis.raw").write_bytes(b"genesis")
        (blocks / "one.raw").write_bytes(b"one")
        (blocks / "two.raw").write_bytes(b"two")
        (specs / "one.json").write_text(
            json.dumps({"blocks": [{"rawBlock": "../blocks/one.raw"}]}) + "\n"
        )
        (specs / "two.json").write_text(
            json.dumps({"blocks": [{"rawBlock": "../blocks/two.raw"}]}) + "\n"
        )
        (capture / "manifest.json").write_text(
            json.dumps(
                {
                    "schema": "usdd-ecash-captured-segments-v1",
                    "chain": "signet",
                    "signetChallenge": "00",
                    "startHeight": 0,
                    "endHeight": 2,
                    "genesisBlock": "blocks/genesis.raw",
                    "segments": [
                        {
                            "firstHeight": 1,
                            "lastHeight": 1,
                            "path": "segments/one.json",
                        },
                        {
                            "firstHeight": 2,
                            "lastHeight": 2,
                            "path": "segments/two.json",
                        },
                    ],
                }
            )
            + "\n"
        )
        checksum_lines = []
        for path in sorted(value for value in capture.rglob("*") if value.is_file()):
            checksum_lines.append(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(capture)}"
            )
        (capture / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n")

        segment_elf = root / "segment.elf"
        fold_elf = root / "fold.elf"
        genesis_spec = root / "genesis.json"
        segment_elf.write_bytes(b"segment")
        fold_elf.write_bytes(b"fold")
        genesis_spec.write_text("{}\n")
        prover = root / "prover"
        if failing_prover:
            prover.write_text("#!/bin/sh\nexit 7\n")
        else:
            prover.write_text(
                """#!/usr/bin/env python3
import json
from pathlib import Path
import sys
command = sys.argv[1]
output = Path(sys.argv[-1])
output.mkdir(parents=True)
if command == "prepare-genesis-segment":
    values = {
        "schema": "usdd-ecash-genesis-segment-input-v1",
        "priorStateCommitment": "state-0", "nextStateCommitment": "state-1",
        "priorTip": "tip-0", "nextTip": "tip-1",
        "priorHeight": 0, "nextHeight": 1
    }
    (output / "config.bin").write_bytes(b"config")
else:
    values = {
        "schema": "usdd-ecash-successor-segment-input-v1",
        "priorStateCommitment": "state-1", "nextStateCommitment": "state-2",
        "priorTip": "tip-1", "nextTip": "tip-2",
        "priorHeight": 1, "nextHeight": 2
    }
(output / "next-state.bin").write_bytes(values["nextStateCommitment"].encode())
(output / "input.bin").write_bytes(b"input")
(output / "metadata.json").write_text(json.dumps(values) + "\\n")
"""
            )
        os.chmod(prover, 0o755)
        return [
            sys.executable,
            str(MODULE_PATH),
            "--prover",
            str(prover),
            "--segment-elf",
            str(segment_elf),
            "--fold-elf",
            str(fold_elf),
            "--genesis-spec",
            str(genesis_spec),
            "--capture",
            str(capture),
            "--output",
            str(root / "handoff"),
        ]

    def test_success_is_published_only_under_final_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            completed = subprocess.run(
                self._fixture(root), check=True, capture_output=True, text=True
            )
            result = json.loads(completed.stdout.splitlines()[-1])
            self.assertEqual(result["segments"], 2)
            self.assertTrue((root / "handoff" / "SHA256SUMS").is_file())
            self.assertFalse((root / ".handoff.building").exists())

    def test_failed_preflight_never_publishes_final_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            completed = subprocess.run(
                self._fixture(root, failing_prover=True),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse((root / "handoff").exists())
            self.assertTrue((root / ".handoff.building").is_dir())


if __name__ == "__main__":
    unittest.main()
