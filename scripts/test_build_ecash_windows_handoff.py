#!/usr/bin/env python3
"""Lightweight tests for atomic eCash Windows handoff publication."""

from __future__ import annotations

import importlib.util
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
