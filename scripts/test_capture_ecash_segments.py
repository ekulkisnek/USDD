import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("capture_ecash_segments.py")
SPEC = importlib.util.spec_from_file_location("capture_ecash_segments", MODULE_PATH)
capture = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(capture)


def block(previous_display: str, timestamp: int, nonce: int) -> tuple[str, bytes]:
    header = (
        struct.pack("<I", 1)
        + bytes.fromhex(previous_display)[::-1]
        + bytes([nonce]) * 32
        + struct.pack("<III", timestamp, 0x207FFFFF, nonce)
    )
    raw = header + b"\x00"
    return capture.display_hash(header), raw


class FakeRpc:
    def __init__(self) -> None:
        genesis_hash, genesis = block("00" * 32, 1_700_000_000, 1)
        successor_hash, successor = block(genesis_hash, 1_700_000_001, 2)
        self.hashes = [genesis_hash, successor_hash]
        self.raw = {genesis_hash: genesis, successor_hash: successor}

    def call(self, method: str, *params: object) -> object:
        if method == "getblockchaininfo":
            return {
                "chain": "signet",
                "blocks": 1,
                "signet_challenge": "0014" + "11" * 20,
            }
        if method == "getblockhash":
            return self.hashes[int(params[0])]
        if method == "getblock":
            return self.raw[str(params[0])].hex()
        raise AssertionError(f"unexpected RPC method {method}")


class CaptureSegmentsTests(unittest.TestCase):
    def test_capture_verifies_and_separates_genesis_from_successor(self) -> None:
        fake = FakeRpc()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "capture"
            argv = [
                "capture_ecash_segments.py",
                "--start-height",
                "0",
                "--end-height",
                "1",
                "--chunk-size",
                "64",
                "--reward-recipient",
                "22" * 20,
                "--output",
                str(output),
            ]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                capture, "Rpc", return_value=fake
            ):
                self.assertEqual(capture.main(), 0)

            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["genesisBlock"].split("/")[0], "blocks")
            self.assertEqual(
                manifest["segments"],
                [
                    {
                        "path": "segment-specs/segment-00000001-00000001.json",
                        "firstHeight": 1,
                        "lastHeight": 1,
                        "blockCount": 1,
                    }
                ],
            )
            segment = json.loads(
                (output / manifest["segments"][0]["path"]).read_text()
            )
            self.assertEqual(segment["rewardRecipient"], "22" * 20)
            self.assertEqual(len(segment["blocks"]), 1)
            self.assertTrue((output / "SHA256SUMS").is_file())

    def test_hash_and_hex_validation_fail_closed(self) -> None:
        self.assertEqual(capture.canonical_hex("ab" * 20, 20, "value"), "ab" * 20)
        with self.assertRaises(ValueError):
            capture.canonical_hex("AB" * 20, 20, "value")
        with self.assertRaises(ValueError):
            capture.canonical_hex("ab" * 19, 20, "value")

    def test_embeds_canonical_m6_artifact_hex(self) -> None:
        fake = FakeRpc()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact_hex = "555344444d3658320001"
            artifact_map = root / "m6.json"
            artifact_map.write_text(
                json.dumps(
                    {
                        "schema": "usdd-ecash-m6-artifact-map-v1",
                        "artifacts": [
                            {"height": 1, "artifactHex": artifact_hex}
                        ],
                    }
                )
            )
            output = root / "capture"
            argv = [
                "capture_ecash_segments.py",
                "--start-height",
                "0",
                "--end-height",
                "1",
                "--chunk-size",
                "64",
                "--reward-recipient",
                "22" * 20,
                "--m6-artifacts",
                str(artifact_map),
                "--output",
                str(output),
            ]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                capture, "Rpc", return_value=fake
            ):
                self.assertEqual(capture.main(), 0)
            self.assertEqual(
                (output / "m6-artifacts" / "00000001.bin").read_bytes(),
                bytes.fromhex(artifact_hex),
            )


if __name__ == "__main__":
    unittest.main()
