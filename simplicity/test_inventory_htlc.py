from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from render_inventory_htlc import (
    MINIMUM_DEADLINE_GAP_SECONDS,
    parse_xonly_pubkey,
    render,
)


ROOT = pathlib.Path(__file__).parent
TEMPLATE = (ROOT / "inventory_htlc_v1.simf.in").read_text(encoding="utf-8")
HASH = "11" * 32
CLAIMANT = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REFUND = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
ELEMENTS_DEADLINE = 2_000_000_000


def valid_render(**overrides: object) -> str:
    values: dict[str, object] = {
        "secret_hash": HASH,
        "claimant_xonly_pubkey": CLAIMANT,
        "refund_xonly_pubkey": REFUND,
        "elements_refund_timestamp": ELEMENTS_DEADLINE,
        "external_refund_timestamp": ELEMENTS_DEADLINE
        + MINIMUM_DEADLINE_GAP_SECONDS,
    }
    values.update(overrides)
    return render(TEMPLATE, **values)  # type: ignore[arg-type]


class InventoryHtlcTemplateTests(unittest.TestCase):
    def test_rendered_program_has_required_authorization(self) -> None:
        source = valid_render()
        self.assertNotIn("@", source)
        self.assertIn(f"0x{HASH}", source)
        self.assertIn(f"0x{CLAIMANT}", source)
        self.assertIn(f"0x{REFUND}", source)
        self.assertIn("sha_256_ctx_8_add_32", source)
        self.assertIn("bip_0340_verify", source)
        self.assertIn("sig_all_hash", source)
        self.assertIn("check_lock_time", source)
        self.assertIn("let elements_refund_timestamp: Time = 2000000000", source)

    def test_hash_is_exact_nonzero_bytes32(self) -> None:
        for bad_hash in ("", "00" * 32, "11" * 31, "11" * 33, "zz" * 32):
            with self.subTest(bad_hash=bad_hash), self.assertRaises(ValueError):
                valid_render(secret_hash=bad_hash)

    def test_keys_must_be_valid_distinct_xonly_points(self) -> None:
        self.assertEqual(CLAIMANT, parse_xonly_pubkey("key", CLAIMANT.upper()))
        for bad_key in ("00" * 32, "ff" * 32, "11" * 31):
            with self.subTest(bad_key=bad_key), self.assertRaises(ValueError):
                valid_render(claimant_xonly_pubkey=bad_key)
        with self.assertRaises(ValueError):
            valid_render(refund_xonly_pubkey=CLAIMANT)

    def test_elements_deadline_must_be_timestamp_u32(self) -> None:
        for deadline in (499_999_999, -1, 0x1_0000_0000):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                valid_render(elements_refund_timestamp=deadline)

    def test_external_deadline_is_later_by_full_safety_gap(self) -> None:
        for gap in (-1, 0, 1, MINIMUM_DEADLINE_GAP_SECONDS - 1):
            with self.subTest(gap=gap), self.assertRaises(ValueError):
                valid_render(external_refund_timestamp=ELEMENTS_DEADLINE + gap)
        valid_render(
            external_refund_timestamp=ELEMENTS_DEADLINE
            + MINIMUM_DEADLINE_GAP_SECONDS
        )

    def test_external_deadline_must_fit_u64(self) -> None:
        for deadline in (-1, 0x1_0000_0000_0000_0000):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                valid_render(external_refund_timestamp=deadline)


if __name__ == "__main__":
    unittest.main()
