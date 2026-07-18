#!/usr/bin/env python3

import copy
import dataclasses
import unittest

import usdd_formats as formats


def state(**changes):
    values = {
        "version": 1,
        "sequence": 7,
        "next_mint_nonce": 20,
        "eth_light_client_digest": b"l" * 32,
        "finalized_beacon_slot": 100,
        "finalized_beacon_root": b"b" * 32,
        "execution_root": b"e" * 32,
        "total_minted": 1_000,
        "config_hash": b"c" * 32,
    }
    values.update(changes)
    return formats.ControllerState(**values)


def manifest():
    return {
        "protocol": "USDD",
        "version": 1,
        "ethereum_chain_id": 1,
        "ethereum_genesis": "01" * 32,
        "bitcoin_genesis": "02" * 32,
        "elements_genesis": "03" * 32,
        "drivechain_slot": 24,
        "usdt": "04" * 20,
        "vault": "05" * 20,
        "vault_code_hash": "06" * 32,
        "usdd_asset_id": "07" * 32,
        "reissuance_token_id": "08" * 32,
        "issuance_txid": "09" * 32,
        "issuance_vout": 1,
        "asset_entropy": "0a" * 32,
        "controller_cmr": "0b" * 32,
        "controller_initial_state_hash": "0c" * 32,
        "ethereum_guest_program_id": "0d" * 32,
        "elements_guest_program_id": "0e" * 32,
        "minimum_bitcoin_confirmations": 100,
        "first_mint_nonce": 0,
        "usdt_decimals": 6,
        "usdd_decimals": 8,
        "usdd_units_per_usdt_micro": 100,
        "max_mint_batch": 64,
    }


class AnnexTests(unittest.TestCase):
    def test_known_vector_and_round_trip(self):
        encoded = formats.encode_sp1_annex(b"\x11" * 32, b"\xaa\xbb", b"\xcc\xdd\xee")
        expected = (
            "50" "5553444453503100" "01" "01" "01" "01" "0000"
            "00000002" "00000003" + "11" * 32 + "aabbccddee"
        )
        self.assertEqual(encoded.hex(), expected)
        self.assertEqual(formats.decode_sp1_annex(encoded), formats.Sp1Annex(b"\x11" * 32, b"\xaa\xbb", b"\xcc\xdd\xee"))

    def test_limits_and_kind_two_rejected(self):
        maximum = formats.encode_sp1_annex(
            b"v" * 32, b"x", b"p" * (formats.SP1_MAX_SIZE - formats.SP1_HEADER_SIZE - 1)
        )
        self.assertEqual(len(maximum), formats.SP1_MAX_SIZE)
        self.assertEqual(len(formats.decode_sp1_annex(maximum).proof), len(maximum) - 56)
        with self.assertRaises(formats.FormatError):
            formats.decode_sp1_annex(maximum + b"x")
        kind_two = bytearray(formats.encode_sp1_annex(b"v" * 32, b"x", b"p"))
        kind_two[11] = 2
        with self.assertRaises(formats.FormatError):
            formats.decode_sp1_annex(bytes(kind_two))

    def test_malformed_never_decodes(self):
        valid = bytearray(formats.encode_sp1_annex(b"v" * 32, b"public", b"proof"))
        mutations = [bytes(valid[:-1]), bytes(valid) + b"x", b"\x50USDD"]
        for offset, value in ((5, 0), (9, 2), (10, 2), (12, 2), (14, 1)):
            changed = valid.copy()
            changed[offset] = value
            mutations.append(bytes(changed))
        zero_vkey = valid.copy()
        zero_vkey[23:55] = b"\0" * 32
        mutations.append(bytes(zero_vkey))
        for value in mutations:
            with self.subTest(value=value[:16].hex()), self.assertRaises(formats.FormatError):
                formats.decode_sp1_annex(value)


class ControllerTests(unittest.TestCase):
    def test_fixed_state_round_trip(self):
        current = state()
        encoded = formats.encode_controller_state(current)
        self.assertEqual(len(encoded), 164)
        self.assertEqual(formats.decode_controller_state(encoded), current)
        self.assertEqual(
            [field.name for field in dataclasses.fields(formats.ControllerState)],
            ["version", "sequence", "next_mint_nonce", "eth_light_client_digest",
             "finalized_beacon_slot", "finalized_beacon_root", "execution_root", "total_minted", "config_hash"],
        )

    def test_one_and_sixty_four_consecutive_deposits(self):
        self.assertEqual(formats.validate_mint_batch(20, [20], [3]), ([300], 300))
        amounts, total = formats.validate_mint_batch(20, list(range(20, 84)), [1] * 64)
        self.assertEqual(amounts, [100] * 64)
        self.assertEqual(total, 6_400)

    def test_bad_batch_counts_order_and_overflow(self):
        for nonces, amounts in (([], []), (list(range(65)), [1] * 65), ([20, 22], [1, 1]), ([20, 20], [1, 1])):
            with self.assertRaises(formats.FormatError):
                formats.validate_mint_batch(20, nonces, amounts)
        with self.assertRaises(formats.FormatError):
            formats.usdt6_to_usdd8(0xFFFFFFFFFFFFFFFF)

    def test_exact_transition(self):
        current = state()
        proposed = state(
            sequence=8,
            next_mint_nonce=22,
            finalized_beacon_slot=101,
            finalized_beacon_root=b"n" * 32,
            execution_root=b"x" * 32,
            eth_light_client_digest=b"d" * 32,
            total_minted=1_300,
        )
        self.assertEqual(formats.validate_controller_transition(current, proposed, [20, 21], [1, 2]), 300)
        with self.assertRaises(formats.FormatError):
            formats.validate_controller_transition(current, dataclasses.replace(proposed, config_hash=b"z" * 32), [20, 21], [1, 2])
        with self.assertRaises(formats.FormatError):
            formats.validate_controller_transition(current, dataclasses.replace(proposed, sequence=9), [20, 21], [1, 2])

    def test_permissionless_heartbeat_is_state_only_and_newer(self):
        current = state()
        heartbeat = state(
            sequence=8,
            finalized_beacon_slot=101,
            finalized_beacon_root=b"n" * 32,
            execution_root=b"x" * 32,
            eth_light_client_digest=b"d" * 32,
        )
        formats.validate_heartbeat_transition(current, heartbeat)
        for bad in (
            dataclasses.replace(heartbeat, next_mint_nonce=21),
            dataclasses.replace(heartbeat, total_minted=1_100),
            dataclasses.replace(heartbeat, finalized_beacon_slot=100),
            dataclasses.replace(heartbeat, eth_light_client_digest=current.eth_light_client_digest),
            dataclasses.replace(heartbeat, config_hash=b"z" * 32),
        ):
            with self.assertRaises(formats.FormatError):
                formats.validate_heartbeat_transition(current, bad)


class BurnTests(unittest.TestCase):
    def test_exact_script_and_round_trip(self):
        script = formats.encode_burn_script(b"v" * 32, b"r" * 20, 1_500_000)
        self.assertEqual(len(script), 67)
        self.assertEqual(script[:7], b"\x6a\x41USDD\x01")
        decoded = formats.decode_burn_script(script)
        self.assertEqual(decoded, formats.BurnData(b"v" * 32, b"r" * 20, 1_500_000))
        self.assertEqual(decoded.output_value_usdd8, 150_000_000)

    def test_nonminimal_or_wrong_payload_rejected(self):
        valid = bytearray(formats.encode_burn_script(b"v" * 32, b"r" * 20, 1))
        for offset, value in ((0, 0), (1, 0x4C), (2, 0), (6, 2)):
            changed = valid.copy()
            changed[offset] = value
            with self.assertRaises(formats.FormatError):
                formats.decode_burn_script(bytes(changed))
        with self.assertRaises(formats.FormatError):
            formats.decode_burn_script(bytes(valid) + b"x")
        with self.assertRaises(formats.FormatError):
            formats.encode_burn_script(b"v" * 32, b"r" * 20, 0)

    def test_burn_id_known_vector_and_vout_binding(self):
        genesis = bytes(range(32, 64))
        txid_display = bytes(range(32))
        first = formats.burn_id(genesis, txid_display, 7)
        self.assertEqual(first.hex(), "bf51107db63f8ee5778b5b1efb1872d1ef849117bc0e44c5a72f4b0ade0b0261")
        self.assertNotEqual(first, formats.burn_id(genesis, txid_display, 8))
        self.assertNotEqual(first, formats.burn_id(genesis, txid_display[::-1], 7))

    def test_sparse_empty_roots_and_contiguous_prefix(self):
        empty = formats.burn_empty_roots()
        self.assertEqual(len(empty), 65)
        self.assertEqual(empty[0].hex(), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
        self.assertEqual(empty[64].hex(), "c13fcc5e95b202155d131894da01dff87c8ac722937c76415daab46e53ed40db")
        formats.validate_burn_append(5, [5, 6, 7], 8)
        with self.assertRaises(formats.FormatError):
            formats.validate_burn_append(5, [5, 7], 8)
        with self.assertRaises(formats.FormatError):
            formats.validate_burn_append(5, [6], 6)


class InventoryHtlcTests(unittest.TestCase):
    def params(self, **changes):
        values = {
            "secret_hash": b"s" * 32,
            "claimant_script_hash": b"c" * 32,
            "refund_script_hash": b"r" * 32,
            "asset_id": b"a" * 32,
            "amount": 100,
            "elements_refund_deadline": 2_000_000_000,
            "external_refund_deadline": 2_000_086_400,
        }
        values.update(changes)
        return formats.InventoryHtlcParameters(**values)

    def test_external_deadline_is_at_least_24h_later(self):
        formats.validate_inventory_htlc(self.params())
        with self.assertRaises(formats.FormatError):
            formats.validate_inventory_htlc(self.params(external_refund_deadline=2_000_086_399))

    def test_fixed_nonzero_distinct_commitments(self):
        for bad in (
            self.params(secret_hash=b"\0" * 32),
            self.params(refund_script_hash=b"c" * 32),
            self.params(asset_id=b"\0" * 32),
            self.params(amount=0),
        ):
            with self.assertRaises(formats.FormatError):
                formats.validate_inventory_htlc(bad)


class IssuanceReviewTests(unittest.TestCase):
    def test_canonical_and_ethereum_only(self):
        first = manifest()
        reverse = dict(reversed(list(first.items())))
        self.assertEqual(formats.canonical_issuance_review(first), formats.canonical_issuance_review(reverse))
        self.assertEqual(formats.issuance_review_digest(first), formats.issuance_review_digest(reverse))
        self.assertNotIn(b"tron", formats.canonical_issuance_review(first).lower())
        self.assertNotIn(b"shard", formats.canonical_issuance_review(first).lower())

    def test_rejects_drift(self):
        cases = []
        for field, value in (
            ("drivechain_slot", 23), ("usdt_decimals", 18), ("usdd_decimals", 6),
            ("usdd_units_per_usdt_micro", 1), ("max_mint_batch", 65),
        ):
            changed = manifest()
            changed[field] = value
            cases.append(changed)
        missing = manifest()
        del missing["controller_cmr"]
        cases.append(missing)
        extra = manifest()
        extra["tron_vault"] = "ff" * 20
        cases.append(extra)
        uppercase = manifest()
        uppercase["elements_genesis"] = "AA" * 32
        cases.append(uppercase)
        shallow_finality = manifest()
        shallow_finality["minimum_bitcoin_confirmations"] = 99
        cases.append(shallow_finality)
        for value in cases:
            with self.assertRaises(formats.FormatError):
                formats.validate_issuance_review(copy.deepcopy(value))


if __name__ == "__main__":
    unittest.main()
