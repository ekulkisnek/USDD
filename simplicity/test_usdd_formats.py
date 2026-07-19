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
    def controller_transaction(self):
        usdd = b"u" * 32
        token = b"t" * 32
        entropy = b"e" * 32
        current_script = b"c" * 32
        successor_script = b"s" * 32
        recipients = [
            formats.MintRecipient(20, 2, b"a" * 32),
            formats.MintRecipient(21, 3, b"b" * 32),
        ]
        inputs = [
            formats.ControllerTxInput(
                token,
                1,
                current_script,
                issuance_kind="reissuance",
                reissuance_entropy=entropy,
                issuance_asset_id=usdd,
                issuance_asset_amount=500,
            ),
            formats.ControllerTxInput(b"f" * 32, 10_000, b"x" * 32),
        ]
        outputs = [
            formats.ControllerTxOutput(token, 1, successor_script),
            formats.ControllerTxOutput(usdd, 200, b"a" * 32),
            formats.ControllerTxOutput(usdd, 300, b"b" * 32),
            formats.ControllerTxOutput(b"f" * 32, 9_000, b"z" * 32),
        ]
        arguments = {
            "current_controller_script_hash": current_script,
            "successor_controller_script_hash": successor_script,
            "usdd_asset_id": usdd,
            "reissuance_token_id": token,
            "reissuance_entropy": entropy,
            "expected_nonce": 20,
            "recipients": recipients,
        }
        return inputs, outputs, arguments

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

    def test_mint_batch_retains_transaction_explicit_value_headroom(self):
        half = formats.MAX_MINT_BATCH_USDT_MICRO // 2
        converted, total = formats.validate_mint_batch(20, [20, 21], [half, half])
        self.assertEqual(converted, [half * 100, half * 100])
        self.assertEqual(total, formats.MAX_MINT_BATCH_USDD_BASE)
        with self.assertRaises(formats.FormatError):
            formats.validate_mint_batch(20, [20, 21, 22], [half, half, 1])
        with self.assertRaises(formats.FormatError):
            formats.validate_mint_batch(
                20, [20], [formats.MAX_DEPOSIT_AMOUNT_USDT_MICRO + 1]
            )

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

    def test_controller_semantics_match_consensus_model(self):
        with self.assertRaises(formats.FormatError):
            formats.encode_controller_state(state(total_minted=1_001))
        bootstrap = state(
            sequence=0,
            next_mint_nonce=0,
            finalized_beacon_slot=0,
            finalized_beacon_root=b"\0" * 32,
            execution_root=b"\0" * 32,
            total_minted=0,
        )
        self.assertEqual(formats.decode_controller_state(formats.encode_controller_state(bootstrap)), bootstrap)
        with self.assertRaises(formats.FormatError):
            formats.encode_controller_state(dataclasses.replace(bootstrap, sequence=1))

    def test_bmm_freshness_uses_authenticated_environment_time(self):
        formats.validate_bmm_finality_freshness(1_700_000_000, 1_700_021_600)
        formats.validate_bmm_finality_freshness(1_700_000_000, 1_699_978_400)
        with self.assertRaises(formats.FormatError):
            formats.validate_bmm_finality_freshness(1_700_000_000, 1_700_021_601)

    def test_exact_controller_transaction_projection(self):
        inputs, outputs, arguments = self.controller_transaction()
        self.assertEqual(formats.validate_controller_transaction(inputs, outputs, **arguments), 500)

    def test_controller_transaction_enforces_elements_explicit_output_total(self):
        inputs, outputs, arguments = self.controller_transaction()
        oversized = [
            *outputs,
            formats.ControllerTxOutput(
                b"q" * 32,
                formats.ELEMENTS_MAX_EXPLICIT_OUTPUT_TOTAL_BASE,
                b"w" * 32,
            ),
        ]
        with self.assertRaises(formats.FormatError):
            formats.validate_controller_transaction(inputs, oversized, **arguments)

    def test_controller_transaction_rejects_hidden_or_extra_protocol_assets(self):
        inputs, outputs, arguments = self.controller_transaction()
        bad_cases = [
            ([dataclasses.replace(inputs[0], asset_explicit=False), *inputs[1:]], outputs),
            (inputs, [*outputs[:3], dataclasses.replace(outputs[3], asset_explicit=False)]),
            (inputs, [*outputs, formats.ControllerTxOutput(b"u" * 32, 1, b"q" * 32)]),
            (inputs, [*outputs, formats.ControllerTxOutput(b"t" * 32, 1, b"q" * 32)]),
            ([*inputs, formats.ControllerTxInput(b"u" * 32, 1, b"q" * 32)], outputs),
            ([*inputs, formats.ControllerTxInput(b"t" * 32, 1, b"q" * 32)], outputs),
        ]
        for bad_inputs, bad_outputs in bad_cases:
            with self.subTest(inputs=bad_inputs, outputs=bad_outputs), self.assertRaises(formats.FormatError):
                formats.validate_controller_transaction(bad_inputs, bad_outputs, **arguments)

    def test_controller_transaction_rejects_issuance_or_recipient_drift(self):
        inputs, outputs, arguments = self.controller_transaction()
        bad_inputs = [
            [dataclasses.replace(inputs[0], issuance_kind="new"), *inputs[1:]],
            [dataclasses.replace(inputs[0], reissuance_entropy=b"q" * 32), *inputs[1:]],
            [dataclasses.replace(inputs[0], issuance_asset_id=b"q" * 32), *inputs[1:]],
            [dataclasses.replace(inputs[0], issuance_asset_amount=499), *inputs[1:]],
            [dataclasses.replace(inputs[0], issuance_token_amount=1), *inputs[1:]],
            [inputs[0], dataclasses.replace(inputs[1], issuance_kind="reissuance", reissuance_entropy=b"e" * 32)],
        ]
        for changed in bad_inputs:
            with self.subTest(inputs=changed), self.assertRaises(formats.FormatError):
                formats.validate_controller_transaction(changed, outputs, **arguments)

        for changed in (
            [outputs[0], outputs[2], outputs[1], outputs[3]],
            [outputs[0], dataclasses.replace(outputs[1], amount=201), outputs[2], outputs[3]],
            [outputs[0], dataclasses.replace(outputs[1], script_hash=b"q" * 32), outputs[2], outputs[3]],
            [dataclasses.replace(outputs[0], amount=2), *outputs[1:]],
        ):
            with self.subTest(outputs=changed), self.assertRaises(formats.FormatError):
                formats.validate_controller_transaction(inputs, changed, **arguments)

    def test_heartbeat_transaction_has_no_monetary_branch(self):
        inputs, outputs, arguments = self.controller_transaction()
        heartbeat_input = dataclasses.replace(
            inputs[0],
            issuance_kind="none",
            reissuance_entropy=None,
            issuance_asset_id=None,
            issuance_asset_amount=0,
        )
        heartbeat_outputs = [outputs[0], outputs[3]]
        heartbeat_arguments = {**arguments, "recipients": [], "heartbeat": True}
        self.assertEqual(
            formats.validate_controller_transaction([heartbeat_input, inputs[1]], heartbeat_outputs, **heartbeat_arguments),
            0,
        )
        with self.assertRaises(formats.FormatError):
            formats.validate_controller_transaction(inputs, heartbeat_outputs, **heartbeat_arguments)
        with self.assertRaises(formats.FormatError):
            formats.validate_controller_transaction(
                [heartbeat_input, inputs[1]], heartbeat_outputs, **{**heartbeat_arguments, "recipients": arguments["recipients"]}
            )


class BurnTests(unittest.TestCase):
    def test_exact_script_and_round_trip(self):
        script = formats.encode_burn_script(b"v" * 32, b"r" * 20, 1_500_000)
        self.assertEqual(len(script), 67)
        self.assertEqual(script[:7], b"\x6a\x41USDD\x01")
        decoded = formats.decode_burn_script(script)
        self.assertEqual(decoded, formats.BurnData(b"v" * 32, b"r" * 20, 1_500_000))
        self.assertEqual(decoded.output_value_usdd8, 150_000_000)
        maximum = formats.MAX_MINT_BATCH_USDT_MICRO
        formats.encode_burn_script(b"v" * 32, b"r" * 20, maximum)
        with self.assertRaises(formats.FormatError):
            formats.encode_burn_script(b"v" * 32, b"r" * 20, maximum + 1)

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
            "claimant_xonly_pubkey": bytes.fromhex(
                "79be667ef9dcbbac55a06295ce870b070"
                "29bfcdb2dce28d959f2815b16f81798"
            ),
            "refund_xonly_pubkey": bytes.fromhex(
                "c6047f9441ed7d6d3045406e95c07cd8"
                "5c778e4b8cef3ca7abac09b95c709ee5"
            ),
            "asset_id": b"a" * 32,
            "amount": 100,
            "elements_refund_timestamp": 2_000_000_000,
            "external_refund_timestamp": 2_000_086_400,
        }
        values.update(changes)
        return formats.InventoryHtlcParameters(**values)

    def test_external_deadline_is_at_least_24h_later(self):
        formats.validate_inventory_htlc(self.params())
        with self.assertRaises(formats.FormatError):
            formats.validate_inventory_htlc(self.params(external_refund_timestamp=2_000_086_399))

    def test_fixed_nonzero_distinct_commitments(self):
        for bad in (
            self.params(secret_hash=b"\0" * 32),
            self.params(
                refund_xonly_pubkey=bytes.fromhex(
                    "79be667ef9dcbbac55a06295ce870b070"
                    "29bfcdb2dce28d959f2815b16f81798"
                )
            ),
            self.params(claimant_xonly_pubkey=b"\xff" * 32),
            self.params(asset_id=b"\0" * 32),
            self.params(amount=0),
            self.params(elements_refund_timestamp=499_999_999),
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
