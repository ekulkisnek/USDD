#!/usr/bin/env python3
"""Strict USDD Elements V1 format helpers; no cryptographic proof verifier."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import struct
from pathlib import Path
from typing import Any, Mapping, Sequence


ANNEX_TAG = 0x50
SP1_MAGIC = b"USDDSP1\x00"
SP1_HEADER_SIZE = 55
SP1_MAX_SIZE = 512 * 1024
SP1_PUBLIC_VALUES_MAX_SIZE = 16 * 1024
ETH_STATE_V1 = 1

USDD_UNITS_PER_USDT_MICRO = 100
MAX_MINT_BATCH = 64

BURN_MAGIC = b"USDD"
BURN_DATA_SIZE = 65
BURN_SCRIPT_SIZE = 67
BURN_ID_DOMAIN = hashlib.sha256(b"USDD_BURN_ID_V1").digest()
BURN_TREE_DEPTH = 64

CONTROLLER_STATE_SIZE = 164
MIN_HTLC_DEADLINE_GAP = 24 * 60 * 60


class FormatError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class Sp1Annex:
    guest_vkey_hash: bytes
    public_values: bytes
    proof: bytes


@dataclasses.dataclass(frozen=True)
class ControllerState:
    version: int
    sequence: int
    next_mint_nonce: int
    eth_light_client_digest: bytes
    finalized_beacon_slot: int
    finalized_beacon_root: bytes
    execution_root: bytes
    total_minted: int
    config_hash: bytes


@dataclasses.dataclass(frozen=True)
class BurnData:
    vault_id: bytes
    ethereum_recipient: bytes
    amount_usdt6: int

    @property
    def output_value_usdd8(self) -> int:
        return usdt6_to_usdd8(self.amount_usdt6)


@dataclasses.dataclass(frozen=True)
class InventoryHtlcParameters:
    secret_hash: bytes
    claimant_script_hash: bytes
    refund_script_hash: bytes
    asset_id: bytes
    amount: int
    elements_refund_deadline: int
    external_refund_deadline: int


def _bytes(name: str, value: bytes, length: int | None = None, *, nonzero: bool = False) -> bytes:
    if not isinstance(value, bytes):
        raise FormatError(f"{name} must be bytes")
    if length is not None and len(value) != length:
        raise FormatError(f"{name} must be exactly {length} bytes")
    if nonzero and not any(value):
        raise FormatError(f"{name} must not be zero")
    return value


def _uint(name: str, value: int, bits: int, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if type(value) is not int or value < minimum or value > (1 << bits) - 1:
        raise FormatError(f"{name} must be {'positive ' if positive else ''}u{bits}")
    return value


def usdt6_to_usdd8(amount_usdt6: int) -> int:
    _uint("amount_usdt6", amount_usdt6, 64, positive=True)
    amount_usdd8 = amount_usdt6 * USDD_UNITS_PER_USDT_MICRO
    if amount_usdd8 > 0xFFFFFFFFFFFFFFFF:
        raise FormatError("USDT6 to USDD8 multiplication overflows u64")
    return amount_usdd8


def validate_mint_batch(expected_nonce: int, nonces: Sequence[int], amounts_usdt6: Sequence[int]) -> tuple[list[int], int]:
    _uint("expected_nonce", expected_nonce, 64)
    if len(nonces) != len(amounts_usdt6) or not 1 <= len(nonces) <= MAX_MINT_BATCH:
        raise FormatError("mint batch must contain 1..64 nonce/amount pairs")
    converted: list[int] = []
    total = 0
    for index, (nonce, amount) in enumerate(zip(nonces, amounts_usdt6)):
        _uint("nonce", nonce, 64)
        expected = expected_nonce + index
        if expected > 0xFFFFFFFFFFFFFFFF or nonce != expected:
            raise FormatError("mint nonces must be consecutive from nextMintNonce")
        converted_amount = usdt6_to_usdd8(amount)
        total += converted_amount
        if total > 0xFFFFFFFFFFFFFFFF:
            raise FormatError("mint batch sum overflows u64")
        converted.append(converted_amount)
    return converted, total


def encode_sp1_annex(guest_vkey_hash: bytes, public_values: bytes, proof: bytes) -> bytes:
    guest_vkey_hash = _bytes("guest_vkey_hash", guest_vkey_hash, 32, nonzero=True)
    public_values = _bytes("public_values", public_values)
    proof = _bytes("proof", proof)
    if not public_values or len(public_values) > SP1_PUBLIC_VALUES_MAX_SIZE:
        raise FormatError("public_values length must be 1..16 KiB")
    if not proof:
        raise FormatError("proof must not be empty")
    if SP1_HEADER_SIZE + len(public_values) + len(proof) > SP1_MAX_SIZE:
        raise FormatError("annex exceeds 512 KiB")
    header = bytes([ANNEX_TAG]) + SP1_MAGIC + struct.pack(
        ">BBBBHII32s", 1, 1, ETH_STATE_V1, 1, 0, len(public_values), len(proof), guest_vkey_hash
    )
    assert len(header) == SP1_HEADER_SIZE
    return header + public_values + proof


def decode_sp1_annex(data: bytes) -> Sp1Annex:
    data = _bytes("annex", data)
    if len(data) < 5 or data[:5] != bytes([ANNEX_TAG]) + b"USDD":
        raise FormatError("not a USDD annex")
    if len(data) > SP1_MAX_SIZE:
        raise FormatError("annex exceeds 512 KiB")
    if len(data) < SP1_HEADER_SIZE:
        raise FormatError("truncated annex")
    if data[1:9] != SP1_MAGIC:
        raise FormatError("bad annex magic")
    version, proof_system, statement, digest, flags, public_len, proof_len, vkey = struct.unpack_from(
        ">BBBBHII32s", data, 9
    )
    if version != 1 or proof_system != 1 or statement != ETH_STATE_V1 or digest != 1 or flags != 0:
        raise FormatError("unsupported annex header")
    if public_len == 0 or public_len > SP1_PUBLIC_VALUES_MAX_SIZE or proof_len == 0:
        raise FormatError("invalid annex field length")
    _bytes("guest_vkey_hash", vkey, 32, nonzero=True)
    if SP1_HEADER_SIZE + public_len + proof_len != len(data):
        raise FormatError("declared lengths do not exactly match annex")
    public_end = SP1_HEADER_SIZE + public_len
    return Sp1Annex(vkey, data[SP1_HEADER_SIZE:public_end], data[public_end:])


_CONTROLLER_STRUCT = struct.Struct(">IQQ32sQ32s32sQ32s")


def validate_controller_state(state: ControllerState) -> None:
    if state.version != 1:
        raise FormatError("controller version must be 1")
    _uint("sequence", state.sequence, 64)
    _uint("next_mint_nonce", state.next_mint_nonce, 64)
    _bytes("eth_light_client_digest", state.eth_light_client_digest, 32, nonzero=True)
    _uint("finalized_beacon_slot", state.finalized_beacon_slot, 64)
    _bytes("finalized_beacon_root", state.finalized_beacon_root, 32, nonzero=True)
    _bytes("execution_root", state.execution_root, 32, nonzero=True)
    _uint("total_minted", state.total_minted, 64)
    _bytes("config_hash", state.config_hash, 32, nonzero=True)


def encode_controller_state(state: ControllerState) -> bytes:
    validate_controller_state(state)
    encoded = _CONTROLLER_STRUCT.pack(
        state.version,
        state.sequence,
        state.next_mint_nonce,
        state.eth_light_client_digest,
        state.finalized_beacon_slot,
        state.finalized_beacon_root,
        state.execution_root,
        state.total_minted,
        state.config_hash,
    )
    assert len(encoded) == CONTROLLER_STATE_SIZE
    return encoded


def decode_controller_state(data: bytes) -> ControllerState:
    data = _bytes("controller state", data, CONTROLLER_STATE_SIZE)
    state = ControllerState(*_CONTROLLER_STRUCT.unpack(data))
    validate_controller_state(state)
    return state


def validate_controller_transition(
    current: ControllerState,
    proposed: ControllerState,
    nonces: Sequence[int],
    amounts_usdt6: Sequence[int],
) -> int:
    validate_controller_state(current)
    validate_controller_state(proposed)
    _, batch_total = validate_mint_batch(current.next_mint_nonce, nonces, amounts_usdt6)
    if current.sequence == 0xFFFFFFFFFFFFFFFF or proposed.sequence != current.sequence + 1:
        raise FormatError("controller sequence must advance exactly once")
    next_nonce = current.next_mint_nonce + len(nonces)
    if next_nonce > 0xFFFFFFFFFFFFFFFF or proposed.next_mint_nonce != next_nonce:
        raise FormatError("nextMintNonce does not match batch")
    next_total = current.total_minted + batch_total
    if next_total > 0xFFFFFFFFFFFFFFFF or proposed.total_minted != next_total:
        raise FormatError("totalMinted does not match batch")
    if proposed.version != current.version or proposed.config_hash != current.config_hash:
        raise FormatError("immutable controller field changed")
    if proposed.finalized_beacon_slot < current.finalized_beacon_slot:
        raise FormatError("finalized beacon slot decreased")
    return batch_total


def validate_heartbeat_transition(current: ControllerState, proposed: ControllerState) -> None:
    validate_controller_state(current)
    validate_controller_state(proposed)
    if current.sequence == 0xFFFFFFFFFFFFFFFF or proposed.sequence != current.sequence + 1:
        raise FormatError("heartbeat sequence must advance exactly once")
    if proposed.next_mint_nonce != current.next_mint_nonce or proposed.total_minted != current.total_minted:
        raise FormatError("heartbeat cannot consume a nonce or change totalMinted")
    if proposed.version != current.version or proposed.config_hash != current.config_hash:
        raise FormatError("heartbeat changed an immutable controller field")
    if proposed.finalized_beacon_slot <= current.finalized_beacon_slot:
        raise FormatError("heartbeat must prove a strictly newer finalized beacon slot")
    if proposed.eth_light_client_digest == current.eth_light_client_digest:
        raise FormatError("heartbeat must update the Ethereum light-client digest")


def encode_burn_data(vault_id: bytes, ethereum_recipient: bytes, amount_usdt6: int) -> bytes:
    vault_id = _bytes("vault_id", vault_id, 32, nonzero=True)
    ethereum_recipient = _bytes("ethereum_recipient", ethereum_recipient, 20, nonzero=True)
    usdt6_to_usdd8(amount_usdt6)
    data = struct.pack(">4sB32s20sQ", BURN_MAGIC, 1, vault_id, ethereum_recipient, amount_usdt6)
    assert len(data) == BURN_DATA_SIZE
    return data


def decode_burn_data(data: bytes) -> BurnData:
    data = _bytes("burn data", data, BURN_DATA_SIZE)
    magic, version, vault, recipient, amount = struct.unpack(">4sB32s20sQ", data)
    if magic != BURN_MAGIC or version != 1:
        raise FormatError("invalid burn magic/version")
    _bytes("vault_id", vault, 32, nonzero=True)
    _bytes("ethereum_recipient", recipient, 20, nonzero=True)
    usdt6_to_usdd8(amount)
    return BurnData(vault, recipient, amount)


def encode_burn_script(vault_id: bytes, ethereum_recipient: bytes, amount_usdt6: int) -> bytes:
    return b"\x6a\x41" + encode_burn_data(vault_id, ethereum_recipient, amount_usdt6)


def decode_burn_script(script: bytes) -> BurnData:
    script = _bytes("burn script", script, BURN_SCRIPT_SIZE)
    if script[:2] != b"\x6a\x41":
        raise FormatError("burn script must use minimal OP_RETURN direct push 0x41")
    return decode_burn_data(script[2:])


def burn_id(elements_genesis: bytes, txid_display: bytes, vout: int) -> bytes:
    elements_genesis = _bytes("elements_genesis", elements_genesis, 32, nonzero=True)
    # Canonical RPC/display hex decoded left-to-right. Convert internal uint256
    # or consensus-serialization order before calling this boundary.
    txid_display = _bytes("txid_display", txid_display, 32, nonzero=True)
    _uint("vout", vout, 32)
    return hashlib.sha256(BURN_ID_DOMAIN + elements_genesis + txid_display + struct.pack(">I", vout)).digest()


def burn_empty_roots() -> tuple[bytes, ...]:
    """Return EMPTY[0] through EMPTY[64] for the fixed burn tree."""
    roots = [hashlib.sha256(b"\x00").digest()]
    for _ in range(BURN_TREE_DEPTH):
        roots.append(hashlib.sha256(b"\x01" + roots[-1] + roots[-1]).digest())
    return tuple(roots)


def validate_burn_append(previous_burn_count: int, appended_indices: Sequence[int], next_burn_count: int) -> None:
    """Check the contiguous-prefix index rule; this does not validate leaves."""
    _uint("previous_burn_count", previous_burn_count, 64)
    _uint("next_burn_count", next_burn_count, 64)
    if next_burn_count < previous_burn_count or len(appended_indices) != next_burn_count - previous_burn_count:
        raise FormatError("burns must append exactly at the contiguous prefix")
    for offset, index in enumerate(appended_indices):
        if index != previous_burn_count + offset:
            raise FormatError("burns must append exactly at the contiguous prefix")


def validate_inventory_htlc(params: InventoryHtlcParameters) -> None:
    _bytes("secret_hash", params.secret_hash, 32, nonzero=True)
    _bytes("claimant_script_hash", params.claimant_script_hash, 32, nonzero=True)
    _bytes("refund_script_hash", params.refund_script_hash, 32, nonzero=True)
    if params.claimant_script_hash == params.refund_script_hash:
        raise FormatError("claimant and refund scripts must differ")
    _bytes("asset_id", params.asset_id, 32, nonzero=True)
    _uint("amount", params.amount, 64, positive=True)
    _uint("elements_refund_deadline", params.elements_refund_deadline, 32, positive=True)
    _uint("external_refund_deadline", params.external_refund_deadline, 64, positive=True)
    if params.external_refund_deadline < params.elements_refund_deadline + MIN_HTLC_DEADLINE_GAP:
        raise FormatError("external refund deadline must be at least 24 hours later")


ISSUANCE_REVIEW_KEYS = frozenset(
    {
        "protocol", "version", "ethereum_chain_id", "ethereum_genesis", "bitcoin_genesis",
        "elements_genesis", "drivechain_slot", "usdt", "vault", "vault_code_hash",
        "usdd_asset_id", "reissuance_token_id", "issuance_txid", "issuance_vout",
        "asset_entropy", "controller_cmr", "controller_initial_state_hash",
        "ethereum_guest_program_id", "elements_guest_program_id", "minimum_bitcoin_confirmations",
        "first_mint_nonce", "usdt_decimals", "usdd_decimals", "usdd_units_per_usdt_micro",
        "max_mint_batch",
    }
)
_HEX32 = (
    "ethereum_genesis", "bitcoin_genesis", "elements_genesis", "vault_code_hash",
    "usdd_asset_id", "reissuance_token_id", "issuance_txid", "asset_entropy", "controller_cmr",
    "controller_initial_state_hash", "ethereum_guest_program_id", "elements_guest_program_id",
)
_HEX20 = ("usdt", "vault")


def _lower_hex(manifest: Mapping[str, Any], field: str, size: int) -> None:
    value = manifest[field]
    if not isinstance(value, str) or len(value) != size * 2 or value != value.lower():
        raise FormatError(f"{field} must be {size}-byte lowercase hex")
    if any(char not in "0123456789abcdef" for char in value) or int(value, 16) == 0:
        raise FormatError(f"{field} must be nonzero lowercase hex")


def validate_issuance_review(record: Mapping[str, Any]) -> None:
    if not isinstance(record, Mapping) or frozenset(record.keys()) != ISSUANCE_REVIEW_KEYS:
        raise FormatError("issuance review has missing or extra fields")
    if record["protocol"] != "USDD" or record["version"] != 1 or type(record["version"]) is not int:
        raise FormatError("protocol/version must be USDD/1")
    fixed = {
        "drivechain_slot": 24,
        "usdt_decimals": 6,
        "usdd_decimals": 8,
        "usdd_units_per_usdt_micro": 100,
        "max_mint_batch": 64,
    }
    for field, expected in fixed.items():
        if type(record[field]) is not int or record[field] != expected:
            raise FormatError(f"{field} must be {expected}")
    _uint("ethereum_chain_id", record["ethereum_chain_id"], 64, positive=True)
    _uint("issuance_vout", record["issuance_vout"], 32)
    _uint("minimum_bitcoin_confirmations", record["minimum_bitcoin_confirmations"], 32, positive=True)
    if record["minimum_bitcoin_confirmations"] < 100:
        raise FormatError("minimum_bitcoin_confirmations must be at least 100")
    _uint("first_mint_nonce", record["first_mint_nonce"], 64)
    for field in _HEX32:
        _lower_hex(record, field, 32)
    for field in _HEX20:
        _lower_hex(record, field, 20)


def canonical_issuance_review(record: Mapping[str, Any]) -> bytes:
    """Non-consensus review bytes; never a protocol configHash."""
    validate_issuance_review(record)
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def issuance_review_digest(record: Mapping[str, Any]) -> bytes:
    return hashlib.sha256(canonical_issuance_review(record)).digest()


def _hex(name: str, value: str, size: int | None = None) -> bytes:
    if value.startswith(("0x", "0X")):
        raise FormatError(f"{name} must be unprefixed hex")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise FormatError(f"{name} must be even-length hex") from exc
    if len(value) != len(result) * 2:
        raise FormatError(f"{name} must be even-length hex")
    return _bytes(name, result, size)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    enc = commands.add_parser("burn-encode")
    enc.add_argument("--vault-id", required=True)
    enc.add_argument("--recipient", required=True)
    enc.add_argument("--amount-usdt6", type=int, required=True)
    dec = commands.add_parser("burn-decode")
    dec.add_argument("script_hex")
    bid = commands.add_parser("burn-id")
    bid.add_argument("--elements-genesis", required=True)
    bid.add_argument("--txid-display", required=True, help="canonical RPC/display txid hex")
    bid.add_argument("--vout", type=int, required=True)
    review = commands.add_parser("issuance-review", help="non-consensus bootstrap review subset")
    review.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "burn-encode":
            print(encode_burn_script(_hex("vault_id", args.vault_id, 32), _hex("recipient", args.recipient, 20), args.amount_usdt6).hex())
        elif args.command == "burn-decode":
            decoded = decode_burn_script(_hex("burn script", args.script_hex))
            print(json.dumps({"amount_usdt6": decoded.amount_usdt6, "output_value_usdd8": decoded.output_value_usdd8,
                              "recipient": decoded.ethereum_recipient.hex(), "vault_id": decoded.vault_id.hex()}, sort_keys=True))
        elif args.command == "burn-id":
            print(burn_id(_hex("elements_genesis", args.elements_genesis, 32), _hex("txid_display", args.txid_display, 32), args.vout).hex())
        elif args.command == "issuance-review":
            value = json.loads(args.path.read_text(encoding="utf-8"))
            canonical = canonical_issuance_review(value)
            print(json.dumps({"canonical_review_json": canonical.decode(), "review_digest": hashlib.sha256(canonical).hexdigest(),
                              "warning": "not protocol configHash"}, sort_keys=True))
    except (FormatError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
