#!/usr/bin/env python3
"""Render and optionally syntax-check the source-only inventory HTLC template."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile


EXPECTED_SIMPLICITYHL_COMMIT = "f62adf11e16816dd8f33f16edb5ff9f4c4b45e36"
EXPECTED_SIMPLICITYHL_VERSION = "0.6.0"
LOCKTIME_TIMESTAMP_THRESHOLD = 500_000_000
MINIMUM_DEADLINE_GAP_SECONDS = 86_400
SECP256K1_FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
TOKEN_RE = re.compile(r"@[A-Z0-9_]+@")


def parse_bytes32(name: str, value: str, *, nonzero: bool = True) -> str:
    if value.startswith("0x"):
        value = value[2:]
    if len(value) != 64 or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError(f"{name} must be exactly 32 hexadecimal bytes")
    canonical = value.lower()
    if nonzero and int(canonical, 16) == 0:
        raise ValueError(f"{name} must be nonzero")
    return canonical


def parse_xonly_pubkey(name: str, value: str) -> str:
    canonical = parse_bytes32(name, value)
    x = int(canonical, 16)
    if x >= SECP256K1_FIELD_PRIME:
        raise ValueError(f"{name} is outside the secp256k1 field")
    # An x-only public key is valid iff x^3 + 7 has a square root in the field.
    y_squared = (pow(x, 3, SECP256K1_FIELD_PRIME) + 7) % SECP256K1_FIELD_PRIME
    y = pow(y_squared, (SECP256K1_FIELD_PRIME + 1) // 4, SECP256K1_FIELD_PRIME)
    if pow(y, 2, SECP256K1_FIELD_PRIME) != y_squared:
        raise ValueError(f"{name} is not a valid secp256k1 x-only public key")
    return canonical


def render(
    template: str,
    *,
    secret_hash: str,
    claimant_xonly_pubkey: str,
    refund_xonly_pubkey: str,
    elements_refund_timestamp: int,
    external_refund_timestamp: int,
) -> str:
    secret_hash = parse_bytes32("secret hash", secret_hash)
    claimant_xonly_pubkey = parse_xonly_pubkey(
        "claimant x-only public key", claimant_xonly_pubkey
    )
    refund_xonly_pubkey = parse_xonly_pubkey(
        "refund x-only public key", refund_xonly_pubkey
    )
    if claimant_xonly_pubkey == refund_xonly_pubkey:
        raise ValueError("claimant and refund x-only public keys must be distinct")
    if not LOCKTIME_TIMESTAMP_THRESHOLD <= elements_refund_timestamp <= 0xFFFFFFFF:
        raise ValueError("Elements refund timestamp must be a u32 absolute timestamp")
    if not 0 <= external_refund_timestamp <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("external refund timestamp must be a u64")
    if external_refund_timestamp <= elements_refund_timestamp:
        raise ValueError("Elements refund timestamp must be strictly before external refund")
    gap = external_refund_timestamp - elements_refund_timestamp
    if gap < MINIMUM_DEADLINE_GAP_SECONDS:
        raise ValueError("external refund must be at least 86,400 seconds later")

    replacements = {
        "@SECRET_HASH@": secret_hash,
        "@CLAIMANT_XONLY_PUBKEY@": claimant_xonly_pubkey,
        "@REFUND_XONLY_PUBKEY@": refund_xonly_pubkey,
        "@ELEMENTS_REFUND_TIMESTAMP@": str(elements_refund_timestamp),
    }
    rendered = template
    for token, value in replacements.items():
        if rendered.count(token) != 1:
            raise ValueError(f"template must contain {token} exactly once")
        rendered = rendered.replace(token, value)
    unresolved = TOKEN_RE.findall(rendered)
    if unresolved:
        raise ValueError(f"unresolved template tokens: {', '.join(unresolved)}")
    return rendered


def checkout_version(checkout: pathlib.Path) -> tuple[str, str]:
    commit = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if status:
        raise ValueError("SimplicityHL checkout must be clean")
    cargo_toml = (checkout / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', cargo_toml, re.MULTILINE)
    if match is None:
        raise ValueError("cannot read SimplicityHL package version")
    return commit, match.group(1)


def compiler_check(rendered: str, checkout: pathlib.Path) -> None:
    commit, version = checkout_version(checkout)
    if commit != EXPECTED_SIMPLICITYHL_COMMIT or version != EXPECTED_SIMPLICITYHL_VERSION:
        raise ValueError(
            "SimplicityHL checkout identity mismatch: "
            f"got {commit} v{version}, expected "
            f"{EXPECTED_SIMPLICITYHL_COMMIT} v{EXPECTED_SIMPLICITYHL_VERSION}"
        )
    with tempfile.TemporaryDirectory(prefix="usdd-inventory-htlc-") as directory:
        source = pathlib.Path(directory) / "inventory_htlc_v1.simf"
        source.write_text(rendered, encoding="utf-8")
        # Discard the encoded program deliberately. Syntax checking is not proof
        # that this compiler's jet encoding is accepted by the Elements fork.
        subprocess.run(
            [
                "cargo",
                "run",
                "--locked",
                "--quiet",
                "--manifest-path",
                str(checkout / "Cargo.toml"),
                "--bin",
                "simc",
                "--",
                str(source),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secret-hash", required=True)
    parser.add_argument("--claimant-xonly-pubkey", required=True)
    parser.add_argument("--refund-xonly-pubkey", required=True)
    parser.add_argument("--elements-refund-timestamp", required=True, type=int)
    parser.add_argument("--external-refund-timestamp", required=True, type=int)
    parser.add_argument("--check-with-simplicityhl", type=pathlib.Path)
    args = parser.parse_args()

    template_path = pathlib.Path(__file__).with_name("inventory_htlc_v1.simf.in")
    try:
        rendered = render(
            template_path.read_text(encoding="utf-8"),
            secret_hash=args.secret_hash,
            claimant_xonly_pubkey=args.claimant_xonly_pubkey,
            refund_xonly_pubkey=args.refund_xonly_pubkey,
            elements_refund_timestamp=args.elements_refund_timestamp,
            external_refund_timestamp=args.external_refund_timestamp,
        )
        if args.check_with_simplicityhl is not None:
            compiler_check(rendered, args.check_with_simplicityhl.resolve())
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
