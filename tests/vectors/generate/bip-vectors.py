#!/usr/bin/env python3
"""Consolidates the official BIP-39, BIP-32 and SLIP-0010 test vectors into one JSON file.

The vectors are fetched from their normative upstreams rather than transcribed, because a
typo in a hand-copied constant produces a test that passes against the wrong answer, which is
worse than having no test at all.

Sources:
  BIP-39     trezor/python-mnemonic vectors.json (the reference vectors the BIP points to)
  BIP-32     bitcoin/bips bip-0032.mediawiki, the four seed-based test vectors
  SLIP-0010  satoshilabs/slips slip-0010.md, the ed25519 vectors

Run:  python3 bip-vectors.py

Requires network access and, for BIP-32, the `gh` CLI (raw.githubusercontent.com rate-limits
the bips repository). Output is committed, so this only needs re-running if an upstream vector
set changes, which for finalised BIPs should be never.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "bip-derivation.json"

BIP39_URL = "https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json"
SLIP10_URL = "https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0010.md"
BIP32_REPO_PATH = "repos/bitcoin/bips/contents/bip-0032.mediawiki"

# Base58 alphabet, for decoding the xprv/xpub in the BIP-32 vectors.
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8")


def fetch_via_gh(api_path: str) -> str:
    import base64

    result = subprocess.run(
        ["gh", "api", api_path, "--jq", ".content"],
        capture_output=True,
        text=True,
        check=True,
    )
    return base64.b64decode(result.stdout).decode("utf-8")


def b58decode(text: str) -> bytes:
    number = 0
    for char in text:
        number = number * 58 + B58.index(char)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    leading = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading + body


def split_extended_key(serialised: str) -> dict:
    """Pulls the fields out of a serialised BIP-32 key.

    Avoids having to implement xprv serialisation in the kernel just to run this test. The
    kernel exposes the private key, chain code and public key, which is what gets asserted.
    """
    raw = b58decode(serialised)
    payload, checksum = raw[:-4], raw[-4:]

    import hashlib

    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        raise ValueError(f"bad checksum on {serialised}")
    if len(payload) != 78:
        raise ValueError(f"unexpected length {len(payload)} for {serialised}")

    version = payload[0:4]
    depth = payload[4]
    parent_fingerprint = payload[5:9]
    child_number = int.from_bytes(payload[9:13], "big")
    chain_code = payload[13:45]
    key_data = payload[45:78]

    entry = {
        "depth": depth,
        "parent_fingerprint": parent_fingerprint.hex(),
        "child_number": child_number,
        "chain_code_hex": chain_code.hex(),
    }
    if version.hex() == "0488ade4":  # xprv
        if key_data[0] != 0:
            raise ValueError("private key must be zero padded")
        entry["private_key_hex"] = key_data[1:].hex()
    elif version.hex() == "0488b21e":  # xpub
        entry["public_key_hex"] = key_data.hex()
    else:
        raise ValueError(f"unknown version {version.hex()}")
    return entry


def parse_bip32(text: str) -> list[dict]:
    """Reads the ``===Test vector N===`` sections into chains of derived keys."""
    vectors: list[dict] = []
    current: dict | None = None
    chain: str | None = None

    for line in text.splitlines():
        line = line.strip()

        heading = re.match(r"^===\s*Test vector (\d+)\s*===$", line)
        if heading:
            current = {"name": f"bip32_vector_{heading.group(1)}", "seed_hex": "", "chains": []}
            vectors.append(current)
            chain = None
            continue

        if current is None:
            continue

        seed = re.match(r"^Seed \(hex\):\s*([0-9a-fA-F]+)$", line)
        if seed:
            current["seed_hex"] = seed.group(1).lower()
            continue

        chain_line = re.match(r"^\*\s*Chain (.+)$", line)
        if chain_line:
            # ``m/0<sub>H</sub>/1`` is the wiki's way of writing ``m/0'/1``.
            path = chain_line.group(1).replace("<sub>H</sub>", "'").strip()
            chain = path
            current["chains"].append({"path": path})
            continue

        key_line = re.match(r"^\*\*\s*ext (pub|prv):\s*(\w+)$", line)
        if key_line and chain is not None:
            current["chains"][-1].update(split_extended_key(key_line.group(2)))
            continue

    complete = [v for v in vectors if v["seed_hex"] and v["chains"]]
    for vector in complete:
        for entry in vector["chains"]:
            missing = {"private_key_hex", "public_key_hex", "chain_code_hex"} - entry.keys()
            if missing:
                raise ValueError(f"{vector['name']} {entry.get('path')} missing {missing}")
    return complete


def parse_slip10(text: str) -> list[dict]:
    """Reads the ed25519 sections of slip-0010.md.

    Only ed25519 is taken: secp256k1 SLIP-0010 derivation is identical to BIP-32, which the
    BIP-32 vectors already cover, and the kernel does not implement curve25519.
    """
    vectors: list[dict] = []
    current: dict | None = None
    entry: dict | None = None
    in_ed25519 = False

    for line in text.splitlines():
        stripped = line.strip()

        heading = re.match(r"^###\s*Test vector (\d+) for (\S+)$", stripped)
        if heading:
            in_ed25519 = heading.group(2) == "ed25519"
            current = None
            if in_ed25519:
                current = {
                    "name": f"slip10_ed25519_vector_{heading.group(1)}",
                    "seed_hex": "",
                    "chains": [],
                }
                vectors.append(current)
            continue

        if not in_ed25519 or current is None:
            continue

        seed = re.match(r"^Seed \(hex\):\s*([0-9a-fA-F]+)$", stripped)
        if seed:
            current["seed_hex"] = seed.group(1).lower()
            continue

        chain_line = re.match(r"^\*\s*Chain (.+)$", stripped)
        if chain_line:
            path = chain_line.group(1).replace("<sub>H</sub>", "'").strip()
            entry = {"path": path}
            current["chains"].append(entry)
            continue

        field = re.match(r"^\*\s*(chain code|private|public|fingerprint):\s*([0-9a-fA-F]+)$", stripped)
        if field and entry is not None:
            key, value = field.group(1), field.group(2).lower()
            if key == "chain code":
                entry["chain_code_hex"] = value
            elif key == "private":
                entry["private_key_hex"] = value
            elif key == "public":
                # SLIP-0010 prefixes ed25519 public keys with a 0x00 byte. The raw 32-byte
                # key is what the kernel returns, so strip it here rather than in the test.
                if not value.startswith("00"):
                    raise ValueError(f"expected 0x00-prefixed ed25519 pubkey, got {value}")
                entry["public_key_hex"] = value[2:]
            else:
                entry["parent_fingerprint"] = value
            continue

    return [v for v in vectors if v["seed_hex"] and v["chains"]]


def main() -> int:
    print(f"fetching BIP-39 vectors from {BIP39_URL}")
    bip39_all = json.loads(fetch(BIP39_URL))
    bip39 = [
        {
            "entropy_hex": entropy,
            "mnemonic": mnemonic,
            "seed_hex": seed,
            "xprv": xprv,
        }
        for entropy, mnemonic, seed, xprv in bip39_all["english"]
    ]
    print(f"  {len(bip39)} English cases")

    print(f"fetching BIP-32 vectors via gh from {BIP32_REPO_PATH}")
    bip32 = parse_bip32(fetch_via_gh(BIP32_REPO_PATH))
    print(f"  {len(bip32)} vectors, {sum(len(v['chains']) for v in bip32)} derived keys")

    print(f"fetching SLIP-0010 vectors from {SLIP10_URL}")
    slip10 = parse_slip10(fetch(SLIP10_URL))
    print(f"  {len(slip10)} vectors, {sum(len(v['chains']) for v in slip10)} derived keys")

    # BIP-32 numbers five test vectors, but the fifth is a list of invalid serialised keys
    # rather than a derivation chain, so four is the complete set here.
    if len(bip39) < 24 or len(bip32) < 4 or len(slip10) < 2:
        print("upstream returned fewer vectors than expected, refusing to write", file=sys.stderr)
        return 1

    output = {
        "_comment": (
            "Official BIP-39, BIP-32 and SLIP-0010 test vectors, fetched from their normative "
            "upstreams by tests/vectors/generate/bip-vectors.py. Do not edit by hand."
        ),
        "sources": {
            "bip39": BIP39_URL,
            "bip32": "https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki",
            "slip10": SLIP10_URL,
        },
        "bip39": {
            "passphrase": "TREZOR",
            "note": "The reference vectors all use the passphrase TREZOR.",
            "cases": bip39,
        },
        "bip32": bip32,
        "slip10_ed25519": slip10,
    }

    OUT.write_text(json.dumps(output, indent=2) + "\n")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
