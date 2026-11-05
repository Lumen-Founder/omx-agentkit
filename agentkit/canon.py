"""Canonical JSON and hashing shared by mandates, receipts and audit verification.

Canonical form is the one OMX's audit log uses (omx/audit.py `_canon`): keys
sorted, no whitespace, UTF-8, non-ASCII kept as is.
"""
from __future__ import annotations

import hashlib
import json
import re

FORBIDDEN_KEYS = frozenset({"private_key", "privatekey", "secret", "api_secret", "app_secret", "mnemonic",
                            "seed", "seed_phrase", "wallet_secret", "password", "key_material"})
_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_address(s) -> bool:
    return isinstance(s, str) and bool(_ADDR.match(s))


def secret_fields(obj, path: str = "$") -> list[str]:
    """Paths of dict keys named like secrets anywhere in obj (keys are refused, never read)."""
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}"
            if isinstance(k, str) and k.lower() in FORBIDDEN_KEYS:
                out.append(p)
            out.extend(secret_fields(v, p))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(secret_fields(v, f"{path}[{i}]"))
    return out
