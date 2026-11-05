"""Signer protocol and the HTTP seam the hosted-wallet adapters use."""
from __future__ import annotations

import json
from typing import Callable, Protocol, runtime_checkable


class SignerError(RuntimeError):
    pass


@runtime_checkable
class Signer(Protocol):
    def sign_typed_data(self, typed: dict) -> str:
        """EIP-712 typed data (domain, types incl. EIP712Domain, primaryType, message) -> 0x + 130 hex (r||s||v)."""
        ...

    def address(self) -> str:
        ...


class HttpTransport(Protocol):
    def __call__(self, method: str, url: str, headers: dict, body: bytes) -> tuple[int, dict]:
        """Send one request; return (status, parsed JSON)."""
        ...


# Callables the user wires to their own credentials (env var, OS keychain, provider SDK).
# They receive the exact request and return extra headers. This repo never sees secrets.
HeaderProvider = Callable[[str, str, bytes], dict]


class DisabledTransport:
    """Default transport: refuses to touch the network."""

    def __call__(self, method, url, headers, body):
        raise SignerError("network transport disabled: pass a transport explicitly (needs the user's account)")


def json_body(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def signature_hex(r, s, v) -> str:
    """r, s (hex with or without 0x, or int) and v (27/28, 0/1, or hex string) -> 0x r||s||v."""
    def as_int(x):
        if isinstance(x, int):
            return x
        x = x[2:] if x.startswith("0x") else x
        return int(x, 16)
    vi = as_int(v)
    if vi in (0, 1):
        vi += 27
    if vi not in (27, 28):
        raise SignerError(f"bad recovery id {v!r}")
    return "0x" + as_int(r).to_bytes(32, "big").hex() + as_int(s).to_bytes(32, "big").hex() + bytes([vi]).hex()


def check_sig(sig) -> str:
    if not isinstance(sig, str) or not sig.startswith("0x") or len(sig) != 132:
        raise SignerError("provider returned no 65-byte 0x signature")
    int(sig[2:], 16)
    return sig.lower()
