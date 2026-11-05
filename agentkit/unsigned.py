"""Unsigned Hyperliquid L1 actions for an external signer (D2).

Mirrors hyperliquid-python-sdk 0.20.0 exactly:
- order wire  (utils/signing.py order_request_to_order_wire): keys a, b, p, s, r, t, c in that order;
- order action (order_wires_to_order_action): {"type": "order", "orders": [...], "grouping": "na",
  "builder": {"b": lowercase address, "f": tenths of a bps}}; Exchange.bulk_orders lowercases b;
- cancel action (Exchange.bulk_cancel): {"type": "cancel", "cancels": [{"a": asset, "o": oid}]};
  cancel by cloid (bulk_cancel_by_cloid): {"type": "cancelByCloid", "cancels": [{"asset", "cloid"}]};
- action hash (action_hash): keccak256( msgpack(action) || nonce u64 BE || vault flag
  (0x00, or 0x01 + 20 address bytes) || [0x00 || expiresAfter u64 BE when expiresAfter is set] );
- phantom agent (construct_phantom_agent): {"source": "a" mainnet / "b" testnet, "connectionId": hash};
- typed data (l1_payload): domain {name "Exchange", version "1", chainId 1337, verifyingContract 0x0},
  primaryType "Agent", types Agent[source string, connectionId bytes32] + EIP712Domain;
- exchange payload (Exchange._post_action): {"action", "nonce", "signature" {r, s, v}, "vaultAddress",
  "expiresAfter"}, signature r/s as eth_utils.to_hex(int) (no zero padding), v 27/28.

msgpack hashes the dict in insertion order, so actions must keep the key order
above; JSON round trips (json.loads) keep it. Asset ids, size decimals and
rounding are inputs: nothing here reads the network.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_EVEN, Decimal
from typing import Optional

import msgpack
from eth_utils import keccak, to_hex

from .canon import is_address
from .mandate import AccountView, Decision, MandateBlocked, MarketView, OrderSpec, check

CHAIN_ID = 1337
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
PERP_MAX_TENTHS_BPS = 100            # 0.1 % venue cap for perps
SPOT_MAX_TENTHS_BPS = 1000           # 1 % venue cap for spot
SPOT_ASSET_OFFSET = 10_000
TIFS = ("Gtc", "Ioc", "Alo")
_CLOID = re.compile(r"^0x[0-9a-f]{32}$")
EIP712_DOMAIN_TYPES = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
AGENT_TYPES = [{"name": "source", "type": "string"}, {"name": "connectionId", "type": "bytes32"}]


class BuildError(ValueError):
    pass


# ------------------------------------------------------------------ wire helpers

def wire_str(d) -> str:
    """Same text as the SDK's float_to_wire: no exponent, no trailing zeros."""
    s = f"{Decimal(str(d)).normalize():f}"
    return "0" if s in ("-0", "") else s


_MODES = {"nearest": ROUND_HALF_EVEN, "down": ROUND_FLOOR, "up": ROUND_CEILING}


def round_px(px, sz_decimals: int, is_spot: bool = False, mode: str = "nearest") -> Decimal:
    """Venue price grid: at most 5 significant figures and at most (6 - szDecimals) decimals for perps
    (8 - szDecimals for spot). Same rule as OMX omx/venue/hyperliquid.py round_px."""
    d = Decimal(str(px))
    if not d.is_finite() or d <= 0:
        raise BuildError(f"INVALID_PRICE:{px}")
    max_dec = (8 if is_spot else 6) - sz_decimals
    q = max(Decimal(1).scaleb(d.adjusted() - 4), Decimal(1).scaleb(-max_dec))
    return (d / q).to_integral_value(rounding=_MODES[mode]) * q


def round_sz(sz, sz_decimals: int) -> Decimal:
    """Size rounded down to szDecimals (never more than asked)."""
    return Decimal(str(sz)).quantize(Decimal(1).scaleb(-sz_decimals), rounding=ROUND_FLOOR)


def builder_field(address: str, tenths_bps: int, *, spot: bool = False) -> dict:
    if not is_address(address):
        raise BuildError(f"malformed builder address: {address!r}")
    if not isinstance(tenths_bps, int) or isinstance(tenths_bps, bool) or tenths_bps < 0:
        raise BuildError("builder fee must be a non-negative int in tenths of a bps")
    cap = SPOT_MAX_TENTHS_BPS if spot else PERP_MAX_TENTHS_BPS
    if tenths_bps > cap:
        raise BuildError(f"builder fee {tenths_bps} tenths bps exceeds the venue cap {cap}")
    return {"b": address.lower(), "f": tenths_bps}


def order_wire(asset: int, is_buy: bool, px, sz, reduce_only: bool, tif: str, cloid: Optional[str]) -> dict:
    if tif not in TIFS:
        raise BuildError(f"tif must be one of {TIFS}")
    if Decimal(str(px)) <= 0 or Decimal(str(sz)) <= 0:
        raise BuildError("px and sz must be positive")
    w = {"a": int(asset), "b": bool(is_buy), "p": wire_str(px), "s": wire_str(sz), "r": bool(reduce_only),
         "t": {"limit": {"tif": tif}}}
    if cloid is not None:
        if not _CLOID.match(cloid):
            raise BuildError("cloid must be 0x + 32 lowercase hex chars")
        w["c"] = cloid
    return w


def order_action(wires: list, builder: Optional[dict]) -> dict:
    action = {"type": "order", "orders": wires, "grouping": "na"}
    if builder:
        action["builder"] = builder
    return action


def cancel_action(cancels: list[tuple[int, int]]) -> dict:
    return {"type": "cancel", "cancels": [{"a": int(a), "o": int(o)} for a, o in cancels]}


def cancel_by_cloid_action(cancels: list[tuple[int, str]]) -> dict:
    for _, c in cancels:
        if not _CLOID.match(c):
            raise BuildError("cloid must be 0x + 32 lowercase hex chars")
    return {"type": "cancelByCloid", "cancels": [{"asset": int(a), "cloid": c} for a, c in cancels]}


# ------------------------------------------------------------------ hashing / typed data

def action_hash(action: dict, vault_address: Optional[str], nonce: int, expires_after: Optional[int]) -> bytes:
    data = msgpack.packb(action)
    data += int(nonce).to_bytes(8, "big")
    if vault_address is None:
        data += b"\x00"
    else:
        data += b"\x01" + bytes.fromhex(vault_address[2:] if vault_address.startswith("0x") else vault_address)
    if expires_after is not None:
        data += b"\x00" + int(expires_after).to_bytes(8, "big")
    return keccak(data)


def l1_typed_data(connection_id: bytes, is_mainnet: bool) -> dict:
    """EIP-712 typed data for the phantom agent, JSON-safe (connectionId as 0x hex)."""
    return {
        "domain": {"chainId": CHAIN_ID, "name": "Exchange", "verifyingContract": ZERO_ADDRESS, "version": "1"},
        "types": {"Agent": [dict(t) for t in AGENT_TYPES], "EIP712Domain": [dict(t) for t in EIP712_DOMAIN_TYPES]},
        "primaryType": "Agent",
        "message": {"source": "a" if is_mainnet else "b", "connectionId": "0x" + connection_id.hex()},
    }


def typed_data_digest(typed: dict) -> bytes:
    """keccak256(0x19 0x01 || domainSeparator || hashStruct(message)) as eth_account computes it."""
    from eth_account.messages import encode_typed_data
    sm = encode_typed_data(full_message=typed)
    return keccak(b"\x19" + sm.version + sm.header + sm.body)


def split_signature(sig) -> dict:
    """65-byte signature (0x hex or bytes, r||s||v) -> the SDK's {"r", "s", "v"} form."""
    if isinstance(sig, dict):
        r, s, v = sig["r"], sig["s"], sig["v"]
        r = int(r, 16) if isinstance(r, str) else int(r)
        s = int(s, 16) if isinstance(s, str) else int(s)
        v = int(v, 16) if isinstance(v, str) else int(v)
    else:
        b = bytes.fromhex(sig[2:] if sig.startswith("0x") else sig) if isinstance(sig, str) else bytes(sig)
        if len(b) != 65:
            raise BuildError(f"signature must be 65 bytes, got {len(b)}")
        r, s, v = int.from_bytes(b[:32], "big"), int.from_bytes(b[32:64], "big"), b[64]
    if v in (0, 1):
        v += 27
    if v not in (27, 28):
        raise BuildError(f"bad recovery id v={v}")
    return {"r": to_hex(r), "s": to_hex(s), "v": v}


def recover_signer(typed: dict, signature) -> str:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    sig = split_signature(signature)
    return Account.recover_message(encode_typed_data(full_message=typed),
                                   vrs=[sig["v"], int(sig["r"], 16), int(sig["s"], 16)])


# ------------------------------------------------------------------ unsigned bundle

@dataclass
class Unsigned:
    action: dict
    nonce: int
    vault_address: Optional[str]
    expires_after: Optional[int]
    is_mainnet: bool
    connection_id: str
    typed_data: dict
    digest: str
    decision: Optional[Decision] = None

    def to_dict(self) -> dict:
        out = {"action": self.action, "nonce": self.nonce, "vault_address": self.vault_address,
               "expires_after": self.expires_after, "network": "mainnet" if self.is_mainnet else "testnet",
               "connection_id": self.connection_id, "typed_data": self.typed_data, "digest": self.digest}
        if self.decision is not None:
            out["mandate_decision"] = self.decision.to_dict()
        return out


def unsigned_l1(action: dict, nonce: int, *, is_mainnet: bool, vault_address: Optional[str] = None,
                expires_after: Optional[int] = None, decision: Optional[Decision] = None) -> Unsigned:
    if vault_address is not None and not is_address(vault_address):
        raise BuildError("malformed vault address")
    h = action_hash(action, vault_address, nonce, expires_after)
    typed = l1_typed_data(h, is_mainnet)
    return Unsigned(action, int(nonce), vault_address, expires_after, is_mainnet, "0x" + h.hex(), typed,
                    "0x" + typed_data_digest(typed).hex(), decision)


def build_order(order: OrderSpec, *, asset: int, mandate: dict, market: MarketView, account: AccountView,
                builder: tuple[str, int], nonce: int, expires_after: int, now_ms: int, is_mainnet: bool,
                cloid: Optional[str] = None, vault_address: Optional[str] = None,
                approval_ref: Optional[str] = None) -> Unsigned:
    """Pre-trade mandate check, then one order action WITH the builder field and expiresAfter.

    Raises MandateBlocked (carrying the decision) when any control blocks; nothing is built then.
    px and sz must already sit on the venue grid (see round_px / round_sz)."""
    if (mandate.get("network") == "mainnet") != bool(is_mainnet):
        raise BuildError("mandate network does not match is_mainnet")
    spot = asset >= SPOT_ASSET_OFFSET
    bf = builder_field(builder[0], builder[1], spot=spot)
    decision = check(mandate, order, market, account, now_ms, builder=(bf["b"], bf["f"]),
                     expires_after=expires_after, approval_ref=approval_ref)
    if not decision.allow:
        raise MandateBlocked(decision)
    wire = order_wire(asset, order.is_buy, order.px, order.sz, order.reduce_only, order.tif, cloid)
    return unsigned_l1(order_action([wire], bf), nonce, is_mainnet=is_mainnet, vault_address=vault_address,
                       expires_after=expires_after, decision=decision)


def build_cancel(cancels: list[tuple[int, int]], *, nonce: int, expires_after: int, is_mainnet: bool,
                 vault_address: Optional[str] = None) -> Unsigned:
    """Cancels are never blocked by the mandate (cancelling reduces risk; it works under a kill switch)."""
    return unsigned_l1(cancel_action(cancels), nonce, is_mainnet=is_mainnet, vault_address=vault_address,
                       expires_after=expires_after)


def assemble(action: dict, nonce: int, signature, *, vault_address: Optional[str] = None,
             expires_after: Optional[int] = None, is_mainnet: Optional[bool] = None,
             expected_signer: Optional[str] = None) -> dict:
    """The /exchange request body, as Exchange._post_action builds it.

    With is_mainnet and expected_signer, the signature is recovered against the
    recomputed typed data first and a mismatch is refused."""
    sig = split_signature(signature)
    if expected_signer is not None:
        if is_mainnet is None:
            raise BuildError("is_mainnet is required to check the signer")
        typed = l1_typed_data(action_hash(action, vault_address, nonce, expires_after), is_mainnet)
        got = recover_signer(typed, sig)
        if got.lower() != expected_signer.lower():
            raise BuildError(f"signature recovers to {got}, not the expected signer")
    return {"action": action, "nonce": int(nonce), "signature": sig, "vaultAddress": vault_address,
            "expiresAfter": expires_after}
