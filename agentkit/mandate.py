"""Agent Trading Mandate v0: validation, hashing and the pre-trade check.

The check mirrors OMX's policy (omx/policy.py) for the controls the mandate
names. Exposure is worst case: position plus every same-side resting order
filled at its own price plus the new order; other coins count toward the
account total at the mark the caller passes, and an exposed coin without a
mark blocks. Reduce-only orders that really reduce skip the size, notional,
leverage and daily-loss blocks, as in OMX.

Where this runs decides what it is worth: inside local OMX the check is
enforced (OMX holds the signer and will not sign a blocked order). On the
remote MCP path the agent signs, so the same check is advisory there.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from functools import lru_cache
from pathlib import Path
from typing import Optional

import jsonschema

from .canon import canon, secret_fields, sha256_hex

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "spec" / "schemas"
CONTROL_ORDER = ("mandate_valid", "kill_switch", "coin_allowlist", "data_freshness", "price_band", "child_size",
                 "reduce_only", "coin_notional", "account_notional", "leverage", "daily_loss", "human_approval",
                 "builder_fee", "order_expiry")


class MandateError(ValueError):
    """The mandate document itself is invalid."""


class MandateBlocked(Exception):
    """A build was refused because the mandate blocks the order."""

    def __init__(self, decision: "Decision"):
        super().__init__("MANDATE_BLOCKED: " + ",".join(decision.reasons))
        self.decision = decision


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def validate_mandate(doc: dict) -> dict:
    """Schema plus semantic checks. Returns the document; raises MandateError."""
    if not isinstance(doc, dict):
        raise MandateError("mandate must be a JSON object")
    bad = secret_fields(doc)
    if bad:
        raise MandateError(f"mandate carries secret-named fields: {bad}")
    v = jsonschema.Draft202012Validator(load_schema("mandate.v0.schema.json"),
                                        format_checker=jsonschema.FormatChecker())
    errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
    if errs:
        raise MandateError("; ".join(f"{'/'.join(map(str, e.path)) or '$'}: {e.message}" for e in errs[:10]))
    allowed = set(doc["coins"]["allowed"])
    extra = set(doc["notional"].get("per_coin_usd", {})) - allowed
    if extra:
        raise MandateError(f"per_coin_usd names coins outside coins.allowed: {sorted(extra)}")
    bf = doc["builder_fee"]
    if bf["accepted"] and "builder" not in bf:
        raise MandateError("builder_fee.accepted requires builder_fee.builder")
    if bf["accepted"] and bf["builder"].lower() == doc["account"].lower():
        raise MandateError("builder_fee.builder must differ from the account")
    try:
        issued = _ts_ms(doc["issued_at"])
        expires = _ts_ms(doc["expires_at"]) if "expires_at" in doc else None
    except ValueError:
        raise MandateError("issued_at / expires_at must be RFC 3339 timestamps") from None
    if expires is not None and expires <= issued:
        raise MandateError("expires_at must be after issued_at")
    return doc


def mandate_hash(doc: dict) -> str:
    """sha256 of the canonical JSON of the whole mandate (hex, no 0x)."""
    return sha256_hex(canon(doc))


def _ts_ms(s: str) -> int:
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)


# ------------------------------------------------------------------ inputs

@dataclass(frozen=True)
class OrderSpec:
    coin: str
    is_buy: bool
    sz: Decimal
    px: Decimal
    reduce_only: bool = False
    tif: str = "Gtc"                      # Gtc | Ioc | Alo

    @property
    def notional_usd(self) -> float:
        return float(self.sz * self.px)


@dataclass(frozen=True)
class MarketView:
    coin: str
    mid: Optional[float]
    ts_ms: int


@dataclass
class AccountView:
    equity_usd: float
    day_start_equity_usd: float
    external_flows_usd: float = 0.0       # deposits - withdrawals +/- transfers since day start
    positions: dict = field(default_factory=dict)      # coin -> signed size (base units)
    open_orders: list = field(default_factory=list)    # dicts: coin, is_buy, sz, px, reduce_only
    marks: dict = field(default_factory=dict)          # coin -> mark price

    def day_pnl_usd(self) -> float:
        return self.equity_usd - self.day_start_equity_usd - self.external_flows_usd

    @classmethod
    def from_dict(cls, d: dict) -> "AccountView":
        return cls(equity_usd=float(d["equity_usd"]), day_start_equity_usd=float(d["day_start_equity_usd"]),
                   external_flows_usd=float(d.get("external_flows_usd", 0.0)),
                   positions={k: float(v) for k, v in (d.get("positions") or {}).items()},
                   open_orders=list(d.get("open_orders") or []),
                   marks={k: float(v) for k, v in (d.get("marks") or {}).items()})


@dataclass
class Decision:
    allow: bool
    reasons: tuple
    controls: dict                        # name -> {"pass": bool, "value": ..., "limit": ...}
    mandate_hash: str
    needs_human_approval: bool = False

    def to_dict(self) -> dict:
        return {"allow": self.allow, "reasons": list(self.reasons), "needs_human_approval": self.needs_human_approval,
                "mandate_hash": self.mandate_hash,
                "controls": {k: self.controls[k] for k in CONTROL_ORDER if k in self.controls}}


# ------------------------------------------------------------------ check

def _worst_case(pos: float, orders: list, coin: str, extra: Optional[OrderSpec]) -> float:
    buys = sum(float(o["sz"]) for o in orders if o["coin"] == coin and o["is_buy"] and not o.get("reduce_only"))
    sells = sum(float(o["sz"]) for o in orders if o["coin"] == coin and not o["is_buy"] and not o.get("reduce_only"))
    if extra is not None and extra.coin == coin and not extra.reduce_only:
        if extra.is_buy:
            buys += float(extra.sz)
        else:
            sells += float(extra.sz)
    return max(abs(pos + buys), abs(pos - sells))


def check(mandate: dict, order: OrderSpec, market: MarketView, account: AccountView, now_ms: int, *,
          builder: Optional[tuple] = None, expires_after: Optional[int] = None,
          approval_ref: Optional[str] = None) -> Decision:
    """Evaluate every mandate control for one order. Never raises for a blocked order."""
    m = validate_mandate(mandate)
    c: dict = {}
    reasons: list[str] = []

    def put(name, ok, reason=None, **info):
        c[name] = {"pass": bool(ok), **info}
        if not ok and reason:
            reasons.append(reason)

    issued, exp = _ts_ms(m["issued_at"]), _ts_ms(m["expires_at"]) if "expires_at" in m else None
    put("mandate_valid", issued <= now_ms and (exp is None or now_ms < exp), "MANDATE_NOT_IN_FORCE",
        issued_ms=issued, expires_ms=exp)
    put("kill_switch", not m["kill_switch"]["engaged"], "KILL_SWITCH_ACTIVE")
    put("coin_allowlist", order.coin in m["coins"]["allowed"], f"COIN_NOT_ALLOWED:{order.coin}", value=order.coin)

    age = now_ms - market.ts_ms
    fresh = market.coin == order.coin and market.mid is not None and -1000 <= age <= m["data_freshness"]["max_age_ms"]
    put("data_freshness", fresh, "STALE_OR_MISSING_DATA", value=age, limit=m["data_freshness"]["max_age_ms"])

    mid = market.mid
    if mid:
        dev = (float(order.px) - mid) / mid * 1e4 * (1 if order.is_buy else -1)
        put("price_band", abs(dev) <= m["price_band"]["max_bps_vs_mid"], f"PRICE_OUTSIDE_BAND:{dev:.1f}bps",
            value=round(dev, 4), limit=m["price_band"]["max_bps_vs_mid"])
    else:
        put("price_band", False, "NO_MID")
    ref = mid or float(order.px)
    ro = order.reduce_only

    child_ntl = order.notional_usd
    put("child_size", ro or child_ntl <= m["child_order"]["max_notional_usd"], "CHILD_NOTIONAL_CAP",
        value=round(child_ntl, 6), limit=m["child_order"]["max_notional_usd"])

    pos = float(account.positions.get(order.coin, 0.0))
    if ro:
        reduces = pos != 0 and ((pos > 0) != order.is_buy) and float(order.sz) <= abs(pos) + 1e-12
        put("reduce_only", reduces, "REDUCE_ONLY_WOULD_INCREASE", value=pos)
    else:
        put("reduce_only", True, value=pos)

    coin_wc = _worst_case(pos, account.open_orders, order.coin, order) * ref
    cap = m["notional"].get("per_coin_usd", {}).get(order.coin, m["notional"]["default_per_coin_usd"])
    put("coin_notional", ro or coin_wc <= cap, "COIN_NOTIONAL_CAP", value=round(coin_wc, 6), limit=cap)

    marks = dict(account.marks)
    marks[order.coin] = ref
    coins = set(account.positions) | {o["coin"] for o in account.open_orders} | {order.coin}
    total, no_mark = 0.0, []
    for coin in sorted(coins):
        px = marks.get(coin)
        if px is None:
            no_mark.append(coin)
            px = max([float(o["px"]) for o in account.open_orders if o["coin"] == coin] + [0.0])
        total += _worst_case(float(account.positions.get(coin, 0.0)), account.open_orders, coin,
                             order if coin == order.coin else None) * px
    acct_ok = ro or (total <= m["notional"]["account_usd"] and not no_mark)
    put("account_notional", acct_ok, "ACCOUNT_NOTIONAL_CAP" if not no_mark else "NO_MARK:" + ",".join(no_mark),
        value=round(total, 6), limit=m["notional"]["account_usd"], coins_without_mark=no_mark)

    lev = total / account.equity_usd if account.equity_usd > 0 else float("inf")
    put("leverage", ro or lev <= m["leverage"]["max"], f"LEVERAGE_CAP:{lev:.2f}",
        value=round(lev, 6) if lev != float("inf") else "inf", limit=m["leverage"]["max"])

    dpl = account.day_pnl_usd()
    put("daily_loss", ro or dpl > -m["daily_loss"]["max_usd"], "DAILY_LOSS_LIMIT",
        value=round(dpl, 6), limit=-m["daily_loss"]["max_usd"], excludes_external_flows=True)

    over = child_ntl > m["human_approval"]["above_notional_usd"]
    if over and approval_ref:
        put("human_approval", True, value=round(child_ntl, 6), limit=m["human_approval"]["above_notional_usd"],
            approval_ref=approval_ref, note="approval_ref asserted by the caller, not verified here")
    else:
        put("human_approval", not over, "HUMAN_APPROVAL_REQUIRED", value=round(child_ntl, 6),
            limit=m["human_approval"]["above_notional_usd"])

    bf = m["builder_fee"]
    if builder is None:
        put("builder_fee", True, value=None)
    else:
        b_addr, f = builder[0].lower(), int(builder[1])
        ok = bf["accepted"] and b_addr == bf.get("builder", "").lower() and f <= bf["max_tenths_bps"]
        put("builder_fee", ok, "BUILDER_FEE_NOT_ACCEPTED", value={"b": b_addr, "f": f},
            limit={"builder": bf.get("builder", "").lower() or None, "max_tenths_bps": bf["max_tenths_bps"],
                   "accepted": bf["accepted"]}, disclosure=bf["disclosure"])

    if expires_after is None:
        put("order_expiry", False, "EXPIRES_AFTER_REQUIRED", limit=m["order_expiry"]["max_ms"])
    else:
        ahead = int(expires_after) - now_ms
        put("order_expiry", 0 < ahead <= m["order_expiry"]["max_ms"], "EXPIRES_AFTER_OUT_OF_RANGE",
            value=ahead, limit=m["order_expiry"]["max_ms"])

    return Decision(allow=not reasons, reasons=tuple(reasons), controls=c, mandate_hash=mandate_hash(m),
                    needs_human_approval=over and not approval_ref)
