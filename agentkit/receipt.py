"""Execution Receipt v0: build from an OMX-style hash-chained audit log, and verify.

The audit log format is OMX's (omx/audit.py): one canonical-JSON record per
line, {"ts_ms", "kind", "prev", "data"}, where prev is the sha256 (hex) of the
previous line's bytes and the first record's prev is 64 zeros. This module
re-implements the chain rules (it does not import OMX) so a third party can
verify a receipt with nothing but the log, the receipt and the mandate.

A receipt is a deterministic projection of the intent's audit records plus the
hashes that pin them. Verification re-reads the log, re-checks the chain,
re-derives the projection and compares. See spec/agent-trading-mandate-v0.md
section 5 for the algorithm (V1..V9).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import jsonschema

from .canon import canon, sha256_hex
from .mandate import load_schema, mandate_hash

GENESIS = "0" * 64
RECEIPT_VERSION = "atm-receipt/0"
MANDATE_RECORD = "mandate_bound"
# OMX policy reason prefix -> mandate control name
_REASON_CONTROL = {
    "KILL_SWITCH_ACTIVE": "kill_switch", "AGENT_SOURCE_DISABLED": "agent_source",
    "COIN_NOT_ALLOWED": "coin_allowlist", "STALE_DATA": "data_freshness", "NO_TWO_SIDED_BOOK": "data_freshness",
    "LIQUIDITY_BELOW_FLOOR": "liquidity", "DEPTH_BELOW_FLOOR": "liquidity",
    "PRICE_OUTSIDE_BAND": "price_band", "SLIPPAGE_CAP": "price_band", "BEYOND_INTENT_LIMIT": "price_band",
    "CHILD_NOTIONAL_CAP": "child_size", "REDUCE_ONLY_WOULD_INCREASE": "reduce_only",
    "COIN_NOTIONAL_CAP": "coin_notional", "ACCOUNT_NOTIONAL_CAP": "account_notional", "NO_MARK": "account_notional",
    "LEVERAGE_CAP": "leverage", "DAILY_LOSS_LIMIT": "daily_loss",
}
# mandate control name -> OMX checks key holding the measured value
_CONTROL_VALUE = {
    "kill_switch": None, "agent_source": None, "coin_allowlist": None, "data_freshness": "data_age_ms",
    "liquidity": "depth_usd", "price_band": "px_vs_mid_bps", "child_size": "child_ntl_usd", "reduce_only": None,
    "coin_notional": "coin_worst_case_usd", "account_notional": "account_worst_case_usd",
    "leverage": "worst_case_leverage", "daily_loss": "day_pnl_usd",
}


class AuditChainError(ValueError):
    pass


@dataclass(frozen=True)
class Line:
    no: int                 # 1-based line number
    hash: str               # sha256 hex of the line bytes (no newline)
    rec: dict


def read_chain(path) -> tuple[list[Line], Optional[str]]:
    """All records with their hashes, checked against the chain rules.

    Returns (lines, problem). problem is None when the whole file chains;
    otherwise it names the first bad line, and lines holds the records before it."""
    out: list[Line] = []
    prev = GENESIS
    with Path(path).open("rb") as fh:
        for i, raw in enumerate(fh, 1):
            line = raw.rstrip(b"\n")
            if not line:
                continue
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return out, f"line {i}: not JSON" + ("" if raw.endswith(b"\n") else " (torn tail)")
            if not isinstance(rec, dict) or rec.get("prev") != prev:
                return out, f"line {i}: chain broken"
            if canon(rec) != line:
                return out, f"line {i}: not canonical"
            prev = sha256_hex(line)
            out.append(Line(i, prev, rec))
    return out, None


def _intent_of(data: dict) -> Optional[str]:
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("intent_id"), str):
        return data["intent_id"]
    for k in ("intent", "report"):
        sub = data.get(k)
        if isinstance(sub, dict) and isinstance(sub.get("intent_id"), str):
            return sub["intent_id"]
    return None


def _belongs(ln: Line, intent_id: str) -> bool:
    return _intent_of(ln.rec.get("data", {})) == intent_id


def _controls(checks: dict, reasons: list) -> dict:
    failed = {_REASON_CONTROL.get(r.split(":", 1)[0], "other") for r in reasons}
    out = {}
    for name, key in _CONTROL_VALUE.items():
        entry = {"pass": name not in failed}
        if key is not None and key in checks:
            entry["value"] = checks[key]
        out[name] = entry
    if "other" in failed:
        out["other"] = {"pass": False}
    return out


def _r(x: float) -> float:
    return round(float(x), 10)


def project(lines: list[Line], intent_id: str) -> dict:
    """The receipt body that the intent's audit records determine."""
    mine = [ln for ln in lines if _belongs(ln, intent_id)]
    decisions, orders, fills = [], [], []
    by_child: dict[str, dict] = {}
    allowed_at: dict[str, tuple[int, dict]] = {}
    received_ms = first_sent_ms = done_ms = None
    for ln in mine:
        kind, d = ln.rec["kind"], ln.rec["data"]
        if kind == "intent_received":
            received_ms = d.get("now_ms", ln.rec["ts_ms"])
        elif kind == "child_decision":
            ch = d.get("child", {})
            decisions.append({"line": ln.no, "child_id": ch.get("child_id"), "allow": bool(d.get("allow")),
                              "reasons": list(d.get("reasons", [])),
                              "controls": _controls(d.get("checks", {}), list(d.get("reasons", [])))})
            if d.get("allow"):
                allowed_at[ch.get("child_id")] = (ln.no, ch)
        elif kind == "child_sent":
            cid = d.get("child_id")
            dec = allowed_at.get(cid)
            ch = dec[1] if dec else {}
            b = ch.get("builder")
            o = {"child_id": cid, "cloid": ch.get("cloid"), "coin": ch.get("coin"), "side": ch.get("side"),
                 "size": ch.get("size"), "px": ch.get("px"), "tif": ch.get("tif"),
                 "reduce_only": bool(ch.get("reduce_only")),
                 "builder": {"b": b[0], "f": b[1]} if isinstance(b, (list, tuple)) and len(b) == 2 else None,
                 "decision_line": dec[0] if dec else None, "sent_line": ln.no, "sent_ms": d.get("now_ms"),
                 "resend": bool(d.get("resend", False)), "oid": None}
            orders.append(o)
            by_child[cid] = o
            if first_sent_ms is None:
                first_sent_ms = d.get("now_ms", ln.rec["ts_ms"])
        elif kind == "child_ack":
            o = by_child.get(d.get("child_id"))
            if o is not None:
                o["oid"] = d.get("oid")
        elif kind == "fill":
            f = d.get("fill", {})
            fills.append({"line": ln.no, "child_id": f.get("child_id"), "fill_id": f.get("fill_id"),
                          "side": f.get("side"), "size": f.get("size"), "px": f.get("px"),
                          "venue_fee_usd": f.get("fee_usd", 0.0), "builder_fee_usd": f.get("builder_fee_usd", 0.0),
                          "ts_ms": f.get("ts_ms"), "crossed": f.get("crossed")})
        elif kind == "intent_done":
            done_ms = d.get("now_ms", ln.rec["ts_ms"])
    totals = {"filled_size": _r(sum(f["size"] or 0 for f in fills)),
              "filled_notional_usd": _r(sum((f["size"] or 0) * (f["px"] or 0) for f in fills)),
              "venue_fee_usd": _r(sum(f["venue_fee_usd"] or 0 for f in fills)),
              "builder_fee_usd": _r(sum(f["builder_fee_usd"] or 0 for f in fills))}
    last_fill_ms = max((f["ts_ms"] for f in fills if f["ts_ms"] is not None), default=None)
    return {
        "status": "final" if done_ms is not None else "partial",
        "decisions": decisions, "orders": orders, "fills": fills, "totals": totals,
        "timestamps": {"intent_received_ms": received_ms, "first_sent_ms": first_sent_ms,
                       "last_fill_ms": last_fill_ms, "intent_done_ms": done_ms},
        "records": [{"line": ln.no, "kind": ln.rec["kind"], "hash": ln.hash} for ln in mine],
    }


def receipt_hash(receipt: dict) -> str:
    body = {k: v for k, v in receipt.items() if k != "receipt_hash"}
    return sha256_hex(canon(body))


def _mandate_binding(lines: list[Line], before_line: int, mhash: str) -> dict:
    bound = [ln for ln in lines if ln.no < before_line and ln.rec["kind"] == MANDATE_RECORD]
    if bound and bound[-1].rec["data"].get("mandate_hash") == mhash:
        return {"mode": "audit_record", "line": bound[-1].no, "hash": bound[-1].hash}
    return {"mode": "asserted"}


def build_receipt(audit_path, intent_id: str, mandate: dict, *, account: str, network: str,
                  created_ms: int, venue: str = "hyperliquid") -> dict:
    lines, problem = read_chain(audit_path)
    if problem:
        raise AuditChainError(f"refusing to build a receipt from a broken log: {problem}")
    body = project(lines, intent_id)
    if not body["records"]:
        raise ValueError(f"no audit records for intent {intent_id}")
    first, last = body["records"][0], body["records"][-1]
    start_prev = next(ln.rec["prev"] for ln in lines if ln.no == first["line"])
    mh = mandate_hash(mandate)
    receipt = {
        "receipt_version": RECEIPT_VERSION, "intent_id": intent_id, "venue": venue, "network": network,
        "account": account.lower(), "mandate_hash": mh,
        "mandate_binding": _mandate_binding(lines, first["line"], mh),
        "audit": {"hash_alg": "sha256", "genesis": GENESIS,
                  "start": {"line": first["line"], "prev": start_prev, "hash": first["hash"]},
                  "end": {"line": last["line"], "hash": last["hash"]},
                  "head_at_creation": {"line": lines[-1].no, "hash": lines[-1].hash},
                  "records": body.pop("records")},
        **body, "created_ms": created_ms,
    }
    receipt["receipt_hash"] = receipt_hash(receipt)
    return receipt


@dataclass
class VerifyResult:
    ok: bool
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    checks: dict = field(default_factory=dict)


def verify_receipt(receipt: dict, audit_path, mandate: Optional[dict] = None,
                   anchor_hash: Optional[str] = None) -> VerifyResult:
    """V1..V9 of the spec. ok is True only when no error was found."""
    res = VerifyResult(ok=False)
    E = res.errors.append

    def mark(name, ok, msg):
        res.checks[name] = bool(ok)
        if not ok:
            E(f"{name}: {msg}")
        return ok

    v = jsonschema.Draft202012Validator(load_schema("receipt.v0.schema.json"))
    errs = [f"{'/'.join(map(str, e.path)) or '$'}: {e.message}" for e in v.iter_errors(receipt)]
    if not mark("V1_schema", not errs, "; ".join(errs[:5])):
        return res
    mark("V2_receipt_hash", receipt_hash(receipt) == receipt.get("receipt_hash"), "receipt_hash does not match body")

    lines, problem = read_chain(audit_path)
    end_no = receipt["audit"]["end"]["line"]
    covered = bool(lines) and lines[-1].no >= end_no
    mark("V3_chain", covered, f"log does not chain through line {end_no}: {problem}")
    if problem and covered:
        res.warnings.append(f"log breaks after the receipt's range: {problem}")
    if not covered:
        return res
    by_no = {ln.no: ln for ln in lines}
    st, en = receipt["audit"]["start"], receipt["audit"]["end"]
    ok4 = (st["line"] in by_no and by_no[st["line"]].hash == st["hash"] and by_no[st["line"]].rec["prev"] == st["prev"]
           and en["line"] in by_no and by_no[en["line"]].hash == en["hash"])
    head = receipt["audit"]["head_at_creation"]
    ok4 = ok4 and head["line"] in by_no and by_no[head["line"]].hash == head["hash"]
    mark("V4_anchors", ok4, "start/end/head hashes do not match the log")

    iid = receipt["intent_id"]
    upto_head = [ln for ln in lines if ln.no <= head["line"]]
    body = project(upto_head, iid)
    listed = receipt["audit"]["records"]
    mark("V5_complete", body["records"] == listed,
         "audit records of the intent (up to head_at_creation) differ from the receipt's list")
    if body["records"]:
        mark("V5_range", body["records"][0]["line"] == st["line"] and body["records"][-1]["line"] == en["line"],
             "start/end are not the intent's first/last record")
    later = [ln.no for ln in lines if ln.no > head["line"] and _belongs(ln, iid)]
    if later:
        (E if receipt["status"] == "final" else res.warnings.append)(
            f"V5_after_head: intent has records after the receipt head: lines {later[:5]}")
        res.checks["V5_after_head"] = receipt["status"] != "final"
    for k in ("status", "decisions", "orders", "fills", "totals", "timestamps"):
        mark(f"V6_{k}", body[k] == receipt[k], f"{k} differs from what the audit log records")

    ok7, why = True, ""
    for o in receipt["orders"]:
        if o["decision_line"] is None or o["decision_line"] >= o["sent_line"]:
            ok7, why = False, f"order {o['child_id']} has no allowing decision before it was sent"
    mark("V7_control_evidence", ok7, why)

    if mandate is not None:
        mh = mandate_hash(mandate)
        mark("V8_mandate_hash", mh == receipt["mandate_hash"], "mandate does not hash to receipt.mandate_hash")
        b = receipt["mandate_binding"]
        if b["mode"] == "audit_record":
            ln = by_no.get(b["line"])
            mark("V8_binding", ln is not None and ln.hash == b["hash"] and ln.rec["kind"] == MANDATE_RECORD
                 and ln.rec["data"].get("mandate_hash") == mh and ln.no < st["line"],
                 "mandate_bound record does not match")
        else:
            res.warnings.append("mandate binding is asserted by the receipt builder, not recorded in the log")
        bf = mandate["builder_fee"]
        bad = [o["child_id"] for o in receipt["orders"] if o["builder"] is not None and not (
            bf["accepted"] and o["builder"]["b"].lower() == bf.get("builder", "").lower()
            and o["builder"]["f"] <= bf["max_tenths_bps"])]
        bad += [o["child_id"] for o in receipt["orders"] if o["coin"] not in mandate["coins"]["allowed"]]
        mark("V8_orders_within_mandate", not bad, f"orders outside the mandate: {bad}")
    if anchor_hash is not None:
        mark("V9_external_anchor", any(ln.hash == anchor_hash and ln.no >= en["line"] for ln in lines),
             "external anchor hash is not a line at or after the receipt's end")
    res.ok = not res.errors
    return res
