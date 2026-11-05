import copy
import hashlib
import json

import pytest

from agentkit.canon import canon
from agentkit.mandate import mandate_hash
from agentkit.receipt import AuditChainError, build_receipt, read_chain, receipt_hash, verify_receipt
from conftest import ACCOUNT, BUILDER, NOW

IID = "ag-test0001"
CLOID = "0x4f4d5801" + "1234abcd" + hashlib.sha256(b"ag-test0001.2").hexdigest()[:16]


def child(n, px, size=0.1):
    return {"child_id": f"{IID}.{n}", "intent_id": IID, "coin": "ETH", "side": "buy", "size": size, "px": px,
            "tif": "Ioc", "reduce_only": False, "cloid": CLOID if n == 2 else "0x" + "00" * 16,
            "builder": [BUILDER, 10]}


def checks(px_bps):
    return {"kill_switch": True, "allowlist": True, "data_age_ms": 420, "day_ntl_usd": 9e8, "depth_usd": 1.2e6,
            "px_vs_mid_bps": px_bps, "child_ntl_usd": 351.0, "coin_worst_case_usd": 351.0,
            "coins_without_mark": [], "account_worst_case_usd": 351.0, "worst_case_leverage": 0.07,
            "day_pnl_usd": -12.5}


def write_log(audit_mod, path, mandate, done=True):
    log = audit_mod.AuditLog(path)
    log.append("mandate_bound", {"mandate_hash": mandate_hash(mandate), "mandate_id": mandate["mandate_id"]})
    log.append("intent_received", {"intent": {"intent_id": IID, "coin": "ETH", "side": "buy", "size": 0.1,
                                              "algo": "market", "source": "agent:test"}, "now_ms": NOW})
    log.append("intent_received", {"intent": {"intent_id": "hu-other01", "coin": "BTC", "side": "sell",
                                              "size": 0.01, "source": "human"}, "now_ms": NOW + 1})
    log.append("child_decision", {"intent_id": IID, "child": child(1, 3570.0), "allow": False,
                                  "reasons": ["PRICE_OUTSIDE_BAND:171.4bps"], "checks": checks(171.4), "now_ms": NOW + 10})
    log.append("child_decision", {"intent_id": IID, "child": child(2, 3510.0), "allow": True, "reasons": [],
                                  "checks": checks(28.6), "now_ms": NOW + 20})
    log.append("child_sent", {"intent_id": IID, "child_id": f"{IID}.2", "now_ms": NOW + 21})
    log.append("venue_error", {"where": "poll", "error": "timeout", "now_ms": NOW + 22})
    log.append("child_ack", {"intent_id": IID, "child_id": f"{IID}.2", "oid": "991", "filled_sz": 0.0})
    for i, (sz, px) in enumerate([(0.06, 3505.0), (0.04, 3506.5)], 1):
        log.append("fill", {"intent_id": IID, "fill": {"child_id": f"{IID}.2", "coin": "ETH", "side": "buy",
                                                       "size": sz, "px": px, "fee_usd": round(sz * px * 0.00045, 8),
                                                       "builder_fee_usd": round(sz * px * 0.0001, 8),
                                                       "ts_ms": NOW + 30 + i, "crossed": True, "fill_id": f"t{i}"}})
    log.append("child_decision", {"intent_id": "hu-other01", "child": {**child(9, 99000.0), "intent_id": "hu-other01",
                                  "child_id": "hu-other01.1", "coin": "BTC"}, "allow": True, "reasons": [],
                                  "checks": checks(5.0), "now_ms": NOW + 40})
    if done:
        log.append("intent_done", {"report": {"intent_id": IID, "state": "done", "filled": 0.1}, "now_ms": NOW + 50})
    return log


@pytest.fixture
def setup(tmp_path, omx_audit, mandate):
    path = tmp_path / "audit.jsonl"
    write_log(omx_audit, path, mandate)
    r = build_receipt(path, IID, mandate, account=ACCOUNT, network="testnet", created_ms=NOW + 60)
    return path, r, mandate, omx_audit


def test_receipt_built_and_verified(setup):
    path, r, mandate, omx = setup
    assert omx.AuditLog.verify(path) == (True, 12, "ok")             # OMX's own verifier agrees
    res = verify_receipt(r, path, mandate)
    assert res.ok, res.errors
    assert not res.warnings
    assert r["status"] == "final" and r["mandate_binding"]["mode"] == "audit_record"
    assert [d["allow"] for d in r["decisions"]] == [False, True]
    assert r["decisions"][0]["controls"]["price_band"]["pass"] is False
    assert r["decisions"][1]["controls"]["price_band"] == {"pass": True, "value": 28.6}
    (o,) = r["orders"]
    assert o["cloid"] == CLOID and o["builder"] == {"b": BUILDER, "f": 10} and o["oid"] == "991"
    assert r["totals"]["filled_size"] == 0.1
    assert r["totals"]["venue_fee_usd"] == round(0.06 * 3505 * 0.00045 + 0.04 * 3506.5 * 0.00045, 10)
    assert r["totals"]["builder_fee_usd"] > 0 and r["totals"]["builder_fee_usd"] != r["totals"]["venue_fee_usd"]
    assert [x["kind"] for x in r["audit"]["records"]] == ["intent_received", "child_decision", "child_decision",
                                                         "child_sent", "child_ack", "fill", "fill", "intent_done"]
    lines, _ = read_chain(path)
    assert r["audit"]["start"]["prev"] == lines[0].hash               # the record before the intent's first
    assert r["audit"]["end"]["hash"] == lines[-1].hash


def _edit_line(path, lineno, fn):
    raw = path.read_bytes().split(b"\n")
    rec = json.loads(raw[lineno - 1])
    fn(rec)
    raw[lineno - 1] = canon(rec)
    path.write_bytes(b"\n".join(raw))


def test_log_edit_detected(setup):
    path, r, mandate, _ = setup
    _edit_line(path, 9, lambda rec: rec["data"]["fill"].update(px=3400.0))
    res = verify_receipt(r, path, mandate)
    assert not res.ok and res.checks["V3_chain"] is False


def test_log_rewritten_with_consistent_chain_detected(setup):
    path, r, mandate, _ = setup
    lines = path.read_bytes().rstrip(b"\n").split(b"\n")
    prev, out = "0" * 64, []
    for i, raw in enumerate(lines, 1):
        rec = json.loads(raw)
        if i == 9:
            rec["data"]["fill"]["builder_fee_usd"] = 0.0             # hide the builder fee
        rec["prev"] = prev
        line = canon(rec)
        prev = hashlib.sha256(line).hexdigest()
        out.append(line)
    path.write_bytes(b"\n".join(out) + b"\n")
    res = verify_receipt(r, path, mandate)
    assert res.checks["V3_chain"] is True and res.checks["V4_anchors"] is False and not res.ok


def test_log_record_deleted_detected(setup):
    path, r, mandate, _ = setup
    raw = path.read_bytes().split(b"\n")
    del raw[9]
    path.write_bytes(b"\n".join(raw))
    assert not verify_receipt(r, path, mandate).ok


def test_receipt_edit_detected(setup):
    path, r, mandate, _ = setup
    t = copy.deepcopy(r)
    t["fills"][0]["builder_fee_usd"] = 0.0
    res = verify_receipt(t, path, mandate)
    assert res.checks["V2_receipt_hash"] is False
    t["receipt_hash"] = receipt_hash(t)                               # rehash: projection still disagrees
    res = verify_receipt(t, path, mandate)
    assert res.checks["V2_receipt_hash"] is True and res.checks["V6_fills"] is False and not res.ok


def test_receipt_omitting_a_record_detected(setup):
    path, r, mandate, _ = setup
    t = copy.deepcopy(r)
    t["audit"]["records"] = [x for x in t["audit"]["records"] if x["kind"] != "fill"]
    t["fills"], t["receipt_hash"] = [], None
    t["receipt_hash"] = receipt_hash(t)
    res = verify_receipt(t, path, mandate)
    assert res.checks["V5_complete"] is False and not res.ok


def test_wrong_mandate_detected(setup):
    path, r, mandate, _ = setup
    other = copy.deepcopy(mandate)
    other["builder_fee"]["max_tenths_bps"] = 5                        # operator never accepted 1 bps
    res = verify_receipt(r, path, other)
    assert res.checks["V8_mandate_hash"] is False
    assert res.checks["V8_orders_within_mandate"] is False


def test_external_anchor(setup):
    path, r, mandate, _ = setup
    assert verify_receipt(r, path, mandate, anchor_hash=r["audit"]["head_at_creation"]["hash"]).ok
    assert not verify_receipt(r, path, mandate, anchor_hash="ab" * 32).ok


def test_partial_then_final(tmp_path, omx_audit, mandate):
    path = tmp_path / "audit.jsonl"
    log = write_log(omx_audit, path, mandate, done=False)
    partial = build_receipt(path, IID, mandate, account=ACCOUNT, network="testnet", created_ms=NOW + 45)
    assert partial["status"] == "partial" and partial["timestamps"]["intent_done_ms"] is None
    log.append("intent_done", {"report": {"intent_id": IID, "state": "done"}, "now_ms": NOW + 50})
    res = verify_receipt(partial, path, mandate)
    assert res.ok and any("after the receipt head" in w for w in res.warnings)
    final = build_receipt(path, IID, mandate, account=ACCOUNT, network="testnet", created_ms=NOW + 60)
    assert final["status"] == "final" and verify_receipt(final, path, mandate).ok


def test_asserted_binding_without_mandate_record(tmp_path, omx_audit, mandate):
    path = tmp_path / "audit.jsonl"
    log = omx_audit.AuditLog(path)
    log.append("intent_received", {"intent": {"intent_id": IID}, "now_ms": NOW})
    r = build_receipt(path, IID, mandate, account=ACCOUNT, network="testnet", created_ms=NOW)
    assert r["mandate_binding"] == {"mode": "asserted"}
    res = verify_receipt(r, path, mandate)
    assert res.ok and any("asserted" in w for w in res.warnings)


def test_refuses_broken_log(setup):
    path, r, mandate, _ = setup
    _edit_line(path, 5, lambda rec: rec["data"].update(allow=False))
    with pytest.raises(AuditChainError):
        build_receipt(path, IID, mandate, account=ACCOUNT, network="testnet", created_ms=NOW)


def test_omx_refuses_secret_fields(tmp_path, omx_audit):
    with pytest.raises(ValueError):
        omx_audit.AuditLog(tmp_path / "a.jsonl").append("fill", {"signature": "0x00"})
