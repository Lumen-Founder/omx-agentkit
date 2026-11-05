import asyncio
import json

import pytest
from eth_account import Account

from agentkit.remote_mcp import TOOL_NAMES, RemoteGateway, build_server
from conftest import BUILDER, NOW

EXP = NOW + 15_000
ORDER = {"coin": "ETH", "asset": 4, "side": "buy", "px": "3510", "sz": "0.2", "tif": "Gtc"}
MARKET = {"coin": "ETH", "mid": 3500.0, "ts_ms": NOW - 500}
ACCOUNT_IN = {"equity_usd": 5000, "day_start_equity_usd": 5000, "marks": {"ETH": 3500.0}}


class FakeSubmit:
    def __init__(self):
        self.calls = []

    def __call__(self, payload, network):
        self.calls.append((payload, network))
        return {"submitted": True, "status": "ok", "fake": True}


@pytest.fixture
def gw():
    return RemoteGateway((BUILDER, 10), clock_ms=lambda: NOW)


def test_build_sign_submit_roundtrip(gw, mandate):
    out = gw.build_order(mandate, ORDER, MARKET, ACCOUNT_IN, NOW, EXP, "testnet")
    assert out["ok"], out
    assert out["controls_mode"] == "advisory" and "ADVISORY" in out["note"]
    u = out["unsigned"]
    assert u["action"]["builder"] == {"b": BUILDER, "f": 10} and u["expires_after"] == EXP
    assert out["builder_disclosure"]["fee_bps"] == 1.0 and out["builder_disclosure"]["fee_percent"] == "0.01%"
    agent = Account.create()
    wire = json.loads(json.dumps(out))                        # as the agent receives it
    sig = "0x" + Account.sign_typed_data(agent.key, full_message=wire["unsigned"]["typed_data"]).signature.hex()
    res = gw.submit_signed(wire["unsigned"]["action"], NOW, sig, "testnet", EXP, expected_signer=agent.address)
    assert res["ok"] and res["submit"]["reason"] == "SUBMIT_DISABLED"     # disabled by default
    assert res["payload"]["expiresAfter"] == EXP and res["payload"]["signature"]["v"] in (27, 28)

    fake = FakeSubmit()
    gw2 = RemoteGateway((BUILDER, 10), submit=fake, clock_ms=lambda: NOW)
    res = gw2.submit_signed(wire["unsigned"]["action"], NOW, sig, "testnet", EXP, expected_signer=agent.address)
    assert res["submit"]["fake"] and fake.calls[0][1] == "testnet" and fake.calls[0][0] == res["payload"]


def test_blocked_order_is_not_built(gw, mandate):
    out = gw.build_order(mandate, {**ORDER, "coin": "SOL"}, {**MARKET, "coin": "SOL"}, ACCOUNT_IN, NOW, EXP, "testnet")
    assert not out["ok"] and out["error"] == "MANDATE_BLOCKED" and "unsigned" not in out
    assert any(r.startswith("COIN_NOT_ALLOWED") for r in out["decision"]["reasons"])
    mandate["builder_fee"]["max_tenths_bps"] = 5
    out = gw.build_order(mandate, ORDER, MARKET, ACCOUNT_IN, NOW, EXP, "testnet")
    assert out["error"] == "MANDATE_BLOCKED" and "BUILDER_FEE_NOT_ACCEPTED" in out["decision"]["reasons"]


def test_secrets_are_refused(gw, mandate):
    out = gw.build_order(mandate, {**ORDER, "private_key": "x"}, MARKET, ACCOUNT_IN, NOW, EXP, "testnet")
    assert out["error"] == "SECRET_FIELD_REFUSED"
    assert gw.pretrade_quote({"coin": "ETH", "mnemonic": "x"})["error"] == "SECRET_FIELD_REFUSED"


def test_submit_refuses_changed_builder_and_expired(gw, mandate):
    out = gw.build_order(mandate, ORDER, MARKET, ACCOUNT_IN, NOW, EXP, "testnet")
    act = json.loads(json.dumps(out["unsigned"]["action"]))
    act.pop("builder")
    assert gw.submit_signed(act, NOW, "0x" + "00" * 65, "testnet", EXP)["error"] == "BUILDER_FIELD_MISSING_OR_CHANGED"
    agent = Account.create()
    sig = "0x" + Account.sign_typed_data(agent.key, full_message=out["unsigned"]["typed_data"]).signature.hex()
    late = RemoteGateway((BUILDER, 10), clock_ms=lambda: EXP + 1)
    assert late.submit_signed(out["unsigned"]["action"], NOW, sig, "testnet", EXP)["error"] == "EXPIRED"


def test_estimator_stub_and_plugin(gw):
    assert gw.pretrade_quote({"coin": "ETH"})["error"] == "ESTIMATOR_NOT_CONFIGURED"
    g = RemoteGateway((BUILDER, 10), estimator=lambda req: {"ok": True, "comparison": [], "echo": req["coin"]})
    assert g.pretrade_quote({"coin": "ETH"})["echo"] == "ETH"


def test_mandate_check_tool(gw, mandate):
    out = gw.mandate_check(mandate, ORDER, MARKET, ACCOUNT_IN, EXP)
    assert out["ok"] and out["decision"]["allow"] and out["controls_mode"] == "advisory"
    bad = dict(mandate, mandate_version="atm/9")
    assert gw.mandate_check(bad, ORDER, MARKET, ACCOUNT_IN, EXP)["error"] == "MandateError"


def test_mcp_server_exposes_four_tools(gw, mandate):
    srv = build_server(gw)

    async def go():
        tools = await srv.list_tools()
        res = await srv.call_tool("omx_build_order", {"mandate": mandate, "order": ORDER, "market": MARKET,
                                                      "account": ACCOUNT_IN, "nonce": NOW, "expires_after": EXP,
                                                      "network": "testnet"})
        return tools, res

    tools, res = asyncio.run(go())
    assert sorted(t.name for t in tools) == sorted(TOOL_NAMES)
    data = res.structured_content if hasattr(res, "structured_content") else res.structuredContent
    assert data["ok"] and data["unsigned"]["action"]["builder"]["b"] == BUILDER
    app = srv.streamable_http_app()                           # builds the HTTP app; nothing is bound
    assert app is not None
