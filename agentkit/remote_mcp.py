"""Remote, non-custodial MCP server skeleton (D2), streamable HTTP.

What it does: builds Hyperliquid order actions WITH the builder field and
expiresAfter, runs the mandate pre-trade check first, and returns the EIP-712
typed data the agent's own wallet must sign. It assembles the /exchange body
from a signature the agent sends back. It holds no keys and signs nothing.

What it is NOT: an enforcement point. The agent holds the signing key, so it
can skip this server, edit the action, or sign anything it likes; every
control here is ADVISORY. Enforced controls exist only in local OMX
(github.com/Lumen-Founder/omx), where the engine holds the signer and refuses to sign a
blocked order, and writes the hash-chained audit log that receipts verify
against. The remote path is a convenience for cloud agents that cannot run
a local process.

Network: nothing is sent anywhere by default. Pre-trade quotes need a
configured estimator; posting to Hyperliquid needs an explicitly injected
SubmitTransport (disabled by default, a fake in tests).

Run (local only, for development): python -m agentkit.remote_mcp --port 8765
"""
from __future__ import annotations

import argparse
import time
from decimal import Decimal
from typing import Any, Callable, Optional, Protocol

from .canon import is_address, secret_fields
from .mandate import AccountView, MandateBlocked, MandateError, MarketView, OrderSpec, check
from .unsigned import BuildError, assemble, build_order

ADVISORY_NOTE = ("Controls on this remote server are ADVISORY: you (the agent) hold the signing key and can bypass "
                 "them. Enforced controls, approvals and the hash-chained audit log exist only in local OMX.")
TOOL_NAMES = ("omx_pretrade_quote", "omx_build_order", "omx_submit_signed", "omx_mandate_check")


class PreTradeEstimator(Protocol):
    def __call__(self, request: dict) -> dict: ...


class SubmitTransport(Protocol):
    def __call__(self, payload: dict, network: str) -> dict: ...


def unconfigured_estimator(request: dict) -> dict:
    return {"ok": False, "error": "ESTIMATOR_NOT_CONFIGURED",
            "message": "No pre-trade estimator is configured on this server. Configure one "
                       "(RemoteGateway(estimator=...)) or run local OMX, whose quotes are free."}


def disabled_submit(payload: dict, network: str) -> dict:
    return {"submitted": False, "reason": "SUBMIT_DISABLED",
            "message": "This server does not post to Hyperliquid. POST the payload to /exchange yourself, "
                       "or the operator must inject a SubmitTransport."}


class RemoteGateway:
    """Tool logic, independent of MCP so it can be tested directly."""

    def __init__(self, builder: tuple[str, int], estimator: Optional[PreTradeEstimator] = None,
                 submit: Optional[SubmitTransport] = None, clock_ms: Callable[[], int] = lambda: int(time.time() * 1000)):
        if not is_address(builder[0]):
            raise ValueError("malformed builder address")
        self.builder = (builder[0].lower(), int(builder[1]))
        self.estimator = estimator or unconfigured_estimator
        self.submit = submit or disabled_submit
        self.clock_ms = clock_ms

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _refuse_secrets(*objs) -> Optional[dict]:
        for o in objs:
            bad = secret_fields(o)
            if bad:
                return {"ok": False, "error": "SECRET_FIELD_REFUSED",
                        "message": f"never send keys or secrets to this server: {bad}"}
        return None

    def disclosure(self) -> dict:
        b, f = self.builder
        return {"builder": b, "fee_tenths_bps": f, "fee_bps": f / 10, "fee_percent": f"{f / 1000:g}%",
                "charged": "by Hyperliquid on each fill of this order, on top of venue fees",
                "requires": "the account's MAIN wallet approved a max builder fee >= this rate for this builder "
                            "(ApproveBuilderFee); otherwise Hyperliquid rejects the order",
                "approved_by": "the user's own main wallet; this server never signs approvals"}

    @staticmethod
    def _inputs(order: dict, market: dict, account: dict) -> tuple[OrderSpec, MarketView, AccountView]:
        side = order["side"]
        if side not in ("buy", "sell"):
            raise BuildError("side must be buy or sell")
        spec = OrderSpec(coin=order["coin"], is_buy=side == "buy", sz=Decimal(str(order["sz"])),
                         px=Decimal(str(order["px"])), reduce_only=bool(order.get("reduce_only", False)),
                         tif=order.get("tif", "Gtc"))
        mv = MarketView(coin=market.get("coin", order["coin"]), mid=market.get("mid"), ts_ms=int(market["ts_ms"]))
        return spec, mv, AccountView.from_dict(account)

    # ------------------------------------------------------------ tools

    def pretrade_quote(self, request: dict) -> dict:
        refused = self._refuse_secrets(request)
        return refused or self.estimator(request)

    def mandate_check(self, mandate: dict, order: dict, market: dict, account: dict,
                      expires_after: Optional[int] = None) -> dict:
        refused = self._refuse_secrets(mandate, order, market, account)
        if refused:
            return refused
        try:
            spec, mv, av = self._inputs(order, market, account)
            d = check(mandate, spec, mv, av, self.clock_ms(), builder=self.builder, expires_after=expires_after)
        except (MandateError, BuildError, KeyError, ValueError, ArithmeticError) as e:
            return {"ok": False, "error": type(e).__name__, "message": str(e)}
        return {"ok": True, "decision": d.to_dict(), "controls_mode": "advisory", "note": ADVISORY_NOTE}

    def build_order(self, mandate: dict, order: dict, market: dict, account: dict, nonce: int,
                    expires_after: int, network: str, vault_address: Optional[str] = None,
                    approval_ref: Optional[str] = None) -> dict:
        refused = self._refuse_secrets(mandate, order, market, account)
        if refused:
            return refused
        if network not in ("mainnet", "testnet"):
            return {"ok": False, "error": "BAD_NETWORK"}
        try:
            spec, mv, av = self._inputs(order, market, account)
            u = build_order(spec, asset=int(order["asset"]), mandate=mandate, market=mv, account=av,
                            builder=self.builder, nonce=int(nonce), expires_after=int(expires_after),
                            now_ms=self.clock_ms(), is_mainnet=network == "mainnet", cloid=order.get("cloid"),
                            vault_address=vault_address, approval_ref=approval_ref)
        except MandateBlocked as e:
            return {"ok": False, "error": "MANDATE_BLOCKED", "decision": e.decision.to_dict(),
                    "controls_mode": "advisory", "builder_disclosure": self.disclosure()}
        except (MandateError, BuildError, KeyError, ValueError, ArithmeticError) as e:
            return {"ok": False, "error": type(e).__name__, "message": str(e)}
        return {"ok": True, "unsigned": u.to_dict(), "builder_disclosure": self.disclosure(),
                "sign": "Sign unsigned.typed_data (EIP-712, primaryType Agent) with the account's agent (API) "
                        "wallet, then call omx_submit_signed with the 65-byte signature.",
                "controls_mode": "advisory", "note": ADVISORY_NOTE}

    def submit_signed(self, action: dict, nonce: int, signature: str, network: str,
                      expires_after: Optional[int] = None, vault_address: Optional[str] = None,
                      expected_signer: Optional[str] = None) -> dict:
        refused = self._refuse_secrets(action)
        if refused:
            return refused
        if network not in ("mainnet", "testnet"):
            return {"ok": False, "error": "BAD_NETWORK"}
        if action.get("type") == "order" and action.get("builder", {}).get("b") != self.builder[0]:
            return {"ok": False, "error": "BUILDER_FIELD_MISSING_OR_CHANGED",
                    "message": "orders assembled here carry this server's disclosed builder field"}
        try:
            payload = assemble(action, int(nonce), signature, vault_address=vault_address,
                               expires_after=expires_after, is_mainnet=network == "mainnet",
                               expected_signer=expected_signer)
        except (BuildError, ValueError, KeyError) as e:
            return {"ok": False, "error": type(e).__name__, "message": str(e)}
        if expires_after is not None and expires_after <= self.clock_ms():
            return {"ok": False, "error": "EXPIRED", "payload": payload}
        return {"ok": True, "payload": payload, "submit": self.submit(payload, network)}


def build_server(gw: RemoteGateway):
    from mcp.server.mcpserver import MCPServer

    srv = MCPServer(name="omx-agentkit-remote", version="0.0.1",
                    instructions="Non-custodial helper for Hyperliquid orders. " + ADVISORY_NOTE)
    tool = srv.tool(structured_output=True)

    @tool
    def omx_pretrade_quote(request: dict[str, Any]) -> dict[str, Any]:
        """Quantitative comparison of execution styles for an order (cost, fill odds, time); no direction or
        profit advice. Delegates to the configured estimator."""
        return gw.pretrade_quote(request)

    @tool
    def omx_mandate_check(mandate: dict[str, Any], order: dict[str, Any], market: dict[str, Any],
                          account: dict[str, Any], expires_after: Optional[int] = None) -> dict[str, Any]:
        """Evaluate an Agent Trading Mandate (atm/0) against one order. Advisory on this server."""
        return gw.mandate_check(mandate, order, market, account, expires_after)

    @tool
    def omx_build_order(mandate: dict[str, Any], order: dict[str, Any], market: dict[str, Any],
                        account: dict[str, Any], nonce: int, expires_after: int, network: str,
                        vault_address: Optional[str] = None, approval_ref: Optional[str] = None) -> dict[str, Any]:
        """Mandate check, then an unsigned order action with the disclosed builder field and expiresAfter,
        plus the EIP-712 typed data your wallet must sign. order: coin, asset (venue asset id), side buy|sell,
        px, sz (on the venue grid), tif Gtc|Ioc|Alo, reduce_only, cloid (optional 0x+32 hex)."""
        return gw.build_order(mandate, order, market, account, nonce, expires_after, network, vault_address,
                              approval_ref)

    @tool
    def omx_submit_signed(action: dict[str, Any], nonce: int, signature: str, network: str,
                          expires_after: Optional[int] = None, vault_address: Optional[str] = None,
                          expected_signer: Optional[str] = None) -> dict[str, Any]:
        """Assemble the /exchange payload from your signature (checked against expected_signer when given).
        Posting is disabled unless the operator configured a transport."""
        return gw.submit_signed(action, nonce, signature, network, expires_after, vault_address, expected_signer)

    return srv


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description="OMX AgentKit remote MCP (development only)")
    p.add_argument("--builder", required=True, help="builder address (0x...)")
    p.add_argument("--fee-tenths-bps", type=int, required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    a = p.parse_args(argv)
    import uvicorn
    app = build_server(RemoteGateway((a.builder, a.fee_tenths_bps))).streamable_http_app(host=a.host)
    uvicorn.run(app, host=a.host, port=a.port)


if __name__ == "__main__":
    main()
