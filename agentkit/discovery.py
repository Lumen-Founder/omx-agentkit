"""Machine-readable discovery files (D4), all generated from product.toml.

Outputs (under public/):
  llms.txt                     llmstxt.org format
  openapi.json                 OpenAPI 3.1 for the Pre-Trade API (x402-paid remote quote)
  server.json                  MCP Registry server.json (schema 2025-12-11), remote streamable-http
  .well-known/x402             x402 discovery manifest per draft-hawkins-x402-dns-discovery-02 (no official
                               x402 format exists as of 2026-11-05); each resource also lists x402 v2
                               PaymentRequirements under "accepts"
  .well-known/agent-card.json  A2A AgentCard (A2A 1.0; the well-known path is agent-card.json)

Run: python -m agentkit.discovery [--check]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from decimal import Decimal
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "schemas"
MCP_SCHEMA_URL = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
SCHEMAS = {
    "server.json": ("mcp-server.schema.2025-12-11.json", jsonschema.Draft7Validator),
    "openapi.json": ("openapi-3.1.schema.2022-10-07.json", jsonschema.Draft202012Validator),
    ".well-known/x402": ("x402-well-known.derived-draft-hawkins-02.schema.json", jsonschema.Draft202012Validator),
    ".well-known/agent-card.json": ("a2a-agent-card.derived-proto.schema.json", jsonschema.Draft202012Validator),
}


def load_product(path: Path = ROOT / "product.toml") -> dict:
    return tomllib.loads(Path(path).read_text(encoding="utf-8"))


def _url(p: dict, path: str) -> str:
    return p["product"]["base_url"].rstrip("/") + path


def _atomic(p: dict) -> str:
    t = p["pretrade"]
    return str(int(Decimal(t["price_usd"]) * (10 ** t["asset_decimals"])))


def payment_requirements(p: dict) -> dict:
    t = p["pretrade"]
    return {"scheme": t["scheme"], "network": t["network"], "amount": _atomic(p), "asset": t["asset"],
            "payTo": t["pay_to"], "maxTimeoutSeconds": t["max_timeout_seconds"],
            "extra": {"name": t["asset_name"], "version": t["asset_version"]}}


def llms_txt(p: dict) -> str:
    pr = p["product"]
    out = [f"# {pr['name']}", "", f"> {pr['summary']}", "", pr["details"], "",
           f"- MCP (streamable HTTP): {_url(p, p['mcp']['path'])}",
           f"- Pre-Trade API: POST {_url(p, p['pretrade']['path'])} (x402, {p['pretrade']['price_usd']} USD per quote)",
           "", "## Docs", ""]
    out += [f"- [{d['title']}]({_url(p, d['path'])}): {d['note']}" for d in p["docs"]]
    out += ["", "## Tools", ""]
    out += [f"- [{t['name']}]({_url(p, p['mcp']['path'])}): {t['description']}" for t in p["tools"]]
    out += ["", "## Optional", "",
            f"- [x402 manifest]({_url(p, '/.well-known/x402')}): payment requirements for the Pre-Trade API",
            f"- [A2A agent card]({_url(p, '/.well-known/agent-card.json')}): skills for agent-to-agent discovery",
            f"- [MCP server card]({_url(p, '/server.json')}): MCP Registry entry", ""]
    return "\n".join(out)


def openapi(p: dict) -> dict:
    pr, t = p["product"], p["pretrade"]
    style = {"type": "string", "enum": ["market", "limit", "twap", "pov", "chase"]}
    req = {"type": "object", "additionalProperties": False, "required": ["coin", "side", "size"],
           "properties": {"coin": {"type": "string", "examples": ["ETH"]}, "side": {"type": "string", "enum": ["buy", "sell"]},
                          "size": {"type": "number", "exclusiveMinimum": 0, "description": "Base units"},
                          "styles": {"type": "array", "items": style},
                          "max_slippage_bps": {"type": "number", "minimum": 0},
                          "horizon_s": {"type": "integer", "minimum": 0}}}
    row = {"type": "object", "required": ["style", "expected_cost_bps", "fill_probability", "expected_time_s"],
           "properties": {"style": style, "expected_cost_bps": {"type": "number"},
                          "cost_p90_bps": {"type": "number"}, "fill_probability": {"type": "number", "minimum": 0, "maximum": 1},
                          "expected_time_s": {"type": "number", "minimum": 0},
                          "builder_fee_bps": {"type": "number", "minimum": 0},
                          "omx_intent": {"type": "object", "description": "Ready to pass to OMX submit_order / omx_build_order"}}}
    resp = {"type": "object", "required": ["coin", "side", "size", "mid", "data_ts_ms", "comparison", "disclaimer"],
            "properties": {"coin": {"type": "string"}, "side": {"type": "string"}, "size": {"type": "number"},
                           "mid": {"type": "number"}, "data_ts_ms": {"type": "integer"},
                           "comparison": {"type": "array", "items": {"$ref": "#/components/schemas/StyleRow"}},
                           "disclaimer": {"type": "string", "const": "Execution cost comparison only. No trade direction, signal or profit advice."}}}
    return {
        "openapi": "3.1.0",
        "info": {"title": f"{pr['name']} Pre-Trade API", "version": pr["version"], "summary": pr["summary"],
                 "description": "Compares execution styles for one Hyperliquid order. Paid per call with x402 "
                                f"({t['price_usd']} USD, {t['network']}); free when computed by local OMX."},
        "servers": [{"url": pr["base_url"]}],
        "paths": {t["path"]: {"post": {
            "operationId": "omx_pretrade_quote", "summary": "Quantitative execution-style comparison",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/QuoteRequest"}}}},
            "responses": {
                "200": {"description": "Comparison", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/QuoteResponse"}}}},
                "402": {"description": "Payment required (x402 v2). The PAYMENT-REQUIRED header carries the requirements; "
                                       "retry with a PAYMENT-SIGNATURE header.",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PaymentRequired"}}}},
                "400": {"description": "Invalid request"}}}}},
        "components": {"schemas": {
            "QuoteRequest": req, "StyleRow": row, "QuoteResponse": resp,
            "PaymentRequired": {"type": "object", "required": ["x402Version", "accepts"],
                                "properties": {"x402Version": {"type": "integer"}, "error": {"type": "string"},
                                               "accepts": {"type": "array", "items": {"type": "object"}}},
                                "examples": [{"x402Version": 2, "accepts": [payment_requirements(p)]}]}}},
    }


def server_json(p: dict) -> dict:
    pr = p["product"]
    return {"$schema": MCP_SCHEMA_URL, "name": p["mcp"]["registry_name"], "title": pr["name"],
            "description": pr["mcp_description"], "version": pr["version"], "websiteUrl": pr["base_url"],
            "remotes": [{"type": "streamable-http", "url": _url(p, p["mcp"]["path"])}]}


def x402_manifest(p: dict) -> dict:
    pr, t = p["product"], p["pretrade"]
    return {"x402Version": 2, "kind": "resource-server", "name": pr["name"], "description": pr["summary"],
            "resources": [{"url": _url(p, t["path"]), "method": "POST",
                           "description": p["tools"][0]["description"], "mimeType": "application/json",
                           "accepts": [payment_requirements(p)]}],
            "attestation": {"type": "none"}, "docs": _url(p, "/llms.txt"), "updated": pr["updated"]}


def agent_card(p: dict) -> dict:
    pr, a = p["product"], p["a2a"]
    return {"name": pr["name"], "description": pr["summary"],
            "supportedInterfaces": [{"url": _url(p, a["path"]), "protocolBinding": a["protocol_binding"],
                                     "protocolVersion": a["protocol_version"]}],
            "provider": {"organization": pr["organization"], "url": pr["base_url"]},
            "version": pr["version"], "documentationUrl": _url(p, "/llms.txt"),
            "capabilities": {"streaming": False, "pushNotifications": False},
            "defaultInputModes": ["application/json"], "defaultOutputModes": ["application/json"],
            "skills": [{"id": t["name"], "name": t["title"], "description": t["description"], "tags": t["tags"]}
                       for t in p["tools"]]}


def render_all(p: dict) -> dict[str, str]:
    j = lambda o: json.dumps(o, indent=2, ensure_ascii=False) + "\n"  # noqa: E731
    return {"llms.txt": llms_txt(p), "openapi.json": j(openapi(p)), "server.json": j(server_json(p)),
            ".well-known/x402": j(x402_manifest(p)), ".well-known/agent-card.json": j(agent_card(p))}


# ------------------------------------------------------------------ checks

_LLMS_LINK = re.compile(r"^- \[[^\]]+\]\([^)\s]+\)(: .+)?$")


def check_llms_txt(text: str) -> list[str]:
    """llmstxt.org structure: H1 first, then an optional blockquote, free text, then H2 sections of link lists."""
    errs, lines = [], text.splitlines()
    if not lines or not lines[0].startswith("# "):
        errs.append("first line must be an H1 title")
    if sum(1 for ln in lines if ln.startswith("# ")) != 1:
        errs.append("exactly one H1")
    in_section = False
    for i, ln in enumerate(lines, 1):
        if ln.startswith("## "):
            in_section = True
        elif in_section and ln.strip() and not _LLMS_LINK.match(ln):
            errs.append(f"line {i}: section content must be '- [name](url): notes' list items")
        elif ln.startswith("#") and not ln.startswith(("# ", "## ")):
            errs.append(f"line {i}: only H1 and H2 headings are used")
    return errs


def _schema(name: str) -> dict:
    return json.loads((VENDOR / name).read_text(encoding="utf-8"))


def check_file(rel: str, text: str) -> list[str]:
    if rel == "llms.txt":
        return check_llms_txt(text)
    schema_name, cls = SCHEMAS[rel]
    doc = json.loads(text)
    errs = [f"{rel}: {'/'.join(map(str, e.path)) or '$'}: {e.message}"
            for e in cls(_schema(schema_name), format_checker=jsonschema.FormatChecker()).iter_errors(doc)]
    if rel == ".well-known/x402":                      # draft-hawkins-02 sec. 3.2 same-domain rule
        host = re.sub(r"^https://", "", doc.get("docs", "")).split("/")[0]
        for r in doc.get("resources", []):
            h = re.sub(r"^https://", "", r["url"]).split("/")[0]
            if not r["url"].startswith("https://") or not (h == host or h.endswith("." + host)):
                errs.append(f"{rel}: resource {r['url']} is not https on the manifest's domain")
    return errs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify public/ matches product.toml and the schemas")
    ap.add_argument("--out", default=str(ROOT / "public"))
    a = ap.parse_args(argv)
    out, files = Path(a.out), render_all(load_product())
    errs = []
    for rel, text in files.items():
        errs += check_file(rel, text)
        target = out / rel
        if a.check:
            if not target.exists() or target.read_text(encoding="utf-8") != text:
                errs.append(f"{rel}: out of date; run python -m agentkit.discovery")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")
    for e in errs:
        print(e, file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    raise SystemExit(main())
