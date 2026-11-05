# OMX AgentKit

The agent-facing layer around OMX, the non-custodial Hyperliquid execution engine
(github.com/Lumen-Founder/omx). It gives AI agents and their operators an open mandate format, unsigned
orders their own wallets can sign, verifiable receipts, and machine-readable discovery files.
It gives no trade direction or signals and makes no performance claim.

## Thesis (default path)

1. Nobody can force agents through us; we can only be the better default where they look.
2. Operators need limits, a kill switch and audit evidence: we publish the format (D1) and OMX implements it.
3. Cloud agents sign in their own wallets (CDP, Privy, Turnkey): we hand them ready-to-sign typed data (D2, D3).
4. Agents and future models find tools through llms.txt, MCP registries, x402 and A2A cards: one source feeds all (D4).
5. Every order built here carries a disclosed builder fee the user's main wallet approves; nothing is hidden.

## Contents

| Path | What |
|---|---|
| `spec/agent-trading-mandate-v0.md`, `spec/schemas/` | D1: Mandate, Execution Receipt, verification algorithm (V1..V9) |
| `agentkit/mandate.py` | Mandate validation, hash, pre-trade check (14 controls) |
| `agentkit/receipt.py` | Build a receipt from an OMX-format hash-chained audit log; verify it |
| `agentkit/unsigned.py` | D2: order/cancel actions with builder field and expiresAfter; L1 phantom-agent EIP-712 typed data (byte-identical to hyperliquid-python-sdk 0.20.0); `assemble()` |
| `agentkit/remote_mcp.py` | D2: remote MCP skeleton (streamable HTTP): `omx_pretrade_quote`, `omx_build_order`, `omx_submit_signed`, `omx_mandate_check` |
| `agentkit/signers/` | D3: `Signer` protocol; `LocalKeyFileSigner` (tests only); CDP, Privy, Turnkey adapters |
| `product.toml`, `agentkit/discovery.py`, `public/` | D4: llms.txt, openapi.json, server.json, `.well-known/x402`, `.well-known/agent-card.json` |
| `vendor/` | Vendored schemas/specs with source URLs and dates (`vendor/SOURCES.md`) |

## Enforced vs advisory

The remote MCP path is a convenience. The agent holds the key and signs, so it can bypass every
check there: those controls are **advisory**. Controls are **enforced** only in local OMX, which
holds the signer, refuses to sign a blocked order, console-confirms human approvals and writes the
audit log that receipts verify against.

## Run

```
python -m venv .venv
.venv/Scripts/python -m pip install -e .[test]       # or the deps in pyproject.toml
.venv/Scripts/python -X utf8 -B -m pytest -q -p no:cacheprovider
.venv/Scripts/python -X utf8 -B -m agentkit.discovery          # regenerate public/ from product.toml
.venv/Scripts/python -X utf8 -B -m agentkit.discovery --check  # verify public/ is current and valid
```

Tests are offline. Receipt tests load OMX's `omx/audit.py` read-only from the OMX checkout
(github.com/Lumen-Founder/omx: `$OMX_REPO` or `$OMX_ROOT` if set, else `../omx` next to this repo;
skipped if absent) without writing bytecode there.

## Not done

- No deployment: no domain, no server, no MCP Registry / x402 Bazaar / A2A listing. `product.toml`
  uses placeholders (`omx.invalid`, `invalid.omx/agentkit`, `payTo = UNSET-NOT-DEPLOYED`).
- No real signer calls: the CDP, Privy and Turnkey adapters were written from public docs and tested
  only against fake HTTP transports (`EXECUTED = False`). They need the user's own accounts; JWT /
  Basic / stamp headers come from caller-supplied functions.
- No requests to Hyperliquid or any chain, facilitator or wallet provider. `omx_submit_signed`
  posting is disabled by default; the Pre-Trade estimator is a stub.
- No A2A endpoint exists behind the agent card yet; `/.well-known/x402` follows an individual IETF
  draft because x402 has no official well-known format.
- Nothing published.
