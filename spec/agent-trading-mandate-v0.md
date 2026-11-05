# Agent Trading Mandate v0 (draft)

Status: draft, 2026-11-05. Not published. Reference implementation: `agentkit/mandate.py`,
`agentkit/receipt.py`; enforcing implementation: local OMX (github.com/Lumen-Founder/omx).

## 1. Purpose

An AI agent that trades with someone else's money needs three things its operator, auditor or
insurer can check: written limits (the **Mandate**), a tamper-evident record of what the agent did
(a **hash-chained audit log**), and a per-order statement tying the two together (the **Execution
Receipt**). This document defines all three for Hyperliquid perpetuals. It says nothing about what
to trade; it gives no signals and makes no performance claim.

Key words MUST, SHOULD, MAY are as in RFC 2119.

## 2. Units and conventions

- Notional in USD; prices in the venue's quote (USDC); sizes in base units.
- Basis points (bps) vs mid: `dev = (px - mid) / mid * 10_000`, sign flipped for sells.
- Builder fees in tenths of a bps (`10` = 1 bps = 0.01 %), the unit of Hyperliquid's `builder.f`.
- Times in Unix milliseconds; timestamps in documents are RFC 3339 UTC.
- Hashes are lowercase hex sha256 without `0x`; canonical JSON is `json.dumps(sort_keys=True,
  separators=(",", ":"), ensure_ascii=False)` UTF-8 (the form OMX's audit log uses).

## 3. Mandate

Schema: `spec/schemas/mandate.v0.schema.json` (JSON Schema 2020-12). `mandate_hash` = sha256 of the
canonical JSON of the whole document. A mandate MUST NOT contain secrets; a validator MUST refuse
fields named like secrets (`private_key`, `secret`, `mnemonic`, `seed`, ...). Extension fields start
with `x-`.

A pre-trade check evaluates every control below for each child order and returns, per control,
`{"pass": bool, "value": measured, "limit": configured}`. The order is allowed only if all pass.

| Control | Field | Rule |
|---|---|---|
| mandate_valid | `issued_at`, `expires_at` | `issued_at <= now < expires_at` |
| kill_switch | `kill_switch.engaged` | engaged blocks every new order. Agents MAY engage it, only a human clears it (`clear_requires: "human"`). Cancels are never blocked. |
| coin_allowlist | `coins.allowed` | coin in the list |
| data_freshness | `data_freshness.max_age_ms` | market snapshot for this coin with a mid, `-1000 <= now - ts <= max_age_ms` |
| price_band | `price_band.max_bps_vs_mid` | `abs(dev) <= max` (symmetric, as OMX) |
| child_size | `child_order.max_notional_usd` | `sz * px <= max` |
| reduce_only | - | a reduce-only order must shrink the position by at most its size |
| coin_notional | `notional.per_coin_usd`, `default_per_coin_usd` | worst case `max(|pos + same-side buys|, |pos - sells|) * mid`, **resting orders counted as filled** plus the new order (`count_resting_orders` MUST be true) |
| account_notional | `notional.account_usd` | sum of worst cases over all exposed coins at their marks; an exposed coin without a mark blocks |
| leverage | `leverage.max` | account worst case / equity |
| daily_loss | `daily_loss.max_usd` | `day_pnl = equity - day_start_equity - external_flows` (deposits minus withdrawals and transfers since the UTC day start); blocks when `day_pnl <= -max`. A deposit never lifts day P&L (`excludes_external_flows` MUST be true). |
| human_approval | `human_approval.above_notional_usd` | above it the order needs a human approval reference; enforcement of the approval itself is the executor's (OMX: console-confirmed approval queue) |
| builder_fee | `builder_fee.accepted`, `builder`, `max_tenths_bps`, `disclosure` | an order carrying `builder: {b, f}` passes only if accepted, `b` equals the named builder and `f <= max_tenths_bps`. The disclosure text MUST be shown to the operator before acceptance. |
| order_expiry | `order_expiry.max_ms` | every signed action carries `expiresAfter` with `0 < expiresAfter - now <= max_ms` |

Reduce-only orders that really reduce skip child_size, coin/account notional, leverage and
daily_loss (they lower risk), as in OMX.

## 4. Execution Receipt

Schema: `spec/schemas/receipt.v0.schema.json`. One receipt per intent. It is unsigned: its strength
comes from the audit log it points into, not from a signature.

Audit log (OMX format, `omx/audit.py`): one canonical-JSON record per line,
`{"ts_ms", "kind", "prev", "data"}`; `prev` is the sha256 of the previous line's bytes, the first
record's `prev` is 64 zeros. Records never contain keys or signatures. A record belongs to intent
`I` when `data.intent_id`, `data.intent.intent_id` or `data.report.intent_id` equals `I`.
A `mandate_bound` record (`data.mandate_hash`) written before an intent binds that intent to the
mandate; without one, the receipt's binding is only `asserted`.

Receipt fields:
- `intent_id`, `venue`, `network`, `account`, `mandate_hash`, `mandate_binding`
  (`{"mode": "audit_record", "line", "hash"}` or `{"mode": "asserted"}`).
- `audit.start` `{line, prev, hash}` (the intent's first record), `audit.end` `{line, hash}` (its
  last), `audit.head_at_creation` `{line, hash}` (last line of the log when the receipt was made),
  `audit.records[]` `{line, kind, hash}`: every record of the intent up to the head, in order.
- `decisions[]`: per child decision `{line, child_id, allow, reasons, controls}`, `controls` naming
  each control with `pass` and the measured value.
- `orders[]`: every sent child `{child_id, cloid, coin, side, size, px, tif, reduce_only,
  builder {b, f} | null, decision_line, sent_line, sent_ms, resend, oid}`.
- `fills[]`: `{line, child_id, fill_id, side, size, px, venue_fee_usd, builder_fee_usd, ts_ms,
  crossed}`. Venue fee and builder fee are always separate (`venue_fee_usd` < 0 is a rebate).
- `totals` `{filled_size, filled_notional_usd, venue_fee_usd, builder_fee_usd}` (rounded to 1e-10).
- `timestamps` `{intent_received_ms, first_sent_ms, last_fill_ms, intent_done_ms}`, `created_ms`.
- `status`: `final` when the intent's `intent_done` record is included, else `partial`.
- `receipt_hash`: sha256 of the canonical JSON of the receipt without `receipt_hash`.

Everything except `created_ms`, `account`, `network` and `mandate_*` is a deterministic projection
of the intent's records (`agentkit.receipt.project`), so the verifier can recompute it.

## 5. Verification algorithm

Input: receipt `R`, the audit log `L`, optionally the mandate `M` and an externally kept head hash
`A`. Output: ok, plus per-check results, errors and warnings.

- **V1 schema**: `R` validates against the receipt schema.
- **V2 receipt hash**: recompute `receipt_hash`.
- **V3 chain**: walk `L` from genesis; every line must be canonical JSON whose `prev` equals the
  sha256 of the previous line. The chain MUST hold at least through `audit.end.line`; a break after
  the receipt's range is a warning.
- **V4 anchors**: line `start.line` has hash `start.hash` and `prev == start.prev`; same for
  `end` and `head_at_creation`. (Catches a log rewritten with a fresh, internally valid chain.)
- **V5 completeness**: the intent's records in `L` up to `head_at_creation` equal `audit.records`
  exactly (line, kind, hash); `start`/`end` are the first/last of them. Records of the intent after
  the head are an error for a `final` receipt and a warning for a `partial` one.
- **V6 projection**: recompute `status`, `decisions`, `orders`, `fills`, `totals`, `timestamps`
  from those records; each must equal the receipt's.
- **V7 control evidence**: every order has an allowing decision on an earlier line.
- **V8 mandate** (when `M` is given): `mandate_hash(M) == R.mandate_hash`; an `audit_record`
  binding must point at a `mandate_bound` record before `start` carrying that hash; every order's
  coin is allowed and its builder field is within `M.builder_fee`.
- **V9 external anchor** (when `A` is given): `A` is the hash of a line at or after `end`. The
  chain proves internal consistency only; an anchor copied elsewhere (daily `omx audit verify`
  output) is what proves the log was not replaced wholesale or cut at the end.

## 6. Enforcement modes

| Path | Who signs | Controls |
|---|---|---|
| Local OMX | OMX engine (agent API wallet key on the user's machine) | **Enforced**: a blocked child is never signed; approvals are console-confirmed; the audit log is written by the executor |
| Remote MCP (`agentkit/remote_mcp.py`) | the agent's own wallet | **Advisory**: the server checks and builds, but the agent can bypass it, alter the action or sign something else. A receipt from this path can only cover what the server saw |

## 7. Hyperliquid L1 signing reference (hyperliquid-python-sdk 0.20.0)

- `connectionId = keccak256(msgpack(action) || nonce u64 BE || vaultFlag || expiry)` with
  `vaultFlag = 0x00` or `0x01 || 20-byte vault address`, and `expiry = 0x00 || expiresAfter u64 BE`
  only when `expiresAfter` is set (so `expiresAfter` is inside the signed hash).
- Phantom agent: `{"source": "a" (mainnet) | "b" (testnet), "connectionId": bytes32}`.
- EIP-712: domain `{name "Exchange", version "1", chainId 1337, verifyingContract 0x0}`,
  primaryType `Agent`, `Agent = [source string, connectionId bytes32]`.
- Order action key order: `type, orders, grouping, builder`; wire key order `a, b, p, s, r, t, c`;
  `builder.b` lowercase. Payload: `{action, nonce, signature {r, s, v}, vaultAddress, expiresAfter}`.

## 8. Security considerations

- No component of this spec holds or transmits keys. Signer adapters take credentials only through
  caller-supplied header functions.
- The builder fee is charged only up to what the account's main wallet approved
  (`ApproveBuilderFee`); agent API wallets cannot approve it. Disclosure precedes approval.
- A receipt is evidence about one log. Without an external anchor (V9) a truncated log can look
  complete.

## 9. Versioning

`mandate_version: "atm/0"`, `receipt_version: "atm-receipt/0"`. Breaking changes bump the number.
