"""Turnkey sign_raw_payload adapter. NOT EXECUTED: needs the user's Turnkey organization.

Source (read 2026-11-05):
  https://docs.turnkey.com/api-reference/activities/sign-raw-payload
  https://docs.turnkey.com/developer-reference/api-overview/stamps
  https://docs.turnkey.com/networks/ethereum
Endpoint: POST https://api.turnkey.com/public/v1/submit/sign_raw_payload
Body:     {"type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "timestampMs": "<ms as string>",
           "organizationId": "<org id>",
           "parameters": {"signWith": "<address>", "payload": "...", "encoding": "...", "hashFunction": "..."}}
Modes:    "digest" (default): payload = EIP-712 digest hex, encoding PAYLOAD_ENCODING_HEXADECIMAL,
            hashFunction HASH_FUNCTION_NO_OP. Turnkey policies cannot read typed-data fields then; for a
            Hyperliquid order they could not anyway, the order sits inside the opaque connectionId.
          "eip712": payload = serialized typed data, encoding PAYLOAD_ENCODING_EIP712, HASH_FUNCTION_NO_OP.
Header:   X-Stamp: base64url(JSON {publicKey, signature (DER hex over the exact body), scheme}), made
          from the user's API key by a caller-supplied HeaderProvider.
Response: activity.result.signRawPayloadResult {r, s, v}  (the doc's example nests one level deeper; both read)
Open: the docs do not state whether r/s carry 0x, whether v is "00"/"01", whether the HEXADECIMAL
payload takes a 0x prefix, nor the exact EIP712 serialization; the activity may also come back
pending (consensus) instead of completed. Verify against a real account before use.
"""
from __future__ import annotations

import json
import time
from typing import Callable, Optional

from ..canon import is_address
from .base import DisabledTransport, HeaderProvider, HttpTransport, SignerError, json_body, signature_hex

BASE_URL = "https://api.turnkey.com"
DOC_URLS = ("https://docs.turnkey.com/api-reference/activities/sign-raw-payload",
            "https://docs.turnkey.com/developer-reference/api-overview/stamps",
            "https://docs.turnkey.com/networks/ethereum")
EXECUTED = False


def _result(res: dict) -> Optional[dict]:
    r = (res.get("activity") or {}).get("result") or {}
    return r.get("signRawPayloadResult") or ((r.get("activity") or {}).get("result") or {}).get("signRawPayloadResult")


class TurnkeySigner:
    def __init__(self, organization_id: str, address: str, stamp_headers: HeaderProvider,
                 transport: Optional[HttpTransport] = None, mode: str = "digest", base_url: str = BASE_URL,
                 clock_ms: Callable[[], int] = lambda: int(time.time() * 1000)):
        if not is_address(address) or not organization_id:
            raise SignerError("malformed address or organization id")
        if mode not in ("digest", "eip712"):
            raise SignerError("mode must be digest or eip712")
        self._org, self._address, self._stamp, self._mode = organization_id, address, stamp_headers, mode
        self._base, self._clock = base_url.rstrip("/"), clock_ms
        self._transport = transport or DisabledTransport()

    def address(self) -> str:
        return self._address

    def request(self, typed: dict) -> tuple[str, str, dict, bytes]:
        if self._mode == "digest":
            from ..unsigned import typed_data_digest
            payload, enc = typed_data_digest(typed).hex(), "PAYLOAD_ENCODING_HEXADECIMAL"
        else:
            payload, enc = json.dumps(typed, separators=(",", ":")), "PAYLOAD_ENCODING_EIP712"
        url = f"{self._base}/public/v1/submit/sign_raw_payload"
        body = json_body({"type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "timestampMs": str(self._clock()),
                          "organizationId": self._org,
                          "parameters": {"signWith": self._address, "payload": payload, "encoding": enc,
                                         "hashFunction": "HASH_FUNCTION_NO_OP"}})
        headers = {"Content-Type": "application/json"}
        headers.update(self._stamp("POST", url, body))
        return "POST", url, headers, body

    def sign_typed_data(self, typed: dict) -> str:
        method, url, headers, body = self.request(typed)
        status, res = self._transport(method, url, headers, body)
        if status != 200:
            raise SignerError(f"Turnkey sign failed: HTTP {status}: {str(res)[:200]}")
        out = _result(res)
        if not out:
            st = (res.get("activity") or {}).get("status")
            raise SignerError(f"Turnkey activity has no signRawPayloadResult (status {st})")
        return signature_hex(out["r"], out["s"], out["v"])
