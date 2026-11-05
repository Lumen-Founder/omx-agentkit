"""Coinbase CDP Server Wallet v2 (EVM account) adapter. NOT EXECUTED: needs the user's CDP account.

Source (read 2026-11-05):
  https://docs.cdp.coinbase.com/api-reference/v2/rest-api/evm-accounts/sign-eip-712-typed-data
  https://docs.cdp.coinbase.com/api-reference/v2/authentication
Endpoint: POST https://api.cdp.coinbase.com/platform/v2/evm/accounts/{address}/sign/typed-data
Body:     {"domain": {...}, "types": {...}, "primaryType": "...", "message": {...}}
Headers:  Authorization: Bearer <API-key JWT (claims incl. uri "POST api.cdp.coinbase.com/platform/...")>
          X-Wallet-Auth: <Wallet-Secret JWT (claims incl. uris and reqHash of the sorted-key JSON body)>
          X-Idempotency-Key: optional, 1..128 chars
Response: {"signature": "0x..."}
Both JWTs are made from the user's secrets; pass a HeaderProvider (for example
backed by the official cdp-sdk) that returns them for the exact request.
Open: the doc page text was partly truncated when read; re-check body/headers before first use.
"""
from __future__ import annotations

import uuid
from typing import Optional

from ..canon import is_address
from .base import DisabledTransport, HeaderProvider, HttpTransport, SignerError, check_sig, json_body

BASE_URL = "https://api.cdp.coinbase.com/platform"
DOC_URLS = ("https://docs.cdp.coinbase.com/api-reference/v2/rest-api/evm-accounts/sign-eip-712-typed-data",
            "https://docs.cdp.coinbase.com/api-reference/v2/authentication")
EXECUTED = False


class CdpServerWalletSigner:
    def __init__(self, address: str, auth_headers: HeaderProvider, transport: Optional[HttpTransport] = None,
                 base_url: str = BASE_URL):
        if not is_address(address):
            raise SignerError("malformed address")
        self._address, self._auth, self._base = address, auth_headers, base_url.rstrip("/")
        self._transport = transport or DisabledTransport()

    def address(self) -> str:
        return self._address

    def request(self, typed: dict) -> tuple[str, str, dict, bytes]:
        url = f"{self._base}/v2/evm/accounts/{self._address}/sign/typed-data"
        body = json_body({"domain": typed["domain"], "types": typed["types"], "primaryType": typed["primaryType"],
                          "message": typed["message"]})
        headers = {"Content-Type": "application/json", "X-Idempotency-Key": str(uuid.uuid4())}
        headers.update(self._auth("POST", url, body))
        return "POST", url, headers, body

    def sign_typed_data(self, typed: dict) -> str:
        method, url, headers, body = self.request(typed)
        status, res = self._transport(method, url, headers, body)
        if status != 200:
            raise SignerError(f"CDP sign failed: HTTP {status}: {str(res)[:200]}")
        return check_sig(res.get("signature"))
