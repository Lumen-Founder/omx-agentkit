"""Privy wallet API adapter (eth_signTypedData_v4). NOT EXECUTED: needs the user's Privy app.

Source (read 2026-11-05):
  https://docs.privy.io/api-reference/wallets/ethereum/eth-signtypeddata-v4
  https://docs.privy.io/basics/rest-api/setup  (Basic auth = app id : app secret; privy-app-id header)
  https://docs.privy.io/controls/authorization-keys/using-owners/sign/  (privy-authorization-signature)
Endpoint: POST https://api.privy.io/v1/wallets/{wallet_id}/rpc
Body:     {"method": "eth_signTypedData_v4",
           "params": {"typed_data": {"domain", "types", "primary_type", "message"}}}   (primary_type is snake_case)
Headers:  Authorization: Basic base64(app_id:app_secret), privy-app-id: <app id>,
          privy-authorization-signature: optional (wallets with an owner / authorization key)
Response: {"method": "eth_signTypedData_v4", "data": {"signature": "0x...", "encoding": "hex"}}
The Authorization and privy-authorization-signature headers are made from the
user's secrets by a caller-supplied HeaderProvider.
"""
from __future__ import annotations

import re
from typing import Optional

from ..canon import is_address
from .base import DisabledTransport, HeaderProvider, HttpTransport, SignerError, check_sig, json_body

BASE_URL = "https://api.privy.io"
DOC_URLS = ("https://docs.privy.io/api-reference/wallets/ethereum/eth-signtypeddata-v4",
            "https://docs.privy.io/basics/rest-api/setup",
            "https://docs.privy.io/controls/authorization-keys/using-owners/sign/")
EXECUTED = False
_WALLET_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class PrivySigner:
    def __init__(self, wallet_id: str, address: str, app_id: str, auth_headers: HeaderProvider,
                 transport: Optional[HttpTransport] = None, base_url: str = BASE_URL):
        if not _WALLET_ID.match(wallet_id) or not is_address(address):
            raise SignerError("malformed wallet id or address")
        self._wallet_id, self._address, self._app_id = wallet_id, address, app_id
        self._auth, self._base = auth_headers, base_url.rstrip("/")
        self._transport = transport or DisabledTransport()

    def address(self) -> str:
        return self._address

    def request(self, typed: dict) -> tuple[str, str, dict, bytes]:
        url = f"{self._base}/v1/wallets/{self._wallet_id}/rpc"
        body = json_body({"method": "eth_signTypedData_v4", "params": {"typed_data": {
            "domain": typed["domain"], "types": typed["types"], "primary_type": typed["primaryType"],
            "message": typed["message"]}}})
        headers = {"Content-Type": "application/json", "privy-app-id": self._app_id}
        headers.update(self._auth("POST", url, body))
        return "POST", url, headers, body

    def sign_typed_data(self, typed: dict) -> str:
        method, url, headers, body = self.request(typed)
        status, res = self._transport(method, url, headers, body)
        if status != 200:
            raise SignerError(f"Privy sign failed: HTTP {status}: {str(res)[:200]}")
        data = res.get("data") or {}
        if data.get("encoding", "hex") != "hex":
            raise SignerError("Privy returned a non-hex signature encoding")
        return check_sig(data.get("signature"))
