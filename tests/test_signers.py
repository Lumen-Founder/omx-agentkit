import base64
import json

import pytest
from eth_account import Account
from hyperliquid.utils import signing as sdk

from agentkit import unsigned as U
from agentkit.signers import (CdpServerWalletSigner, LocalKeyFileSigner, PrivySigner, Signer, SignerError,
                              TurnkeySigner, signature_hex)
from agentkit.signers import cdp, privy, turnkey
from conftest import BUILDER, NOW

ACT = U.order_action([U.order_wire(0, False, "100000", "0.001", False, "Ioc", None)], U.builder_field(BUILDER, 5))


@pytest.fixture(scope="module")
def acct():
    return Account.create()


def typed(mainnet=True):
    return U.unsigned_l1(ACT, NOW, is_mainnet=mainnet, expires_after=NOW + 10_000).typed_data


def test_local_key_file_signer_matches_sdk(tmp_path, acct):
    p = tmp_path / "throwaway.key"
    p.write_text(acct.key.hex(), encoding="utf-8")
    s = LocalKeyFileSigner(p)
    assert isinstance(s, Signer) and s.address() == acct.address
    assert "0x" not in repr(s).replace(acct.address, "")
    for mainnet in (True, False):
        sig = s.sign_typed_data(typed(mainnet))
        assert U.split_signature(sig) == sdk.sign_l1_action(acct, ACT, None, NOW, NOW + 10_000, mainnet)
    with pytest.raises(TypeError):
        import pickle
        pickle.dumps(s)


class FakeHttp:
    def __init__(self, reply):
        self.reply, self.calls = reply, []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, json.loads(body)))
        return self.reply(json.loads(body))


def sign_hex(acct, t):
    return "0x" + Account.sign_typed_data(acct.key, full_message=t).signature.hex()


def test_cdp_request_shape_and_result(acct):
    seen = []

    def auth(method, url, body):
        seen.append((method, url, body))
        return {"Authorization": "Bearer test-jwt", "X-Wallet-Auth": "test-wallet-jwt"}

    t = typed()
    http = FakeHttp(lambda b: (200, {"signature": sign_hex(acct, {**b})}))
    s = CdpServerWalletSigner(acct.address, auth, http)
    sig = s.sign_typed_data(t)
    method, url, headers, body = http.calls[0]
    assert method == "POST"
    assert url == f"https://api.cdp.coinbase.com/platform/v2/evm/accounts/{acct.address}/sign/typed-data"
    assert set(body) == {"domain", "types", "primaryType", "message"} and body["primaryType"] == "Agent"
    assert headers["Authorization"] == "Bearer test-jwt" and headers["X-Wallet-Auth"] == "test-wallet-jwt"
    assert 1 <= len(headers["X-Idempotency-Key"]) <= 128
    assert json.loads(seen[0][2]) == body                     # auth sees the exact body (reqHash)
    assert U.recover_signer(t, sig) == acct.address
    assert cdp.EXECUTED is False and cdp.DOC_URLS


def test_privy_request_shape_and_result(acct):
    basic = "Basic " + base64.b64encode(b"app-id:app-secret-from-user").decode()
    t = typed(False)

    def reply(b):
        td = b["params"]["typed_data"]
        full = {"domain": td["domain"], "types": td["types"], "primaryType": td["primary_type"], "message": td["message"]}
        return 200, {"method": "eth_signTypedData_v4", "data": {"signature": sign_hex(acct, full), "encoding": "hex"}}

    http = FakeHttp(reply)
    s = PrivySigner("wallet_123", acct.address, "app-id", lambda m, u, b: {"Authorization": basic}, http)
    sig = s.sign_typed_data(t)
    method, url, headers, body = http.calls[0]
    assert url == "https://api.privy.io/v1/wallets/wallet_123/rpc"
    assert body["method"] == "eth_signTypedData_v4"
    assert set(body["params"]["typed_data"]) == {"domain", "types", "primary_type", "message"}
    assert headers["privy-app-id"] == "app-id" and headers["Authorization"] == basic
    assert U.split_signature(sig) == sdk.sign_l1_action(acct, ACT, None, NOW, NOW + 10_000, False)
    assert privy.EXECUTED is False


@pytest.mark.parametrize("mode", ["digest", "eip712"])
@pytest.mark.parametrize("nested", [False, True])
def test_turnkey_request_shape_and_result(acct, mode, nested):
    t = typed()
    digest = U.typed_data_digest(t)

    def reply(b):
        sm = acct.unsafe_sign_hash(digest)
        res = {"signRawPayloadResult": {"r": f"{sm.r:064x}", "s": f"{sm.s:064x}", "v": f"{sm.v - 27:02x}"}}
        body = {"activity": {"status": "ACTIVITY_STATUS_COMPLETED",
                             "result": {"activity": {"result": res}} if nested else res}}
        return 200, body

    http = FakeHttp(reply)
    s = TurnkeySigner("org-1", acct.address, lambda m, u, b: {"X-Stamp": "stamp-from-user-key"}, http, mode=mode,
                      clock_ms=lambda: 1234)
    sig = s.sign_typed_data(t)
    _, url, headers, body = http.calls[0]
    assert url == "https://api.turnkey.com/public/v1/submit/sign_raw_payload"
    assert body["type"] == "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2" and body["timestampMs"] == "1234"
    assert body["organizationId"] == "org-1" and headers["X-Stamp"] == "stamp-from-user-key"
    p = body["parameters"]
    assert p["signWith"] == acct.address and p["hashFunction"] == "HASH_FUNCTION_NO_OP"
    if mode == "digest":
        assert p["encoding"] == "PAYLOAD_ENCODING_HEXADECIMAL" and p["payload"] == digest.hex()
    else:
        assert p["encoding"] == "PAYLOAD_ENCODING_EIP712" and json.loads(p["payload"]) == t
    assert U.recover_signer(t, sig) == acct.address
    assert turnkey.EXECUTED is False


def test_turnkey_pending_activity_is_an_error(acct):
    http = FakeHttp(lambda b: (200, {"activity": {"status": "ACTIVITY_STATUS_CONSENSUS_NEEDED", "result": {}}}))
    with pytest.raises(SignerError, match="CONSENSUS_NEEDED"):
        TurnkeySigner("org-1", acct.address, lambda *a: {}, http).sign_typed_data(typed())


def test_default_transport_never_touches_network(acct):
    for s in (CdpServerWalletSigner(acct.address, lambda *a: {}),
              PrivySigner("w1", acct.address, "app", lambda *a: {}),
              TurnkeySigner("org", acct.address, lambda *a: {})):
        with pytest.raises(SignerError, match="disabled"):
            s.sign_typed_data(typed())


def test_http_errors_and_bad_signatures(acct):
    with pytest.raises(SignerError, match="HTTP 401"):
        CdpServerWalletSigner(acct.address, lambda *a: {}, FakeHttp(lambda b: (401, {}))).sign_typed_data(typed())
    with pytest.raises(SignerError, match="65-byte"):
        CdpServerWalletSigner(acct.address, lambda *a: {}, FakeHttp(lambda b: (200, {"signature": "0x12"}))).sign_typed_data(typed())


def test_signature_hex_normalises_v():
    r, s = "0x" + "11" * 32, "22" * 32
    assert signature_hex(r, s, "00").endswith("1b") and signature_hex(r, s, 28).endswith("1c")
    with pytest.raises(SignerError):
        signature_hex(r, s, 5)
