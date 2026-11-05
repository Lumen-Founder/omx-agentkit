import json
from decimal import Decimal

import pytest
from eth_account import Account
from hyperliquid.utils import signing as sdk
from hyperliquid.utils.types import Cloid

from agentkit import unsigned as U
from agentkit.mandate import MandateBlocked, OrderSpec
from conftest import BUILDER, NOW

NONCE, EXP = NOW, NOW + 15_000
CLOID = "0x4f4d580112345678" + "9a" * 8
VAULT = "0x" + "7e" * 20


@pytest.fixture(scope="module")
def key():
    return Account.create()                                   # throwaway, in memory only


def sdk_action(builder=True):
    w = sdk.order_request_to_order_wire({"coin": "ETH", "is_buy": True, "sz": 0.0123, "limit_px": 3456.7,
                                         "order_type": {"limit": {"tif": "Alo"}}, "reduce_only": False,
                                         "cloid": Cloid(CLOID)}, 4)
    return sdk.order_wires_to_order_action([w], {"b": BUILDER, "f": 10} if builder else None)


def our_action():
    return U.order_action([U.order_wire(4, True, "3456.7", "0.0123", False, "Alo", CLOID)],
                          U.builder_field(BUILDER.upper().replace("0X", "0x"), 10))


def test_action_matches_sdk_bytes():
    import msgpack
    assert our_action() == sdk_action()
    assert msgpack.packb(our_action()) == msgpack.packb(sdk_action())
    assert list(our_action()) == ["type", "orders", "grouping", "builder"]
    assert list(our_action()["orders"][0]) == ["a", "b", "p", "s", "r", "t", "c"]


@pytest.mark.parametrize("mainnet", [True, False])
@pytest.mark.parametrize("vault", [None, VAULT])
@pytest.mark.parametrize("expires", [None, EXP])
def test_signature_equals_sdk_sign_l1_action(key, mainnet, vault, expires):
    act = our_action()
    want = sdk.sign_l1_action(key, sdk_action(), vault, NONCE, expires, mainnet)
    u = U.unsigned_l1(act, NONCE, is_mainnet=mainnet, vault_address=vault, expires_after=expires)
    assert u.connection_id == "0x" + sdk.action_hash(sdk_action(), vault, NONCE, expires).hex()
    assert u.typed_data["message"]["source"] == ("a" if mainnet else "b")
    typed = json.loads(json.dumps(u.typed_data))               # what an external signer receives over JSON
    sig = Account.sign_typed_data(key.key, full_message=typed).signature
    assert U.split_signature(sig) == want
    assert U.recover_signer(typed, sig) == key.address
    payload = U.assemble(json.loads(json.dumps(act)), NONCE, "0x" + sig.hex(), vault_address=vault,
                         expires_after=expires, is_mainnet=mainnet, expected_signer=key.address)
    assert payload == {"action": sdk_action(), "nonce": NONCE, "signature": want, "vaultAddress": vault,
                       "expiresAfter": expires}


def test_typed_data_shape_matches_sdk_l1_payload():
    h = sdk.action_hash(sdk_action(), None, NONCE, EXP)
    ours = U.l1_typed_data(h, True)
    theirs = sdk.l1_payload(sdk.construct_phantom_agent(h, True))
    assert ours["domain"] == theirs["domain"] and ours["types"] == theirs["types"]
    assert ours["primaryType"] == theirs["primaryType"] == "Agent"
    assert ours["message"] == {"source": "a", "connectionId": "0x" + h.hex()}
    from eth_account.messages import encode_typed_data
    assert encode_typed_data(full_message=ours) == encode_typed_data(full_message=theirs)
    assert U.typed_data_digest(ours) == U.typed_data_digest(theirs)


def test_expires_after_is_inside_the_hash():
    a = U.action_hash(our_action(), None, NONCE, None)
    b = U.action_hash(our_action(), None, NONCE, EXP)
    c = U.action_hash(our_action(), None, NONCE, EXP + 1)
    assert len({a, b, c}) == 3
    import msgpack
    from eth_utils import keccak
    raw = msgpack.packb(our_action()) + NONCE.to_bytes(8, "big") + b"\x00" + b"\x00" + EXP.to_bytes(8, "big")
    assert b == keccak(raw)


def test_cancel_actions_sign_like_sdk(key):
    act = U.cancel_action([(4, 123456)])
    assert act == {"type": "cancel", "cancels": [{"a": 4, "o": 123456}]}
    u = U.build_cancel([(4, 123456)], nonce=NONCE, expires_after=EXP, is_mainnet=False)
    sig = Account.sign_typed_data(key.key, full_message=u.typed_data).signature
    assert U.split_signature(sig) == sdk.sign_l1_action(key, act, None, NONCE, EXP, False)
    assert U.cancel_by_cloid_action([(4, CLOID)]) == {"type": "cancelByCloid", "cancels": [{"asset": 4, "cloid": CLOID}]}


def test_assemble_refuses_wrong_signer(key):
    u = U.unsigned_l1(our_action(), NONCE, is_mainnet=True, expires_after=EXP)
    sig = Account.sign_typed_data(key.key, full_message=u.typed_data).signature
    with pytest.raises(U.BuildError, match="recovers to"):
        U.assemble(our_action(), NONCE, sig, expires_after=EXP, is_mainnet=True, expected_signer="0x" + "11" * 20)
    with pytest.raises(U.BuildError, match="recovers to"):              # signed for mainnet, claimed testnet
        U.assemble(our_action(), NONCE, sig, expires_after=EXP, is_mainnet=False, expected_signer=key.address)


def test_build_order_runs_mandate_first(mandate, market, account, order):
    u = U.build_order(order, asset=4, mandate=mandate, market=market, account=account, builder=(BUILDER, 10),
                      nonce=NONCE, expires_after=EXP, now_ms=NOW, is_mainnet=False, cloid=CLOID)
    assert u.action["builder"] == {"b": BUILDER, "f": 10}
    assert u.action["orders"][0] == {"a": 4, "b": True, "p": "3510", "s": "0.2", "r": False,
                                     "t": {"limit": {"tif": "Gtc"}}, "c": CLOID}
    assert u.expires_after == EXP and u.decision.allow
    assert u.to_dict()["mandate_decision"]["allow"] is True


@pytest.mark.parametrize("kw,reason", [
    (dict(order=OrderSpec("SOL", True, Decimal("1"), Decimal("150"))), "COIN_NOT_ALLOWED"),
    (dict(builder=(BUILDER, 20)), "BUILDER_FEE_NOT_ACCEPTED"),
    (dict(expires_after=NOW + 120_000), "EXPIRES_AFTER_OUT_OF_RANGE"),
])
def test_build_order_refuses_blocked(mandate, market, account, order, kw, reason):
    args = dict(order=order, asset=4, mandate=mandate, market=market, account=account, builder=(BUILDER, 10),
                nonce=NONCE, expires_after=EXP, now_ms=NOW, is_mainnet=False)
    args.update(kw)
    o = args.pop("order")
    with pytest.raises(MandateBlocked) as e:
        U.build_order(o, **args)
    assert any(r.startswith(reason) for r in e.value.decision.reasons)


def test_build_order_refuses_network_mismatch_and_bad_builder(mandate, market, account, order):
    with pytest.raises(U.BuildError, match="network"):
        U.build_order(order, asset=4, mandate=mandate, market=market, account=account, builder=(BUILDER, 10),
                      nonce=NONCE, expires_after=EXP, now_ms=NOW, is_mainnet=True)
    with pytest.raises(U.BuildError, match="venue cap"):
        U.builder_field(BUILDER, 101)
    U.builder_field(BUILDER, 1000, spot=True)


def test_rounding_helpers():
    assert U.round_px(3456.789, 4) == Decimal("3456.8")
    assert U.round_px(0.000123456, 0) == Decimal("0.000123")
    assert U.round_sz(0.123456, 4) == Decimal("0.1234")
    assert U.wire_str(Decimal("1.2300")) == "1.23" == sdk.float_to_wire(1.23)
    assert U.wire_str("3510") == sdk.float_to_wire(3510.0)
