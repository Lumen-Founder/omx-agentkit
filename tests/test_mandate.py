from dataclasses import replace
from decimal import Decimal

import pytest

from agentkit.mandate import (CONTROL_ORDER, MandateError, MarketView, OrderSpec, check, mandate_hash,
                              validate_mandate)
from conftest import BUILDER, NOW

B = (BUILDER, 10)
EXP = NOW + 15_000


def run(mandate, order, market, account, **kw):
    kw.setdefault("builder", B)
    kw.setdefault("expires_after", EXP)
    return check(mandate, order, market, account, NOW, **kw)


def test_valid_order_passes_every_control(mandate, order, market, account):
    d = run(mandate, order, market, account)
    assert d.allow, d.reasons
    assert list(d.to_dict()["controls"]) == list(CONTROL_ORDER)
    assert all(c["pass"] for c in d.controls.values())
    assert d.mandate_hash == mandate_hash(mandate) and len(d.mandate_hash) == 64


def test_hash_is_key_order_independent(mandate):
    assert mandate_hash(dict(reversed(list(mandate.items())))) == mandate_hash(mandate)


@pytest.mark.parametrize("mutate,msg", [
    (lambda m: m["notional"].update(count_resting_orders=False), "count_resting_orders"),
    (lambda m: m["daily_loss"].update(excludes_external_flows=False), "excludes_external_flows"),
    (lambda m: m["kill_switch"].update(clear_requires="agent"), "clear_requires"),
    (lambda m: m["builder_fee"].update(max_tenths_bps=101), "max_tenths_bps"),
    (lambda m: m.update(private_key="0x" + "11" * 32), "secret"),
    (lambda m: m["notional"]["per_coin_usd"].update(SOL=1.0), "outside coins.allowed"),
    (lambda m: m["builder_fee"].pop("builder"), "requires builder_fee.builder"),
    (lambda m: m.update(unknown_field=1), "unknown_field"),
    (lambda m: m.update(issued_at="yesterday"), "RFC 3339"),
])
def test_invalid_mandates_are_refused(mandate, mutate, msg):
    mutate(mandate)
    with pytest.raises(MandateError, match=msg):
        validate_mandate(mandate)


def test_extension_fields_allowed(mandate):
    mandate["x-operator-note"] = "fine"
    validate_mandate(mandate)


def blocked(d, reason_prefix, control):
    assert not d.allow
    assert any(r.startswith(reason_prefix) for r in d.reasons), d.reasons
    assert d.controls[control]["pass"] is False


def test_kill_switch(mandate, order, market, account):
    mandate["kill_switch"]["engaged"] = True
    blocked(run(mandate, order, market, account), "KILL_SWITCH_ACTIVE", "kill_switch")


def test_mandate_out_of_force(mandate, order, market, account):
    mandate["expires_at"] = "2025-11-02T00:00:00Z"
    blocked(run(mandate, order, market, account), "MANDATE_NOT_IN_FORCE", "mandate_valid")


def test_coin_allowlist(mandate, market, account):
    o = OrderSpec("SOL", True, Decimal("1"), Decimal("150"))
    blocked(run(mandate, o, MarketView("SOL", 150.0, NOW), account), "COIN_NOT_ALLOWED", "coin_allowlist")


def test_stale_and_missing_data(mandate, order, account):
    blocked(run(mandate, order, MarketView("ETH", 3500.0, NOW - 3001), account), "STALE", "data_freshness")
    blocked(run(mandate, order, MarketView("ETH", None, NOW), account), "STALE", "data_freshness")


def test_price_band(mandate, market, account):
    o = OrderSpec("ETH", True, Decimal("0.1"), Decimal("3540"))       # +114 bps
    blocked(run(mandate, o, market, account), "PRICE_OUTSIDE_BAND", "price_band")
    o = OrderSpec("ETH", False, Decimal("0.1"), Decimal("3540"))      # the band is symmetric, as in OMX
    blocked(run(mandate, o, market, account), "PRICE_OUTSIDE_BAND", "price_band")


def test_child_size(mandate, market, account):
    o = OrderSpec("ETH", True, Decimal("0.6"), Decimal("3500"))       # 2100 > 2000
    blocked(run(mandate, o, market, account), "CHILD_NOTIONAL_CAP", "child_size")


def test_coin_notional_counts_resting_orders(mandate, order, market, account):
    assert run(mandate, order, market, account).allow
    account.positions["ETH"] = 0.5
    account.open_orders = [{"coin": "ETH", "is_buy": True, "sz": 0.8, "px": 3400.0, "reduce_only": False}]
    # (0.5 + 0.8 + 0.2) * 3500 = 5250 > 5000, though the position alone is 1750
    blocked(run(mandate, order, market, account), "COIN_NOTIONAL_CAP", "coin_notional")


def test_account_notional_across_coins(mandate, order, market, account):
    account.positions["BTC"] = 0.075                                   # 7500 + 702 <= 12000
    assert run(mandate, order, market, account).allow
    account.open_orders = [{"coin": "BTC", "is_buy": True, "sz": 0.004, "px": 99000.0, "reduce_only": False}]
    account.positions["ETH"] = 1.0                                     # 7900 + 4200 > 12000
    blocked(run(mandate, order, market, account), "ACCOUNT_NOTIONAL_CAP", "account_notional")


def test_exposed_coin_without_mark_blocks(mandate, order, market, account):
    account.positions["DOGE"] = 100.0
    blocked(run(mandate, order, market, account), "NO_MARK:DOGE", "account_notional")


def test_leverage(mandate, order, market, account):
    account.equity_usd = account.day_start_equity_usd = 200.0          # 702 / 200 = 3.5x
    blocked(run(mandate, order, market, account), "LEVERAGE_CAP", "leverage")


def test_daily_loss_excludes_deposits(mandate, order, market, account):
    account.equity_usd = 4790.0                                        # -210 on the day
    blocked(run(mandate, order, market, account), "DAILY_LOSS_LIMIT", "daily_loss")
    account.equity_usd, account.external_flows_usd = 5790.0, 1000.0   # deposit after the loss
    d = run(mandate, order, market, account)
    blocked(d, "DAILY_LOSS_LIMIT", "daily_loss")
    assert d.controls["daily_loss"]["value"] == -210.0


def test_human_approval_threshold(mandate, market, account):
    o = OrderSpec("ETH", True, Decimal("0.5"), Decimal("3500"))       # 1750 > 1500
    d = run(mandate, o, market, account)
    blocked(d, "HUMAN_APPROVAL_REQUIRED", "human_approval")
    assert d.needs_human_approval
    d = run(mandate, o, market, account, approval_ref="ap-123")
    assert d.allow and "not verified" in d.controls["human_approval"]["note"]


def test_builder_fee(mandate, order, market, account):
    blocked(run(mandate, order, market, account, builder=(BUILDER, 11)), "BUILDER_FEE_NOT_ACCEPTED", "builder_fee")
    blocked(run(mandate, order, market, account, builder=("0x" + "cc" * 20, 5)), "BUILDER_FEE", "builder_fee")
    mandate["builder_fee"]["accepted"] = False
    blocked(run(mandate, order, market, account), "BUILDER_FEE_NOT_ACCEPTED", "builder_fee")
    assert run(mandate, order, market, account, builder=None).controls["builder_fee"]["pass"]


def test_order_expiry(mandate, order, market, account):
    blocked(run(mandate, order, market, account, expires_after=None), "EXPIRES_AFTER_REQUIRED", "order_expiry")
    blocked(run(mandate, order, market, account, expires_after=NOW + 60_001), "EXPIRES_AFTER", "order_expiry")
    blocked(run(mandate, order, market, account, expires_after=NOW), "EXPIRES_AFTER", "order_expiry")


def test_reduce_only_that_reduces_skips_risk_caps(mandate, market, account):
    account.positions["ETH"] = 2.0
    account.equity_usd = 500.0
    o = OrderSpec("ETH", False, Decimal("0.3"), Decimal("3490"), reduce_only=True)
    d = run(mandate, o, market, account)
    assert d.allow, d.reasons
    o = replace(o, is_buy=True)
    blocked(run(mandate, o, market, account), "REDUCE_ONLY_WOULD_INCREASE", "reduce_only")


def test_spec_example_validates():
    import json
    from conftest import ROOT
    validate_mandate(json.loads((ROOT / "spec" / "examples" / "mandate.example.json").read_text(encoding="utf-8")))
