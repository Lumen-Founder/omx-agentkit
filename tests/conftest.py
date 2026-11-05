import copy
import importlib.util
import os
import sys
from decimal import Decimal
from pathlib import Path

import pytest

sys.dont_write_bytecode = True          # never write __pycache__ into the read-only OMX repo
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# The OMX checkout (github.com/Lumen-Founder/omx): $OMX_REPO, else $OMX_ROOT, else ../omx next to this repo.
# Tests that need it are skipped when it is absent.
OMX_REPO = Path(os.environ.get("OMX_REPO") or os.environ.get("OMX_ROOT") or ROOT.parent / "omx")

NOW = 1_762_300_800_000                 # 2025-11-05T00:00:00Z
BUILDER = "0x" + "b1" * 20
ACCOUNT = "0x" + "a0" * 20

MANDATE = {
    "mandate_version": "atm/0",
    "mandate_id": "test-mandate-1",
    "issued_at": "2025-11-01T00:00:00Z",
    "expires_at": "2026-11-01T00:00:00Z",
    "operator": {"name": "test operator"},
    "venue": "hyperliquid",
    "network": "testnet",
    "account": ACCOUNT,
    "agents": ["agent:test"],
    "coins": {"allowed": ["BTC", "ETH"]},
    "notional": {"per_coin_usd": {"BTC": 8000}, "default_per_coin_usd": 5000, "account_usd": 12000,
                 "count_resting_orders": True},
    "leverage": {"max": 3.0},
    "daily_loss": {"max_usd": 200, "excludes_external_flows": True, "day_boundary": "UTC"},
    "price_band": {"max_bps_vs_mid": 100},
    "data_freshness": {"max_age_ms": 3000},
    "child_order": {"max_notional_usd": 2000},
    "kill_switch": {"engaged": False, "clear_requires": "human"},
    "human_approval": {"above_notional_usd": 1500},
    "builder_fee": {"accepted": True, "builder": BUILDER, "max_tenths_bps": 10,
                    "disclosure": "1 bps builder fee per fill, approved by the user's main wallet"},
    "order_expiry": {"max_ms": 60000},
}


@pytest.fixture
def mandate():
    return copy.deepcopy(MANDATE)


@pytest.fixture
def account():
    from agentkit.mandate import AccountView
    return AccountView(equity_usd=5000.0, day_start_equity_usd=5000.0, external_flows_usd=0.0,
                       positions={}, open_orders=[], marks={"BTC": 100000.0, "ETH": 3500.0})


@pytest.fixture
def market():
    from agentkit.mandate import MarketView
    return MarketView(coin="ETH", mid=3500.0, ts_ms=NOW - 500)


@pytest.fixture
def order():
    from agentkit.mandate import OrderSpec
    return OrderSpec(coin="ETH", is_buy=True, sz=Decimal("0.2"), px=Decimal("3510"), tif="Gtc")


@pytest.fixture(scope="session")
def omx_audit():
    """OMX's AuditLog, loaded read-only from its source file (no package import, no bytecode written)."""
    path = OMX_REPO / "omx" / "audit.py"
    if not path.exists():
        pytest.skip(f"OMX source not found at {path}")
    spec = importlib.util.spec_from_file_location("omx_audit_readonly", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
