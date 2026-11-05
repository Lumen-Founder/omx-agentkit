import copy
import json

import pytest

from agentkit import discovery as D

P = D.load_product()
FILES = D.render_all(P)


def test_public_files_match_product_toml():
    for rel, text in FILES.items():
        assert (D.ROOT / "public" / rel).read_text(encoding="utf-8") == text, f"{rel} is stale"


@pytest.mark.parametrize("rel", sorted(FILES))
def test_each_file_validates(rel):
    assert D.check_file(rel, FILES[rel]) == []


def test_one_source_of_truth():
    url = P["product"]["base_url"]
    assert json.loads(FILES["server.json"])["remotes"][0]["url"] == url + "/mcp"
    assert json.loads(FILES["openapi.json"])["servers"][0]["url"] == url
    x402 = json.loads(FILES[".well-known/x402"])
    assert x402["resources"][0]["accepts"][0]["amount"] == "10000"          # 0.01 USDC, 6 decimals
    assert x402["resources"][0]["accepts"][0]["payTo"] == "UNSET-NOT-DEPLOYED"
    card = json.loads(FILES[".well-known/agent-card.json"])
    assert [s["id"] for s in card["skills"]] == [t["name"] for t in P["tools"]]
    assert "omx_pretrade_quote" in FILES["llms.txt"]


def bad(rel, fn):
    doc = json.loads(FILES[rel])
    fn(doc)
    return D.check_file(rel, json.dumps(doc))


def test_schemas_catch_errors():
    assert bad("server.json", lambda d: d.update(description="x" * 101))
    assert bad("server.json", lambda d: d.update(name="no-slash"))
    assert bad("server.json", lambda d: d["remotes"][0].update(type="websocket"))
    assert bad("openapi.json", lambda d: d.pop("info"))
    assert bad(".well-known/agent-card.json", lambda d: d.pop("skills"))
    assert bad(".well-known/agent-card.json", lambda d: d["supportedInterfaces"][0].pop("protocolVersion"))
    assert bad(".well-known/x402", lambda d: d.update(kind="shop"))
    assert bad(".well-known/x402", lambda d: d["resources"][0]["accepts"][0].pop("payTo"))
    assert bad(".well-known/x402", lambda d: d["resources"][0].update(url="https://evil.example/x"))
    assert D.check_llms_txt("no title\n")
    assert D.check_llms_txt("# T\n\n## Docs\n\nplain text in a section\n")
