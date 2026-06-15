"""B — content-addressed naming cache: clones collapse, re-runs are cheap."""
import asyncio

from spectrida.core import namecache
from spectrida.core.namecache import NameCache, key, key_global, normalize_code
from spectrida.core import demo
from spectrida.api import open_demo
from spectrida.core.demo import FUNCTIONS


def test_normalize_collapses_clones():
    a = "v1 = sub_140001000(a1); return *(_DWORD *)(a1 + 0x40) + 5;"
    b = "v7 = sub_1400ABCDE(a3); return *(_DWORD *)(a3 + 0x18) + 9;"
    # differ only in addresses / sub_ ids / aN-vN / numeric literals
    assert normalize_code(a) == normalize_code(b)


def test_key_stability_and_sensitivity():
    pc_a = "v1 = sub_1(a1); return a1->f;"
    pc_b = "v9 = sub_2(a3); return a3->f;"
    k1 = key(pc_a, ["sub_1000"], [], {"api_calls": ["send"]})
    k2 = key(pc_b, ["sub_2000"], [], {"api_calls": ["send"]})
    assert k1 == k2                                  # clones → same key
    # a distinctive hint (different API) must change the key
    k3 = key(pc_a, ["sub_1000"], [], {"api_calls": ["recv"]})
    assert k1 != k3


def test_cache_get_put_and_disabled():
    c = NameCache(enabled=True)
    assert c.get("k") is None
    c.put("k", {"name": "parse_header", "ret_type": "int", "variables": {"a1": {"name": "buf"}}})
    assert c.get("k")["name"] == "parse_header"
    c.put("k2", {"name": ""})                        # empty result is never stored
    assert c.get("k2") is None

    off = NameCache(enabled=False)
    off.put("k", {"name": "x"})
    assert off.get("k") is None


def test_key_global_namespaced_and_stable():
    gi = {"size": 4, "cur_type": ""}
    sites = [{"func_name": "GameManager__Update", "access": ["read", "write"],
              "snippet": "if ( dword_140030010 < 4 ) ++dword_140030010;"}]
    k1 = key_global(gi, sites)
    k2 = key_global(dict(gi), [dict(sites[0])])
    assert k1 == k2                                   # stable for identical input
    assert k1.startswith("g:")                        # namespaced vs function keys
    # a changed use site re-keys
    sites2 = [{"func_name": "Other__Func", "access": ["read"], "snippet": "x"}]
    assert key_global(gi, sites2) != k1


def test_put_global_roundtrip(tmp_path):
    c = NameCache()
    c.put_global("g:abc", {"name": "g_player_count", "type": "int"})
    assert c.get("g:abc") == {"name": "g_player_count", "type": "int"}
    c.put_global("g:empty", {"name": "", "type": ""})    # non-result not stored
    assert c.get("g:empty") is None
    p = str(tmp_path / "names.json")
    c.save(p)
    assert NameCache().load(p).get("g:abc")["name"] == "g_player_count"


def test_save_load_roundtrip(tmp_path):
    p = str(tmp_path / "names.json")
    c = NameCache()
    c.put("abc", {"name": "send_packet", "ret_type": "void", "variables": {}})
    c.save(p)

    c2 = NameCache().load(p)
    assert c2.get("abc")["name"] == "send_packet"


def test_name_all_uses_cache_hit(monkeypatch):
    """A pre-seeded key → name_all reuses it and never calls the model."""
    async def run():
        async with open_demo() as db:
            calls = {"n": 0}
            orig = demo.name_function_staged

            def counting(*a, **k):
                calls["n"] += 1
                return orig(*a, **k)
            monkeypatch.setattr(demo, "name_function_staged", counting)
            monkeypatch.setattr(namecache, "key", lambda *a, **k: "FIXED")

            db._cache.put("FIXED", {"name": "cached_name", "ret_type": "void",
                                    "variables": {}})
            addr = next(f["start"] for f in FUNCTIONS if f["name"].startswith("sub_"))
            r = await db.name_all(addr, rename=True)
            assert r["new_name"] == "cached_name"
            assert r["source"] == "cache"
            assert calls["n"] == 0                    # model not called on a hit

    asyncio.run(run())


def test_name_all_populates_cache_on_miss(monkeypatch):
    async def run():
        async with open_demo() as db:
            monkeypatch.setattr(namecache, "key", lambda *a, **k: "MISSKEY")
            addr = next(f["start"] for f in FUNCTIONS if f["name"].startswith("sub_"))
            assert db._cache.get("MISSKEY") is None
            await db.name_all(addr, rename=True)
            assert db._cache.get("MISSKEY") is not None   # put() happened

    asyncio.run(run())
