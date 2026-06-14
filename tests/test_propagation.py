"""D — return-type propagation to caller variables."""
import asyncio

from spectrida.api import _worth_propagating, open_demo
from spectrida.core import demo


def test_worth_propagating():
    assert _worth_propagating("Player *")
    assert _worth_propagating("Foo")          # named struct/enum
    assert _worth_propagating("void *")       # pointer
    assert not _worth_propagating("int")
    assert not _worth_propagating("unsigned __int64")
    assert not _worth_propagating("")


def test_name_all_propagates_pointer_return(monkeypatch):
    async def run():
        async with open_demo() as db:
            addr = demo.FUNCTIONS[3]["start"]

            def staged(pc, lvars, callees, callers, history=None, glossary=""):
                return {"name": "get_player", "reason": "x",
                        "ret_type": "Player *", "variables": {}}
            monkeypatch.setattr(demo, "name_function_staged", staged)

            r = await db.name_all(addr, rename=True)
            assert r["ret_type"] == "Player *"
            assert r["propagated"] == len(demo.xrefs_to(addr))
            assert r["propagated"] >= 1

    asyncio.run(run())


def test_scalar_return_not_propagated(monkeypatch):
    async def run():
        async with open_demo() as db:
            addr = demo.FUNCTIONS[3]["start"]
            called = {"n": 0}

            def staged(pc, lvars, callees, callers, history=None, glossary=""):
                return {"name": "compute", "reason": "x", "ret_type": "int", "variables": {}}
            monkeypatch.setattr(demo, "name_function_staged", staged)
            monkeypatch.setattr(demo, "propagate_ret",
                                lambda ad: called.__setitem__("n", called["n"] + 1) or {})

            r = await db.name_all(addr, rename=True)
            assert called["n"] == 0            # scalar return → no propagation call
            assert r["propagated"] == 0

    asyncio.run(run())


def test_propagation_disabled(monkeypatch):
    monkeypatch.setenv("SPECTRIDA_TYPE_PROPAGATION", "0")

    async def run():
        async with open_demo() as db:
            addr = demo.FUNCTIONS[3]["start"]
            called = {"n": 0}

            def staged(pc, lvars, callees, callers, history=None, glossary=""):
                return {"name": "get_player", "reason": "x",
                        "ret_type": "Player *", "variables": {}}
            monkeypatch.setattr(demo, "name_function_staged", staged)
            monkeypatch.setattr(demo, "propagate_ret",
                                lambda ad: called.__setitem__("n", called["n"] + 1) or {})

            r = await db.name_all(addr, rename=True)
            assert called["n"] == 0
            assert r["propagated"] == 0

    asyncio.run(run())
