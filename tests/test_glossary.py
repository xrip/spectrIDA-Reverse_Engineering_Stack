import asyncio

from spectrida.api import open_demo
from spectrida.core.demo import FUNCTIONS
from spectrida.core.glossary import Glossary, _tokens


def test_tokens_splits_camel_snake_and_class():
    assert _tokens("Player$$TakeDamage") == ["player", "take", "damage"]
    assert _tokens("send_udp_packet") == ["send", "udp", "packet"]
    assert _tokens("parsePEHeader") == ["parse", "pe", "header"]


def test_add_name_skips_sub_and_dedups_to_recent():
    g = Glossary()
    g.add_name(0x1000, "sub_1000")          # skipped
    g.add_name(0x2000, "parse_packet")
    g.add_name(0x3000, "send_packet")
    assert len(g) == 2
    # re-adding 0x2000 moves it to most-recent (last)
    g.add_name(0x2000, "parse_packet_v2")
    last = list(g.names.values())[-1]["name"]
    assert last == "parse_packet_v2"


def test_render_empty_is_blank():
    assert Glossary().render() == ""


def test_render_includes_names_and_vocabulary():
    g = Glossary()
    for addr, nm in [(1, "parse_packet"), (2, "send_packet"),
                     (3, "build_packet"), (4, "init_world")]:
        g.add_name(addr, nm)
    out = g.render()
    assert "=== PROJECT GLOSSARY ===" in out
    assert "parse_packet" in out and "init_world" in out
    # "packet" stem shared by 3 names → in the vocabulary line
    assert "packet" in out.split("Names already assigned")[0]


def test_vocabulary_requires_repetition():
    g = Glossary()
    g.add_name(1, "alpha_one")
    g.add_name(2, "beta_two")
    # no stem shared ≥2 → empty vocab (names still rendered)
    assert g.vocabulary() == []


def test_add_term_dedup():
    g = Glossary()
    g.add_term("Networking", "networking", "Physics")
    assert g.terms == ["Networking", "Physics"]


def test_glossary_seeds_and_accumulates_through_name_all():
    async def run():
        async with open_demo() as db:
            b = db._b
            sub_addrs = [f["start"] for f in FUNCTIONS if f["name"].startswith("sub_")]

            r1 = await db.name_all(sub_addrs[0], rename=True)
            g1 = b.last_glossary
            # seeded from the demo's already-named functions
            assert "=== PROJECT GLOSSARY ===" in g1
            assert ("Player" in g1 or "TakeDamage" in g1)

            r2 = await db.name_all(sub_addrs[1], rename=True)
            # the name just assigned to the first sub_ is now in the glossary
            assert r1["new_name"]
            assert r1["new_name"] in b.last_glossary
            assert r2["new_name"]

    asyncio.run(run())
