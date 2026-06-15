"""Compact user-type catalogue injected into the (cached) system prompt."""
from spectrida.core.backend import format_local_types


def test_format_struct_and_enum():
    block = format_local_types({
        "structs": [{"name": "Player", "fields": 12, "size": 0x148}],
        "enums":   [{"name": "Color", "members": 5, "size": 4}],
    })
    assert "Player(12f,0x148)" in block
    assert "Color(5m,0x4)" in block
    assert "Structs/unions:" in block and "Enums:" in block


def test_format_empty_is_blank():
    assert format_local_types({}) == ""
    assert format_local_types({"structs": [], "enums": []}) == ""


def test_format_unknown_count_omits_count():
    block = format_local_types({"structs": [{"name": "Opaque", "fields": -1, "size": 0}]})
    assert "Opaque" in block
    assert "Opaque(" not in block          # no count, no size → bare name


def test_format_size_only():
    block = format_local_types({"structs": [{"name": "Blob", "fields": -1, "size": 16}]})
    assert "Blob(0x10)" in block


def test_format_legacy_string_entries():
    block = format_local_types({"structs": ["LegacyName"], "enums": ["OldEnum"]})
    assert "LegacyName" in block and "OldEnum" in block


def test_format_truncates():
    structs = [{"name": f"S{i}", "fields": i, "size": 4} for i in range(500)]
    block = format_local_types({"structs": structs}, max_structs=10)
    assert block.count("S") >= 10
    assert "S400" not in block             # tail dropped
