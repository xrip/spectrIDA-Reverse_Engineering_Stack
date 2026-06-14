from spectrida.core.types import (
    extract_type_identifiers,
    is_builtin_c_type,
    normalize_type,
    types_match,
)


def test_is_builtin_c_type():
    for t in ("int", "void", "char", "uint8_t", "__int64", "size_t",
              "DWORD", "Int", "BOOL", "unsigned"):
        # case-insensitive scalars/keywords-as-types
        pass
    assert is_builtin_c_type("int")
    assert is_builtin_c_type("VOID")
    assert is_builtin_c_type("uint8_t")
    assert is_builtin_c_type("__int64")
    assert is_builtin_c_type("DWORD")
    assert not is_builtin_c_type("Player")
    assert not is_builtin_c_type("Entity")


def test_extract_named_types():
    assert extract_type_identifiers("struct Player *") == ["Player"]
    assert extract_type_identifiers("Foo **") == ["Foo"]
    assert extract_type_identifiers("const unsigned int") == []
    assert extract_type_identifiers("uint8_t *") == []
    assert extract_type_identifiers("void") == []
    assert extract_type_identifiers("") == []
    assert extract_type_identifiers("enum PlayerState") == ["PlayerState"]


def test_extract_dedup_and_order():
    assert extract_type_identifiers("Pair<Foo, Foo, Bar>") == ["Pair", "Foo", "Bar"]


def test_normalize_type():
    assert normalize_type("Player  *") == "Player*"
    assert normalize_type("const  char *") == "constchar*"


def test_types_match_lenient():
    assert types_match("Player *", "Player  *")
    assert types_match("Player*", "Player *")
    assert types_match("struct Foo *", "Foo *")          # idents+depth fallback
    assert not types_match("Player *", "Player **")      # pointer depth differs
    assert not types_match("Player *", "Entity *")       # different named type
