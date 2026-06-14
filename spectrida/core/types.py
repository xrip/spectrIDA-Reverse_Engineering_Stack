"""Pure C-type-string helpers — no IDA dependency, fully unit-testable.

The in-IDA worker (`core/ida.py` ``_WORKER``) runs in a subprocess whose
``sys.path`` only has the idalib dir, so it can't import this module. It mirrors
a compact copy of this logic. THIS file is the canonical, tested source — keep the
worker's ``_type_idents`` / builtin sets in sync with the sets below.

Used to decide, before/after applying a type in IDA, whether a type string from
the LLM references a named type (struct/enum/typedef) that must exist in the type
library — so an unknown type is reported as a *dropped* field with a reason
instead of being silently ignored.
"""
from __future__ import annotations

import re

# C / IDA scalar types — never need a type-library lookup.
BUILTIN_TYPES: frozenset[str] = frozenset({
    "void", "bool", "_bool", "char", "short", "int", "long", "float", "double",
    "wchar_t", "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t",
    "__int8", "__int16", "__int32", "__int64", "__int128",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "_byte", "_word", "_dword", "_qword", "_oword", "_unknown",
    "byte", "word", "dword", "qword", "uchar", "ushort", "uint", "ulong",
})

# Qualifiers / storage / calling conventions — not types, dropped before lookup.
TYPE_KEYWORDS: frozenset[str] = frozenset({
    "const", "volatile", "struct", "union", "enum", "signed", "unsigned",
    "register", "static", "restrict", "__restrict", "__unaligned",
    "near", "far", "__ptr32", "__ptr64",
    "__cdecl", "__stdcall", "__fastcall", "__thiscall", "__usercall",
})

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def is_builtin_c_type(token: str) -> bool:
    """True if *token* is a C/IDA scalar that needs no type-library lookup."""
    return token.lower() in BUILTIN_TYPES


def extract_type_identifiers(type_str: str) -> list[str]:
    """Return the NAMED-type identifiers in a C type string (struct/enum/typedef
    names that must exist in the type library), dropping keywords and builtins.

        "struct Player *"   -> ["Player"]
        "const unsigned int"-> []
        "Foo **"            -> ["Foo"]
        "uint8_t *"         -> []

    Order-preserving, de-duplicated.
    """
    out: list[str] = []
    seen: set[str] = set()
    for tok in _IDENT_RE.findall(type_str or ""):
        low = tok.lower()
        if low in TYPE_KEYWORDS or low in BUILTIN_TYPES:
            continue
        if tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def normalize_type(type_str: str) -> str:
    """Whitespace-insensitive form for comparing an applied type to the intended
    one (read-back verification)."""
    return re.sub(r"\s+", "", type_str or "")


def types_match(applied: str, intended: str) -> bool:
    """Lenient equality between an applied type and the intended one — tolerates
    spacing and qualifier reordering by falling back to (named idents + pointer
    depth) comparison."""
    if normalize_type(applied) == normalize_type(intended):
        return True
    return (
        sorted(extract_type_identifiers(applied)) == sorted(extract_type_identifiers(intended))
        and (applied or "").count("*") == (intended or "").count("*")
    )
