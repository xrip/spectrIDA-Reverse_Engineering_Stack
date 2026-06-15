"""Pure name-canonicalisation linter (C) — no IDA dependency, unit-testable.

The model names each function well *locally*, but across a whole binary the same
concept drifts into variant spellings (``send_message`` vs ``send_msg``,
``recv_buffer`` vs ``receive_buf``) and the odd typo. C is a consistency linter:
it unifies equivalent tokens to the form THIS binary already uses most, and fixes
always-wrong spellings — so the symbol set reads as one hand.

Design choices that keep it safe:
  * the canonical token is **data-driven** — whichever variant is most frequent in
    the corpus wins (ties fall back to the conventional RE abbreviation). The
    linter therefore only touches names when the binary is *already* inconsistent;
    it never imposes an abbreviation the binary doesn't use. Typos are always fixed.
  * only **multi-token snake_case** names are rewritten (``^[a-z][a-z0-9]*(_…)+$``).
    Single-token names (``memcpy``, ``recv``, ``strlen``), library/runtime symbols
    (``__chkstk``, ``_except_handler``), C++/mangled names and class-style names
    (uppercase, ``$$``, ``::``) are left untouched.
"""
from __future__ import annotations

import re

# Equivalent-token groups. The FIRST entry is the conventional RE abbreviation,
# used as the default when the corpus has no majority. Every member maps to the
# corpus-chosen representative at lint time.
_EQUIV_GROUPS: tuple[tuple[str, ...], ...] = (
    ("init", "initialize", "initialise", "initialization", "initialisation"),
    ("recv", "receive"),
    ("send", "transmit"),
    ("msg", "message"),
    ("buf", "buffer"),
    ("len", "length"),
    ("ptr", "pointer"),
    ("addr", "address"),
    ("idx", "index"),
    ("num", "number"),
    ("cnt", "count"),
    ("cfg", "config", "configuration"),
    ("alloc", "allocate"),
    ("calc", "calculate"),
    ("str", "string"),
    ("attr", "attribute"),
    ("ctx", "context"),
    ("desc", "descriptor", "description"),
    ("err", "error"),
    ("req", "request"),
    ("resp", "response"),
    ("tmp", "temp", "temporary"),
    ("info", "information"),
    ("mgr", "manager"),
    ("obj", "object"),
    ("val", "value"),
    ("var", "variable"),
    ("func", "function"),
    ("param", "parameter"),
    ("hdr", "header"),
    ("pkt", "packet"),
    ("sz", "size"),
)

# token → equivalence-group index, for O(1) lookup
_TOKEN_GROUP: dict[str, int] = {
    tok: gi for gi, grp in enumerate(_EQUIV_GROUPS) for tok in grp
}

# Always-wrong spellings → corrected token (run BEFORE equivalence mapping, so a
# typo can still be abbreviated to the corpus form afterwards).
_TYPO: dict[str, str] = {
    "recieve": "receive", "seperate": "separate", "lenght": "length",
    "lengh": "length", "adress": "address", "occured": "occurred",
    "successfull": "successful", "paramter": "parameter", "arguement": "argument",
    "intialize": "initialize", "initalize": "initialize", "refernce": "reference",
    "reponse": "response", "requeset": "request", "defualt": "default",
    "vlaue": "value", "wirte": "write", "raed": "read", "lisetner": "listener",
    "destory": "destroy", "retreive": "retrieve", "uncrypt": "decrypt",
}

# Names that carry no real meaning — reported, never auto-renamed (no good target).
_GENERIC_NAMES: frozenset[str] = frozenset({
    "process", "handle", "do_stuff", "run", "execute", "thing", "helper",
    "callback", "function", "func", "proc", "stuff", "work", "do_work",
    "main_loop", "init_stuff", "routine", "subroutine", "unknown", "sub",
})

_LINTABLE_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")


def is_lintable(name: str) -> bool:
    """True only for multi-token, all-lowercase snake_case names — the shape the
    model emits. Library/runtime/mangled/class names are excluded so we never
    rewrite ``__chkstk``, ``memcpy``, ``operator new`` or ``Foo::bar``."""
    return bool(_LINTABLE_RE.match(name or ""))


def _tokens(name: str) -> list[str]:
    return name.split("_")


def default_preferences() -> dict[str, str]:
    """Map every known variant to its group's default (conventional) form."""
    return {tok: grp[0] for grp in _EQUIV_GROUPS for tok in grp}


def build_preferences(names: list[str]) -> dict[str, str]:
    """Choose, per equivalence group, the representative token THIS corpus uses
    most, and return a ``{variant: chosen}`` map covering every known variant.

    Only the lintable names contribute counts. A group with no present variant
    falls back to its default; ties break toward the earlier (more conventional)
    listing.
    """
    counts: dict[str, int] = {}
    for nm in names or []:
        if not is_lintable(nm):
            continue
        for tok in _tokens(nm):
            tok = _TYPO.get(tok, tok)
            if tok in _TOKEN_GROUP:
                counts[tok] = counts.get(tok, 0) + 1

    prefs: dict[str, str] = {}
    for grp in _EQUIV_GROUPS:
        # pick the present variant with the highest count; tie → group order
        best = max(grp, key=lambda t: (counts.get(t, 0), -grp.index(t)))
        if counts.get(best, 0) == 0:
            best = grp[0]
        for tok in grp:
            prefs[tok] = best
    return prefs


def canonical_name(name: str, preferences: dict[str, str] | None = None) -> str:
    """Return the canonical spelling of *name*: typos fixed, equivalent tokens
    unified to the corpus form. Non-lintable names are returned unchanged.

    *preferences* (from :func:`build_preferences`) selects the per-group form; the
    conventional defaults are used when omitted.
    """
    if not is_lintable(name):
        return name
    prefs = preferences if preferences is not None else default_preferences()
    out = []
    for tok in _tokens(name):
        tok = _TYPO.get(tok, tok)
        tok = prefs.get(tok, tok)
        out.append(tok)
    return "_".join(out)


def lint_names(names: list[str],
               preferences: dict[str, str] | None = None) -> list[dict]:
    """Return canonicalisation proposals for *names*.

    Each item: ``{"current", "suggested", "reason"}`` where reason is
    ``"normalize"`` (a renameable spelling fix; ``suggested`` differs) or
    ``"generic"`` (a meaningless name flagged for attention; ``suggested`` is ""
    — no safe automatic target).
    """
    prefs = preferences if preferences is not None else build_preferences(names)
    out: list[dict] = []
    seen: set[str] = set()
    for nm in names or []:
        if nm in seen:
            continue
        seen.add(nm)
        sug = canonical_name(nm, prefs)
        if sug != nm:
            out.append({"current": nm, "suggested": sug, "reason": "normalize"})
        elif nm.lower() in _GENERIC_NAMES:
            out.append({"current": nm, "suggested": "", "reason": "generic"})
    return out
