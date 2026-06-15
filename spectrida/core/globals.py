"""Pure helpers for global-variable naming/typing (G) — no IDA dependency.

A global's meaning lives in its *use sites*, not in any one function. G ranks
generic globals by leverage (how many functions touch them) and, for each, ranks
the referencing functions by analysis quality so the model reasons over the
best-understood call sites only — not every raw body.

The in-IDA worker (`core/ida.py` ``_WORKER``) can't import this module
(idalib-only ``sys.path``); it mirrors a compact copy of ``is_generic_global`` /
the quality weighting inline. THIS file is the canonical, tested source.
"""
from __future__ import annotations

import re

# IDA auto-generated data names — placeholders with no analyst meaning. A name
# like ``g_PlayerList`` is NOT here: the ``g_`` prefix already carries intent.
_GENERIC_DATA_RE = re.compile(
    r"^(?:dword|qword|word|byte|off|unk|stru|asc|xmmword|ymmword|flt|dbl|"
    r"xmmword|packreal|tbyte|stru)_[0-9A-Fa-f]+$"
)


def is_generic_global(name: str) -> bool:
    """True if *name* is an IDA auto-generated data placeholder (``dword_…``,
    ``byte_…``, ``off_…``, …) worth renaming/typing. Meaningful names (exports,
    ``g_*`` analyst names, runtime symbols) return False."""
    return bool(_GENERIC_DATA_RE.match(name or ""))


# ── function-quality scoring (rank referencing functions) ────────────────────

# Weights are deliberately separated so they can be tuned without touching IDA
# code. "Quality" ≈ distinct-signal density: a named, typed, API/string-rich
# function explains a global far better than a bare sub_* stub.
_W_NAMED        = 5.0    # has a real (non sub_*) name
_W_TYPED_PROTO  = 3.0    # has an actual prototype (params/types), not int()(void)
_W_PER_API      = 1.5    # per distinct API/import call (capped)
_W_PER_STRING   = 1.0    # per referenced string literal (capped)
_W_PER_CALLEE   = 0.8    # per already-named callee (resolved neighbourhood)
_CAP_API        = 6
_CAP_STRING     = 6
_CAP_CALLEE     = 8


def function_quality(meta: dict) -> float:
    """Score a referencing function for how well it can explain a global.

    *meta* is cheap per-function metadata (any subset; missing keys → 0/False):
      ``named`` bool · ``typed_proto`` bool · ``napis`` int · ``nstrings`` int ·
      ``nnamed_callees`` int · ``size`` int (body bytes).

    Higher = better naming context. Huge bodies are penalised — signal is diffuse.
    """
    m = meta or {}
    score = 0.0
    if m.get("named"):
        score += _W_NAMED
    if m.get("typed_proto"):
        score += _W_TYPED_PROTO
    score += _W_PER_API    * min(int(m.get("napis", 0) or 0), _CAP_API)
    score += _W_PER_STRING * min(int(m.get("nstrings", 0) or 0), _CAP_STRING)
    score += _W_PER_CALLEE * min(int(m.get("nnamed_callees", 0) or 0), _CAP_CALLEE)
    size = int(m.get("size", 0) or 0)
    if size > 4000:
        score -= 2.0
    elif size > 1500:
        score -= 0.5
    return score


def rank_functions(funcs: list[dict], *, top_k: int = 5) -> list[dict]:
    """Return the *top_k* referencing functions by `function_quality`, best first.
    Stable tie-break by descending size then ascending ea so ordering is
    deterministic."""
    return sorted(
        funcs,
        key=lambda f: (-function_quality(f.get("meta", f)),
                       -int(f.get("size", 0) or 0),
                       int(f.get("func_ea", f.get("ea", 0)) or 0)),
    )[:max(0, top_k)]


def rank_globals(globals_: list[dict]) -> list[dict]:
    """Order globals by leverage: most-referenced first (more use sites = more
    evidence and more downstream benefit). Tie-break by size then ea."""
    return sorted(
        globals_ or [],
        key=lambda g: (-int(g.get("nxrefs", 0) or 0),
                       -int(g.get("size", 0) or 0),
                       int(g.get("ea", 0) or 0)),
    )
