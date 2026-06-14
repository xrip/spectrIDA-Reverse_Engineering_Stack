"""Content-addressed naming cache.

Keys a naming result by the *normalized* function body (+ call-chain + the most
distinctive hints), so structurally-identical functions — template
instantiations, duplicated helpers, repeated thunks — collapse to one key and get
the SAME name by construction, and re-running an unchanged database is a cheap
cache hit instead of a fresh LLM round-trip.

Pure / no IDA / no LLM. Persisted as JSON next to the .i64. The normalization is
heuristic (it masks addresses, sub_/loc_/data refs, aN/vN placeholders and
numeric literals); api_calls + strings stay in the key so functions that merely
share a control-flow skeleton don't collide. Per-address rename dedup downstream
(`name_1`) bounds the blast radius of any false collision, and the cache has a
kill switch (`SPECTRIDA_NAME_CACHE=0`).
"""
from __future__ import annotations

import hashlib
import json
import os
import re

_SUB   = re.compile(r"\bsub_[0-9A-Fa-f]+\b")
_LOC   = re.compile(r"\bloc_[0-9A-Fa-f]+\b")
_DATA  = re.compile(r"\b(?:off|unk|dword|byte|word|qword|flt|dbl|stru|asc)_[0-9A-Fa-f]+\b")
_HEX   = re.compile(r"0x[0-9a-fA-F]+")
_VAR   = re.compile(r"\b[av]\d+\b")
_NUM   = re.compile(r"\b\d+\b")
_WS    = re.compile(r"\s+")


def normalize_code(s: str) -> str:
    """Canonicalize code so clones collapse: mask names/addresses/literals that
    vary between otherwise-identical functions."""
    s = s or ""
    s = _SUB.sub("F", s)      # sub_140001000 → F   (do these before _HEX)
    s = _LOC.sub("L", s)
    s = _DATA.sub("D", s)
    s = _HEX.sub("H", s)      # 0x40 → H
    s = _VAR.sub("V", s)      # a1, v3 → V
    s = _NUM.sub("N", s)      # 40 → N
    return _WS.sub(" ", s).strip()


def key(pseudocode: str, callees: list[str] | None, callers: list[str] | None,
        hints: dict | None) -> str:
    """Stable content hash for a function's naming inputs."""
    h = hints or {}
    parts = [
        normalize_code(pseudocode or ""),
        "|".join(sorted(normalize_code(c) for c in (callees or []) if c)),
        "|".join(sorted(normalize_code(c) for c in (callers or []) if c)),
        "|".join(sorted(str(x) for x in (h.get("api_calls") or []) if x)),
        "|".join(sorted(str(x) for x in (h.get("strings") or []) if x)),
    ]
    return hashlib.sha1("\x00".join(parts).encode("utf-8", "replace")).hexdigest()


class NameCache:
    """key → {"name", "ret_type", "variables"}. JSON-persisted."""

    VERSION = 1

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._d: dict[str, dict] = {}
        self._path: str | None = None
        self._dirty = 0

    def __len__(self) -> int:
        return len(self._d)

    def get(self, k: str) -> dict | None:
        return self._d.get(k) if self.enabled else None

    def put(self, k: str, staged: dict) -> None:
        if not self.enabled:
            return
        name = staged.get("name", "") or ""
        if not name:            # never cache a non-result
            return
        self._d[k] = {
            "name": name,
            "ret_type": staged.get("ret_type", "") or "",
            "variables": staged.get("variables", {}) or {},
        }
        self._dirty += 1

    # ── persistence ───────────────────────────────────────────────────────────
    def load(self, path: str) -> "NameCache":
        self._path = str(path)
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and isinstance(data.get("entries"), dict):
                self._d = data["entries"]
        except FileNotFoundError:
            pass
        except Exception:
            pass            # corrupt cache → start fresh, never fatal
        return self

    def save(self, path: str | None = None) -> None:
        p = str(path or self._path or "")
        if not p or not self.enabled:
            return
        try:
            tmp = p + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"version": self.VERSION, "entries": self._d}, f)
            os.replace(tmp, p)
            self._dirty = 0
        except Exception:
            pass

    def maybe_save(self, every: int = 50) -> None:
        if self._dirty >= every:
            self.save()
