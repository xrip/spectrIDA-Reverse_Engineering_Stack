"""Project glossary — a running, bounded vocabulary of names assigned in THIS
binary, injected into naming prompts so the model stays consistent across
functions and branches (reuses stems/prefixes, avoids synonyms & duplicate names).

Pure / no IDA / no LLM — fully unit-testable. The `IDADatabase` owns one instance
per open database, seeds it from already-named functions, and grows it as naming
proceeds. `render()` is dropped into the *user* turn (never the cached system
prefix) and returns "" while empty, so the cold-start prompt is unchanged.
"""
from __future__ import annotations

import re
from collections import Counter

# generic tokens that carry no domain signal — excluded from the vocabulary
_STOP_STEMS = frozenset({
    "sub", "func", "fun", "proc", "tmp", "temp", "var", "val", "ptr", "buf",
    "the", "and", "for", "with", "this", "that", "arg", "ret", "obj",
})

# two-pass split mirrors llamacpp._camel_to_snake so acronyms split cleanly
# (PEHeader → pe, header), not just camelCase boundaries.
_SPLIT_ACRONYM = re.compile(r"([A-Z]+)([A-Z][a-z])")
_SPLIT_CAMEL = re.compile(r"([a-z0-9])([A-Z])")


def _tokens(name: str) -> list[str]:
    """snake_case / CamelCase / Class$$Method → lowercase word tokens."""
    s = _SPLIT_ACRONYM.sub(r"\1_\2", name or "")
    s = _SPLIT_CAMEL.sub(r"\1_\2", s)
    return [t.lower() for t in re.split(r"[^A-Za-z0-9]+", s) if t]


def _is_sub(name: str) -> bool:
    n = (name or "").lower()
    return n.startswith("sub_") or n.startswith("j_") or n.startswith("unknown")


class Glossary:
    def __init__(self) -> None:
        self.names: dict[int, dict] = {}      # addr -> {"name", "proto"} (insertion-ordered)
        self.terms: list[str] = []            # explicit domain terms (optional)
        self._term_keys: set[str] = set()

    def __len__(self) -> int:
        return len(self.names)

    # ── population ────────────────────────────────────────────────────────────
    def add_name(self, addr: int, name: str, proto: str = "") -> None:
        """Record a real (non-sub_*) name. Re-adding moves it to most-recent."""
        if not name or _is_sub(name):
            return
        if addr in self.names:
            del self.names[addr]
        self.names[addr] = {"name": name, "proto": proto or ""}

    def add_existing(self, funcs: list[dict]) -> None:
        """Bulk-seed from a function list (skips sub_* automatically)."""
        for f in funcs:
            self.add_name(f.get("start", -1), f.get("name", ""))

    def add_term(self, *terms: str) -> None:
        for t in terms:
            key = (t or "").strip().lower()
            if key and key not in self._term_keys:
                self._term_keys.add(key)
                self.terms.append(t.strip())

    # ── vocabulary derived from the assigned names ────────────────────────────
    def vocabulary(self, limit: int = 24) -> list[str]:
        """Frequent name stems (+ explicit terms) — the project's working lexicon.

        Deterministic: stems shared by ≥2 names, ranked by frequency then alpha.
        """
        counter: Counter[str] = Counter()
        for entry in self.names.values():
            for tok in set(_tokens(entry["name"])):
                if len(tok) >= 3 and not tok.isdigit() and tok not in _STOP_STEMS:
                    counter[tok] += 1
        stems = [t for t, c in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
                 if c >= 2]
        out: list[str] = []
        seen: set[str] = set()
        for t in self.terms + stems:
            k = t.lower()
            if k not in seen:
                seen.add(k)
                out.append(t)
            if len(out) >= limit:
                break
        return out

    # ── prompt block ──────────────────────────────────────────────────────────
    def render(self, limit: int = 80, vocab: int = 24) -> str:
        """Compact glossary block for the user turn, or "" when empty."""
        if not self.names and not self.terms:
            return ""
        lines = ["=== PROJECT GLOSSARY ==="]
        vocab_terms = self.vocabulary(vocab)
        if vocab_terms:
            lines.append("Domain vocabulary (reuse these stems/prefixes for consistency): "
                         + ", ".join(vocab_terms))
        if self.names:
            recent = list(self.names.values())[-limit:]
            lines.append("Names already assigned in this binary "
                         "(match their style; never reuse a name for a different function):")
            for e in recent:
                lines.append(f"  - {e['proto'] or e['name']}")
        return "\n".join(lines)
