"""Project change journal — an append-only audit log of every mutation the tool
makes to the database, so a session can be reviewed and rolled back.

Everything spectrIDA does (function renames, variable/param rename + type, return
types, global name/type, struct creation + application, return-type propagation)
is recorded as one JSON event per line in ``<i64>.spectrida-audit.jsonl``. JSONL is
append-only and crash-safe: each event is written and flushed the moment it
happens, so even a hard crash keeps the history.

Pure / no IDA / no LLM. The log can render a human-readable summary and emit a
best-effort IDAPython revert script (names + global types + struct deletes are
reverted exactly; lvar/arg/function-prototype TYPE reverts are emitted as
annotated comments carrying the old value for manual application).
"""
from __future__ import annotations

import json
import os
from datetime import datetime

# Operations we record. *old*/*new* are display strings; *ea* is the owning
# address (function for var/arg/ret/propagation, global for global_*).
OPS = (
    "rename_func", "rename_var", "retype_var", "rename_arg", "func_arg",
    "func_ret", "global_name", "global_type", "make_struct", "apply_struct",
    "propagate_ret",
)


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class AuditLog:
    """Append-only journal of database mutations, persisted as JSONL."""

    VERSION = 1

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._entries: list[dict] = []
        self._path: str | None = None

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> list[dict]:
        return self._entries

    # ── recording ──────────────────────────────────────────────────────────────
    def record(self, op: str, *, ea=None, target: str = "", old: str = "",
               new: str = "", **extra) -> None:
        """Append one event. Written + flushed to disk immediately when a path is
        bound, so the journal survives a crash mid-session."""
        if not self.enabled:
            return
        ev = {"ts": _now(), "op": op}
        if ea is not None:
            ev["ea"] = ea if isinstance(ea, str) else hex(ea)
        if target != "":
            ev["target"] = target
        ev["old"] = old or ""
        ev["new"] = new or ""
        if extra:
            ev.update(extra)
        self._entries.append(ev)
        self._append(ev)

    def record_changes(self, changes: list[dict], *, ea=None) -> int:
        """Record a batch of worker-reported ``{op, target, old, new, ...}`` changes
        under the owning address *ea*. Returns how many were recorded."""
        n = 0
        for ch in changes or []:
            if not isinstance(ch, dict) or not ch.get("op"):
                continue
            self.record(
                ch["op"],
                ea=ch.get("ea", ea),
                target=str(ch.get("target", "")),
                old=str(ch.get("old", "")),
                new=str(ch.get("new", "")),
            )
            n += 1
        return n

    # ── persistence ────────────────────────────────────────────────────────────
    def open(self, path: str) -> "AuditLog":
        """Bind to *path*, loading any existing journal so the view shows the full
        project history (across sessions)."""
        self._path = str(path)
        try:
            with open(self._path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self._entries.append(json.loads(line))
        except FileNotFoundError:
            pass
        except Exception:
            pass            # corrupt/partial line → keep what parsed, never fatal
        return self

    def _append(self, ev: dict) -> None:
        if not self._path:
            return
        try:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
                f.flush()
        except Exception:
            pass            # logging must never break the actual work

    # ── views ──────────────────────────────────────────────────────────────────
    _OP_LABEL = {
        "rename_func": "func", "rename_var": "var", "retype_var": "var-type",
        "rename_arg": "arg", "func_arg": "arg-type", "func_ret": "ret-type",
        "global_name": "global", "global_type": "global-type",
        "make_struct": "struct+", "apply_struct": "struct→", "propagate_ret": "prop",
    }

    def render(self, limit: int = 200) -> str:
        """Human-readable newest-first summary for the TUI / CLI."""
        if not self._entries:
            return "  (no changes recorded yet)"
        rows = []
        for ev in self._entries[-limit:][::-1]:
            label = self._OP_LABEL.get(ev["op"], ev["op"])
            ea = ev.get("ea", "")
            tgt = ev.get("target", "")
            where = f"{ea}" + (f" {tgt}" if tgt else "")
            old = ev.get("old", ""); new = ev.get("new", "")
            arrow = f"{old or '∅'} → {new or '∅'}"
            rows.append(f"  {ev['ts'][11:]}  {label:<11} {where:<24} {arrow}")
        return "\n".join(rows)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for ev in self._entries:
            out[ev["op"]] = out.get(ev["op"], 0) + 1
        return out

    # ── revert ─────────────────────────────────────────────────────────────────
    def revert_script(self) -> str:
        """Best-effort IDAPython script that undoes the recorded changes in reverse
        order. Names (function/var/global) and struct creates + global types are
        reverted exactly; lvar/arg/prototype TYPE reverts are emitted as comments
        carrying the old value (rebuilding a single prototype field automatically is
        unsafe — apply by hand)."""
        lines = [
            "# spectrIDA revert script — generated from the project audit log.",
            "# Review before running. Apply in IDA: File > Script file…",
            "import idc, idaapi",
            "try:",
            "    import ida_hexrays",
            "    ida_hexrays.init_hexrays_plugin()",
            "except Exception:",
            "    ida_hexrays = None",
            "",
        ]
        for ev in reversed(self._entries):
            lines.append(self._revert_line(ev))
        lines.append("")
        lines.append("idc.refresh_idaview_anyway()")
        return "\n".join(lines)

    @staticmethod
    def _q(s: str) -> str:
        return '"' + (s or "").replace("\\", "\\\\").replace('"', '\\"') + '"'

    def _revert_line(self, ev: dict) -> str:
        op = ev["op"]; ea = ev.get("ea", ""); old = ev.get("old", "")
        tgt = ev.get("target", "")
        q = self._q
        if op in ("rename_func", "global_name"):
            return f"idc.set_name({ea}, {q(old)}, idc.SN_NOWARN | idc.SN_NOCHECK)"
        if op == "global_type":
            if old:
                return f"idc.SetType({ea}, {q(old + ';')})"
            return f"# {ea}: was untyped — clear the type manually"
        if op == "make_struct":
            nm = ev.get("new", "")
            return (f"_sid = idc.get_struc_id({q(nm)})\n"
                    f"idc.del_struc(_sid) if _sid != idc.BADADDR else None")
        if op == "rename_var":
            return (f"ida_hexrays.rename_lvar({ea}, {q(ev.get('new',''))}, {q(old)}) "
                    f"if ida_hexrays else None")
        if op == "rename_arg":
            return f"# {ea} arg {tgt}: rename back to {old!r} (set in prototype)"
        # type reverts — recorded for manual application
        return f"# {ea} {op} {tgt}: restore old type {old!r}"

    def export_revert(self, path: str) -> str:
        """Write the revert script to *path*; return the path."""
        p = str(path)
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.revert_script())
        return p
