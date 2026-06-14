# Implementation Plan — Naming Uniformity & Typing Correctness (E + A + B)

> **Status:** E ✅ · A ✅ · B ✅ · E-2 ✅ (opt-in retry) — done (42 tests green).
> Also added: scrollable TUI report pane (`[`/`]` + wheel).
> Deviation in A: domain vocabulary is auto-derived from name stems (zero-cost,
> deterministic) instead of parsing `overview()` prose; `seed_overview` not added.
> Note: B's worker growth from E required moving the idalib worker off `python -c`
> onto a tempfile (Windows 32 KB cmdline limit, WinError 206).

## Context

spectrIDA names/types IDA functions with a local LLM. Two quality factors are
weak today:

- **Typing correctness** — when the LLM returns a bad type string or an unknown
  struct, the type is **silently dropped**: `_parse_type` returns `None`
  (`ida.py:62`), `_set_func_proto` returns all-zeros if `apply_tinfo` fails
  (`ida.py:129`), and there is **no read-back verification**. The user never
  learns a type didn't apply, and the model never gets a chance to correct.
- **Name uniformity** — consistency only exists *within a single branch* via the
  shared `branch_history` (`api.py` `name_branch`). Across branches / the whole
  binary there is **no shared vocabulary**, so similar concepts drift
  (`send_packet` vs `transmit_msg`), and structurally-identical functions
  (template clones, thunks) get unrelated names. `overview()` builds subsystem
  terminology but discards it.

This plan delivers three changes, smallest-blast-radius first:

- **E** — Type validation + post-apply verification + visible "dropped" feedback (optional one-shot corrective retry).
- **A** — Project glossary: accumulate assigned names + subsystem vocabulary, inject into every naming call (uniformity).
- **B** — Content-addressed name cache: identical functions → identical names; cheap/stable re-runs (uniformity + cost).

Shared theme: nothing changes the **static system prefix** (`_build_system`,
`llamacpp.py:78`) — KV-cache prefix reuse must be preserved. All new context goes
into the **user turn**.

---

## E — Typing: validate, verify, surface failures

### Goal
No silent type drops. Every attempted type is either applied-and-verified or
reported with a reason. Optionally, unknown-struct failures trigger one
corrective LLM call constrained to existing types.

### Integration points

**1. New pure helper module `spectrida/core/types.py`** (IDA-free, unit-testable)
- `is_builtin_c_type(token) -> bool` — allowlist of C builtins + IDA scalars
  (`int`, `unsigned`, `char`, `void`, `bool`, `__int64`, `size_t`, `uint8_t`, …).
- `extract_type_identifiers(type_str) -> list[str]` — strip `*`, `[]`, `const`,
  `struct`/`union`/`enum` keywords, return the non-builtin named-type tokens
  (e.g. `"struct Player *"` → `["Player"]`, `"int"` → `[]`).
- These let us decide *which* identifiers must exist in the type library.

**2. Worker `rename_lvars` cmd + helpers (`ida.py:62–131`, `:182–252`)** — runs
inside IDA, so the actual til lookups + read-back live here:
- Add `_type_exists(ident) -> bool` using `ida_typeinf.get_named_type(None, ident, ...)`.
- Add `_classify_type(type_str) -> (tif|None, reason)`:
  - `""` → `(None, "empty")`
  - `parse_decl` fails → `(None, "parse_failed")`
  - any identifier from `extract_type_identifiers` not in til → `(None, "unknown_type:<ident>")`
  - else → `(tif, "")`
  Replace the two raw `_parse_type(ty)` call sites in the lvar loop (`ida.py:238`)
  and inside `_set_func_proto` (`ida.py:113,122`) with `_classify_type`.
- **Post-apply verification** in `_set_func_proto`: after `apply_tinfo`
  (`ida.py:129`), re-read with `idaapi.get_tinfo(check, func_ea)` +
  `check.get_func_details(fi2)` and confirm each `fi2[idx].type` / `fi2.rettype`
  matches what we set; count only verified fields in `done`.
- For locals, after `_set_lvar_type` (`ida.py:89`) confirm via a fresh
  `modify_user_lvar_info` read or a re-`decompile` lvar type compare.
- Accumulate a `dropped: list[dict]` = `{"var", "type", "reason"}` and return it:
  ```
  {"renamed", "retyped", "ret_type", "pseudocode", "dropped": [...]}
  ```
  (Worker emit at `ida.py:246`.)

**3. Propagation (no logic, just pass-through)**
- `ida.rename_lvars` (`ida.py:854`) already returns the worker dict verbatim — add
  `"dropped"` to the exception-fallback default (`ida.py:868`).
- `backend.py` `RealBackend.rename_lvars` / `DemoBackend.rename_lvars` return verbatim.
- `api.py` `name_all` (`api.py:374–394`): capture `r.get("dropped", [])` and add
  `"dropped": dropped` to the returned dict.

**4. Optional corrective retry (E-2, behind a flag)**
- In `name_all`, when `dropped` contains `unknown_type:*` entries and
  `retry_types=True`, issue ONE extra `name_variables`-style call listing the
  failed vars + the **valid** struct/enum list (already in binary context) asking
  for replacement types only; re-apply via `rename_lvars`. Keep it bounded to one
  retry. New config knob `SPECTRIDA_TYPE_RETRY` (default off initially).

**5. Surface in TUI (`browser.py`)**
- `_name_vars` (`browser.py:342`): append `· N dropped` to the result line when
  `result["dropped"]`, and list reasons in the reason pane (reuse `_var_change`
  style).
- Deep-tree `_make_deep_callbacks` (`browser.py`): when `dropped`, render the `T`
  checkbox as a dim partial marker instead of a flat ✓.

### Tests (E)
- `tests/test_types.py` (new, pure): `is_builtin_c_type`, `extract_type_identifiers`
  — table cases incl. `"Player *"`, `"struct Foo **"`, `"unsigned int"`,
  `"const char *"`, garbage.
- `tests/test_core.py` integration via demo: extend `DemoBackend.rename_lvars`
  (`backend.py:144`) + `demo.rename_lvars` (`demo.py:221`) to echo a `dropped`
  entry when fed a sentinel bad type; assert `name_all` returns it and the TUI
  line includes the drop count.
- Manual/IDA verification: run `V` on a function, give it a known-bad struct via a
  forced mapping; confirm log shows `unknown_type:` and the proto is unchanged
  (read-back catches it) — see Verification section.

---

## A — Project glossary (uniformity)

### Goal
Every naming call sees a compact, bounded list of **already-assigned names** and
**subsystem vocabulary**, so the model reuses stems/prefixes and avoids synonyms.

### Integration points

**1. New module `spectrida/core/glossary.py`** (pure, unit-testable)
```python
class Glossary:
    terms: list[str]                 # subsystem/domain vocabulary (from overview)
    names: dict[int, dict]           # addr -> {"name", "proto"}
    def add_term(self, *terms): ...
    def add_name(self, addr, name, proto=""): ...   # dedup, skip sub_*
    def render(self, limit=80) -> str:              # compact block or "" if empty
```
`render()` emits:
```
=== PROJECT GLOSSARY ===
Domain/subsystems: <comma terms>
Names already assigned (reuse these stems/prefixes; do NOT duplicate a name):
  - <name>  <proto>
  ...
```
Bounded (`limit` most-recent or real-proto-first). Returns `""` when empty so the
prompt is unchanged on first function (preserves cache for the cold path).

**2. Thread `glossary` text into the LLM call (user turn only)**
- `llamacpp._single_stage_prompt` (`llamacpp.py:368`): add param `glossary: str = ""`,
  prepend the block to the returned user content when non-empty.
- `llamacpp.name_function_staged` (`llamacpp.py:574`): add param `glossary: str = ""`,
  forward into `_single_stage_prompt` (`llamacpp.py:609`). System prefix untouched.
- `backend.py` `name_function_staged` (Real `:94`, Demo `:149`) + the `Backend`
  ABC (`backend.py:35`): add `glossary: str = ""` pass-through.

**3. Plumb through `IDADatabase` (`api.py`)**
- `__init__` (`api.py:101`): `self._glossary = Glossary()`.
- Lazy seed on first naming: pre-populate from already-named functions —
  iterate `list_functions()`, `add_name` for every non-`sub_*` (names only). This
  instantly aligns new names with existing exports/library symbols.
- `name_all` (`api.py:296`): pass `glossary=self._glossary.render()` into
  `self._b.name_function_staged(...)` (`api.py:353`). After a successful apply,
  `self._glossary.add_name(a, new_name, proto)` where `proto` comes from a cheap
  `get_protos([a])` (already typed by the just-applied prototype) — or skip proto.
- `name_branch` / `batch_name_branches`: glossary is shared on `self`, so the
  whole-binary sweep accumulates vocabulary across branches automatically.

**4. Seed terms from `overview()`**
- `batch_name_branches` (`api.py`): add `seed_overview: bool = False`. When True,
  run a single `overview()` first, split its subsystem section into keywords,
  `glossary.add_term(...)`. TUI `B` action passes `seed_overview=True`.

### KV-cache note
Glossary lives in the **user turn** (already per-function variable). The cached
static system prefix and the per-branch history mechanism are unaffected.

### Tests (A)
- `tests/test_glossary.py` (new, pure): `add_name` dedup + `sub_*` skip;
  `render` boundedness, ordering, empty→`""`; `add_term` dedup.
- Integration via demo: extend `DemoBackend.name_function_staged` to record the
  `glossary` arg; run `batch_name_branches` over the demo graph and assert the
  glossary string is empty on the first call and non-empty later (vocabulary
  accumulates).

---

## B — Content-addressed name cache (uniformity + cost)

### Goal
Structurally-identical functions get identical names by construction; re-runs are
stable and skip the LLM.

### Integration points

**1. New module `spectrida/core/namecache.py`** (pure, unit-testable)
```python
def normalize_code(pseudocode: str) -> str:
    # mask addresses/hex, sub_XXXX, vN/aN locals, numeric literals → canonical
    # tokens so clones (differ only by addr/ids) collapse to one key.
def key(pseudocode, callees, callers, hints) -> str:   # sha1 of normalized inputs
class NameCache:
    def get(self, k) -> dict | None        # cached {name, ret_type, variables}
    def put(self, k, staged) -> None
    def load(self, path) / save(self, path)
```
- Key excludes the address; uses `normalize_code` + sorted callee/caller name
  sets + a stable hint subset (api_calls, strings). Clones → same key on purpose.

**2. Persist next to the `.i64`**
- Path `<i64>.spectrida-namecache.json`. `RealBackend` exposes the i64 path
  (`backend.py:44`); `IDADatabase` loads on first use, saves on `close`
  (`api.py:656`) and every N puts.
- Config knob `SPECTRIDA_NAME_CACHE` (default on) + optional path override in
  `config.py` (mirror `batch_concurrency` style, `config.py:189`).

**3. Wrap the LLM path in `name_all` (`api.py:351–372`)**
- After `_fast_name` (which stays as-is — already deterministic), before the
  staged call: compute `k = namecache.key(pseudocode, callees, callers, hints)`.
  - **Hit** → reuse cached `{name, ret_type, variables}`; skip
    `name_function_staged`. Still run the apply path (`rename` + `rename_lvars`)
    against *this* address, so per-address dedup (`name_1`) still happens at
    `ida.py:461`.
  - **Miss** → call staged, then `cache.put(k, staged)`.
- Interaction with A: cache stores the *staged result*; glossary still updated
  from the applied name on both hit and miss, so uniformity compounds.

### Tests (B)
- `tests/test_namecache.py` (new, pure): `normalize_code` collapses two snippets
  differing only by addresses / `sub_1234` / `v5` to equal output; `key`
  stability & sensitivity; `put`/`get`; `save`/`load` round-trip in `tmp_path`.
- Integration via demo: instrument `DemoBackend.name_function_staged` with a call
  counter; call `name_all` twice on the same demo function; assert the second is a
  cache hit (counter unchanged) and returns the same name.

---

## Sequencing & risks

1. **E first** (isolated to typing path; immediate visible win, low risk). Ship
   validation+verification+`dropped`; gate the corrective retry behind a flag.
2. **A second** (touches the staged-call signature across `llamacpp`/`backend`/
   `api`; additive `glossary=""` default keeps everything backward-compatible).
3. **B third** (wraps `name_all`; independent of A but composes with it).

Risks / mitigations:
- *Signature churn for A*: add `glossary: str = ""` with defaults everywhere →
  existing callers/tests unaffected.
- *Cache false-collisions (B)*: `normalize_code` is heuristic. Mitigate by
  including api_calls/strings in the key; ship with cache **on** but a one-flag
  kill switch. Per-address dedup still prevents literal name clashes.
- *Glossary context growth (A)*: hard cap `render(limit=80)`; it's in the user
  turn so it can't poison the cached system prefix.
- *Worker testability (E)*: the IDA-dependent til lookups can't be unit-tested
  without idalib — that's why the pure decisions live in `types.py`; the worker
  is covered by the demo plumbing test + manual IDA check.

---

## End-to-end verification

- **Unit**: `python -m pytest tests/test_types.py tests/test_glossary.py
  tests/test_namecache.py tests/test_core.py -q` (note: pre-existing
  `test_core.py` import of removed `_STAGED_SYSTEM` must be fixed or that file
  re-pointed — unrelated to this work but currently red).
- **Demo (no IDA/LLM)**:
  ```python
  async with open_demo() as db:
      await db.batch_name_branches(scope="all", seed_overview=True)
  ```
  Assert: glossary non-empty after branch 1; second pass over a function is a
  cache hit; a forced bad type surfaces in `dropped`.
- **Real IDA**: open a `.i64`, press `V` on a function whose param should be a
  known struct → confirm the proto changes and `retyped` counts only verified
  fields; feed a bogus struct → confirm `dropped: unknown_type:*` and the proto is
  left intact. Run `B` (whole-binary) and spot-check that same-shaped functions
  share a name stem and that subsystem naming is consistent.
