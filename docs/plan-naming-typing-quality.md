# Implementation Plan — Naming Uniformity & Typing Correctness (E + A + B)

> **Status:** E ✅ · A ✅ · B ✅ · E-2 ✅ · H+I ✅ · D ✅ · F ✅ · G ✅ · C ✅ — done (96 tests green).
> Also added: scrollable TUI report pane (`[`/`]` + wheel).
> Remaining (broader proposal, not yet built): disasm-path caching.
> C notes: pure `core/canon.py` — token equivalence groups + typo table; the
> canonical form is **data-driven** (the corpus's most-frequent variant wins, so
> nothing is imposed unless the binary is already inconsistent; typos always
> fixed). Only multi-token snake_case names are rewritten (`is_lintable`) —
> library/runtime/class/mangled names untouched. Driver `canonicalize_names`,
> TUI key `L`, `SPECTRIDA_NAME_LINT` (default on). Generic names reported, never
> auto-renamed.
> G notes: quality scoring is pure (`core/globals.py` `function_quality` /
> `rank_globals` / `is_generic_global`, mirrored inline in the worker). Worker
> `list_globals` (generic-data names w/ ≥min_xrefs code refs) + `global_context`
> (ranks referencing funcs, returns top-K snippets + access kinds via ctree) +
> `set_global` (name FIRST, then type — E validation + read-back). Driver
> `name_globals`, TUI key `G`, `SPECTRIDA_GLOBAL_NAMING` (default on). Runs after
> the `B` sweep; a pointer/struct type on a global seeds D propagation.
> F notes: layout engine is pure (`core/structs.py`); worker harvests evidence
> (`struct_evidence`) + registers via `parse_decls` of a host-built C decl
> (`make_struct`) + applies through the prototype (`apply_struct`, rename→type
> ordering preserved — struct fields are named at creation, then the type is set
> on the param). Driver `recover_struct`/`recover_structs`, TUI key `F`,
> `SPECTRIDA_STRUCT_RECOVERY` (default on). Cross-function evidence aggregation
> deferred — v1 harvests within the single function (signature dedup already
> collapses clones).
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

## F — Struct recovery from field-access patterns

### Goal
Turn `*(int *)(a1 + 0x18)` / `a1[10]` access soup into real structs: synthesize a
`struct` type for a pointer/`this` parameter (or a global) from the set of offsets
it's dereferenced at across all functions, apply it, and let Hex-Rays re-render
`a1->health` instead of `*(_DWORD *)(a1 + 0x18)`. This is the **largest single
readability jump** — it converts dozens of opaque offset arithmetic sites into
named field accesses at once and unlocks return/arg typing (D) to carry the new
struct around.

### Why this shape
A struct's shape is the **union of how a pointer is dereferenced across every
function that receives it** — no single site is authoritative. So recovery is a
*collect-then-synthesize* pass: gather `(offset, access-size, access-kind)` tuples
for one base pointer from all call sites, reconcile them into a field layout, name
the fields with the LLM (context = the accessing snippets), create the UDT, apply.
The model names; the **layout is computed deterministically** from observed
offsets (never hallucinated), which keeps it safe.

### Integration points

**1. Worker: harvest field accesses (`ida.py` `_WORKER`)**
- New cmd `struct_evidence(func_ea, arg_index|var)`: decompile the function, walk
  the ctree (`ctree_visitor_t`, CV_FAST) collecting every dereference of the target
  base expression — patterns `*(T *)(base + off)`, `base[idx]`, `cot_memref` once a
  partial struct exists. For each emit `{offset, size, kind}` where `size` from the
  cast/`cot_ptr` width, `kind` ∈ read / write / call-arg / address-taken / deref
  (nested pointer → candidate sub-struct pointer). Offsets resolved through
  `cot_add` constant folding.
- Aggregate across functions at the host layer (step 3), not in the worker — the
  worker only reports raw evidence per function.
- New cmd `make_struct(name, fields)`: build a UDT via `ida_typeinf` /
  `til` (`tinfo_t.create_udt`, `add_member` at fixed offsets; gaps → padding
  `_BYTE field_NN[gap]`; nested pointers → forward-declared struct ptr). Validate +
  read-back (reuse E). Returns the created type name or a `dropped` reason.
- New cmd `apply_struct(target, type)`: set the param/var/global's type to the new
  `Struct *` (reuses `_set_func_proto` / `_set_lvar_type` / `set_global` from G).

**2. Pure helper `spectrida/core/structs.py`** (IDA-free, unit-testable)
- `reconcile_fields(evidence) -> list[Field]` — the deterministic layout engine.
  Input: aggregated `{offset, size, kind}` tuples. Output: ordered, non-overlapping
  field list with sizes, padding gaps, and per-field flags (is_pointer,
  array-candidate when stride pattern detected). Conflict policy: widest observed
  access at an offset wins; overlapping accesses (offset 0x10 read as 4 and 8) →
  prefer the larger and flag `union_candidate`; never emit overlapping members.
- `struct_signature(fields) -> str` — content hash of the layout (offset+size set)
  so two pointers with the **same shape** collapse to one struct (clone instances,
  shared base classes) — composes with B's caching philosophy.
- `propose_field_names(fields, snippets) -> ...` — packaging only; actual naming is
  the LLM call. Pure part just bounds/orders the evidence fed to the model.

**3. Backend: `name_struct` LLM call (`llamacpp.py` / `backend.py` / `demo.py`)**
- `RealBackend.name_struct(layout, snippets)`: prompt = the computed field layout
  (offsets + sizes + access kinds) + a few representative accessing snippets per
  field + glossary (A) → ask for `{struct_name, fields:{off: {name, type}},
  reason}`. The model may **refine** a field's scalar type (e.g. `int` → `BOOL`,
  ptr → `Player *`) but **cannot change offsets/sizes** (host enforces; mismatches
  dropped). Deterministic sampling, `_RE_SYSTEM` prefix reused.
- `Backend` ABC + `DemoBackend` stub.

**4. `IDADatabase` driver (`api.py`)**
- `recover_struct(target)` where `target` = `(func_ea, arg_index)` or a global ea:
  1. find all functions that receive this pointer (xref/dataflow: for a `this`/arg,
     follow the call graph one hop — callers passing into this arg, and callees it's
     forwarded to; bounded depth);
  2. `struct_evidence` on each → aggregate;
  3. `reconcile_fields` → layout; `struct_signature` → dedup against already-built
     structs (reuse, don't duplicate);
  4. `name_struct` → names/refines;
  5. `make_struct` + `apply_struct` on every site that uses this shape;
  6. feed struct name into glossary (A); the new `Struct *` becomes a D-propagation
     seed automatically.
- `recover_structs(*, scope="all", min_fields=2, min_sites=1, progress_cb,
  plan_cb)`: candidate targets = pointer-typed params/returns/globals that have ≥N
  offset accesses and no existing UDT. Totals `{structs, fields, applied_sites,
  dropped}`. Runs **after B** (functions named → snippets meaningful) and naturally
  **before/with G** (a recovered global struct improves global typing).

**5. TUI (`browser.py`)**
- New key (e.g. `F` "recover struct") → `_recover_struct` on the focused function's
  primary pointer arg, plus a sweep variant. Shared progress UI; summary
  `struct <Name> · fields N · sites M · dropped D`. Update `HelpScreen._KEYS`.

### Tests (F)
- `tests/test_structs.py` (new, pure): `reconcile_fields` — non-overlapping layout
  from scattered offsets, padding-gap insertion, widest-access-wins, overlap →
  `union_candidate`, array stride detection; `struct_signature` equal for
  same-shape / different for different-shape.
- Integration via demo: `demo.py` stubs for `struct_evidence` (returns canned
  offset tuples), `make_struct`/`apply_struct`/`name_struct`; assert
  `recover_struct` builds the expected field set, names it, and a forced
  offset-mismatch from the model lands in `dropped`.
- Real IDA: a function with obvious `a1+off` accesses → run `F`, confirm Hex-Rays
  re-renders `a1->field` and `retyped`/applied-sites count is correct; confirm an
  existing hand-made struct is **not** clobbered.

### Risks
- *Hallucinated layout*: eliminated — offsets/sizes are observed, model only names.
  Read-back gate on `make_struct`.
- *Over-merging distinct types* sharing a prefix shape: `struct_signature` keys on
  the full offset+size set, not a prefix; require `min_fields`/`min_sites` floors.
- *Union ambiguity*: don't auto-create unions; flag `union_candidate` and pick the
  dominant access, leaving a comment — full union recovery is a later refinement.
- *Cross-function aggregation cost*: bound the caller/callee follow depth; process
  highest-xref pointers first so early stop keeps the best wins.

---

## G — Global variable naming + typing (sequenced after F)

### Goal
Name and type the binary's generic globals (`dword_*`, `byte_*`, `off_*`,
`unk_*`, `qword_*`, `xmmword_*`, `g_*` placeholders) using the **already-named,
high-quality functions** that reference them as context. Globals are the missing
half of typing: locals/args/returns are handled (E/D), but a `dword_140C00010`
touched by 40 functions stays anonymous and untyped, and its type can't propagate.

### Why this shape
A global's meaning is distributed across its use sites, not contained in one
function. The richest evidence comes from the **best-understood** call sites
(named, typed, API/string-bearing), not from every site — feeding 40 raw
pseudocode bodies is noisy and expensive. So: rank globals by leverage (xref
count), rank each global's referencing functions by analysis quality, and let the
model reason over the top-K sites only.

### Integration points

**1. Worker: enumerate + describe globals (`ida.py` `_WORKER`)**
- New cmd `list_globals`: walk data segments / `idautils.Names()`, keep entries
  whose name matches the generic pattern (`_GENERIC_DATA_RE` = `dword_|byte_|word_
  |qword_|off_|unk_|stru_|asc_|xmmword_|flt_|dbl_` etc.) AND that have ≥1 code
  xref. For each emit `{ea, name, size, cur_type, nxrefs}` where `nxrefs =
  len(list(idautils.XrefsTo(ea)))` restricted to code refs.
- New cmd `global_context(ea, top_k)`: for the global at `ea`, gather code xrefs,
  resolve each to its containing function, score each function (see step 3), keep
  the top-`top_k`, and for each return `{func_ea, func_name, proto, snippet}`
  where `snippet` is the few pseudocode lines around the access (a windowed slice
  of `decompile()` text, not the whole body) plus the access kind (read / write /
  call-arg / address-taken) derived from the ctree (`cot_obj` parent: `cot_asg`
  lhs = write, rhs = read, `cot_call` arg = arg).
- New cmd `set_global(ea, name, type)`: `idc.set_name(ea, name, SN_NOWARN)` +
  `idc.SetType(ea, type)` / `ida_typeinf.apply_tinfo`, reusing the **same
  `_classify_type` validation + read-back** from E (no silent drops; return a
  `dropped` reason on failure). Name dedup mirrors the lvar path.

**2. Pure helper `spectrida/core/globals.py`** (IDA-free, unit-testable)
- `is_generic_global(name) -> bool` — the `_GENERIC_DATA_RE` allowlist (mirrors the
  worker inline copy, like `types.py`).
- `function_quality(meta) -> float` — the "entropy"/quality score for ranking
  referencing functions. Inputs from cheap per-function metadata already available
  (named?, proto typed?, #distinct api_calls, #strings, #named callees, body len).
  Score favours: non-generic name (`not sub_*`), a real typed proto, more distinct
  API calls / strings (information content), more named neighbours; penalises huge
  bodies (diffuse signal). This is the "several named functions with higher
  entropy" selection — entropy ≈ distinct-signal density, not raw size.
- `rank_globals(globals) -> list` — sort by `nxrefs` desc (leverage), tie-break by
  size then ea.

**3. Backend: `name_global` LLM call (`llamacpp.py` / `backend.py` / `demo.py`)**
- `RealBackend.name_global(ea)`: `list`/`global_context` → build a prompt:
  global's current name/size/type + the top-K `{func_name, proto, access-kind,
  snippet}` blocks + the **project glossary** (A, uniformity) → ask for
  `{name, type, reason}` (one JSON call, deterministic sampling like staged).
- Reuses `_RE_SYSTEM` prefix (KV-cache); global-specific instructions + context go
  in the **user turn**. `DemoBackend.name_global` returns a deterministic stub.
- `Backend` ABC gains `name_global(ea) -> dict`.

**4. `IDADatabase` driver (`api.py`)**
- `name_globals(*, scope="all", top_k=5, min_xrefs=2, rename=True, progress_cb,
  plan_cb)`:
  - `globals = await self._b.list_globals()`; `rank_globals`; filter `nxrefs >=
    min_xrefs`.
  - For each: `staged = await self._b.name_global(ea)`; validate; `set_global`;
    feed the applied name into the **glossary** (A) and, when the chosen type is a
    pointer/struct/enum, it's a natural seed for **D**-style propagation into the
    functions that load it (future).
  - Totals `{globals, named, typed, dropped}`.
  - Runs **after** the function sweep (`B`) so referencing functions are already
    named/typed → maximum context quality. Document this ordering.
- Optional name-cache (B) keyed on `(normalized snippets + access kinds + glossary
  vocab)` so identical global-usage shapes collapse — defer unless cheap.

**5. TUI (`browser.py`)**
- New key (e.g. `G` "name globals") → `_name_globals` running `name_globals` with
  the shared deep-tree/sweep progress UI (`_make_deep_callbacks`-style), summary
  line `globals N · named M · typed K · dropped D`. Update `HelpScreen._KEYS`.

### Tests (G)
- `tests/test_globals.py` (new, pure): `is_generic_global` table (`dword_140…`
  yes, `g_PlayerList` borderline, `WinMain` no); `function_quality` ordering (a
  named+typed+api-rich fn outranks a `sub_*` stub); `rank_globals` sorts by xref
  count.
- Integration via demo: add a couple of generic globals + xrefs to `demo.py`
  (`list_globals`/`global_context`/`set_global`/`name_global` stubs); assert
  `name_globals` names them, applies a type, records them in the glossary, and a
  bogus type lands in `dropped`.
- Real IDA: pick a hot global (`dword_*` with many xrefs), run `G`, confirm the
  name/type stick (read-back) and that low-xref noise is skipped by `min_xrefs`.

### Risks
- *Wrong type from one-sided evidence*: a global written as `int` but used as a
  flags field. Mitigate by requiring agreement across ≥2 top sites for a non-scalar
  type, else fall back to the size-derived scalar; never clobber an existing
  non-generic type (read-back gate, like D).
- *Cost*: bounded by `top_k` snippets (not full bodies) and `min_xrefs` floor;
  globals processed in xref-desc order so the run can be stopped early with the
  highest-leverage ones already done.
- *Quality-score tuning*: `function_quality` is heuristic — keep it pure + tested
  so weights can be adjusted without touching IDA code.

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
