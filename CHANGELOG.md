# Changelog

## Unreleased

- **Globals are cached too; the cache is actually persisted.** The
  content-addressed name cache now stores **global** naming results
  (`{name, type}`) keyed by the global's size/type + its ranked use sites
  (`namecache.key_global`, `g:`-namespaced so it can't collide with function
  keys) — re-running `G` on an unchanged binary reuses names with no LLM call
  (shown as `(cache)` in the log). Pass `use_cache=False` to bypass.
  **Efficiency fix:** the TUI used to build a throwaway `IDADatabase` per action,
  each with its own empty cache + glossary, and never `close()`d it — so the
  cache's final save never ran and nothing accumulated across actions. The
  browser now keeps **one** long-lived database: the name cache and project
  glossary build up over the whole session (a `B` sweep warms what `G`/`T`/`V`
  reuse) and are flushed to disk after every action and on exit.
- **Name canonicalisation linter (`L`).** Unifies function names across the whole
  binary so the symbol set reads as one hand: equivalent tokens
  (`message`/`msg`, `receive`/`recv`, `length`/`len`, …) are normalised to the
  form **this binary already uses most** (data-driven — nothing is imposed unless
  the binary is already inconsistent), and always-wrong spellings (`recieve`,
  `lenght`, …) are fixed. Only multi-token snake_case names are rewritten;
  single-token, library/runtime (`__chkstk`), class and mangled names are left
  untouched (`spectrida/core/canon.py`, pure + tested). Generic, meaningless names
  (`process`, `handler`, …) are *reported* but never auto-renamed. The MODEL pane
  streams `old → new` proposals live. Kill switch `SPECTRIDA_NAME_LINT=0`.
- **Global variable naming + typing (`G`).** Names and types the binary's generic
  globals (`dword_*`, `byte_*`, `off_*`, …) from how the **best-understood**
  functions use them. Each global is ranked by leverage (xref count); for each,
  the referencing functions are ranked by analysis quality (named / typed /
  API-and-string-rich — `core/globals.py function_quality`, pure + tested) and only
  the top-K feed the model with windowed snippets + access kinds (read / write /
  address-taken). The name is applied first, then the type (validated + read-back,
  like E) — failures surface as `dropped`, never silent. A pointer/struct type on
  a global seeds return-type propagation (D). Best run after the `B` sweep. `G`
  first prompts for a **minimum xref count** (default 3) so you can focus on the
  high-leverage globals. The MODEL pane streams a readable live log — enumeration
  count, `analysing <name> (n xrefs)…` per global, then `old → new : type` results
  (skips shown dimmed). Kill switch `SPECTRIDA_GLOBAL_NAMING=0`.
- **Struct recovery from field accesses (`F`).** Recovers a C struct for a
  function's generic pointer parameter from the offsets/sizes it's dereferenced
  at, names the struct + fields (LLM), registers it in IDA, and sets the
  parameter to `Struct *` — so Hex-Rays re-renders `a1->health` instead of
  `*(_DWORD *)(a1 + 0x40)`. The layout is computed **deterministically** from
  observed accesses (`spectrida/core/structs.py`, pure + tested) — the model only
  names fields and refines scalar types, it can't move offsets. Widest-access-wins,
  padding gaps filled, overlaps flagged `union_candidate`, pointer fields detected.
  Structurally identical pointers collapse to one struct (`struct_signature`).
  Names are applied **before** typing (IDA splits the two ops). The MODEL pane
  streams a live `structs done/total · scanning <fn>` log so a long sweep is
  legible instead of a silent spinner. Driver
  `recover_struct` / `recover_structs` (run after the `B` sweep for best context;
  a recovered `Struct *` then seeds return-type propagation). Kill switch
  `SPECTRIDA_STRUCT_RECOVERY=0`.
- **Confidence + refine pass (whole-binary).** Each naming result now carries a
  confidence (`high`/`medium`/`low`); low-confidence guesses are kept out of the
  project glossary (no vocabulary pollution). The `B` whole-binary sweep runs a
  second **refine** pass over low-confidence functions once the whole binary is
  named (richer glossary + resolved neighbours), bypassing the name cache.
- **Return-type propagation.** When a function is typed to return a pointer /
  struct / enum, that type is pushed onto caller variables that receive the
  result (Hex-Rays ctree walk), but only over generic placeholders so a better
  existing type is never clobbered. Toggle `SPECTRIDA_TYPE_PROPAGATION=0`.
- **Content-addressed name cache.** Naming results are keyed by the *normalized*
  function body (addresses, `sub_`/`loc_`/data refs, `aN`/`vN`, literals masked) +
  call-chain + distinctive hints (`spectrida/core/namecache.py`), so
  structurally-identical functions (template clones, duplicated helpers, thunks)
  get the **same name by construction**, and re-running an unchanged database is a
  cheap cache hit instead of an LLM round-trip. Persisted as
  `<i64>.spectrida-namecache.json`. Kill switch `SPECTRIDA_NAME_CACHE=0`.
- **Project glossary for naming consistency.** A per-binary glossary
  (`spectrida/core/glossary.py`) seeds from already-named functions and grows as
  naming proceeds; it's injected into each fresh naming conversation's user turn
  (cached system prefix untouched) so the model reuses stems/prefixes and never
  duplicates a name across the binary. A domain vocabulary is auto-derived from
  frequent name stems — no extra LLM/IDA calls. Carries consistency across the
  whole-binary / branch sweeps.
- **Typing no longer fails silently.** Every type the model proposes is validated
  (unknown struct/enum → reason `unknown_type:<name>`, bad syntax → `parse_failed`)
  and **verified by read-back** after `apply_tinfo` — counts reflect only types
  that actually stuck. Unapplied types are returned as a `dropped` list
  `{var, type, reason}` and surfaced in the TUI (`V`, deep-branch, batch) instead
  of vanishing. New tested pure helper `spectrida/core/types.py`. Optional
  corrective retry (`SPECTRIDA_TYPE_RETRY=1`, off by default): for types dropped
  as `unknown_type`, ask the model once for a replacement from existing/primitive
  types and re-apply.
- **Report pane scrolls.** The bottom-right MODEL/report pane is now scrollable
  (mouse wheel, or `[` / `]`) so long deep-branch trees and dropped-type lists
  aren't clipped.

- **`B` Batch** now deep-names the **whole binary**, branch by branch, bottom-up
  (leaves→roots). Finds the call-graph roots, runs deep naming per branch with a
  shared visited-set, then sweeps any leftover (cycles / depth-capped) until every
  function is covered. Already-named functions are re-entered for variable/return
  typing (like `V`) without being renamed. (replaces the old flat quick-batch)
- **`U` Find unnamed branches** — deep-name every `sub_*` function's branch
  bottom-up, leaving already-named regions untouched.
- `T` Deep branch and the new sweeps share one API: `name_branch(revisit_named=…)`
  and `batch_name_branches(scope="all"|"unnamed")`. Deep-name now re-enters
  already-named callees to apply typing.

## 0.1.0 — first ghost

- Parallel sharded IDA analysis (Capstone recursive descent + idalib merge).
- AI function naming via a local llama.cpp server model, streamed token-by-token.
- Terminal UI: virtualized function browser, syntax-highlighted disasm, decompiler view,
  call-chain explorer, inline rename, command palette.
- First-run onboarding wizard (humorous, skippable) that checks llama.cpp server + the model.
- Demo mode (`spectrida --demo`) — runs the whole TUI with no IDA/llama.cpp server.
- Config-driven everything (`~/.spectrida/config.toml` + env vars); no hardcoded paths.
