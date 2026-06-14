# Changelog

## Unreleased

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
