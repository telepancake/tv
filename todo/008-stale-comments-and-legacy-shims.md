# 008: Remove stale, misleading, and history-heavy comments/code shims

## Goal

Make comments and compatibility code describe the current system, not past experiments or reviewer conversations. This reduces technical debt that future LLM agents might copy or amplify.

## Current symptoms

- Stale help: `sud/sudtrace.c` tells users to decode with `yeetdump FILE`, but the current command is `tv dump FILE`.
- Several comments mention former standalone binaries (`former sudtrace`, `former yeetdump`, `former fv`) without distinguishing compatibility from history.
- `tv_db.h` exposes `ensure_canon_table()` as a source-compat shim; this may be dead API or needs a clear deprecation plan.
- Some comments include narrative history such as reviewer complaints, user complaints, or implementation reversions. These should become concise invariants and constraints.
- `wire/wire.h` mentions a parquet converter, but the visible tool is `tools/jsonl2wire.py`; verify whether that reference is stale.
- `README.md` still starts with `proctrace Output Schema`, while the repository now centers on `tv` and multiple producers.

## Primary files

- `/home/runner/work/tv/tv/README.md`
- `/home/runner/work/tv/tv/Makefile`
- `/home/runner/work/tv/tv/main.cpp`
- `/home/runner/work/tv/tv/sud/sudtrace.c`
- `/home/runner/work/tv/tv/tv_db.h`
- `/home/runner/work/tv/tv/tv_db.cpp`
- `/home/runner/work/tv/tv/data_source.cpp`
- `/home/runner/work/tv/tv/wire/wire.h`
- `/home/runner/work/tv/tv/tools/jsonl2wire.py`

## Dependencies

- None.
- This can be done before or after structural refactors. If a structural task edits the same comments, let that task own the cleanup.

## Can run concurrently with

- All other tasks, as long as line-level conflicts are avoided.

## Instructions for a coding agent

1. Search for terms like `former`, `was`, `legacy`, `old`, `reviewer`, `user complaint`, `dummy`, `compat`, `deprecated`, `TODO`, `FIXME`, and obsolete tool names.
2. For each hit, decide whether it is:
   - current compatibility documentation,
   - useful historical rationale that should be shortened to a current invariant,
   - stale/misleading text to update,
   - or dead compatibility code to remove in a separate behavior-changing patch.
3. Do not delete comments that explain non-obvious platform constraints, signal-safety, kernel compatibility, or memory/performance bounds.
4. Rewrite comments in present tense. Prefer constraints such as “must remain async-signal-safe” over narratives like “the reviewer hit this”.
5. Keep user-facing help and README examples synchronized with actual commands.
6. If removing a public shim such as `ensure_canon_table()`, first confirm no call sites or downstream compatibility requirements remain.

## Acceptance criteria

- Known stale `yeetdump` help is corrected.
- Historical narratives are replaced with concise current invariants.
- Remaining legacy/compatibility comments clearly state whether compatibility is intentional and for whom.
- README title and examples match the current multi-producer `tv` architecture.
- No behavior changes are hidden in a comment-only cleanup patch.

## Validation

- For comment-only changes, no build is required.
- If removing code shims or changing help behavior, build `tv` and run relevant help/self-test commands.
