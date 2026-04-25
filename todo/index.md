# Codebase audit todo index

This folder turns the audit into implementation-ready tasks for coding agents. Treat these as architectural cleanup tasks, not feature work. Keep changes small, preserve existing behavior, and avoid broad rewrites unless a task explicitly asks for staged extraction.

## Dependency and concurrency overview

```text
Foundation cleanup (can start now)
├─ 008-stale-comments-and-legacy-shims.md
├─ 006-uniform-error-handling.md
├─ 007-global-state-lifetime.md
└─ 005-entrypoints-and-tool-boundaries.md

TUI/viewer chain
001-engine-api-boundaries.md
└─ 002-tv-viewer-structure.md

Tracing chain
003-sud-supervised-execution-engine.md
└─ 004-trace-producer-boundaries.md
```

## Issues

| ID | Issue | Status | Depends on | Can run concurrently with |
| --- | --- | --- | --- | --- |
| 001 | TUI engine API is too broad and exposes implementation-driven concepts | Open | None | 003, 005, 006, 007, 008 |
| 002 | tv viewer logic is split across `main.cpp`, `data_source.*`, and raw `Box` mutation | Open | 001 recommended | 003, 004, 005, 006, 008 |
| 003 | `sudtrace` should expose a reusable supervised execution engine beneath trace writing | Open | None | 001, 002, 005, 006, 007, 008 |
| 004 | Trace producers duplicate wire emission/process-supervision concepts | Open | 003 recommended | 001, 002, 005, 006, 008 |
| 005 | Tool entrypoints still look like folded legacy binaries instead of uniform subcommands | Open | None | 001, 003, 006, 007, 008 |
| 006 | Error handling conventions differ across public module boundaries | Open | None | 001, 003, 005, 007, 008 |
| 007 | Global mutable state makes components hard to test or instantiate cleanly | Open | None | 001, 003, 005, 006, 008 |
| 008 | Outdated, misleading, or history-heavy comments and compatibility shims remain | Open | None | All other tasks if edits do not touch the same lines |

## Smaller cleanup items that can be batched into the detailed tasks

- Update stale `sud/sudtrace.c` help text that says `Decode with: yeetdump FILE`; the current user-facing path is `tv dump FILE`.
- Audit references to former standalone binaries (`sudtrace`, `yeetdump`, `fv`) and decide whether they are historical notes, user-facing compatibility promises, or stale names.
- Decide whether `TvDb::ensure_canon_table()` remains a required compatibility API. If it stays, document the deprecation plan; if it goes, update all call sites and tests.
- Replace comments containing reviewer/user-history rationale with current invariants and measurable constraints.
- Align README command examples with the actual top-level usage and subcommand names.
- Avoid adding new grandiose comments. New comments should describe invariants, constraints, ownership, or non-obvious platform behavior.

## General implementation rules for all tasks

- Preserve behavior unless the task explicitly calls for an API migration.
- Keep public interfaces small and named after domain concepts, not current implementation workarounds.
- Split mechanical moves from behavior changes. A reviewer should be able to verify one concern at a time.
- Add or update tests for behavior changes. Documentation-only or comment-only edits do not need test changes.
- Prefer existing build/test targets: `make tv`, `make test`, `make wire-test`, and relevant `tests/*.sh` scripts when environment support is available.
