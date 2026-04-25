# 001: Make the TUI engine a clean API instead of an implementation-shaped wrapper

## Goal

Turn `engine.h` / `engine.cpp` into a stable, minimal TUI component API that applications can use without depending on internal layout and cache mechanics.

## Current symptoms

- `engine.h` mixes API styles: anonymous enums, `inline constexpr int`, and `enum class RowStyle`.
- `Tui::Impl` is forward-declared in the public header with a comment saying it is exposed for `engine.cpp` helpers.
- `Box` is a mutable public tree whose fields are edited directly by application code (`main.cpp` mutates `weight`, `min_size`, and `panel`).
- The engine owns row caching, lazy iteration, cursor resolution, rendering, fd watches, timers, prompts, and layout in one large implementation file.
- Public constants such as panel flags, box types, key codes, callback return codes, alignment, and overflow policy are not grouped by concept.

## Primary files

- `/home/runner/work/tv/tv/engine.h`
- `/home/runner/work/tv/tv/engine.cpp`
- `/home/runner/work/tv/tv/main.cpp`
- `/home/runner/work/tv/tv/fv.cpp`
- `/home/runner/work/tv/tv/data_source.h`

## Dependencies

- No hard prerequisite.
- Prefer doing this before issue 002 so the viewer can target the cleaned API instead of codifying current workarounds.

## Can run concurrently with

- 003, 005, 006, 007, 008, if those changes avoid overlapping edits in `engine.*` and `main.cpp`.

## Instructions for a coding agent

1. Map the current public surface and all call sites before changing names or types.
2. Group API concepts explicitly: key codes, callback results, panel flags, layout primitives, row style, data source contract, and lifecycle.
3. Hide implementation details from the public header. Do not expose `Impl` or internal helper needs as public API rationale.
4. Replace direct `Box` field mutation at call sites with a small layout API or builder-style helper. Keep the migration incremental.
5. Keep `DataSource` contract clear: specify ownership, row lifetime, cache behavior, and whether callbacks may be missing.
6. Split large mechanical changes into stages: type cleanup, layout ownership cleanup, then helper/function decomposition.

## Acceptance criteria

- Application code does not need to know about `Tui::Impl`.
- Public constants follow one consistent style and are grouped by domain.
- Layout mutation from callers is reduced or wrapped in named methods.
- Existing viewer and `fv` behavior remains unchanged.
- Tests or headless dumps still pass after API migration.

## Validation

- Build `tv`.
- Run `make test` when dependencies are present.
- Run any headless/dump smoke tests already used by the repository.
