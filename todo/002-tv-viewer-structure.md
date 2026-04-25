# 002: Restructure tv viewer code into clear, uniformly structured components

## Goal

Separate the viewer application into components with clear ownership: command-line setup, live/ingest plumbing, viewer state, layout, key handling, and SQL-backed row models.

## Current symptoms

- `main.cpp` contains subcommand dispatch, ingest, live tracing, TUI construction, key handling, status text, htop visibility, hat syncing, timer behavior, dump mode, and process cleanup.
- `data_source.h` exposes a large `AppState` and `TvDataSource` with many mode-specific methods and cache fields.
- `TvDataSource` cache invalidation mirrors many `AppState` fields using `built_for_*` copies. Adding one state field requires remembering to update cache keys.
- Hat/breadcrumb panels are built in `TvDataSource`, sized by `main.cpp`, and rendered by the engine. This spreads one feature over three layers.
- Mode concepts (`0` output, `1` process, etc.) are represented as raw integers across status text, help, dumps, SQL, and key handling.

## Primary files

- `/home/runner/work/tv/tv/main.cpp`
- `/home/runner/work/tv/tv/data_source.h`
- `/home/runner/work/tv/tv/data_source.cpp`
- `/home/runner/work/tv/tv/tv_db.h`
- `/home/runner/work/tv/tv/tv_db.cpp`
- `/home/runner/work/tv/tv/engine.h`

## Dependencies

- Recommended after 001 so viewer layout can use a cleaner engine API.
- If removing `ensure_canon_table()`, coordinate with 008 or do that first as a focused cleanup.

## Can run concurrently with

- 003, 004, 005, 006, 008, if edits do not overlap `main.cpp` or `data_source.*`.

## Instructions for a coding agent

1. Inventory current responsibilities in `main.cpp` and `data_source.*`.
2. Introduce named viewer concepts before moving logic: mode enum, state snapshot/cache key, layout controller, key controller, live trace session, and dump request.
3. Replace raw mode integers at internal boundaries with a named type while keeping CLI compatibility.
4. Create a single cache-key representation for `TvDataSource` instead of many `built_for_*` fields.
5. Move hat/breadcrumb sizing into either a viewer layout controller or the engine layout API. Avoid leaving sizing split across timer callbacks and data source methods.
6. Keep SQL query behavior unchanged during structural moves. Do not rewrite queries unless the issue being fixed requires it.

## Acceptance criteria

- `main.cpp` is mostly orchestration and no longer owns detailed viewer behavior.
- `TvDataSource` has a clear cache invalidation model.
- Mode names are discoverable and not duplicated as raw numbers everywhere.
- Hat/breadcrumb behavior is owned by one layer.
- Dump mode and interactive mode share the same mode definitions.

## Validation

- Build `tv`.
- Run `make test` where available.
- Exercise at least one `--dump` mode from an existing test fixture or generated trace.
