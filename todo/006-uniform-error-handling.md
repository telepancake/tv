# 006: Make error handling uniform across module boundaries

## Goal

Use consistent error reporting patterns so callers can display useful failures without scraping stderr or losing context.

## Current symptoms

- `Tui::open()` returns `nullptr` without a structured error.
- `TvDb` methods use `std::string *err` out-parameters.
- `WireDecoder::feed()` returns `bool` without detailed decode errors.
- Ingest functions print some errors to stderr inside callbacks and also return status to callers.
- `TvDataSource` often turns SQL/index failures into synthetic rows, while other code prints and exits.
- C and freestanding SUD code must not use the same C++ mechanisms as the viewer, but the boundary between low-level status and user-facing messages is not documented.

## Primary files

- `/home/runner/work/tv/tv/engine.h`
- `/home/runner/work/tv/tv/engine.cpp`
- `/home/runner/work/tv/tv/wire_in.h`
- `/home/runner/work/tv/tv/wire_in.cpp`
- `/home/runner/work/tv/tv/tv_db.h`
- `/home/runner/work/tv/tv/tv_db.cpp`
- `/home/runner/work/tv/tv/data_source.cpp`
- `/home/runner/work/tv/tv/main.cpp`
- `/home/runner/work/tv/tv/sud/*`

## Dependencies

- None.
- Coordinate with 001 and 002 if changing public C++ APIs.

## Can run concurrently with

- 003, 005, 007, 008.

## Instructions for a coding agent

1. Choose conventions per layer: C++ application/library APIs, C-linked tools, freestanding SUD code, and kernel module code.
2. Do not force exceptions into the codebase unless the project already opts into them consistently.
3. Prefer returning structured error context at module boundaries and printing only at top-level command boundaries.
4. Ensure callbacks that can fail have a way to propagate failure to the owner.
5. Keep UI-facing synthetic error rows where they improve interactive behavior, but make the source error available to callers/tests.
6. Document the chosen conventions in headers where public APIs expose errors.

## Acceptance criteria

- New public APIs have predictable error semantics.
- Top-level commands decide how to print errors.
- Decode, ingest, database, and TUI initialization failures carry actionable messages.
- Tests can assert error cases without relying only on stderr text.

## Validation

- Build `tv`.
- Run existing tests.
- Add focused tests only for newly introduced error behavior.
