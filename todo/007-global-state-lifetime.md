# 007: Reduce global mutable state and clarify ownership/lifetime

## Goal

Make components easier to test, instantiate, and reason about by reducing mutable globals and static lifetime coupling.

## Current symptoms

- `engine.cpp` uses process-global signal/atexit state for terminal restoration.
- `fv.cpp` has a global `FvState g` and static `Box` layout objects.
- `uproctrace.cpp` keeps global output, wire state, stdout stat, and tracing config.
- `sud/event.c` exports many globals through `sud/event.h`; some are generic execution state, others trace-writer state.
- `main.cpp` uses static `Box` objects and timer-local static scroll/mode state for an interactive session.

## Primary files

- `/home/runner/work/tv/tv/engine.cpp`
- `/home/runner/work/tv/tv/fv.cpp`
- `/home/runner/work/tv/tv/uproctrace.cpp`
- `/home/runner/work/tv/tv/main.cpp`
- `/home/runner/work/tv/tv/sud/event.c`
- `/home/runner/work/tv/tv/sud/event.h`

## Dependencies

- None.
- Coordinate with 001 for engine lifetime changes and 003 for SUD globals.

## Can run concurrently with

- 002, 005, 006, 008 where files do not overlap.

## Instructions for a coding agent

1. Classify each global as process-wide by necessity, session-specific, cache, configuration, or compatibility shim.
2. Move session-specific state into context structs owned by the relevant run/session function.
3. Keep truly process-wide state small and documented, especially signal handlers and freestanding SUD state.
4. Avoid introducing singletons as a replacement for globals.
5. For C/freestanding code, prefer explicit context structs only where they do not break signal-safety or startup constraints.
6. Ensure cleanup paths remain correct when state becomes owned by an object/context.

## Acceptance criteria

- `fv` and viewer sessions no longer rely on unnecessary global app state.
- `uproctrace` output/wire state ownership is clearer.
- Engine terminal restoration does not expose hidden multi-instance hazards without documentation.
- SUD global exports are reduced or grouped by generic execution vs trace writer responsibilities.

## Validation

- Build affected targets.
- Run existing self-tests and relevant integration tests.
- Use sanitizers only if already supported by the repository; do not add new tooling just for this task.
