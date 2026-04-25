# 005: Make tool entrypoints and subcommands uniform

## Goal

Replace the current folded-binary feel with an explicit subcommand architecture.

## Current symptoms

- `main.cpp` declares external `*_main` entrypoints for `uproctrace`, `fv`, `sudtrace`, and `yeetdump`.
- Top-level dispatch is a chain of string comparisons in `main()`.
- Usage text mixes primary viewer modes, compatibility flags, and former standalone tool names.
- Legacy long-flag entrypoints such as `--uproctrace` and `--test` are still handled inline.
- Some tool help text still points at former names, for example `sud/sudtrace.c` says to decode with `yeetdump FILE`.

## Primary files

- `/home/runner/work/tv/tv/main.cpp`
- `/home/runner/work/tv/tv/fv.cpp`
- `/home/runner/work/tv/tv/uproctrace.cpp`
- `/home/runner/work/tv/tv/sud/sudtrace.c`
- `/home/runner/work/tv/tv/tools/yeetdump/yeetdump.c`
- `/home/runner/work/tv/tv/README.md`
- `/home/runner/work/tv/tv/Makefile`

## Dependencies

- None.
- Coordinate with 002 if both edit `main.cpp`.

## Can run concurrently with

- 001, 003, 006, 007, 008 if files do not overlap.

## Instructions for a coding agent

1. Define a small subcommand table or dispatcher abstraction with name, help summary, compatibility aliases, and function pointer.
2. Keep old command aliases if compatibility is intentional, but mark them in one place.
3. Move each tool's usage text near its entrypoint or into a uniform registration shape.
4. Update README examples and help strings after command behavior is confirmed.
5. Keep C/C++ linkage constraints intact for C tools linked into the C++ binary.
6. Do not remove a legacy alias unless tests and documentation are updated and the change is intentional.

## Acceptance criteria

- Adding a new subcommand does not require editing a long ad-hoc `if` chain.
- Former standalone names are either compatibility aliases or removed from user-facing help.
- `tv --help`/usage and README agree on supported commands.
- The stale `yeetdump` decode instruction is fixed.

## Validation

- Build `tv`.
- Run `tv test`, `tv dump --selftest`, and basic `tv <subcommand> --help` smoke checks where applicable.
