# 004: Unify trace producer boundaries and remove duplicated supervision/wire concepts

## Goal

Make kernel-module, ptrace, and SUD producers share clear concepts while preserving their platform-specific mechanics.

## Current symptoms

- `proctrace.c`, `uproctrace.cpp`, and `sud/event.c` all emit the same wire event model but use different state ownership and comments.
- `uproctrace.cpp` has its own output ring, writer thread, wire emission lock, process maps, syscall state, and CLI handling in one large file.
- `sud/event.c` uses wire v2 stream IDs while `wire/wire.h` defaults `WIRE_VERSION` to v1 for other producers. This is valid but needs an explicit producer policy.
- Similar event concepts (`EXEC`, `ARGV`, `ENV`, `AUXV`, inherited `OPEN`, `EXIT`, stdio capture) appear in multiple producers without a shared checklist or conformance tests.
- Producer-specific comments explain history rather than current invariants.

## Primary files

- `/home/runner/work/tv/tv/wire/wire.h`
- `/home/runner/work/tv/tv/wire_in.cpp`
- `/home/runner/work/tv/tv/proctrace.c`
- `/home/runner/work/tv/tv/uproctrace.cpp`
- `/home/runner/work/tv/tv/sud/event.c`
- `/home/runner/work/tv/tv/sud/event.h`
- `/home/runner/work/tv/tv/tests.cpp`
- `/home/runner/work/tv/tv/tests/trace_compare/run.sh`

## Dependencies

- Recommended after 003 so SUD producer boundaries are stable before producer-wide cleanup.

## Can run concurrently with

- 001, 002, 005, 006, 008.

## Instructions for a coding agent

1. Document the producer contract in one place: event ordering, version choice, stream-id policy, inherited fd behavior, stdio capture policy, and env omission semantics.
2. Add or extend producer conformance tests before refactoring behavior.
3. Split `uproctrace.cpp` into logical units only after tests cover the current event stream.
4. Avoid forcing kernel, ptrace, and SUD code into identical implementations. Share contracts and helpers where practical, not where platform constraints differ.
5. Make wire-version choices explicit per producer rather than relying on a generic `WIRE_VERSION` alias in new code.
6. Ensure `WireDecoder` behavior stays compatible with existing v1 and v2 streams.

## Acceptance criteria

- Each producer states which wire version it emits and why.
- Trace event semantics are testable across at least two producers where the environment supports them.
- Large producer files have clearer internal sections or are split into modules with one responsibility each.
- Refactoring does not change the persisted `.tvdb` schema unless a separate migration task is created.

## Validation

- Build `tv` and the kernel module target when kernel headers are available.
- Run `make test` and trace comparison scripts where prerequisites exist.
- Verify `tv dump` can read representative traces from all supported producer types.
