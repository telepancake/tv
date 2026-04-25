# 003: Split sudtrace into a reusable supervised execution engine plus trace writer

## Goal

Make the SUD resident/prefix program infrastructure reusable for non-tracing tools such as environment spoofing, file access monitoring, performance monitoring, or policy enforcement.

## Current symptoms

- `sud/sudtrace.c` is a launcher whose process supervision, wrapper selection, output setup, shared state page, and trace-specific wire emission are coupled.
- `sud/wrapper.c`, `sud/loader.c`, `sud/handler.c`, and `sud/event.c` are named and documented as sudtrace-specific even when they contain generic SUD execution machinery.
- `sud/event.h` exports globals such as `g_out_fd`, `g_target_exe`, `g_path_env`, and tracing configuration that are shared across loader/handler/event code.
- The SIGSYS handler directly emits tracing events rather than calling through a smaller instrumentation interface.
- The launcher emits `EXIT` events itself, so process supervision and trace writing are intertwined.

## Primary files

- `/home/runner/work/tv/tv/sud/sudtrace.c`
- `/home/runner/work/tv/tv/sud/wrapper.c`
- `/home/runner/work/tv/tv/sud/loader.c`
- `/home/runner/work/tv/tv/sud/handler.c`
- `/home/runner/work/tv/tv/sud/event.c`
- `/home/runner/work/tv/tv/sud/event.h`
- `/home/runner/work/tv/tv/sud/handler.h`
- `/home/runner/work/tv/tv/sud/libc.*`
- `/home/runner/work/tv/tv/sud/raw.*`

## Dependencies

- No hard prerequisite.
- Should happen before issue 004 if issue 004 consolidates producer behavior around the new engine.

## Can run concurrently with

- 001, 002, 005, 006, 007, 008, as long as edits do not conflict in `sud/*`.

## Instructions for a coding agent

1. Identify which parts are generic supervised execution: argument preparation, target resolution, ELF-class wrapper selection, SUD setup, syscall dispatch, child preparation, seccomp handling, signal handling, and wait/reap behavior.
2. Identify which parts are trace-specific: wire version selection, event encoding, stdout/stderr capture policy, inherited-fd emission, `--no-env`, and trace output fd naming.
3. Define a small instrumentation interface that the SUD handler can call without knowing that the implementation writes tv wire events.
4. Keep freestanding constraints explicit. Anything used by `sud32`/`sud64` must remain compatible with `-nostdlib`, raw syscalls, async-signal safety, and both 32-bit and 64-bit builds.
5. Do not convert everything at once. First extract names and boundaries, then move trace writer code behind the interface, then add reusable engine documentation.
6. Preserve the current `tv sud` behavior and command-line options during the extraction.

## Acceptance criteria

- There is a clearly named supervised execution layer that is not trace-writer-specific.
- Trace writing is implemented on top of that layer through a narrow interface.
- SUD handler code no longer has to know high-level `sudtrace` launcher details beyond the interface.
- Future tools can reuse the resident/prefix infrastructure without copying trace writer code.
- Existing SUD tests remain valid.

## Validation

- Build `sud64` and `sud32` where toolchain support exists.
- Build `tv`.
- Run `tests/sudtrace_test.sh` and `tests/sud_stress.sh` when environment support exists.
