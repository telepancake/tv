# tv trace CTF 1.8 schema

This document defines the on-the-wire format produced by `proctrace` (kernel
module), `sudtrace` (freestanding sud32/sud64 helpers), and `uproctrace`
(ptrace-based userspace tracer), and consumed by `ctf2parquet`. It is
intentionally a **strict superset** of CTF 1.8 packet framing so that
`babeltrace2 --input-format=ctf` can read it given the metadata stream.

The full machine-readable definition lives in `ctf/metadata.tsdl`; this file
is the human-friendly companion.

## Why these choices

* **Packets are sealed before commit.** The header carries
  `timestamp_end` and `content_size`, which are written into a per-session
  staging buffer at the moment the packet is sealed; the staging buffer is
  then handed to the ring/output as a single contiguous unit. **No
  back-patching of the output stream is ever required.** This matters for
  the kernel module (which streams via `read()` on `/proc/proctrace/new`)
  and for the freestanding sud helpers (which write into a single shared
  fd from a signal handler).
* **Per-stream timestamp delta encoding.** Each event's timestamp is a
  ULEB128-encoded delta against `packet.context.timestamp_begin`, and a
  packet covers at most `2^32 - 1` ns (~4.3 s), so a delta fits in 5 bytes
  and most fit in 1–3.
* **Strings are bytes, not text.** Linux paths, argv entries, and
  environment values are bytes with no encoding contract. Every "string"
  field in the schema is `{ u32 len; u8 data[len]; }` with no NUL
  terminator and no claimed character set. Embedded NULs are legal.
  Decoders (Parquet writer, TUI) are responsible for rendering whatever
  bytes are there.
* **`exec` argv/env/auxv are emitted as raw blobs.** The kernel and the
  ptrace tracer already have these structures laid out by the loader as
  contiguous memory: NUL-separated argv/env strings as the `execve`
  argument vector, and a `Elf{32,64}_auxv_t[]` array for the auxiliary
  vector. The tracer dumps those bytes verbatim. The converter splits
  argv on NUL, splits env on `=`, and decodes the auxv array. Doing the
  parsing in the tracer is wasted work and adds escaping bugs.
* **One stream per producer thread.** Multiple producer threads can write
  concurrently into independent streams (multiplexed onto a single fd by
  the kernel module via the ring buffer; trivially independent in the
  ptrace and sud cases since both produce a single stream per process).
  This avoids any cross-thread timestamp contention.

## Trace packet layout

```
+---------------------------+ packet boundary
| packet.header             |   8B magic + 16B uuid + 4B stream_id  = 28 B
| packet.context            |   2 * u64 ts + 2 * u32 sizes + ...    = 32 B
| event*                    |   variable
| padding                   |   to packet_size
+---------------------------+
```

### `packet.header` (CTF-required magic)

| field      | bits | notes                                            |
|------------|------|--------------------------------------------------|
| `magic`    |   32 | `0xC1FC1FC1` little-endian                       |
| `uuid`     |  128 | trace UUID; same in every packet of a trace      |
| `stream_id`|   32 | always `0` in this schema (single stream class)  |

### `packet.context`

| field              | bits | notes                                   |
|--------------------|------|-----------------------------------------|
| `timestamp_begin`  |   64 | ns since Unix epoch, monotonic clock    |
| `timestamp_end`    |   64 | ns since Unix epoch; sealed at flush    |
| `content_size`     |   32 | bits of valid content (excludes padding)|
| `packet_size`      |   32 | total packet bits (always a multiple of 8)|
| `producer_id`      |   16 | stream-distinguishing id (cpu, tid, ...)|
| `events_discarded` |   32 | cumulative events lost since stream start (always 0 today; kept for future backpressure exposure) |

### `event.header`

Common to every event, regardless of class.

| field    | bits | notes                                              |
|----------|------|----------------------------------------------------|
| `id`     |   16 | event class id (table below)                       |
| `ts_delta` | varint (ULEB128) | ns since `packet.timestamp_begin`        |
| `pid`    |   32 | kernel TID                                         |
| `tgid`   |   32 | kernel TGID — primary process identifier           |
| `ppid`   |   32 | parent TGID (init namespace)                       |
| `nspid`  |   32 | TID in the process's pid namespace                 |
| `nstgid` |   32 | TGID in the process's pid namespace                |

## Event classes

| id | name     | payload                                              |
|----|----------|------------------------------------------------------|
| 0  | `exec`   | `string exe; bytes argv_blob; bytes env_blob; bytes auxv_blob` |
| 1  | `exit`   | `u8 status; i32 code_or_signal; u8 core_dumped; i32 raw` |
| 2  | `open`   | `string path; u32 flags; i32 fd; u64 ino; u32 dev_major; u32 dev_minor; i32 err; u8 inherited` |
| 3  | `cwd`    | `string path`                                        |
| 4  | `stdout` | `bytes data`                                         |
| 5  | `stderr` | `bytes data`                                         |

All composite types use the layouts:

```
string : { u32 len; u8  data[len]; }   // bytes, no encoding contract
bytes  : { u32 len; u8  data[len]; }   // alias for clarity at call sites
```

### `exec` blobs

* `argv_blob` is the byte image of the original `execve` argv vector,
  i.e. the NUL-separated argv strings concatenated in order. The
  converter splits on NUL to reconstruct individual argv entries.
  Empty blob (`len == 0`) means the tracer could not read argv.
* `env_blob` is the byte image of the original `execve` envp vector,
  laid out the same way (NUL-separated `KEY=VALUE` strings). Tracers
  capturing without `--no-env` emit it; with `--no-env` they emit
  `len == 0`.
* `auxv_blob` is the byte image of the architecture's `Elf{32,64}_auxv_t`
  array as the kernel placed it on the stack: a sequence of
  `(unsigned long a_type, union a_un)` pairs terminated by an
  `AT_NULL` entry. The converter decodes only the entries the schema
  cares about (`AT_UID`, `AT_EUID`, `AT_GID`, `AT_EGID`, `AT_SECURE`,
  `AT_CLKTCK`, `AT_EXECFN`, `AT_PLATFORM`); the rest is dropped.

### `exit.status`

| value | meaning      |
|-------|--------------|
| 0     | `exited`     — `code_or_signal` is the exit code (0–255) |
| 1     | `signaled`   — `code_or_signal` is the signal number     |

`core_dumped` is meaningful only when `status == 1`.

### `open.flags`

The raw `int` flags passed to `open()`/`openat()`. The converter
decodes these into the symbolic `O_*` set. For inherited fds the
flags reflect the post-exec state of the descriptor.

`fd >= 0` and `err == 0` ⇒ success: `ino`, `dev_major`, `dev_minor`
are valid. Otherwise `err` is a negative errno, `fd` is `-1`, and
the inode/dev fields are zero.

`inherited == 1` for the synthetic OPEN events emitted at exec time.

## Endianness

Little-endian throughout. The CTF metadata declares `byte_order = le;`.

## Compression

Producers emit the raw CTF stream. Optional zstd compression is the
caller's choice (`uproctrace` honors `-o trace.ctf.zst`; the kernel
module never compresses; sud32/sud64 never compress). The converter
auto-detects zstd via the magic bytes.
