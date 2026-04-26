# TV Wire Format

## Status of This Memo

This document describes the canonical binary trace format emitted by
`uproctrace`, the `proctrace` kernel module, and `sudtrace`. The format
definition in `wire.h` is normative; this document is the companion
protocol description intended to be sufficient for independent
implementations of conformant emitters and processors.

## Scope

This document specifies:

* the yeet byte encoding primitive
* the top-level stream layout
* versioned event encoding rules
* event-class semantics and field meanings
* decoder requirements for malformed inputs
* the reference trace files shipped in this directory

This document does not specify producer-side collection policy (for
example, when a tracer chooses to emit `EV_ENV`) beyond the wire-level
requirements for bytes once an event is emitted.

## Conformance Language

The key words “MUST”, “MUST NOT”, “SHOULD”, “SHOULD NOT”, and “MAY” are
to be interpreted as described in RFC 2119.

## Integer and Byte Conventions

All fixed-width integers are signed or unsigned 64-bit conceptual values
unless stated otherwise. Little-endian byte order is used whenever raw
integer bytes appear in the encoding.

Strings are byte sequences, not text. Producers and processors MUST NOT
assume UTF-8 or any other character encoding. NUL bytes are permitted in
all blobs.

## 1. Yeet Atom Encoding

The stream is a sequence of yeet atoms. Every atom is self-delimiting.

### 1.1 Forms

Let the first byte be `b`.

* `0x00..0xBF`: the atom length is 1 byte and the payload is the single
  byte `b`.
* `0xC0..0xF7`: inline form. Payload length is `b - 0xC0` (0..55). The
  payload immediately follows the tag.
* `0xF8..0xFF`: long form. Let `lensz = b - 0xF8` (0..7). The next
  `lensz` bytes are a little-endian unsigned payload length. The payload
  bytes follow immediately after the length field.

Conformant encoders and decoders in this repository MUST support payload
lengths up to `2^56 - 1` and MUST reject longer encodings.

### 1.2 Canonical Integer Encoding

Unsigned integers are encoded as the minimal-length little-endian byte
string and then wrapped as a yeet atom.

Signed integers are encoded by zigzagging to an unsigned integer:

* `u = (v << 1) ^ (v >> 63)`

and then applying the unsigned integer encoding above.

Processors MUST accept any valid yeet atom for a blob. Integer decoders
MUST reject atom payloads longer than 8 bytes.

## 2. Stream Layout

A wire stream is:

1. exactly one version atom
2. zero or more event atoms

There are no packet markers, checksums, or record trailers.

The first atom MUST decode as either:

* `WIRE_VERSION_V1` (`1`)
* `WIRE_VERSION_V2` (`2`)

Streams with any other version value MUST be rejected.

## 3. Event Framing

Each event is stored as one outer yeet atom. The payload of that atom is:

* for version 1: `header || blob`
* for version 2: `stream_id || header || blob`

Where:

* `stream_id` is one yeet-encoded unsigned integer
* `header` is a concatenation of yeet-encoded signed integers
* `blob` is the unstructured trailing byte payload for that event class

Version 1 has a single delta state for the whole stream. Version 2 has
one delta state per `stream_id`.

## 4. Delta-Coded Header

Each event header begins with seven base fields, all encoded as zigzagged
delta values against the previous event in the same stream state:

1. `type`
2. `ts_ns`
3. `pid`
4. `tgid`
5. `ppid`
6. `nspid`
7. `nstgid`

After the seven base fields come zero or more type-specific extra fields.
Extras are encoded as signed integers but are **not** delta-coded.

The initial state for every stream is all zeros.

## 5. Version Semantics

### 5.1 Version 1

Version 1 maintains one stream-wide delta state. Multiple producers
writing to the same output MUST externally serialize event emission if
they share a v1 stream.

### 5.2 Version 2

Version 2 prefixes every event payload with `stream_id`. Each distinct
`stream_id` maintains an independent delta state, initialized to zeros.

`stream_id = 0` is the default stream. Decoders in this repository also
accept legacy v1-shaped events on the default stream for compatibility.

## 6. Event Classes

The event type codes are:

| Code | Name | Blob | Extras |
| ---: | :--- | :--- | ---: |
| 0 | `EV_EXEC` | executable path bytes | 0 |
| 1 | `EV_ARGV` | NUL-separated argv bytes | 0 |
| 2 | `EV_ENV` | NUL-separated environment bytes | 0 |
| 3 | `EV_AUXV` | raw `Elf*_auxv_t[]` bytes | 0 |
| 4 | `EV_EXIT` | empty | 4 |
| 5 | `EV_OPEN` | opened path bytes | 7 |
| 6 | `EV_CWD` | cwd path bytes | 0 |
| 7 | `EV_STDOUT` | stdout bytes | 0 |
| 8 | `EV_STDERR` | stderr bytes | 0 |

Unknown event types MUST be rejected by processors that require semantic
decoding.

### 6.1 Common Header Fields

* `ts_ns`: event timestamp in nanoseconds
* `pid`: process ID
* `tgid`: thread-group ID
* `ppid`: parent process ID
* `nspid`: PID as observed in the traced namespace
* `nstgid`: TGID as observed in the traced namespace

### 6.2 `EV_EXIT` Extras

`EV_EXIT` carries four extras in this order:

1. `status_kind`: `0` for exited, `1` for signaled
2. `code_or_signal`
3. `core_dumped`
4. `raw`

`blob` MUST be empty.

### 6.3 `EV_OPEN` Extras

`EV_OPEN` carries seven extras in this order:

1. `flags`
2. `fd`
3. `ino`
4. `dev_major`
5. `dev_minor`
6. `err`
7. `inherited`

The trailing `blob` contains the path bytes associated with the open.

## 7. Blob Semantics

Blob bytes are opaque to the wire layer.

Processors MAY interpret blob structure for specific event classes, but
the wire format imposes only the following class-specific conventions:

* `EV_ARGV` and `EV_ENV` blobs are conventionally NUL-separated lists
* `EV_AUXV` blobs are raw auxiliary-vector bytes
* `EV_EXIT` has no blob

A producer MAY omit an event class entirely; omission does not require
any compensating structural changes elsewhere in the stream.

## 8. Error Handling Requirements

Processors MUST reject streams that contain:

* a missing or truncated version atom
* an unknown version
* truncated yeet atoms
* integer atoms longer than 8 bytes where an integer is expected
* malformed stream IDs in version 2
* truncated base headers or extras

Processors MAY stop at the first hard error.

## 9. Reference Traces

This directory contains two reference binary streams:

* `reference-v1.wire`
* `reference-v2.wire`

`reference-v1.wire` demonstrates a single-stream version-1 trace with
`EV_EXEC`, `EV_ARGV`, and `EV_EXIT`.

`reference-v2.wire` demonstrates a multi-stream version-2 trace with two
interleaved `stream_id` values and per-stream delta state.

These files are intended as byte-level interoperability fixtures and may
be rendered with `./yeetdump`.

## 10. Implementation Pointers

The following repository files are the primary format artifacts:

* `wire.h`: normative constants and encoder/decoder helpers
* `wire_in.h`, `wire_in.cpp`: streaming decoder
* `yeetdump.c`: standalone dump and selftest utility

Independent implementations SHOULD match `wire.h` exactly when producing
or consuming the format.
