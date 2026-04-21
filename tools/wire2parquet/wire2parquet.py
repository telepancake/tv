#!/usr/bin/env python3
# wire2parquet — decode a tv wire stream to per-event-class Parquet files.
#
#   wire2parquet trace.wire [trace.wire …] -o OUTDIR
#
# Input is a flat byte stream as produced by sud, proctrace and uproctrace
# (see wire/wire.h). `.zst` inputs are auto-decompressed if zstandard is
# available, otherwise pipe through `zstd -dc`.
#
# Output is OUTDIR/{exec,argv,env,auxv,exit,open,cwd,stdout,stderr}.parquet,
# each compressed with zstd. Column choices match the wire layer: argv/env
# blobs are split into one row per argument / per env entry; auxv into one
# row per (a_type, a_val) pair; everything else is one row per event.
#
# This is the canonical reference decoder. Bytes in === decoded rows out;
# any change to wire/wire.h must be mirrored here in lockstep.

from __future__ import annotations

import argparse
import os
import struct
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

# ── wire constants (must mirror wire/wire.h) ──────────────────────────
WIRE_VERSION = 1

EV_EXEC, EV_ARGV, EV_ENV, EV_AUXV, EV_EXIT, EV_OPEN, EV_CWD, EV_STDOUT, EV_STDERR = range(9)

EV_NAMES = {
    EV_EXEC: "exec",   EV_ARGV: "argv",   EV_ENV:  "env",
    EV_AUXV: "auxv",   EV_EXIT: "exit",   EV_OPEN: "open",
    EV_CWD:  "cwd",    EV_STDOUT: "stdout", EV_STDERR: "stderr",
}

# Number of trailing i64 extras per event class.
EXTRAS = {EV_EXIT: 4, EV_OPEN: 7}

# ── yeet decode primitives (mirror of wire/wire.h's yeet_get / yeet_get_i64) ─

def yeet_get(buf: memoryview, p: int) -> tuple[memoryview, int]:
    """Return (payload_view, new_p) for one atom starting at buf[p]."""
    n = len(buf)
    if p >= n:
        raise ValueError("truncated atom: at end of buffer")
    b = buf[p]
    if b < 0xC0:
        return buf[p:p + 1], p + 1
    if b < 0xF8:
        ln = b - 0xC0
        if p + 1 + ln > n:
            raise ValueError("truncated inline atom")
        return buf[p + 1:p + 1 + ln], p + 1 + ln
    lensz = b - 0xF8
    if p + 1 + lensz > n:
        raise ValueError("truncated long atom length")
    ln = 0
    for i in range(lensz):
        ln |= buf[p + 1 + i] << (8 * i)
    end = p + 1 + lensz + ln
    if end > n:
        raise ValueError(f"truncated long atom: need {ln} bytes")
    return buf[p + 1 + lensz:end], end


def yeet_get_u64(buf: memoryview, p: int) -> tuple[int, int]:
    payload, p = yeet_get(buf, p)
    if len(payload) > 8:
        raise ValueError("u64 atom > 8 bytes")
    v = 0
    for i, x in enumerate(payload):
        v |= x << (8 * i)
    return v, p


def yeet_get_i64(buf: memoryview, p: int) -> tuple[int, int]:
    u, p = yeet_get_u64(buf, p)
    # zigzag decode in two's-complement 64-bit
    v = (u >> 1) ^ -(u & 1)
    # signed clamp into 64 bits
    if v >= (1 << 63):
        v -= 1 << 64
    return v, p


# ── per-class column accumulators ─────────────────────────────────────

class _Cols:
    """Append-only column store for one event class. Flushed to parquet
    in row groups of ROW_GROUP_BYTES total raw bytes worth of data."""
    ROW_GROUP_BYTES = 64 * 1024 * 1024

    def __init__(self, schema: pa.Schema):
        self.schema = schema
        self.cols: dict[str, list] = {f.name: [] for f in schema}
        self._approx_bytes = 0

    def append(self, **kw):
        for k, v in kw.items():
            self.cols[k].append(v)
            if isinstance(v, (bytes, bytearray, memoryview)):
                self._approx_bytes += len(v)
            else:
                self._approx_bytes += 8
        # Sanity: every column must advance in lockstep.
        n = len(next(iter(self.cols.values())))
        for k, lst in self.cols.items():
            if len(lst) != n:
                raise RuntimeError(f"column {k!r} out of sync: {len(lst)} vs {n}")

    def make_batch(self) -> pa.RecordBatch | None:
        n = len(next(iter(self.cols.values())))
        if n == 0:
            return None
        arrays = [pa.array(self.cols[f.name], type=f.type) for f in self.schema]
        for k in self.cols:
            self.cols[k].clear()
        self._approx_bytes = 0
        return pa.RecordBatch.from_arrays(arrays, schema=self.schema)


def _hdr_fields() -> list[pa.Field]:
    """Common header columns shared by every event class."""
    return [
        pa.field("ts_ns", pa.uint64()),
        pa.field("pid",    pa.int32()),
        pa.field("tgid",   pa.int32()),
        pa.field("ppid",   pa.int32()),
        pa.field("nspid",  pa.int32()),
        pa.field("nstgid", pa.int32()),
    ]


def _build_schemas() -> dict[int, pa.Schema]:
    h = _hdr_fields()
    return {
        EV_EXEC:   pa.schema(h + [pa.field("exe",  pa.binary())]),
        EV_ARGV:   pa.schema(h + [pa.field("idx",  pa.uint32()),
                                   pa.field("arg",  pa.binary())]),
        EV_ENV:    pa.schema(h + [pa.field("idx",  pa.uint32()),
                                   pa.field("key",  pa.binary()),
                                   pa.field("val",  pa.binary())]),
        EV_AUXV:   pa.schema(h + [pa.field("a_type", pa.uint64()),
                                   pa.field("a_val",  pa.uint64())]),
        EV_EXIT:   pa.schema(h + [pa.field("status_kind", pa.int8()),
                                   pa.field("code_or_sig", pa.int32()),
                                   pa.field("core_dumped", pa.bool_()),
                                   pa.field("raw",          pa.int32())]),
        EV_OPEN:   pa.schema(h + [pa.field("flags",      pa.int32()),
                                   pa.field("fd",         pa.int32()),
                                   pa.field("ino",        pa.uint64()),
                                   pa.field("dev_major",  pa.uint32()),
                                   pa.field("dev_minor",  pa.uint32()),
                                   pa.field("err",        pa.int32()),
                                   pa.field("inherited",  pa.bool_()),
                                   pa.field("path",       pa.binary())]),
        EV_CWD:    pa.schema(h + [pa.field("cwd",  pa.binary())]),
        EV_STDOUT: pa.schema(h + [pa.field("data", pa.binary())]),
        EV_STDERR: pa.schema(h + [pa.field("data", pa.binary())]),
    }


# ── decoder ───────────────────────────────────────────────────────────

class WireToParquet:
    """Decode a wire stream into per-event-class Parquet files in `outdir`."""

    def __init__(self, outdir: Path, *, compression: str = "zstd",
                 compression_level: int = 3):
        outdir.mkdir(parents=True, exist_ok=True)
        self.outdir = outdir
        self.compression = compression
        self.compression_level = compression_level

        self.schemas = _build_schemas()
        self.cols: dict[int, _Cols] = {ev: _Cols(s) for ev, s in self.schemas.items()}
        self.writers: dict[int, pq.ParquetWriter] = {}

        # delta-decoder state, one per stream
        self._reset_state()
        # stats
        self.events_decoded = 0

    def _reset_state(self):
        self.s_type = 0
        self.s_ts   = 0
        self.s_pid  = 0
        self.s_tgid = 0
        self.s_ppid = 0
        self.s_nspid  = 0
        self.s_nstgid = 0

    def _get_writer(self, ev: int) -> pq.ParquetWriter:
        w = self.writers.get(ev)
        if w is None:
            path = self.outdir / f"{EV_NAMES[ev]}.parquet"
            w = pq.ParquetWriter(
                path, self.schemas[ev],
                compression=self.compression,
                compression_level=self.compression_level,
                use_dictionary=False,
            )
            self.writers[ev] = w
        return w

    def _maybe_flush(self, ev: int):
        c = self.cols[ev]
        if c._approx_bytes >= _Cols.ROW_GROUP_BYTES:
            batch = c.make_batch()
            if batch is not None:
                self._get_writer(ev).write_batch(batch)

    def feed(self, data: bytes | bytearray | memoryview):
        """Decode one complete wire stream from `data`. Each call resets
        the delta-decoder state, so call once per source stream."""
        buf = memoryview(data)
        n = len(buf)
        p = 0
        # First atom: WIRE_VERSION.
        version, p = yeet_get_u64(buf, p)
        if version != WIRE_VERSION:
            raise ValueError(
                f"unsupported wire version {version} (expect {WIRE_VERSION})")
        self._reset_state()

        while p < n:
            atom, p = yeet_get(buf, p)
            self._decode_event(atom)

    def _decode_event(self, atom: memoryview):
        # Header is the leading bytes; blob is the remainder.
        ap = 0
        # --- 7 base scalars (all delta i64) ---
        d, ap = yeet_get_i64(atom, ap); self.s_type   += d; type_   = self.s_type
        d, ap = yeet_get_i64(atom, ap); self.s_ts     += d; ts_ns   = self.s_ts
        d, ap = yeet_get_i64(atom, ap); self.s_pid    += d; pid     = self.s_pid
        d, ap = yeet_get_i64(atom, ap); self.s_tgid   += d; tgid    = self.s_tgid
        d, ap = yeet_get_i64(atom, ap); self.s_ppid   += d; ppid    = self.s_ppid
        d, ap = yeet_get_i64(atom, ap); self.s_nspid  += d; nspid   = self.s_nspid
        d, ap = yeet_get_i64(atom, ap); self.s_nstgid += d; nstgid  = self.s_nstgid

        # --- type-specific i64 extras ---
        n_extras = EXTRAS.get(type_, 0)
        extras: list[int] = []
        for _ in range(n_extras):
            v, ap = yeet_get_i64(atom, ap)
            extras.append(v)

        blob = bytes(atom[ap:])

        hdr = dict(ts_ns=ts_ns, pid=pid, tgid=tgid, ppid=ppid,
                   nspid=nspid, nstgid=nstgid)

        if   type_ == EV_EXEC:
            self.cols[EV_EXEC].append(exe=blob, **hdr)
            self._maybe_flush(EV_EXEC)
        elif type_ == EV_ARGV:
            for idx, arg in enumerate(_split_nul(blob)):
                self.cols[EV_ARGV].append(idx=idx, arg=arg, **hdr)
            self._maybe_flush(EV_ARGV)
        elif type_ == EV_ENV:
            for idx, entry in enumerate(_split_nul(blob)):
                eq = entry.find(b"=")
                if eq < 0:
                    key, val = entry, b""
                else:
                    key, val = entry[:eq], entry[eq + 1:]
                self.cols[EV_ENV].append(idx=idx, key=key, val=val, **hdr)
            self._maybe_flush(EV_ENV)
        elif type_ == EV_AUXV:
            for a_type, a_val in _split_auxv(blob):
                self.cols[EV_AUXV].append(a_type=a_type, a_val=a_val, **hdr)
            self._maybe_flush(EV_AUXV)
        elif type_ == EV_EXIT:
            sk, codeorsig, cored, raw = extras
            self.cols[EV_EXIT].append(
                status_kind=sk, code_or_sig=codeorsig,
                core_dumped=bool(cored), raw=raw, **hdr)
            self._maybe_flush(EV_EXIT)
        elif type_ == EV_OPEN:
            flags, fd, ino, dmaj, dmin, err, inh = extras
            self.cols[EV_OPEN].append(
                flags=flags, fd=fd, ino=ino,
                dev_major=dmaj, dev_minor=dmin,
                err=err, inherited=bool(inh), path=blob, **hdr)
            self._maybe_flush(EV_OPEN)
        elif type_ == EV_CWD:
            self.cols[EV_CWD].append(cwd=blob, **hdr)
            self._maybe_flush(EV_CWD)
        elif type_ == EV_STDOUT:
            self.cols[EV_STDOUT].append(data=blob, **hdr)
            self._maybe_flush(EV_STDOUT)
        elif type_ == EV_STDERR:
            self.cols[EV_STDERR].append(data=blob, **hdr)
            self._maybe_flush(EV_STDERR)
        else:
            # Unknown event class within this WIRE_VERSION — refuse to drop
            # silently so format drift is caught loudly.
            raise ValueError(f"unknown event type {type_}")

        self.events_decoded += 1

    def close(self):
        # Flush any buffered rows for every class touched.
        for ev, c in self.cols.items():
            batch = c.make_batch()
            if batch is not None:
                self._get_writer(ev).write_batch(batch)
        for w in self.writers.values():
            w.close()
        self.writers.clear()


# ── small utilities ───────────────────────────────────────────────────

def _split_nul(blob: bytes) -> list[bytes]:
    """Split a NUL-separated blob, dropping a trailing empty entry from
    the kernel's terminating NUL (but not legitimate empty entries)."""
    if not blob:
        return []
    parts = blob.split(b"\x00")
    if parts and parts[-1] == b"":
        parts.pop()
    return parts


_AUXV_PAIR = struct.Struct("<QQ")  # native-LE on Linux for both 32 and 64-bit auxv

def _split_auxv(blob: bytes) -> list[tuple[int, int]]:
    """Decode a saved_auxv blob into (a_type, a_val) pairs, stopping at
    the AT_NULL terminator (a_type == 0)."""
    out = []
    sz = _AUXV_PAIR.size
    n = len(blob) - (len(blob) % sz)
    for off in range(0, n, sz):
        a_type, a_val = _AUXV_PAIR.unpack_from(blob, off)
        if a_type == 0:
            break
        out.append((a_type, a_val))
    return out


def _open_input(path: str | Path):
    """Open a wire file, transparently decompressing .zst with zstandard
    if installed."""
    p = Path(path)
    if p.suffix == ".zst":
        try:
            import zstandard as zstd  # type: ignore
        except ImportError:
            sys.exit(f"{path}: pipe through `zstd -dc` (python zstandard "
                     f"not installed)")
        return zstd.ZstdDecompressor().stream_reader(open(p, "rb"))
    return open(p, "rb")


# ── CLI ───────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Decode a tv wire stream to per-event-class Parquet files.")
    ap.add_argument("inputs", nargs="+", help="wire files (.wire or .wire.zst)")
    ap.add_argument("-o", "--outdir", required=True,
                    help="output directory for per-class Parquet files")
    ap.add_argument("--compression", default="zstd",
                    choices=("zstd", "snappy", "gzip", "none"))
    ap.add_argument("--level", type=int, default=3,
                    help="compression level (default 3)")
    args = ap.parse_args(argv)

    conv = WireToParquet(
        Path(args.outdir),
        compression=args.compression,
        compression_level=args.level,
    )
    for inp in args.inputs:
        with _open_input(inp) as f:
            data = f.read()
        conv.feed(data)
    conv.close()
    print(f"decoded {conv.events_decoded} events into {args.outdir}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
