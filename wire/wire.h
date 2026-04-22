/* wire/wire.h — the only file that knows the tv trace wire format.
 *
 * Self-contained C99. No libc beyond memcpy. Includes correctly from
 *   - the kernel module (proctrace.c),
 *   - freestanding sud helpers (sud32/sud64; no libc),
 *   - userspace tracers (uproctrace, C++),
 *   - the parquet converter, the dump tool, and tests.
 *
 * Format is intentionally fluid. Bump WIRE_VERSION when bytes change;
 * every consumer reads the version atom first and refuses unknown
 * versions. Nothing outside this header should poke at the raw bytes.
 *
 * ── Stream layout ──────────────────────────────────────────────────
 * The stream is a flat sequence of yeet atoms. The first atom is
 *   yeet_u64(WIRE_VERSION_V1)   or   yeet_u64(WIRE_VERSION_V2)
 * everything after is a sequence of one-atom-per-event payloads
 * produced by yeet_pair(out, header, hlen, blob, blen).
 *
 * In v2, the header is preceded by yeet_u64(stream_id); see the
 * comment on WIRE_VERSION_V2 below for the semantics.
 *
 * No packet boundaries. No record-end markers. No back-patching.
 * Producers never need to seek the output. A reader that drops a
 * prefix of bytes can resume on any fresh atom boundary, but in
 * practice the kernel ring is byte-perfect so this never matters.
 *
 * ── Yeet (the byte primitive) ──────────────────────────────────────
 *   b in 0x00..0xBF : 1-byte atom, payload is the single byte b.
 *                                                       (1 byte total)
 *   b in 0xC0..0xF7 : inline atom, len = b - 0xC0 (0..55).
 *                     payload follows.            (1 + len bytes total)
 *   b in 0xF8..0xFF : long atom, lensz = b - 0xF8 (0..7).
 *                     lensz bytes of LE length follow,
 *                     then `length` bytes of payload.
 *                                          (1 + lensz + len bytes total)
 *
 * Round-trips arbitrary byte sequences: every byte value is a legal
 * single-byte atom, every length up to 2^56-1 is a legal long atom.
 *
 * Worst-case overhead for one atom is 8 bytes of prefix (long form,
 * lensz=7), so any inline header field is bounded by 9 bytes
 * (1 tag + at most 8 LE bytes for a u64), and a yeet_pair wrapping
 * (header, blob) costs at most 8 bytes of outer prefix on top of the
 * raw header+blob bytes.
 *
 * ── Event layer ────────────────────────────────────────────────────
 * Each event is one outer atom whose payload is:
 *
 *   header = yeet_i64(type   - prev.type)
 *            yeet_i64(ts_ns  - prev.ts_ns)
 *            yeet_i64(pid    - prev.pid)
 *            yeet_i64(tgid   - prev.tgid)
 *            yeet_i64(ppid   - prev.ppid)
 *            yeet_i64(nspid  - prev.nspid)
 *            yeet_i64(nstgid - prev.nstgid)
 *            [type-specific extras: yeet_i64 each]
 *   blob   = the (possibly empty) opaque payload bytes
 *
 * Producers maintain one ev_state per output stream (v1: one global;
 * v2: one per stream_id). Successive events are delta-encoded against
 * it - typical deltas are one byte. For events with no blob (EV_EXIT)
 * blen == 0; the outer atom is still emitted so event boundaries are
 * explicit.
 *
 * Each event class has at most one blob. argv/env/auxv are separate
 * event classes (EV_ARGV/EV_ENV/EV_AUXV), each with the raw bytes the
 * kernel laid out, so a tracer can omit env by simply not emitting
 * EV_ENV without rearranging anything. The converter splits the blob
 * into individual entries; the tracer never parses it.
 *
 * Strings are bytes. The path / argv / env / stdout / stderr blobs
 * are whatever bytes the kernel handed us, NUL-included. There is no
 * encoding contract anywhere in this format.
 */

#ifndef WIRE_H
#define WIRE_H

#ifdef __KERNEL__
#  include <linux/types.h>
#  include <linux/string.h>
#else
#  include <stdint.h>
#  include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Version atom written as the first thing in any stream.
 *
 * v1: single global delta-encoded ev_state per stream. Producers that
 *     write to the same fd must coordinate (the sud launcher used a
 *     cross-process spinlock; proctrace and uproctrace are inherently
 *     single-producer-per-fd). One ev_state at the decoder side.
 *
 * v2: each event payload is preceded by a stream_id varint
 *     (yeet_u64(stream_id)). The decoder maintains one ev_state per
 *     observed stream_id. Producers grab a stream_id once at startup
 *     (atomic CAS counter in shared memory) and delta-encode against
 *     a *process-local* ev_state - no cross-process lock needed; the
 *     only requirement is that each event reach the fd as a single
 *     atomic write() / writev(), which is the existing guarantee for
 *     bounded-size writes to regular files and pipes ≤ PIPE_BUF.
 *
 *     stream_id = 0 is the "default" stream. v2 readers also accept
 *     legacy v1-shaped events at this default stream_id, and a v1
 *     producer that simply re-versions itself as v2 (without adding
 *     stream_ids) keeps working - the decoder just sees everything
 *     on stream 0. This is the "events without stream id are part of
 *     a single, separate stream" compatibility path.
 *
 * Producers should pick the version they emit explicitly. The
 * WIRE_VERSION alias defaults to v1 to avoid silently changing the
 * format for the kernel module / uproctrace; sud opts into v2.
 */
#define WIRE_VERSION_V1 1u
#define WIRE_VERSION_V2 2u
#define WIRE_VERSION    WIRE_VERSION_V1

/* Event class codes. Stable within one WIRE_VERSION. */
enum {
    EV_EXEC   = 0,  /* blob = exe path bytes              */
    EV_ARGV   = 1,  /* blob = NUL-separated argv bytes    */
    EV_ENV    = 2,  /* blob = NUL-separated envp bytes    */
    EV_AUXV   = 3,  /* blob = raw Elf*_auxv_t[] bytes     */
    EV_EXIT   = 4,  /* no blob; 4 i64 extras              */
    EV_OPEN   = 5,  /* blob = path bytes; 7 i64 extras    */
    EV_CWD    = 6,  /* blob = path bytes                  */
    EV_STDOUT = 7,  /* blob = stdout bytes                */
    EV_STDERR = 8,  /* blob = stderr bytes                */
};

/* exit.status values */
enum {
    EV_EXIT_EXITED   = 0,
    EV_EXIT_SIGNALED = 1,
};

/* Maximum bytes any yeet helper writes for the prefix portion of
 * one atom. Useful for stack-buffer sizing. */
#define YEET_PREFIX_MAX 8u

/* ───────────────────────────── yeet ───────────────────────────── */

/* Encode `len` bytes of `src` into `*p..end`, advancing `*p`.
 * Returns 0 on success, -1 if there isn't room. */
static inline int yeet_blob(uint8_t **p, const uint8_t *end,
                            const void *src, uint64_t len) {
    uint8_t *q = *p;
    /* Self-byte form: 1-byte payload whose only byte is < 0xC0. */
    if (len == 1) {
        const uint8_t *s = (const uint8_t *)src;
        if (s[0] < 0xC0u) {
            if (q + 1 > end) { return -1; }
            q[0] = s[0];
            *p = q + 1;
            return 0;
        }
    }
    /* Inline form: 1 + len bytes, len in 0..55. */
    if (len <= 0x37u) {
        if ((uint64_t)(end - q) < 1u + len) { return -1; }
        q[0] = (uint8_t)(0xC0u + len);
        if (len) { memcpy(q + 1, src, (size_t)len); }
        *p = q + 1u + len;
        return 0;
    }
    /* Long form: 1 + lensz + len bytes. */
    uint8_t lenbuf[8];
    uint8_t lensz = 0;
    uint64_t tmp = len;
    while (tmp) { lenbuf[lensz++] = (uint8_t)(tmp & 0xFFu); tmp >>= 8; }
    if (lensz > 7u) { return -1; }     /* len ≥ 2^56, refuse */
    if ((uint64_t)(end - q) < 1u + lensz + len) { return -1; }
    q[0] = (uint8_t)(0xF8u + lensz);
    /* Loop copy (≤ 7 bytes) so the compiler sees the bound clearly. */
    for (uint8_t i = 0; i < lensz; i++) { q[1 + i] = lenbuf[i]; }
    if (len) { memcpy(q + 1 + lensz, src, (size_t)len); }
    *p = q + 1u + lensz + len;
    return 0;
}

/* Encode v as the minimal-LE-bytes blob. Specialised so the compiler
 * can see the source buffer is bounded by 8 bytes (no fortify warnings
 * from inlining yeet_blob's general path). */
static inline int yeet_u64(uint8_t **p, const uint8_t *end, uint64_t v) {
    uint8_t *q = *p;
    /* Minimal LE byte count of v: 0 for v=0, otherwise the index of
     * the highest non-zero byte plus one. */
    uint8_t buf[8];
    uint8_t n = 0;
    while (v) { buf[n++] = (uint8_t)(v & 0xFFu); v >>= 8; }

    /* n is in 0..8. Self-byte form when n==1 and the byte is small. */
    if (n == 1u && buf[0] < 0xC0u) {
        if (q + 1 > end) { return -1; }
        q[0] = buf[0];
        *p = q + 1;
        return 0;
    }
    /* Inline form (n ≤ 8 ≤ 55, always fits the inline tag range). */
    if ((uint64_t)(end - q) < 1u + (uint64_t)n) { return -1; }
    q[0] = (uint8_t)(0xC0u + n);
    for (uint8_t i = 0; i < n; i++) { q[1 + i] = buf[i]; }
    *p = q + 1u + n;
    return 0;
}

/* Encode v via zigzag, then yeet_u64. */
static inline int yeet_i64(uint8_t **p, const uint8_t *end, int64_t v) {
    uint64_t u = ((uint64_t)v << 1) ^ (uint64_t)(v >> 63);
    return yeet_u64(p, end, u);
}

/* Emit one outer atom whose payload is `a` (alen bytes) followed by
 * `b` (blen bytes), without ever copying either piece into a temp.
 * The prefix is computed up front. */
static inline int yeet_pair(uint8_t **p, const uint8_t *end,
                            const void *a, uint64_t alen,
                            const void *b, uint64_t blen) {
    uint8_t *q = *p;
    uint64_t total = alen + blen;
    if (total < alen) { return -1; }       /* overflow */
    /* Inline form for total ≤ 55 bytes. */
    if (total <= 0x37u) {
        if ((uint64_t)(end - q) < 1u + total) { return -1; }
        q[0] = (uint8_t)(0xC0u + total);
        if (alen) { memcpy(q + 1,        a, (size_t)alen); }
        if (blen) { memcpy(q + 1 + alen, b, (size_t)blen); }
        *p = q + 1u + total;
        return 0;
    }
    /* Long form. */
    uint8_t lenbuf[8];
    uint8_t lensz = 0;
    uint64_t tmp = total;
    while (tmp) { lenbuf[lensz++] = (uint8_t)(tmp & 0xFFu); tmp >>= 8; }
    if (lensz > 7u) { return -1; }
    if ((uint64_t)(end - q) < 1u + lensz + total) { return -1; }
    q[0] = (uint8_t)(0xF8u + lensz);
    for (uint8_t i = 0; i < lensz; i++) { q[1 + i] = lenbuf[i]; }
    if (alen) { memcpy(q + 1 + lensz,        a, (size_t)alen); }
    if (blen) { memcpy(q + 1 + lensz + alen, b, (size_t)blen); }
    *p = q + 1u + lensz + total;
    return 0;
}

/* ─────────────────────── yeet decoders ────────────────────────── */

/* Read one atom from `*p..end`. On success returns 0, sets
 * *out_data and *out_len to the payload bytes (a view into the
 * input buffer, not a copy), and advances *p past the atom. */
static inline int yeet_get(const uint8_t **p, const uint8_t *end,
                           const uint8_t **out_data, uint64_t *out_len) {
    const uint8_t *q = *p;
    if (q >= end) { return -1; }
    uint8_t b = q[0];
    if (b < 0xC0u) {
        *out_data = q;          /* the byte is its own payload */
        *out_len  = 1u;
        *p = q + 1;
        return 0;
    }
    if (b < 0xF8u) {
        uint64_t len = (uint64_t)(b - 0xC0u);
        if ((uint64_t)(end - q) < 1u + len) { return -1; }
        *out_data = q + 1;
        *out_len  = len;
        *p = q + 1u + len;
        return 0;
    }
    uint8_t lensz = (uint8_t)(b - 0xF8u);
    if ((uint64_t)(end - q) < 1u + lensz) { return -1; }
    uint64_t len = 0;
    for (uint8_t i = 0; i < lensz; i++) {
        len |= (uint64_t)q[1 + i] << (8u * i);
    }
    if ((uint64_t)(end - q) < 1u + lensz + len) { return -1; }
    *out_data = q + 1u + lensz;
    *out_len  = len;
    *p = q + 1u + lensz + len;
    return 0;
}

/* Decode an atom as u64 (LE-extend the payload bytes to 64 bits). */
static inline int yeet_get_u64(const uint8_t **p, const uint8_t *end,
                               uint64_t *out) {
    const uint8_t *d; uint64_t n;
    if (yeet_get(p, end, &d, &n) < 0) { return -1; }
    if (n > 8u) { return -1; }
    uint64_t v = 0;
    for (uint64_t i = 0; i < n; i++) { v |= (uint64_t)d[i] << (8u * i); }
    *out = v;
    return 0;
}

static inline int yeet_get_i64(const uint8_t **p, const uint8_t *end,
                               int64_t *out) {
    uint64_t u;
    if (yeet_get_u64(p, end, &u) < 0) { return -1; }
    int64_t lsb = (int64_t)(u & 1u);
    *out = (int64_t)(u >> 1) ^ -lsb;
    return 0;
}

/* ──────────────────────── event layer ─────────────────────────── */

/* One per output stream. Initialise to all zeros. Encoder and
 * decoder keep one of these; values must match step-for-step. */
typedef struct {
    int64_t type;
    int64_t ts_ns;
    int64_t pid;
    int64_t tgid;
    int64_t ppid;
    int64_t nspid;
    int64_t nstgid;
} ev_state;

/* Comfortable upper bound on the bytes ev_build_header writes:
 * 7 base scalars + up to 7 extras (largest event is EV_OPEN), each
 * at most 9 bytes (yeet_u64 worst case), plus headroom. */
#define EV_HEADER_MAX 160u

/* Build one event's inline header into `hdr`, delta-encoded against
 * `*st`, then commit the new values into `*st`. Returns the byte
 * count written (0..EV_HEADER_MAX), or -1 on overflow.
 *
 * `extras`/`n_extras` are appended after the seven base scalars and
 * are NOT delta-encoded — each is one yeet_i64. They carry the
 * type-specific fixed fields:
 *   EV_EXIT : { status, code_or_signal, core_dumped, raw }       (4)
 *   EV_OPEN : { flags, fd, ino, dev_major, dev_minor, err, inh } (7)
 *   others  : (none)
 *
 * Caller then emits the event with
 *   yeet_pair(out, end, hdr, hlen, blob, blen)
 * where blob/blen is the optional payload bytes (path, argv blob,
 * stdout bytes, …) — passed through verbatim, no copy. */
static inline int ev_build_header(ev_state *st,
                                  uint8_t hdr[EV_HEADER_MAX],
                                  int32_t type,
                                  uint64_t ts_ns,
                                  int32_t pid, int32_t tgid, int32_t ppid,
                                  int32_t nspid, int32_t nstgid,
                                  const int64_t *extras,
                                  unsigned n_extras) {
    uint8_t *p   = hdr;
    const uint8_t *end = hdr + EV_HEADER_MAX;

    int64_t n_type   = type;
    int64_t n_ts     = (int64_t)ts_ns;
    int64_t n_pid    = pid;
    int64_t n_tgid   = tgid;
    int64_t n_ppid   = ppid;
    int64_t n_nspid  = nspid;
    int64_t n_nstgid = nstgid;

    if (yeet_i64(&p, end, n_type   - st->type)   < 0) { return -1; }
    if (yeet_i64(&p, end, n_ts     - st->ts_ns)  < 0) { return -1; }
    if (yeet_i64(&p, end, n_pid    - st->pid)    < 0) { return -1; }
    if (yeet_i64(&p, end, n_tgid   - st->tgid)   < 0) { return -1; }
    if (yeet_i64(&p, end, n_ppid   - st->ppid)   < 0) { return -1; }
    if (yeet_i64(&p, end, n_nspid  - st->nspid)  < 0) { return -1; }
    if (yeet_i64(&p, end, n_nstgid - st->nstgid) < 0) { return -1; }
    for (unsigned i = 0; i < n_extras; i++) {
        if (yeet_i64(&p, end, extras[i]) < 0) { return -1; }
    }

    st->type   = n_type;
    st->ts_ns  = n_ts;
    st->pid    = n_pid;
    st->tgid   = n_tgid;
    st->ppid   = n_ppid;
    st->nspid  = n_nspid;
    st->nstgid = n_nstgid;
    return (int)(p - hdr);
}

/* Decode the seven base scalars from `hdr_bytes`, commit them into
 * `*st`, and return the number of bytes consumed (or -1 on
 * truncation). The caller continues parsing extras/blob from
 * (hdr_bytes + ret) onward, using the event type to know how many
 * extras to read and whether the trailing bytes are a blob. */
static inline int ev_decode_header(ev_state *st,
                                   const uint8_t *hdr_bytes, uint64_t hlen,
                                   int32_t *type, uint64_t *ts_ns,
                                   int32_t *pid, int32_t *tgid, int32_t *ppid,
                                   int32_t *nspid, int32_t *nstgid) {
    const uint8_t *p   = hdr_bytes;
    const uint8_t *end = hdr_bytes + hlen;
    int64_t d;
    if (yeet_get_i64(&p, end, &d) < 0) { return -1; } st->type   += d; *type   = (int32_t)st->type;
    if (yeet_get_i64(&p, end, &d) < 0) { return -1; } st->ts_ns  += d; *ts_ns  = (uint64_t)st->ts_ns;
    if (yeet_get_i64(&p, end, &d) < 0) { return -1; } st->pid    += d; *pid    = (int32_t)st->pid;
    if (yeet_get_i64(&p, end, &d) < 0) { return -1; } st->tgid   += d; *tgid   = (int32_t)st->tgid;
    if (yeet_get_i64(&p, end, &d) < 0) { return -1; } st->ppid   += d; *ppid   = (int32_t)st->ppid;
    if (yeet_get_i64(&p, end, &d) < 0) { return -1; } st->nspid  += d; *nspid  = (int32_t)st->nspid;
    if (yeet_get_i64(&p, end, &d) < 0) { return -1; } st->nstgid += d; *nstgid = (int32_t)st->nstgid;
    return (int)(p - hdr_bytes);
}

/* ─── v2 wrappers: stream_id-prefixed delta encoding ──────────────
 *
 * v2 events are exactly v1 events with a leading yeet_u64(stream_id)
 * inside the outer atom payload. The remaining base-scalar deltas are
 * computed against the per-stream ev_state passed in by the caller -
 * the caller is responsible for keeping one ev_state per stream_id
 * (typically: one per producer process, allocated once at startup).
 *
 * Comfortable bound: stream_id is at most 9 bytes (u64 worst case),
 * plus EV_HEADER_MAX (160). */
#define EV_HEADER_V2_MAX (EV_HEADER_MAX + 9u)

static inline int ev_build_header_v2(uint32_t stream_id,
                                     ev_state *st,
                                     uint8_t hdr[EV_HEADER_V2_MAX],
                                     int32_t type,
                                     uint64_t ts_ns,
                                     int32_t pid, int32_t tgid, int32_t ppid,
                                     int32_t nspid, int32_t nstgid,
                                     const int64_t *extras,
                                     unsigned n_extras) {
    uint8_t *p   = hdr;
    const uint8_t *end = hdr + EV_HEADER_V2_MAX;
    if (yeet_u64(&p, end, (uint64_t)stream_id) < 0) { return -1; }
    int hlen = ev_build_header(st, p, type, ts_ns, pid, tgid, ppid,
                               nspid, nstgid, extras, n_extras);
    if (hlen < 0) { return -1; }
    return (int)((p - hdr) + (uint64_t)hlen);
}

/* Decode the leading stream_id from a v2 event payload. Returns the
 * number of bytes consumed (1..9), or -1 on truncation. The caller
 * then runs ev_decode_header against the per-stream ev_state on
 * (hdr_bytes + ret, hlen - ret). */
static inline int ev_decode_stream_id(const uint8_t *hdr_bytes, uint64_t hlen,
                                      uint32_t *out_stream_id) {
    const uint8_t *p   = hdr_bytes;
    const uint8_t *end = hdr_bytes + hlen;
    uint64_t sid;
    if (yeet_get_u64(&p, end, &sid) < 0) { return -1; }
    *out_stream_id = (uint32_t)sid;
    return (int)(p - hdr_bytes);
}

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* WIRE_H */
