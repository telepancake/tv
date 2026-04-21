/* ctf/encode.h — Shared CTF 1.8 encoder for tv traces.
 *
 * Produces the wire format described in ctf/SCHEMA.md and ctf/metadata.tsdl.
 *
 * Constraints:
 *   - Pure C99 with no libc dependencies beyond memcpy / static inline.
 *   - Used unmodified by the kernel module (proctrace.c), the freestanding
 *     sud helpers (sud32, sud64), and the userspace ptrace tracer
 *     (uproctrace.cpp). All three call into these helpers directly.
 *   - All encoding is little-endian. All multi-byte integers go out via
 *     memcpy so unaligned writes are safe on every supported arch.
 *   - No allocation; the caller owns the buffer. Every helper returns
 *     the number of bytes written, or a negative value on overflow.
 *
 * Usage model:
 *   Producers maintain a per-session ("staging") buffer the size of one
 *   packet (commonly 64 KiB). They:
 *     1. ctf_packet_begin(buf, cap, uuid, producer_id, ts_begin)
 *     2. ctf_event_*(buf + off, cap - off, ...)  for each event;
 *        if the call returns < 0 (would overflow), the packet is sealed
 *        and a new one started. Events that don't fit in an empty packet
 *        are an error (caller must size buffers larger than the largest
 *        possible event).
 *     3. ctf_packet_seal(buf, content_off, ts_end)  patches header fields
 *        in the staging buffer, *not* in any output stream.
 *     4. write(out_fd, buf, packet_size).
 */

#ifndef CTF_ENCODE_H
#define CTF_ENCODE_H

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

/* ── On-the-wire constants ─────────────────────────────────────────── */

#define CTF_PACKET_MAGIC        0xC1FC1FC1u
#define CTF_STREAM_ID           0u
#define CTF_UUID_SIZE           16

/* Event class ids — stable, never reused. */
enum {
    CTF_EVENT_EXEC   = 0,
    CTF_EVENT_EXIT   = 1,
    CTF_EVENT_OPEN   = 2,
    CTF_EVENT_CWD    = 3,
    CTF_EVENT_STDOUT = 4,
    CTF_EVENT_STDERR = 5,
};

/* exit.status values */
enum {
    CTF_EXIT_EXITED   = 0,
    CTF_EXIT_SIGNALED = 1,
};

/* Suggested packet size: 64 KiB. Producers may pick anything ≥ the
 * largest event they intend to emit. The kernel module and sud should
 * keep this small; uproctrace can go larger. */
#define CTF_DEFAULT_PACKET_SIZE (64u * 1024u)

/* Layout offsets inside a packet's header+context block. Convenience
 * for ctf_packet_seal. */
#define CTF_OFF_MAGIC           0
#define CTF_OFF_UUID            4
#define CTF_OFF_STREAM_ID       (CTF_OFF_UUID + CTF_UUID_SIZE)        /* 20 */
#define CTF_OFF_TS_BEGIN        (CTF_OFF_STREAM_ID + 4)               /* 24 */
#define CTF_OFF_TS_END          (CTF_OFF_TS_BEGIN + 8)                /* 32 */
#define CTF_OFF_CONTENT_SIZE    (CTF_OFF_TS_END + 8)                  /* 40 */
#define CTF_OFF_PACKET_SIZE     (CTF_OFF_CONTENT_SIZE + 4)            /* 44 */
#define CTF_OFF_PRODUCER_ID     (CTF_OFF_PACKET_SIZE + 4)             /* 48 */
#define CTF_OFF_DISCARDED       (CTF_OFF_PRODUCER_ID + 2)             /* 50 */
#define CTF_PACKET_HEADER_SIZE  (CTF_OFF_DISCARDED + 4)               /* 54 */

/* ── Low-level little-endian writers ───────────────────────────────── */

static inline int ctf_put_u8(uint8_t *p, uint32_t cap, uint32_t off, uint8_t v) {
    if (off + 1 > cap) return -1;
    p[off] = v;
    return 1;
}
static inline int ctf_put_u16(uint8_t *p, uint32_t cap, uint32_t off, uint16_t v) {
    if (off + 2 > cap) return -1;
    p[off + 0] = (uint8_t)(v);
    p[off + 1] = (uint8_t)(v >> 8);
    return 2;
}
static inline int ctf_put_u32(uint8_t *p, uint32_t cap, uint32_t off, uint32_t v) {
    if (off + 4 > cap) return -1;
    p[off + 0] = (uint8_t)(v);
    p[off + 1] = (uint8_t)(v >> 8);
    p[off + 2] = (uint8_t)(v >> 16);
    p[off + 3] = (uint8_t)(v >> 24);
    return 4;
}
static inline int ctf_put_i32(uint8_t *p, uint32_t cap, uint32_t off, int32_t v) {
    return ctf_put_u32(p, cap, off, (uint32_t)v);
}
static inline int ctf_put_u64(uint8_t *p, uint32_t cap, uint32_t off, uint64_t v) {
    if (off + 8 > cap) return -1;
    p[off + 0] = (uint8_t)(v);
    p[off + 1] = (uint8_t)(v >> 8);
    p[off + 2] = (uint8_t)(v >> 16);
    p[off + 3] = (uint8_t)(v >> 24);
    p[off + 4] = (uint8_t)(v >> 32);
    p[off + 5] = (uint8_t)(v >> 40);
    p[off + 6] = (uint8_t)(v >> 48);
    p[off + 7] = (uint8_t)(v >> 56);
    return 8;
}
static inline int ctf_put_bytes(uint8_t *p, uint32_t cap, uint32_t off,
                                const void *src, uint32_t len) {
    if (off + len < off || off + len > cap) return -1;
    if (len) memcpy(p + off, src, len);
    return (int)len;
}

/* ULEB128 — never more than 10 bytes for a u64. */
static inline int ctf_put_uleb128(uint8_t *p, uint32_t cap, uint32_t off, uint64_t v) {
    uint32_t start = off;
    do {
        if (off + 1 > cap) return -1;
        uint8_t b = (uint8_t)(v & 0x7fu);
        v >>= 7;
        if (v) b |= 0x80u;
        p[off++] = b;
    } while (v);
    return (int)(off - start);
}

/* string : { u32 len; u8 data[len]; } */
static inline int ctf_put_string(uint8_t *p, uint32_t cap, uint32_t off,
                                 const void *data, uint32_t len) {
    int n = ctf_put_u32(p, cap, off, len);
    if (n < 0) return -1;
    int m = ctf_put_bytes(p, cap, off + (uint32_t)n, data, len);
    if (m < 0) return -1;
    return n + m;
}

/* ── Packet framing ────────────────────────────────────────────────── */

/* Begin a packet in the staging buffer. timestamp_end / content_size /
 * packet_size are written as zero placeholders; ctf_packet_seal patches
 * them. Returns the offset at which the first event header starts, or
 * -1 if the staging buffer is too small. */
static inline int ctf_packet_begin(uint8_t *p, uint32_t cap,
                                   const uint8_t uuid[CTF_UUID_SIZE],
                                   uint16_t producer_id,
                                   uint64_t ts_begin) {
    if (cap < CTF_PACKET_HEADER_SIZE) return -1;
    /* packet.header */
    ctf_put_u32  (p, cap, CTF_OFF_MAGIC,        CTF_PACKET_MAGIC);
    ctf_put_bytes(p, cap, CTF_OFF_UUID,         uuid, CTF_UUID_SIZE);
    ctf_put_u32  (p, cap, CTF_OFF_STREAM_ID,    CTF_STREAM_ID);
    /* packet.context */
    ctf_put_u64  (p, cap, CTF_OFF_TS_BEGIN,     ts_begin);
    ctf_put_u64  (p, cap, CTF_OFF_TS_END,       0);  /* sealed later */
    ctf_put_u32  (p, cap, CTF_OFF_CONTENT_SIZE, 0);  /* sealed later */
    ctf_put_u32  (p, cap, CTF_OFF_PACKET_SIZE,  0);  /* sealed later */
    ctf_put_u16  (p, cap, CTF_OFF_PRODUCER_ID,  producer_id);
    ctf_put_u32  (p, cap, CTF_OFF_DISCARDED,    0);
    return (int)CTF_PACKET_HEADER_SIZE;
}

/* Seal a packet: stamp timestamp_end / content_size / packet_size into
 * the staging buffer's header. content_off is the byte length of all
 * valid content (header + events). packet_off is the final padded
 * length to write to the output (>= content_off). The CTF spec
 * requires both in *bits*; we multiply here. */
static inline void ctf_packet_seal(uint8_t *p, uint32_t cap,
                                   uint32_t content_off,
                                   uint32_t packet_off,
                                   uint64_t ts_end) {
    (void)cap;
    /* Caller is expected to have checked sizes. */
    ctf_put_u64(p, packet_off, CTF_OFF_TS_END,       ts_end);
    ctf_put_u32(p, packet_off, CTF_OFF_CONTENT_SIZE, content_off * 8u);
    ctf_put_u32(p, packet_off, CTF_OFF_PACKET_SIZE,  packet_off  * 8u);
}

/* ── Event header ──────────────────────────────────────────────────── */

/* Common event prologue: id, ts_delta (ULEB128), pid, tgid, ppid,
 * nspid, nstgid. Returns bytes written or -1 on overflow. */
static inline int ctf_event_header(uint8_t *p, uint32_t cap, uint32_t off,
                                   uint16_t id, uint64_t ts_delta,
                                   int32_t pid, int32_t tgid, int32_t ppid,
                                   int32_t nspid, int32_t nstgid) {
    uint32_t start = off;
    int n;
    if ((n = ctf_put_u16     (p, cap, off, id))         < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_uleb128 (p, cap, off, ts_delta))   < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_i32     (p, cap, off, pid))        < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_i32     (p, cap, off, tgid))       < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_i32     (p, cap, off, ppid))       < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_i32     (p, cap, off, nspid))      < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_i32     (p, cap, off, nstgid))     < 0) { return -1; } off += (uint32_t)n;
    return (int)(off - start);
}

/* ── Event encoders ────────────────────────────────────────────────── */

/* Each helper writes a complete event (header + payload) at p[off..]
 * and returns the total bytes written, or -1 on overflow. The caller
 * must seal & start a new packet on overflow. */

static inline int ctf_event_exec(uint8_t *p, uint32_t cap, uint32_t off,
                                 uint64_t ts_delta,
                                 int32_t pid, int32_t tgid, int32_t ppid,
                                 int32_t nspid, int32_t nstgid,
                                 const void *exe,       uint32_t exe_len,
                                 const void *argv_blob, uint32_t argv_len,
                                 const void *env_blob,  uint32_t env_len,
                                 const void *auxv_blob, uint32_t auxv_len) {
    uint32_t start = off;
    int n;
    if ((n = ctf_event_header(p, cap, off, CTF_EVENT_EXEC, ts_delta,
                              pid, tgid, ppid, nspid, nstgid)) < 0) return -1;
    off += (uint32_t)n;
    if ((n = ctf_put_string(p, cap, off, exe,       exe_len))  < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_string(p, cap, off, argv_blob, argv_len)) < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_string(p, cap, off, env_blob,  env_len))  < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_string(p, cap, off, auxv_blob, auxv_len)) < 0) { return -1; } off += (uint32_t)n;
    return (int)(off - start);
}

static inline int ctf_event_exit(uint8_t *p, uint32_t cap, uint32_t off,
                                 uint64_t ts_delta,
                                 int32_t pid, int32_t tgid, int32_t ppid,
                                 int32_t nspid, int32_t nstgid,
                                 uint8_t status, int32_t code_or_signal,
                                 uint8_t core_dumped, int32_t raw) {
    uint32_t start = off;
    int n;
    if ((n = ctf_event_header(p, cap, off, CTF_EVENT_EXIT, ts_delta,
                              pid, tgid, ppid, nspid, nstgid)) < 0) return -1;
    off += (uint32_t)n;
    if ((n = ctf_put_u8 (p, cap, off, status))           < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_i32(p, cap, off, code_or_signal))   < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_u8 (p, cap, off, core_dumped))      < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_i32(p, cap, off, raw))              < 0) { return -1; } off += (uint32_t)n;
    return (int)(off - start);
}

static inline int ctf_event_open(uint8_t *p, uint32_t cap, uint32_t off,
                                 uint64_t ts_delta,
                                 int32_t pid, int32_t tgid, int32_t ppid,
                                 int32_t nspid, int32_t nstgid,
                                 const void *path, uint32_t path_len,
                                 uint32_t flags, int32_t fd,
                                 uint64_t ino, uint32_t dev_major, uint32_t dev_minor,
                                 int32_t err, uint8_t inherited) {
    uint32_t start = off;
    int n;
    if ((n = ctf_event_header(p, cap, off, CTF_EVENT_OPEN, ts_delta,
                              pid, tgid, ppid, nspid, nstgid)) < 0) return -1;
    off += (uint32_t)n;
    if ((n = ctf_put_string(p, cap, off, path, path_len))      < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_u32   (p, cap, off, flags))               < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_i32   (p, cap, off, fd))                  < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_u64   (p, cap, off, ino))                 < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_u32   (p, cap, off, dev_major))           < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_u32   (p, cap, off, dev_minor))           < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_i32   (p, cap, off, err))                 < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_put_u8    (p, cap, off, inherited))           < 0) { return -1; } off += (uint32_t)n;
    return (int)(off - start);
}

static inline int ctf_event_cwd(uint8_t *p, uint32_t cap, uint32_t off,
                                uint64_t ts_delta,
                                int32_t pid, int32_t tgid, int32_t ppid,
                                int32_t nspid, int32_t nstgid,
                                const void *path, uint32_t path_len) {
    uint32_t start = off;
    int n;
    if ((n = ctf_event_header(p, cap, off, CTF_EVENT_CWD, ts_delta,
                              pid, tgid, ppid, nspid, nstgid)) < 0) return -1;
    off += (uint32_t)n;
    if ((n = ctf_put_string(p, cap, off, path, path_len))      < 0) { return -1; } off += (uint32_t)n;
    return (int)(off - start);
}

static inline int ctf_event_stream(uint8_t *p, uint32_t cap, uint32_t off,
                                   uint16_t which, /* CTF_EVENT_STDOUT or _STDERR */
                                   uint64_t ts_delta,
                                   int32_t pid, int32_t tgid, int32_t ppid,
                                   int32_t nspid, int32_t nstgid,
                                   const void *data, uint32_t data_len) {
    uint32_t start = off;
    int n;
    if ((n = ctf_event_header(p, cap, off, which, ts_delta,
                              pid, tgid, ppid, nspid, nstgid)) < 0) return -1;
    off += (uint32_t)n;
    if ((n = ctf_put_string(p, cap, off, data, data_len))      < 0) { return -1; } off += (uint32_t)n;
    return (int)(off - start);
}

/* ── Decoder mirrors (used by ctf2parquet, tests) ──────────────────── */

static inline int ctf_get_u8(const uint8_t *p, uint32_t cap, uint32_t off, uint8_t *out) {
    if (off + 1 > cap) return -1;
    *out = p[off];
    return 1;
}
static inline int ctf_get_u16(const uint8_t *p, uint32_t cap, uint32_t off, uint16_t *out) {
    if (off + 2 > cap) return -1;
    *out = (uint16_t)p[off] | ((uint16_t)p[off + 1] << 8);
    return 2;
}
static inline int ctf_get_u32(const uint8_t *p, uint32_t cap, uint32_t off, uint32_t *out) {
    if (off + 4 > cap) return -1;
    *out = (uint32_t)p[off]
         | ((uint32_t)p[off + 1] << 8)
         | ((uint32_t)p[off + 2] << 16)
         | ((uint32_t)p[off + 3] << 24);
    return 4;
}
static inline int ctf_get_i32(const uint8_t *p, uint32_t cap, uint32_t off, int32_t *out) {
    uint32_t u; int n = ctf_get_u32(p, cap, off, &u);
    if (n < 0) return -1;
    *out = (int32_t)u;
    return n;
}
static inline int ctf_get_u64(const uint8_t *p, uint32_t cap, uint32_t off, uint64_t *out) {
    if (off + 8 > cap) return -1;
    *out = (uint64_t)p[off]
         | ((uint64_t)p[off + 1] << 8)
         | ((uint64_t)p[off + 2] << 16)
         | ((uint64_t)p[off + 3] << 24)
         | ((uint64_t)p[off + 4] << 32)
         | ((uint64_t)p[off + 5] << 40)
         | ((uint64_t)p[off + 6] << 48)
         | ((uint64_t)p[off + 7] << 56);
    return 8;
}
static inline int ctf_get_uleb128(const uint8_t *p, uint32_t cap, uint32_t off, uint64_t *out) {
    uint64_t v = 0;
    uint32_t shift = 0;
    uint32_t start = off;
    for (;;) {
        if (off + 1 > cap) return -1;
        uint8_t b = p[off++];
        v |= (uint64_t)(b & 0x7fu) << shift;
        if ((b & 0x80u) == 0) break;
        shift += 7;
        if (shift >= 64) return -1;       /* malformed */
    }
    *out = v;
    return (int)(off - start);
}
/* string view; caller does not own the bytes. */
static inline int ctf_get_string(const uint8_t *p, uint32_t cap, uint32_t off,
                                 const uint8_t **out_data, uint32_t *out_len) {
    uint32_t len; int n = ctf_get_u32(p, cap, off, &len);
    if (n < 0) return -1;
    if (off + (uint32_t)n + len < off + (uint32_t)n) return -1;  /* overflow */
    if (off + (uint32_t)n + len > cap) return -1;
    *out_len  = len;
    *out_data = p + off + (uint32_t)n;
    return n + (int)len;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CTF_ENCODE_H */
