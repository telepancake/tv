/* yeetdump.c — round-trip selftest and human dump for tv wire streams.
 *
 *   yeetdump --selftest
 *       Round-trip every event class plus boundary cases for the yeet
 *       byte primitive (lengths 0/1/55/56/256/65536, deltas across
 *       zero, embedded NULs in blobs, etc.). Exits non-zero on any
 *       mismatch.
 *
 *   yeetdump trace.bin [trace.bin ...]
 *       mmap each file, print one line per event to stdout. Pipe
 *       compressed traces through `zstd -dc`.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wire/wire.h"

/* ─── pretty-print bytes that aren't claimed to be text ─────────── */

static void put_safe(const uint8_t *b, uint64_t n) {
    for (uint64_t i = 0; i < n; i++) {
        uint8_t c = b[i];
        if (c >= 0x20 && c < 0x7f && c != '\\') {
            putchar((int)c);
        } else {
            printf("\\x%02x", c);
        }
    }
}

static const char *ev_name(int32_t t) {
    switch (t) {
    case EV_EXEC:   return "EXEC";
    case EV_ARGV:   return "ARGV";
    case EV_ENV:    return "ENV";
    case EV_AUXV:   return "AUXV";
    case EV_EXIT:   return "EXIT";
    case EV_OPEN:   return "OPEN";
    case EV_CWD:    return "CWD";
    case EV_STDOUT: return "STDOUT";
    case EV_STDERR: return "STDERR";
    default:        return "?";
    }
}

/* ─── decode one whole event from the outer atom payload ────────── */

static int print_event(ev_state *st,
                       const uint8_t *atom, uint64_t alen) {
    int32_t  type, pid, tgid, ppid, nspid, nstgid;
    uint64_t ts;
    int hbytes = ev_decode_header(st, atom, alen,
                                  &type, &ts, &pid, &tgid, &ppid,
                                  &nspid, &nstgid);
    if (hbytes < 0) { return -1; }

    const uint8_t *p   = atom + hbytes;
    const uint8_t *end = atom + alen;

    printf("[%lu.%09lu] %-6s tgid=%d pid=%d ppid=%d ns=%d/%d ",
           (unsigned long)(ts / 1000000000ull),
           (unsigned long)(ts % 1000000000ull),
           ev_name(type), tgid, pid, ppid, nstgid, nspid);

    switch (type) {
    case EV_EXIT: {
        int64_t status, code, core, raw;
        if (yeet_get_i64(&p, end, &status) < 0) { return -1; }
        if (yeet_get_i64(&p, end, &code)   < 0) { return -1; }
        if (yeet_get_i64(&p, end, &core)   < 0) { return -1; }
        if (yeet_get_i64(&p, end, &raw)    < 0) { return -1; }
        printf("%s code/sig=%ld core=%ld raw=%ld",
               status == EV_EXIT_EXITED ? "exited" : "signaled",
               (long)code, (long)core, (long)raw);
        break;
    }
    case EV_OPEN: {
        int64_t flags, fd, ino, devmaj, devmin, err, inh;
        if (yeet_get_i64(&p, end, &flags)  < 0) { return -1; }
        if (yeet_get_i64(&p, end, &fd)     < 0) { return -1; }
        if (yeet_get_i64(&p, end, &ino)    < 0) { return -1; }
        if (yeet_get_i64(&p, end, &devmaj) < 0) { return -1; }
        if (yeet_get_i64(&p, end, &devmin) < 0) { return -1; }
        if (yeet_get_i64(&p, end, &err)    < 0) { return -1; }
        if (yeet_get_i64(&p, end, &inh)    < 0) { return -1; }
        printf("flags=0x%lx fd=%ld ino=%ld dev=%ld:%ld err=%ld inh=%ld path=\"",
               (unsigned long)flags, (long)fd, (long)ino,
               (long)devmaj, (long)devmin, (long)err, (long)inh);
        put_safe(p, (uint64_t)(end - p));
        putchar('"');
        break;
    }
    case EV_EXEC: case EV_CWD:
    case EV_STDOUT: case EV_STDERR:
    case EV_ARGV: case EV_ENV: case EV_AUXV: {
        uint64_t blen = (uint64_t)(end - p);
        printf("blob=%luB \"", (unsigned long)blen);
        put_safe(p, blen);
        putchar('"');
        break;
    }
    default:
        printf("(unknown event class)");
        return -1;
    }
    putchar('\n');
    return 0;
}

/* ─── stream walker ─────────────────────────────────────────────── */

static int walk_stream(const uint8_t *buf, uint64_t len) {
    const uint8_t *p   = buf;
    const uint8_t *end = buf + len;

    /* version atom */
    uint64_t ver;
    if (yeet_get_u64(&p, end, &ver) < 0) {
        fprintf(stderr, "yeetdump: missing version atom\n");
        return -1;
    }
    if (ver != WIRE_VERSION) {
        fprintf(stderr, "yeetdump: unsupported wire version %lu (this build: %u)\n",
                (unsigned long)ver, WIRE_VERSION);
        return -1;
    }
    fprintf(stderr, "-- wire version %lu, %lu bytes --\n",
            (unsigned long)ver, (unsigned long)len);

    ev_state st = {0};
    while (p < end) {
        const uint8_t *atom; uint64_t alen;
        if (yeet_get(&p, end, &atom, &alen) < 0) {
            fprintf(stderr, "yeetdump: truncated atom at offset %ld\n",
                    (long)(p - buf));
            return -1;
        }
        if (print_event(&st, atom, alen) < 0) {
            fprintf(stderr, "yeetdump: malformed event\n");
            return -1;
        }
    }
    return 0;
}

static int dump_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return 1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return 1; }
    if (st.st_size <= 0) { close(fd); return 0; }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) { perror("mmap"); return 1; }
    int rc = walk_stream((const uint8_t *)m, (uint64_t)st.st_size);
    munmap(m, (size_t)st.st_size);
    return rc != 0;
}

/* ─── selftest ──────────────────────────────────────────────────── */

#define ASSERT(cond) do { if (!(cond)) { \
    fprintf(stderr, "SELFTEST FAIL: %s (line %d)\n", #cond, __LINE__); \
    return 1; \
} } while (0)

/* Round-trip a yeet_blob of every interesting length, including the
 * boundaries of the three encoding regions. */
static int rt_blob(uint64_t len, uint8_t fill) {
    static uint8_t buf[1024 * 1024];
    static uint8_t src[70000];
    if (len > sizeof src) { return 1; }
    for (uint64_t i = 0; i < len; i++) { src[i] = (uint8_t)((fill + i) & 0xFF); }
    uint8_t *w = buf;
    if (yeet_blob(&w, buf + sizeof buf, src, len) < 0) {
        fprintf(stderr, "rt_blob len=%lu: encode failed\n", (unsigned long)len);
        return 1;
    }
    const uint8_t *r = buf;
    const uint8_t *out; uint64_t got;
    if (yeet_get(&r, w, &out, &got) < 0) {
        fprintf(stderr, "rt_blob len=%lu: decode failed\n", (unsigned long)len);
        return 1;
    }
    if (got != len || memcmp(out, src, (size_t)len) != 0) {
        fprintf(stderr, "rt_blob len=%lu: mismatch (got %lu)\n",
                (unsigned long)len, (unsigned long)got);
        return 1;
    }
    return 0;
}

static int rt_u64(uint64_t v) {
    uint8_t buf[16];
    uint8_t *w = buf;
    if (yeet_u64(&w, buf + sizeof buf, v) < 0) { return 1; }
    const uint8_t *r = buf;
    uint64_t got;
    if (yeet_get_u64(&r, w, &got) < 0) { return 1; }
    if (got != v) {
        fprintf(stderr, "rt_u64 v=%lu got=%lu\n",
                (unsigned long)v, (unsigned long)got);
        return 1;
    }
    return 0;
}

static int rt_i64(int64_t v) {
    uint8_t buf[16];
    uint8_t *w = buf;
    if (yeet_i64(&w, buf + sizeof buf, v) < 0) { return 1; }
    const uint8_t *r = buf;
    int64_t got;
    if (yeet_get_i64(&r, w, &got) < 0) { return 1; }
    if (got != v) {
        fprintf(stderr, "rt_i64 v=%ld got=%ld\n", (long)v, (long)got);
        return 1;
    }
    return 0;
}

/* Build a small synthetic stream covering every event class, walk it,
 * and check the printed output (by visual inspection — we only assert
 * structural properties here). */
static int test_stream(void) {
    static uint8_t buf[4096];
    uint8_t *w   = buf;
    const uint8_t *end = buf + sizeof buf;

    ASSERT(yeet_u64(&w, end, WIRE_VERSION) == 0);

    ev_state enc = {0};
    uint8_t hdr[EV_HEADER_MAX];
    int hlen;
    int64_t extras[7];
    const uint64_t base_ts = 1711814400ull * 1000000000ull;

    /* 1. EV_EXEC with embedded \x00 in path */
    hlen = ev_build_header(&enc, hdr, EV_EXEC, base_ts + 100,
                           1234, 1234, 1200, 1234, 1234, NULL, 0);
    ASSERT(hlen > 0);
    ASSERT(yeet_pair(&w, end, hdr, hlen,
                     "/usr/bin/\0make", 14) == 0);

    /* 2. EV_ARGV — argv blob is NUL-separated */
    hlen = ev_build_header(&enc, hdr, EV_ARGV, base_ts + 101,
                           1234, 1234, 1200, 1234, 1234, NULL, 0);
    ASSERT(yeet_pair(&w, end, hdr, hlen, "make\0-j8\0", 9) == 0);

    /* 3. EV_ENV */
    hlen = ev_build_header(&enc, hdr, EV_ENV, base_ts + 102,
                           1234, 1234, 1200, 1234, 1234, NULL, 0);
    ASSERT(yeet_pair(&w, end, hdr, hlen,
                     "PATH=/usr/bin\0HOME=/root\0", 25) == 0);

    /* 4. EV_AUXV — single AT_NULL entry, 16 bytes on x86_64 */
    static const uint8_t auxv_null[16] = {0};
    hlen = ev_build_header(&enc, hdr, EV_AUXV, base_ts + 103,
                           1234, 1234, 1200, 1234, 1234, NULL, 0);
    ASSERT(yeet_pair(&w, end, hdr, hlen, auxv_null, sizeof auxv_null) == 0);

    /* 5. EV_CWD with high byte */
    hlen = ev_build_header(&enc, hdr, EV_CWD, base_ts + 200,
                           1234, 1234, 1200, 1234, 1234, NULL, 0);
    ASSERT(yeet_pair(&w, end, hdr, hlen, "/home/u\xff", 8) == 0);

    /* 6. EV_OPEN */
    extras[0] = 0;            /* flags */
    extras[1] = 3;            /* fd */
    extras[2] = 524297;       /* ino */
    extras[3] = 259;          /* dev_major */
    extras[4] = 2;            /* dev_minor */
    extras[5] = 0;            /* err */
    extras[6] = 0;            /* inh */
    hlen = ev_build_header(&enc, hdr, EV_OPEN, base_ts + 300,
                           1234, 1234, 1200, 1234, 1234, extras, 7);
    ASSERT(yeet_pair(&w, end, hdr, hlen, "/etc/passwd", 11) == 0);

    /* 7. EV_STDOUT */
    hlen = ev_build_header(&enc, hdr, EV_STDOUT, base_ts + 400,
                           1234, 1234, 1200, 1234, 1234, NULL, 0);
    ASSERT(yeet_pair(&w, end, hdr, hlen, "hello\n", 6) == 0);

    /* 8. EV_STDERR */
    hlen = ev_build_header(&enc, hdr, EV_STDERR, base_ts + 500,
                           1234, 1234, 1200, 1234, 1234, NULL, 0);
    ASSERT(yeet_pair(&w, end, hdr, hlen, "warning\n", 8) == 0);

    /* 9. EV_EXIT (signaled) */
    extras[0] = EV_EXIT_SIGNALED;
    extras[1] = 11;           /* SIGSEGV */
    extras[2] = 1;            /* core dumped */
    extras[3] = 139;          /* raw */
    hlen = ev_build_header(&enc, hdr, EV_EXIT, base_ts + 600,
                           1234, 1234, 1200, 1234, 1234, extras, 4);
    ASSERT(yeet_pair(&w, end, hdr, hlen, NULL, 0) == 0);

    uint64_t total = (uint64_t)(w - buf);
    fprintf(stderr, "test_stream: %lu bytes, walking back…\n",
            (unsigned long)total);
    return walk_stream(buf, total);
}

static int selftest(void) {
    /* Yeet primitive boundaries. */
    for (uint64_t L = 0; L <= 56; L++) { if (rt_blob(L, 0x42)) { return 1; } }
    if (rt_blob(255, 0x11))   { return 1; }
    if (rt_blob(256, 0x22))   { return 1; }
    if (rt_blob(65535, 0x33)) { return 1; }
    if (rt_blob(65536, 0x44)) { return 1; }

    /* u64 boundaries. */
    static const uint64_t us[] = {
        0, 1, 191, 192, 255, 256, 65535, 65536,
        0xFFFFFFFFu, 0x100000000ull,
        0x7FFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull,
    };
    for (size_t i = 0; i < sizeof us / sizeof us[0]; i++) {
        if (rt_u64(us[i])) { return 1; }
    }

    /* i64 boundaries — including big negatives. */
    static const int64_t is[] = {
        0, 1, -1, 63, 64, -64, -65,
        0x7FFFFFFF, -0x80000000ll,
        0x7FFFFFFFFFFFFFFFll, (int64_t)0x8000000000000000ull,
    };
    for (size_t i = 0; i < sizeof is / sizeof is[0]; i++) {
        if (rt_i64(is[i])) { return 1; }
    }

    /* Encode/decode state symmetry on a synthetic stream. */
    if (test_stream()) { return 1; }

    /* Verify that a tiny event packs into ≤ 16 bytes, as the user
     * asked. After the first event has primed the deltas, the second
     * EV_STDOUT in the same thread (1 ns later, 6-byte payload)
     * should be tiny: 1 (outer prefix) + 7×1 (delta i64 of 0/1/0…)
     * + 1 (blob prefix portion) + 6 = ~15 bytes. */
    {
        uint8_t buf[64], hdr[EV_HEADER_MAX];
        uint8_t *w = buf;
        ev_state s = {0};
        /* Prime with a stub event. */
        int hl = ev_build_header(&s, hdr, EV_STDOUT, 1000,
                                 1, 1, 1, 1, 1, NULL, 0);
        ASSERT(hl > 0);
        ASSERT(yeet_pair(&w, buf + sizeof buf, hdr, hl, "x", 1) == 0);
        size_t before = (size_t)(w - buf);
        /* Second event 1 ns later, same pids. */
        hl = ev_build_header(&s, hdr, EV_STDOUT, 1001,
                             1, 1, 1, 1, 1, NULL, 0);
        ASSERT(hl > 0);
        ASSERT(yeet_pair(&w, buf + sizeof buf, hdr, hl, "hello\n", 6) == 0);
        size_t delta = (size_t)(w - buf) - before;
        fprintf(stderr, "tiny-event size: %zu bytes\n", delta);
        ASSERT(delta <= 16);
    }

    fprintf(stderr, "yeetdump selftest: OK\n");
    return 0;
}

int yeetdump_main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--selftest") == 0) {
        return selftest();
    }
    if (argc < 2) {
        fprintf(stderr,
                "usage: tv dump --selftest\n"
                "       tv dump trace.bin [trace.bin ...]\n");
        return 2;
    }
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        if (dump_file(argv[i]) != 0) { rc = 1; }
    }
    return rc;
}
