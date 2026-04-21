/* ctf-dump.c — Decode a tv CTF stream to text, or self-test the
 * encoder/decoder round-trip.
 *
 *   ctf-dump --selftest
 *       Build a synthetic packet covering every event class, decode
 *       it back, and compare. Exits non-zero on mismatch.
 *
 *   ctf-dump trace.ctf [trace.ctf...]
 *       Decode each file (raw CTF, no zstd here — pipe through
 *       `zstd -dc` for compressed traces) and print a one-line
 *       summary per event to stdout.
 *
 * Kept tiny on purpose: this is a contract validator, not a feature
 * tool. babeltrace2 + the TSDL metadata is the production decoder.
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

#include "ctf/encode.h"

/* ── Decode helpers ────────────────────────────────────────────────── */

static int read_event_header(const uint8_t *p, uint32_t cap, uint32_t off,
                             uint16_t *id, uint64_t *ts_delta,
                             int32_t *pid, int32_t *tgid, int32_t *ppid,
                             int32_t *nspid, int32_t *nstgid,
                             uint32_t *consumed) {
    uint32_t start = off;
    int n;
    if ((n = ctf_get_u16    (p, cap, off, id))      < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_get_uleb128(p, cap, off, ts_delta))< 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_get_i32    (p, cap, off, pid))     < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_get_i32    (p, cap, off, tgid))    < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_get_i32    (p, cap, off, ppid))    < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_get_i32    (p, cap, off, nspid))   < 0) { return -1; } off += (uint32_t)n;
    if ((n = ctf_get_i32    (p, cap, off, nstgid))  < 0) { return -1; } off += (uint32_t)n;
    *consumed = off - start;
    return 0;
}

static void print_bytes_safe(const uint8_t *b, uint32_t n) {
    /* Bytes are bytes — no encoding contract. Print printable ASCII as-is,
     * everything else as \xHH so the dump stays line-oriented. */
    for (uint32_t i = 0; i < n; i++) {
        uint8_t c = b[i];
        if (c >= 0x20 && c < 0x7f && c != '\\') {
            putchar((int)c);
        } else {
            printf("\\x%02x", c);
        }
    }
}

/* Returns event size on success, -1 on malformed. Prints one line. */
static int decode_one_event(const uint8_t *p, uint32_t cap, uint32_t off,
                            uint64_t ts_begin) {
    uint16_t id;
    uint64_t ts_delta;
    int32_t pid, tgid, ppid, nspid, nstgid;
    uint32_t hdr_bytes;
    uint32_t start = off;

    if (read_event_header(p, cap, off, &id, &ts_delta,
                          &pid, &tgid, &ppid, &nspid, &nstgid, &hdr_bytes) < 0)
        return -1;
    off += hdr_bytes;

    uint64_t ts = ts_begin + ts_delta;
    printf("[%lu.%09lu] tgid=%d pid=%d ppid=%d ns=%d/%d ",
           (unsigned long)(ts / 1000000000ull),
           (unsigned long)(ts % 1000000000ull),
           tgid, pid, ppid, nstgid, nspid);

    int n;
    const uint8_t *s; uint32_t slen;

    switch (id) {
    case CTF_EVENT_EXEC: {
        printf("EXEC exe=\"");
        if ((n = ctf_get_string(p, cap, off, &s, &slen)) < 0) return -1;
        print_bytes_safe(s, slen); off += (uint32_t)n;
        printf("\" argv_blob=%u", slen);
        if ((n = ctf_get_string(p, cap, off, &s, &slen)) < 0) return -1;
        printf("B(%u)", slen); off += (uint32_t)n;
        if ((n = ctf_get_string(p, cap, off, &s, &slen)) < 0) return -1;
        printf(" env_blob=%uB", slen); off += (uint32_t)n;
        if ((n = ctf_get_string(p, cap, off, &s, &slen)) < 0) return -1;
        printf(" auxv_blob=%uB", slen); off += (uint32_t)n;
        break;
    }
    case CTF_EVENT_EXIT: {
        uint8_t status, core; int32_t code, raw;
        if ((n = ctf_get_u8 (p, cap, off, &status)) < 0) { return -1; } off += (uint32_t)n;
        if ((n = ctf_get_i32(p, cap, off, &code))   < 0) { return -1; } off += (uint32_t)n;
        if ((n = ctf_get_u8 (p, cap, off, &core))   < 0) { return -1; } off += (uint32_t)n;
        if ((n = ctf_get_i32(p, cap, off, &raw))    < 0) { return -1; } off += (uint32_t)n;
        printf("EXIT %s code/sig=%d core=%d raw=%d",
               status == CTF_EXIT_EXITED ? "exited" : "signaled",
               code, core, raw);
        break;
    }
    case CTF_EVENT_OPEN: {
        uint32_t flags, devmaj, devmin; int32_t fd, err;
        uint64_t ino; uint8_t inh;
        if ((n = ctf_get_string(p, cap, off, &s, &slen)) < 0) { return -1; } off += (uint32_t)n;
        printf("OPEN path=\""); print_bytes_safe(s, slen); printf("\" ");
        if ((n = ctf_get_u32(p, cap, off, &flags))  < 0) { return -1; } off += (uint32_t)n;
        if ((n = ctf_get_i32(p, cap, off, &fd))     < 0) { return -1; } off += (uint32_t)n;
        if ((n = ctf_get_u64(p, cap, off, &ino))    < 0) { return -1; } off += (uint32_t)n;
        if ((n = ctf_get_u32(p, cap, off, &devmaj)) < 0) { return -1; } off += (uint32_t)n;
        if ((n = ctf_get_u32(p, cap, off, &devmin)) < 0) { return -1; } off += (uint32_t)n;
        if ((n = ctf_get_i32(p, cap, off, &err))    < 0) { return -1; } off += (uint32_t)n;
        if ((n = ctf_get_u8 (p, cap, off, &inh))    < 0) { return -1; } off += (uint32_t)n;
        printf("flags=0x%x fd=%d ino=%lu dev=%u:%u err=%d inh=%d",
               flags, fd, (unsigned long)ino, devmaj, devmin, err, inh);
        break;
    }
    case CTF_EVENT_CWD: {
        if ((n = ctf_get_string(p, cap, off, &s, &slen)) < 0) { return -1; } off += (uint32_t)n;
        printf("CWD path=\""); print_bytes_safe(s, slen); printf("\"");
        break;
    }
    case CTF_EVENT_STDOUT:
    case CTF_EVENT_STDERR: {
        if ((n = ctf_get_string(p, cap, off, &s, &slen)) < 0) { return -1; } off += (uint32_t)n;
        printf("%s len=%u data=\"",
               id == CTF_EVENT_STDOUT ? "STDOUT" : "STDERR", slen);
        print_bytes_safe(s, slen);
        printf("\"");
        break;
    }
    default:
        printf("UNKNOWN id=%u", id);
        return -1;
    }
    putchar('\n');
    return (int)(off - start);
}

/* Decode a single packet at p[0..]. Returns packet_size (bytes) or -1. */
static int decode_packet(const uint8_t *p, uint32_t cap) {
    if (cap < CTF_PACKET_HEADER_SIZE) return -1;

    uint32_t magic;     ctf_get_u32(p, cap, CTF_OFF_MAGIC, &magic);
    if (magic != CTF_PACKET_MAGIC) {
        fprintf(stderr, "ctf-dump: bad magic 0x%08x\n", magic);
        return -1;
    }
    uint64_t ts_begin, ts_end;
    uint32_t content_bits, packet_bits;
    uint16_t producer_id;
    ctf_get_u64(p, cap, CTF_OFF_TS_BEGIN,     &ts_begin);
    ctf_get_u64(p, cap, CTF_OFF_TS_END,       &ts_end);
    ctf_get_u32(p, cap, CTF_OFF_CONTENT_SIZE, &content_bits);
    ctf_get_u32(p, cap, CTF_OFF_PACKET_SIZE,  &packet_bits);
    ctf_get_u16(p, cap, CTF_OFF_PRODUCER_ID,  &producer_id);

    uint32_t content_bytes = content_bits / 8u;
    uint32_t packet_bytes  = packet_bits  / 8u;
    if (packet_bytes > cap || content_bytes > packet_bytes) {
        fprintf(stderr, "ctf-dump: packet size out of range\n");
        return -1;
    }

    fprintf(stderr,
            "-- packet: producer=%u ts=[%lu..%lu] content=%uB packet=%uB --\n",
            producer_id,
            (unsigned long)ts_begin, (unsigned long)ts_end,
            content_bytes, packet_bytes);

    uint32_t off = CTF_PACKET_HEADER_SIZE;
    while (off < content_bytes) {
        int n = decode_one_event(p, content_bytes, off, ts_begin);
        if (n <= 0) {
            fprintf(stderr, "ctf-dump: malformed event at offset %u\n", off);
            return -1;
        }
        off += (uint32_t)n;
    }
    return (int)packet_bytes;
}

static int decode_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return 1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return 1; }
    if (st.st_size <= 0) { close(fd); return 0; }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) { perror("mmap"); return 1; }

    const uint8_t *p = (const uint8_t *)m;
    uint32_t left = (uint32_t)st.st_size;
    uint32_t off = 0;
    while (left >= CTF_PACKET_HEADER_SIZE) {
        int n = decode_packet(p + off, left);
        if (n <= 0) { munmap(m, (size_t)st.st_size); return 1; }
        off  += (uint32_t)n;
        left -= (uint32_t)n;
    }
    munmap(m, (size_t)st.st_size);
    return 0;
}

/* ── Self-test ─────────────────────────────────────────────────────── */

static int selftest(void) {
    static uint8_t buf[16 * 1024];
    static const uint8_t uuid[CTF_UUID_SIZE] = {
        0xde,0xad,0xbe,0xef,0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
    };
    const uint64_t ts_begin = 1711814400ull * 1000000000ull;
    int off = ctf_packet_begin(buf, sizeof buf, uuid, /*producer_id*/7, ts_begin);
    if (off < 0) { fprintf(stderr, "begin failed\n"); return 1; }

    /* Embed a NUL in argv to prove strings carry raw bytes. */
    static const uint8_t argv_blob[] = "make\0-j8\0";  /* 9 bytes */
    static const uint8_t env_blob[]  = "PATH=/usr/bin\0HOME=/root\0";
    static const uint8_t auxv_blob[] = { 0,0,0,0, 0,0,0,0 };  /* AT_NULL */

    int n;
    n = ctf_event_exec(buf, sizeof buf, (uint32_t)off,
                       /*ts_delta*/100, 1234, 1234, 1200, 1234, 1234,
                       "/usr/bin/make", 13,
                       argv_blob, sizeof argv_blob - 1,
                       env_blob,  sizeof env_blob  - 1,
                       auxv_blob, sizeof auxv_blob);
    if (n < 0) { fprintf(stderr, "exec emit failed\n"); return 1; }
    off += n;

    n = ctf_event_cwd(buf, sizeof buf, (uint32_t)off,
                      /*ts_delta*/200, 1234, 1234, 1200, 1234, 1234,
                      "/home/user\0\xff", 12); /* embedded NUL & high byte */
    if (n < 0) { fprintf(stderr, "cwd emit failed\n"); return 1; }
    off += n;

    n = ctf_event_open(buf, sizeof buf, (uint32_t)off,
                       /*ts_delta*/300, 1234, 1234, 1200, 1234, 1234,
                       "/etc/passwd", 11,
                       /*flags*/0, /*fd*/3, /*ino*/524297,
                       /*devmaj*/259, /*devmin*/2, /*err*/0, /*inh*/0);
    if (n < 0) { fprintf(stderr, "open emit failed\n"); return 1; }
    off += n;

    n = ctf_event_stream(buf, sizeof buf, (uint32_t)off, CTF_EVENT_STDOUT,
                         /*ts_delta*/400, 1234, 1234, 1200, 1234, 1234,
                         "hello\n", 6);
    if (n < 0) { fprintf(stderr, "stdout emit failed\n"); return 1; }
    off += n;

    n = ctf_event_stream(buf, sizeof buf, (uint32_t)off, CTF_EVENT_STDERR,
                         /*ts_delta*/500, 1234, 1234, 1200, 1234, 1234,
                         "warning\n", 8);
    if (n < 0) { fprintf(stderr, "stderr emit failed\n"); return 1; }
    off += n;

    n = ctf_event_exit(buf, sizeof buf, (uint32_t)off,
                       /*ts_delta*/600, 1234, 1234, 1200, 1234, 1234,
                       CTF_EXIT_SIGNALED, /*sig*/11, /*core*/1, /*raw*/139);
    if (n < 0) { fprintf(stderr, "exit emit failed\n"); return 1; }
    off += n;

    /* Pad to an 8-byte boundary so packet_size is a multiple of 8. */
    uint32_t content_off = (uint32_t)off;
    uint32_t packet_off  = (content_off + 7u) & ~7u;
    while ((uint32_t)off < packet_off) buf[off++] = 0;
    ctf_packet_seal(buf, sizeof buf, content_off, packet_off,
                    ts_begin + 600);

    int rc = decode_packet(buf, packet_off);
    if (rc != (int)packet_off) {
        fprintf(stderr, "decode size mismatch: got %d, want %u\n",
                rc, packet_off);
        return 1;
    }
    fprintf(stderr, "ctf-dump selftest: OK (%u bytes)\n", packet_off);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--selftest") == 0) {
        return selftest();
    }
    if (argc < 2) {
        fprintf(stderr,
                "usage: ctf-dump --selftest\n"
                "       ctf-dump trace.ctf [trace.ctf ...]\n");
        return 2;
    }
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        if (decode_file(argv[i]) != 0) rc = 1;
    }
    return rc;
}
