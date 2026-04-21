/* tests.cpp — tv self-tests.
 *
 * Run with `tv --test`. Strictly black-box: build a wire byte stream
 * in-memory, feed it through the same WireDecoder + TvDb path the
 * real ingest uses, then assert that SQL queries against the resulting
 * database return what we expect.
 */

#include "wire_in.h"
#include "tv_db.h"

extern "C" {
#include "wire/wire.h"
}

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

int g_fail = 0;
int g_pass = 0;

#define EXPECT(cond) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

#define EXPECT_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { g_pass++; } \
    else { g_fail++; std::fprintf(stderr, "FAIL %s:%d: %s == %s (left=%lld right=%lld)\n", \
        __FILE__, __LINE__, #a, #b, (long long)_a, (long long)_b); } \
} while (0)

#define EXPECT_STR(a, b) do { \
    std::string _a = (a); std::string _b = (b); \
    if (_a == _b) { g_pass++; } \
    else { g_fail++; std::fprintf(stderr, "FAIL %s:%d: %s == %s (left=\"%s\" right=\"%s\")\n", \
        __FILE__, __LINE__, #a, #b, _a.c_str(), _b.c_str()); } \
} while (0)

/* ── tiny wire-stream builder ─────────────────────────────────────── */

struct WireBuilder {
    std::vector<uint8_t> buf;
    ev_state st{};
    bool wrote_version = false;

    void reserve_more(size_t n) {
        if (buf.size() + n > buf.capacity()) buf.reserve(buf.size() + n + 64);
    }

    void write_atom(const void *data, size_t len) {
        /* Use the public yeet_pair (header empty), allocating a generous
         * scratch then truncating. For tests, just compute the prefix
         * worst-case and resize. */
        size_t cap = buf.size() + 16 + len;
        buf.resize(cap);
        uint8_t *p = buf.data() + buf.size() - 16 - len;
        const uint8_t *end = buf.data() + cap;
        if (yeet_blob(&p, end, data, (uint64_t)len) < 0) {
            std::fprintf(stderr, "wirebuilder yeet_blob failed\n");
            std::abort();
        }
        buf.resize((size_t)(p - buf.data()));
    }

    void version() {
        if (wrote_version) return;
        uint8_t pre[8]; uint8_t *p = pre;
        if (yeet_u64(&p, pre + sizeof pre, WIRE_VERSION) < 0) std::abort();
        buf.insert(buf.end(), pre, p);
        wrote_version = true;
    }

    void event(int32_t type, uint64_t ts_ns, int32_t pid, int32_t tgid,
               int32_t ppid, const int64_t *extras, unsigned n_extras,
               const void *blob, size_t blen) {
        version();
        uint8_t hdr[EV_HEADER_MAX];
        int hlen = ev_build_header(&st, hdr, type, ts_ns, pid, tgid, ppid,
                                   pid /*nspid*/, tgid /*nstgid*/,
                                   extras, n_extras);
        if (hlen < 0) { std::fprintf(stderr, "ev_build_header failed\n"); std::abort(); }
        /* Outer atom = header || blob. Use yeet_pair. */
        size_t cap_extra = 16 + (size_t)hlen + blen;
        size_t cur = buf.size();
        buf.resize(cur + cap_extra);
        uint8_t *p = buf.data() + cur;
        const uint8_t *end = buf.data() + cur + cap_extra;
        if (yeet_pair(&p, end, hdr, (uint64_t)hlen, blob, (uint64_t)blen) < 0) {
            std::fprintf(stderr, "yeet_pair failed\n"); std::abort();
        }
        buf.resize((size_t)(p - buf.data()));
    }
};

/* ── fixture: a tiny synthetic trace ──────────────────────────────── */

void build_fixture(WireBuilder &w) {
    /* Process 100: make all */
    w.event(EV_EXEC, 1000, /*pid*/100, /*tgid*/100, /*ppid*/1, nullptr, 0,
            "/usr/bin/make", 13);
    /* argv: make\0all\0 (trailing NUL kernel-style) */
    w.event(EV_ARGV, 1000, 100, 100, 1, nullptr, 0, "make\0all\0", 9);
    w.event(EV_CWD,  1000, 100, 100, 1, nullptr, 0, "/home/user", 10);
    /* OPEN /etc/passwd O_RDONLY fd=3 */
    int64_t open_ex[7] = {0 /*flags*/, 3, 0, 0, 0, 0, 0};
    w.event(EV_OPEN, 1100, 100, 100, 1, open_ex, 7, "/etc/passwd", 11);
    /* OPEN /tmp/out O_WRONLY|O_CREAT fd=4 with err=0 */
    int64_t open_ex2[7] = {0101 /*O_WRONLY|O_CREAT*/, 4, 0, 0, 0, 0, 0};
    w.event(EV_OPEN, 1200, 100, 100, 1, open_ex2, 7, "/tmp/out", 8);
    /* exit code 0 */
    int64_t ex[4] = {EV_EXIT_EXITED, 0, 0, 0};
    w.event(EV_EXIT, 2000, 100, 100, 1, ex, 4, nullptr, 0);

    /* Process 200: failing child of 100 */
    w.event(EV_EXEC, 1500, 200, 200, 100, nullptr, 0, "/bin/false", 10);
    w.event(EV_ARGV, 1500, 200, 200, 100, nullptr, 0, "false\0", 6);
    int64_t ex2[4] = {EV_EXIT_EXITED, 1, 0, 256};
    w.event(EV_EXIT, 1600, 200, 200, 100, ex2, 4, nullptr, 0);
}

/* ── tests ─────────────────────────────────────────────────────────── */

void test_wire_decoder_parses_all_events() {
    WireBuilder w;
    build_fixture(w);

    int counts[16] = {0};
    WireDecoder dec([&](const WireEvent &ev) {
        if (ev.type >= 0 && ev.type < 16) counts[ev.type]++;
    });
    EXPECT(dec.feed(w.buf.data(), w.buf.size()));
    EXPECT_EQ(counts[EV_EXEC], 2);
    EXPECT_EQ(counts[EV_ARGV], 2);
    EXPECT_EQ(counts[EV_CWD],  1);
    EXPECT_EQ(counts[EV_OPEN], 2);
    EXPECT_EQ(counts[EV_EXIT], 2);
}

void test_wire_decoder_byte_at_a_time() {
    WireBuilder w;
    build_fixture(w);
    int total = 0;
    WireDecoder dec([&](const WireEvent &) { total++; });
    for (size_t i = 0; i < w.buf.size(); i++) {
        EXPECT(dec.feed(&w.buf[i], 1));
    }
    /* 2 EXEC + 2 ARGV + 1 CWD + 2 OPEN + 2 EXIT = 9 */
    EXPECT_EQ(total, 9);
}

void test_wire_decoder_rejects_wrong_version() {
    /* Hand-craft a stream with a bad version. */
    uint8_t bad[2];
    uint8_t *p = bad;
    yeet_u64(&p, bad + sizeof bad, 99); /* version 99 — unsupported */
    int evs = 0;
    WireDecoder dec([&](const WireEvent &){ evs++; });
    EXPECT(!dec.feed(bad, (size_t)(p - bad)));
    EXPECT_EQ(evs, 0);
}

void test_tvdb_ingest_and_query() {
    std::string err;
    auto db = TvDb::open_memory(&err);
    EXPECT(db != nullptr);
    if (!db) { std::fprintf(stderr, "open_memory: %s\n", err.c_str()); return; }

    WireBuilder w;
    build_fixture(w);
    WireDecoder dec([&](const WireEvent &ev) {
        std::string e; (void)db->append(ev, &e);
    });
    EXPECT(dec.feed(w.buf.data(), w.buf.size()));
    EXPECT(db->flush(&err));

    /* row counts per table */
    auto exec_n = db->query_int64("SELECT COUNT(*) FROM exec", &err);
    EXPECT_EQ((int64_t)2, exec_n.empty() ? -1 : exec_n[0]);
    auto open_n = db->query_int64("SELECT COUNT(*) FROM open_", &err);
    EXPECT_EQ((int64_t)2, open_n.empty() ? -1 : open_n[0]);
    auto exit_n = db->query_int64("SELECT COUNT(*) FROM exit_", &err);
    EXPECT_EQ((int64_t)2, exit_n.empty() ? -1 : exit_n[0]);
    auto argv_n = db->query_int64("SELECT COUNT(*) FROM argv", &err);
    /* Process 100: make, all (2 args). Process 200: false (1 arg). */
    EXPECT_EQ((int64_t)3, argv_n.empty() ? -1 : argv_n[0]);

    /* Process 100 ran make */
    auto exes = db->query_strings(
        "SELECT exe FROM exec WHERE tgid = 100", &err);
    EXPECT_EQ((size_t)1, exes.size());
    if (!exes.empty()) EXPECT_STR(exes[0][0], "/usr/bin/make");

    /* Process 200 exited with code 1 (failing) */
    auto codes = db->query_int64(
        "SELECT code_or_sig FROM exit_ WHERE tgid = 200", &err);
    EXPECT_EQ((int64_t)1, codes.empty() ? -1 : codes[0]);

    /* The OPEN of /tmp/out was a write (O_WRONLY|O_CREAT). Test uses
     * `% 4` instead of `& 3` because the bitwise & operator lives in
     * DuckDB's core_functions extension which is not linked into the
     * vendored amalgamation. */
    auto wopens = db->query_strings(
        "SELECT path FROM open_ WHERE tgid = 100 AND (flags % 4) != 0", &err);
    EXPECT_EQ((size_t)1, wopens.size());
    if (!wopens.empty()) EXPECT_STR(wopens[0][0], "/tmp/out");

    /* Total row count = 2 EXEC + 3 ARGV-rows (make,all,false)
     *                 + 1 CWD + 2 OPEN + 2 EXIT = 10 rows. */
    EXPECT_EQ((int64_t)10, db->total_event_count());
}

void test_tvdb_persists_across_open() {
    std::string err;
    char path[64]; std::snprintf(path, sizeof path, "/tmp/tv_test_%d.tvdb",
                                 (int)::getpid());
    ::unlink(path);
    {
        auto db = TvDb::open_file(path, &err);
        EXPECT(db != nullptr);
        if (!db) return;
        WireBuilder w; build_fixture(w);
        WireDecoder dec([&](const WireEvent &ev){
            std::string e; (void)db->append(ev, &e);
        });
        dec.feed(w.buf.data(), w.buf.size());
        db->flush(&err);
    }
    {
        auto db = TvDb::open_file(path, &err);
        EXPECT(db != nullptr);
        if (!db) { ::unlink(path); return; }
        EXPECT_EQ((int64_t)10, db->total_event_count());
    }
    ::unlink(path);
}

void test_data_source_mode1_query() {
    /* The lpane mode 1 query must produce one row per process,
     * ordered by start_ns ascending. */
    std::string err;
    auto db = TvDb::open_memory(&err);
    if (!db) { std::fprintf(stderr, "open_memory: %s\n", err.c_str()); g_fail++; return; }
    WireBuilder w; build_fixture(w);
    WireDecoder dec([&](const WireEvent &ev){ std::string e; (void)db->append(ev, &e); });
    dec.feed(w.buf.data(), w.buf.size());
    db->flush(&err);

    auto rows = db->query_strings(
        "SELECT p.tgid FROM exec p GROUP BY p.tgid ORDER BY MIN(p.ts_ns)", &err);
    EXPECT_EQ((size_t)2, rows.size());
    if (rows.size() == 2) {
        EXPECT_STR(rows[0][0], "100");
        EXPECT_STR(rows[1][0], "200");
    }
}

} /* namespace */

int run_tests() {
    test_wire_decoder_parses_all_events();
    test_wire_decoder_byte_at_a_time();
    test_wire_decoder_rejects_wrong_version();
    test_tvdb_ingest_and_query();
    test_tvdb_persists_across_open();
    test_data_source_mode1_query();

    std::fprintf(stderr, "tv tests: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
