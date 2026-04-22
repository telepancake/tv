/* main.cpp — tv top-level: arg parsing, ingest, and TUI wiring.
 *
 * The whole pipeline:
 *
 *   wire bytes   ───►  WireDecoder  ───►  TvDb (DuckDB Appender)  ───►  .tvdb file
 *      ▲                                                                  │
 *      │                                                                  ▼
 *   uproctrace child / `--trace foo.wire`                  TvDataSource (SQL queries)
 *                                                                          │
 *                                                                          ▼
 *                                                                    Tui (engine.h)
 *
 * No in-memory aggregation, no JSONL, one wire decoder, one storage
 * format. Trace files on disk are DuckDB native (`foo.tvdb`); they
 * are mmaped on open and queried directly — no "load" step.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <csignal>

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <memory>
#include <string>
#include <vector>

#include <zstd.h>

#include "engine.h"
#include "wire_in.h"
#include "tv_db.h"
#include "data_source.h"

extern int uproctrace_main(int argc, char **argv);
extern int run_tests(); /* tests.cpp */
extern int fv_main(int argc, char **argv); /* fv.cpp */
extern "C" int sudtrace_main(int argc, char **argv);  /* sud/sudtrace.c */
extern "C" int yeetdump_main(int argc, char **argv);  /* tools/yeetdump/yeetdump.c */

namespace {

enum live_trace_backend {
    LIVE_TRACE_BACKEND_AUTO = 0,
    LIVE_TRACE_BACKEND_MODULE,
    LIVE_TRACE_BACKEND_SUD,
    LIVE_TRACE_BACKEND_PTRACE,
};

const char *USAGE =
    "tv — process trace viewer (DuckDB-backed)\n"
    "\n"
    "Subcommands:\n"
    "  tv [--module|--sud|--ptrace] -- <cmd> [args...]\n"
    "                              record live and view\n"
    "  tv --trace <file.wire[.zst]>      ingest into <file>.tvdb and view\n"
    "  tv --open  <file.tvdb>            open existing tvdb and view\n"
    "  tv --dump                         dump mode 1 (process tree) to stdout (with --trace/--open)\n"
    "\n"
    "Tools (folded in from former separate binaries):\n"
    "  tv sud [args...]            sudtrace launcher (former sudtrace)\n"
    "  tv dump <wire-file>...      hexdump a wire stream (former yeetdump)\n"
    "  tv dump --selftest          wire-format roundtrip test\n"
    "  tv fv [path]                file viewer (former fv)\n"
    "  tv module -- <cmd> ...      shorthand for `tv uproctrace --module --`\n"
    "  tv ptrace -- <cmd> ...      shorthand for `tv uproctrace --ptrace --`\n"
    "  tv uproctrace [-o FILE] [--module|--sud|--ptrace] -- <cmd> ...\n"
    "                              raw recorder (writes wire to fd/file)\n"
    "  tv test                     run built-in self-tests\n";

/* ── ingest helpers ───────────────────────────────────────────────── */

bool has_suffix(const char *s, const char *suf) {
    size_t n = std::strlen(s), k = std::strlen(suf);
    return n >= k && std::memcmp(s + n - k, suf, k) == 0;
}

/* Pipe the bytes of `f` through a wire decoder feeding `db`. Returns
 * false on a hard wire/decode error or db append failure. */
bool ingest_wire_plain(FILE *f, TvDb &db, std::string *err) {
    WireDecoder dec([&](const WireEvent &ev) {
        std::string e;
        if (!db.append(ev, &e)) {
            std::fprintf(stderr, "tv: ingest: %s\n", e.c_str());
        }
    });
    char buf[64 * 1024];
    while (true) {
        size_t n = std::fread(buf, 1, sizeof buf, f);
        if (n == 0) break;
        if (!dec.feed(buf, n)) {
            if (err) *err = "wire decode error";
            return false;
        }
    }
    return true;
}

bool ingest_wire_zstd(FILE *f, TvDb &db, std::string *err) {
    ZSTD_DCtx *dctx = ZSTD_createDCtx();
    if (!dctx) { if (err) *err = "ZSTD_createDCtx failed"; return false; }
    size_t in_cap = ZSTD_DStreamInSize();
    size_t out_cap = ZSTD_DStreamOutSize();
    std::unique_ptr<char[]> in_buf(new char[in_cap]);
    std::unique_ptr<char[]> out_buf(new char[out_cap]);
    bool ok = true;
    WireDecoder dec([&](const WireEvent &ev) {
        std::string e;
        if (!db.append(ev, &e)) {
            std::fprintf(stderr, "tv: ingest: %s\n", e.c_str());
        }
    });
    while (true) {
        size_t n = std::fread(in_buf.get(), 1, in_cap, f);
        if (n == 0) break;
        ZSTD_inBuffer in{in_buf.get(), n, 0};
        while (in.pos < in.size) {
            ZSTD_outBuffer out{out_buf.get(), out_cap, 0};
            size_t r = ZSTD_decompressStream(dctx, &out, &in);
            if (ZSTD_isError(r)) {
                if (err) *err = std::string("zstd: ") + ZSTD_getErrorName(r);
                ok = false;
                goto done;
            }
            if (out.pos > 0) {
                if (!dec.feed(out_buf.get(), out.pos)) {
                    if (err) *err = "wire decode error";
                    ok = false;
                    goto done;
                }
            }
        }
    }
done:
    ZSTD_freeDCtx(dctx);
    return ok;
}

bool ingest_wire_file(const char *path, TvDb &db, std::string *err) {
    FILE *f = std::fopen(path, "rb");
    if (!f) {
        if (err) *err = std::string("open ") + path + ": " + std::strerror(errno);
        return false;
    }
    bool zst = has_suffix(path, ".zst");
    bool ok = zst ? ingest_wire_zstd(f, db, err) : ingest_wire_plain(f, db, err);
    std::fclose(f);
    return ok;
}

/* Derive a default `.tvdb` path next to the given wire file. */
std::string default_tvdb_for_wire(const char *wire_path) {
    std::string p = wire_path;
    /* strip .zst */
    if (p.size() > 4 && p.compare(p.size() - 4, 4, ".zst") == 0)
        p.resize(p.size() - 4);
    /* strip .wire */
    if (p.size() > 5 && p.compare(p.size() - 5, 5, ".wire") == 0)
        p.resize(p.size() - 5);
    return p + ".tvdb";
}

bool file_exists(const char *path) {
    struct stat st;
    return ::stat(path, &st) == 0;
}

/* ── live-trace pipe glue ──────────────────────────────────────────── */

struct LiveTrace {
    pid_t          child_pid = 0;
    int            fd = -1;
    TvDb          *db = nullptr;
    WireDecoder   *dec = nullptr;
};

void on_trace_fd_cb(Tui &tui, int fd, LiveTrace &lt) {
    char buf[64 * 1024];
    ssize_t n = ::read(fd, buf, sizeof buf);
    if (n <= 0) {
        tui.unwatch_fd(fd);
        if (n == 0) std::fprintf(stderr, "tv: trace pipe EOF\n");
        ::close(fd); lt.fd = -1;
        return;
    }
    if (!lt.dec->feed(buf, n)) {
        std::fprintf(stderr, "tv: wire decode error\n");
        tui.unwatch_fd(fd); ::close(fd); lt.fd = -1;
    }
    /* Trigger redraw by dirtying both panels. */
    tui.dirty();
}

/* ── TUI key handling ──────────────────────────────────────────────── */

const char *HELP_LINES[] = {
    "",
    "  tv — Process Trace Viewer (DuckDB-backed)",
    "  ─────────────────────────────────────────",
    "",
    "  ↑↓ jk    Navigate    PgUp/PgDn  Page    g/G  First/Last",
    "  Tab      Switch panel    Enter   Follow link to process",
    "  /text    Search current panel    Esc    Clear search",
    "",
    "  1  Process tree     2  File tree       3  Event log",
    "  4  Deps             5  Reverse deps    6  Dep cmds       7  RDep cmds",
    "  s  Toggle subtree-only (mode 1)",
    "  q  Quit             ?  Help",
    nullptr
};

struct UiCtx {
    Tui          *tui = nullptr;
    int           lpane = -1;
    int           rpane = -1;
    AppState     *state = nullptr;
    TvDataSource *src = nullptr;
};

void update_status(UiCtx &c) {
    if (!c.tui) return;
    char buf[256];
    std::snprintf(buf, sizeof buf,
        "tv (DuckDB) | mode %d | %s%s | 1..7 mode  /  search  ?  help",
        c.state->mode,
        c.state->cursor_id.empty() ? "no-cursor" : ("cursor=" + c.state->cursor_id).c_str(),
        c.state->search.empty() ? "" : (" /" + c.state->search).c_str());
    c.tui->set_status(buf);
}

int on_key_cb(Tui &tui, int key, int panel, int /*cursor*/, const char *row_id,
              UiCtx &c) {
    auto refresh = [&]() {
        if (row_id) c.state->cursor_id = row_id;
        c.src->invalidate();
        tui.dirty();
        update_status(c);
    };
    if (key >= '1' && key <= '7') {
        c.state->mode = key - '0';
        c.state->cursor_id.clear();
        c.src->invalidate();
        tui.dirty();
        update_status(c);
        return TUI_HANDLED;
    }
    if (key == 'q' || key == TUI_K_ESC) {
        if (key == TUI_K_ESC && !c.state->search.empty()) {
            c.state->search.clear();
            c.src->invalidate();
            tui.dirty();
            update_status(c);
            return TUI_HANDLED;
        }
        tui.quit();
        return TUI_HANDLED;
    }
    if (key == '?') {
        tui.show_help(HELP_LINES);
        return TUI_HANDLED;
    }
    if (key == '/') {
        char buf[128] = {};
        if (tui.line_edit("search: ", buf, sizeof buf) >= 0) {
            c.state->search = buf;
            c.src->invalidate();
            tui.dirty();
            update_status(c);
        }
        return TUI_HANDLED;
    }
    /* Cursor changes update the rpane. */
    if (panel == c.lpane && row_id && std::string(row_id) != c.state->cursor_id) {
        c.state->cursor_id = row_id;
        c.src->invalidate();
        tui.dirty(c.rpane);
        update_status(c);
    }
    (void)refresh;
    return TUI_DEFAULT;
}

/* ── --dump : non-interactive dump of mode 1 lpane (for tests) ─────── */

int dump_mode1(TvDb &db) {
    AppState st;
    st.mode = 1;
    TvDataSource ts(db, st);
    auto srcfn = ts.make_data_source();
    srcfn.row_begin(0);
    while (srcfn.row_has_more(0)) {
        RowData r = srcfn.row_next(0);
        std::printf("%s", r.id.c_str());
        for (auto &col : r.cols) std::printf("\t%s", col.c_str());
        std::printf("\n");
    }
    return 0;
}

} /* namespace */

int main(int argc, char **argv) {
    /* Subcommand dispatch (must be the first positional arg, before any
     * --flag). This consolidates what used to be separate binaries. */
    if (argc >= 2 && argv[1][0] != '-') {
        const char *sub = argv[1];
        if (!std::strcmp(sub, "sud"))
            return sudtrace_main(argc - 1, argv + 1);
        if (!std::strcmp(sub, "dump"))
            return yeetdump_main(argc - 1, argv + 1);
        if (!std::strcmp(sub, "fv"))
            return fv_main(argc - 1, argv + 1);
        if (!std::strcmp(sub, "test"))
            return run_tests();
        if (!std::strcmp(sub, "uproctrace"))
            return uproctrace_main(argc - 1, argv + 1);
        if (!std::strcmp(sub, "module") || !std::strcmp(sub, "ptrace")) {
            /* tv module -- <cmd>  ==  tv uproctrace --module -- <cmd> */
            std::vector<char*> nargv;
            nargv.push_back((char*)"uproctrace");
            std::string flag = std::string("--") + sub;
            nargv.push_back((char*)flag.c_str());
            for (int i = 2; i < argc; i++) nargv.push_back(argv[i]);
            return uproctrace_main((int)nargv.size(), nargv.data());
        }
        /* Fall through: not a known subcommand. Treat as a usage error
         * rather than silently feeding it to the TUI parser, which
         * would just print USAGE again. */
        std::fprintf(stderr, "tv: unknown subcommand: %s\n\n", sub);
        std::fputs(USAGE, stderr);
        return 1;
    }

    /* Legacy long-flag entry points (kept for back-compat). */
    if (argc >= 2 && std::strcmp(argv[1], "--uproctrace") == 0)
        return uproctrace_main(argc - 1, argv + 1);
    if (argc >= 2 && std::strcmp(argv[1], "--test") == 0)
        return run_tests();

    live_trace_backend live_backend = LIVE_TRACE_BACKEND_AUTO;
    int no_env = 0;
    const char *trace_file = nullptr;
    const char *open_file  = nullptr;
    const char *out_db     = nullptr;
    bool dump = false;
    char **cmd = nullptr;

    for (int i = 1; i < argc; i++) {
        if      (!std::strcmp(argv[i], "--trace") && i + 1 < argc) trace_file = argv[++i];
        else if (!std::strcmp(argv[i], "--open")  && i + 1 < argc) open_file  = argv[++i];
        else if (!std::strcmp(argv[i], "-o")      && i + 1 < argc) out_db     = argv[++i];
        else if (!std::strcmp(argv[i], "--dump")) dump = true;
        else if (!std::strcmp(argv[i], "--no-env")) no_env = 1;
        else if (!std::strcmp(argv[i], "--module"))  live_backend = LIVE_TRACE_BACKEND_MODULE;
        else if (!std::strcmp(argv[i], "--sud"))     live_backend = LIVE_TRACE_BACKEND_SUD;
        else if (!std::strcmp(argv[i], "--ptrace"))  live_backend = LIVE_TRACE_BACKEND_PTRACE;
        else if (!std::strcmp(argv[i], "--") && i + 1 < argc) { cmd = argv + i + 1; break; }
        else {
            std::fprintf(stderr, "tv: unrecognised arg: %s\n", argv[i]);
            std::fputs(USAGE, stderr);
            return 1;
        }
    }

    if (!trace_file && !open_file && !cmd) {
        std::fputs(USAGE, stderr);
        return 1;
    }

    /* Decide backing .tvdb path. */
    std::string db_path;
    if (open_file) {
        db_path = open_file;
    } else if (trace_file) {
        db_path = out_db ? out_db : default_tvdb_for_wire(trace_file);
        /* If the .tvdb is older than the wire file or absent, rebuild. */
        struct stat st_wire{}, st_db{};
        bool need_build = ::stat(db_path.c_str(), &st_db) != 0;
        if (!need_build && ::stat(trace_file, &st_wire) == 0 &&
            st_wire.st_mtime > st_db.st_mtime) need_build = true;
        if (need_build) {
            ::unlink(db_path.c_str());
            std::string err;
            auto db = TvDb::open_file(db_path, &err);
            if (!db) { std::fprintf(stderr, "tv: %s\n", err.c_str()); return 1; }
            if (!ingest_wire_file(trace_file, *db, &err)) {
                std::fprintf(stderr, "tv: %s\n", err.c_str()); return 1;
            }
            if (!db->flush(&err)) {
                std::fprintf(stderr, "tv: flush: %s\n", err.c_str()); return 1;
            }
        }
    } else {
        /* Live: write to a tempfile next to cwd. */
        if (out_db) db_path = out_db;
        else {
            char tmp[256];
            std::snprintf(tmp, sizeof tmp, "tv-live-%d.tvdb", (int)::getpid());
            db_path = tmp;
        }
        ::unlink(db_path.c_str());
    }

    std::string err;
    auto db = TvDb::open_file(db_path, &err);
    if (!db) { std::fprintf(stderr, "tv: %s\n", err.c_str()); return 1; }

    /* Live-trace child setup. */
    LiveTrace lt;
    lt.db = db.get();
    if (cmd) {
        int pipefd[2];
        if (pipe(pipefd) < 0) { std::perror("pipe"); return 1; }
        lt.child_pid = ::fork();
        if (lt.child_pid < 0) { std::perror("fork"); return 1; }
        if (lt.child_pid == 0) {
            ::close(pipefd[0]);
            if (::dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
            ::close(pipefd[1]);
            size_t cmdc = 0; while (cmd[cmdc]) cmdc++;
            size_t extra = 2 + cmdc + 1;
            if (no_env) extra++;
            if (live_backend != LIVE_TRACE_BACKEND_AUTO) extra++;
            char **uargv = (char **)std::calloc(extra, sizeof(char*));
            size_t ui = 0;
            uargv[ui++] = (char*)"--uproctrace";
            if (no_env) uargv[ui++] = (char*)"--no-env";
            if (live_backend == LIVE_TRACE_BACKEND_MODULE) uargv[ui++] = (char*)"--module";
            else if (live_backend == LIVE_TRACE_BACKEND_SUD) uargv[ui++] = (char*)"--sud";
            else if (live_backend == LIVE_TRACE_BACKEND_PTRACE) uargv[ui++] = (char*)"--ptrace";
            uargv[ui++] = (char*)"--";
            for (size_t j = 0; j < cmdc; j++) uargv[ui++] = cmd[j];
            uargv[ui] = nullptr;
            _exit(uproctrace_main((int)ui, uargv));
        }
        ::close(pipefd[1]);
        lt.fd = pipefd[0];
    }

    /* If we just wanted a non-interactive dump, do it and exit. */
    if (dump) {
        if (cmd) { /* drain the live pipe first */
            char buf[64 * 1024];
            WireDecoder dec([&](const WireEvent &ev) {
                std::string e; (void)db->append(ev, &e);
            });
            while (true) {
                ssize_t n = ::read(lt.fd, buf, sizeof buf);
                if (n <= 0) break;
                if (!dec.feed(buf, n)) break;
            }
            ::close(lt.fd);
            ::waitpid(lt.child_pid, nullptr, 0);
            db->flush(&err);
        }
        return dump_mode1(*db);
    }

    /* TUI. */
    AppState state;
    state.mode = 1;
    TvDataSource src(*db, state);
    UiCtx ui;
    ui.state = &state;
    ui.src = &src;

    bool headless = !::isatty(STDIN_FILENO) || !::isatty(STDOUT_FILENO);
    auto tui = headless ? Tui::open_headless(src.make_data_source(), 24, 80)
                        : Tui::open(src.make_data_source());
    if (!tui) {
        std::fprintf(stderr, "tv: cannot open terminal\n");
        return 1;
    }
    ui.tui = tui.get();

    static const ColDef text_col[] = {{-1, TUI_ALIGN_LEFT, TUI_OVERFLOW_TRUNCATE}};
    static const PanelDef lpane_def = {nullptr, text_col, 1, TUI_PANEL_CURSOR};
    static const PanelDef rpane_def = {nullptr, text_col, 1,
                                       TUI_PANEL_CURSOR | TUI_PANEL_BORDER};
    ui.lpane = tui->add_panel(lpane_def);
    ui.rpane = tui->add_panel(rpane_def);
    static Box lbox = {TUI_BOX_PANEL, 1, 0, 0, 0, {}};
    static Box rbox = {TUI_BOX_PANEL, 1, 0, 0, 0, {}};
    static Box hbox = {TUI_BOX_HBOX,  1, 0, 0, -1, {&lbox, &rbox}};
    lbox.panel = ui.lpane; rbox.panel = ui.rpane;
    tui->set_layout(&hbox);

    tui->on_key([&ui](Tui &t, int key, int panel, int cur, const char *id) {
        return on_key_cb(t, key, panel, cur, id, ui);
    });
    update_status(ui);
    tui->dirty();

    if (lt.fd >= 0) {
        WireDecoder dec([&](const WireEvent &ev) {
            std::string e; (void)db->append(ev, &e);
            src.invalidate();
        });
        lt.dec = &dec;
        tui->watch_fd(lt.fd, [&](Tui &t, int fd){ on_trace_fd_cb(t, fd, lt); });
        tui->run();
    } else {
        tui->run();
    }

    if (lt.fd >= 0) { ::close(lt.fd); lt.fd = -1; }
    if (lt.child_pid > 0) { ::kill(lt.child_pid, SIGTERM); ::waitpid(lt.child_pid, nullptr, 0); }
    return 0;
}
