/* trace/trace_processor.cpp — streaming TRACE processor.
 *
 * Reads zero or more TRACE streams (plain or zstd), optionally adds a live
 * tracer/processor launched as `EXE [--no-env] -- command...`, filters and
 * rewrites events, merges by timestamp, and writes a single TRACE stream to
 * stdout or a file.
 */

#include "trace/trace_stream.h"
#include "trace/trace.h"

#include <zstd.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cctype>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <algorithm>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

const char *USAGE =
    "traceproc - streaming tv TRACE processor\n"
    "\n"
    "Usage:\n"
    "  traceproc [options] [trace-file ...]\n"
    "  traceproc [options] --tracer EXE [--no-env] -- command [args...]\n"
    "\n"
    "Inputs:\n"
    "  trace-file              TRACE stream; use - for stdin\n"
    "  --tracer EXE            launch EXE like tv does and read its stdout\n"
    "  --processor EXE         alias for --tracer\n"
    "  --input-zstd=auto|yes|no  input compression (default: auto)\n"
    "\n"
    "Filters / selection:\n"
    "  --select LIST, --type LIST  keep event types (EXEC,OPEN,... or numbers)\n"
    "  --drop LIST             drop event types\n"
    "  --pid LIST              keep pids\n"
    "  --tgid LIST             keep tgids\n"
    "  --after-ns N            keep events at/after N\n"
    "  --before-ns N           keep events at/before N\n"
    "\n"
    "Modification / output:\n"
    "  --time-offset-ns N      add N to event timestamps\n"
    "  --set-stream-id N       rewrite all events to stream id N\n"
    "  -o FILE                 write output to FILE (default: stdout)\n"
    "  --zstd                  zstd-compress output\n"
    "  --no-zstd               force plain output\n";

enum class ZstdMode { Auto, Yes, No };

bool has_suffix(const std::string &s, const char *suffix) {
    size_t n = s.size(), k = std::strlen(suffix);
    return n >= k && std::memcmp(s.data() + n - k, suffix, k) == 0;
}

std::optional<long long> parse_i64(const char *s) {
    errno = 0;
    char *end = nullptr;
    long long v = std::strtoll(s, &end, 0);
    if (errno || !end || *end) return std::nullopt;
    return v;
}

std::optional<unsigned long long> parse_u64(const char *s) {
    errno = 0;
    char *end = nullptr;
    unsigned long long v = std::strtoull(s, &end, 0);
    if (errno || !end || *end) return std::nullopt;
    return v;
}

int event_type_by_name(const std::string &s) {
    std::string u;
    u.reserve(s.size());
    for (char c : s) u.push_back((char)std::toupper((unsigned char)c));
    if (u == "EXEC") return EV_EXEC;
    if (u == "ARGV") return EV_ARGV;
    if (u == "ENV") return EV_ENV;
    if (u == "AUXV") return EV_AUXV;
    if (u == "EXIT") return EV_EXIT;
    if (u == "OPEN") return EV_OPEN;
    if (u == "CWD") return EV_CWD;
    if (u == "STDOUT") return EV_STDOUT;
    if (u == "STDERR") return EV_STDERR;
    auto n = parse_i64(s.c_str());
    return n ? (int)*n : -1;
}

bool parse_type_list(const char *arg, bool bits[16]) {
    std::string s(arg);
    size_t pos = 0;
    while (pos <= s.size()) {
        size_t comma = s.find(',', pos);
        std::string tok = s.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
        if (tok.empty()) return false;
        int t = event_type_by_name(tok);
        if (t < 0 || t >= 16) return false;
        bits[t] = true;
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    return true;
}

bool parse_int_list(const char *arg, std::vector<int> &out) {
    std::string s(arg);
    size_t pos = 0;
    while (pos <= s.size()) {
        size_t comma = s.find(',', pos);
        std::string tok = s.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
        auto v = parse_i64(tok.c_str());
        if (!v || *v < INT_MIN || *v > INT_MAX) return false;
        out.push_back((int)*v);
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return true;
}

bool contains_int(const std::vector<int> &v, int x) {
    return v.empty() || std::binary_search(v.begin(), v.end(), x);
}

struct Options {
    std::vector<std::string> files;
    const char *tracer = nullptr;
    char **cmd = nullptr;
    bool no_env = false;
    ZstdMode input_zstd = ZstdMode::Auto;
    const char *out_path = nullptr;
    std::optional<bool> out_zstd;
    bool include_types[16] = {};
    bool have_include_types = false;
    bool drop_types[16] = {};
    std::vector<int> pids;
    std::vector<int> tgids;
    std::optional<uint64_t> after_ns;
    std::optional<uint64_t> before_ns;
    int64_t time_offset_signed_ns = 0;
    std::optional<uint32_t> set_stream_id;
};

struct OwnedEvent {
    int source = 0;
    int32_t type = 0;
    uint64_t ts_ns = 0;
    int32_t pid = 0, tgid = 0, ppid = 0, nspid = 0, nstgid = 0;
    uint32_t stream_id = 0;
    int64_t extras[7] = {};
    unsigned n_extras = 0;
    std::vector<uint8_t> blob;
};

class Output {
public:
    explicit Output(const Options &opt) : opt_(opt) {}
    ~Output() { close(); }

    bool open(std::string *err) {
        if (opt_.out_path) {
            f_ = std::fopen(opt_.out_path, "wb");
            if (!f_) {
                if (err) *err = std::string("open output: ") + std::strerror(errno);
                return false;
            }
            owns_ = true;
        } else {
            f_ = stdout;
        }
        bool want_zstd = opt_.out_zstd.value_or(opt_.out_path && has_suffix(opt_.out_path, ".zst"));
        if (want_zstd) {
            cctx_ = ZSTD_createCStream();
            if (!cctx_) {
                if (err) *err = "ZSTD_createCStream failed";
                return false;
            }
            size_t r = ZSTD_initCStream(cctx_, 3);
            if (ZSTD_isError(r)) {
                if (err) *err = std::string("zstd: ") + ZSTD_getErrorName(r);
                return false;
            }
            outbuf_.resize(ZSTD_CStreamOutSize());
        }
        uint8_t version[16];
        Dst d = wire_dst(version, sizeof version);
        wire_put_u64(&d, TRACE_VERSION);
        return d.p && write_bytes(version, (size_t)(d.p - version), err);
    }

    bool write_event(const OwnedEvent &ev, std::string *err) {
        const uint32_t sid = opt_.set_stream_id.value_or(out_stream_id(ev));
        ev_state &st = states_[sid];
        uint8_t hdr[EV_HEADER_MAX];
        Dst hd = wire_dst(hdr, sizeof hdr);
        ev_build_header(&st, &hd, sid, ev.type, ev.ts_ns,
                        ev.pid, ev.tgid, ev.ppid, ev.nspid, ev.nstgid,
                        ev.extras, ev.n_extras);
        if (!hd.p) {
            if (err) *err = "header encode failed";
            return false;
        }
        size_t hlen = (size_t)(hd.p - hdr);
        size_t cap = hlen + ev.blob.size() + 2 * WIRE_PREFIX_MAX + 16;
        std::vector<uint8_t> buf(cap);
        Dst od = wire_dst(buf.data(), buf.size());
        wire_put_pair(&od, wire_src(hdr, hlen), wire_src(ev.blob.data(), ev.blob.size()));
        if (!od.p) {
            if (err) *err = "event encode failed";
            return false;
        }
        return write_bytes(buf.data(), (size_t)(od.p - buf.data()), err);
    }

    bool close(std::string *err = nullptr) {
        bool ok = true;
        if (cctx_) {
            for (;;) {
                ZSTD_outBuffer out{outbuf_.data(), outbuf_.size(), 0};
                size_t r = ZSTD_endStream(cctx_, &out);
                if (ZSTD_isError(r)) {
                    if (err) *err = std::string("zstd: ") + ZSTD_getErrorName(r);
                    ok = false;
                    break;
                }
                if (out.pos && std::fwrite(out.dst, 1, out.pos, f_) != out.pos) {
                    if (err) *err = std::string("write output: ") + std::strerror(errno);
                    ok = false;
                    break;
                }
                if (r == 0) break;
            }
            ZSTD_freeCStream(cctx_);
            cctx_ = nullptr;
        }
        if (f_) {
            if (std::fflush(f_) != 0) {
                if (err) *err = std::string("flush output: ") + std::strerror(errno);
                ok = false;
            }
            if (owns_ && std::fclose(f_) != 0) {
                if (err) *err = std::string("close output: ") + std::strerror(errno);
                ok = false;
            }
            f_ = nullptr;
        }
        return ok;
    }

private:
    struct PairHash {
        size_t operator()(const uint64_t &v) const { return (size_t)(v ^ (v >> 32)); }
    };

    uint32_t out_stream_id(const OwnedEvent &ev) {
        uint64_t key = ((uint64_t)(uint32_t)ev.source << 32) | ev.stream_id;
        auto it = stream_map_.find(key);
        if (it != stream_map_.end()) return it->second;
        uint32_t sid = next_stream_id_++;
        if (sid == 0) sid = next_stream_id_++;
        stream_map_[key] = sid;
        return sid;
    }

    bool write_bytes(const void *data, size_t n, std::string *err) {
        if (!cctx_) {
            if (n && std::fwrite(data, 1, n, f_) != n) {
                if (err) *err = std::string("write output: ") + std::strerror(errno);
                return false;
            }
            return true;
        }
        ZSTD_inBuffer in{data, n, 0};
        while (in.pos < in.size) {
            ZSTD_outBuffer out{outbuf_.data(), outbuf_.size(), 0};
            size_t r = ZSTD_compressStream(cctx_, &out, &in);
            if (ZSTD_isError(r)) {
                if (err) *err = std::string("zstd: ") + ZSTD_getErrorName(r);
                return false;
            }
            if (out.pos && std::fwrite(out.dst, 1, out.pos, f_) != out.pos) {
                if (err) *err = std::string("write output: ") + std::strerror(errno);
                return false;
            }
        }
        return true;
    }

    const Options &opt_;
    FILE *f_ = nullptr;
    bool owns_ = false;
    ZSTD_CStream *cctx_ = nullptr;
    std::vector<char> outbuf_;
    std::unordered_map<uint32_t, ev_state> states_;
    std::unordered_map<uint64_t, uint32_t, PairHash> stream_map_;
    uint32_t next_stream_id_ = 1;
};

class Source {
public:
    Source(int index, std::string name, FILE *f, bool owns, ZstdMode zstd)
        : index_(index), name_(std::move(name)), f_(f), owns_(owns), mode_(zstd),
          dec_([this](const TraceEvent &ev) { on_event(ev); }) {}

    ~Source() { close(); }

    bool fill_one(const Options &opt, std::string *err) {
        while (queue_.empty() && !eof_) {
            if (!read_chunk(err)) return false;
            apply_pending(opt);
        }
        return true;
    }

    bool empty() const { return queue_.empty(); }
    const OwnedEvent &front() const { return queue_.front(); }
    void pop() { queue_.pop_front(); }
    bool eof() const { return eof_; }
    const std::string &name() const { return name_; }

    void close() {
        if (dctx_) { ZSTD_freeDStream(dctx_); dctx_ = nullptr; }
        if (f_) {
            if (owns_) std::fclose(f_);
            f_ = nullptr;
        }
    }

private:
    bool detect(std::string *err) {
        if (detected_) return true;
        detected_ = true;
        unsigned char hdr[4];
        size_t n = std::fread(hdr, 1, sizeof hdr, f_);
        if (n) prefix_.insert(prefix_.end(), hdr, hdr + n);
        if (std::ferror(f_)) {
            if (err) *err = name_ + ": read: " + std::strerror(errno);
            return false;
        }
        bool magic = n >= 4 && hdr[0] == 0x28 && hdr[1] == 0xb5 && hdr[2] == 0x2f && hdr[3] == 0xfd;
        compressed_ = (mode_ == ZstdMode::Yes) || (mode_ == ZstdMode::Auto && magic);
        if (compressed_) {
            dctx_ = ZSTD_createDStream();
            if (!dctx_) {
                if (err) *err = name_ + ": ZSTD_createDStream failed";
                return false;
            }
            size_t r = ZSTD_initDStream(dctx_);
            if (ZSTD_isError(r)) {
                if (err) *err = name_ + ": zstd: " + ZSTD_getErrorName(r);
                return false;
            }
            zstd_in_.resize(ZSTD_DStreamInSize());
            zstd_out_.resize(ZSTD_DStreamOutSize());
        }
        return true;
    }

    bool read_raw(void *buf, size_t cap, size_t *n, std::string *err) {
        if (!prefix_.empty()) {
            *n = std::min(cap, prefix_.size());
            std::memcpy(buf, prefix_.data(), *n);
            prefix_.erase(prefix_.begin(), prefix_.begin() + (ptrdiff_t)*n);
            return true;
        }
        *n = std::fread(buf, 1, cap, f_);
        if (*n == 0 && std::ferror(f_)) {
            if (err) *err = name_ + ": read: " + std::strerror(errno);
            return false;
        }
        return true;
    }

    bool read_chunk(std::string *err) {
        if (!detect(err)) return false;
        if (!compressed_) {
            char buf[64 * 1024];
            size_t n = 0;
            if (!read_raw(buf, sizeof buf, &n, err)) return false;
            if (n == 0) { eof_ = true; return true; }
            if (!dec_.feed(buf, n)) {
                if (err) *err = name_ + ": wire decode error";
                return false;
            }
            return true;
        }

        size_t n = 0;
        if (!read_raw(zstd_in_.data(), zstd_in_.size(), &n, err)) return false;
        if (n == 0) { eof_ = true; return true; }
        ZSTD_inBuffer in{zstd_in_.data(), n, 0};
        while (in.pos < in.size) {
            ZSTD_outBuffer out{zstd_out_.data(), zstd_out_.size(), 0};
            size_t r = ZSTD_decompressStream(dctx_, &out, &in);
            if (ZSTD_isError(r)) {
                if (err) *err = name_ + ": zstd: " + ZSTD_getErrorName(r);
                return false;
            }
            if (out.pos > 0 && !dec_.feed(zstd_out_.data(), out.pos)) {
                if (err) *err = name_ + ": wire decode error";
                return false;
            }
            if (!queue_.empty()) break;
        }
        return true;
    }

    void on_event(const TraceEvent &ev) {
        OwnedEvent out;
        out.source = index_;
        out.type = ev.type;
        out.ts_ns = ev.ts_ns;
        out.pid = ev.pid; out.tgid = ev.tgid; out.ppid = ev.ppid;
        out.nspid = ev.nspid; out.nstgid = ev.nstgid;
        out.stream_id = ev.stream_id;
        out.n_extras = ev.n_extras;
        for (unsigned i = 0; i < ev.n_extras && i < 7; i++) out.extras[i] = ev.extras[i];
        out.blob.assign((const uint8_t *)ev.blob, (const uint8_t *)ev.blob + ev.blen);
        pending_.push_back(std::move(out));
    }

    void apply_pending(const Options &opt) {
        for (OwnedEvent &ev : pending_) {
            if (opt.have_include_types && (ev.type < 0 || ev.type >= 16 || !opt.include_types[ev.type]))
                continue;
            if (ev.type >= 0 && ev.type < 16 && opt.drop_types[ev.type])
                continue;
            if (!contains_int(opt.pids, ev.pid) || !contains_int(opt.tgids, ev.tgid))
                continue;
            if (opt.after_ns && ev.ts_ns < *opt.after_ns) continue;
            if (opt.before_ns && ev.ts_ns > *opt.before_ns) continue;
            ev.ts_ns = (uint64_t)((int64_t)ev.ts_ns + opt.time_offset_signed_ns);
            queue_.push_back(std::move(ev));
        }
        pending_.clear();
    }

    int index_ = 0;
    std::string name_;
    FILE *f_ = nullptr;
    bool owns_ = false;
    ZstdMode mode_ = ZstdMode::Auto;
    bool detected_ = false;
    bool compressed_ = false;
    bool eof_ = false;
    std::vector<unsigned char> prefix_;
    ZSTD_DStream *dctx_ = nullptr;
    std::vector<char> zstd_in_;
    std::vector<char> zstd_out_;
    TraceDecoder dec_;
    std::vector<OwnedEvent> pending_;
    std::deque<OwnedEvent> queue_;
};

bool parse_args(int argc, char **argv, Options &opt) {
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if ((!std::strcmp(a, "-o") || !std::strcmp(a, "--output")) && i + 1 < argc) {
            opt.out_path = argv[++i];
        } else if (!std::strcmp(a, "--zstd")) {
            opt.out_zstd = true;
        } else if (!std::strcmp(a, "--no-zstd")) {
            opt.out_zstd = false;
        } else if (!std::strncmp(a, "--input-zstd=", 13)) {
            const char *v = a + 13;
            if (!std::strcmp(v, "auto")) opt.input_zstd = ZstdMode::Auto;
            else if (!std::strcmp(v, "yes")) opt.input_zstd = ZstdMode::Yes;
            else if (!std::strcmp(v, "no")) opt.input_zstd = ZstdMode::No;
            else return false;
        } else if ((!std::strcmp(a, "--select") || !std::strcmp(a, "--type")) && i + 1 < argc) {
            if (!parse_type_list(argv[++i], opt.include_types)) return false;
            opt.have_include_types = true;
        } else if (!std::strcmp(a, "--drop") && i + 1 < argc) {
            if (!parse_type_list(argv[++i], opt.drop_types)) return false;
        } else if (!std::strcmp(a, "--pid") && i + 1 < argc) {
            if (!parse_int_list(argv[++i], opt.pids)) return false;
        } else if (!std::strcmp(a, "--tgid") && i + 1 < argc) {
            if (!parse_int_list(argv[++i], opt.tgids)) return false;
        } else if (!std::strcmp(a, "--after-ns") && i + 1 < argc) {
            auto v = parse_u64(argv[++i]); if (!v) return false; opt.after_ns = (uint64_t)*v;
        } else if (!std::strcmp(a, "--before-ns") && i + 1 < argc) {
            auto v = parse_u64(argv[++i]); if (!v) return false; opt.before_ns = (uint64_t)*v;
        } else if (!std::strcmp(a, "--time-offset-ns") && i + 1 < argc) {
            auto v = parse_i64(argv[++i]); if (!v) return false; opt.time_offset_signed_ns = (int64_t)*v;
        } else if (!std::strcmp(a, "--set-stream-id") && i + 1 < argc) {
            auto v = parse_u64(argv[++i]); if (!v || *v > UINT32_MAX) return false;
            opt.set_stream_id = (uint32_t)*v;
        } else if ((!std::strcmp(a, "--tracer") || !std::strcmp(a, "--processor")) && i + 1 < argc) {
            opt.tracer = argv[++i];
        } else if (!std::strcmp(a, "--no-env")) {
            opt.no_env = true;
        } else if (!std::strcmp(a, "--") && i + 1 < argc) {
            opt.cmd = argv + i + 1;
            break;
        } else if (a[0] == '-' && std::strcmp(a, "-") != 0) {
            return false;
        } else {
            opt.files.emplace_back(a);
        }
    }
    if (opt.cmd && !opt.tracer) return false;
    if (opt.tracer && !opt.cmd) return false;
    return true;
}

std::unique_ptr<Source> open_file_source(int idx, const std::string &path,
                                         ZstdMode zstd, std::string *err) {
    if (path == "-")
        return std::make_unique<Source>(idx, "stdin", stdin, false, zstd);
    FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) {
        if (err) *err = path + ": " + std::strerror(errno);
        return nullptr;
    }
    return std::make_unique<Source>(idx, path, f, true, zstd);
}

std::unique_ptr<Source> open_tracer_source(int idx, const Options &opt,
                                           pid_t *child, std::string *err) {
    int pipefd[2];
    if (::pipe(pipefd) < 0) {
        if (err) *err = std::string("pipe: ") + std::strerror(errno);
        return nullptr;
    }
    pid_t pid = ::fork();
    if (pid < 0) {
        if (err) *err = std::string("fork: ") + std::strerror(errno);
        ::close(pipefd[0]); ::close(pipefd[1]);
        return nullptr;
    }
    if (pid == 0) {
        ::close(pipefd[0]);
        if (::dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
        ::close(pipefd[1]);
        size_t cmdc = 0; while (opt.cmd[cmdc]) cmdc++;
        size_t argc = 1 + (opt.no_env ? 1 : 0) + 1 + cmdc + 1;
        char **av = (char **)std::calloc(argc, sizeof(char *));
        size_t ai = 0;
        av[ai++] = (char *)opt.tracer;
        if (opt.no_env) av[ai++] = (char *)"--no-env";
        av[ai++] = (char *)"--";
        for (size_t i = 0; i < cmdc; i++) av[ai++] = opt.cmd[i];
        av[ai] = nullptr;
        if (std::strchr(opt.tracer, '/')) ::execv(opt.tracer, av);
        else ::execvp(opt.tracer, av);
        std::perror("traceproc: exec tracer");
        _exit(127);
    }
    ::close(pipefd[1]);
    FILE *f = ::fdopen(pipefd[0], "rb");
    if (!f) {
        if (err) *err = std::string("fdopen: ") + std::strerror(errno);
        ::close(pipefd[0]);
        return nullptr;
    }
    *child = pid;
    return std::make_unique<Source>(idx, "tracer", f, true, ZstdMode::Auto);
}

int run(const Options &opt) {
    std::string err;
    std::vector<std::unique_ptr<Source>> sources;
    int idx = 0;
    for (const std::string &p : opt.files) {
        auto s = open_file_source(idx++, p, opt.input_zstd, &err);
        if (!s) { std::fprintf(stderr, "traceproc: %s\n", err.c_str()); return 1; }
        sources.push_back(std::move(s));
    }
    pid_t child = 0;
    if (opt.tracer) {
        auto s = open_tracer_source(idx++, opt, &child, &err);
        if (!s) { std::fprintf(stderr, "traceproc: %s\n", err.c_str()); return 1; }
        sources.push_back(std::move(s));
    }

    Output out(opt);
    if (!out.open(&err)) {
        std::fprintf(stderr, "traceproc: %s\n", err.c_str());
        return 1;
    }

    bool ok = true;
    for (;;) {
        bool any_live = false;
        for (auto &s : sources) {
            if (!s->eof()) any_live = true;
            if (s->empty() && !s->eof() && !s->fill_one(opt, &err)) {
                std::fprintf(stderr, "traceproc: %s\n", err.c_str());
                ok = false;
                goto done;
            }
        }
        int best = -1;
        for (size_t i = 0; i < sources.size(); i++) {
            if (sources[i]->empty()) continue;
            if (best < 0 || sources[i]->front().ts_ns < sources[(size_t)best]->front().ts_ns)
                best = (int)i;
        }
        if (best < 0) {
            if (!any_live) break;
            continue;
        }
        if (!out.write_event(sources[(size_t)best]->front(), &err)) {
            std::fprintf(stderr, "traceproc: %s\n", err.c_str());
            ok = false;
            break;
        }
        sources[(size_t)best]->pop();
    }

done:
    if (!out.close(&err)) {
        std::fprintf(stderr, "traceproc: %s\n", err.c_str());
        ok = false;
    }
    for (auto &s : sources) s->close();
    if (child > 0) {
        int st = 0;
        ::waitpid(child, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) ok = false;
    }
    return ok ? 0 : 1;
}

} // namespace

int main(int argc, char **argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        std::fputs(USAGE, stderr);
        return 2;
    }
    return run(opt);
}
