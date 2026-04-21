/* wire_in.cpp — implements wire_in.h. See header for design notes. */

#include "wire_in.h"

#include <cstring>
#include <vector>

extern "C" {
#include "wire/wire.h"
}

/* ── byte sniff ───────────────────────────────────────────────────── */

bool wire_looks_like_wire(unsigned char first_byte) {
    /* JSON traces start with '{' (0x7B). The wire stream's first atom
     * is yeet_u64(WIRE_VERSION); for any WIRE_VERSION in 1..0xBF it
     * is a 1-byte self-atom equal to the version byte. We treat any
     * byte that isn't '{' or whitespace as wire. */
    if (first_byte == '{') return false;
    if (first_byte == ' ' || first_byte == '\t' ||
        first_byte == '\n' || first_byte == '\r') return false;
    return true;
}

/* ── per-atom length probe (without consuming) ────────────────────── */

/* Given the first up to 8 bytes of a yeet atom, returns its total
 * encoded length in bytes, or 0 if more bytes are needed to determine
 * length, or (size_t)-1 on a malformed first byte. */
static size_t yeet_atom_len(const uint8_t *p, size_t n) {
    if (n == 0) return 0;
    uint8_t b = p[0];
    if (b < 0xC0u) return 1;
    if (b < 0xF8u) return 1u + (size_t)(b - 0xC0u);
    uint8_t lensz = (uint8_t)(b - 0xF8u);
    if (lensz < 1 || lensz > 7) return (size_t)-1;
    if (n < 1u + lensz) return 0;
    uint64_t len = 0;
    for (uint8_t i = 0; i < lensz; i++) {
        len |= (uint64_t)p[1 + i] << (8u * i);
    }
    return 1u + (size_t)lensz + (size_t)len;
}

/* ── implementation ───────────────────────────────────────────────── */

struct WireDecoder::Impl {
    Sink sink;
    std::vector<uint8_t> buf;       /* unconsumed bytes carried across feeds */
    ev_state state{};               /* delta-decoder state */
    bool got_version = false;
    bool error = false;
    bool any_input = false;

    /* Coalesce buffer for EV_EXEC awaiting its EV_ARGV partner. */
    bool        pending_exec = false;
    WireRawEvent pending;
    std::string pending_exe_storage;
    /* (no separate path/data storage needed: the next feed may overwrite
     * `buf`, so we must copy any blob the pending event refers to.) */

    explicit Impl(Sink s) : sink(std::move(s)) {}

    void emit(const WireRawEvent &ev) { if (sink) sink(ev); }

    /* If a previous EXEC is buffered, deliver it (without argv) before
     * the new event. */
    void flush_pending_exec() {
        if (!pending_exec) return;
        pending_exec = false;
        emit(pending);
        pending = WireRawEvent{};
        pending_exe_storage.clear();
    }

    /* Try to consume one whole event from `buf`. Returns the number of
     * bytes consumed, or 0 if not enough data, or (size_t)-1 on error. */
    size_t consume_one() {
        if (error) return (size_t)-1;
        const uint8_t *p = buf.data();
        size_t n = buf.size();
        if (n == 0) return 0;

        /* version atom must be first */
        if (!got_version) {
            size_t alen = yeet_atom_len(p, n);
            if (alen == 0) return 0;
            if (alen == (size_t)-1 || alen > n) {
                if (alen == (size_t)-1) { error = true; return (size_t)-1; }
                return 0;
            }
            const uint8_t *vp = p;
            uint64_t v = 0;
            if (yeet_get_u64(&vp, p + alen, &v) < 0) { error = true; return (size_t)-1; }
            if (v != WIRE_VERSION) { error = true; return (size_t)-1; }
            got_version = true;
            return alen;
        }

        /* outer atom = hdr || blob */
        size_t alen = yeet_atom_len(p, n);
        if (alen == 0) return 0;
        if (alen == (size_t)-1) { error = true; return (size_t)-1; }
        if (alen > n) return 0;

        const uint8_t *ap = p;
        const uint8_t *aend = p + alen;
        const uint8_t *payload = nullptr;
        uint64_t plen = 0;
        if (yeet_get(&ap, aend, &payload, &plen) < 0) { error = true; return (size_t)-1; }

        /* decode 7 base scalars */
        int32_t type, pid, tgid, ppid, nspid, nstgid;
        uint64_t ts_ns;
        int hlen = ev_decode_header(&state, payload, plen,
                                    &type, &ts_ns,
                                    &pid, &tgid, &ppid, &nspid, &nstgid);
        if (hlen < 0) { error = true; return (size_t)-1; }

        const uint8_t *xp  = payload + hlen;
        const uint8_t *xend = payload + plen;

        /* type-specific extras */
        int64_t extras[7] = {0};
        unsigned n_extras = 0;
        switch (type) {
            case EV_EXIT: n_extras = 4; break;
            case EV_OPEN: n_extras = 7; break;
            default:      n_extras = 0; break;
        }
        for (unsigned i = 0; i < n_extras; i++) {
            if (yeet_get_i64(&xp, xend, &extras[i]) < 0) { error = true; return (size_t)-1; }
        }

        const char *blob = (const char *)xp;
        size_t blen = (size_t)(xend - xp);

        dispatch(type, ts_ns, pid, tgid, ppid, extras, blob, blen);
        return alen;
    }

    void dispatch(int32_t type, uint64_t ts_ns,
                  int32_t pid, int32_t tgid, int32_t ppid,
                  const int64_t *extras,
                  const char *blob, size_t blen) {
        WireRawEvent ev{};
        ev.ts_ns = ts_ns;
        ev.pid   = pid;
        ev.tgid  = tgid;
        ev.ppid  = ppid;

        switch (type) {
        case EV_EXEC: {
            /* Buffer EXEC; coalesce with the next EV_ARGV if it shares
             * the same identity (ts/pid/tgid). */
            flush_pending_exec();
            ev.kind = WIRE_EV_EXEC;
            pending_exe_storage.assign(blob, blen);
            ev.exe = pending_exe_storage.data();
            ev.exe_len = pending_exe_storage.size();
            pending = ev;
            pending_exec = true;
            return;
        }
        case EV_ARGV: {
            if (pending_exec &&
                pending.ts_ns == ts_ns &&
                pending.pid == pid &&
                pending.tgid == tgid) {
                pending.argv = blob;
                pending.argv_len = blen;
                emit(pending);
                pending_exec = false;
                pending = WireRawEvent{};
                pending_exe_storage.clear();
            }
            /* Stray ARGV with no matching EXEC: ignore. */
            return;
        }
        case EV_ENV:
        case EV_AUXV:
            /* tv ignores these; flushing pending exec isn't needed
             * because they share identity with the EXEC and may legally
             * appear between EXEC and ARGV (producers emit EXEC, ARGV,
             * ENV, AUXV in that order — but be defensive). */
            return;
        case EV_EXIT: {
            flush_pending_exec();
            ev.kind = WIRE_EV_EXIT;
            ev.exit_status_kind = (int32_t)extras[0];
            ev.exit_code_or_sig = (int32_t)extras[1];
            ev.exit_core_dumped = extras[2] != 0;
            ev.exit_raw         = (int32_t)extras[3];
            emit(ev);
            return;
        }
        case EV_OPEN: {
            flush_pending_exec();
            ev.kind = WIRE_EV_OPEN;
            ev.open_flags     = (int32_t)extras[0];
            ev.open_fd        = (int32_t)extras[1];
            ev.open_ino       = (uint64_t)extras[2];
            ev.open_dev_major = (uint32_t)extras[3];
            ev.open_dev_minor = (uint32_t)extras[4];
            ev.open_err       = (int32_t)extras[5];
            ev.open_inherited = extras[6] != 0;
            ev.path = blob;
            ev.path_len = blen;
            emit(ev);
            return;
        }
        case EV_CWD: {
            flush_pending_exec();
            ev.kind = WIRE_EV_CWD;
            ev.path = blob;
            ev.path_len = blen;
            emit(ev);
            return;
        }
        case EV_STDOUT: {
            flush_pending_exec();
            ev.kind = WIRE_EV_STDOUT;
            ev.data = blob;
            ev.data_len = blen;
            emit(ev);
            return;
        }
        case EV_STDERR: {
            flush_pending_exec();
            ev.kind = WIRE_EV_STDERR;
            ev.data = blob;
            ev.data_len = blen;
            emit(ev);
            return;
        }
        default:
            /* Unknown event class within this WIRE_VERSION — refuse
             * silently; format drift will be loud at the producer. */
            return;
        }
    }
};

WireDecoder::WireDecoder(Sink sink) : impl_(std::make_unique<Impl>(std::move(sink))) {}
WireDecoder::~WireDecoder() = default;

bool WireDecoder::feed(const void *data, size_t n) {
    if (n == 0) return !impl_->error;
    impl_->any_input = true;
    impl_->buf.insert(impl_->buf.end(),
                      (const uint8_t *)data, (const uint8_t *)data + n);
    size_t consumed = 0;
    while (true) {
        if (impl_->error) return false;
        if (consumed == impl_->buf.size()) break;
        /* shift the working window via a slice view rather than
         * memmove'ing on every iteration */
        std::vector<uint8_t> &b = impl_->buf;
        if (consumed > 0) {
            b.erase(b.begin(), b.begin() + (ptrdiff_t)consumed);
            consumed = 0;
        }
        size_t k = impl_->consume_one();
        if (k == (size_t)-1) return false;
        if (k == 0) break;          /* not enough data yet */
        consumed += k;
    }
    if (consumed > 0) impl_->buf.erase(impl_->buf.begin(),
                                       impl_->buf.begin() + (ptrdiff_t)consumed);
    return !impl_->error;
}

void WireDecoder::flush() {
    impl_->flush_pending_exec();
}

bool WireDecoder::started() const {
    return impl_->any_input;
}
