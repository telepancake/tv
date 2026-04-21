/* wire_in.cpp — implements wire_in.h. See header for design notes. */

#include "wire_in.h"

#include <cstring>
#include <vector>

extern "C" {
#include "wire/wire.h"
}

/* ── per-atom length probe (without consuming) ────────────────────── */

/* yeet's long-form length prefix can be up to 7 bytes (0xF8..0xFE);
 * 0xFF is reserved. */
static constexpr uint8_t YEET_MAX_LENSZ = 7;

static size_t yeet_atom_len(const uint8_t *p, size_t n) {
    if (n == 0) return 0;
    uint8_t b = p[0];
    if (b < 0xC0u) return 1;
    if (b < 0xF8u) return 1u + (size_t)(b - 0xC0u);
    uint8_t lensz = (uint8_t)(b - 0xF8u);
    if (lensz > YEET_MAX_LENSZ) return (size_t)-1;
    if (n < 1u + (size_t)lensz) return 0;
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

    explicit Impl(Sink s) : sink(std::move(s)) {}

    /* Try to consume one whole event from `buf` starting at offset `pos`.
     * Returns the number of bytes consumed, 0 if not enough data, or
     * (size_t)-1 on hard error. */
    size_t consume_one(size_t pos) {
        if (error) return (size_t)-1;
        const uint8_t *p = buf.data() + pos;
        size_t n = buf.size() - pos;
        if (n == 0) return 0;

        /* version atom must be first */
        if (!got_version) {
            size_t alen = yeet_atom_len(p, n);
            if (alen == 0) return 0;
            if (alen == (size_t)-1) { error = true; return (size_t)-1; }
            if (alen > n) return 0;
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

        WireEvent ev{};
        ev.type   = type;
        ev.ts_ns  = ts_ns;
        ev.pid    = pid;
        ev.tgid   = tgid;
        ev.ppid   = ppid;
        ev.nspid  = nspid;
        ev.nstgid = nstgid;
        ev.extras   = extras;
        ev.n_extras = n_extras;
        ev.blob   = (const char *)xp;
        ev.blen   = (size_t)(xend - xp);
        if (sink) sink(ev);
        return alen;
    }
};

WireDecoder::WireDecoder(Sink sink) : impl_(std::make_unique<Impl>(std::move(sink))) {}
WireDecoder::~WireDecoder() = default;

bool WireDecoder::feed(const void *data, size_t n) {
    if (n == 0) return !impl_->error;
    impl_->any_input = true;
    impl_->buf.insert(impl_->buf.end(),
                      (const uint8_t *)data, (const uint8_t *)data + n);
    /* Walk the buffer with a cursor; erase consumed bytes only once at
     * the end. This keeps feed() linear in the number of bytes added,
     * even when called byte-at-a-time across many events. */
    size_t pos = 0;
    while (pos < impl_->buf.size()) {
        if (impl_->error) return false;
        size_t k = impl_->consume_one(pos);
        if (k == (size_t)-1) return false;
        if (k == 0) break;
        pos += k;
    }
    if (pos > 0) {
        impl_->buf.erase(impl_->buf.begin(),
                         impl_->buf.begin() + (ptrdiff_t)pos);
    }
    return !impl_->error;
}

bool WireDecoder::started() const {
    return impl_->any_input;
}
