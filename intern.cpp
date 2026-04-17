/* intern.cpp — Implementation of the unified interning library.
 *
 * Internal design
 * ───────────────
 * Arena:  flat vector<char> — all entry payloads live here.
 * Entry:  small metadata struct per interned blob.
 * Dedup:  open-addressing hash table mapping hash → entry chain.
 * Compression:  blobs ≥ COMPRESS_THRESHOLD bytes are ZSTD-compressed;
 *   smaller blobs are stored inline (raw).
 * Thread safety:  single mutex guards put(); reads are lock-free
 *   once the entry exists (entries are append-only, never modified).
 */

#include "intern.h"

#include <cstring>
#include <cstdio>
#include <cassert>
#include <mutex>
#include <ostream>
#include <unistd.h>

#include <fnmatch.h>
#include <zstd.h>

/* ── FNV-1a 64-bit hash ──────────────────────────────────────────── */

static uint64_t fnv1a(const void *data, size_t len) {
    auto *p = static_cast<const uint8_t *>(data);
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

/* ── Constants ────────────────────────────────────────────────────── */

/* Blobs smaller than this are stored inline (fast O(1) view()).
   Larger blobs are ZSTD-compressed to save memory. */
static constexpr size_t COMPRESS_THRESHOLD = 128;

/* Fast compression — level 1 prioritizes speed over ratio, which
   matters during live ingestion where latency must stay low. */
static constexpr int    ZSTD_LEVEL         = 1;

/* ── Entry descriptor ─────────────────────────────────────────────── */

struct Entry {
    uint32_t offset;       /* start in arena            */
    uint32_t stored_size;  /* bytes in arena (may be compressed) */
    uint32_t orig_size;    /* original byte count       */
    uint64_t hash;         /* FNV-1a of original data   */
    bool     compressed;   /* stored_size is ZSTD frame */
};

/* ── Impl ─────────────────────────────────────────────────────────── */

struct Intern::Impl {
    /* Arena — all payloads (inline or compressed) live here. */
    std::vector<char> arena;

    /* Entries indexed by IID (slot 0 unused = "empty"). */
    std::vector<Entry> entries;

    /* Open-addressing hash table for dedup.
       Each slot holds 0 (empty) or an IID (1-based). */
    std::vector<IID> htab;
    size_t htab_count = 0;

    /* ZSTD contexts (reused for speed). */
    ZSTD_CCtx *cctx = nullptr;
    ZSTD_DCtx *dctx = nullptr;

    std::mutex mu;

    Impl() {
        /* Slot 0 = empty sentinel. */
        entries.push_back(Entry{0, 0, 0, 0, false});
        htab.resize(256, 0);
        cctx = ZSTD_createCCtx();
        dctx = ZSTD_createDCtx();
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, ZSTD_LEVEL);
    }

    ~Impl() {
        if (cctx) ZSTD_freeCCtx(cctx);
        if (dctx) ZSTD_freeDCtx(dctx);
    }

    /* ── helpers ──────────────────────────────────────────────── */

    const char *raw(IID id) const { return arena.data() + entries[id].offset; }

    /* Decompress entry id into buf.  Caller must ensure buf has
       entries[id].orig_size bytes. */
    void decompress_into(IID id, char *buf) const {
        auto &e = entries[id];
        if (!e.compressed) {
            std::memcpy(buf, raw(id), e.orig_size);
            return;
        }
        size_t rc = ZSTD_decompressDCtx(
            dctx, buf, e.orig_size, raw(id), e.stored_size);
        if (ZSTD_isError(rc)) {
            /* Should never happen — data was compressed by us. */
            std::memset(buf, 0, e.orig_size);
        }
    }

    /* Full-content comparison between entry and raw bytes. */
    bool content_eq(IID id, const void *data, size_t len) const {
        auto &e = entries[id];
        if (e.orig_size != static_cast<uint32_t>(len)) return false;
        if (!e.compressed)
            return std::memcmp(raw(id), data, len) == 0;
        /* Compressed: decompress and compare. */
        std::string tmp(e.orig_size, '\0');
        decompress_into(id, tmp.data());
        return std::memcmp(tmp.data(), data, len) == 0;
    }

    /* ── hash table ──────────────────────────────────────────── */

    void htab_grow() {
        size_t new_cap = htab.size() * 2;
        std::vector<IID> new_tab(new_cap, 0);
        for (IID id : htab) {
            if (!id) continue;
            uint64_t h = entries[id].hash;
            size_t slot = static_cast<size_t>(h) & (new_cap - 1);
            while (new_tab[slot]) slot = (slot + 1) & (new_cap - 1);
            new_tab[slot] = id;
        }
        htab = std::move(new_tab);
    }

    /* Try to find an existing entry that matches (hash, data, len).
       Returns the IID or 0 if not found. */
    IID htab_find(uint64_t hash, const void *data, size_t len) const {
        size_t mask = htab.size() - 1;
        size_t slot = static_cast<size_t>(hash) & mask;
        for (;;) {
            IID id = htab[slot];
            if (!id) return 0;
            auto &e = entries[id];
            if (e.hash == hash && e.orig_size == static_cast<uint32_t>(len)) {
                if (content_eq(id, data, len)) return id;
            }
            slot = (slot + 1) & mask;
        }
    }

    void htab_insert(IID id) {
        if (htab_count * 4 >= htab.size() * 3) htab_grow(); /* 75% load */
        size_t mask = htab.size() - 1;
        size_t slot = static_cast<size_t>(entries[id].hash) & mask;
        while (htab[slot]) slot = (slot + 1) & mask;
        htab[slot] = id;
        htab_count++;
    }

    /* ── put core ────────────────────────────────────────────── */

    IID put_locked(const void *data, size_t len) {
        if (len == 0) return 0;
        uint64_t h = fnv1a(data, len);
        IID existing = htab_find(h, data, len);
        if (existing) return existing;

        /* New entry. */
        IID id = static_cast<IID>(entries.size());
        Entry e;
        e.hash = h;
        e.orig_size = static_cast<uint32_t>(len);
        e.offset = static_cast<uint32_t>(arena.size());

        if (len < COMPRESS_THRESHOLD) {
            /* Store inline. */
            arena.insert(arena.end(),
                         static_cast<const char *>(data),
                         static_cast<const char *>(data) + len);
            e.stored_size = static_cast<uint32_t>(len);
            e.compressed = false;
        } else {
            /* Try ZSTD compression. */
            size_t bound = ZSTD_compressBound(len);
            size_t old_sz = arena.size();
            arena.resize(old_sz + bound);
            size_t csz = ZSTD_compressCCtx(
                cctx, arena.data() + old_sz, bound,
                data, len, ZSTD_LEVEL);
            if (!ZSTD_isError(csz) && csz < len) {
                /* Compression helped. */
                arena.resize(old_sz + csz);
                e.stored_size = static_cast<uint32_t>(csz);
                e.compressed = true;
            } else {
                /* Store raw. */
                arena.resize(old_sz);
                arena.insert(arena.end(),
                             static_cast<const char *>(data),
                             static_cast<const char *>(data) + len);
                e.stored_size = static_cast<uint32_t>(len);
                e.compressed = false;
            }
        }

        entries.push_back(e);
        htab_insert(id);
        return id;
    }
};

/* ── Public API ───────────────────────────────────────────────────── */

Intern::Intern()  : m_(new Impl) {}
Intern::~Intern() { delete m_; }

IID Intern::put(std::string_view data) {
    if (data.empty()) return 0;
    std::lock_guard<std::mutex> lk(m_->mu);
    return m_->put_locked(data.data(), data.size());
}

IID Intern::put(const void *data, size_t len) {
    if (!data || !len) return 0;
    std::lock_guard<std::mutex> lk(m_->mu);
    return m_->put_locked(data, len);
}

IID Intern::put(const std::vector<uint8_t> &data) {
    if (data.empty()) return 0;
    std::lock_guard<std::mutex> lk(m_->mu);
    return m_->put_locked(data.data(), data.size());
}

IID Intern::put_argv(const std::vector<std::string> &argv) {
    if (argv.empty()) return 0;
    std::string flat;
    for (size_t i = 0; i < argv.size(); i++) {
        if (i) flat += '\0';
        flat += argv[i];
    }
    std::lock_guard<std::mutex> lk(m_->mu);
    return m_->put_locked(flat.data(), flat.size());
}

/* ── Retrieve ─────────────────────────────────────────────────────── */

std::string Intern::str(IID id) const {
    if (!id || id >= m_->entries.size()) return {};
    auto &e = m_->entries[id];
    if (!e.compressed)
        return std::string(m_->raw(id), e.orig_size);
    std::string out(e.orig_size, '\0');
    m_->decompress_into(id, out.data());
    return out;
}

std::vector<uint8_t> Intern::bytes(IID id) const {
    if (!id || id >= m_->entries.size()) return {};
    auto &e = m_->entries[id];
    std::vector<uint8_t> out(e.orig_size);
    if (!e.compressed)
        std::memcpy(out.data(), m_->raw(id), e.orig_size);
    else
        m_->decompress_into(id, reinterpret_cast<char *>(out.data()));
    return out;
}

std::string_view Intern::view(IID id) const {
    if (!id || id >= m_->entries.size()) return {};
    auto &e = m_->entries[id];
    if (e.compressed) return {};
    return {m_->raw(id), e.orig_size};
}

size_t Intern::size(IID id) const {
    if (!id || id >= m_->entries.size()) return 0;
    return m_->entries[id].orig_size;
}

void Intern::write(IID id, int fd) const {
    if (!id || id >= m_->entries.size()) return;
    auto &e = m_->entries[id];
    if (!e.compressed) {
        ::write(fd, m_->raw(id), e.orig_size);
    } else {
        std::string tmp = str(id);
        ::write(fd, tmp.data(), tmp.size());
    }
}

void Intern::write(IID id, std::ostream &os) const {
    if (!id || id >= m_->entries.size()) return;
    auto &e = m_->entries[id];
    if (!e.compressed) {
        os.write(m_->raw(id), e.orig_size);
    } else {
        std::string tmp = str(id);
        os.write(tmp.data(), tmp.size());
    }
}

std::vector<std::string> Intern::get_argv(IID id) const {
    std::vector<std::string> out;
    if (!id || id >= m_->entries.size()) return out;
    std::string flat = str(id);
    if (flat.empty()) return out;
    size_t pos = 0;
    while (pos < flat.size()) {
        size_t next = flat.find('\0', pos);
        if (next == std::string::npos) {
            out.push_back(flat.substr(pos));
            break;
        }
        out.push_back(flat.substr(pos, next - pos));
        pos = next + 1;
    }
    return out;
}

/* ── Compare ──────────────────────────────────────────────────────── */

bool Intern::eq(IID a, IID b) const {
    if (a == b) return true;
    if (!a || !b) return false;
    if (a >= m_->entries.size() || b >= m_->entries.size()) return false;
    auto &ea = m_->entries[a];
    auto &eb = m_->entries[b];
    if (ea.hash != eb.hash || ea.orig_size != eb.orig_size) return false;
    /* Same hash+size with our dedup means they must be equal
       (they would have been deduped on insert).  But be safe: */
    return true;
}

bool Intern::eq(IID a, std::string_view data) const {
    if (!a && data.empty()) return true;
    if (!a || a >= m_->entries.size()) return data.empty();
    return m_->content_eq(a, data.data(), data.size());
}

bool Intern::eq(IID a, const void *data, size_t len) const {
    if (!a && !len) return true;
    if (!a || a >= m_->entries.size()) return len == 0;
    return m_->content_eq(a, data, len);
}

bool Intern::contains(IID a, std::string_view needle) const {
    if (needle.empty()) return true;
    if (!a || a >= m_->entries.size()) return false;
    auto &e = m_->entries[a];
    if (e.orig_size < needle.size()) return false;
    if (!e.compressed) {
        std::string_view sv(m_->raw(a), e.orig_size);
        return sv.find(needle) != std::string_view::npos;
    }
    std::string tmp = str(a);
    return tmp.find(needle) != std::string::npos;
}

/* ── Pattern matching ─────────────────────────────────────────────── */

bool Intern::glob(IID id, const char *pattern) const {
    if (!pattern) return false;
    if (!id || id >= m_->entries.size()) return false;
    auto &e = m_->entries[id];
    /* fnmatch needs a null-terminated string. */
    if (!e.compressed) {
        /* Make a temp null-terminated copy (view may not be terminated). */
        std::string tmp(m_->raw(id), e.orig_size);
        return fnmatch(pattern, tmp.c_str(), FNM_PATHNAME) == 0;
    }
    std::string tmp = str(id);
    return fnmatch(pattern, tmp.c_str(), FNM_PATHNAME) == 0;
}

/* ── Utility ──────────────────────────────────────────────────────── */

bool Intern::empty(IID id) const {
    return !id || id >= m_->entries.size();
}

void Intern::clear() {
    std::lock_guard<std::mutex> lk(m_->mu);
    m_->arena.clear();
    m_->entries.clear();
    m_->entries.push_back(Entry{0, 0, 0, 0, false}); /* slot 0 */
    std::fill(m_->htab.begin(), m_->htab.end(), 0u);
    m_->htab_count = 0;
}

size_t Intern::count() const {
    return m_->entries.size() - 1; /* minus the sentinel */
}

size_t Intern::memory_bytes() const {
    return m_->arena.capacity()
         + m_->entries.capacity() * sizeof(Entry)
         + m_->htab.capacity() * sizeof(IID);
}
