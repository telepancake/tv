/* intern.cpp — Implementation of the unified interning library.
 *
 * Internal design
 * ───────────────
 * The pool is split into NUM_SHARDS independent shards, each with its
 * own arena, entry table, hash table, ZSTD contexts, and mutex.
 * put() hashes the input, routes to a shard by the hash's upper bits,
 * and only locks that one shard — giving near-linear speedup when many
 * threads call put() concurrently (the common case during trace load).
 *
 * IID encoding:  upper SHARD_BITS select the shard,
 *                lower (32 − SHARD_BITS) are the local entry index.
 * IID 0 is always "empty / null" (shard 0, index 0 = sentinel).
 *
 * Reads (str/view/eq/…) are lock-free: entries and arenas are
 * append-only, never modified after creation.
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

static constexpr size_t COMPRESS_THRESHOLD = 128;
static constexpr int    ZSTD_LEVEL         = 1;

/* Sharding: upper 4 bits of IID = shard index (0–15),
   lower 28 bits = local entry index within that shard. */
static constexpr int      NUM_SHARDS  = 16;
static constexpr int      SHARD_BITS  = 4;
static constexpr int      SHARD_SHIFT = 32 - SHARD_BITS;   /* 28 */
static constexpr uint32_t LOCAL_MASK  = (1u << SHARD_SHIFT) - 1;

static int      shard_of(IID id)  { return static_cast<int>(id >> SHARD_SHIFT); }
static uint32_t local_of(IID id)  { return id & LOCAL_MASK; }
static IID      make_iid(int shard, uint32_t local) {
    return (static_cast<uint32_t>(shard) << SHARD_SHIFT) | local;
}
/* Use upper bits of the 64-bit hash for shard routing (independent of
   the lower bits used for hash-table probing within the shard). */
static int hash_to_shard(uint64_t h) {
    return static_cast<int>(h >> (64 - SHARD_BITS)) & (NUM_SHARDS - 1);
}

/* ── Entry descriptor ─────────────────────────────────────────────── */

struct Entry {
    uint32_t offset;       /* start in arena            */
    uint32_t stored_size;  /* bytes in arena (may be compressed) */
    uint32_t orig_size;    /* original byte count       */
    uint64_t hash;         /* FNV-1a of original data   */
    bool     compressed;   /* stored_size is ZSTD frame */
};

/* ── Shard — one independent slice of the pool ────────────────────── */

struct Shard {
    std::vector<char>  arena;
    std::vector<Entry> entries;   /* index 0 = unused sentinel */
    std::vector<IID>   htab;     /* open-addressing; 0 = empty slot */
    size_t             htab_count = 0;
    ZSTD_CCtx         *cctx = nullptr;
    ZSTD_DCtx         *dctx = nullptr;
    std::mutex         mu;

    /* ── helpers ──────────────────────────────────────────────── */

    const char *raw(uint32_t local) const {
        return arena.data() + entries[local].offset;
    }

    void decompress_into(uint32_t local, char *buf) const {
        auto &e = entries[local];
        if (!e.compressed) {
            std::memcpy(buf, raw(local), e.orig_size);
            return;
        }
        size_t rc = ZSTD_decompressDCtx(
            dctx, buf, e.orig_size, raw(local), e.stored_size);
        if (ZSTD_isError(rc))
            std::memset(buf, 0, e.orig_size);
    }

    bool content_eq(uint32_t local, const void *data, size_t len) const {
        auto &e = entries[local];
        if (e.orig_size != static_cast<uint32_t>(len)) return false;
        if (!e.compressed)
            return std::memcmp(raw(local), data, len) == 0;
        std::string tmp(e.orig_size, '\0');
        decompress_into(local, tmp.data());
        return std::memcmp(tmp.data(), data, len) == 0;
    }

    /* ── hash table ──────────────────────────────────────────── */

    void htab_grow() {
        size_t new_cap = htab.size() * 2;
        std::vector<IID> new_tab(new_cap, 0);
        for (IID id : htab) {
            if (!id) continue;
            uint32_t loc = local_of(id);
            uint64_t h = entries[loc].hash;
            size_t slot = static_cast<size_t>(h) & (new_cap - 1);
            while (new_tab[slot]) slot = (slot + 1) & (new_cap - 1);
            new_tab[slot] = id;
        }
        htab = std::move(new_tab);
    }

    IID htab_find(uint64_t hash, const void *data, size_t len) const {
        size_t mask = htab.size() - 1;
        size_t slot = static_cast<size_t>(hash) & mask;
        for (;;) {
            IID id = htab[slot];
            if (!id) return 0;
            uint32_t loc = local_of(id);
            auto &e = entries[loc];
            if (e.hash == hash && e.orig_size == static_cast<uint32_t>(len))
                if (content_eq(loc, data, len)) return id;
            slot = (slot + 1) & mask;
        }
    }

    void htab_insert(IID id) {
        if (htab_count * 4 >= htab.size() * 3) htab_grow();
        size_t mask = htab.size() - 1;
        uint32_t loc = local_of(id);
        size_t slot = static_cast<size_t>(entries[loc].hash) & mask;
        while (htab[slot]) slot = (slot + 1) & mask;
        htab[slot] = id;
        htab_count++;
    }

    /* ── put core (caller holds mu) ──────────────────────────── */

    IID put_locked(int shard_idx, const void *data, size_t len, uint64_t h) {
        IID existing = htab_find(h, data, len);
        if (existing) return existing;

        uint32_t local = static_cast<uint32_t>(entries.size());
        IID id = make_iid(shard_idx, local);
        Entry e;
        e.hash = h;
        e.orig_size = static_cast<uint32_t>(len);
        e.offset = static_cast<uint32_t>(arena.size());

        if (len < COMPRESS_THRESHOLD) {
            arena.insert(arena.end(),
                         static_cast<const char *>(data),
                         static_cast<const char *>(data) + len);
            e.stored_size = static_cast<uint32_t>(len);
            e.compressed = false;
        } else {
            size_t bound = ZSTD_compressBound(len);
            size_t old_sz = arena.size();
            arena.resize(old_sz + bound);
            size_t csz = ZSTD_compressCCtx(
                cctx, arena.data() + old_sz, bound,
                data, len, ZSTD_LEVEL);
            if (!ZSTD_isError(csz) && csz < len) {
                arena.resize(old_sz + csz);
                e.stored_size = static_cast<uint32_t>(csz);
                e.compressed = true;
            } else {
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

/* ── Impl ─────────────────────────────────────────────────────────── */

struct Intern::Impl {
    Shard shards[NUM_SHARDS];

    Impl() {
        for (int i = 0; i < NUM_SHARDS; i++) {
            auto &s = shards[i];
            s.entries.push_back(Entry{0, 0, 0, 0, false}); /* sentinel */
            s.htab.resize(64, 0);
            s.cctx = ZSTD_createCCtx();
            s.dctx = ZSTD_createDCtx();
            ZSTD_CCtx_setParameter(s.cctx, ZSTD_c_compressionLevel, ZSTD_LEVEL);
        }
    }
    ~Impl() {
        for (auto &s : shards) {
            if (s.cctx) ZSTD_freeCCtx(s.cctx);
            if (s.dctx) ZSTD_freeDCtx(s.dctx);
        }
    }

    /* Resolve IID → (shard, local) and get entry/raw. */
    const Entry &entry(IID id) const {
        return shards[shard_of(id)].entries[local_of(id)];
    }
    const char *raw(IID id) const {
        auto &sh = shards[shard_of(id)];
        return sh.raw(local_of(id));
    }
    void decompress_into(IID id, char *buf) const {
        shards[shard_of(id)].decompress_into(local_of(id), buf);
    }
    bool content_eq(IID id, const void *data, size_t len) const {
        return shards[shard_of(id)].content_eq(local_of(id), data, len);
    }
    bool valid(IID id) const {
        if (!id) return false;
        int s = shard_of(id);
        uint32_t loc = local_of(id);
        return s < NUM_SHARDS && loc < shards[s].entries.size();
    }
};

/* ── Public API ───────────────────────────────────────────────────── */

Intern::Intern()  : m_(new Impl) {}
Intern::~Intern() { delete m_; }

IID Intern::put(std::string_view data) {
    if (data.empty()) return 0;
    uint64_t h = fnv1a(data.data(), data.size());
    int s = hash_to_shard(h);
    auto &shard = m_->shards[s];
    std::lock_guard<std::mutex> lk(shard.mu);
    return shard.put_locked(s, data.data(), data.size(), h);
}

IID Intern::put(const void *data, size_t len) {
    if (!data || !len) return 0;
    uint64_t h = fnv1a(data, len);
    int s = hash_to_shard(h);
    auto &shard = m_->shards[s];
    std::lock_guard<std::mutex> lk(shard.mu);
    return shard.put_locked(s, data, len, h);
}

IID Intern::put(const std::vector<uint8_t> &data) {
    if (data.empty()) return 0;
    uint64_t h = fnv1a(data.data(), data.size());
    int s = hash_to_shard(h);
    auto &shard = m_->shards[s];
    std::lock_guard<std::mutex> lk(shard.mu);
    return shard.put_locked(s, data.data(), data.size(), h);
}

IID Intern::put_argv(const std::vector<std::string> &argv) {
    if (argv.empty()) return 0;
    std::string flat;
    for (size_t i = 0; i < argv.size(); i++) {
        if (i) flat += '\0';
        flat += argv[i];
    }
    uint64_t h = fnv1a(flat.data(), flat.size());
    int s = hash_to_shard(h);
    auto &shard = m_->shards[s];
    std::lock_guard<std::mutex> lk(shard.mu);
    return shard.put_locked(s, flat.data(), flat.size(), h);
}

IID Intern::find(std::string_view data) const {
    if (data.empty()) return 0;
    uint64_t h = fnv1a(data.data(), data.size());
    int s = hash_to_shard(h);
    auto &shard = m_->shards[s];
    /* Safe without lock when called after ingestion (append-only data). */
    return shard.htab_find(h, data.data(), data.size());
}

/* ── Retrieve ─────────────────────────────────────────────────────── */

std::string Intern::str(IID id) const {
    if (!m_->valid(id)) return {};
    auto &e = m_->entry(id);
    if (!e.compressed)
        return std::string(m_->raw(id), e.orig_size);
    std::string out(e.orig_size, '\0');
    m_->decompress_into(id, out.data());
    return out;
}

std::vector<uint8_t> Intern::bytes(IID id) const {
    if (!m_->valid(id)) return {};
    auto &e = m_->entry(id);
    std::vector<uint8_t> out(e.orig_size);
    if (!e.compressed)
        std::memcpy(out.data(), m_->raw(id), e.orig_size);
    else
        m_->decompress_into(id, reinterpret_cast<char *>(out.data()));
    return out;
}

std::string_view Intern::view(IID id) const {
    if (!m_->valid(id)) return {};
    auto &e = m_->entry(id);
    if (e.compressed) return {};
    return {m_->raw(id), e.orig_size};
}

size_t Intern::size(IID id) const {
    if (!m_->valid(id)) return 0;
    return m_->entry(id).orig_size;
}

void Intern::write(IID id, int fd) const {
    if (!m_->valid(id)) return;
    auto &e = m_->entry(id);
    if (!e.compressed) {
        ::write(fd, m_->raw(id), e.orig_size);
    } else {
        std::string tmp = str(id);
        ::write(fd, tmp.data(), tmp.size());
    }
}

void Intern::write(IID id, std::ostream &os) const {
    if (!m_->valid(id)) return;
    auto &e = m_->entry(id);
    if (!e.compressed) {
        os.write(m_->raw(id), e.orig_size);
    } else {
        std::string tmp = str(id);
        os.write(tmp.data(), tmp.size());
    }
}

std::vector<std::string> Intern::get_argv(IID id) const {
    std::vector<std::string> out;
    if (!m_->valid(id)) return out;
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
    /* With sharding, identical data always hashes to the same shard
       and is deduped there, so equal data ⟺ equal IID. */
    return a == b;
}

bool Intern::eq(IID a, std::string_view data) const {
    if (!a && data.empty()) return true;
    if (!m_->valid(a)) return data.empty();
    return m_->content_eq(a, data.data(), data.size());
}

bool Intern::eq(IID a, const void *data, size_t len) const {
    if (!a && !len) return true;
    if (!m_->valid(a)) return len == 0;
    return m_->content_eq(a, data, len);
}

bool Intern::contains(IID a, std::string_view needle) const {
    if (needle.empty()) return true;
    if (!m_->valid(a)) return false;
    auto &e = m_->entry(a);
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
    if (!m_->valid(id)) return false;
    auto &e = m_->entry(id);
    if (!e.compressed) {
        std::string tmp(m_->raw(id), e.orig_size);
        return fnmatch(pattern, tmp.c_str(), FNM_PATHNAME) == 0;
    }
    std::string tmp = str(id);
    return fnmatch(pattern, tmp.c_str(), FNM_PATHNAME) == 0;
}

/* ── Utility ──────────────────────────────────────────────────────── */

bool Intern::empty(IID id) const {
    return !m_->valid(id);
}

void Intern::clear() {
    for (auto &s : m_->shards) {
        std::lock_guard<std::mutex> lk(s.mu);
        s.arena.clear();
        s.entries.clear();
        s.entries.push_back(Entry{0, 0, 0, 0, false});
        std::fill(s.htab.begin(), s.htab.end(), 0u);
        s.htab_count = 0;
    }
}

size_t Intern::count() const {
    size_t n = 0;
    for (auto &s : m_->shards)
        n += s.entries.size() - 1;  /* minus sentinel per shard */
    return n;
}

size_t Intern::memory_bytes() const {
    size_t n = 0;
    for (auto &s : m_->shards) {
        n += s.arena.capacity();
        n += s.entries.capacity() * sizeof(Entry);
        n += s.htab.capacity() * sizeof(IID);
    }
    return n;
}
