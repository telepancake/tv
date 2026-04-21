/* intern.cpp — Implementation of the typed interning library.
 *
 * Two independent pools live side-by-side:
 *
 *   inline_pool_  — stores entries verbatim, never compressed.
 *                   Backs InlineIID; view() is total.
 *   blob_pool_    — may ZSTD-compress entries above COMPRESS_THRESHOLD.
 *                   Backs BlobIID; only str()/bytes()/write() are exposed.
 *
 * Each pool is split into NUM_SHARDS independent shards, each with its
 * own arena, entry table, hash table, ZSTD contexts (blob pool only),
 * and per-shard std::mutex.
 *
 * put_*() hashes the input, routes to a shard by the hash's upper bits,
 * and only locks that one shard — giving near-linear speedup when many
 * threads call put_*() concurrently with different inputs.
 *
 * find_inline() locks the same per-shard mutex so it is safe alongside
 * put_inline() on the same shard.
 *
 * Note: an earlier version used std::shared_mutex.  Under glibc + static
 * linking that pulls a weakref to pthread_rwlock_wrlock from libstdc++
 * which can resolve to NULL when the rwlock object isn't dragged out of
 * libpthread.a, crashing worker threads on the first lock.  We use
 * std::mutex instead — critical sections here are all very short
 * (memcpy + hash lookup, bounded by a single shard) and the 16-way
 * sharding already makes contention negligible, so the difference is
 * not measurable on real workloads.
 *
 * IID encoding:  upper SHARD_BITS select the shard,
 *                lower (32 − SHARD_BITS) are the local entry index.
 * IID 0 is always "empty" (shard 0, index 0 = sentinel).
 *
 * Reads (str/view/eq/...) take the per-shard mutex briefly so that
 * concurrent std::vector reallocations during growth (entries / arena)
 * can't pull the rug from under them.
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
#define XXH_INLINE_ALL
#include <common/xxhash.h>

/* ── XXH3 64-bit hash (SIMD-friendly, excellent short+medium input perf) ── */

static uint64_t fast_hash64(const void *data, size_t len) {
    return XXH3_64bits(data, len);
}

/* ── Constants ────────────────────────────────────────────────────── */

static constexpr size_t COMPRESS_THRESHOLD = 128;
static constexpr int    ZSTD_LEVEL         = 1;

/* Sharding: upper 4 bits of IID = shard index (0–15),
   lower 28 bits = local entry index within that shard. */
static constexpr int      NUM_SHARDS  = 16;
static constexpr int      SHARD_BITS  = 4;
static constexpr int      SHARD_SHIFT = 32 - SHARD_BITS;
static constexpr uint32_t LOCAL_MASK  = (1u << SHARD_SHIFT) - 1;

static int      shard_of(uint32_t id)  { return static_cast<int>(id >> SHARD_SHIFT); }
static uint32_t local_of(uint32_t id)  { return id & LOCAL_MASK; }
static uint32_t make_id(int shard, uint32_t local) {
    return (static_cast<uint32_t>(shard) << SHARD_SHIFT) | local;
}
static int hash_to_shard(uint64_t h) {
    return static_cast<int>(h >> (64 - SHARD_BITS)) & (NUM_SHARDS - 1);
}

/* ── Entry descriptor ─────────────────────────────────────────────── */

struct Entry {
    uint32_t offset;       /* start in arena            */
    uint32_t stored_size;  /* bytes in arena (may be compressed in blob pool) */
    uint32_t orig_size;    /* original byte count       */
    uint64_t hash;         /* XXH3_64bits of original data */
    bool     compressed;   /* stored_size is ZSTD frame (blob pool only) */
};

/* ── Shard — one independent slice of a pool ──────────────────────── */
/* Templated on a compile-time flag controlling whether put may
   compress.  Inline-pool shards never compress (no ZSTD context). */

template <bool AllowCompress>
struct Shard {
    std::vector<char>   arena;
    std::vector<Entry>  entries;          /* index 0 = unused sentinel */
    std::vector<uint32_t> htab;           /* open-addressing; 0 = empty slot */
    size_t              htab_count = 0;
    ZSTD_CCtx          *cctx = nullptr;   /* nullptr in inline pool */
    ZSTD_DCtx          *dctx = nullptr;   /* nullptr in inline pool */
    mutable std::mutex mu;

    Shard() {
        entries.push_back(Entry{0, 0, 0, 0, false}); /* sentinel */
        htab.resize(64, 0);
        if constexpr (AllowCompress) {
            cctx = ZSTD_createCCtx();
            dctx = ZSTD_createDCtx();
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, ZSTD_LEVEL);
        }
    }
    ~Shard() {
        if (cctx) ZSTD_freeCCtx(cctx);
        if (dctx) ZSTD_freeDCtx(dctx);
    }

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
        std::vector<uint32_t> new_tab(new_cap, 0);
        for (uint32_t id : htab) {
            if (!id) continue;
            uint32_t loc = local_of(id);
            uint64_t h = entries[loc].hash;
            size_t slot = static_cast<size_t>(h) & (new_cap - 1);
            while (new_tab[slot]) slot = (slot + 1) & (new_cap - 1);
            new_tab[slot] = id;
        }
        htab = std::move(new_tab);
    }

    /* Caller must hold at least a shared lock. */
    uint32_t htab_find(uint64_t hash, const void *data, size_t len) const {
        size_t mask = htab.size() - 1;
        size_t slot = static_cast<size_t>(hash) & mask;
        for (;;) {
            uint32_t id = htab[slot];
            if (!id) return 0;
            uint32_t loc = local_of(id);
            auto &e = entries[loc];
            if (e.hash == hash && e.orig_size == static_cast<uint32_t>(len))
                if (content_eq(loc, data, len)) return id;
            slot = (slot + 1) & mask;
        }
    }

    void htab_insert(uint32_t id) {
        if (htab_count * 4 >= htab.size() * 3) htab_grow();
        size_t mask = htab.size() - 1;
        uint32_t loc = local_of(id);
        size_t slot = static_cast<size_t>(entries[loc].hash) & mask;
        while (htab[slot]) slot = (slot + 1) & mask;
        htab[slot] = id;
        htab_count++;
    }

    /* ── put core (caller holds exclusive lock) ──────────────── */

    uint32_t put_locked(int shard_idx, const void *data, size_t len, uint64_t h) {
        uint32_t existing = htab_find(h, data, len);
        if (existing) return existing;

        uint32_t local = static_cast<uint32_t>(entries.size());
        uint32_t id = make_id(shard_idx, local);
        Entry e;
        e.hash = h;
        e.orig_size = static_cast<uint32_t>(len);
        e.offset = static_cast<uint32_t>(arena.size());

        if (!AllowCompress || len < COMPRESS_THRESHOLD) {
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

    void clear_locked() {
        arena.clear();
        entries.clear();
        entries.push_back(Entry{0, 0, 0, 0, false});
        std::fill(htab.begin(), htab.end(), 0u);
        htab_count = 0;
    }

    size_t mem_approx() const {
        return arena.capacity()
             + entries.capacity() * sizeof(Entry)
             + htab.capacity() * sizeof(uint32_t);
    }
};

using InlineShard = Shard<false>;
using BlobShard   = Shard<true>;

/* ── A typed pool: NUM_SHARDS shards, sharded by upper hash bits. */

template <typename ShardT>
struct Pool {
    ShardT shards[NUM_SHARDS];

    /* Read paths take the per-shard mutex briefly to guard against a
       concurrent push_back() reallocating arena/entries out from under
       us.  The critical section is just a vector indexing op. */
    const Entry &entry_locked(uint32_t id, std::unique_lock<std::mutex> &lk) const {
        auto &sh = shards[shard_of(id)];
        lk = std::unique_lock<std::mutex>(sh.mu);
        return sh.entries[local_of(id)];
    }
    bool valid(uint32_t id) const {
        if (!id) return false;
        int s = shard_of(id);
        if (s < 0 || s >= NUM_SHARDS) return false;
        std::unique_lock<std::mutex> lk(shards[s].mu);
        return local_of(id) < shards[s].entries.size();
    }

    uint32_t put(const void *data, size_t len) {
        if (!data || !len) return 0;
        uint64_t h = fast_hash64(data, len);
        int s = hash_to_shard(h);
        auto &sh = shards[s];
        std::unique_lock<std::mutex> lk(sh.mu);
        return sh.put_locked(s, data, len, h);
    }

    uint32_t find(const void *data, size_t len) const {
        if (!data || !len) return 0;
        uint64_t h = fast_hash64(data, len);
        int s = hash_to_shard(h);
        auto &sh = shards[s];
        std::unique_lock<std::mutex> lk(sh.mu);
        return sh.htab_find(h, data, len);
    }

    void clear() {
        for (auto &sh : shards) {
            std::unique_lock<std::mutex> lk(sh.mu);
            sh.clear_locked();
        }
    }

    size_t count() const {
        size_t n = 0;
        for (auto &sh : shards) {
            std::unique_lock<std::mutex> lk(sh.mu);
            n += sh.entries.size() - 1;
        }
        return n;
    }

    size_t memory_bytes() const {
        size_t n = 0;
        for (auto &sh : shards) {
            std::unique_lock<std::mutex> lk(sh.mu);
            n += sh.mem_approx();
        }
        return n;
    }
};

/* ── Impl ─────────────────────────────────────────────────────────── */

struct Intern::Impl {
    Pool<InlineShard> inline_pool;
    Pool<BlobShard>   blob_pool;
};

Intern::Intern()  : m_(new Impl) {}
Intern::~Intern() { delete m_; }

/* ── Inline pool API ─────────────────────────────────────────────── */

InlineIID Intern::put_inline(std::string_view data) {
    return InlineIID{ m_->inline_pool.put(data.data(), data.size()) };
}
InlineIID Intern::put_inline(const void *data, size_t len) {
    return InlineIID{ m_->inline_pool.put(data, len) };
}
InlineIID Intern::find_inline(std::string_view data) const {
    return InlineIID{ m_->inline_pool.find(data.data(), data.size()) };
}

std::string_view Intern::view(InlineIID id) const {
    if (!id) return {};
    auto &sh = m_->inline_pool.shards[shard_of(id.v)];
    std::unique_lock<std::mutex> lk(sh.mu);
    auto &e = sh.entries[local_of(id.v)];
    /* Inline pool guarantees uncompressed storage. */
    return std::string_view(sh.raw(local_of(id.v)), e.orig_size);
}

std::string Intern::str(InlineIID id) const {
    auto sv = view(id);
    return std::string(sv);
}

size_t Intern::size(InlineIID id) const {
    if (!id) return 0;
    auto &sh = m_->inline_pool.shards[shard_of(id.v)];
    std::unique_lock<std::mutex> lk(sh.mu);
    return sh.entries[local_of(id.v)].orig_size;
}

bool Intern::eq(InlineIID a, InlineIID b) const {
    /* Equal data ⟺ equal IID by construction (sharding is content-derived
       and dedup is per-shard).  Verify in debug builds so an innocent
       change to hash_to_shard or put_locked can't silently break the
       invariant.  Contrapositive: when a.v != b.v we must have differing
       data — equal data here would mean dedup failed. */
#ifndef NDEBUG
    if (a == b) return true;
    if (!a || !b) return false;
    auto va = view(a);
    auto vb = view(b);
    bool data_equal = (va.size() == vb.size() &&
                       std::memcmp(va.data(), vb.data(), va.size()) == 0);
    assert(!data_equal &&
           "Intern: equal data produced different InlineIIDs "
           "(sharding/dedup invariant violated)");
    return false;
#else
    return a == b;
#endif
}

bool Intern::eq(InlineIID a, std::string_view data) const {
    if (!a) return data.empty();
    auto sv = view(a);
    return sv.size() == data.size() &&
           std::memcmp(sv.data(), data.data(), sv.size()) == 0;
}

bool Intern::contains(InlineIID a, std::string_view needle) const {
    if (needle.empty()) return true;
    if (!a) return false;
    auto sv = view(a);
    return sv.find(needle) != std::string_view::npos;
}

bool Intern::glob(InlineIID id, const char *pattern) const {
    if (!pattern || !id) return false;
    auto sv = view(id);
    std::string tmp(sv);
    return fnmatch(pattern, tmp.c_str(), FNM_PATHNAME) == 0;
}

/* ── Blob pool API ───────────────────────────────────────────────── */

BlobIID Intern::put_blob(std::string_view data) {
    return BlobIID{ m_->blob_pool.put(data.data(), data.size()) };
}
BlobIID Intern::put_blob(const void *data, size_t len) {
    return BlobIID{ m_->blob_pool.put(data, len) };
}
BlobIID Intern::put_blob(const std::vector<uint8_t> &data) {
    return BlobIID{ m_->blob_pool.put(data.data(), data.size()) };
}

BlobIID Intern::put_blob_argv(const std::vector<std::string> &argv) {
    if (argv.empty()) return BlobIID{};
    std::string flat;
    size_t total = 0;
    for (auto &s : argv) total += s.size() + 1;
    flat.reserve(total);
    for (size_t i = 0; i < argv.size(); i++) {
        if (i) flat += '\0';
        flat += argv[i];
    }
    return put_blob(flat);
}

std::string Intern::str(BlobIID id) const {
    if (!id) return {};
    auto &sh = m_->blob_pool.shards[shard_of(id.v)];
    std::unique_lock<std::mutex> lk(sh.mu);
    auto &e = sh.entries[local_of(id.v)];
    if (!e.compressed)
        return std::string(sh.raw(local_of(id.v)), e.orig_size);
    std::string out(e.orig_size, '\0');
    sh.decompress_into(local_of(id.v), out.data());
    return out;
}

std::vector<uint8_t> Intern::bytes(BlobIID id) const {
    if (!id) return {};
    auto &sh = m_->blob_pool.shards[shard_of(id.v)];
    std::unique_lock<std::mutex> lk(sh.mu);
    auto &e = sh.entries[local_of(id.v)];
    std::vector<uint8_t> out(e.orig_size);
    if (!e.compressed)
        std::memcpy(out.data(), sh.raw(local_of(id.v)), e.orig_size);
    else
        sh.decompress_into(local_of(id.v), reinterpret_cast<char *>(out.data()));
    return out;
}

size_t Intern::size(BlobIID id) const {
    if (!id) return 0;
    auto &sh = m_->blob_pool.shards[shard_of(id.v)];
    std::unique_lock<std::mutex> lk(sh.mu);
    return sh.entries[local_of(id.v)].orig_size;
}

void Intern::write(BlobIID id, int fd) const {
    if (!id) return;
    std::string tmp = str(id);
    ssize_t n = ::write(fd, tmp.data(), tmp.size());
    (void)n;
}

void Intern::write(BlobIID id, std::ostream &os) const {
    if (!id) return;
    std::string tmp = str(id);
    os.write(tmp.data(), static_cast<std::streamsize>(tmp.size()));
}

std::vector<std::string> Intern::get_argv(BlobIID id) const {
    std::vector<std::string> out;
    if (!id) return out;
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

bool Intern::eq(BlobIID a, BlobIID b) const {
    /* Equal data ⟺ equal IID; same invariant as inline pool.
       Contrapositive in debug: a != b ⇒ data differs. */
#ifndef NDEBUG
    if (a == b) return true;
    if (!a || !b) return false;
    std::string sa = str(a), sb = str(b);
    bool data_equal = (sa == sb);
    assert(!data_equal &&
           "Intern: equal data produced different BlobIIDs "
           "(sharding/dedup invariant violated)");
    return false;
#else
    return a == b;
#endif
}

bool Intern::eq(BlobIID a, std::string_view data) const {
    if (!a) return data.empty();
    auto &sh = m_->blob_pool.shards[shard_of(a.v)];
    std::unique_lock<std::mutex> lk(sh.mu);
    return sh.content_eq(local_of(a.v), data.data(), data.size());
}

bool Intern::contains(BlobIID a, std::string_view needle) const {
    if (needle.empty()) return true;
    if (!a) return false;
    auto &sh = m_->blob_pool.shards[shard_of(a.v)];
    std::unique_lock<std::mutex> lk(sh.mu);
    auto &e = sh.entries[local_of(a.v)];
    if (e.orig_size < needle.size()) return false;
    if (!e.compressed) {
        std::string_view sv(sh.raw(local_of(a.v)), e.orig_size);
        return sv.find(needle) != std::string_view::npos;
    }
    std::string tmp(e.orig_size, '\0');
    sh.decompress_into(local_of(a.v), tmp.data());
    return tmp.find(needle) != std::string::npos;
}

bool Intern::glob(BlobIID id, const char *pattern) const {
    if (!pattern || !id) return false;
    std::string tmp = str(id);
    return fnmatch(pattern, tmp.c_str(), FNM_PATHNAME) == 0;
}

/* ── Utility ──────────────────────────────────────────────────────── */

void Intern::clear() {
    m_->inline_pool.clear();
    m_->blob_pool.clear();
}

size_t Intern::count() const {
    return m_->inline_pool.count() + m_->blob_pool.count();
}

size_t Intern::memory_bytes() const {
    return m_->inline_pool.memory_bytes() + m_->blob_pool.memory_bytes();
}
