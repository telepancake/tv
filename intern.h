/* intern.h — Unified byte-interning library with two typed pools.
 *
 * Every distinct blob of bytes gets a unique ID.  Duplicates share storage.
 * No deletion.
 *
 * Two pools, two distinct ID types:
 *
 *   InlineIID  — entries are *always* stored uncompressed.  view() returns
 *                a string_view into the pool's arena and is total — it
 *                never silently fails.  Use for short data that callers
 *                want zero-copy access to: path components, exe basenames,
 *                flag strings, status strings, search queries, etc.
 *
 *   BlobIID    — entries may be ZSTD-compressed when large.  Only str()
 *                / bytes() / write() are available; there is no view().
 *                Use for data the caller will copy out anyway: full
 *                paths, argv blobs, stdout/stderr captures.
 *
 * IID 0 ("empty") is the sentinel for both types.  The strong types
 * statically prevent passing one kind of ID to a method expecting the
 * other.
 *
 * Thread safety: put_inline() and put_blob() are safe to call from
 * multiple threads concurrently — each pool is internally sharded
 * (16 shards), so different inputs usually lock different shards.
 * Reads (str/view/eq/...) acquire the per-shard mutex briefly to
 * guard against a concurrent put_*() reallocating the underlying
 * vectors.  find_inline() is also concurrent-safe with put_inline().
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <iosfwd>

/* ── Strong-typed IDs ─────────────────────────────────────────────── */

struct InlineIID {
    uint32_t v = 0;
    constexpr bool empty() const { return v == 0; }
    constexpr explicit operator bool() const { return v != 0; }
    constexpr bool operator==(InlineIID o) const { return v == o.v; }
    constexpr bool operator!=(InlineIID o) const { return v != o.v; }
    constexpr bool operator< (InlineIID o) const { return v <  o.v; }
};

struct BlobIID {
    uint32_t v = 0;
    constexpr bool empty() const { return v == 0; }
    constexpr explicit operator bool() const { return v != 0; }
    constexpr bool operator==(BlobIID o) const { return v == o.v; }
    constexpr bool operator!=(BlobIID o) const { return v != o.v; }
    constexpr bool operator< (BlobIID o) const { return v <  o.v; }
};

class Intern {
public:
    Intern();
    ~Intern();
    Intern(const Intern &) = delete;
    Intern &operator=(const Intern &) = delete;

    /* ── Inline pool (always uncompressed; view() is total) ─────── */

    InlineIID put_inline(std::string_view data);
    InlineIID put_inline(const void *data, size_t len);

    /* Lookup without inserting — concurrent-safe with put_inline()
       on the same shard (uses shared/exclusive locking).  Returns
       an empty InlineIID if the data was never interned. */
    InlineIID find_inline(std::string_view data) const;

    std::string_view view(InlineIID id) const;       /* total: never empty for non-empty id */
    std::string      str (InlineIID id) const;       /* same bytes as view, copied out      */
    size_t           size(InlineIID id) const;
    bool             empty(InlineIID id) const { return id.empty(); }

    /* Equality is exact: equal data ⟺ equal IID (debug-asserted). */
    bool eq(InlineIID a, InlineIID b) const;
    bool eq(InlineIID a, std::string_view data) const;

    bool contains(InlineIID a, std::string_view needle) const;
    bool glob    (InlineIID id, const char *pattern) const;

    /* ── Blob pool (may be compressed; no view() is offered) ────── */

    BlobIID put_blob(std::string_view data);
    BlobIID put_blob(const void *data, size_t len);
    BlobIID put_blob(const std::vector<uint8_t> &data);

    /* Convenience: store an argv-style vector as a single
       null-separated blob and return one BlobIID. */
    BlobIID put_blob_argv(const std::vector<std::string> &argv);

    std::string          str  (BlobIID id) const;
    std::vector<uint8_t> bytes(BlobIID id) const;
    std::vector<std::string> get_argv(BlobIID id) const;
    size_t               size (BlobIID id) const;
    bool                 empty(BlobIID id) const { return id.empty(); }

    void write(BlobIID id, int fd) const;
    void write(BlobIID id, std::ostream &os) const;

    bool eq(BlobIID a, BlobIID b) const;
    bool eq(BlobIID a, std::string_view data) const;

    bool contains(BlobIID a, std::string_view needle) const;
    bool glob    (BlobIID id, const char *pattern) const;

    /* ── Utility ──────────────────────────────────────────────── */
    void   clear();
    size_t count() const;        /* number of unique entries (both pools) */
    size_t memory_bytes() const; /* approximate pool RAM                  */

private:
    struct Impl;
    Impl *m_;
};
