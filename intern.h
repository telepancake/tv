/* intern.h — Unified byte-interning library.
 *
 * Every distinct blob of bytes gets a unique 32-bit ID (IID).
 * Duplicates share storage.  No deleting.  Thread-safe put().
 *
 * Internally the pool chooses the best representation per entry:
 *   • small blobs (< threshold): stored inline, O(1) view()
 *   • large blobs: ZSTD-compressed, decompressed on demand
 *
 * The interface is oblivious to the internal representation.
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <iosfwd>

/* Interned-blob identifier.  0 always means "empty / null". */
using IID = uint32_t;

class Intern {
public:
    Intern();
    ~Intern();
    Intern(const Intern &) = delete;
    Intern &operator=(const Intern &) = delete;

    /* ── Store (deduplicate) ──────────────────────────────────── */
    IID put(std::string_view data);
    IID put(const void *data, size_t len);
    IID put(const std::vector<uint8_t> &data);

    /* Convenience: store an argv-style vector as a single
       null-separated blob and return one IID. */
    IID put_argv(const std::vector<std::string> &argv);

    /* ── Retrieve ─────────────────────────────────────────────── */
    /* Return a copy of the original bytes. */
    std::string           str(IID id) const;
    std::vector<uint8_t>  bytes(IID id) const;

    /* Fast O(1) view into pool storage — only valid for entries
       stored inline (uncompressed).  Returns empty view for
       compressed entries; caller should fall back to str(). */
    std::string_view      view(IID id) const;

    /* Original size in bytes. */
    size_t                size(IID id) const;

    /* Write original bytes to a file descriptor or stream. */
    void write(IID id, int fd) const;
    void write(IID id, std::ostream &os) const;

    /* Convenience: decompress an argv blob back into a vector. */
    std::vector<std::string> get_argv(IID id) const;

    /* ── Compare ──────────────────────────────────────────────── */
    /* Two interned IDs — same ID means equal, otherwise compare
       the underlying bytes (fast: hash + size check first). */
    bool eq(IID a, IID b) const;

    /* Compare interned data with a raw blob, without interning
       the blob.  Hash + size short-circuit first. */
    bool eq(IID a, std::string_view data) const;
    bool eq(IID a, const void *data, size_t len) const;

    /* Substring search: does the interned data contain needle? */
    bool contains(IID a, std::string_view needle) const;

    /* ── Pattern matching ─────────────────────────────────────── */
    /* POSIX fnmatch()-style glob against the interned data. */
    bool glob(IID id, const char *pattern) const;

    /* ── Utility ──────────────────────────────────────────────── */
    bool   empty(IID id) const;
    void   clear();
    size_t count() const;        /* number of unique entries  */
    size_t memory_bytes() const; /* approximate pool RAM      */

private:
    struct Impl;
    Impl *m_;
};
