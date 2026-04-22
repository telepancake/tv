/* wire_in.h - streaming decoder for tv's wire-format trace input.
 *
 * Producers (sud, proctrace, uproctrace) emit binary wire events as
 * defined in wire/wire.h. tv consumes them through this adapter.
 *
 * The decoder is byte-streaming - feed() is safe to call with any
 * fragment size, including a single byte at a time from a non-blocking
 * pipe. Each decoded event is delivered to the sink as a WireEvent
 * (a POD view into a small internal scratch buffer). No coalescing,
 * no event filtering - every wire event class is delivered raw, with
 * its bytes owned by the decoder until the sink call returns.
 *
 * The sink is responsible for *consuming* (e.g. appending into a
 * DuckDB table) before returning; the decoder reuses its scratch
 * buffer between events.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

/* One decoded wire event. All blob/extras pointers are valid only
 * for the duration of the sink call. The `type` is the EV_* code
 * from wire/wire.h. `extras`/`n_extras` are type-specific i64 fields
 * (4 for EV_EXIT, 7 for EV_OPEN, 0 otherwise). `blob` is the
 * variable-length payload (may be empty / nullptr).
 *
 * `stream_id` identifies which producer stream the event was delta-
 * encoded against. v1 streams always report 0; v2 streams report the
 * stream_id the producer chose (0 = default / legacy stream). */
struct WireEvent {
    int32_t  type;
    uint64_t ts_ns;
    int32_t  pid, tgid, ppid, nspid, nstgid;
    uint32_t stream_id;
    const int64_t *extras;
    unsigned       n_extras;
    const char *blob;
    size_t      blen;
};

class WireDecoder {
public:
    using Sink = std::function<void(const WireEvent &)>;

    explicit WireDecoder(Sink sink);
    ~WireDecoder();
    WireDecoder(const WireDecoder &) = delete;
    WireDecoder &operator=(const WireDecoder &) = delete;

    /* Append `n` bytes of wire-format input. Decoded events are passed
     * to the sink as they complete. Bytes that don't form a whole atom
     * are buffered until the next call. Returns false on a hard format
     * error (unsupported version, decode error). */
    bool feed(const void *data, size_t n);

    /* True if any byte has been fed since construction. */
    bool started() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
