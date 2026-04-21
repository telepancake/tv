/* wire_in.h — streaming decoder for tv's wire-format trace input.
 *
 * Producers (sud, proctrace, uproctrace) emit binary wire events as
 * defined in wire/wire.h. tv consumes them through this adapter.
 *
 * The decoder is byte-streaming — feed() is safe to call with any
 * fragment size, including a single byte at a time from a non-blocking
 * pipe. Each fully-decoded event is delivered to the sink as a
 * WireRawEvent (a POD view into a small internal scratch buffer).
 *
 * tv's caller is expected to translate the raw event into its own
 * preparsed_event_t shape (path classification, interning, etc).
 *
 * EV_EXEC + immediately-following EV_ARGV (matching ts_ns/pid/tgid)
 * are coalesced into a single delivered event of kind EV_EXEC with
 * both `exe` and `argv_blob` populated. EV_ENV/EV_AUXV are dropped.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

/* Mirrors wire/wire.h's event-class numbering, narrowed to the kinds
 * tv actually surfaces (no ENV/AUXV; coalesced EXEC+ARGV). */
enum WireEvKind : uint8_t {
    WIRE_EV_EXEC = 0,
    WIRE_EV_EXIT,
    WIRE_EV_OPEN,
    WIRE_EV_CWD,
    WIRE_EV_STDOUT,
    WIRE_EV_STDERR,
};

struct WireRawEvent {
    WireEvKind kind;
    uint64_t   ts_ns;
    int32_t    pid, tgid, ppid;

    /* CWD/OPEN: path bytes (may be empty). */
    const char *path = nullptr;
    size_t      path_len = 0;

    /* EXEC: exe path + raw NUL-separated argv blob. */
    const char *exe = nullptr;
    size_t      exe_len = 0;
    const char *argv = nullptr;     /* raw NUL-separated, no terminator */
    size_t      argv_len = 0;

    /* OPEN: 7 wire extras. */
    int32_t  open_flags = 0;
    int32_t  open_fd    = -1;
    uint64_t open_ino   = 0;
    uint32_t open_dev_major = 0;
    uint32_t open_dev_minor = 0;
    int32_t  open_err   = 0;
    bool     open_inherited = false;

    /* EXIT: 4 wire extras. */
    int32_t exit_status_kind = 0;   /* EV_EXIT_EXITED / EV_EXIT_SIGNALED */
    int32_t exit_code_or_sig = 0;
    bool    exit_core_dumped = false;
    int32_t exit_raw         = 0;

    /* STDOUT/STDERR: payload bytes. */
    const char *data = nullptr;
    size_t      data_len = 0;
};

class WireDecoder {
public:
    using Sink = std::function<void(const WireRawEvent &)>;

    explicit WireDecoder(Sink sink);
    ~WireDecoder();
    WireDecoder(const WireDecoder &) = delete;
    WireDecoder &operator=(const WireDecoder &) = delete;

    /* Append `n` bytes of wire-format input. Decoded events are passed
     * to the sink as they complete. Bytes that don't form a whole atom
     * are buffered until the next call. Returns false on a hard format
     * error (unsupported version, decode error). */
    bool feed(const void *data, size_t n);

    /* Flush any pending coalescing buffer (a buffered EV_EXEC waiting
     * for its argv companion is delivered with empty argv). */
    void flush();

    /* True if any byte has been fed since construction. */
    bool started() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/* Sniff the first byte of an input source to decide whether to use the
 * wire decoder. Returns true for wire (yeet self-byte or length atom),
 * false for legacy JSONL (`{`). The first wire atom is always
 * yeet_u64(WIRE_VERSION); for WIRE_VERSION==1 that encodes as 0x01,
 * a single self-byte (b<0xC0). For larger versions or future yeet
 * forms it's an inline atom (0xC0..0xF7). JSON lines start with `{`
 * which is 0x7B — also < 0xC0, but never 0x01. We disambiguate using
 * "looks like JSON if first non-WS byte is `{`". */
bool wire_looks_like_wire(unsigned char first_byte);
