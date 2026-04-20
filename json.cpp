#include "json.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>

/* ── Internal helpers ───────────────────────────────────────────────── */

static const char *skip_ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

static const char *json_skip_string(const char *p, const char *end) {
    if (p >= end || *p != '"') return nullptr;
    p++;
    while (p < end) {
        if (*p == '\\') { p += 2; continue; }
        if (*p == '"') return p + 1;
        p++;
    }
    return nullptr;
}

static const char *json_skip_value(const char *p, const char *end) {
    p = skip_ws(p, end);
    if (p >= end) return nullptr;
    if (*p == '"') return json_skip_string(p, end);
    if (*p == '{') {
        int depth = 1; p++;
        while (p < end && depth > 0) {
            if (*p == '"') { p = json_skip_string(p, end); if (!p) return nullptr; continue; }
            if (*p == '{') depth++; else if (*p == '}') depth--;
            p++;
        }
        return depth == 0 ? p : nullptr;
    }
    if (*p == '[') {
        int depth = 1; p++;
        while (p < end && depth > 0) {
            if (*p == '"') { p = json_skip_string(p, end); if (!p) return nullptr; continue; }
            if (*p == '[') depth++; else if (*p == ']') depth--;
            p++;
        }
        return depth == 0 ? p : nullptr;
    }
    while (p < end && *p != ',' && *p != '}' && *p != ']') p++;
    return p;
}

/* ── Public API ─────────────────────────────────────────────────────── */

std::string json_decode_string(std::string_view sp) {
    if (sp.empty() || sp[0] != '"') return {};
    const char *p = sp.data() + 1, *end = sp.data() + sp.size() - 1;
    /* Fast path: if no backslash, return the substring directly. */
    const char *bs = static_cast<const char *>(std::memchr(p, '\\', static_cast<size_t>(end - p)));
    if (!bs) return std::string(p, static_cast<size_t>(end - p));
    /* Slow path: copy up to the first backslash, then decode escapes. */
    std::string out(p, static_cast<size_t>(bs - p));
    out.reserve(static_cast<size_t>(end - p));
    p = bs;
    while (p < end) {
        if (*p == '\\' && p + 1 < end) {
            p++;
            switch (*p) {
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'u':
                if (p + 4 < end) {
                    unsigned v = 0;
                    for (int i = 0; i < 4; i++) {
                        char c = p[1 + i];
                        v <<= 4;
                        if (c >= '0' && c <= '9') v |= static_cast<unsigned>(c - '0');
                        else if (c >= 'a' && c <= 'f') v |= static_cast<unsigned>(c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') v |= static_cast<unsigned>(c - 'A' + 10);
                    }
                    out += (v >= 32 && v < 127) ? static_cast<char>(v) : '?';
                    p += 4;
                }
                break;
            default: out += *p; break;
            }
            p++;
            continue;
        }
        out += *p++;
    }
    return out;
}

bool json_get(const char *json, const char *key, std::string_view &out) {
    char pat[128];
    int pat_len = std::snprintf(pat, sizeof pat, "\"%s\":", key);
    const char *p = std::strstr(json, pat);
    if (!p) return false;
    p += pat_len;
    /* Scan forward from match position for end-of-string, avoiding a
       full-length strlen from the beginning of json. */
    const char *end = p + std::strlen(p);
    p = skip_ws(p, end);
    const char *ve = json_skip_value(p, end);
    if (!ve) return false;
    out = std::string_view(p, static_cast<size_t>(ve - p));
    return true;
}

std::vector<std::string> json_array_of_strings(std::string_view sp) {
    std::vector<std::string> arr;
    const char *p = skip_ws(sp.data(), sp.data() + sp.size());
    const char *end = sp.data() + sp.size();
    if (p >= end || *p != '[') return arr;
    p++;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == ']') break;
        const char *is = p;
        p = json_skip_string(p, end);
        if (!p) break;
        arr.push_back(json_decode_string(std::string_view(is, static_cast<size_t>(p - is))));
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
    return arr;
}

int span_to_int(std::string_view sp, int def) {
    std::string tmp(sp);
    char *ep = nullptr;
    long v = std::strtol(tmp.c_str(), &ep, 10);
    return (ep && *ep == '\0') ? static_cast<int>(v) : def;
}

double span_to_double(std::string_view sp, double def) {
    std::string tmp(sp);
    char *ep = nullptr;
    double v = std::strtod(tmp.c_str(), &ep);
    return (ep && *ep == '\0') ? v : def;
}

int span_to_bool(std::string_view sp, int def) {
    if (sp == "true") return 1;
    if (sp == "false") return 0;
    return def;
}
