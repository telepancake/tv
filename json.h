#pragma once

#include <string>
#include <string_view>
#include <vector>

/* Decode a JSON-encoded string value (including surrounding quotes). */
std::string json_decode_string(std::string_view sp);

/* Look up a top-level key in a single-line JSON object and return its raw
   value span (e.g. "42", "\"hello\"", "[...]").  Returns false if not found. */
bool json_get(const char *json, const char *key, std::string_view &out);

/* Parse a JSON array of strings and return the decoded string values. */
std::vector<std::string> json_array_of_strings(std::string_view sp);

/* Convert a raw JSON value span to a primitive C type. */
int    span_to_int   (std::string_view sp, int    def);
double span_to_double(std::string_view sp, double def);
int    span_to_bool  (std::string_view sp, int    def);
