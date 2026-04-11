/* gen_sql_h.c — Generate tv_sql.h from tv.sql.
 *
 * Replaces gen_sql_h.py.  Sections in tv.sql are delimited by lines
 * matching  --%% <NAME>.  Output: C string constants tv_sql_schema,
 * tv_sql_setup, tv_sql_fts.
 *
 * Usage: gen_sql_h [input.sql] [output.h]
 *        Defaults: tv.sql  tv_sql.h
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *varname(const char *section) {
    if (strcmp(section, "SCHEMA") == 0) return "tv_sql_schema";
    if (strcmp(section, "SETUP")  == 0) return "tv_sql_setup";
    if (strcmp(section, "FTS")    == 0) return "tv_sql_fts";
    /* fallback */
    static char buf[128];
    snprintf(buf, sizeof buf, "tv_sql_%s", section);
    for (char *p = buf; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
    return buf;
}

int main(int argc, char **argv) {
    const char *src = argc > 1 ? argv[1] : "tv.sql";
    const char *dst = argc > 2 ? argv[2] : "tv_sql.h";

    FILE *in = fopen(src, "r");
    if (!in) { fprintf(stderr, "gen_sql_h: cannot open %s\n", src); return 1; }

    /* Read entire file */
    fseek(in, 0, SEEK_END);
    long sz = ftell(in);
    fseek(in, 0, SEEK_SET);
    char *data = malloc(sz + 1);
    if (!data) { fclose(in); return 1; }
    sz = (long)fread(data, 1, sz, in);
    data[sz] = '\0';
    fclose(in);

    FILE *out = fopen(dst, "w");
    if (!out) { fprintf(stderr, "gen_sql_h: cannot create %s\n", dst); free(data); return 1; }

    fprintf(out, "/* Auto-generated from %s -- do not edit */\n\n", src);

    /* Parse into sections */
    char section[64] = "SCHEMA";
    int in_section = 0; /* whether we've started writing lines for current section */

    char *line = data;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        int len = nl ? (int)(nl - line) : (int)strlen(line);

        /* Check for section delimiter: --%% NAME */
        if (len >= 5 && strncmp(line, "--%% ", 5) == 0) {
            if (in_section) fprintf(out, "    \"\";\n\n");
            /* Extract section name */
            char *nm = line + 5;
            int nmlen = len - 5;
            while (nmlen > 0 && (nm[nmlen-1] == ' ' || nm[nmlen-1] == '\r')) nmlen--;
            if (nmlen > 0 && nmlen < (int)sizeof(section)) {
                memcpy(section, nm, nmlen);
                section[nmlen] = '\0';
            }
            in_section = 0;
            line = nl ? nl + 1 : NULL;
            continue;
        }

        /* Skip comment-only lines and blank lines */
        int skip = 0;
        if (len == 0 || (len == 1 && line[0] == '\r')) skip = 1;
        else {
            /* Trim leading whitespace to check if it's a comment */
            int i = 0;
            while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
            if (i >= len || line[i] == '\r') skip = 1;
            else if (len - i >= 2 && line[i] == '-' && line[i+1] == '-') skip = 1;
        }
        if (skip) {
            line = nl ? nl + 1 : NULL;
            continue;
        }

        /* Emit this line as part of the current section */
        if (!in_section) {
            fprintf(out, "static const char %s[] =\n", varname(section));
            in_section = 1;
        }

        /* Escape and write */
        fprintf(out, "    \"");
        for (int i = 0; i < len; i++) {
            if (line[i] == '\r') continue;
            if (line[i] == '\\') fprintf(out, "\\\\");
            else if (line[i] == '"') fprintf(out, "\\\"");
            else fputc(line[i], out);
        }
        fprintf(out, "\\n\"\n");

        line = nl ? nl + 1 : NULL;
    }

    if (in_section) fprintf(out, "    \"\";\n\n");

    fclose(out);
    free(data);
    return 0;
}
