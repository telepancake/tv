/*
 * sud/elf.c — Unified ELF inspection, path resolution, and exec argv
 *             building using only raw syscalls.
 *
 * These are the signal-safe (raw_*) implementations from sudtrace.c
 * with the _raw suffix removed.  The old libc-based duplicates are
 * deleted — these work in both the SIGSYS handler and parent process.
 */

#include "sud/libc.h"
#include "sud/raw.h"
#include "sud/fmt.h"
#include "sud/event.h"
#include "sud/elf.h"

/* ELF ident helpers not provided by our minimal libc.h */
#ifndef SELFMAG
#define SELFMAG  4
#endif
#ifndef EI_CLASS
#define EI_CLASS 4
#endif
#ifndef X_OK
#define X_OK     1
#endif

/* ================================================================
 * Shebang / ELF inspection
 * ================================================================ */

int check_shebang(const char *path, char *interp, int interp_sz,
                  char *interp_arg, int arg_sz)
{
    int fd = raw_open(path, O_RDONLY);
    if (fd < 0) return 0;

    char buf[256];
    ssize_t n = raw_read(fd, buf, sizeof(buf) - 1);
    raw_close(fd);
    if (n < 3) return 0;
    buf[n] = '\0';

    if (buf[0] != '#' || buf[1] != '!') return 0;

    char *nl = strchr(buf + 2, '\n');
    if (nl) *nl = '\0';

    char *p = buf + 2;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) return 0;

    char *end = p;
    while (*end && *end != ' ' && *end != '\t') end++;

    size_t ilen = (size_t)(end - p);
    if (ilen >= (size_t)interp_sz) ilen = (size_t)interp_sz - 1;
    memcpy(interp, p, ilen);
    interp[ilen] = '\0';

    if (interp_arg) {
        interp_arg[0] = '\0';
        while (*end == ' ' || *end == '\t') end++;
        if (*end) {
            size_t alen = strlen(end);
            if (alen >= (size_t)arg_sz) alen = (size_t)arg_sz - 1;
            memcpy(interp_arg, end, alen);
            interp_arg[alen] = '\0';
        }
    }

    return 1;
}

void trim_interp(char *interp)
{
    size_t len = strlen(interp);
    while (len > 0 && interp[len - 1] == '\n')
        len--;
    interp[len] = '\0';
}

int inspect_elf_dynamic_fd(int fd, char *interp, int interp_sz,
                           int *elf_class)
{
    unsigned char ident[EI_NIDENT];
    if (raw_pread(fd, ident, sizeof(ident), 0) != (ssize_t)sizeof(ident))
        return -1;
    if (memcmp(ident, ELFMAG, SELFMAG) != 0)
        return -1;
    if (elf_class)
        *elf_class = ident[EI_CLASS];

    if (ident[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr ehdr;
        if (raw_pread(fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr))
            return -1;
        for (int i = 0; i < ehdr.e_phnum; i++) {
            Elf64_Phdr phdr;
            if (raw_pread(fd, &phdr, sizeof(phdr),
                          ehdr.e_phoff + i * ehdr.e_phentsize) != sizeof(phdr))
                continue;
            if (phdr.p_type != PT_INTERP)
                continue;
            size_t sz = phdr.p_filesz;
            if (sz >= (size_t)interp_sz) sz = (size_t)interp_sz - 1;
            if (raw_pread(fd, interp, sz, phdr.p_offset) != (ssize_t)sz)
                return -1;
            interp[sz] = '\0';
            trim_interp(interp);
            return 1;
        }
        return 0;
    }

    if (ident[EI_CLASS] == ELFCLASS32) {
        Elf32_Ehdr ehdr;
        if (raw_pread(fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr))
            return -1;
        for (int i = 0; i < ehdr.e_phnum; i++) {
            Elf32_Phdr phdr;
            if (raw_pread(fd, &phdr, sizeof(phdr),
                          ehdr.e_phoff + i * ehdr.e_phentsize) != sizeof(phdr))
                continue;
            if (phdr.p_type != PT_INTERP)
                continue;
            size_t sz = phdr.p_filesz;
            if (sz >= (size_t)interp_sz) sz = (size_t)interp_sz - 1;
            if (raw_pread(fd, interp, sz, phdr.p_offset) != (ssize_t)sz)
                return -1;
            interp[sz] = '\0';
            trim_interp(interp);
            return 1;
        }
        return 0;
    }

    return -1;
}

int check_elf_dynamic(const char *path, char *interp, int interp_sz,
                      int *elf_class)
{
    int fd = raw_open(path, O_RDONLY);
    if (fd < 0) return -1;
    int ret = inspect_elf_dynamic_fd(fd, interp, interp_sz, elf_class);
    raw_close(fd);
    return ret;
}

/* ================================================================
 * Path resolution
 * ================================================================ */

int resolve_path(const char *cmd, char *out, int out_sz)
{
    /* Defensive: traced programs can reach the SIGSYS execve handler with
     * a NULL or empty filename (e.g. execve(NULL, argv, envp), or an argv
     * whose first slot is NULL after sud_arena_strdup of a NULL fn). The
     * kernel would normally answer -EFAULT/-ENOENT; we must not crash
     * trying to dereference cmd[0] before forwarding the syscall. */
    if (!cmd || !cmd[0] || out_sz <= 0) return 0;

    if (cmd[0] == '/' || cmd[0] == '.') {
        size_t clen = strlen(cmd);
        if (clen >= (size_t)out_sz) clen = (size_t)out_sz - 1;
        memcpy(out, cmd, clen);
        out[clen] = '\0';
        return (raw_access(out, X_OK) == 0);
    }

    const char *path_env = (g_path_env && g_path_env[0]) ? g_path_env : "/usr/bin:/bin";

    const char *p = path_env;
    while (*p) {
        const char *colon = p;
        while (*colon && *colon != ':') colon++;
        size_t dlen = (size_t)(colon - p);
        size_t clen = strlen(cmd);
        if (dlen + 1 + clen + 1 <= (size_t)out_sz) {
            memcpy(out, p, dlen);
            out[dlen] = '/';
            memcpy(out + dlen + 1, cmd, clen);
            out[dlen + 1 + clen] = '\0';
            if (raw_access(out, X_OK) == 0)
                return 1;
        }
        p = *colon ? colon + 1 : colon;
    }

    return 0;
}

int resolve_execveat_path(int dirfd, const char *path, long flags,
                          char *out, int out_sz)
{
#ifdef AT_EMPTY_PATH
    if ((flags & AT_EMPTY_PATH) && path && path[0] == '\0')
        return 0;
#endif

    if (!path || !path[0])
        return 0;

    if (dirfd == AT_FDCWD || path[0] == '/')
        return resolve_path(path, out, out_sz);

    char proc_path[64];
    int pos = 0;
    const char prefix[] = "/proc/self/fd/";
    memcpy(proc_path, prefix, sizeof(prefix) - 1);
    pos += sizeof(prefix) - 1;
    pos += (int)(fmt_int(proc_path + pos, dirfd) - (proc_path + pos));
    if (pos <= 0 || pos >= (int)sizeof(proc_path))
        return 0;
    proc_path[pos] = '\0';

    char dirbuf[PATH_MAX];
    ssize_t dlen = raw_readlink(proc_path, dirbuf, sizeof(dirbuf) - 1);
    if (dlen <= 0 || dlen >= (ssize_t)sizeof(dirbuf))
        return 0;
    dirbuf[dlen] = '\0';

    size_t plen = strlen(path);
    size_t base_len = (size_t)dlen;
    int need_slash = (base_len > 0 && dirbuf[base_len - 1] != '/');
    if (base_len + (size_t)need_slash + plen + 1 > (size_t)out_sz)
        return 0;

    memcpy(out, dirbuf, base_len);
    if (need_slash)
        out[base_len++] = '/';
    memcpy(out + base_len, path, plen);
    out[base_len + plen] = '\0';
    return (raw_access(out, X_OK) == 0);
}

/* ================================================================
 * Self exe helper
 * ================================================================ */

const char *self_exe_for_class(int elf_class)
{
    if (elf_class == ELFCLASS32 && g_self_exe32[0])
        return g_self_exe32;
    if (elf_class == ELFCLASS64 && g_self_exe64[0])
        return g_self_exe64;
    if (elf_class == SUD_NATIVE_ELF_CLASS)
        return g_self_exe;
    return NULL;
}

/* ================================================================
 * Exec argv building (arena-based, signal-safe)
 * ================================================================ */

/* Ensure room for additional entries; returns (possibly new) args pointer. */
static char **ensure_args(struct sud_arena *a, char **args, int nargs,
                          int need, int *max_args)
{
    if (nargs + need < *max_args)
        return args;
    *max_args = nargs + need + 8;
    char **new_args = sud_arena_alloc(a, ((size_t)*max_args + 1) * sizeof(char *));
    if (!new_args) return NULL;
    memcpy(new_args, args, ((size_t)nargs + 1) * sizeof(char *));
    return new_args;
}

char **build_exec_argv(struct sud_arena *a, int orig_argc, char **orig_argv)
{
    int max_args = orig_argc + 20;
    char **args = sud_arena_alloc(a, ((size_t)max_args + 1) * sizeof(char *));
    if (!args) return NULL;

    int nargs = 0;
    for (int i = 0; i < orig_argc; i++) {
        char *dup = sud_arena_strdup(a, orig_argv[i]);
        /* Arena exhaustion: signal caller to forward the original execve
         * unchanged so the program is not broken by sud's per-handler
         * 64 KiB arena.  Without this, mid-vector NULLs end up in argv
         * and the kernel either truncates the vector early or rejects
         * the call (the user reported this as silent build failures
         * that work fine without sud). */
        if (orig_argv[i] && !dup) return NULL;
        args[nargs++] = dup;
    }
    args[nargs] = NULL;

    /* If the caller didn't give us a usable argv[0] (e.g. execve(NULL,...)
     * the kernel will reject), there's nothing for us to resolve and
     * shebang/ELF-classify. Hand the original argv back so the syscall
     * forwards as-is and lets the kernel produce -EFAULT/-ENOENT. */
    if (nargs == 0 || !args[0] || !args[0][0])
        return args;

    int drop_count = 0;

    for (int depth = 0; depth < 16; depth++) {
        char resolved[PATH_MAX];
        if (!resolve_path(args[0], resolved, sizeof(resolved)))
            return args;

        char *dup = sud_arena_strdup(a, resolved);
        if (!dup) return NULL;  /* arena full → caller forwards original */
        args[0] = dup;

        char interp[PATH_MAX], interp_arg[256];
        if (check_shebang(resolved, interp, sizeof(interp),
                           interp_arg, sizeof(interp_arg))) {
            int extra = interp_arg[0] ? 2 : 1;
            char **na = ensure_args(a, args, nargs, extra, &max_args);
            if (!na) return NULL;
            args = na;
            memmove(args + extra, args, ((size_t)nargs + 1) * sizeof(char *));
            char *d_int = sud_arena_strdup(a, interp);
            if (!d_int) return NULL;
            args[0] = d_int;
            if (interp_arg[0]) {
                char *d_arg = sud_arena_strdup(a, interp_arg);
                if (!d_arg) return NULL;
                args[1] = d_arg;
            }
            nargs += extra;
            continue;
        }

        char elf_interp[PATH_MAX];
        int elf_class = 0;
        int dyn = check_elf_dynamic(resolved, elf_interp,
                                     sizeof(elf_interp), &elf_class);

        if (dyn == 1) {
            char **na = ensure_args(a, args, nargs, 1, &max_args);
            if (!na) return NULL;
            args = na;
            memmove(args + 1, args, ((size_t)nargs + 1) * sizeof(char *));
            char *d = sud_arena_strdup(a, elf_interp);
            if (!d) return NULL;
            args[0] = d;
            nargs++;
            drop_count++;
            continue;
        }

        if (dyn == 0) {
            const char *self_exe = self_exe_for_class(elf_class);
            if (!self_exe)
                return args;
            char **na = ensure_args(a, args, nargs, 1, &max_args);
            if (!na) return NULL;
            args = na;
            memmove(args + 1, args, ((size_t)nargs + 1) * sizeof(char *));
            char *d_self = sud_arena_strdup(a, self_exe);
            if (!d_self) return NULL;
            args[0] = d_self;
            nargs++;
            if (!g_trace_exec_env) {
                na = ensure_args(a, args, nargs, 1, &max_args);
                if (!na) return NULL;
                args = na;
                memmove(args + 2, args + 1,
                        (size_t)nargs * sizeof(char *));
                char *d_ne = sud_arena_strdup(a, "--no-env");
                if (!d_ne) return NULL;
                args[1] = d_ne;
                nargs++;
            }
            /* Insert --drop-argv N after sudtrace's own flags */
            if (drop_count > 0) {
                int insert_pos = g_trace_exec_env ? 1 : 2;
                na = ensure_args(a, args, nargs, 2, &max_args);
                if (!na) return NULL;
                args = na;
                memmove(args + insert_pos + 2, args + insert_pos,
                        ((size_t)(nargs - insert_pos) + 1) * sizeof(char *));
                char *d_drop = sud_arena_strdup(a, "--drop-argv");
                char drop_buf[16];
                fmt_int(drop_buf, drop_count);
                char *d_n = sud_arena_strdup(a, drop_buf);
                if (!d_drop || !d_n) return NULL;
                args[insert_pos] = d_drop;
                args[insert_pos + 1] = d_n;
                nargs += 2;
            }
            break;
        }

        break;
    }

    return args;
}

void free_exec_argv(char **args)
{
    /* No-op: storage lives in the caller's stack-local arena. */
    (void)args;
}
