/*
 * sud/sudtrace.c — Launcher program for SUD-based process tracing.
 *
 * This is a NORMAL C program linked with libc.  It:
 *   1. Parses user arguments (-o FILE, --no-env, -- command ...)
 *   2. Builds the wrapper command (sud64/sud32 ... /path/to/binary ...)
 *   3. Sets up the output fd and environment
 *   4. Fork + exec's the wrapper
 *   5. Waits for children, emitting EXIT events
 *
 * This program does NOT set up SUD or intercept syscalls itself.
 * That is entirely the job of sud32/sud64 (sud/wrapper.c).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif

/* Reserve a high FD so children are unlikely to clobber it */
#define SUD_OUTPUT_FD        1023
#define SUDTRACE_OUTFILE_ENV "SUDTRACE_OUTFILE"

/* ================================================================
 * Usage / help
 * ================================================================ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-o FILE] [--no-env] -- command [args...]\n"
        "\n"
        "Syscall User Dispatch (SUD) based process tracer.\n"
        "Produces JSONL event stream compatible with proctrace/uproctrace.\n",
        prog);
    exit(1);
}

/* ================================================================
 * Path helpers
 * ================================================================ */

static void make_absolute_path(const char *path, char *out, size_t out_sz)
{
    if (!path || !path[0]) { out[0] = '\0'; return; }
    if (path[0] == '/') { snprintf(out, out_sz, "%s", path); return; }

    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) { snprintf(out, out_sz, "%s", path); return; }
    snprintf(out, out_sz, "%s/%s", cwd, path);
}

/* Find our own exe and derive the sud32/sud64 wrapper paths */
static char g_self_exe[PATH_MAX];
static char g_wrapper_32[PATH_MAX];
static char g_wrapper_64[PATH_MAX];

static void init_wrapper_paths(const char *argv0)
{
    ssize_t slen = readlink("/proc/self/exe", g_self_exe,
                            sizeof(g_self_exe) - 1);
    if (slen > 0)
        g_self_exe[slen] = '\0';
    else
        snprintf(g_self_exe, sizeof(g_self_exe), "%s", argv0);

    char *slash = strrchr(g_self_exe, '/');
    if (!slash) {
        /* No directory — assume wrappers in current dir */
        snprintf(g_wrapper_32, sizeof(g_wrapper_32), "sud32");
        snprintf(g_wrapper_64, sizeof(g_wrapper_64), "sud64");
        return;
    }

    int dirlen = (int)(slash - g_self_exe);
    snprintf(g_wrapper_32, sizeof(g_wrapper_32), "%.*s/sud32", dirlen, g_self_exe);
    snprintf(g_wrapper_64, sizeof(g_wrapper_64), "%.*s/sud64", dirlen, g_self_exe);
}

/* ================================================================
 * ELF class detection — determine if target is 32-bit or 64-bit
 * to pick the correct wrapper.
 * ================================================================ */

static int detect_elf_class(const char *path)
{
    unsigned char ident[16];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, ident, sizeof(ident));
    close(fd);
    if (n < 16) return 0;
    /* Check ELF magic */
    if (ident[0] != 0x7f || ident[1] != 'E' ||
        ident[2] != 'L' || ident[3] != 'F')
        return 0;
    return ident[4]; /* EI_CLASS: 1=32bit, 2=64bit */
}

/* Check if a path is a script (#! line) and if so, detect the
 * ELF class of the interpreter. */
static int detect_target_class(const char *path)
{
    int cls = detect_elf_class(path);
    if (cls) return cls;

    /* Might be a script — read first line */
    char buf[512];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 2; /* default to 64-bit */
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 3 || buf[0] != '#' || buf[1] != '!') return 2;
    buf[n] = '\0';

    /* Extract interpreter path */
    char *p = buf + 2;
    while (*p == ' ' || *p == '\t') p++;
    char *end = p;
    while (*end && *end != ' ' && *end != '\t' && *end != '\n') end++;
    *end = '\0';

    cls = detect_elf_class(p);
    return cls ? cls : 2; /* default to 64-bit */
}

/* ================================================================
 * JSONL helpers for EXIT events from the wait loop.
 * Only the launcher needs to emit EXIT — it's the parent process.
 * ================================================================ */

static int g_out_fd = -1;

static void get_timestamp(struct timespec *ts)
{
    clock_gettime(CLOCK_REALTIME, ts);
}

/* Read /proc/<pid>/status to get Tgid */
static pid_t get_tgid_for(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    char buf[2048];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return pid;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return pid;
    buf[n] = '\0';
    char *tg = strstr(buf, "Tgid:");
    if (!tg) return pid;
    tg += 5;
    while (*tg == ' ' || *tg == '\t') tg++;
    pid_t tgid = 0;
    while (*tg >= '0' && *tg <= '9')
        tgid = tgid * 10 + (*tg++ - '0');
    return tgid > 0 ? tgid : pid;
}

static void emit_exit(pid_t pid, int status)
{
    struct timespec ts;
    get_timestamp(&ts);
    char line[512];
    int exit_code = 0;
    int signal_num = 0;
    if (WIFEXITED(status))
        exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        signal_num = WTERMSIG(status);

    int len = snprintf(line, sizeof(line),
        "{\"event\":\"EXIT\",\"ts\":%ld.%09ld,\"pid\":%d",
        (long)ts.tv_sec, ts.tv_nsec, pid);
    if (WIFEXITED(status))
        len += snprintf(line + len, sizeof(line) - len,
            ",\"exit_code\":%d}\n", exit_code);
    else
        len += snprintf(line + len, sizeof(line) - len,
            ",\"signal\":%d}\n", signal_num);

    if (len > 0 && g_out_fd >= 0)
        (void)write(g_out_fd, line, len);
}

/* ================================================================
 * Build the wrapper command line
 *
 * Given user's command, inspect the target binary, choose the
 * correct sud32/sud64 wrapper, and build the exec argv:
 *
 *   sud64 [--no-env] [--drop-argv N] /path/to/ld-linux.so /path/to/binary [args...]
 *
 * For static binaries:
 *   sud64 [--no-env] /path/to/binary [args...]
 *
 * For scripts:
 *   sud64 [--no-env] [--drop-argv N] /path/to/interp [script] [args...]
 * ================================================================ */

static char **build_wrapper_argv(int cmd_argc, char **cmd_argv,
                                 int no_env)
{
    if (cmd_argc < 1 || !cmd_argv[0]) return NULL;

    /* Resolve the target path */
    char resolved[PATH_MAX];
    char *target = cmd_argv[0];
    if (target[0] != '/') {
        /* Search PATH */
        const char *pathenv = getenv("PATH");
        if (!pathenv) pathenv = "/usr/bin:/bin";
        int found = 0;
        while (*pathenv && !found) {
            const char *seg = pathenv;
            while (*pathenv && *pathenv != ':') pathenv++;
            int seglen = (int)(pathenv - seg);
            if (*pathenv == ':') pathenv++;
            snprintf(resolved, sizeof(resolved), "%.*s/%s", seglen, seg, target);
            if (access(resolved, X_OK) == 0) found = 1;
        }
        if (!found) {
            snprintf(resolved, sizeof(resolved), "%s", target);
        }
        target = resolved;
    } else {
        snprintf(resolved, sizeof(resolved), "%s", target);
    }

    /* Check for shebang */
    char shebang_interp[PATH_MAX] = "";
    char shebang_arg[PATH_MAX] = "";
    {
        char buf[512];
        int fd = open(resolved, O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n >= 3 && buf[0] == '#' && buf[1] == '!') {
                buf[n] = '\0';
                char *nl = strchr(buf, '\n');
                if (nl) *nl = '\0';
                char *p = buf + 2;
                while (*p == ' ' || *p == '\t') p++;
                char *iend = p;
                while (*iend && *iend != ' ' && *iend != '\t') iend++;
                if (*iend) {
                    *iend = '\0';
                    char *a = iend + 1;
                    while (*a == ' ' || *a == '\t') a++;
                    /* Trim trailing whitespace */
                    char *ae = a + strlen(a);
                    while (ae > a && (ae[-1] == ' ' || ae[-1] == '\t' ||
                                      ae[-1] == '\r'))
                        *--ae = '\0';
                    if (*a) snprintf(shebang_arg, sizeof(shebang_arg), "%s", a);
                }
                snprintf(shebang_interp, sizeof(shebang_interp), "%s", p);
            }
        }
    }

    /* Determine the actual executable to trace */
    const char *elf_path;
    int drop_count = 0;
    int extra_args = 0;
    char interp_buf[PATH_MAX] = "";
    char *extra_before[4] = {NULL};  /* Fixed: at most interp + arg + script */
    int extra_count = 0;

    if (shebang_interp[0]) {
        /* Script with shebang — trace through the interpreter */
        elf_path = shebang_interp;
        extra_before[extra_count++] = shebang_interp;
        if (shebang_arg[0])
            extra_before[extra_count++] = shebang_arg;
        extra_before[extra_count++] = resolved;
        /* Hide the prepended interpreter (and optional arg) from visible argv,
         * but keep the script path visible — it is the process's argv[0]. */
        drop_count = extra_count - 1;
    } else {
        /* ELF binary — check if dynamic */
        int elf_class = 0;
        int fd = open(resolved, O_RDONLY);
        if (fd >= 0) {
            unsigned char ehdr[64];
            ssize_t n = read(fd, ehdr, sizeof(ehdr));
            if (n >= 20 && ehdr[0] == 0x7f && ehdr[1] == 'E' &&
                ehdr[2] == 'L' && ehdr[3] == 'F') {
                elf_class = ehdr[4];
                /* Check for dynamic linker (PT_INTERP) */
                /* Simplified: read the phdrs to find PT_INTERP */
                lseek(fd, 0, SEEK_SET);
                /* Just use the existing detect mechanism for the class;
                 * the wrapper will do the actual elf inspection */
            }
            close(fd);
            if (!elf_class) elf_class = 2; /* default 64-bit */
        }
        elf_path = resolved;
    }

    /* Determine the target ELF class */
    int target_class = detect_target_class(elf_path);
    const char *wrapper = (target_class == 1) ? g_wrapper_32 : g_wrapper_64;

    /* Build argv:
     * wrapper [--no-env] [--drop-argv N] extra_before... cmd_argv[0] cmd_argv[1:] */
    int max_args = 4 + extra_count + cmd_argc + 1;
    char **args = calloc(max_args, sizeof(char *));
    if (!args) return NULL;
    int idx = 0;

    args[idx++] = strdup(wrapper);
    if (no_env)
        args[idx++] = strdup("--no-env");

    /* The wrapper itself handles ELF inspection and prepending ld-linux.
     * We just pass through the resolved target + original args.
     * For scripts, we prepend the interpreter. */
    if (extra_count > 0) {
        char drop_str[16];
        snprintf(drop_str, sizeof(drop_str), "%d", drop_count);
        args[idx++] = strdup("--drop-argv");
        args[idx++] = strdup(drop_str);
        for (int i = 0; i < extra_count; i++)
            args[idx++] = strdup(extra_before[i]);
        /* Add the remaining original args (skip argv[0] since script path
         * is already included via extra_before) */
        for (int i = 1; i < cmd_argc; i++)
            args[idx++] = strdup(cmd_argv[i]);
    } else {
        /* Just pass through to the wrapper — it handles ELF inspection */
        for (int i = 0; i < cmd_argc; i++)
            args[idx++] = strdup(cmd_argv[i]);
    }
    args[idx] = NULL;
    return args;
}

/* ================================================================
 * Main — sudtrace launcher
 * ================================================================ */

int main(int argc, char **argv)
{
    init_wrapper_paths(argv[0]);

    /* Parse options */
    const char *outfile = NULL;
    int cmd_start = -1;
    int no_env = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            cmd_start = i + 1;
            break;
        }
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outfile = argv[++i];
        } else if (strcmp(argv[i], "--no-env") == 0) {
            no_env = 1;
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
        } else {
            cmd_start = i;
            break;
        }
    }

    if (cmd_start < 0 || cmd_start >= argc)
        usage(argv[0]);

    /* Setup output */
    if (outfile) {
        char abs_out[PATH_MAX];
        make_absolute_path(outfile, abs_out, sizeof(abs_out));
        int ofd = open(abs_out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (ofd < 0) { perror("sudtrace: open output"); exit(1); }
        g_out_fd = ofd;
        setenv(SUDTRACE_OUTFILE_ENV, abs_out, 1);
    } else {
        g_out_fd = STDOUT_FILENO;
        unsetenv(SUDTRACE_OUTFILE_ENV);
    }

    /* Move output to a high fd so children don't clobber it */
    {
        int high_fd = dup2(g_out_fd, SUD_OUTPUT_FD);
        if (high_fd >= 0) {
            if (g_out_fd != STDOUT_FILENO && g_out_fd != STDERR_FILENO)
                close(g_out_fd);
            g_out_fd = high_fd;
            /* NOT FD_CLOEXEC: wrapper child inherits the fd */
        }
    }

    /* Build wrapper command */
    int cmd_argc = argc - cmd_start;
    char **exec_argv = build_wrapper_argv(cmd_argc, argv + cmd_start, no_env);
    if (!exec_argv) {
        fprintf(stderr, "sudtrace: failed to build wrapper command\n");
        exit(1);
    }

    /* Fork the child */
    pid_t child = fork();
    if (child < 0) { perror("sudtrace: fork"); exit(1); }

    if (child == 0) {
        execv(exec_argv[0], exec_argv);
        perror("sudtrace: exec");
        _exit(127);
    }

    /* Free exec_argv */
    for (int i = 0; exec_argv[i]; i++)
        free(exec_argv[i]);
    free(exec_argv);

    /* Main wait loop — emit EXIT events for reaped children */
    for (;;) {
        int wstatus;
        pid_t wpid = waitpid(-1, &wstatus, __WALL);
        if (wpid < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            pid_t tgid = get_tgid_for(wpid);
            if (wpid == tgid || wpid == child)
                emit_exit(wpid, wstatus);

            if (wpid == child) break;
        }
    }

    if (g_out_fd >= 0 && g_out_fd != STDOUT_FILENO &&
        g_out_fd != STDERR_FILENO)
        close(g_out_fd);

    return 0;
}
