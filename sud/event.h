/*
 * sud/event.h — JSONL event formatting and emission for sudtrace.
 *
 * Declares the globals, constants, and functions used to emit
 * structured JSONL trace events (EXEC, OPEN, CWD, STDOUT, STDERR,
 * EXIT, etc.) from both the SIGSYS signal handler and the startup
 * path.  All emit functions are async-signal-safe: they use only
 * raw syscalls, static buffers, and a spinlock for serialisation.
 */

#ifndef SUD_EVENT_H
#define SUD_EVENT_H

#include "sud/libc.h"

/* ================================================================
 * Constants
 * ================================================================ */
#define WRITE_CAPTURE_MAX    4096
#define ARGV_MAX_READ        32768
#define ENV_MAX_READ         65536
#define LINE_MAX_BUF         (PATH_MAX * 8 + 262144 + 1024)

/* Reserve a high FD for our output so children are unlikely to clobber it */
#define SUD_OUTPUT_FD        1023
#define SUDTRACE_OUTFILE_ENV "SUDTRACE_OUTFILE"

/* ================================================================
 * Extern globals
 * ================================================================ */
extern int        g_out_fd;
extern stat_buf_t g_creator_stdout_stbuf;
extern int        g_creator_stdout_valid;
extern char       g_self_exe[PATH_MAX];
extern char       g_self_exe32[PATH_MAX];
extern char       g_self_exe64[PATH_MAX];
extern char       g_target_exe[PATH_MAX];
extern char      *g_path_env;
extern int        g_trace_exec_env;

/* ================================================================
 * JSON helpers
 * ================================================================ */
int json_escape(char *dst, int dstsize, const char *src, int srclen);
int json_argv_array(char *dst, int dstsize, const char *raw, int rawlen);
int json_argv_array_vec(char *dst, int dstsize, char *const *argv, int argc);
int json_env_object(char *dst, int dstsize, const char *raw, int rawlen);
int json_open_flags(int flags, char *buf, int buflen);
int json_header(char *buf, int buflen, const char *event,
                pid_t pid, pid_t tgid, pid_t ppid,
                struct timespec *ts);

/* ================================================================
 * Proc helpers
 * ================================================================ */
ssize_t read_proc_raw(pid_t pid, const char *name, char *buf, size_t bufsz);
char   *read_proc_exe(pid_t pid, char *buf, size_t bufsz);
char   *read_proc_cwd(pid_t pid, char *buf, size_t bufsz);
pid_t   get_ppid(pid_t pid);
pid_t   get_tgid(pid_t pid);

/* ================================================================
 * Event emission
 * ================================================================ */
void emit_cwd_event(pid_t pid);
void emit_exec_event(pid_t pid, const char *fallback_exe,
                     int fallback_argc, char **fallback_argv);
void emit_inherited_open_for_fd(pid_t pid, pid_t tgid, pid_t ppid,
                                struct timespec *ts, int fd_num);
void emit_inherited_open_events(pid_t pid);
void emit_open_event(pid_t pid, const char *path, int flags, long fd_or_err);
void emit_write_event(pid_t pid, const char *stream,
                      const void *data_buf, size_t count);
void emit_exit_event(pid_t pid, int status);

/* ================================================================
 * STDOUT filtering
 * ================================================================ */
int fd1_is_creator_stdout(pid_t pid);

#endif /* SUD_EVENT_H */
