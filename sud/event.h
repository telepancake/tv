/*
 * sud/event.h — Wire-format event emission for sudtrace.
 *
 * Emits events in the binary wire format defined by wire/wire.h.
 * All emit_* functions are async-signal-safe: raw syscalls only,
 * static buffers, cross-process spinlock on a shared mmap page
 * (so `ev_state` deltas stay coherent across traced children).
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

/* Reserve two high FDs so children are unlikely to clobber them.
 *   SUD_OUTPUT_FD : the wire output file.
 *   SUD_STATE_FD  : a MAP_SHARED anonymous page holding the
 *                   cross-process emit spinlock + the shared ev_state. */
#define SUD_OUTPUT_FD        1023
#define SUD_STATE_FD         1022
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
 * Wire setup — must be called once per process after g_out_fd is set.
 *
 * sud_wire_init():
 *   Map SUD_STATE_FD as MAP_SHARED so the encoder's ev_state is
 *   shared across every traced child. Falls back to a process-local
 *   state if the FD isn't set up (stand-alone wrapper runs).
 * ================================================================ */
void sud_wire_init(void);

/* ================================================================
 * Proc helpers
 * ================================================================ */
ssize_t read_proc_raw(pid_t pid, const char *name, char *buf, size_t bufsz);
char   *read_proc_exe(pid_t pid, char *buf, size_t bufsz);
char   *read_proc_cwd(pid_t pid, char *buf, size_t bufsz);
pid_t   get_ppid(pid_t pid);
pid_t   get_tgid(pid_t pid);

/* ================================================================
 * Event emission (public API — callers unchanged from the JSONL era)
 * ================================================================ */
void emit_cwd_event(pid_t pid);
void emit_exec_event(pid_t pid, const char *fallback_exe,
                     int fallback_argc, char **fallback_argv);
void emit_inherited_open_for_fd(pid_t pid, pid_t tgid, pid_t ppid,
                                struct timespec *ts, int fd_num);
void emit_inherited_open_events(pid_t pid);
void emit_open_event(pid_t pid, const char *path, int flags, long fd_or_err);
void emit_unlink_event(pid_t pid, const char *path, long ret);
void emit_write_event(pid_t pid, const char *stream,
                      const void *data_buf, size_t count);
void emit_exit_event(pid_t pid, int status);

/* ================================================================
 * STDOUT filtering
 * ================================================================ */
int fd1_is_creator_stdout(pid_t pid);

#endif /* SUD_EVENT_H */
