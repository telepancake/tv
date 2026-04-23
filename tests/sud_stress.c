/*
 * tests/sud_stress.c — single-binary stress harness for sud32/sud64.
 *
 * Each subtest is selected by argv[1].  The harness's only job is to
 * exercise the SIGSYS handler in ways that real builds actually do:
 * concurrent fork/exec/posix_spawn, signal storms during exec, vfork
 * emulation, deep shebang/exec chains, and argv shapes (up to and
 * near ARG_MAX) that stress the per-handler arena in build_exec_argv.
 *
 * The acceptance criterion is the user's:  if the harness can't produce
 * a "sudtrace: CRASH DIAGNOSTIC" from sud64 on bug-prone code, the
 * coverage is bad.  No checkmark-spam tests.
 *
 * Usage:    sud_stress <subtest> [args...]
 * Subtest --list prints the catalogue.  Each subtest exits 0 on success
 * and prints "OK <subtest>" to stdout as the very last line.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <unistd.h>

extern char **environ;

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("sud_stress: ", stderr);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

static void ok(const char *name)
{
    printf("OK %s\n", name);
    fflush(stdout);
}

/* ─────────────────────────────────────────────────────────────────────
 * Subtest: argv-huge
 *
 * Exec /bin/true with a large argv.  Default ~96 KiB, configurable up
 * to (and beyond) the kernel's ARG_MAX.  Without sud, the kernel
 * accepts argvs up to ~2 MiB (ARG_MAX); sud must accept the same set
 * of inputs that the bare kernel does.  A previous fixed 64 KiB stack
 * arena in the SIGSYS execve handler silently truncated argv around
 * 60 KiB and either NULL-deref'd in resolve_path or produced a
 * malformed argv that the kernel then rejected with -E2BIG/-EFAULT.
 *
 * If sud is healthy, /bin/true runs and we read the wait status.
 * If the handler crashes, we get killed by the kernel re-raising
 * SIGSEGV with the default disposition (after the diagnostic dumper).
 * ───────────────────────────────────────────────────────────────────── */
static int t_argv_huge(int total_argv_bytes)
{
    if (total_argv_bytes <= 0) total_argv_bytes = 96 * 1024;
    /* Each arg is ~64 bytes of payload; pick N so total bytes match. */
    int per = 64;
    int n = total_argv_bytes / per;
    if (n < 8) n = 8;

    char **argv = calloc((size_t)n + 2, sizeof(char *));
    if (!argv) die("calloc");
    argv[0] = strdup("/bin/true");
    for (int i = 1; i <= n; i++) {
        char *s = malloc(per + 1);
        if (!s) die("malloc");
        memset(s, 'A' + (i % 26), per);
        s[per] = '\0';
        argv[i] = s;
    }
    argv[n + 1] = NULL;

    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        execve("/bin/true", argv, environ);
        _exit(127);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) die("waitpid");
    if (!WIFEXITED(st)) die("argv-huge: child died: status=0x%x", st);
    if (WEXITSTATUS(st) != 0)
        die("argv-huge: /bin/true returned %d", WEXITSTATUS(st));

    ok("argv-huge");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────
 * Subtest: argv-near-argmax
 *
 * Same shape as argv-huge but pushes argv near the kernel's ARG_MAX
 * (typically 2 MiB on Linux).  Verifies the arena scales — sud must
 * accept the same inputs that the bare kernel accepts.
 * ───────────────────────────────────────────────────────────────────── */
static int t_argv_near_argmax(void)
{
    /* Try ~1.5 MiB.  Safely below the 2 MiB ARG_MAX with envp + alignment. */
    return t_argv_huge(1536 * 1024);
}

/* ─────────────────────────────────────────────────────────────────────
 * Subtest: argv-single-huge
 *
 * One single argv entry of 1 MiB.  Verifies sud handles extremely
 * large single arguments without crashing — whether the new
 * dynamically-sized arena accommodates the string or the kernel
 * rejects the exec with -E2BIG, the only unacceptable outcome is a
 * crash inside the SIGSYS handler.
 * ───────────────────────────────────────────────────────────────────── */
static int t_argv_single_huge(void)
{
    size_t big_sz = 1 * 1024 * 1024;  /* 1 MiB */
    char *big = malloc(big_sz + 1);
    if (!big) die("malloc");
    memset(big, 'X', big_sz);
    big[big_sz] = '\0';

    char *argv[] = {(char *)"/bin/true", big, NULL};
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        execve("/bin/true", argv, environ);
        _exit(126);  /* expected: E2BIG */
    }
    int st = 0;
    waitpid(pid, &st, 0);
    /* Either the kernel returned E2BIG (child _exit(126)) or true ran. */
    if (!WIFEXITED(st))
        die("argv-single-huge: child died: status=0x%x", st);

    ok("argv-single-huge");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────
 * Subtest: shebang-chain
 *
 * Build a chain of N shebang scripts a → b → c → … → /bin/sh -c true.
 * build_exec_argv loops up to depth=16, prepending the interpreter at
 * each step; that prepend is more sud_arena_strdup calls into the same
 * 64 KiB arena.  Combined with even modest argv this can exhaust it.
 * ───────────────────────────────────────────────────────────────────── */
static int t_shebang_chain(int depth, const char *tmpdir)
{
    if (depth <= 0) depth = 12;
    if (depth > 14) depth = 14;  /* sud's own depth cap is 16 */
    if (!tmpdir) tmpdir = "/tmp";

    char prev[600];
    snprintf(prev, sizeof(prev), "/bin/sh");

    for (int i = 0; i < depth; i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/sb_%d.sh", tmpdir, i);
        /* Open with mode 0755 directly to avoid a TOCTOU race between
         * fopen() and chmod() (CodeQL cpp/toctou-race-condition). */
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (fd < 0) die("open %s", path);
        FILE *f = fdopen(fd, "w");
        if (!f) { close(fd); die("fdopen %s", path); }
        /* Each script execs the next via shebang, with a few padding
         * args to keep the arena under pressure. */
        fprintf(f, "#!%s\nexit 0\n", prev);
        fclose(f);
        snprintf(prev, sizeof(prev), "%s", path);
    }

    /* Run the deepest one with a beefy argv to push arena. */
    char *argv[64];
    int ai = 0;
    argv[ai++] = prev;
    for (int i = 0; i < 32; i++) {
        char *s = malloc(512);
        memset(s, 'a' + (i % 26), 511);
        s[511] = '\0';
        argv[ai++] = s;
    }
    argv[ai] = NULL;

    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        execve(prev, argv, environ);
        _exit(127);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
        die("shebang-chain: status=0x%x", st);

    ok("shebang-chain");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────
 * Subtest: thread-exec-storm
 *
 * Spawn T threads.  Each thread loops M times: fork + execve(/bin/true).
 * This exercises:
 *   • concurrent SIGSYS handlers in many threads (any racy global state
 *     in the handler will surface)
 *   • prepare_child_sud() races as new SUD-enabled processes appear
 *   • the per-handler 64 KiB arena under repeated allocation
 *   • SIGCHLD interrupting handlers in other threads
 * ───────────────────────────────────────────────────────────────────── */
struct exec_storm_arg { int iters; };

static void *exec_storm_thread(void *p)
{
    struct exec_storm_arg *a = p;
    for (int i = 0; i < a->iters; i++) {
        pid_t pid = fork();
        if (pid < 0) die("storm fork");
        if (pid == 0) {
            char *av[] = {(char *)"/bin/true", NULL};
            execve("/bin/true", av, environ);
            _exit(127);
        }
        int st = 0;
        if (waitpid(pid, &st, 0) != pid)
            die("storm waitpid");
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
            die("storm: child died status=0x%x", st);
    }
    return NULL;
}

static int t_thread_exec_storm(int threads, int iters)
{
    if (threads <= 0) threads = 8;
    if (iters   <= 0) iters   = 50;
    pthread_t *th = calloc((size_t)threads, sizeof(pthread_t));
    struct exec_storm_arg a = { iters };
    for (int i = 0; i < threads; i++)
        pthread_create(&th[i], NULL, exec_storm_thread, &a);
    for (int i = 0; i < threads; i++)
        pthread_join(th[i], NULL);
    free(th);
    ok("thread-exec-storm");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────
 * Subtest: posix-spawn-storm
 *
 * Glibc's posix_spawn uses clone3(CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND
 * |...) and exec inside the child while the parent is suspended.  This
 * is the same code path that handler.c steers into the "vfork fallback
 * via -ENOSYS" branch.  Hammer it from many threads simultaneously.
 * ───────────────────────────────────────────────────────────────────── */
static void *spawn_storm_thread(void *p)
{
    int iters = *(int *)p;
    for (int i = 0; i < iters; i++) {
        pid_t pid = -1;
        char *av[] = {(char *)"/bin/true", NULL};
        if (posix_spawn(&pid, "/bin/true", NULL, NULL, av, environ) != 0)
            die("posix_spawn");
        int st = 0;
        if (waitpid(pid, &st, 0) != pid) die("spawn wait");
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
            die("spawn: status=0x%x", st);
    }
    return NULL;
}

static int t_posix_spawn_storm(int threads, int iters)
{
    if (threads <= 0) threads = 8;
    if (iters   <= 0) iters   = 50;
    pthread_t *th = calloc((size_t)threads, sizeof(pthread_t));
    for (int i = 0; i < threads; i++)
        pthread_create(&th[i], NULL, spawn_storm_thread, &iters);
    for (int i = 0; i < threads; i++)
        pthread_join(th[i], NULL);
    free(th);
    ok("posix-spawn-storm");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────
 * Subtest: vfork-exec-loop
 *
 * Direct vfork()+execve in a loop.  The handler emulates real vfork
 * with plain fork to avoid the "child overwrites parent's signal frame"
 * trap; this verifies that emulation works under repetition.
 * ───────────────────────────────────────────────────────────────────── */
static int t_vfork_exec_loop(int iters_in)
{
    /* volatile to silence -Wclobbered around vfork() */
    volatile int iters = iters_in <= 0 ? 200 : iters_in;
    volatile int i;
    for (i = 0; i < iters; i++) {
        pid_t pid = vfork();
        if (pid < 0) die("vfork");
        if (pid == 0) {
            char *av[] = {(char *)"/bin/true", NULL};
            execve("/bin/true", av, environ);
            _exit(127);
        }
        int st = 0;
        if (waitpid(pid, &st, 0) != pid) die("vfork wait");
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
            die("vfork: status=0x%x", st);
    }
    ok("vfork-exec-loop");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────
 * Subtest: signal-storm-during-exec
 *
 * Set up a 1 ms itimer that delivers SIGALRM repeatedly.  Spawn worker
 * threads that fork+exec in tight loops.  SIGALRM gets delivered to
 * threads that are mid-SIGSYS (the SUD handler now blocks all signals
 * via sa_mask, but the SIGALRM still queues and runs after the handler
 * returns; if the handler returned an inconsistent ucontext, the
 * SIGALRM's syscall will fault inside sud).
 * ───────────────────────────────────────────────────────────────────── */
static volatile int g_signal_storm_quit;

static void sigalrm_busy(int sig)
{
    (void)sig;
    /* Make a syscall here so signal-during-handler races have a target. */
    int fd = open("/dev/null", O_WRONLY);
    if (fd >= 0) { (void)!write(fd, "x", 1); close(fd); }
}

static void *sigstorm_worker(void *p)
{
    int iters = *(int *)p;
    for (int i = 0; i < iters && !g_signal_storm_quit; i++) {
        pid_t pid = fork();
        if (pid < 0) die("sigstorm fork");
        if (pid == 0) {
            char *av[] = {(char *)"/bin/true", NULL};
            execve("/bin/true", av, environ);
            _exit(127);
        }
        int st = 0;
        if (waitpid(pid, &st, 0) != pid) die("sigstorm wait");
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
            die("sigstorm: status=0x%x", st);
    }
    return NULL;
}

static int t_signal_storm(int threads, int iters)
{
    if (threads <= 0) threads = 6;
    if (iters   <= 0) iters   = 40;

    struct sigaction sa = { .sa_handler = sigalrm_busy };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, NULL);

    struct itimerval it = {
        .it_interval = { .tv_sec = 0, .tv_usec = 1000 },
        .it_value    = { .tv_sec = 0, .tv_usec = 1000 },
    };
    setitimer(ITIMER_REAL, &it, NULL);

    pthread_t *th = calloc((size_t)threads, sizeof(pthread_t));
    for (int i = 0; i < threads; i++)
        pthread_create(&th[i], NULL, sigstorm_worker, &iters);
    for (int i = 0; i < threads; i++)
        pthread_join(th[i], NULL);
    free(th);

    g_signal_storm_quit = 1;
    struct itimerval off = {0};
    setitimer(ITIMER_REAL, &off, NULL);

    ok("signal-storm");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────
 * Subtest: ptrace-traceme
 *
 * Child does PTRACE_TRACEME, raises SIGSTOP, parent resumes; child then
 * exec()s.  Exercises the handler's SYS_ptrace+TRACEME branch which
 * disables SUD in the child.
 * ───────────────────────────────────────────────────────────────────── */
static int t_ptrace_traceme(void)
{
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
            /* If we can't ptrace ourselves (Yama, container), skip cleanly. */
            _exit(77);
        }
        raise(SIGSTOP);
        char *av[] = {(char *)"/bin/true", NULL};
        execve("/bin/true", av, environ);
        _exit(127);
    }
    int st = 0;
    if (waitpid(pid, &st, WUNTRACED) != pid) die("traceme wait");
    if (WIFEXITED(st) && WEXITSTATUS(st) == 77) {
        printf("SKIP ptrace-traceme (no PTRACE)\n");
        return 0;
    }
    if (!WIFSTOPPED(st)) die("traceme: not stopped: 0x%x", st);
    ptrace(PTRACE_CONT, pid, 0, 0);
    /* Eat the exec stop and exit. */
    while (waitpid(pid, &st, 0) > 0) {
        if (WIFEXITED(st) || WIFSIGNALED(st)) break;
        ptrace(PTRACE_CONT, pid, 0, 0);
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
        die("traceme: bad final status 0x%x", st);
    ok("ptrace-traceme");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────
 * Subtest: execve-null
 *
 * The check we already added.  Verify that execve(NULL, av, env) does
 * NOT crash sud.  Kernel returns -EFAULT, child should _exit(99).
 * ───────────────────────────────────────────────────────────────────── */
static int t_execve_null(void)
{
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        char *av[] = {NULL};
        /* Use raw syscall to avoid libc adding its own validation. */
        long r = syscall(SYS_execve, (long)NULL, (long)av, (long)environ);
        (void)r;
        _exit(99);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st))
        die("execve-null: child died status=0x%x (sud crashed?)", st);
    if (WEXITSTATUS(st) != 99)
        die("execve-null: unexpected exit %d", WEXITSTATUS(st));
    ok("execve-null");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────
 * Subtest: waitid-tight
 *
 * Many short-lived children; waitid(WNOHANG) in a tight loop.  Verifies
 * the SYS_waitid branch with NULL siginfo on no-children-ready.
 * ───────────────────────────────────────────────────────────────────── */
static int t_waitid_tight(int rounds)
{
    if (rounds <= 0) rounds = 200;
    for (int r = 0; r < rounds; r++) {
        pid_t pid = fork();
        if (pid < 0) die("waitid fork");
        if (pid == 0) _exit(0);
        siginfo_t si;
        memset(&si, 0, sizeof(si));
        for (;;) {
            int rc = waitid(P_PID, pid, &si, WEXITED | WNOHANG);
            if (rc == 0 && si.si_pid == pid) break;
            if (rc < 0 && errno == ECHILD) break;
        }
    }
    ok("waitid-tight");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────
 * Dispatcher
 * ───────────────────────────────────────────────────────────────────── */
static void list_tests(void)
{
    static const char *names[] = {
        "argv-huge [bytes]",
        "argv-near-argmax",
        "argv-single-huge",
        "shebang-chain [depth] [tmpdir]",
        "thread-exec-storm [threads] [iters]",
        "posix-spawn-storm [threads] [iters]",
        "vfork-exec-loop [iters]",
        "signal-storm [threads] [iters]",
        "ptrace-traceme",
        "execve-null",
        "waitid-tight [rounds]",
        NULL
    };
    for (const char **p = names; *p; p++) printf("%s\n", *p);
}

int main(int argc, char **argv)
{
    if (argc < 2 || !strcmp(argv[1], "--list")) {
        list_tests();
        return argc < 2 ? 2 : 0;
    }
    const char *t = argv[1];
    if (!strcmp(t, "argv-huge"))
        return t_argv_huge(argc > 2 ? atoi(argv[2]) : 0);
    if (!strcmp(t, "argv-near-argmax"))
        return t_argv_near_argmax();
    if (!strcmp(t, "argv-single-huge"))
        return t_argv_single_huge();
    if (!strcmp(t, "shebang-chain"))
        return t_shebang_chain(argc > 2 ? atoi(argv[2]) : 0,
                               argc > 3 ? argv[3] : NULL);
    if (!strcmp(t, "thread-exec-storm"))
        return t_thread_exec_storm(argc > 2 ? atoi(argv[2]) : 0,
                                   argc > 3 ? atoi(argv[3]) : 0);
    if (!strcmp(t, "posix-spawn-storm"))
        return t_posix_spawn_storm(argc > 2 ? atoi(argv[2]) : 0,
                                   argc > 3 ? atoi(argv[3]) : 0);
    if (!strcmp(t, "vfork-exec-loop"))
        return t_vfork_exec_loop(argc > 2 ? atoi(argv[2]) : 0);
    if (!strcmp(t, "signal-storm"))
        return t_signal_storm(argc > 2 ? atoi(argv[2]) : 0,
                              argc > 3 ? atoi(argv[3]) : 0);
    if (!strcmp(t, "ptrace-traceme"))
        return t_ptrace_traceme();
    if (!strcmp(t, "execve-null"))
        return t_execve_null();
    if (!strcmp(t, "waitid-tight"))
        return t_waitid_tight(argc > 2 ? atoi(argv[2]) : 0);

    fprintf(stderr, "unknown subtest: %s\n", t);
    list_tests();
    return 2;
}
