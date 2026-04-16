/*
 * sud/handler.h — SIGSYS signal handler and SUD setup for sudtrace.
 *
 * Declares the core signal handler that intercepts all syscalls via
 * Syscall User Dispatch, plus the helper functions for installing
 * the handler and preparing child processes.
 */

#ifndef SUD_HANDLER_H
#define SUD_HANDLER_H

#include "sud/libc.h"

/* ================================================================
 * SUD selector globals
 *
 * The selector byte controls whether the kernel delivers SIGSYS for
 * syscalls outside the allowed IP range.  It lives in a dedicated
 * mmap page so it survives the loaded binary's glibc TLS
 * re-initialisation.
 * ================================================================ */
extern volatile unsigned char  sud_selector_storage;
extern volatile unsigned char *g_sud_selector_ptr;

#define sud_selector (*g_sud_selector_ptr)

/* ================================================================
 * kernel_sigaction_raw — raw kernel sigaction structure.
 *
 * This matches the kernel's struct sigaction layout (not glibc's),
 * used with the raw rt_sigaction syscall.
 * ================================================================ */
struct kernel_sigaction_raw {
    void (*handler)(int);
    unsigned long flags;
    void (*restorer)(void);
    sud_sigset_word_t mask;
};

/* ================================================================
 * UC_* macros — access ucontext register state by architecture.
 * ================================================================ */
#if defined(__x86_64__)
#define UC_SYSCALL_NR(uc) ((long)(uc)->uc_mcontext.gregs[REG_RAX])
#define UC_ARG0(uc) ((long)(uc)->uc_mcontext.gregs[REG_RDI])
#define UC_ARG1(uc) ((long)(uc)->uc_mcontext.gregs[REG_RSI])
#define UC_ARG2(uc) ((long)(uc)->uc_mcontext.gregs[REG_RDX])
#define UC_ARG3(uc) ((long)(uc)->uc_mcontext.gregs[REG_R10])
#define UC_ARG4(uc) ((long)(uc)->uc_mcontext.gregs[REG_R8])
#define UC_ARG5(uc) ((long)(uc)->uc_mcontext.gregs[REG_R9])
#define UC_SET_RET(uc, v) ((uc)->uc_mcontext.gregs[REG_RAX] = (v))
#else
#define UC_SYSCALL_NR(uc) ((long)(uc)->uc_mcontext.gregs[REG_EAX])
#define UC_ARG0(uc) ((long)(uc)->uc_mcontext.gregs[REG_EBX])
#define UC_ARG1(uc) ((long)(uc)->uc_mcontext.gregs[REG_ECX])
#define UC_ARG2(uc) ((long)(uc)->uc_mcontext.gregs[REG_EDX])
#define UC_ARG3(uc) ((long)(uc)->uc_mcontext.gregs[REG_ESI])
#define UC_ARG4(uc) ((long)(uc)->uc_mcontext.gregs[REG_EDI])
#define UC_ARG5(uc) ((long)(uc)->uc_mcontext.gregs[REG_EBP])
#define UC_SET_RET(uc, v) ((uc)->uc_mcontext.gregs[REG_EAX] = (v))
#endif

/* ================================================================
 * Function declarations
 * ================================================================ */
void install_sigsys_handler_raw(void);
void reset_sigmask_raw(void);
void reenable_sud_in_child(void);
void prepare_child_sud(void);
void sigsys_handler(int sig, siginfo_t *info, void *uctx_raw);

#endif /* SUD_HANDLER_H */
