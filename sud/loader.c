/*
 * sud/loader.c — In-process ELF loader.
 *
 * Loads a target ELF binary into memory, sets up SUD, and jumps
 * to its entry point.  Used by wrapper mode (sud32/sud64).
 */

#include "sud/libc.h"
#include "sud/raw.h"
#include "sud/fmt.h"
#include "sud/event.h"
#include "sud/elf.h"
#include "sud/handler.h"
#include "sud/loader.h"
#include "deps/printf/printf.h"

void load_and_run_elf(const char *path, int argc, char **argv,
                      int drop_count)
{
    /* Compute the visible argv (what the target process should see) */
    int vis_argc = argc - drop_count;
    char **vis_argv = argv + drop_count;
    if (vis_argc < 0) vis_argc = 0;

    /* Record the target program's resolved path so the SIGSYS handler can
     * mask /proc/self/exe and other identity queries. */
    {
        const char *tgt = (vis_argc > 0 && vis_argv[0]) ? vis_argv[0] : path;
        char tgt_resolved[PATH_MAX];
        if (resolve_path(tgt, tgt_resolved, sizeof(tgt_resolved)))
            snprintf_(g_target_exe, sizeof(g_target_exe), "%s", tgt_resolved);
        else
            snprintf_(g_target_exe, sizeof(g_target_exe), "%s", tgt);
    }

    pid_t self = raw_gettid();
    const char *event_exe = (vis_argc > 0 && vis_argv[0]) ? vis_argv[0] : path;
    emit_cwd_event(self);
    emit_exec_event(self, event_exe, vis_argc, vis_argv);
    emit_inherited_open_events(self);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("sudtrace: open ELF");
        _exit(127);
    }

    sud_elf_ehdr_t ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != (ssize_t)sizeof(ehdr)) {
        fprintf(stderr, "sudtrace: cannot read ELF header\n");
        close(fd);
        _exit(127);
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != SUD_NATIVE_ELF_CLASS) {
        fprintf(stderr, "sudtrace: not a valid native ELF for %s: %s\n",
                SUD_VARIANT_NAME, path);
        close(fd);
        _exit(127);
    }

    /* For PIE/ET_DYN binaries (e.g. ld.so), p_vaddr starts at 0.
     * We need to pick a base address because mmap(0, ..., MAP_FIXED) fails
     * due to vm.mmap_min_addr.  For ET_EXEC, base stays 0 (use as-is). */
    unsigned long load_base = 0;
    if (ehdr.e_type == ET_DYN) {
        unsigned long lo = ~0UL, hi = 0;
        for (int i = 0; i < ehdr.e_phnum; i++) {
            sud_elf_phdr_t phdr;
            if (pread(fd, &phdr, sizeof(phdr),
                      ehdr.e_phoff + i * ehdr.e_phentsize) != (ssize_t)sizeof(phdr))
                continue;
            if (phdr.p_type != PT_LOAD) continue;
            unsigned long seg_lo = phdr.p_vaddr & ~0xfffUL;
            unsigned long seg_hi = (phdr.p_vaddr + phdr.p_memsz + 0xfff)
                                    & ~0xfffUL;
            if (seg_lo < lo) lo = seg_lo;
            if (seg_hi > hi) hi = seg_hi;
        }
        if (hi > lo) {
            void *hint = mmap(NULL, hi - lo, PROT_NONE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (hint == MAP_FAILED) {
                fprintf(stderr, "sudtrace: cannot reserve %lu bytes for PIE\n",
                        hi - lo);
                close(fd);
                _exit(127);
            }
            load_base = (unsigned long)hint - lo;
            munmap(hint, hi - lo);
        }
    }

    /* Load PT_LOAD segments */
    for (int i = 0; i < ehdr.e_phnum; i++) {
        sud_elf_phdr_t phdr;
        if (pread(fd, &phdr, sizeof(phdr),
                  ehdr.e_phoff + i * ehdr.e_phentsize) != (ssize_t)sizeof(phdr))
            continue;

        if (phdr.p_type != PT_LOAD) continue;

        unsigned long vaddr = load_base + phdr.p_vaddr;
        unsigned long page_offset = vaddr & 0xfff;
        unsigned long map_addr = vaddr - page_offset;
        unsigned long map_size = phdr.p_memsz + page_offset;
        map_size = (map_size + 0xfff) & ~0xfffUL;

        int prot = 0;
        if (phdr.p_flags & PF_R) prot |= PROT_READ;
        if (phdr.p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr.p_flags & PF_X) prot |= PROT_EXEC;

        void *mapped = mmap((void *)map_addr, map_size,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                           -1, 0);
        if (mapped == MAP_FAILED) {
            fprintf(stderr, "sudtrace: mmap segment at %#lx: %s\n",
                    map_addr, strerror(errno));
            close(fd);
            _exit(127);
        }

        if (phdr.p_filesz > 0) {
            if (pread(fd, (char *)mapped + page_offset, phdr.p_filesz,
                      phdr.p_offset) != (ssize_t)phdr.p_filesz) {
                fprintf(stderr, "sudtrace: failed to read segment\n");
                close(fd);
                _exit(127);
            }
        }

        mprotect(mapped, map_size, prot);
    }

    /* If drop_count > 0, the primary ELF is an intermediate loader
     * (ld-linux) and we also need to load the target program. */
    unsigned long target_load_base = 0;
    sud_elf_ehdr_t target_ehdr;
    unsigned long target_phdr_addr = 0;
    int target_fd = -1;
    memset(&target_ehdr, 0, sizeof(target_ehdr));

    if (drop_count > 0 && vis_argc > 0 && vis_argv[0]) {
        char target_resolved[PATH_MAX];
        const char *target_name = vis_argv[0];
        if (!resolve_path(target_name, target_resolved, sizeof(target_resolved)))
            snprintf_(target_resolved, sizeof(target_resolved), "%s", target_name);

        target_fd = open(target_resolved, O_RDONLY);
        if (target_fd >= 0) {
            if (read(target_fd, &target_ehdr, sizeof(target_ehdr)) == (ssize_t)sizeof(target_ehdr) &&
                memcmp(target_ehdr.e_ident, ELFMAG, SELFMAG) == 0 &&
                target_ehdr.e_ident[EI_CLASS] == SUD_NATIVE_ELF_CLASS) {

                /* Determine target load base */
                if (target_ehdr.e_type == ET_DYN) {
                    unsigned long lo = ~0UL, hi = 0;
                    for (int i = 0; i < target_ehdr.e_phnum; i++) {
                        sud_elf_phdr_t phdr;
                        if (pread(target_fd, &phdr, sizeof(phdr),
                                  target_ehdr.e_phoff + i * target_ehdr.e_phentsize) != (ssize_t)sizeof(phdr))
                            continue;
                        if (phdr.p_type != PT_LOAD) continue;
                        unsigned long seg_lo = phdr.p_vaddr & ~0xfffUL;
                        unsigned long seg_hi = (phdr.p_vaddr + phdr.p_memsz + 0xfff)
                                                & ~0xfffUL;
                        if (seg_lo < lo) lo = seg_lo;
                        if (seg_hi > hi) hi = seg_hi;
                    }
                    if (hi > lo) {
                        void *hint = mmap(NULL, hi - lo, PROT_NONE,
                                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                        if (hint != MAP_FAILED) {
                            target_load_base = (unsigned long)hint - lo;
                            munmap(hint, hi - lo);
                        }
                    }
                }

                /* Load target PT_LOAD segments */
                for (int i = 0; i < target_ehdr.e_phnum; i++) {
                    sud_elf_phdr_t phdr;
                    if (pread(target_fd, &phdr, sizeof(phdr),
                              target_ehdr.e_phoff + i * target_ehdr.e_phentsize) != (ssize_t)sizeof(phdr))
                        continue;
                    if (phdr.p_type != PT_LOAD) continue;

                    unsigned long vaddr = target_load_base + phdr.p_vaddr;
                    unsigned long page_offset = vaddr & 0xfff;
                    unsigned long map_addr = vaddr - page_offset;
                    unsigned long map_size = phdr.p_memsz + page_offset;
                    map_size = (map_size + 0xfff) & ~0xfffUL;

                    int prot = 0;
                    if (phdr.p_flags & PF_R) prot |= PROT_READ;
                    if (phdr.p_flags & PF_W) prot |= PROT_WRITE;
                    if (phdr.p_flags & PF_X) prot |= PROT_EXEC;

                    void *mapped = mmap((void *)map_addr, map_size,
                                       PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                       -1, 0);
                    if (mapped == MAP_FAILED) continue;

                    if (phdr.p_filesz > 0) {
                        pread(target_fd, (char *)mapped + page_offset,
                              phdr.p_filesz, phdr.p_offset);
                    }
                    mprotect(mapped, map_size, prot);
                }

                /* Find target's phdr address in memory */
                for (int i = 0; i < target_ehdr.e_phnum; i++) {
                    sud_elf_phdr_t phdr;
                    if (pread(target_fd, &phdr, sizeof(phdr),
                              target_ehdr.e_phoff + i * target_ehdr.e_phentsize) != (ssize_t)sizeof(phdr))
                        continue;
                    if (phdr.p_type == PT_PHDR) {
                        target_phdr_addr = target_load_base + phdr.p_vaddr;
                        break;
                    }
                }
                if (!target_phdr_addr) {
                    for (int i = 0; i < target_ehdr.e_phnum; i++) {
                        sud_elf_phdr_t phdr;
                        if (pread(target_fd, &phdr, sizeof(phdr),
                                  target_ehdr.e_phoff + i * target_ehdr.e_phentsize) != (ssize_t)sizeof(phdr))
                            continue;
                        if (phdr.p_type == PT_LOAD &&
                            target_ehdr.e_phoff >= phdr.p_offset &&
                            target_ehdr.e_phoff < phdr.p_offset + phdr.p_filesz) {
                            target_phdr_addr = target_load_base + phdr.p_vaddr +
                                               (target_ehdr.e_phoff - phdr.p_offset);
                            break;
                        }
                    }
                }
                if (!target_phdr_addr)
                    target_phdr_addr = target_load_base + target_ehdr.e_phoff;
            } else {
                close(target_fd);
                target_fd = -1;
                drop_count = 0;
                vis_argc = argc;
                vis_argv = argv;
            }
        } else {
            drop_count = 0;
            vis_argc = argc;
            vis_argv = argv;
        }
    }

    /* Install SIGSYS handler */
    install_sigsys_handler_raw();

    /* Allocate SUD selector byte in a dedicated mmap page */
    void *sel_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (sel_page == MAP_FAILED) {
        perror("sudtrace: mmap selector");
        _exit(127);
    }
    volatile unsigned char *sel = (volatile unsigned char *)sel_page;
    *sel = SYSCALL_DISPATCH_FILTER_BLOCK;
    g_sud_selector_ptr = sel;

    reset_sigmask_raw();

    /* Enable SUD */
    unsigned long off = (unsigned long)__sud_begin;
    unsigned long len = (unsigned long)__sud_end - (unsigned long)__sud_begin;

    if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON,
              off, len, (unsigned long)sel) < 0) {
        perror("sudtrace: prctl(PR_SET_SYSCALL_USER_DISPATCH)");
        fprintf(stderr, "  Requires CONFIG_SYSCALL_USER_DISPATCH=y "
                "(Linux 5.11+).\n");
        _exit(127);
    }

    /* Set process name to target basename */
    if (g_target_exe[0]) {
        const char *bn = g_target_exe;
        const char *sl = g_target_exe;
        while (*sl) { if (*sl == '/') bn = sl + 1; sl++; }
        prctl(PR_SET_NAME, (unsigned long)bn, 0, 0, 0);
    }

    /* Build the new stack */
    size_t stack_size = 8 * 1024 * 1024;
    void *stack_base = mmap(NULL, stack_size,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
                           -1, 0);
    if (stack_base == MAP_FAILED) {
        perror("sudtrace: mmap stack");
        _exit(127);
    }

    unsigned long *sp = (unsigned long *)((char *)stack_base + stack_size);

    extern char **environ;
    int envc = 0;
    if (environ)
        while (environ[envc]) envc++;

    int total_slots = 1 + vis_argc + 1 + envc + 1 + 128;
    sp -= total_slots;
    sp = (unsigned long *)((unsigned long)sp & ~0xfUL);

    int idx = 0;
    sp[idx++] = vis_argc;
    for (int i = 0; i < vis_argc; i++)
        sp[idx++] = (unsigned long)vis_argv[i];
    sp[idx++] = 0;
    for (int i = 0; i < envc; i++)
        sp[idx++] = (unsigned long)environ[i];
    sp[idx++] = 0;

    /* Copy auxv, patching relevant entries */
    {
        unsigned long phdr_addr = 0;
        for (int i = 0; i < ehdr.e_phnum; i++) {
            sud_elf_phdr_t phdr;
            if (pread(fd, &phdr, sizeof(phdr),
                      ehdr.e_phoff + i * ehdr.e_phentsize) != (ssize_t)sizeof(phdr))
                continue;
            if (phdr.p_type == PT_PHDR) {
                phdr_addr = load_base + phdr.p_vaddr;
                break;
            }
        }
        if (!phdr_addr) {
            for (int i = 0; i < ehdr.e_phnum; i++) {
                sud_elf_phdr_t phdr;
                if (pread(fd, &phdr, sizeof(phdr),
                          ehdr.e_phoff + i * ehdr.e_phentsize) != (ssize_t)sizeof(phdr))
                    continue;
                if (phdr.p_type == PT_LOAD &&
                    ehdr.e_phoff >= phdr.p_offset &&
                    ehdr.e_phoff < phdr.p_offset + phdr.p_filesz) {
                    phdr_addr = load_base + phdr.p_vaddr +
                                (ehdr.e_phoff - phdr.p_offset);
                    break;
                }
            }
        }
        if (!phdr_addr)
            phdr_addr = load_base + ehdr.e_phoff;

        int use_interp_mode = (drop_count > 0 && target_fd >= 0);

        int aux_fd2 = open("/proc/self/auxv", O_RDONLY);
        if (aux_fd2 >= 0) {
            sud_auxv_t avbuf[64];
            ssize_t n = read(aux_fd2, avbuf, sizeof(avbuf));
            close(aux_fd2);
            if (n > 0) {
                int auxc = n / (int)sizeof(sud_auxv_t);
                for (int i = 0; i < auxc; i++) {
                    if (use_interp_mode) {
                        switch (avbuf[i].a_type) {
                        case AT_ENTRY:
                            avbuf[i].a_un.a_val = target_load_base +
                                                  target_ehdr.e_entry;
                            break;
                        case AT_PHDR:
                            avbuf[i].a_un.a_val = target_phdr_addr;
                            break;
                        case AT_PHNUM:
                            avbuf[i].a_un.a_val = target_ehdr.e_phnum;
                            break;
                        case AT_PHENT:
                            avbuf[i].a_un.a_val = target_ehdr.e_phentsize;
                            break;
                        case AT_BASE:
                            avbuf[i].a_un.a_val = load_base;
                            break;
#ifdef AT_EXECFN
                        case AT_EXECFN:
                            if (g_target_exe[0])
                                avbuf[i].a_un.a_val =
                                    (unsigned long)g_target_exe;
                            break;
#endif
                        }
                    } else {
                        switch (avbuf[i].a_type) {
                        case AT_ENTRY:
                            avbuf[i].a_un.a_val = load_base + ehdr.e_entry;
                            break;
                        case AT_PHDR:
                            avbuf[i].a_un.a_val = phdr_addr;
                            break;
                        case AT_PHNUM:
                            avbuf[i].a_un.a_val = ehdr.e_phnum;
                            break;
                        case AT_PHENT:
                            avbuf[i].a_un.a_val = ehdr.e_phentsize;
                            break;
                        case AT_BASE:
                            avbuf[i].a_un.a_val = 0;
                            break;
#ifdef AT_EXECFN
                        case AT_EXECFN:
                            if (g_target_exe[0])
                                avbuf[i].a_un.a_val =
                                    (unsigned long)g_target_exe;
                            break;
#endif
                        }
                    }

                    sp[idx++] = avbuf[i].a_type;
                    sp[idx++] = avbuf[i].a_un.a_val;

                    if (avbuf[i].a_type == AT_NULL) break;
                }
            }
        }
    }

    close(fd);
    if (target_fd >= 0)
        close(target_fd);

    /* Jump to the entry point */
    unsigned long entry = load_base + ehdr.e_entry;

#if defined(__x86_64__)
    __asm__ volatile(
        "mov %0, %%rsp\n\t"
        "push %1\n\t"
        "xor %%rax, %%rax\n\t"
        "xor %%rbx, %%rbx\n\t"
        "xor %%rcx, %%rcx\n\t"
        "xor %%rdx, %%rdx\n\t"
        "xor %%rsi, %%rsi\n\t"
        "xor %%rdi, %%rdi\n\t"
        "xor %%rbp, %%rbp\n\t"
        "xor %%r8, %%r8\n\t"
        "xor %%r9, %%r9\n\t"
        "xor %%r10, %%r10\n\t"
        "xor %%r11, %%r11\n\t"
        "xor %%r12, %%r12\n\t"
        "xor %%r13, %%r13\n\t"
        "xor %%r14, %%r14\n\t"
        "xor %%r15, %%r15\n\t"
        "ret\n\t"
        :
        : "r"(sp), "r"(entry)
        : "memory"
    );
#else
    __asm__ volatile(
        "mov %0, %%esp\n\t"
        "push %1\n\t"
        "xor %%eax, %%eax\n\t"
        "xor %%ebx, %%ebx\n\t"
        "xor %%ecx, %%ecx\n\t"
        "xor %%edx, %%edx\n\t"
        "xor %%esi, %%esi\n\t"
        "xor %%edi, %%edi\n\t"
        "xor %%ebp, %%ebp\n\t"
        "ret\n\t"
        :
        : "r"(sp), "r"(entry)
        : "memory"
    );
#endif

    __builtin_unreachable();
}
