# Fakeroot Plan — sud/path_remap integration

## 1  Goal and motivation

`fakeroot` allows an unprivileged user to behave *as if* they are root for
filesystem-metadata operations, so that tools like `tar`, `dpkg-deb`, and
`makepkg` can produce archives and packages with correct uid/gid/mode metadata
without requiring a privileged environment.

In the classic Debian `fakeroot` implementation a daemon process holds a
shadow table (path → uid:gid:mode override), and the traced program's libc is
patched via `LD_PRELOAD` to consult the daemon on stat/chown/mknod.  This
approach is fragile (broken by statically-linked binaries, SUID helpers,
`execve` across tool boundaries) and couples the implementation to the C
library ABI.

sud already intercepts every syscall via SUD (Syscall User Dispatch) and owns
the single path-resolution authority in `sud/path_remap/`.  Fakeroot semantics
fit naturally as a new `--remap-rule fakeroot:` rule kind inside path_remap:
the rule is matched by `find_rule()` like any other, no LD_PRELOAD is
involved, and statically-linked binaries are handled automatically.

This document covers two delivery tiers:

| Tier | Name | What it provides |
|------|------|-----------------|
| 1 | Blanket mode | Every path under the prefix appears owned by a fixed uid:gid (default 0:0).  `chown` calls are no-ops.  No shared memory required. |
| 2 | Shadow-table mode | Per-file uid:gid:mode stored in a shared-memory region; `chown`/`chmod` calls update it and survive `fork`/`execve`. |

Tier 1 is sufficient for the most common build use case (`tar -czf` of a
staging tree, `dpkg-deb --build`).  Tier 2 is needed for workflows where the
same tree is `chown`'d to different owners per file (e.g. BSD ports, rpm
`%files` with `%defattr`).  The plan below covers both; each tier is a
self-contained step so Tier 1 can ship first.


---

## 2  CLI syntax

The new rule kind slots into the existing `--remap-rule` flag accepted by
`sud32`/`sud64`:

```
--remap-rule fakeroot:<prefix>[:<uid>:<gid>]
```

- `<prefix>` — absolute path prefix (matched on a component boundary, as with
  the other rule kinds).
- `<uid>:<gid>` — optional; default `0:0`.  When the traced program calls
  `getuid`/`geteuid`/`getgid`/`getegid`, the wrapper returns these values.
  When stat results are patched, `st_uid`/`st_gid` are replaced with these
  values for any file whose absolute path falls under `<prefix>`.

Multiple `--remap-rule fakeroot:` entries with different prefixes are allowed;
`find_rule()` returns the first match (longest-prefix-wins ordering is the
caller's responsibility when ordering matters).

Examples:

```
# Everything under /build/staging looks owned by root:root
--remap-rule fakeroot:/build/staging

# Custom uid:gid
--remap-rule fakeroot:/build/staging:1000:1000
```

`sudtrace` gains a new `--fakeroot <prefix>[:<uid>:<gid>]` option that
translates to the above wrapper flag, mirroring the existing `--remap` and
`--overlay` options.


---

## 3  Rule kind integration in path_remap

### 3.1  Rule struct extension

`overlay.c` already has an internal `struct overlay_rule`.  Add a `kind`
discriminator (it currently infers kind from the field presence); a clean
enum is:

```c
enum sud_pr_rule_kind {
    SUD_PR_PASSTHROUGH = 0,
    SUD_PR_REMAP,
    SUD_PR_OVERLAY,
    SUD_PR_INRAMFS,
    SUD_PR_FAKEROOT,        /* new */
};
```

Add two fields to the rule struct:

```c
uint32_t fake_uid;   /* effective when kind == SUD_PR_FAKEROOT */
uint32_t fake_gid;
```

### 3.2  Rule parsing

In `sud_overlay_init()` (which already parses `--remap-rule` entries from
`g_sud_runtime_config.remap_rules[]`), add a branch for the `fakeroot:`
prefix, parsing the optional `:<uid>:<gid>` suffix.  Absent suffix defaults
to uid=0, gid=0.

### 3.3  find_rule() return value

`find_rule()` (internal to `overlay.c`) currently returns a pointer to an
`overlay_rule` or NULL.  No change needed: the dispatcher checks
`rule->kind == SUD_PR_FAKEROOT` after the lookup and branches accordingly.


---

## 4  Syscall interception

### 4.1  Overview table

| Syscall group | Interception point | Action under fakeroot rule |
|---------------|--------------------|---------------------------|
| `getuid` / `geteuid` / `getgid` / `getegid` / `getresuid` / `getresgid` | pre_syscall — short-circuit | Return `fake_uid` / `fake_gid`; never calls the kernel |
| `setuid` / `setgid` / `seteuid` / `setegid` / `setresuid` / `setresgid` | pre_syscall — short-circuit | Return 0 (success) without calling the kernel |
| `stat` / `lstat` / `fstatat` / `newfstatat` / `fstatat64` / `statx` — **path form** | pre_syscall marks intent; post_syscall patches | Run kernel call normally; post-patch `st_uid`/`st_gid` in the output struct if path matches fakeroot rule |
| `fstat` / `fstat64` — **fd form** | pre_syscall marks intent; post_syscall patches | If the fd was opened against a fakeroot path (see §4.3), post-patch uid/gid |
| `chown` / `lchown` / `fchownat` (path-bearing) | pre_syscall — short-circuit | Tier 1: return 0 without calling kernel.  Tier 2: update shadow table and return 0 |
| `fchown` (fd-bearing) | pre_syscall — short-circuit | Same as above; use fd→fakeroot tag (§4.3) to decide whether to intercept |
| `chmod` / `fchmodat` (path-bearing) | pre_syscall — pass-through or shadow | Tier 1: pass through (mode bits are settable by the file owner without privileges).  Tier 2: update shadow table mode field |
| `mknod` / `mknodat` — device nodes under fakeroot prefix | pre_syscall — short-circuit | Return 0; Tier 2 records in shadow table so a subsequent `stat` on the same path returns the right type/mode |
| `mknod` / `mknodat` — regular files under fakeroot prefix | pass-through | No special handling needed (already allowed by the kernel) |

### 4.2  Pre→post communication for stat patching

The `sud_syscall_ctx.scratch` buffer is the conventional place to pass data
between `pre_syscall` and `post_syscall` within the same addin.  A one-byte
flag at a fixed offset in scratch is enough:

```c
#define SCRATCH_FAKEROOT_TAG_OFFSET 0
/* Written in pre_syscall, read in post_syscall: */
/*   0 = no fakeroot action needed               */
/*   1 = patch stat uid/gid after kernel call    */
/*   2 = patch stat uid/gid with shadow-table values (Tier 2) */
```

In `pre_syscall` for the stat family:

1. Absolutise (dirfd, path).
2. Call `find_rule()`.
3. If the first matching rule has `kind == SUD_PR_FAKEROOT`:
   - write tag `1` (or `2` in Tier 2) at `scratch[SCRATCH_FAKEROOT_TAG_OFFSET]`.
   - stash `fake_uid` and `fake_gid` in the next 8 bytes of scratch.
   - for Tier 2: also stash the abs_path hash so `post_syscall` can look up the shadow table without re-absolutising.
   - return 0 (let the kernel run the stat).
4. Otherwise: clear the tag byte, return 0.

In `post_syscall`, if the tag byte is `1` or `2`, and `ctx->ret == 0`:

1. Determine the stat struct pointer and layout from the syscall number (same
   per-architecture dispatch already done in `overlay.c`'s whiteout checker).
2. Overwrite `st_uid` and `st_gid` with the stashed values (Tier 1) or the
   shadow-table values (Tier 2).
3. For `statx`: overwrite `stx_uid` and `stx_gid` in the `struct statx` layout.

The path_remap addin's `post_syscall` hook is currently NULL.  This plan
adds it.

### 4.3  fd-to-fakeroot tracking

When a successful `open` / `openat` returns an fd for a path that matched a
fakeroot rule, path_remap registers the fd in a **fakeroot fd bitmap** (a
companion to the existing `g_dirfd_tab`).  On `fstat`/`fchown`/`fchmod` the
bitmap is checked; if the fd is tagged, the fakeroot path for the action is
known.

A simple 1024-entry open-addressed table (fd → rule index) suffices.  On
`close`/`dup2`-replace the entry is cleared (same lifecycle as `g_dirfd_tab`
entries).

New functions to add to `sud/path_remap/path.h`:

```c
void sud_pr_fakeroot_fd_tag(int fd, int rule_idx);
int  sud_pr_fakeroot_fd_lookup(int fd);   /* returns rule_idx or -1 */
void sud_pr_fakeroot_fd_forget(int fd);
```


---

## 5  Post-syscall stat struct patching

Both x86-64 and i386 stat struct layouts are already described in
`overlay.c` (`struct sud_overlay_stat`).  Extend that struct (or add a
parallel `struct sud_fakeroot_stat`) to expose `st_uid` and `st_gid` at the
right offsets:

**x86-64 `struct stat` (`newfstatat` / `__NR_stat`)**:

```
offset 28: unsigned int st_uid
offset 32: unsigned int st_gid
```

**i386 `struct stat64` (`fstatat64`)**:

```
offset 24: unsigned long st_uid
offset 28: unsigned long st_gid
```

**`struct statx` (`__NR_statx`)**:

```
offset  4: unsigned int stx_uid
offset  8: unsigned int stx_gid
```

Write a helper:

```c
static void fakeroot_patch_stat(long nr, void *statbuf,
                                uint32_t uid, uint32_t gid);
```

that switches on `nr` and writes the right offsets.  Called from
`post_syscall` after the tag check.


---

## 6  Tier 2 — per-file shadow table

### 6.1  Storage

Add a dedicated small shared-memory region:

```
/dev/shm/sud-fakeroot.<key>
```

where `<key>` is the same inramfs-style key minted by `sudtrace` and passed
via `--remap-rule fakeroot:<prefix>:<uid>:<gid>:<key>` (or a dedicated
`--fakeroot-key` flag; the remap-rule string can embed it).

The region is a fixed-size open-addressed hash map:

```c
#define SUD_FR_TABLE_SIZE 4096   /* must be power of two */

struct sud_fakeroot_entry {
    uint64_t path_hash;          /* FNV-1a of the absolute path; 0 = empty */
    uint32_t uid, gid, mode;
    char     path[256];          /* truncated abs path for collision disambiguation */
};

struct sud_fakeroot_shm {
    uint32_t magic;              /* SUD_FR_MAGIC */
    uint32_t version;
    uint32_t lock;               /* futex word — namespace lock for mutations */
    uint32_t _pad;
    struct sud_fakeroot_entry entries[SUD_FR_TABLE_SIZE];
};
```

Size: `sizeof(sud_fakeroot_shm)` ≈ 4096 × 272 bytes ≈ 1.06 MiB.  Acceptable
for a /dev/shm file.

### 6.2  Chown / chmod update path

When `chown(path, uid, gid)` resolves under a fakeroot rule:

1. Absolutise (dirfd, path).
2. Look up or insert an entry in the shadow table.
3. Update `entry.uid`, `entry.gid`.
4. Return 0 to the traced program without calling the kernel.

When `chmod(path, mode)` resolves under a fakeroot rule (Tier 2):

1. Absolutise (dirfd, path).
2. Look up or insert an entry.
3. Update `entry.mode`.
4. Still let the kernel run `chmod` (mode bits are settable; we just want the
   shadow to be authoritative for subsequent stat).

### 6.3  Stat lookup path (Tier 2)

In `post_syscall` with tag `2`:

1. Hash the stashed abs_path.
2. Look up in the shadow table.
3. If found: patch `st_uid`/`st_gid`/`st_mode` from the shadow entry.
4. If not found: patch with the rule's default `fake_uid`/`fake_gid`; mode
   is left as-is.

### 6.4  mknod interception (Tier 2)

For `mknod` / `mknodat` under a fakeroot prefix where the `type` field
is `S_IFBLK` or `S_IFCHR`:

1. Intercept in `pre_syscall`; do NOT call the kernel.
2. Insert a shadow-table entry with `uid=fake_uid`, `gid=fake_gid`,
   `mode` = the requested mode (including `S_IFBLK`/`S_IFCHR`).
3. Create an empty regular file at the same kernel path (so that
   subsequent `open`/`stat` on the host FS do not return ENOENT and so
   that `tar` can read *something* there).
4. Return 0.  The traced program believes a device node was created.


---

## 7  State inheritance across execve

The fakeroot rule list is already part of `g_sud_runtime_config.remap_rules[]`
and is re-emitted by `sud_runtime_config_emit()` onto every child wrapper's
argv.  No additional mechanism is needed for Tier 1.

For Tier 2, the shadow-table key must propagate.  Options:

**Option A (preferred):** embed the key in the `--remap-rule` string itself:

```
--remap-rule fakeroot:<prefix>:<uid>:<gid>:<key>
```

The parser splits on `:` and picks up the key; all five fields are re-emitted
verbatim by `sud_runtime_config_emit`.  Child wrapper processes attach the
same `/dev/shm/sud-fakeroot.<key>` region and see all shadow-table updates
from the parent.

**Option B:** a dedicated `--fakeroot-key` flag, analogous to `--inramfs-key`.
Slightly cleaner but requires a new `sud_runtime_config` field.

Option A is simpler and keeps the remap-rule string self-describing.

The `sudtrace` launcher mints the key (a random 8-hex-digit string, same as
the inramfs key) and passes it into the wrapper argv.


---

## 8  New files and changes

### New files

| File | Purpose |
|------|---------|
| `sud/path_remap/fakeroot.c` | `sud_fr_*` functions: rule parsing for the `fakeroot:` kind, the fd-fakeroot bitmap (§4.3), shadow-table attach/lookup/update (Tier 2), `fakeroot_patch_stat()` |
| `sud/path_remap/fakeroot.h` | Public interface for the above |
| `sud/path_remap/tests/test_fakeroot.c` | Unit tests (see §9) |

### Modified files

| File | Change |
|------|--------|
| `sud/path_remap/overlay.c` | Add `SUD_PR_FAKEROOT` to `sud_pr_rule_kind`; add parsing branch in `sud_overlay_init()`; add `fake_uid`/`fake_gid` fields to the rule struct |
| `sud/path_remap/overlay.h` | Export `sud_pr_rule_kind` enum; expose helper `sud_overlay_find_rule_fakeroot(abs_path, uid_out, gid_out)` for use by addin.c |
| `sud/path_remap/addin.c` | 1. In `pre_syscall` for the stat family: tag scratch when path is under a fakeroot rule.  2. In `pre_syscall` for `getuid`/`getgid` family: short-circuit with fake value.  3. In `pre_syscall` for `setuid`/`setgid` family: short-circuit success.  4. In `pre_syscall` for `chown`/`fchown`/`mknod` family: short-circuit or shadow-update.  5. Wire the new `post_syscall` hook. |
| `sud/path_remap/inramfs_glue.c` | In `h_open_inode` / `h_create_open_inode`: call `sud_pr_fakeroot_fd_tag` if the resolved path is under a fakeroot rule (so subsequent `fstat` on the returned fd is patched). |
| `sud/runtime_config.h` | No new fields needed for Tier 1.  For Tier 2 Option B: add `fakeroot_key` field. |
| `sudtrace.c` | Add `--fakeroot <spec>` option; translate to `--remap-rule fakeroot:<spec>` in wrapper argv; for Tier 2 also mint and pass the key. |
| `Makefile` | Add `sud/path_remap/fakeroot.c` to the sud object list. |


---

## 9  Testing plan

### 9.1  Unit tests (`sud/path_remap/tests/test_fakeroot.c`)

Following the existing test_overlay.c / test_dispatcher.c style (freestanding,
links libc-fs directly, drives the addin via
`sud_runtime_config_test_install()`):

1. **Rule parsing** — `--remap-rule fakeroot:/prefix` produces a rule with
   `kind = SUD_PR_FAKEROOT`, `fake_uid = 0`, `fake_gid = 0`.
2. **Rule parsing with explicit uid:gid** — `fakeroot:/prefix:1000:2000`
   produces `fake_uid = 1000`, `fake_gid = 2000`.
3. **getuid / geteuid short-circuit** — call the addin `pre_syscall` with
   `nr = SYS_getuid`; verify `ctx->ret == fake_uid` and return value is 1.
4. **setuid no-op** — `nr = SYS_setuid`; verify `ctx->ret == 0`, return 1.
5. **stat path under rule tagged** — call `pre_syscall` for `SYS_newfstatat`
   with a path under the fakeroot prefix; verify the scratch tag byte is set
   and the stashed uid/gid are correct.
6. **stat post_syscall patching** — simulate a kernel stat result in a buffer;
   call the addin `post_syscall`; verify `st_uid`/`st_gid` are overwritten.
7. **stat path NOT under rule** — path outside the prefix; verify scratch tag
   byte is 0 and stat buffer is not modified.
8. **chown under rule** — `pre_syscall` for `SYS_fchownat`; verify short-
   circuit with ret=0.
9. **fd tagging round-trip** — `sud_pr_fakeroot_fd_tag(5, 0)`, then
   `sud_pr_fakeroot_fd_lookup(5) == 0`; `sud_pr_fakeroot_fd_forget(5)`,
   then lookup returns -1.
10. **Prefix component-boundary check** — path `/fakeroot_extra/file` does NOT
    match a rule for `/fakeroot`; path `/fakeroot/sub/file` does.

### 9.2  Integration smoke tests

Add a shell-script test (alongside the existing `tests/` directory) that runs
under `sudtrace --fakeroot /tmp/pkg-staging`:

```sh
mkdir -p /tmp/pkg-staging/usr/bin
cp /bin/true /tmp/pkg-staging/usr/bin/
# inside sudtrace --fakeroot /tmp/pkg-staging:
stat /tmp/pkg-staging/usr/bin/true  | grep -q "Uid: (   0/root)"
tar -cf /tmp/test.tar -C /tmp/pkg-staging .
# ownership in archive must be 0:0
tar -tvf /tmp/test.tar | grep usr/bin/true | grep -q "root/root"
```

Also verify that the wrapper's own getuid/geteuid return 0 (visible via
`id` run under the trace).


---

## 10  Implementation order

1. **Rule struct and parser (overlay.c / overlay.h)** — add the
   `SUD_PR_FAKEROOT` enum value, rule fields, and parser branch.  Unit test:
   items 1–2 from §9.1.

2. **fakeroot.c / fakeroot.h skeleton** — fd-bitmap, `fakeroot_patch_stat()`
   helper, `sud_overlay_find_rule_fakeroot()` wrapper.  Unit tests: items 9–10.

3. **pre_syscall hooks in addin.c** — getuid/setuid short-circuits, stat
   scratch tagging, chown short-circuit.  Unit tests: items 3–5, 7–8.

4. **post_syscall hook in addin.c** — stat buffer patching.  Unit tests:
   items 5–6.

5. **fd tagging in inramfs_glue.c** — tag fds opened against fakeroot paths.

6. **sudtrace `--fakeroot` option** — translate to wrapper argv.

7. **Integration smoke test** (§9.2).

8. **Tier 2 shadow table** (separate PR) — fakeroot.c shadow-table attach,
   chown/chmod/mknod update paths, stat Tier-2 lookup.


---

## 11  Out of scope (explicit non-goals for first cut)

- Extended attributes / POSIX ACLs — not intercepted; fakeroot classic also
  ignores these.
- `SO_PEERCRED`-style credential passing over sockets — not needed for build
  workflows.
- `capget` / `capset` interception — capability queries will still return the
  real (unprivileged) capability set.  Tools that query `CAP_CHOWN` before
  calling `chown` will need a separate `--cap-fake` extension if required.
- Multiple disjoint fakeroot prefixes with independent shadow tables — allowed
  syntactically (multiple `--remap-rule fakeroot:` entries are parsed and kept
  in the rule list), but the Tier 2 shadow table currently supports one key
  per wrapper invocation.  Each prefix shares the same shadow table; conflicts
  are resolved by the first matching prefix rule.
