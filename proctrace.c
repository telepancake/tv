/*
 * proctrace.c — Log exec/exit/open/cwd/output for tagged process subtrees.
 *
 * v12
 * ===
 * • Output is read from the /proc/proctrace/new fd — no log file.
 *   open() creates session + tags opener.  read() drains JSONL.
 *   close() destroys session.
 *
 * • Per-session kernel ring buffer with backpressure:
 *   when buffer is full, producing workqueue workers block until
 *   the reader drains space.  This means traced processes slow
 *   down proportionally to how fast the reader consumes — no lost
 *   events, no OOM, no disk I/O.
 *
 * • TGID-based tagging (threads bundled).
 * • Paths as JSON strings.
 * • OPEN logs inode + device of the result.
 * • CWD event emitted on exec and chdir (replaces cwd field in EXEC).
 * • Compat 4.15–6.x.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/pid_namespace.h>
#include <linux/binfmts.h>
#include <linux/timekeeping.h>
#include <linux/kprobes.h>
#include <linux/workqueue.h>
#include <linux/ctype.h>
#include <linux/fcntl.h>
#include <linux/elf.h>
#include <linux/namei.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/circ_buf.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("proctrace");
MODULE_DESCRIPTION("Log exec/exit/open/cwd/output for tagged process subtrees");

/* ===============================================================
 * Compat
 * =============================================================== */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
  #define mmap_read_lock(mm)    down_read(&(mm)->mmap_sem)
  #define mmap_read_unlock(mm)  up_read(&(mm)->mmap_sem)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
  #define PROC_OPS_TYPE             struct file_operations
  #define PROC_OPS_OWNER            .owner   = THIS_MODULE,
  #define PROC_OPS_OPEN(fn)         .open    = (fn),
  #define PROC_OPS_READ(fn)         .read    = (fn),
  #define PROC_OPS_WRITE(fn)        .write   = (fn),
  #define PROC_OPS_RELEASE(fn)      .release = (fn),
  #define PROC_OPS_LSEEK(fn)        .llseek  = (fn),
  #define PROC_OPS_POLL(fn)         .poll    = (fn),
#else
  #define PROC_OPS_TYPE             struct proc_ops
  #define PROC_OPS_OWNER
  #define PROC_OPS_OPEN(fn)         .proc_open    = (fn),
  #define PROC_OPS_READ(fn)         .proc_read    = (fn),
  #define PROC_OPS_WRITE(fn)        .proc_write   = (fn),
  #define PROC_OPS_RELEASE(fn)      .proc_release = (fn),
  #define PROC_OPS_LSEEK(fn)        .proc_lseek   = (fn),
  #define PROC_OPS_POLL(fn)         .proc_poll    = (fn),
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
  #ifndef strscpy
    #define strscpy(dst, src, sz) strlcpy(dst, src, sz)
  #endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
  #define FORK_SYMBOL_PRIMARY   "kernel_clone"
  #define FORK_SYMBOL_FALLBACK  "_do_fork"
#else
  #define FORK_SYMBOL_PRIMARY   "_do_fork"
  #define FORK_SYMBOL_FALLBACK  "do_fork"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
  #define EXEC_SYMBOL_PRIMARY   "bprm_execve"
  #define EXEC_SYMBOL_FALLBACK  "exec_binprm"
#else
  #define EXEC_SYMBOL_PRIMARY   "exec_binprm"
  #define EXEC_SYMBOL_FALLBACK  "search_binary_handler"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
  #define OPEN_SYMBOL_PRIMARY   "do_sys_openat2"
  #define OPEN_SYMBOL_FALLBACK  "do_sys_open"
#else
  #define OPEN_SYMBOL_PRIMARY   "do_sys_open"
  #define OPEN_SYMBOL_FALLBACK  "do_sys_openat2"
#endif

/* ===============================================================
 * JSON string escaping (RFC 8259)
 * =============================================================== */

static int json_escape(char *dst, int dstsize, const char *src, int srclen)
{
    int si, di = 0;
    if (dstsize < 3) { if (dstsize > 0) dst[0]='\0'; return 0; }
    dst[di++] = '"';
    for (si = 0; si < srclen && di + 7 < dstsize; si++) {
        unsigned char c = (unsigned char)src[si];
        switch (c) {
        case '"':  dst[di++]='\\'; dst[di++]='"'; break;
        case '\\': dst[di++]='\\'; dst[di++]='\\'; break;
        case '\n': dst[di++]='\\'; dst[di++]='n'; break;
        case '\r': dst[di++]='\\'; dst[di++]='r'; break;
        case '\t': dst[di++]='\\'; dst[di++]='t'; break;
        case '\b': dst[di++]='\\'; dst[di++]='b'; break;
        case '\f': dst[di++]='\\'; dst[di++]='f'; break;
        default:
            if (c < 0x20) di += snprintf(dst+di, dstsize-di, "\\u%04x", c);
            else dst[di++] = c;
        }
    }
    dst[di++] = '"'; dst[di] = '\0';
    return di;
}

static int json_argv_array(char *dst, int dstsize, const char *raw, int rawlen)
{
    int di = 0, si = 0;
    dst[di++] = '[';
    while (si < rawlen && di + 8 < dstsize) {
        const char *arg = raw + si; int arglen = 0;
        while (si+arglen < rawlen && raw[si+arglen] != '\0') arglen++;
        if (arglen == 0 && si+1 >= rawlen) break;
        if (di > 1) dst[di++] = ',';
        di += json_escape(dst+di, dstsize-di, arg, arglen);
        si += arglen + 1;
    }
    if (di < dstsize) dst[di++] = ']';
    if (di < dstsize) dst[di] = '\0';
    return di;
}

static int json_env_object(char *dst, int dstsize, const char *raw, int rawlen)
{
    int di = 0, si = 0;
    dst[di++] = '{';
    while (si < rawlen && di + 16 < dstsize) {
        const char *entry = raw + si; int entlen = 0;
        const char *eq; int keylen, vallen; const char *val;
        while (si+entlen < rawlen && raw[si+entlen] != '\0') entlen++;
        if (entlen == 0 && si+1 >= rawlen) break;
        eq = memchr(entry, '=', entlen);
        if (eq) { keylen=eq-entry; val=eq+1; vallen=entlen-keylen-1; }
        else { keylen=entlen; val=""; vallen=0; }
        if (di > 1) dst[di++] = ',';
        di += json_escape(dst+di, dstsize-di, entry, keylen);
        dst[di++] = ':';
        di += json_escape(dst+di, dstsize-di, val, vallen);
        si += entlen + 1;
    }
    if (di < dstsize) dst[di++] = '}';
    if (di < dstsize) dst[di] = '\0';
    return di;
}

/* ===============================================================
 * Constants
 * =============================================================== */

#define TAG_HASH_BITS       10
#define LOG_LINE_MAX        (PATH_MAX * 8 + 262144 + 1024)
#define ARGV_MAX_READ       32768
#define ENV_MAX_READ        65536
#define WRITE_CAPTURE_MAX   4096
#define RING_BUF_ORDER      8       /* 2^8 pages = 1MB ring buffer */
#define RING_BUF_SIZE       (PAGE_SIZE << RING_BUF_ORDER)

/* ===============================================================
 * /dev/null inode
 * =============================================================== */

static struct inode *devnull_ino;

static void capture_devnull_inode(void)
{
    struct path p;
    if (kern_path("/dev/null", LOOKUP_FOLLOW, &p) == 0) {
        devnull_ino = p.dentry->d_inode; path_put(&p);
    }
}

/* ===============================================================
 * Ring buffer (per-session)
 * ===============================================================
 *
 * Simple byte ring buffer.  Producer (workqueue) blocks when full.
 * Consumer (read syscall) blocks when empty.
 * Protected by ring_lock spinlock; waitqueues for blocking.
 */

struct ring_buffer {
    char               *buf;
    size_t              size;       /* always power of 2 */
    size_t              head;       /* write position */
    size_t              tail;       /* read position */
    spinlock_t          lock;
    wait_queue_head_t   wq_reader;  /* reader waits here when empty */
    wait_queue_head_t   wq_writer;  /* writer waits here when full */
    bool                closed;     /* set on session teardown */
};

static int ring_init(struct ring_buffer *rb, size_t size)
{
    rb->buf = vmalloc(size);
    if (!rb->buf) return -ENOMEM;
    rb->size = size; rb->head = 0; rb->tail = 0; rb->closed = false;
    spin_lock_init(&rb->lock);
    init_waitqueue_head(&rb->wq_reader);
    init_waitqueue_head(&rb->wq_writer);
    return 0;
}

static void ring_destroy(struct ring_buffer *rb)
{
    if (rb->buf) { vfree(rb->buf); rb->buf = NULL; }
}

static size_t ring_used(struct ring_buffer *rb)
{ return rb->head - rb->tail; }

static size_t ring_free(struct ring_buffer *rb)
{ return rb->size - ring_used(rb); }

/*
 * Write into ring buffer.  Blocks if full (called from workqueue context
 * where sleeping is safe).  Returns bytes written, or -EPIPE if closed.
 */
static ssize_t ring_write(struct ring_buffer *rb, const char *data, size_t len)
{
    size_t written = 0;

    while (written < len) {
        size_t avail, chunk, off;
        unsigned long flags;

        /* Wait for space. */
        if (wait_event_interruptible(rb->wq_writer,
                rb->closed || ring_free(rb) > 0))
            return written ? (ssize_t)written : -EINTR;

        if (rb->closed) return -EPIPE;

        spin_lock_irqsave(&rb->lock, flags);
        avail = ring_free(rb);
        if (avail == 0) {
            spin_unlock_irqrestore(&rb->lock, flags);
            continue;
        }
        chunk = len - written;
        if (chunk > avail) chunk = avail;

        off = rb->head & (rb->size - 1);
        if (off + chunk > rb->size) {
            size_t first = rb->size - off;
            memcpy(rb->buf + off, data + written, first);
            memcpy(rb->buf, data + written + first, chunk - first);
        } else {
            memcpy(rb->buf + off, data + written, chunk);
        }
        rb->head += chunk;
        written += chunk;
        spin_unlock_irqrestore(&rb->lock, flags);

        wake_up_interruptible(&rb->wq_reader);
    }

    return (ssize_t)written;
}

/*
 * Read from ring buffer into user buffer.  Blocks if empty.
 * Returns bytes read, 0 on closed+empty (EOF), or -errno.
 */
static ssize_t ring_read_user(struct ring_buffer *rb,
                              char __user *ubuf, size_t count)
{
    size_t avail, chunk, off, first;
    unsigned long flags;

    if (wait_event_interruptible(rb->wq_reader,
            rb->closed || ring_used(rb) > 0))
        return -EINTR;

    spin_lock_irqsave(&rb->lock, flags);
    avail = ring_used(rb);
    if (avail == 0) {
        spin_unlock_irqrestore(&rb->lock, flags);
        return 0; /* EOF — closed and drained */
    }
    chunk = count;
    if (chunk > avail) chunk = avail;

    off = rb->tail & (rb->size - 1);
    if (off + chunk > rb->size) {
        first = rb->size - off;
        spin_unlock_irqrestore(&rb->lock, flags);
        if (copy_to_user(ubuf, rb->buf + off, first)) return -EFAULT;
        if (copy_to_user(ubuf + first, rb->buf, chunk - first)) return -EFAULT;
    } else {
        spin_unlock_irqrestore(&rb->lock, flags);
        if (copy_to_user(ubuf, rb->buf + off, chunk)) return -EFAULT;
    }

    spin_lock_irqsave(&rb->lock, flags);
    rb->tail += chunk;
    spin_unlock_irqrestore(&rb->lock, flags);

    wake_up_interruptible(&rb->wq_writer);
    return (ssize_t)chunk;
}

/* ===============================================================
 * Data structures
 * =============================================================== */

struct tagged_pid {
    pid_t pid;
    struct hlist_node hnode;
    struct rcu_head rcu;
};

struct trace_session {
    unsigned int        id;
    pid_t               root_tgid;
    bool                dead;

    struct ring_buffer  ring;
    struct inode       *creator_stdout_ino;

    DECLARE_HASHTABLE(tags, TAG_HASH_BITS);
    spinlock_t          tag_lock;
    atomic_t            tag_count;

    struct list_head    list;
    struct rcu_head     rcu_s;
};

static LIST_HEAD(sessions);
static DEFINE_MUTEX(sessions_mutex);
static atomic_t next_session_id = ATOMIC_INIT(1);

static bool have_ksys_write;

/* ===============================================================
 * Deferred writes via workqueue
 * ===============================================================
 *
 * Probe handlers capture data into a heap buffer and queue work.
 * The work item writes into the ring buffer, blocking if full.
 * This provides backpressure to traced processes.
 */

static struct workqueue_struct *log_wq;

struct log_work {
    struct work_struct      work;
    struct trace_session   *session;
    unsigned int            session_id;
    size_t                  len;
    char                    data[];
};

static void log_work_fn(struct work_struct *work)
{
    struct log_work *lw = container_of(work, struct log_work, work);
    struct trace_session *s = lw->session;

    if (s && !s->dead && s->id == lw->session_id)
        ring_write(&s->ring, lw->data, lw->len);

    kfree(lw);
}

static void session_log_queue(struct trace_session *s,
                              const char *buf, size_t len)
{
    struct log_work *lw;
    if (s->dead) return;
    lw = kmalloc(sizeof(*lw) + len, GFP_ATOMIC);
    if (!lw) return;
    INIT_WORK(&lw->work, log_work_fn);
    lw->session = s; lw->session_id = s->id; lw->len = len;
    memcpy(lw->data, buf, len);
    queue_work(log_wq, &lw->work);
}

/* ===============================================================
 * Session tag helpers
 * =============================================================== */

static bool session_is_tagged(struct trace_session *s, pid_t tgid)
{
    struct tagged_pid *entry;
    hash_for_each_possible_rcu(s->tags, entry, hnode, tgid) {
        if (entry->pid == tgid) return true;
    }
    return false;
}

static int session_tag_pid(struct trace_session *s, pid_t tgid)
{
    struct tagged_pid *entry; unsigned long flags;
    if (session_is_tagged(s, tgid)) return 0;
    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) return -ENOMEM;
    entry->pid = tgid; INIT_HLIST_NODE(&entry->hnode);
    spin_lock_irqsave(&s->tag_lock, flags);
    hash_add_rcu(s->tags, &entry->hnode, tgid);
    spin_unlock_irqrestore(&s->tag_lock, flags);
    atomic_inc(&s->tag_count); return 0;
}

static void session_untag_pid(struct trace_session *s, pid_t tgid)
{
    struct tagged_pid *entry; unsigned long flags;
    spin_lock_irqsave(&s->tag_lock, flags);
    hash_for_each_possible(s->tags, entry, hnode, tgid) {
        if (entry->pid == tgid) {
            hash_del_rcu(&entry->hnode);
            spin_unlock_irqrestore(&s->tag_lock, flags);
            kfree_rcu(entry, rcu);
            atomic_dec(&s->tag_count); return;
        }
    }
    spin_unlock_irqrestore(&s->tag_lock, flags);
}

static void session_free_all_tags(struct trace_session *s)
{
    struct tagged_pid *entry; struct hlist_node *tmp;
    unsigned long flags; int bkt;
    spin_lock_irqsave(&s->tag_lock, flags);
    hash_for_each_safe(s->tags, bkt, tmp, entry, hnode) {
        hash_del(&entry->hnode); kfree(entry);
    }
    spin_unlock_irqrestore(&s->tag_lock, flags);
    atomic_set(&s->tag_count, 0);
}

/* ===============================================================
 * fd → inode
 * =============================================================== */

static struct inode *get_fd_inode(unsigned int fd)
{
    struct file *f; struct inode *ino = NULL;
    f = fget(fd);
    if (f) { ino = file_inode(f); fput(f); }
    return ino;
}

/* ===============================================================
 * Session lifecycle
 * =============================================================== */

static struct trace_session *session_create(pid_t root_tgid)
{
    struct trace_session *s; int ret;
    s = kzalloc(sizeof(*s), GFP_KERNEL);
    if (!s) return ERR_PTR(-ENOMEM);

    ret = ring_init(&s->ring, RING_BUF_SIZE);
    if (ret) { kfree(s); return ERR_PTR(ret); }

    s->id = atomic_fetch_inc(&next_session_id);
    s->root_tgid = root_tgid; s->dead = false;
    s->creator_stdout_ino = get_fd_inode(1);
    atomic_set(&s->tag_count, 0);
    hash_init(s->tags); spin_lock_init(&s->tag_lock);
    INIT_LIST_HEAD(&s->list);

    session_tag_pid(s, root_tgid);

    mutex_lock(&sessions_mutex);
    list_add_tail_rcu(&s->list, &sessions);
    mutex_unlock(&sessions_mutex);

    pr_info("proctrace: session %u root_tgid=%d\n", s->id, root_tgid);
    return s;
}

static void session_destroy_rcu(struct rcu_head *head)
{ kfree(container_of(head, struct trace_session, rcu_s)); }

static void session_destroy_locked(struct trace_session *s)
{
    s->dead = true; smp_wmb();
    s->ring.closed = true;
    wake_up_interruptible(&s->ring.wq_writer);
    wake_up_interruptible(&s->ring.wq_reader);

    list_del_rcu(&s->list);
    flush_workqueue(log_wq);
    session_free_all_tags(s);
    ring_destroy(&s->ring);
    call_rcu(&s->rcu_s, session_destroy_rcu);
}

/* ===============================================================
 * Task info helpers
 * =============================================================== */

static char *get_task_cwd(struct task_struct *task, char *buf, int buflen)
{
    struct path pwd; char *p;
    task_lock(task);
    if (!task->fs) { task_unlock(task); return NULL; }
    get_fs_pwd(task->fs, &pwd); task_unlock(task);
    p = d_path(&pwd, buf, buflen); path_put(&pwd);
    return IS_ERR(p) ? NULL : p;
}

static char *get_task_exe_path(struct task_struct *task, char *buf, int buflen)
{
    struct mm_struct *mm; struct file *exe; char *p = NULL;
    mm = get_task_mm(task); if (!mm) return NULL;
    rcu_read_lock();
    exe = rcu_dereference(mm->exe_file);
    if (exe) { get_file(exe); rcu_read_unlock();
        p = file_path(exe, buf, buflen); fput(exe);
        if (IS_ERR(p)) p = NULL;
    } else { rcu_read_unlock(); }
    mmput(mm); return p;
}

static char *read_mm_region(struct task_struct *task,
                            unsigned long start, unsigned long end,
                            size_t max, size_t *out_len)
{
    struct mm_struct *mm; unsigned long len; char *buf; int ret;
    mm = get_task_mm(task); if (!mm) return NULL;
    len = end - start;
    if (len == 0) { mmput(mm); return NULL; }
    if (len > max) len = max;
    buf = kmalloc(len, GFP_ATOMIC);
    if (!buf) { mmput(mm); return NULL; }
    ret = access_process_vm(task, start, buf, len, 0);
    mmput(mm);
    if (ret <= 0) { kfree(buf); return NULL; }
    *out_len = (size_t)ret; return buf;
}

static char *read_task_argv_raw(struct task_struct *task, size_t *out_len)
{
    struct mm_struct *mm; unsigned long s, e;
    mm = get_task_mm(task); if (!mm) return NULL;
    mmap_read_lock(mm); s=mm->arg_start; e=mm->arg_end; mmap_read_unlock(mm);
    mmput(mm); return read_mm_region(task, s, e, ARGV_MAX_READ, out_len);
}

static char *read_task_env_raw(struct task_struct *task, size_t *out_len)
{
    struct mm_struct *mm; unsigned long s, e;
    mm = get_task_mm(task); if (!mm) return NULL;
    mmap_read_lock(mm); s=mm->env_start; e=mm->env_end; mmap_read_unlock(mm);
    mmput(mm); return read_mm_region(task, s, e, ENV_MAX_READ, out_len);
}

static pid_t get_task_ns_pid(struct task_struct *t)
{ pid_t p; rcu_read_lock(); p=task_pid_nr_ns(t,task_active_pid_ns(t)); rcu_read_unlock(); return p; }

static pid_t get_task_ns_tgid(struct task_struct *t)
{ pid_t p; rcu_read_lock(); p=task_tgid_nr_ns(t,task_active_pid_ns(t)); rcu_read_unlock(); return p; }

/* ===============================================================
 * Auxv → JSON object innards
 * =============================================================== */

static int format_auxv_json(struct task_struct *task, char *buf, int buflen)
{
    struct mm_struct *mm; int pos=0, i, first=1;
    mm = get_task_mm(task); if (!mm) return 0;
    for (i=0; i<AT_VECTOR_SIZE*2; i+=2) {
        unsigned long type=mm->saved_auxv[i], val=mm->saved_auxv[i+1];
        if (type==AT_NULL) break;
        switch(type) {
        case AT_UID: case AT_EUID: case AT_GID: case AT_EGID: case AT_SECURE:
#ifdef AT_CLKTCK
        case AT_CLKTCK:
#endif
        {
            const char *n= type==AT_UID?"AT_UID":type==AT_EUID?"AT_EUID":
                type==AT_GID?"AT_GID":type==AT_EGID?"AT_EGID":
                type==AT_SECURE?"AT_SECURE":"AT_CLKTCK";
            if(!first) buf[pos++]=',';
            pos+=snprintf(buf+pos,buflen-pos,"\"%s\":%lu",n,val);
            first=0;
        } break;
#ifdef AT_EXECFN
        case AT_EXECFN: { char u[256]; char e[520];
            long n=strncpy_from_user(u,(const char __user*)val,sizeof(u));
            if(n>0){json_escape(e,sizeof(e),u,n); if(!first)buf[pos++]=',';
                pos+=snprintf(buf+pos,buflen-pos,"\"AT_EXECFN\":%s",e); first=0;}
        } break;
#endif
#ifdef AT_PLATFORM
        case AT_PLATFORM: { char u[64]; char e[140];
            long n=strncpy_from_user(u,(const char __user*)val,sizeof(u));
            if(n>0){json_escape(e,sizeof(e),u,n); if(!first)buf[pos++]=',';
                pos+=snprintf(buf+pos,buflen-pos,"\"AT_PLATFORM\":%s",e); first=0;}
        } break;
#endif
        default: break;
        }
        if(pos>=buflen-1) break;
    }
    mmput(mm); return pos;
}

/* ===============================================================
 * Open flags → JSON array
 * =============================================================== */

static int json_open_flags(int flags, char *buf, int buflen)
{
    int pos=0, acc=flags&O_ACCMODE;
    buf[pos++]='[';
    switch(acc){
    case O_RDONLY:pos+=snprintf(buf+pos,buflen-pos,"\"O_RDONLY\"");break;
    case O_WRONLY:pos+=snprintf(buf+pos,buflen-pos,"\"O_WRONLY\"");break;
    case O_RDWR: pos+=snprintf(buf+pos,buflen-pos,"\"O_RDWR\"");break;
    default:     pos+=snprintf(buf+pos,buflen-pos,"\"0x%x\"",acc);break;
    }
#define F(f) if((flags&(f))&&pos<buflen-2) pos+=snprintf(buf+pos,buflen-pos,",\""#f"\"")
    F(O_CREAT);F(O_EXCL);F(O_TRUNC);F(O_APPEND);F(O_NONBLOCK);
    F(O_DIRECTORY);F(O_NOFOLLOW);F(O_CLOEXEC);
#ifdef O_TMPFILE
    F(O_TMPFILE);
#endif
#undef F
    if(pos<buflen) buf[pos++]=']';
    if(pos<buflen) buf[pos]='\0';
    return pos;
}

/* ===============================================================
 * Fast tgid check
 * =============================================================== */

static bool tgid_in_any_session(pid_t tgid)
{
    struct trace_session *s; bool f=false;
    rcu_read_lock();
    list_for_each_entry_rcu(s, &sessions, list) {
        if(!s->dead && session_is_tagged(s, tgid)){f=true;break;}
    }
    rcu_read_unlock(); return f;
}

/* ===============================================================
 * JSON header helper
 * =============================================================== */

static int json_header(char *buf, int buflen, const char *event,
                       struct task_struct *task, struct timespec64 *ts)
{
    return snprintf(buf, buflen,
        "{\"event\":\"%s\",\"ts\":%lld.%09ld,"
        "\"pid\":%d,\"tgid\":%d,\"ppid\":%d,"
        "\"nspid\":%d,\"nstgid\":%d",
        event, (long long)ts->tv_sec, ts->tv_nsec,
        task->pid, task->tgid, task_ppid_nr(task),
        get_task_ns_pid(task), get_task_ns_tgid(task));
}

/* ===============================================================
 * Emit CWD event
 * =============================================================== */

static void emit_cwd_event(struct task_struct *task)
{
    struct trace_session *s;
    pid_t tgid = task->tgid;
    struct timespec64 ts;
    char *cwd_buf, *cwd, *cwd_esc, *line;
    int pos;

    cwd_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!cwd_buf) return;
    cwd = get_task_cwd(task, cwd_buf, PATH_MAX);
    if (!cwd) { kfree(cwd_buf); return; }

    cwd_esc = kmalloc(PATH_MAX*2, GFP_ATOMIC);
    if (!cwd_esc) { kfree(cwd_buf); return; }
    json_escape(cwd_esc, PATH_MAX*2, cwd, strlen(cwd));

    line = kmalloc(PATH_MAX*2+256, GFP_ATOMIC);
    if (!line) { kfree(cwd_esc); kfree(cwd_buf); return; }

    ktime_get_real_ts64(&ts);
    pos = json_header(line, PATH_MAX*2+256, "CWD", task, &ts);
    pos += snprintf(line+pos, PATH_MAX*2+256-pos, ",\"path\":%s}\n", cwd_esc);

    if (pos > 0) {
        rcu_read_lock();
        list_for_each_entry_rcu(s, &sessions, list) {
            if (!s->dead && session_is_tagged(s, tgid))
                session_log_queue(s, line, (size_t)pos);
        }
        rcu_read_unlock();
    }
    kfree(line); kfree(cwd_esc); kfree(cwd_buf);
}

/* ===============================================================
 * Emit write log
 * =============================================================== */

static void emit_write_log(struct task_struct *task, const char *stream,
                           unsigned long ubuf_ptr, size_t count)
{
    struct trace_session *s;
    pid_t tgid = task->tgid;
    struct timespec64 ts;
    char *ubuf=NULL, *escaped=NULL, *line=NULL;
    size_t to_read; unsigned long left; int pos;

    ktime_get_real_ts64(&ts);
    to_read = count; if (to_read > WRITE_CAPTURE_MAX) to_read = WRITE_CAPTURE_MAX;
    ubuf = kmalloc(to_read, GFP_ATOMIC); if (!ubuf) return;
    left = copy_from_user(ubuf, (const void __user *)ubuf_ptr, to_read);
    if (left == to_read) goto out;
    to_read -= left;

    escaped = kmalloc(to_read*6+4, GFP_ATOMIC); if (!escaped) goto out;
    json_escape(escaped, to_read*6+4, ubuf, to_read);

    line = kmalloc(to_read*6+512, GFP_ATOMIC); if (!line) goto out;
    pos = json_header(line, to_read*6+512, stream, task, &ts);
    pos += snprintf(line+pos, to_read*6+512-pos,
        ",\"len\":%zu,\"data\":%s}\n", to_read, escaped);

    if (pos > 0) {
        rcu_read_lock();
        list_for_each_entry_rcu(s, &sessions, list) {
            if (!s->dead && session_is_tagged(s, tgid))
                session_log_queue(s, line, (size_t)pos);
        }
        rcu_read_unlock();
    }
out: kfree(line); kfree(escaped); kfree(ubuf);
}

/* ===============================================================
 * kprobe hooks
 * =============================================================== */

/* ---- 1. Fork ---- */

static int fork_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{ return 0; }

static int fork_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct trace_session *s;
    pid_t parent_tgid = current->tgid;
    pid_t child_pid = (pid_t)regs_return_value(regs);
    if (child_pid <= 0) return 0;
    rcu_read_lock();
    list_for_each_entry_rcu(s, &sessions, list) {
        if (!s->dead && session_is_tagged(s, parent_tgid))
            session_tag_pid(s, child_pid);
    }
    rcu_read_unlock();
    return 0;
}

static struct kretprobe fork_kretprobe = {
    .handler=fork_ret, .entry_handler=fork_entry, .maxactive=64,
};

/* ===============================================================
 * Emit fake OPEN events for inherited fds
 * ===============================================================
 *
 * On exec, the new program inherits the fd table of its predecessor
 * (minus O_CLOEXEC ones, which the kernel has already closed by the
 * time our kretprobe fires).  Emit one "inherited":true OPEN event
 * per surviving fd, so the trace records which files/pipes/sockets
 * a freshly-exec'd process started with — even if it never calls
 * open() itself (e.g. `sort` in `cat a | sort > b`).
 *
 * Both ends of a pipe share the same pipefs inode, so matching
 * (dev,ino) across two inherited OPEN events unambiguously pairs
 * the two ends of a shell pipe.
 */

static void emit_inherited_open_for_fd(struct task_struct *task,
                                       struct timespec64 *ts,
                                       unsigned int fd, struct file *file)
{
    struct trace_session *s;
    pid_t tgid = task->tgid;
    struct inode *ino;
    unsigned long ino_nr = 0;
    dev_t dev = 0;
    char *path_buf = NULL, *path = NULL, *path_esc = NULL;
    char *flags_j = NULL, *line = NULL;
    int pos;

    ino = file_inode(file);
    if (ino) { ino_nr = ino->i_ino; dev = ino->i_sb->s_dev; }

    path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!path_buf) return;
    path = file_path(file, path_buf, PATH_MAX);
    if (IS_ERR(path)) path = NULL;

    path_esc = kmalloc(PATH_MAX*2, GFP_ATOMIC);
    if (path_esc && path) json_escape(path_esc, PATH_MAX*2, path, strlen(path));

    flags_j = kmalloc(256, GFP_ATOMIC);
    if (flags_j) json_open_flags(file->f_flags, flags_j, 256);

    line = kmalloc(PATH_MAX*2+512, GFP_ATOMIC);
    if (!line) goto out;

    pos = json_header(line, PATH_MAX*2+512, "OPEN", task, ts);
    pos += snprintf(line+pos, PATH_MAX*2+512-pos,
        ",\"path\":%s,\"flags\":%s,\"fd\":%u,\"ino\":%lu,\"dev\":\"%u:%u\","
        "\"inherited\":true}\n",
        (path && path_esc) ? path_esc : "null",
        flags_j ? flags_j : "[]",
        fd, ino_nr, MAJOR(dev), MINOR(dev));

    if (pos > 0) {
        rcu_read_lock();
        list_for_each_entry_rcu(s, &sessions, list) {
            if (!s->dead && session_is_tagged(s, tgid))
                session_log_queue(s, line, (size_t)pos);
        }
        rcu_read_unlock();
    }

out:
    kfree(line); kfree(flags_j); kfree(path_esc); kfree(path_buf);
}

struct inherited_open_ctx {
    struct task_struct *task;
    struct timespec64   ts;
};

static int inherited_open_iter(const void *p, struct file *file, unsigned fd)
{
    struct inherited_open_ctx *ctx = (struct inherited_open_ctx *)p;
    emit_inherited_open_for_fd(ctx->task, &ctx->ts, fd, file);
    return 0; /* 0 = keep iterating */
}

static void emit_inherited_open_events(struct task_struct *task)
{
    struct inherited_open_ctx ctx;
    struct files_struct *files = task->files; /* safe: task == current */
    if (!files) return;
    ctx.task = task;
    ktime_get_real_ts64(&ctx.ts);
    iterate_fd(files, 0, inherited_open_iter, &ctx);
}

/* ---- 2. Exec ---- */

static int exec_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{ return 0; }

static int exec_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct trace_session *s;
    struct task_struct *task = current;
    pid_t tgid = task->tgid;
    struct timespec64 ts;
    char *argv_raw=NULL, *env_raw=NULL, *argv_j=NULL, *env_j=NULL;
    char *exe_buf=NULL, *exe=NULL, *exe_esc=NULL;
    char *auxv_buf=NULL, *line=NULL;
    size_t argv_len=0, env_len=0;
    int pos;

    if ((int)regs_return_value(regs) != 0) return 0;
    if (!tgid_in_any_session(tgid)) return 0;

    /* Emit CWD event first. */
    emit_cwd_event(task);

    ktime_get_real_ts64(&ts);

    exe_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
    if (exe_buf) exe = get_task_exe_path(task, exe_buf, PATH_MAX);
    argv_raw = read_task_argv_raw(task, &argv_len);
    env_raw = read_task_env_raw(task, &env_len);

    exe_esc = kmalloc(PATH_MAX*2, GFP_ATOMIC);
    if (exe_esc && exe) json_escape(exe_esc, PATH_MAX*2, exe, strlen(exe));
    argv_j = kmalloc(ARGV_MAX_READ*6+64, GFP_ATOMIC);
    if (argv_j && argv_raw) json_argv_array(argv_j, ARGV_MAX_READ*6+64, argv_raw, argv_len);
    env_j = kmalloc(ENV_MAX_READ*6+64, GFP_ATOMIC);
    if (env_j && env_raw) json_env_object(env_j, ENV_MAX_READ*6+64, env_raw, env_len);
    auxv_buf = kmalloc(4096, GFP_ATOMIC);
    if (auxv_buf) { auxv_buf[0]='\0'; format_auxv_json(task, auxv_buf, 4096); }

    line = kmalloc(LOG_LINE_MAX, GFP_ATOMIC);
    if (!line) goto out;

    pos = json_header(line, LOG_LINE_MAX, "EXEC", task, &ts);
    pos += snprintf(line+pos, LOG_LINE_MAX-pos,
        ",\"exe\":%s,\"argv\":%s,\"env\":%s,\"auxv\":{%s}}\n",
        (exe_esc&&exe)?exe_esc:"null",
        (argv_j&&argv_raw)?argv_j:"[]",
        (env_j&&env_raw)?env_j:"{}",
        (auxv_buf&&auxv_buf[0])?auxv_buf:"");

    if (pos > 0 && pos < LOG_LINE_MAX) {
        rcu_read_lock();
        list_for_each_entry_rcu(s, &sessions, list) {
            if (!s->dead && session_is_tagged(s, tgid))
                session_log_queue(s, line, (size_t)pos);
        }
        rcu_read_unlock();
    }

    /* Emit fake OPEN events for inherited fds (pipes, redirects, etc). */
    emit_inherited_open_events(task);
out:
    kfree(line); kfree(auxv_buf); kfree(env_j); kfree(argv_j);
    kfree(exe_esc); kfree(env_raw); kfree(argv_raw); kfree(exe_buf);
    return 0;
}

static struct kretprobe exec_kretprobe = {
    .handler=exec_ret, .entry_handler=exec_entry, .maxactive=64,
};

/* ---- 3. Exit ---- */

static int exit_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct trace_session *s;
    struct task_struct *task = current;
    pid_t tgid = task->tgid;
    long code; struct timespec64 ts;
    char line[384]; int pos, exit_sig, exit_val; bool core_dumped;

    if (task->pid != task->tgid) return 0;
    if (tgid_in_any_session(tgid)) {
#if defined(CONFIG_X86_64)
        code=(long)regs->di;
#elif defined(CONFIG_X86)
        code=(long)regs->ax;
#elif defined(CONFIG_ARM64)
        code=(long)regs->regs[0];
#elif defined(CONFIG_ARM)
        code=(long)regs->ARM_r0;
#elif defined(CONFIG_S390)
        code=(long)regs->gprs[2];
#elif defined(CONFIG_PPC)
        code=(long)regs->gpr[3];
#else
        code=0;
#endif
        ktime_get_real_ts64(&ts);
        exit_sig=code&0x7f; core_dumped=!!(code&0x80); exit_val=(code>>8)&0xff;
        pos = json_header(line, sizeof(line), "EXIT", task, &ts);
        if (exit_sig==0)
            pos+=snprintf(line+pos,sizeof(line)-pos,
                ",\"status\":\"exited\",\"code\":%d,\"raw\":%ld}\n",exit_val,code);
        else
            pos+=snprintf(line+pos,sizeof(line)-pos,
                ",\"status\":\"signaled\",\"signal\":%d,\"core_dumped\":%s,\"raw\":%ld}\n",
                exit_sig,core_dumped?"true":"false",code);
        if (pos>0&&pos<(int)sizeof(line)) {
            rcu_read_lock();
            list_for_each_entry_rcu(s,&sessions,list){
                if(!s->dead&&session_is_tagged(s,tgid))
                    session_log_queue(s,line,(size_t)pos);
            }
            rcu_read_unlock();
        }
    }
    rcu_read_lock();
    list_for_each_entry_rcu(s,&sessions,list){
        if(!s->dead&&session_is_tagged(s,tgid)) session_untag_pid(s,tgid);
    }
    rcu_read_unlock();
    return 0;
}

static struct kprobe exit_kprobe = { .pre_handler=exit_pre, .symbol_name="do_exit" };

/* ---- 4. Open ---- */

struct open_probe_data { unsigned long filename_ptr; int flags; };

static int open_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct open_probe_data *d=(void*)ri->data;
    if(!tgid_in_any_session(current->tgid)){d->filename_ptr=0;return 1;}
#if defined(CONFIG_X86_64)
    d->filename_ptr=regs->si; d->flags=(int)regs->dx;
#elif defined(CONFIG_ARM64)
    d->filename_ptr=regs->regs[1]; d->flags=(int)regs->regs[2];
#else
    d->filename_ptr=0;
#endif
    return 0;
}

static int open_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct open_probe_data *d=(void*)ri->data;
    struct trace_session *s;
    struct task_struct *task=current;
    pid_t tgid=task->tgid;
    struct timespec64 ts;
    long fd_or_err=(long)regs_return_value(regs);
    char *upath=NULL,*path_esc=NULL,*flags_j=NULL,*line=NULL;
    int pos; long n;
    struct inode *ino=NULL; unsigned long ino_nr=0; dev_t dev=0;

    if(!d->filename_ptr||!tgid_in_any_session(tgid)) return 0;
    ktime_get_real_ts64(&ts);

    upath=kmalloc(PATH_MAX,GFP_ATOMIC); if(!upath) return 0;
    n=strncpy_from_user(upath,(const char __user*)d->filename_ptr,PATH_MAX);
    if(n<=0) goto out;

    path_esc=kmalloc(PATH_MAX*2,GFP_ATOMIC);
    if(path_esc) json_escape(path_esc,PATH_MAX*2,upath,n);
    flags_j=kmalloc(256,GFP_ATOMIC);
    if(flags_j) json_open_flags(d->flags,flags_j,256);

    /* Get inode of result fd. */
    if(fd_or_err>=0){
        struct file *rf=fget((unsigned int)fd_or_err);
        if(rf){
            ino=file_inode(rf);
            if(ino){ino_nr=ino->i_ino; dev=ino->i_sb->s_dev;}
            fput(rf);
        }
    }

    line=kmalloc(PATH_MAX*2+512,GFP_ATOMIC); if(!line) goto out;
    pos=json_header(line,PATH_MAX*2+512,"OPEN",task,&ts);

    if(fd_or_err>=0)
        pos+=snprintf(line+pos,PATH_MAX*2+512-pos,
            ",\"path\":%s,\"flags\":%s,\"fd\":%ld,\"ino\":%lu,\"dev\":\"%u:%u\"}\n",
            path_esc?path_esc:"null", flags_j?flags_j:"[]",
            fd_or_err, ino_nr, MAJOR(dev), MINOR(dev));
    else
        pos+=snprintf(line+pos,PATH_MAX*2+512-pos,
            ",\"path\":%s,\"flags\":%s,\"err\":%ld}\n",
            path_esc?path_esc:"null", flags_j?flags_j:"[]", fd_or_err);

    if(pos>0){
        rcu_read_lock();
        list_for_each_entry_rcu(s,&sessions,list){
            if(!s->dead&&session_is_tagged(s,tgid))
                session_log_queue(s,line,(size_t)pos);
        }
        rcu_read_unlock();
    }
out: kfree(line);kfree(flags_j);kfree(path_esc);kfree(upath);
    return 0;
}

static struct kretprobe open_kretprobe = {
    .handler=open_ret,.entry_handler=open_entry,
    .data_size=sizeof(struct open_probe_data),.maxactive=128,
};

/* ---- 5. Chdir ---- */

static int chdir_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (!tgid_in_any_session(current->tgid)) return 1;
    return 0;
}

static int chdir_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if ((int)regs_return_value(regs) != 0) return 0;
    emit_cwd_event(current);
    return 0;
}

static struct kretprobe chdir_kretprobe = {
    .handler=chdir_ret,.entry_handler=chdir_entry,.maxactive=32,
};

/* ---- 6a. ksys_write (fd-based) ---- */

struct ksys_write_data { unsigned int fd; unsigned long buf_ptr; size_t count; };

static int ksys_write_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ksys_write_data *d=(void*)ri->data; unsigned int fd;
#if defined(CONFIG_X86_64)
    fd=(unsigned int)regs->di;
#elif defined(CONFIG_ARM64)
    fd=(unsigned int)regs->regs[0];
#else
    return 1;
#endif
    if(fd!=1&&fd!=2) return 1;
    if(!tgid_in_any_session(current->tgid)) return 1;
    d->fd=fd;
#if defined(CONFIG_X86_64)
    d->buf_ptr=regs->si; d->count=(size_t)regs->dx;
#elif defined(CONFIG_ARM64)
    d->buf_ptr=regs->regs[1]; d->count=(size_t)regs->regs[2];
#endif
    return 0;
}

static int ksys_write_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ksys_write_data *d=(void*)ri->data;
    struct trace_session *s;
    long ret_val=(long)regs_return_value(regs);
    struct inode *write_ino; bool any;
    if(ret_val<=0) return 0;
    if(d->fd==2){emit_write_log(current,"STDERR",d->buf_ptr,(size_t)ret_val);return 0;}
    write_ino=get_fd_inode(1); if(!write_ino) return 0;
    any=false;
    rcu_read_lock();
    list_for_each_entry_rcu(s,&sessions,list){
        if(!s->dead&&session_is_tagged(s,current->tgid)&&
           write_ino==s->creator_stdout_ino){any=true;break;}
    }
    rcu_read_unlock();
    if(any) emit_write_log(current,"STDOUT",d->buf_ptr,(size_t)ret_val);
    return 0;
}

static struct kretprobe ksys_write_kretprobe = {
    .handler=ksys_write_ret,.entry_handler=ksys_write_entry,
    .data_size=sizeof(struct ksys_write_data),.maxactive=128,
};

/* ---- 6b. vfs_write (fallback) ---- */

struct vfs_write_data { struct file *filp; unsigned long buf_ptr; size_t count; };

static int vfs_write_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct vfs_write_data *d=(void*)ri->data;
    if(!tgid_in_any_session(current->tgid)) return 1;
#if defined(CONFIG_X86_64)
    d->filp=(struct file*)regs->di; d->buf_ptr=regs->si; d->count=(size_t)regs->dx;
#elif defined(CONFIG_ARM64)
    d->filp=(struct file*)regs->regs[0]; d->buf_ptr=regs->regs[1]; d->count=(size_t)regs->regs[2];
#else
    return 1;
#endif
    if(!d->filp||!d->buf_ptr||d->count==0) return 1;
    return 0;
}

static int vfs_write_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct vfs_write_data *d=(void*)ri->data;
    struct trace_session *s;
    long ret_val=(long)regs_return_value(regs);
    struct inode *write_ino,*stderr_ino;
    const char *stream=NULL; bool any=false;
    if(ret_val<=0) return 0;
    write_ino=file_inode(d->filp); if(!write_ino) return 0;
    stderr_ino=get_fd_inode(2);
    if(write_ino==stderr_ino){
        if(devnull_ino&&write_ino==devnull_ino) return 0;
        stream="STDERR"; any=true;
    }
    if(!any){
        if(devnull_ino&&write_ino==devnull_ino) return 0;
        rcu_read_lock();
        list_for_each_entry_rcu(s,&sessions,list){
            if(!s->dead&&session_is_tagged(s,current->tgid)&&
               write_ino==s->creator_stdout_ino){any=true;break;}
        }
        rcu_read_unlock();
        if(any) stream="STDOUT";
    }
    if(any&&stream) emit_write_log(current,stream,d->buf_ptr,(size_t)ret_val);
    return 0;
}

static struct kretprobe vfs_write_kretprobe = {
    .handler=vfs_write_ret,.entry_handler=vfs_write_entry,
    .data_size=sizeof(struct vfs_write_data),.maxactive=128,
};

/* ===============================================================
 * /proc interface
 * =============================================================== */

static struct proc_dir_entry *proc_dir;

static int proc_new_open(struct inode *inode, struct file *filp)
{
    struct trace_session *s = session_create(current->tgid);
    if (IS_ERR(s)) return PTR_ERR(s);
    filp->private_data = s;
    return 0;
}

static ssize_t proc_new_read(struct file *filp, char __user *ubuf,
                              size_t count, loff_t *off)
{
    struct trace_session *s = filp->private_data;
    if (!s) return -EINVAL;
    return ring_read_user(&s->ring, ubuf, count);
}

static __poll_t proc_new_poll(struct file *filp, struct poll_table_struct *wait)
{
    struct trace_session *s = filp->private_data;
    __poll_t mask = 0;
    if (!s) return POLLERR;
    poll_wait(filp, &s->ring.wq_reader, wait);
    if (ring_used(&s->ring) > 0) mask |= POLLIN | POLLRDNORM;
    if (s->ring.closed) mask |= POLLHUP;
    return mask;
}

static int proc_new_release(struct inode *inode, struct file *filp)
{
    struct trace_session *s = filp->private_data;
    if (!s) return 0;
    filp->private_data = NULL;
    mutex_lock(&sessions_mutex);
    session_destroy_locked(s);
    mutex_unlock(&sessions_mutex);
    return 0;
}

static const PROC_OPS_TYPE proc_new_ops = {
    PROC_OPS_OWNER
    PROC_OPS_OPEN(proc_new_open)
    PROC_OPS_READ(proc_new_read)
    PROC_OPS_POLL(proc_new_poll)
    PROC_OPS_RELEASE(proc_new_release)
};

static int proc_sessions_show(struct seq_file *m, void *v)
{
    struct trace_session *s;
    seq_printf(m,"%-6s %-10s %-8s %-10s %s\n","ID","ROOT_TGID","#TAGS","BUF_USED","STATUS");
    rcu_read_lock();
    list_for_each_entry_rcu(s,&sessions,list)
        seq_printf(m,"%-6u %-10d %-8d %-10zu %s\n",
            s->id,s->root_tgid,atomic_read(&s->tag_count),
            ring_used(&s->ring), s->dead?"dead":"active");
    rcu_read_unlock();
    return 0;
}

static int proc_sessions_open(struct inode *inode, struct file *file)
{ return single_open(file, proc_sessions_show, NULL); }

static const PROC_OPS_TYPE proc_sessions_ops = {
    PROC_OPS_OWNER
    PROC_OPS_OPEN(proc_sessions_open) PROC_OPS_READ(seq_read)
    PROC_OPS_LSEEK(seq_lseek) PROC_OPS_RELEASE(single_release)
};

/* ===============================================================
 * Symbol resolution
 * =============================================================== */

static bool symbol_exists(const char *name)
{
    struct kprobe kp={}; kp.symbol_name=name;
    if(register_kprobe(&kp)<0) return false;
    unregister_kprobe(&kp); return true;
}

/* ===============================================================
 * Module init / exit
 * =============================================================== */

static const char *write_hook_name;
static const char *chdir_sym;

static int __init proctrace_init(void)
{
    int ret;
    const char *fork_sym, *exec_sym, *open_sym;

    capture_devnull_inode();
    log_wq = alloc_workqueue("proctrace", WQ_UNBOUND, 0);
    if (!log_wq) return -ENOMEM;

    proc_dir = proc_mkdir("proctrace", NULL);
    if (!proc_dir) { ret=-ENOMEM; goto err_wq; }
    if (!proc_create("new",0666,proc_dir,&proc_new_ops)) goto err_proc;
    if (!proc_create("sessions",0444,proc_dir,&proc_sessions_ops)) goto err_proc;

    fork_sym = symbol_exists(FORK_SYMBOL_PRIMARY)?FORK_SYMBOL_PRIMARY:
               symbol_exists(FORK_SYMBOL_FALLBACK)?FORK_SYMBOL_FALLBACK:NULL;
    if(!fork_sym){pr_err("proctrace: no fork\n");ret=-ENOENT;goto err_proc;}
    fork_kretprobe.kp.symbol_name=fork_sym;

    exec_sym = symbol_exists(EXEC_SYMBOL_PRIMARY)?EXEC_SYMBOL_PRIMARY:
               symbol_exists(EXEC_SYMBOL_FALLBACK)?EXEC_SYMBOL_FALLBACK:NULL;
    if(!exec_sym){pr_err("proctrace: no exec\n");ret=-ENOENT;goto err_proc;}
    exec_kretprobe.kp.symbol_name=exec_sym;

    open_sym = symbol_exists(OPEN_SYMBOL_PRIMARY)?OPEN_SYMBOL_PRIMARY:
               symbol_exists(OPEN_SYMBOL_FALLBACK)?OPEN_SYMBOL_FALLBACK:NULL;
    if(open_sym) open_kretprobe.kp.symbol_name=open_sym;

    /* chdir */
    chdir_sym = symbol_exists("__x64_sys_chdir")?"__x64_sys_chdir":
                symbol_exists("ksys_chdir")?"ksys_chdir":
                symbol_exists("sys_chdir")?"sys_chdir":NULL;
    if(chdir_sym) chdir_kretprobe.kp.symbol_name=chdir_sym;

    have_ksys_write=false; write_hook_name=NULL;
    if(symbol_exists("ksys_write")){
        ksys_write_kretprobe.kp.symbol_name="ksys_write";
        have_ksys_write=true; write_hook_name="ksys_write";
    } else if(symbol_exists("vfs_write")){
        vfs_write_kretprobe.kp.symbol_name="vfs_write";
        write_hook_name="vfs_write";
    }

    ret=register_kretprobe(&fork_kretprobe);
    if(ret){pr_err("proctrace: fork: %d\n",ret);goto err_proc;}
    ret=register_kretprobe(&exec_kretprobe);
    if(ret){pr_err("proctrace: exec: %d\n",ret);goto err_fork;}
    ret=register_kprobe(&exit_kprobe);
    if(ret){pr_err("proctrace: exit: %d\n",ret);goto err_exec;}

    if(open_sym){ret=register_kretprobe(&open_kretprobe);
        if(ret){pr_warn("proctrace: open: %d\n",ret);open_sym=NULL;}}
    if(chdir_sym){ret=register_kretprobe(&chdir_kretprobe);
        if(ret){pr_warn("proctrace: chdir: %d\n",ret);chdir_sym=NULL;}}
    if(write_hook_name){
        ret=have_ksys_write?register_kretprobe(&ksys_write_kretprobe)
                           :register_kretprobe(&vfs_write_kretprobe);
        if(ret){pr_warn("proctrace: write: %d\n",ret);write_hook_name=NULL;have_ksys_write=false;}
    }

    pr_info("proctrace: loaded (fork=%s exec=%s exit=do_exit open=%s chdir=%s write=%s ring=%zuKB)\n",
            fork_sym,exec_sym,open_sym?open_sym:"off",chdir_sym?chdir_sym:"off",
            write_hook_name?write_hook_name:"off", RING_BUF_SIZE/1024);
    return 0;

err_exec: unregister_kretprobe(&exec_kretprobe);
err_fork: unregister_kretprobe(&fork_kretprobe);
err_proc: proc_remove(proc_dir);
err_wq:   destroy_workqueue(log_wq);
    return ret?ret:-ENOMEM;
}

static void __exit proctrace_exit(void)
{
    struct trace_session *s, *tmp;
    if(write_hook_name){
        if(have_ksys_write)unregister_kretprobe(&ksys_write_kretprobe);
        else unregister_kretprobe(&vfs_write_kretprobe);
    }
    if(chdir_sym) unregister_kretprobe(&chdir_kretprobe);
    if(open_kretprobe.kp.symbol_name) unregister_kretprobe(&open_kretprobe);
    unregister_kprobe(&exit_kprobe);
    unregister_kretprobe(&exec_kretprobe);
    unregister_kretprobe(&fork_kretprobe);
    proc_remove(proc_dir);
    flush_workqueue(log_wq); destroy_workqueue(log_wq);
    mutex_lock(&sessions_mutex);
    list_for_each_entry_safe(s,tmp,&sessions,list){
        list_del(&s->list); s->ring.closed=true;
        wake_up_interruptible(&s->ring.wq_writer);
        session_free_all_tags(s); ring_destroy(&s->ring); kfree(s);
    }
    mutex_unlock(&sessions_mutex);
    pr_info("proctrace: unloaded\n");
}

module_init(proctrace_init);
module_exit(proctrace_exit);
