/*
 * fshide.c - Hide files and directories from userspace (KernelPatch module)
 * Optimized version with improved path normalization, fd resolution,
 * config parsing and reduced code duplication.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <common.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#include <stdint.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>
#include <accctl.h>

KPM_NAME("fshide");
KPM_VERSION("0.2.1");
KPM_LICENSE("AGPLv3");
KPM_AUTHOR("时汐安");
KPM_DESCRIPTION("Hide specified files and directories from userspace");

/* ---------- Debug & Configuration ---------- */
#ifdef FSHIDE_DEBUG
#define LOG_TAG            "[fshide]"
#define DBG(fmt, ...)      pr_info(LOG_TAG " [DBG] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG(fmt, ...)      ((void)0)
#endif

#define CONFIG_PATH        "/data/adb/fshide"

#define MAX_HIDE_ENTRIES   128
#define MAX_PATH_LEN       512
#define MAX_UID_DIGITS     10
#define CONFIG_BUF_SIZE    2048
#define RESP_BUF_SIZE      2048
#define RESP_LINE_RESERVE  80
#define DIRENT64_BUF_SIZE  4096

#ifndef AT_FDCWD
#define AT_FDCWD           (-100)
#endif
#ifndef O_RDONLY
#define O_RDONLY           0
#endif

#ifndef __NR_newfstatat
#define __NR_newfstatat __NR3264_fstatat
#endif

/* ---------- Data Structures ---------- */
struct linux_dirent64 {
    uint64_t        d_ino;
    int64_t         d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[];
};

struct hide_entry {
    char    path[MAX_PATH_LEN];
    uid_t   uid;
    uint8_t active;
    uint8_t has_uid;
};

static struct hide_entry hide_list[MAX_HIDE_ENTRIES];
static int hide_count;
static int g_loading;

/* Kernel function pointers */
static void *(*do_memdup_user)(const void __user *, size_t) = NULL;
static void (*do_kfree)(const void *) = NULL;

/* ---------- Utility Functions ---------- */
static void normalize_path(char *path)
{
    int len;
    if (!path || !*path) return;
    len = strlen(path);
    while (len > 1 && path[len - 1] == '/') {
        path[--len] = '\0';
    }
}

static void clear_all(void)
{
    DBG("clear_all: was %d entries", hide_count);
    memset(hide_list, 0, sizeof(hide_list));
    hide_count = 0;
}

static int find_path(const char *path, uid_t uid, int has_uid)
{
    int i;
    char tmp[MAX_PATH_LEN];

    if (!path || !*path || path[0] != '/') {
        DBG("find_path: reject non-absolute or NULL");
        return -1;
    }

    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    normalize_path(tmp);

    for (i = 0; i < hide_count; i++) {
        if (!hide_list[i].active) continue;
        if (strcmp(hide_list[i].path, tmp) != 0) continue;
        if (!has_uid && !hide_list[i].has_uid) {
            DBG("find_path: found global '%s' at index %d", tmp, i);
            return i;
        }
        if (has_uid && hide_list[i].has_uid && hide_list[i].uid == uid) {
            DBG("find_path: found '%s' uid=%d at index %d", tmp, uid, i);
            return i;
        }
    }
    DBG("find_path: '%s'%s not found", tmp,
        has_uid ? " uid matched" : "");
    return -1;
}

static int add_path_with_uid(const char *path, uid_t uid, int has_uid)
{
    char tmp[MAX_PATH_LEN];

    if (!path || !*path || path[0] != '/') return -EINVAL;
    if (hide_count >= MAX_HIDE_ENTRIES) {
        DBG("add_path: FULL (%d/%d) dropping '%s'", hide_count, MAX_HIDE_ENTRIES, path);
        return -ENOSPC;
    }

    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    normalize_path(tmp);

    if (find_path(tmp, uid, has_uid) >= 0) {
        DBG("add_path: duplicate '%s', skip", tmp);
        return 0;
    }

    strncpy(hide_list[hide_count].path, tmp, MAX_PATH_LEN - 1);
    hide_list[hide_count].path[MAX_PATH_LEN - 1] = '\0';
    hide_list[hide_count].active = 1;
    hide_list[hide_count].uid = uid;
    hide_list[hide_count].has_uid = has_uid ? 1 : 0;

    DBG("add_path: [%d] '%s' uid=%d has_uid=%d",
        hide_count, hide_list[hide_count].path,
        hide_list[hide_count].uid, hide_list[hide_count].has_uid);
    hide_count++;
    return 0;
}

static long parse_uid_str(const char *s, uid_t *out)
{
    long val = 0;
    int digits = 0;
    if (!s || !*s || *s < '0' || *s > '9') return -EINVAL;
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (*s++ - '0');
        digits++;
        if (digits > MAX_UID_DIGITS) return -ERANGE;
    }
    if (val < 0 || val > (long)(uid_t)-1) return -ERANGE;
    *out = (uid_t)val;
    return 0;
}

/* ---------- Config File Parsing ---------- */
static void parse_config_line(char *line)
{
    char *p = line;
    char *comment;
    char *path_end, *uid_part;
    char path_buf[MAX_PATH_LEN];
    int plen;

    /* Strip inline comment */
    comment = strchr(line, '#');
    if (comment) *comment = '\0';

    /* Trim leading whitespace */
    while (isspace(*p)) p++;
    if (!*p) {
        DBG("parse_line: skip empty/comment");
        return;
    }

    if (*p != '/') {
        DBG("parse_line: skip non-absolute: %s", p);
        return;
    }

    path_end = p;
    while (*path_end && !isspace(*path_end))
        path_end++;

    plen = (int)(path_end - p);
    if (plen >= MAX_PATH_LEN) plen = MAX_PATH_LEN - 1;
    memcpy(path_buf, p, plen);
    path_buf[plen] = '\0';
    normalize_path(path_buf);

    uid_part = path_end;
    while (isspace(*uid_part)) uid_part++;

    DBG("parse_line: path='%s' uid_part='%s'", path_buf, uid_part);

    if (!strncasecmp(uid_part, "uid:", 4)) {
        const char *up = uid_part + 4;
        while (*up) {
            uid_t uid;
            const char *uend = up;
            while (*uend && *uend != ',') uend++;
            if (parse_uid_str(up, &uid) >= 0)
                add_path_with_uid(path_buf, uid, 1);
            up = (*uend == ',') ? uend + 1 : uend;
        }
    } else {
        add_path_with_uid(path_buf, 0, 0);
    }
}

static int load_config(void)
{
    long fd;
    char kbuf[CONFIG_BUF_SIZE];
    void __user *upath, *ubuf;
    long total, nread;
    char *p;

    DBG("load_config: start g_loading=%d", g_loading);
    g_loading = 1;
    memset(kbuf, 0, sizeof(kbuf));
    set_priv_sel_allow(current, true);

    upath = copy_to_user_stack(CONFIG_PATH, sizeof(CONFIG_PATH));
    if (!upath || (long)upath < 0) {
        DBG("load_config: copy_to_user_stack(path) FAILED");
        goto fail;
    }

    fd = raw_syscall4(__NR_openat, AT_FDCWD, (long)upath, O_RDONLY, 0L);
    if (fd < 0) {
        DBG("load_config: openat('%s') FAILED err=%ld", CONFIG_PATH, fd);
        goto fail;
    }
    DBG("load_config: opened fd=%ld", fd);

    ubuf = copy_to_user_stack(kbuf, CONFIG_BUF_SIZE);
    if (!ubuf || (long)ubuf < 0) {
        raw_syscall1(__NR_close, fd);
        goto fail;
    }

    total = 0;
    while (total < CONFIG_BUF_SIZE - 1) {
        nread = raw_syscall3(__NR_read, fd, (long)ubuf + total,
                             CONFIG_BUF_SIZE - 1 - total);
        if (nread <= 0) break;
        total += nread;
    }
    raw_syscall1(__NR_close, fd);
    DBG("load_config: read total=%ld bytes", total);

    if (total <= 0) {
        DBG("load_config: read EMPTY or FAILED");
        goto fail;
    }

    compat_strncpy_from_user(kbuf, ubuf,
                             total < CONFIG_BUF_SIZE ? (int)total + 1 : CONFIG_BUF_SIZE);
    set_priv_sel_allow(current, false);

    clear_all();
    p = kbuf;
    while (*p) {
        char *line_end = strpbrk(p, "\n\r");
        if (!line_end) {
            parse_config_line(p);
            break;
        }
        *line_end = '\0';
        parse_config_line(p);
        p = line_end + 1;
        while (*p == '\n' || *p == '\r') p++;
    }

    DBG("load_config: done entries=%d", hide_count);
    g_loading = 0;
    return 0;

fail:
    set_priv_sel_allow(current, false);
    g_loading = 0;
    return -EIO;
}

/* ---------- Path Matching & FD Resolution ---------- */
static int match_hide_path(const char *path, uid_t uid)
{
    int i;
    char tmp[MAX_PATH_LEN];

    if (!path || !*path || path[0] != '/') return -1;

    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    normalize_path(tmp);

    for (i = 0; i < hide_count; i++) {
        if (!hide_list[i].active) continue;
        if (strcmp(hide_list[i].path, tmp) != 0) continue;
        if (hide_list[i].has_uid && hide_list[i].uid != uid) {
            DBG("match_path: uid mismatch entry[%d] uid=%d caller=%d",
                i, hide_list[i].uid, uid);
            continue;
        }
        DBG("match_path: HIT entry[%d] '%s' uid=%d caller=%d",
            i, hide_list[i].path, hide_list[i].uid, uid);
        return i;
    }
    return -1;
}

static int ensure_loaded(void)
{
    if (g_loading) return -1;
    if (hide_count <= 0) {
        load_config();
        if (hide_count <= 0) return -1;
    }
    return 0;
}

static int resolve_fd_path(long fd, char *buf, int buflen)
{
    char self_fd_path[48];
    void __user *upath, *ubuf;
    long n, fd2;

    if ((int)fd < 0 || (int)fd >= 1000000) return -1;
    n = scnprintf(self_fd_path, sizeof(self_fd_path), "/proc/self/fd/%ld", fd);
    if (n <= 0 || n >= (long)sizeof(self_fd_path)) return -1;

    upath = copy_to_user_stack(self_fd_path, n + 1);
    if (!upath || (long)upath < 0) return -1;

    fd2 = raw_syscall4(__NR_openat, AT_FDCWD, (long)upath, O_RDONLY, 0L);
    if (fd2 < 0) return -1;

    memset(buf, 0, buflen);
    ubuf = copy_to_user_stack(buf, buflen);
    if (!ubuf || (long)ubuf < 0) {
        raw_syscall1(__NR_close, fd2);
        return -1;
    }

    n = raw_syscall4(__NR_readlinkat, fd2, (long)upath, (long)ubuf, buflen - 1);
    raw_syscall1(__NR_close, fd2);
    if (n > 0 && n < buflen) {
        compat_strncpy_from_user(buf, ubuf, (int)n + 1);
        buf[n] = '\0';
        return (int)n;
    }
    return -1;
}

static int fetch_user_path(const char __user *uptr, char *buf, int buflen)
{
    int flen = compat_strncpy_from_user(buf, uptr, buflen);
    if (flen <= 0 || flen >= buflen) return -1;
    buf[flen] = '\0';
    normalize_path(buf);
    return flen;
}

static int resolve_hook_fd(hook_fargs4_t *args, int arg_idx, char *buf, int buflen)
{
    long fd = (long)syscall_argn(args, arg_idx);
    DBG("resolve_hook_fd: fd=%ld uid=%d comm=%s",
        fd, current_uid(), get_task_comm(current));
    return resolve_fd_path(fd, buf, buflen);
}

/* ---------- Hook Handlers ---------- */
static void hide_by_path(hook_fargs4_t *args, int arg_idx, const char *name)
{
    char buf[MAX_PATH_LEN];

    if (ensure_loaded() < 0) return;
    if (fetch_user_path((const char __user *)syscall_argn(args, arg_idx),
                        buf, sizeof(buf)) < 0) {
        DBG("hide_by_path(%s): bad path", name);
        return;
    }

    DBG("hide_by_path(%s): checking '%s' uid=%d comm=%s",
        name, buf, current_uid(), get_task_comm(current));

    if (match_hide_path(buf, current_uid()) >= 0) {
        args->skip_origin = 1;
        args->ret = (uint64_t)(long)(-ENOENT);
        DBG("hide_by_path(%s): HIDDEN '%s' uid=%d", name, buf, current_uid());
    } else {
        DBG("hide_by_path(%s): PASS '%s' uid=%d", name, buf, current_uid());
    }
}

/* Macro to generate simple path-based before hooks */
#define DEFINE_PATH_HOOK(name, arg_idx) \
static void before_##name(hook_fargs4_t *args, void *udata) \
{ \
    (void)udata; \
    hide_by_path(args, arg_idx, #name); \
}

DEFINE_PATH_HOOK(openat, 1)
DEFINE_PATH_HOOK(faccessat, 1)
DEFINE_PATH_HOOK(newfstatat, 1)
DEFINE_PATH_HOOK(chdir, 0)

/* fchdir needs special FD resolution */
static void before_fchdir(hook_fargs1_t *args, void *udata)
{
    char kbuf[MAX_PATH_LEN];
    (void)udata;

    if (resolve_hook_fd((hook_fargs4_t *)args, 0, kbuf, sizeof(kbuf)) > 0) {
        DBG("before_fchdir: resolved -> '%s'", kbuf);
        if (match_hide_path(kbuf, current_uid()) >= 0) {
            args->skip_origin = 1;
            args->ret = (uint64_t)(long)(-ENOENT);
            DBG("before_fchdir: HIDDEN '%s' uid=%d", kbuf, current_uid());
            return;
        }
    }
    DBG("before_fchdir: PASS");
}

/* getdents64 uses before/after to filter directory entries */
static void before_getdents64(hook_fargs3_t *args, void *udata)
{
    static char dir_path[MAX_PATH_LEN];
    int rlen;
    (void)udata;

    rlen = resolve_hook_fd((hook_fargs4_t *)args, 0, dir_path, sizeof(dir_path));
    if (rlen > 0) {
        args->local.data0 = (uint64_t)dir_path;
    } else {
        args->local.data0 = 0;
    }
    DBG("before_getdents64: rlen=%d path='%s'",
        rlen, rlen > 0 ? dir_path : "(fail)");
}

static void after_getdents64(hook_fargs3_t *args, void *udata)
{
    char *dir_path = (char *)args->local.data0;
    void __user *ubuf;
    char *kbuf;
    long total, pos, new_total;
    (void)udata;

    if (ensure_loaded() < 0) return;
    total = (long)args->ret;
    if (total <= 0 || !dir_path) {
        DBG("after_getdents64: no data or dir_path, SKIP");
        return;
    }

    ubuf = (void __user *)syscall_argn(args, 1);
    if (!ubuf) return;

    if (total > DIRENT64_BUF_SIZE) total = DIRENT64_BUF_SIZE;
    kbuf = do_memdup_user(ubuf, total);
    if (IS_ERR(kbuf)) return;

    pos = 0;
    new_total = 0;
    while (pos < total) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)(kbuf + pos);
        unsigned short reclen = d->d_reclen;

        if (!reclen || pos + reclen > total) break;

        if (d->d_name[0]) {
            char full[MAX_PATH_LEN];
            scnprintf(full, sizeof(full), "%s/%s", dir_path, d->d_name);
            if (match_hide_path(full, current_uid()) >= 0) {
                DBG("after_getdents64: FILTER '%s'", full);
                pos += reclen;
                continue;
            }
        }

        if (new_total != pos)
            memmove(kbuf + new_total, kbuf + pos, reclen);
        new_total += reclen;
        pos += reclen;
    }

    if (new_total < total && new_total > 0) {
        compat_copy_to_user(ubuf, kbuf, (int)new_total);
        args->ret = (uint64_t)new_total;
        DBG("after_getdents64: filtered %ld -> %ld bytes in '%s'",
            total, new_total, dir_path);
    } else {
        DBG("after_getdents64: PASS '%s' %ld bytes", dir_path, total);
    }
    do_kfree(kbuf);
}

/* ---------- Hook Table ---------- */
struct hook_def {
    int nr;
    int narg;
    void *before;
    void *after;
};

static const struct hook_def hooks[] = {
    { __NR_openat,     4, before_openat,     NULL },
    { __NR_faccessat,  4, before_faccessat,  NULL },
    { __NR_newfstatat, 4, before_newfstatat, NULL },
    { __NR_getdents64, 3, before_getdents64, after_getdents64 },
    { __NR_chdir,      1, before_chdir,      NULL },
    { __NR_fchdir,     1, before_fchdir,     NULL },
};
#define HOOK_COUNT (sizeof(hooks) / sizeof(hooks[0]))

/* ---------- Module Lifecycle ---------- */
static long fshide_init(const char *args, const char *event, void *__user reserved)
{
    int i;
    hook_err_t err;
    (void)args; (void)event; (void)reserved;

    DBG("INIT v0.2.1 kpver=0x%x kver=0x%x event='%s'",
        kpver, kver, event ? event : "(null)");

    do_memdup_user = (void *)kallsyms_lookup_name("memdup_user");
    do_kfree = (void *)kallsyms_lookup_name("kfree");
    if (!do_memdup_user || !do_kfree) {
        DBG("INIT: memdup_user/kfree NOT FOUND");
        return -ENOSYS;
    }

    clear_all();
    if (load_config() < 0)
        DBG("INIT: config load FAILED, hooks will be no-op");

    for (i = 0; i < (int)HOOK_COUNT; i++) {
        err = hook_syscalln(hooks[i].nr, hooks[i].narg,
                            hooks[i].before, hooks[i].after, NULL);
        if (err) {
            DBG("INIT: hook[%d] nr=%d FAIL=%d", i, hooks[i].nr, err);
            return err;
        }
        DBG("INIT: hook[%d] nr=%d OK", i, hooks[i].nr);
    }

    DBG("INIT: READY entries=%d", hide_count);
    return 0;
}

static long fshide_ctl0(const char *ctl_args, char *__user out_msg, int outlen)
{
    char resp[RESP_BUF_SIZE];
    int pos = 0;
    int i;

    DBG("ctl0: args='%s' outlen=%d", ctl_args ? ctl_args : "(null)", outlen);

    if (!ctl_args || !*ctl_args) {
        pos = scnprintf(resp, RESP_BUF_SIZE,
                        "cmds: reload|list|status");
        goto out;
    }

    if (!strcmp(ctl_args, "reload")) {
        load_config();
        pos = scnprintf(resp, RESP_BUF_SIZE,
                        "reloaded %d entries", hide_count);
        goto out;
    }

    if (!strcmp(ctl_args, "list")) {
        pos = scnprintf(resp, RESP_BUF_SIZE, "entries=%d\n", hide_count);
        for (i = 0; i < hide_count && pos < RESP_BUF_SIZE - RESP_LINE_RESERVE; i++) {
            if (hide_list[i].active)
                pos += scnprintf(resp + pos, RESP_BUF_SIZE - pos,
                                 "  [%d] '%s' uid=%d%s\n",
                                 i, hide_list[i].path,
                                 hide_list[i].uid,
                                 hide_list[i].has_uid ? "" : " [global]");
        }
        goto out;
    }

    if (!strcmp(ctl_args, "status")) {
        pos = scnprintf(resp, RESP_BUF_SIZE,
                        "entries=%d conf='%s'", hide_count, CONFIG_PATH);
        goto out;
    }

    pos = scnprintf(resp, RESP_BUF_SIZE, "unknown cmd: %s", ctl_args);

out:
    DBG("ctl0: response='%.*s'", pos, resp);
    if (out_msg && outlen > 0)
        compat_copy_to_user(out_msg, resp, pos + 1);
    return 0;
}

static long fshide_exit(void *__user reserved)
{
    int i;
    (void)reserved;
    DBG("EXIT: unhooking all syscalls");
    for (i = (int)HOOK_COUNT - 1; i >= 0; i--) {
        unhook_syscalln(hooks[i].nr, hooks[i].before, hooks[i].after);
    }
    clear_all();
    DBG("EXIT: done");
    return 0;
}

KPM_INIT(fshide_init);
KPM_CTL0(fshide_ctl0);
KPM_EXIT(fshide_exit);
