#include <compiler.h>
#include <kpmodule.h>
#include <common.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <stdint.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>
#include <accctl.h>

KPM_NAME("fshide");
KPM_VERSION("0.1.0");
KPM_LICENSE("AGPLv3");
KPM_AUTHOR("时汐安");
KPM_DESCRIPTION("Hide specified files and directories from userspace");

#ifdef FSHIDE_DEBUG
#define LOG_TAG            "[fshide]"
#define DBG(fmt, ...)      pr_info(LOG_TAG" [DBG] " fmt "\n", ##__VA_ARGS__)
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

struct linux_dirent64 {
	uint64_t        d_ino;
	int64_t         d_off;
	unsigned short  d_reclen;
	unsigned char   d_type;
	char            d_name[];
};

struct hide_entry {
	char   path[MAX_PATH_LEN];
	uid_t  uid;
	uint8_t active;
	uint8_t has_uid;
};

static struct hide_entry hide_list[MAX_HIDE_ENTRIES];
static int hide_count;
static int g_loading;

static void *(*do_memdup_user)(const void __user *, size_t) = 0;
static void (*do_kfree)(const void *) = 0;

static void clear_all(void)
{
	DBG("clear_all: was %d entries", hide_count);
	memset(hide_list, 0, sizeof(hide_list));
	hide_count = 0;
}

static int find_path(const char *path)
{
	int i;
	if (!path || !*path || path[0] != '/') {
		DBG("find_path: reject non-absolute or NULL");
		return -1;
	}
	for (i = 0; i < hide_count; i++) {
		if (hide_list[i].active && !strcmp(hide_list[i].path, path)) {
			DBG("find_path: found '%s' at index %d", path, i);
			return i;
		}
	}
	DBG("find_path: '%s' not found in %d entries", path, hide_count);
	return -1;
}

static int add_path_with_uid(const char *path, uid_t uid, int has_uid)
{
	if (!path || !*path || path[0] != '/') return -EINVAL;
	if (hide_count >= MAX_HIDE_ENTRIES) {
		DBG("add_path: FULL (%d/%d) dropping '%s'", hide_count, MAX_HIDE_ENTRIES, path);
		return -ENOSPC;
	}
	if (find_path(path) >= 0) {
		DBG("add_path: duplicate '%s', skip", path);
		return 0;
	}
	strncpy(hide_list[hide_count].path, path, MAX_PATH_LEN - 1);
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

static void parse_config_line(const char *line)
{
	const char *p = line;
	const char *path_end, *uid_part;
	char path_buf[MAX_PATH_LEN];
	int plen;

	while (*p == ' ' || *p == '\t') p++;
	if (!*p || *p == '#' || *p == '\n' || *p == '\r') {
		DBG("parse_line: skip blank/comment: %.40s", line);
		return;
	}
	if (*p != '/') {
		DBG("parse_line: skip non-absolute: %s", line);
		return;
	}
	path_end = p;
	while (*path_end && *path_end != ' ' && *path_end != '\t' &&
	       *path_end != '\n' && *path_end != '\r')
		path_end++;
	plen = (int)(path_end - p);
	if (plen >= MAX_PATH_LEN) plen = MAX_PATH_LEN - 1;
	memcpy(path_buf, p, plen);
	path_buf[plen] = '\0';
	while (plen > 1 && path_buf[plen - 1] == '/') { path_buf[--plen] = '\0'; }
	uid_part = path_end;
	while (*uid_part == ' ' || *uid_part == '\t') uid_part++;
	DBG("parse_line: path='%s' uid_part='%s'", path_buf, uid_part);
	if (!strncasecmp(uid_part, "uid:", 4)) {
		uid_t uid;
		if (parse_uid_str(uid_part + 4, &uid) < 0) {
			DBG("parse_line: bad uid in '%s'", line);
			return;
		}
		add_path_with_uid(path_buf, uid, 1);
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
	const char *p;

	DBG("load_config: start g_loading=%d", g_loading);
	g_loading = 1;
	memset(kbuf, 0, sizeof(kbuf));
	set_priv_sel_allow(current, true);

	upath = copy_to_user_stack(CONFIG_PATH, sizeof(CONFIG_PATH));
	if (!upath || (long)upath < 0) {
		DBG("load_config: copy_to_user_stack(path) FAILED ptr=0x%lx", (long)upath);
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
		const char *line_end = p;
		while (*line_end && *line_end != '\n' && *line_end != '\r')
			line_end++;
		parse_config_line(p);
		p = (*line_end == '\0') ? line_end : line_end + 1;
		while ((*p == '\n' || *p == '\r') && *p) p++;
	}
	DBG("load_config: done entries=%d bytes=%ld", hide_count, total);
	g_loading = 0;
	return 0;
fail:
	set_priv_sel_allow(current, false);
	g_loading = 0;
	return -EIO;
}

static int match_hide_path(const char *path, uid_t uid)
{
	int i;

	if (!path || !*path || path[0] != '/') return -1;

	for (i = 0; i < hide_count; i++) {
		if (!hide_list[i].active) continue;
		if (strcmp(hide_list[i].path, path) != 0) continue;
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

/* Resolve an fd to its filesystem path.
 * Method 1: readlinkat(fd, "") — works for most fs types
 * Method 2: /proc/self/fd/<fd> — universal fallback for procfs etc. */
static int resolve_fd_path(long fd, char *buf, int buflen)
{
	void __user *upath, *ubuf;
	long n;
	char self_fd_path[48];

	/* Method 1: readlinkat on the fd itself */
	upath = copy_to_user_stack("", sizeof(""));
	if (upath && (long)upath >= 0) {
		memset(buf, 0, buflen);
		ubuf = copy_to_user_stack(buf, buflen);
		if (ubuf && (long)ubuf >= 0) {
			n = raw_syscall4(__NR_readlinkat, fd, (long)upath,
			                 (long)ubuf, buflen - 1);
			if (n > 0 && n < buflen) {
				compat_strncpy_from_user(buf, ubuf, (int)n + 1);
				buf[n] = '\0';
				if (buf[0] == '/') return (int)n;
			}
		}
	}

	/* Method 2: read /proc/self/fd/<fd> as fallback */
	if ((int)fd < 0 || (int)fd >= 1000000) return -1;
	n = scnprintf(self_fd_path, sizeof(self_fd_path), "/proc/self/fd/%ld", fd);
	if (n <= 0 || n >= (long)sizeof(self_fd_path)) return -1;

	upath = copy_to_user_stack(self_fd_path, n + 1);
	if (!upath || (long)upath < 0) return -1;

	fd = raw_syscall4(__NR_openat, AT_FDCWD, (long)upath, O_RDONLY, 0L);
	if (fd < 0) return -1;

	memset(buf, 0, buflen);
	ubuf = copy_to_user_stack(buf, buflen);
	if (!ubuf || (long)ubuf < 0) {
		raw_syscall1(__NR_close, fd);
		return -1;
	}

	n = raw_syscall4(__NR_readlinkat, fd, (long)upath, (long)ubuf, buflen - 1);
	raw_syscall1(__NR_close, fd);
	if (n > 0 && n < buflen) {
		compat_strncpy_from_user(buf, ubuf, (int)n + 1);
		buf[n] = '\0';
		return (int)n;
	}
	return -1;
}

static int fetch_user_path(const char __user *uptr, char *buf, int buflen)
{
	int flen;

	flen = compat_strncpy_from_user(buf, uptr, buflen);
	if (flen <= 0 || flen >= buflen) return -1;
	buf[flen] = '\0';
	return flen;
}

static int resolve_hook_fd(hook_fargs4_t *args, int arg_idx, char *buf, int buflen)
{
	long fd;

	if (ensure_loaded() < 0) return -1;
	fd = (long)syscall_argn(args, arg_idx);
	DBG("resolve_hook_fd: fd=%ld uid=%d comm=%s",
	    fd, current_uid(), get_task_comm(current));
	return resolve_fd_path(fd, buf, buflen);
}

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

static void before_openat(hook_fargs4_t *args, void *udata)
{
	(void)udata;
	hide_by_path(args, 1, "openat");
}

static void before_faccessat(hook_fargs4_t *args, void *udata)
{
	(void)udata;
	hide_by_path(args, 1, "faccessat");
}

static void before_newfstatat(hook_fargs4_t *args, void *udata)
{
	(void)udata;
	hide_by_path(args, 1, "newfstatat");
}

static void before_chdir(hook_fargs2_t *args, void *udata)
{
	(void)udata;
	hide_by_path((hook_fargs4_t *)args, 0, "chdir");
}

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

static void before_getdents64(hook_fargs3_t *args, void *udata)
{
	char kbuf[MAX_PATH_LEN];
	int rlen;

	(void)udata;
	rlen = resolve_hook_fd((hook_fargs4_t *)args, 0, kbuf, sizeof(kbuf));
	DBG("before_getdents64: resolved rlen=%d path='%s'", rlen,
	    rlen > 0 ? kbuf : "(fail)");
	if (rlen > 0) {
		void *__user *sptr = copy_to_user_stack(kbuf, rlen + 1);
		args->local.data0 = (sptr && (long)sptr >= 0)
		                     ? (uint64_t)sptr : 0;
	} else {
		args->local.data0 = 0;
	}
}

static void after_getdents64(hook_fargs3_t *args, void *udata)
{
	void __user *dir_ptr, *ubuf;
	char dir_path[MAX_PATH_LEN];
	char *kbuf;
	long total, pos, new_total;
	int dlen;

	(void)udata;
	if (ensure_loaded() < 0) return;
	total = (long)args->ret;
	if (total <= 0) return;

	dir_ptr = (void __user *)args->local.data0;
	if (!dir_ptr) {
		/* Cannot resolve directory path (should not happen with
		   /proc/self/fd/ fallback), skip filtering safely */
		DBG("after_getdents64: no dir_path, SKIP");
		return;
	}

	dlen = compat_strncpy_from_user(dir_path, dir_ptr, sizeof(dir_path));
	if (dlen <= 0 || dlen >= MAX_PATH_LEN) return;
	dir_path[dlen] = '\0';

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
			scnprintf(full, sizeof(full), "%s/%s",
			         dir_path, d->d_name);
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

struct hook_def {
	int nr;
	int narg;
	void *before;
	void *after;
};

static const struct hook_def hooks[] = {
	{ __NR_openat,     4, before_openat,     NULL },
	{ __NR_faccessat,  4, before_faccessat,   NULL },
	{ __NR_newfstatat, 4, before_newfstatat,  NULL },
	{ __NR_getdents64, 3, before_getdents64,  after_getdents64 },
	{ __NR_chdir,      1, before_chdir,       NULL },
	{ __NR_fchdir,     1, before_fchdir,      NULL },
};
#define HOOK_COUNT (sizeof(hooks) / sizeof(hooks[0]))

static long fshide_init(const char *args, const char *event, void *__user reserved)
{
	int i;
	hook_err_t err;
	(void)args;
	(void)event;
	(void)reserved;


	DBG("INIT v0.1.0 kpver=0x%x kver=0x%x event='%s'",
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
