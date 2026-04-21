/*
 * fshide.c - VFS filldir64 hook for file hiding (KernelPatch KPM)
 */

#include <compiler.h>
#include <kpmodule.h>
#include <common.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/kallsyms.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <stdint.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <accctl.h>

KPM_NAME("fshide_vfs");
KPM_VERSION("0.3.0");
KPM_LICENSE("AGPLv3");
KPM_AUTHOR("Advanced Hide");
KPM_DESCRIPTION("VFS filldir64 hook for file hiding");

/* ===== 调试开关 ===== */
#ifdef FSHIDE_DEBUG
#define LOG_TAG            "[fshide_vfs]"
#define DBG(fmt, ...)      pr_info(LOG_TAG" [DBG] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG(fmt, ...)      ((void)0)
#endif

/* ===== 配置常量 ===== */
#define CONFIG_PATH        "/data/adb/fshide"
#define MAX_HIDE_ENTRIES   128
#define MAX_PATH_LEN       512

struct hide_entry {
    char path[MAX_PATH_LEN];
    uid_t uid;
    bool active;
    bool has_uid;
};

static struct hide_entry hide_list[MAX_HIDE_ENTRIES];
static int hide_count;
static DEFINE_MUTEX(hide_lock);

/* ===== Ftrace 相关 ===== */
static struct ftrace_ops fops;
static unsigned long target_ip;                  // filldir64 地址
static void *return_thunk;                       // ret 指令地址

/* ===== 符号解析（处理未导出符号） ===== */
static unsigned long lookup_name(const char *name)
{
    unsigned long addr = kallsyms_lookup_name(name);
    if (!addr) {
        struct kprobe kp = { .symbol_name = name };
        if (register_kprobe(&kp) == 0) {
            addr = (unsigned long)kp.addr;
            unregister_kprobe(&kp);
        }
    }
    return addr;
}

/* ===== 白名单检查（当前仅允许 root 看到全部） ===== */
static inline bool is_whitelisted_uid(uid_t uid)
{
    return (uid == 0);
}

/* ===== 配置文件解析（与原版兼容） ===== */
static void clear_all_entries(void)
{
    mutex_lock(&hide_lock);
    memset(hide_list, 0, sizeof(hide_list));
    hide_count = 0;
    mutex_unlock(&hide_lock);
}

static int find_entry(const char *path, uid_t uid, bool has_uid)
{
    int i;
    if (!path || path[0] != '/')
        return -1;
    for (i = 0; i < hide_count; i++) {
        if (!hide_list[i].active)
            continue;
        if (strcmp(hide_list[i].path, path) != 0)
            continue;
        if (!has_uid && !hide_list[i].has_uid)
            return i;
        if (has_uid && hide_list[i].has_uid && hide_list[i].uid == uid)
            return i;
    }
    return -1;
}

static int add_entry(const char *path, uid_t uid, bool has_uid)
{
    if (!path || path[0] != '/')
        return -EINVAL;
    if (hide_count >= MAX_HIDE_ENTRIES)
        return -ENOSPC;

    mutex_lock(&hide_lock);
    if (find_entry(path, uid, has_uid) >= 0) {
        mutex_unlock(&hide_lock);
        return 0;
    }

    strncpy(hide_list[hide_count].path, path, MAX_PATH_LEN - 1);
    hide_list[hide_count].path[MAX_PATH_LEN - 1] = '\0';
    hide_list[hide_count].uid = uid;
    hide_list[hide_count].has_uid = has_uid;
    hide_list[hide_count].active = true;
    hide_count++;
    mutex_unlock(&hide_lock);
    return 0;
}

static long parse_uid(const char *s, uid_t *out)
{
    long val = 0;
    if (!s || *s < '0' || *s > '9')
        return -EINVAL;
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (*s++ - '0');
        if (val > ((uid_t)-1))
            return -ERANGE;
    }
    *out = (uid_t)val;
    return 0;
}

static void parse_config_line(char *line)
{
    char *p = line;
    char *path_end, *uid_part;
    char path_buf[MAX_PATH_LEN];
    int plen;

    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#' || *p == '\0' || *p == '\n')
        return;
    if (*p != '/')
        return;

    path_end = p;
    while (*path_end && *path_end != ' ' && *path_end != '\t' &&
           *path_end != '\n' && *path_end != '\r')
        path_end++;

    plen = path_end - p;
    if (plen >= MAX_PATH_LEN) plen = MAX_PATH_LEN - 1;
    memcpy(path_buf, p, plen);
    path_buf[plen] = '\0';
    while (plen > 1 && path_buf[plen-1] == '/')
        path_buf[--plen] = '\0';

    uid_part = path_end;
    while (*uid_part == ' ' || *uid_part == '\t') uid_part++;

    if (strncmp(uid_part, "uid:", 4) == 0) {
        const char *up = uid_part + 4;
        while (*up) {
            const char *uend = up;
            uid_t uid;
            while (*uend && *uend != ',') uend++;
            if (parse_uid(up, &uid) == 0)
                add_entry(path_buf, uid, true);
            up = (*uend == ',') ? uend + 1 : uend;
        }
    } else {
        add_entry(path_buf, 0, false);
    }
}

static int load_config(void)
{
    struct file *f;
    char *buf;
    loff_t pos = 0;
    ssize_t len;
    char *line, *next;

    f = filp_open(CONFIG_PATH, O_RDONLY, 0);
    if (IS_ERR(f)) {
        pr_err(LOG_TAG " failed to open %s\n", CONFIG_PATH);
        return PTR_ERR(f);
    }

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf) {
        filp_close(f, NULL);
        return -ENOMEM;
    }

    len = kernel_read(f, buf, PAGE_SIZE - 1, &pos);
    if (len < 0) {
        kfree(buf);
        filp_close(f, NULL);
        return len;
    }
    buf[len] = '\0';
    filp_close(f, NULL);

    clear_all_entries();

    line = buf;
    while (line && *line) {
        next = strchr(line, '\n');
        if (next)
            *next++ = '\0';
        parse_config_line(line);
        line = next;
    }

    kfree(buf);
    DBG("config loaded: %d entries", hide_count);
    return 0;
}

/* ===== 判断目录项是否应隐藏 ===== */
static bool should_hide_dentry(const char *name, int namelen)
{
    struct task_struct *task = current;
    uid_t uid = from_kuid(&init_user_ns, task_uid(task));
    char full_path[MAX_PATH_LEN];
    struct path pwd;
    char *cwd = NULL;
    bool hide = false;
    int i;

    if (is_whitelisted_uid(uid))
        return false;

    get_fs_pwd(current->fs, &pwd);
    cwd = dentry_path_raw(pwd.dentry, full_path, MAX_PATH_LEN);
    path_put(&pwd);
    if (IS_ERR(cwd))
        cwd = full_path;

    snprintf(full_path, MAX_PATH_LEN, "%s/%.*s", cwd, namelen, name);

    mutex_lock(&hide_lock);
    for (i = 0; i < hide_count; i++) {
        if (!hide_list[i].active)
            continue;
        if (strcmp(hide_list[i].path, full_path) != 0)
            continue;
        if (hide_list[i].has_uid && hide_list[i].uid != uid)
            continue;
        hide = true;
        break;
    }
    mutex_unlock(&hide_lock);

    return hide;
}

/* ===== Ftrace 钩子 ===== */
static void notrace filldir64_hook(unsigned long ip, unsigned long parent_ip,
                                   struct ftrace_ops *ops, struct pt_regs *regs)
{
    const char *name;
    int namlen;

    // x86_64 调用约定：RDI=buf, RSI=name, RDX=namlen
    name = (const char *)regs->si;
    namlen = (int)regs->dx;

    if (!name || namlen <= 0)
        return;

    if (should_hide_dentry(name, namlen)) {
        regs->ip = (unsigned long)return_thunk;
    }
}

/* ===== 定位 ret 指令地址 ===== */
static int setup_return_thunk(void)
{
    unsigned long addr = lookup_name("mutex_unlock");
    if (!addr)
        return -ENOENT;

    unsigned char *p = (unsigned char *)addr;
    int i;
    for (i = 0; i < 64; i++) {
        if (p[i] == 0xC3) {
            return_thunk = (void *)(addr + i);
            DBG("return_thunk at %p", return_thunk);
            return 0;
        }
    }
    return -EFAULT;
}

/* ===== 注册 Ftrace 钩子 ===== */
static int register_filldir64_hook(void)
{
    int ret;

    target_ip = lookup_name("filldir64");
    if (!target_ip) {
        pr_err(LOG_TAG " filldir64 not found\n");
        return -ENOENT;
    }
    DBG("filldir64 at 0x%lx", target_ip);

    ret = setup_return_thunk();
    if (ret)
        return ret;

    fops.func = filldir64_hook;
    fops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&fops, target_ip, 0, 0);
    if (ret) {
        pr_err(LOG_TAG " ftrace_set_filter_ip failed: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&fops);
    if (ret) {
        pr_err(LOG_TAG " register_ftrace_function failed: %d\n", ret);
        ftrace_set_filter_ip(&fops, target_ip, 1, 0);
        return ret;
    }

    pr_info(LOG_TAG " VFS hook installed\n");
    return 0;
}

static void unregister_filldir64_hook(void)
{
    unregister_ftrace_function(&fops);
    ftrace_set_filter_ip(&fops, target_ip, 1, 0);
    pr_info(LOG_TAG " VFS hook removed\n");
}

/* ===== KPM 接口 ===== */
static long fshide_init(const char *args, const char *event, void __user *reserved)
{
    DBG("init v0.3.0");

    load_config();
    return register_filldir64_hook();
}

static long fshide_ctl0(const char *ctl_args, char *__user out_msg, int outlen)
{
    char *resp;
    int pos = 0, i;

    resp = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!resp)
        return -ENOMEM;

    if (!ctl_args || !*ctl_args) {
        pos += scnprintf(resp + pos, PAGE_SIZE - pos,
                         "cmds: reload|list|status");
        goto out;
    }

    if (!strcmp(ctl_args, "reload")) {
        load_config();
        pos += scnprintf(resp + pos, PAGE_SIZE - pos,
                         "reloaded %d entries", hide_count);
    } else if (!strcmp(ctl_args, "list")) {
        pos += scnprintf(resp + pos, PAGE_SIZE - pos,
                         "entries=%d\n", hide_count);
        mutex_lock(&hide_lock);
        for (i = 0; i < hide_count && pos < PAGE_SIZE - 128; i++) {
            if (!hide_list[i].active)
                continue;
            pos += scnprintf(resp + pos, PAGE_SIZE - pos,
                             "  [%d] '%s' uid=%d%s\n",
                             i, hide_list[i].path,
                             hide_list[i].uid,
                             hide_list[i].has_uid ? "" : " [global]");
        }
        mutex_unlock(&hide_lock);
    } else if (!strcmp(ctl_args, "status")) {
        pos += scnprintf(resp + pos, PAGE_SIZE - pos,
                         "VFS hook active, entries=%d, filldir64=%lx",
                         hide_count, target_ip);
    } else {
        pos += scnprintf(resp + pos, PAGE_SIZE - pos,
                         "unknown cmd: %s", ctl_args);
    }

out:
    if (out_msg && outlen > 0)
        compat_copy_to_user(out_msg, resp, pos + 1);
    kfree(resp);
    return 0;
}

static long fshide_exit(void *__user reserved)
{
    unregister_filldir64_hook();
    clear_all_entries();
    DBG("exited");
    return 0;
}

KPM_INIT(fshide_init);
KPM_CTL0(fshide_ctl0);
KPM_EXIT(fshide_exit);
