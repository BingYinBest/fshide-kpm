/*
 * fshide_vfs.c - Advanced file hiding via VFS filldir64 hooking
 *
 * 通过 Ftrace 劫持 filldir64，在 VFS 层实现高效文件隐藏。
 * 配置方式与原 fshide 兼容。
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/kallsyms.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>

#include "kpmodule.h"   // KernelPatch 框架头文件
#include "common.h"
#include "syscall.h"

/* ===== 配置与常量 ===== */
#define MODULE_NAME        "fshide_vfs"
#define MODULE_VERSION     "0.3.0"

#define CONFIG_PATH        "/data/adb/fshide"
#define MAX_HIDE_ENTRIES   128
#define MAX_PATH_LEN       512

/* ===== 隐藏条目结构 ===== */
struct hide_entry {
    char path[MAX_PATH_LEN];
    uid_t uid;
    bool active;
    bool has_uid;
};

static struct hide_entry hide_list[MAX_HIDE_ENTRIES];
static int hide_count;
static DEFINE_MUTEX(hide_lock);

/* ===== 白名单 UID (0 = root) ===== */
static inline bool is_whitelisted_uid(uid_t uid)
{
    // 在此处添加你的白名单逻辑，例如只允许特定 root 子进程看到隐藏文件
    // 目前默认：非 root (uid != 0) 会触发隐藏；root 看到全部。
    return (uid == 0);
}

/* ===== Ftrace 相关 ===== */
static struct ftrace_ops fops;
static unsigned long target_ip;                  // filldir64 的地址
static asmlinkage int (*orig_filldir64)(void *, const char *, int, loff_t, u64, unsigned int);

/* 用于快速返回的汇编指令段 (retq) */
static void *return_thunk;

/* ===== 辅助函数：符号解析 (处理未导出符号) ===== */
static unsigned long lookup_name(const char *name)
{
    unsigned long addr = kallsyms_lookup_name(name);
    if (!addr) {
        // 如果 kallsyms 没有，尝试用 kprobe 解析
        struct kprobe kp = { .symbol_name = name };
        if (register_kprobe(&kp) == 0) {
            addr = (unsigned long)kp.addr;
            unregister_kprobe(&kp);
        }
    }
    return addr;
}

/* ===== 配置文件加载 (与原版兼容) ===== */
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
        return 0; // 已存在
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

    // 跳过空白
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
    // 去掉末尾多余的 '/'
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
        pr_err(MODULE_NAME ": failed to open %s, error %ld\n",
               CONFIG_PATH, PTR_ERR(f));
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
    pr_info(MODULE_NAME ": loaded %d entries\n", hide_count);
    return 0;
}

/* ===== VFS 层隐藏核心：判断路径是否应隐藏 ===== */
static bool should_hide_dentry(const char *name, int namelen)
{
    struct task_struct *task = current;
    uid_t uid = from_kuid(&init_user_ns, task_uid(task));
    char full_path[MAX_PATH_LEN];
    struct path pwd;
    char *cwd = NULL;
    bool hide = false;
    int i;

    // 白名单 root 可见全部
    if (is_whitelisted_uid(uid))
        return false;

    // 获取当前目录路径 (近似，仅用于日志)
    get_fs_pwd(current->fs, &pwd);
    cwd = dentry_path_raw(pwd.dentry, full_path, MAX_PATH_LEN);
    path_put(&pwd);
    if (IS_ERR(cwd))
        cwd = full_path;

    // 构造完整路径用于匹配
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

    if (hide) {
        pr_debug(MODULE_NAME ": hiding '%s' from uid %d\n", full_path, uid);
    }
    return hide;
}

/* ===== Ftrace 钩子函数 ===== */
static void notrace filldir64_hook(unsigned long ip, unsigned long parent_ip,
                                   struct ftrace_ops *ops, struct pt_regs *regs)
{
    const char *name;
    int namlen;

    // 从寄存器提取参数 (x86_64 调用约定)
    // filldir64(void *buf, const char *name, int namlen, loff_t offset, u64 ino, unsigned int type)
    // RDI = buf, RSI = name, RDX = namlen
    name = (const char *)regs->si;
    namlen = (int)regs->dx;

    // 空名字或特殊条目直接放行
    if (!name || namlen <= 0)
        return;

    // 检查是否需要隐藏
    if (should_hide_dentry(name, namlen)) {
        // 跳过该条目：修改 IP 到返回地址 thunk，直接返回
        regs->ip = (unsigned long)return_thunk;
    }
    // 否则 regs->ip 保持不变，ftrace 会继续执行原始函数
}

/* ===== 准备 return_thunk (用于快速返回) ===== */
static int __init setup_return_thunk(void)
{
    // 简单起见，我们劫持一个内核中无用的函数结尾作为 retq 指令地址
    // 这里用 kallsyms 找一个简单的函数，取其结尾 ret 指令
    unsigned long addr = lookup_name("mutex_unlock");
    if (!addr)
        return -ENOENT;

    // 搜索 ret 指令 (0xC3)
    unsigned char *p = (unsigned char *)addr;
    int i;
    for (i = 0; i < 64; i++) {
        if (p[i] == 0xC3) {
            return_thunk = (void *)(addr + i);
            pr_info(MODULE_NAME ": return_thunk at %p\n", return_thunk);
            return 0;
        }
    }
    return -EFAULT;
}

/* ===== 注册 Ftrace 钩子 ===== */
static int __init register_filldir64_hook(void)
{
    int ret;

    // 1. 查找 filldir64 地址
    target_ip = lookup_name("filldir64");
    if (!target_ip) {
        pr_err(MODULE_NAME ": filldir64 not found\n");
        return -ENOENT;
    }
    pr_info(MODULE_NAME ": filldir64 at 0x%lx\n", target_ip);

    // 2. 准备返回 thunk
    ret = setup_return_thunk();
    if (ret) {
        pr_err(MODULE_NAME ": failed to setup return_thunk\n");
        return ret;
    }

    // 3. 保存原始函数地址 (用于非 ftrace 调用场景)
    orig_filldir64 = (void *)target_ip;

    // 4. 初始化 ftrace_ops
    fops.func = filldir64_hook;
    fops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    // 5. 设置过滤器
    ret = ftrace_set_filter_ip(&fops, target_ip, 0, 0);
    if (ret) {
        pr_err(MODULE_NAME ": ftrace_set_filter_ip failed: %d\n", ret);
        return ret;
    }

    // 6. 注册函数
    ret = register_ftrace_function(&fops);
    if (ret) {
        pr_err(MODULE_NAME ": register_ftrace_function failed: %d\n", ret);
        ftrace_set_filter_ip(&fops, target_ip, 1, 0);
        return ret;
    }

    pr_info(MODULE_NAME ": filldir64 hook installed\n");
    return 0;
}

static void __exit unregister_filldir64_hook(void)
{
    unregister_ftrace_function(&fops);
    ftrace_set_filter_ip(&fops, target_ip, 1, 0);
    pr_info(MODULE_NAME ": filldir64 hook removed\n");
}

/* ===== 保留原始 syscall 钩子 (兼容/备用) ===== */
// 此处可选择保留原 fshide 中的 syscall hook 作为备份，
// 但为了简洁，这里省略。你可以按需添加。

/* ===== KernelPatch 接口 ===== */
static long fshide_vfs_init(const char *args, const char *event, void __user *reserved)
{
    int ret;

    pr_info(MODULE_NAME ": init v" MODULE_VERSION "\n");

    ret = load_config();
    if (ret && ret != -ENOENT)
        pr_warn(MODULE_NAME ": config load failed, hiding disabled\n");

    ret = register_filldir64_hook();
    if (ret) {
        pr_err(MODULE_NAME ": failed to install VFS hook\n");
        return ret;
    }

    return 0;
}

static long fshide_vfs_ctl0(const char *ctl_args, char *__user out_msg, int outlen)
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

static long fshide_vfs_exit(void *__user reserved)
{
    unregister_filldir64_hook();
    clear_all_entries();
    pr_info(MODULE_NAME ": exited\n");
    return 0;
}

/* ===== 模块注册 ===== */
KPM_NAME(MODULE_NAME);
KPM_VERSION(MODULE_VERSION);
KPM_LICENSE("GPL");
KPM_AUTHOR("Advanced Hide");
KPM_DESCRIPTION("VFS filldir64 hook for file hiding");

KPM_INIT(fshide_vfs_init);
KPM_CTL0(fshide_vfs_ctl0);
KPM_EXIT(fshide_vfs_exit);
