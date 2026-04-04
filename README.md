# fshide-kpm

基于 [KernelPatch](https://github.com/bmax121/KernelPatch) 的 KPM 模块，用于隐藏指定的文件和目录。

## 技术原理

fshide 通过 **syscall hook** 在内核层面拦截文件系统访问，对匹配的路径返回"不存在"：

### Hook 的 syscall

| syscall | 作用 |
|---------|------|
| `openat` | 打开文件/目录时返回 `-ENOENT` |
| `faccessat` | 权限检查时返回不存在 |
| `newfstatat` | `stat`/`lstat`/`fstatat` 查询时返回不存在 |
| `getdents64` | **目录列表中过滤掉目标条目**（`ls` 不可见） |
| `chdir` / `fchdir` | 进入目录时返回不存在 |

### Hook 流程

```
用户空间调用 open("/data/local/tmp/secret")
    ↓
[before 回调] 解析完整路径 → 与隐藏规则表精确匹配
    ↓ 匹配成功
skip_origin = 1, ret = -ENOENT
    ↓
调用方收到"文件不存在"
```

```
用户空间 ls /data/local/tmp/
    ↓ getdents64 syscall
[before 回调] 通过 readlinkat + /proc/self/fd/<fd> 双策略解析目录 fd 路径
[after 回调] 从用户空间拷贝 dirent 缓冲区 → 遍历条目 → 移除匹配项 → 压缩写回
    ↓
ls 输出中不包含被隐藏的文件或目录名
```

### 配置文件

运行时从 `/data/adb/fshide` 读取隐藏规则，支持热重载：

```
# 全局隐藏（所有用户不可见）
/data/local/tmp/secret_file.txt
/data/local/tmp/hidden_folder

# 仅对特定 UID 隐藏
/dev/scene uid:10344
/dev/cpuset/scene-daemon uid:10344
```

## 使用方法

```bash
# 加载模块（自动读取配置文件）
sc_kpm_load key ./fshide_release.kpm ""

# 运行时重新加载配置
sc_kpm_control key "fshide" "reload"

# 列出当前隐藏规则
sc_kpm_control key "fshide" "list"

# 查看状态
sc_kpm_control key "fshide" "status"

# 卸载模块
sc_kpm_unload key "fshide"
```

## 构建

```bash
make release    # 生产版本 (O2, stripped)
make debug      # 调试版本 (O0, 带日志)
```

产物: `fshide_release.kpm` / `fshide_debug.kpm`

## 许可证

[AGPLv3](LICENSE)
