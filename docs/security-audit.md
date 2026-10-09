# wx-cli 代码审计报告（bug + 安全问题）

审计对象：本仓库 `main`（v0.6.3）全部 `src/**`（约 17k 行）、`install.sh` / `install.ps1`、
`npm/**`、`.github/workflows/release.yml`。

审计方式：逐文件通读 + 与上游实现交叉验证。关键结论已用外部权威源核实：

- SQLCipher 4.5.6 源码（`src/crypto.c` / `src/pager.c` / `src/wal.c`）——验证 WAL 页 1 的加密布局；
- xnu 头文件 `osfmk/mach/vm_region.h` + 内核 `osfmk/vm/vm_map.c`——验证 Mach 常量与内核校验；
- 本地 `gcc` 实测 `sizeof(vm_region_basic_info_data_64_t)`；
- serde 上游 `private/ser.rs`——验证 `#[serde(flatten)]` 对 `Value::Null` 的行为。

> 环境说明：本沙箱未安装 Rust 工具链（`cargo`/`rustc` 不存在），因此所有结论均来自源码阅读 +
> 上游交叉验证，未经过本地编译/运行。下文每条都标注了置信度与验证方式。

---

## 0. 结论摘要

| 级别 | 数量 | 代表问题 |
|------|------|----------|
| 严重 (High) | 4 | macOS 内存扫描完全失效；WAL 页 1 解密路径错误；密钥文件权限；daemon 任意路径写盘 |
| 中 (Medium) | 11 | IPC 无对端认证；root 往用户可写目录写文件（符号链接提权）；负数 LIMIT；WAL 无校验 |
| 低 / 信息 | 15 | panic、溢出、安装脚本无校验和、CI 未 pin SHA 等 |

最值得优先处理的两件事：

1. **`src/scanner/macos.rs` 的 `VM_REGION_BASIC_INFO_COUNT_64` 写成了 9（应为 10）** ——
   macOS 的进程内存扫描阶段实际上一次都没跑过，全部 key 只能靠 LLDB hook 兜底。
2. **`src/crypto/wal.rs` 对页 1 的 WAL 帧用错了解密路径** —— 只要 WAL 里出现过页 1 的帧，
   解密产物首页就会被写坏。

---


## 1. 严重问题（High）

### H1. macOS 内存扫描完全失效：Mach 的 `info_count` 用了 flavor 值而不是 count 值

**文件**：`src/scanner/macos.rs:358-359`（使用点 `:377-391`）

```rust
    // VM_REGION_BASIC_INFO_COUNT_64 = 9（来自 <mach/vm_region.h>，固定值，不能用 sizeof 计算）
    let info_count_expected: mach_msg_type_number_t = 9;
```

**为什么是错的（已交叉验证）**

- xnu `osfmk/mach/vm_region.h`：
  ```c
  #define VM_REGION_BASIC_INFO_64         9          /* ← 这是 flavor */
  struct vm_region_basic_info_64 { ... };
  #define VM_REGION_BASIC_INFO_COUNT_64   ((mach_msg_type_number_t) \
        (sizeof(vm_region_basic_info_data_64_t)/sizeof(int)))
  ```
  按同样的字段/类型用 `gcc` 实测：`sizeof = 40`，`40 / sizeof(int) = 10`。**COUNT 是 10，不是 9**；
  9 是 flavor 值。代码把两者搞混了。
- xnu `osfmk/vm/vm_map.c:15689-15696`（`vm_map_region()`，即 `mach_vm_region` 的内核实现）：
  ```c
  case VM_REGION_BASIC_INFO_64:
      if (*count < VM_REGION_BASIC_INFO_COUNT_64) {
          vmlp_api_end(VM_MAP_REGION, KERN_INVALID_ARGUMENT);
          return KERN_INVALID_ARGUMENT;
      }
  ```

因此传入 `info_count = 9 < 10` 时，`mach_vm_region` **第一次调用就返回 `KERN_INVALID_ARGUMENT`**，
`scan_memory` 的 `loop` 立刻 `break`（`macos.rs:389-391`），返回 `bytes_read = 0`。

**影响**：macOS 的 Phase 1（进程内存扫描）是死代码，永远扫不到任何 key。
唯一可用的路径退化为 Phase 2 的 LLDB hook；而 hook 只在"仍有缺失分片"时才启动
（`macos.rs:221`），所以表现是"取不全密钥 / 老是提示要 hook"，日志里会打印
`内存扫描完成：... 读取约 0.0 MB`（`macos.rs:160-165`）——这行日志就是现场证据。

**修复**

```rust
let info_count_expected: mach_msg_type_number_t =
    (std::mem::size_of::<VmRegionBasicInfo64>() / std::mem::size_of::<i32>()) as u32; // = 10
```

（`VmRegionBasicInfo64` 的结构体布局本身是对的：`#[repr(C)]`，5×u32 + 8 字节对齐的 `u64` +
`i32` + `u16` = 40 字节，与 C 侧一致。**只有 count 常量错**。）

**置信度**：高（上游头文件 + 内核源码 + 本地实测 sizeof 三重验证）。建议在 macOS 上跑一次
`sudo wx init`，确认日志不再是 `0.0 MB`。

---

### H2. WAL 中 page 1 的帧用错了解密路径，会把解密产物第 1 页写坏

**文件**：`src/crypto/wal.rs:64-66`

```rust
        // WAL 帧中的页数据不含 SALT 头，所以对 pgno=1 的帧也用普通页解密路径
        // （区别于主数据库第一页需要跳过 SALT 并写入 SQLite 魔数）
        let dec = decrypt_page(enc_key, &page_buf, if pgno == 1 { 2 } else { pgno })?;
```

**为什么是错的（已用 SQLCipher 4.5.6 源码验证）**

注释里的前提"WAL 帧的页数据不含 SALT 头"不成立。SQLCipher 的 pager codec 是**按 `pgno` 分支**的，
和"主库还是 WAL"无关：

- `src/crypto.c:757-758`：`if(pgno == 1) offset = plaintext_header_sz ? plaintext_header_sz : FILE_HEADER_SZ;`
- `src/crypto.c:787-799`（`CODEC_WRITE_OP`）：
  ```c
  if(pgno == 1) { /* copy initial part of file header or salt to buffer */
      sqlcipher_codec_ctx_get_kdf_salt(ctx, &kdf_salt);
      memcpy(buffer, plaintext_header_sz ? pData : kdf_salt, offset);
  }
  ```
- `src/pager.c:7265-7268`：`sqlcipherPagerCodec()` 调用 `CODEC2(..., pPg->pgno, 6, ...)`，
  而 `6 = CODEC_WRITE_OP`（`crypto.c:716`）。
- `src/wal.c:3851-3852`：每个 WAL 帧都经 `sqlcipherPagerCodec(pPage)` 加密后写出。

即：**WAL 里页 1 的帧和主库页 1 一样，前 16 字节是 KDF salt，后 4080 字节才是密文。**

现在传 `2` 会让 `decrypt_page` 走 `enc = &page_data[..PAGE_SZ - RESERVE_SZ]`，把 16 字节 salt
当作密文参与 AES-CBC 解密（前两块明文全错），而且**不会写回 `SQLite format 3\0` 文件头**
（`crypto/mod.rs:48-57` 只有 `pgno == 1` 分支才写）。结果是把输出库本来正确的第 1 页覆盖成垃圾。

**触发路径**：任何包含页 1 帧的 WAL（事务改了页 1 b-tree 根或库头、schema 变更等），经
`src/daemon/cache.rs:546-548`（WAL 增量）或 `:600-601`（全量解密后 apply_wal）应用。

**影响**：解密产物 `file is not a database` / 元数据错乱，静默数据损坏。

**修复**：`decrypt_page(enc_key, &page_buf, pgno)?`（去掉 `if pgno == 1 { 2 }`）。

**置信度**：高（SQLCipher 官方源码逐行核对）。

---


### H3. `all_keys.json`（SQLCipher 原始密钥）在非 sudo 路径下按 0644 落盘

**文件**：`src/cli/init.rs:105-124`、`src/cli/init.rs:306-315`、`src/cli/key_cmd.rs:167-170`

```rust
// init.rs:105-106
    #[cfg(unix)]
    drop_privileges_if_sudo()?;
...
// init.rs:124
    std::fs::write(&keys_file_path, serde_json::to_string_pretty(&keys_json)?)
        .context("写入 all_keys.json 失败")?;
```

```rust
// init.rs:311-315 —— 只有 root 才会走到 umask / tighten_perms
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
```

唯一的权限收紧手段（`libc::umask(0o077)` 在 `init.rs:334-337`、`tighten_perms` 把 `*.json`
改成 0600 在 `init.rs:370-382`）**全部在 `drop_privileges_if_sudo()` 内部**，而该函数对非 root
直接返回。`wx key set` 更是连这一步都没有：

```rust
// key_cmd.rs:167-170
    if let Some(parent) = cfg.keys_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&cfg.keys_file, serde_json::to_string_pretty(&map)?)?;
```

**触发**：Linux 上非 sudo 的 `wx init`、或 macOS ad-hoc 包推荐的
`wx key extract --hook-seconds 60`（README 明确写了不加 sudo 也可）→ 进程 umask 保持默认 022
→ `~/.wx-cli` 0755、`all_keys.json` **0644**。

**影响**：同机任意本地用户可读取 32 字节 raw page key，直接解密受害者全部微信数据库——
正好是本工具声称保护的数据。此外若当前目录存在 `config.json`，`keys_file_path` 会落在
CWD（`init.rs:64-67` + `init.rs:387-404`），可能落到共享目录/仓库里。

**修复**：无条件 `umask(0o077)`（或创建时显式 `OpenOptions::mode(0o600)` + 目录 `0700`），
并把 `tighten_perms` 覆盖到所有写密钥的路径上。

---

### H4. daemon 的 `Extract` 按客户端给的任意路径写盘 / 建目录（daemon 可能是 root）

**文件**：`src/daemon/query.rs:5262-5275`、`src/daemon/query.rs:5344`、`src/ipc.rs:185-193`

```rust
    let output_path = std::path::PathBuf::from(output);
    if output_path.exists() && !overwrite { anyhow::bail!(...) }
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await ...
        }
    }
...
        std::fs::write(&output_path2, &decoded.data)
```

`output` 是从 IPC 直接来的 `String`，没有任何校验：不 canonicalize、不拒绝 `..`、不限制在某个
导出目录内、不用 `O_NOFOLLOW`/`create_new`。`fs::write` 会跟随符号链接。

**触发**：任何能连上 daemon socket 的进程发送
`{"cmd":"extract","attachment_id":"<合法 id>","output":"/root/.ssh/authorized_keys","overwrite":true}`。
内容受限于磁盘上已存在的附件字节（md5 来自 `message_resource.db`，客户端不能任意指定），
所以不是"任意内容写任意位置"，但在 daemon 以 root 运行时（见 M2）仍然是特权路径写入 /
任意目录创建 / 覆盖任意文件。

**修复**：限制到配置的导出根目录（对父目录 canonicalize 后做组件级前缀校验）、拒绝 `..`、
非 `overwrite` 时用 `create_new(true)`，最终文件用 `O_NOFOLLOW`。


## 2. 中等问题（Medium）

### M1. IPC 没有对端认证，且 socket 存在 bind → chmod 的竞态窗口

**文件**：`src/daemon/server.rs:28-34`（Windows 侧 `:89-91`）

```rust
    let listener = UnixListener::bind(&sock_path)?;
    // 设置权限 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;
    }
```

- 全仓库 grep 不到 `SO_PEERCRED` / `getpeereid` / `UCred` / `GetNamedPipeClientProcessId`，
  daemon 从不校验对端身份，唯一屏障是文件模式。
- `bind()` 先按 `0777 & ~umask`（通常 0755）创建 socket，之后才 chmod 0600 ——
  这段窗口内任意本地用户可以连上并下发任意命令（含 H4 的 `Extract`、`ReloadConfig`）。

**修复**：`umask(0o077)` 包住 `bind`（或先建 0700 目录再 bind），并额外校验
`SO_PEERCRED.uid == euid`；Windows 侧显式设置 pipe 安全描述符。

---

### M2. root 进程往"非特权用户可写目录"写 `daemon.log` / `daemon.pid` / cache → 符号链接任意文件覆盖（本地提权）

**文件**：`src/cli/transport.rs:127-137`、`src/cli/transport.rs:199-215`、`src/config.rs:146-205`

```rust
        // 日志文件：~/.wx-cli/daemon.log
        let log_path = config::log_path();
        ...
        let (stdout_stdio, stderr_stdio) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)                 // 跟随符号链接
            .and_then(|f| f.try_clone().map(|g| (f, g)))
            ...
        let child = cmd.spawn()...
```

```rust
fn write_pid_file(pid: u32, exe: &Path) -> Result<()> {
    ...
    std::fs::write(config::pid_path(), content)   // std::fs::write 会 truncate，且跟随符号链接
```

`config::cli_dir()` 在 sudo 下被解析成 **`$SUDO_USER` 的家目录**
（`config.rs:146-154` + `resolve_cli_home`），且 `wx init` 会把该目录 chown 回调用用户
（`init.rs:328-332`）。于是 `~/.wx-cli/` 属主是普通用户，而 root 会在里面创建/写文件。

**触发**：普通用户先做

```bash
ln -sf /etc/sudoers ~/.wx-cli/daemon.pid
sudo wx sessions        # 任何以 sudo 运行的 wx 命令都会 start_daemon()
```

root 的 `std::fs::write` 会**截断并覆写** `/etc/sudoers`。同理 `daemon.log` 被 root 以
append 方式打开（可向任意 root 可写文件追加内容），`~/.wx-cli/cache/` 下的文件也由 root 创建。

**影响**：本地权限提升原语（任意文件覆盖/追加，以 root 身份）。

**修复**：对这些运行期文件用 `O_NOFOLLOW`（`OpenOptionsExt::custom_flags(libc::O_NOFOLLOW)`），
写入前校验父目录属主/权限，或把 socket/pid/log/cache 放到 `/var/run`、`/Library/...` 等 root 专属目录。

**置信度**：高（代码路径明确）；利用需要用户以 sudo 运行任意查询命令，而 README 反复示范 `sudo wx ...`。

---

### M3. 客户端可传负数 SQL `LIMIT`（`usize as i64`）→ SQLite 视为"无上限"→ 全库载入内存

**文件**：`src/daemon/query.rs:1516-1517`、`:1624`、`:3906`、`:4214`、`:305`、`:3737`

```rust
// query.rs:1516-1517
    params.push(Box::new(limit as i64));
    params.push(Box::new(offset as i64));
```

`limit` 是 IPC 来的 `usize`。传 `9223372036854775808`（= 2^63）时 `as i64` 得到负数，
而 SQLite 文档明确：**LIMIT 为负 = 不设上限**。只有 SNS 两个查询做了钳制
（`query.rs:4548`、`:4619` 的 `limit.min(SNS_MAX_LIMIT)`），其余全都没有。

`q_new_messages` 更狠：`state` 也是客户端可控，传 `{"wxid_x":0}` 会把 `since_ts` 变成 0，
配合负 LIMIT 就是"把所有历史消息（含 zstd 解压）全部读进内存"。

**修复**：进入 SQL 前统一钳制，例如 `let limit = limit.min(MAX_LIMIT);` 并用
`i64::try_from(limit).unwrap_or(i64::MAX)`。

---

### M4. WAL 解析不做任何完整性校验（magic / page_size / 头部与每帧校验和全都不看）

**文件**：`src/crypto/wal.rs:26-31`、`:40-57`

```rust
    let s1 = u32::from_be_bytes(wal_data[16..20].try_into().unwrap());
    let s2 = u32::from_be_bytes(wal_data[20..24].try_into().unwrap());
    ...
        if fs1 != s1 || fs2 != s2 { continue; }
```

- 头部 checksum（`wal_data[24..32]`）、每帧 checksum（`fh[16..24]`）、
  WAL magic（`wal_data[0..4]`，应为 `0x377f0682`/`0x377f0683`）、
  头部 page_size 字段（`wal_data[8..12]`）**一个都没读**；帧长被硬编码成 `24 + 4096`。
- 唯一的"校验"是拿帧里的 salt 和（同样来自文件头的）salt 比，等于自证。

**影响**：任意 >32 字节的文件都会被当 WAL 解析；位翻转/截断/构造的帧被静默应用；
非 4096 页大小的库全盘错位。真实 SQLite 会因 checksum 直接拒绝这些输入。

**修复**：校验 magic、读并用头部 `page_size`、按 SQLite 规则校验头部与每帧的累积 checksum
（byte order 由 magic 决定）后再应用。

---

### M5. WAL 帧页号上限硬编码 1_000_000 → 输出库可被写到 ~4 GiB 之外

**文件**：`src/crypto/wal.rs:51-53`、`:67-69`

```rust
        if pgno == 0 || pgno > 1_000_000 { continue; }
        ...
        let file_offset = (pgno as u64 - 1) * PAGE_SZ as u64;
        db_file.seek(SeekFrom::Start(file_offset))?;
        db_file.write_all(&dec)?;
```

上限与输出库真实页数无关。配合 M4（无 checksum）可构造 `pgno = 1_000_000` 的帧，
把输出文件撑到 ~4 GiB（sparse 便宜，但 FAT/exFAT/网络盘会真实占盘），
并在库尾注入 SQLite 可能读到的伪造页。

**修复**：用输出库真实页数（SQLite 头 offset 28，或 `out_len / PAGE_SZ`）作上界。

---

### M6. 批量解密 / WAL 路径完全不校验页 HMAC

**文件**：`src/crypto/mod.rs:35-67`（`decrypt_page`）、`:139-163`（`full_decrypt`）、`src/crypto/wal.rs:66`

`decrypt_page` 只做 AES 解密，不校验 reserve 里的 64 字节 HMAC；`full_decrypt` 也不调用
`verify_hmac_page1`（只有 `validate_raw_key_for_db` 对第 1 页验一次）。
SQLCipher 在 HMAC 不匹配时返回 `SQLITE_ERROR` 拒绝该页，这里则是静默产出垃圾明文。

**影响**：位翻转或恶意改写的页（第 2..N 页、WAL 帧）被当成有效数据，取证完整性丧失。

**修复**：在 `decrypt_page` 里按页校验
`HMAC-SHA512(mac_key, content || IV || pgno_le)`，
其中 `mac_key = PBKDF2-HMAC-SHA512(key, salt ^ 0x3a, 2, dklen=32)`（该推导已被验证是正确的）。

---


### M7. `wx key list` 在非 ASCII 密钥值上 panic（按字节切片）

**文件**：`src/cli/key_cmd.rs:33`

```rust
            let preview = format!("{}…", &enc[..enc.len().min(12)]);
```

`enc` 是 `all_keys.json` 里的任意字符串。`&enc[..n]` 是 `str` 范围索引，
当第 `n` 个字节不是 UTF-8 字符边界时**直接 panic**。这条读取路径没有做 64 位 hex 校验
（`cmd_key_set` 在 `key_cmd.rs:145-148` 才校验）。

**触发**：`{"message/message_1.db":"aaaaaaaaaa密"}`（10 个 ASCII + 3 字节汉字）→
`&enc[..12]` 落在汉字中间 → `byte index 12 is not a char boundary`。

**修复**：`enc.chars().take(12).collect::<String>()` 或 `enc.get(..12).unwrap_or(enc)`。

---

### M8. `config.json` 优先从当前工作目录加载，而工具被反复以 sudo 运行 → 特权路径重定向

**文件**：`src/config.rs:93-124`、`src/config.rs:45-77`、`src/cli/init.rs:387-404`

```rust
fn find_config_file() -> Result<PathBuf> {
    let cwd_dir = std::env::current_dir().ok();
    ...
    let candidates = [
        cwd_dir.map(config_path_in_dir),   // ← CWD 优先级最高
        exe_dir.map(config_path_in_dir),
        home_dir.map(home_config_path),
    ];
    candidates.into_iter().flatten().find(|path| path.exists())
}
```

`db_dir` / `keys_file` / `decrypted_dir` 直接取自该文件，`keys_file` 还允许绝对路径
（`config.rs:53-64`）。产品自己把 `sudo wx ...` 当成推荐用法
（`config.rs:7` 的 `RECOMMENDED_KEY_EXTRACT`、README、`install.sh`）。

**触发**：在 `/tmp/anything/` 放一个 `config.json`（`keys_file` 指向攻击者可控路径），
用户在该目录执行任意 `sudo wx ...` → root 按攻击者的路径读/写。

**修复**：`geteuid() == 0` 时拒绝 CWD 相对配置（或要求属主为 `SUDO_UID` 且非 group/world-writable），
至少给出显著警告并要求显式开关。

---

### M9. macOS LLDB hook：`TMPDIR` 派生路径被未加引号地拼进 lldb 命令与内嵌 Python 原始字符串

**文件**：`src/scanner/macos.rs:474`、`:509-517`、`:612-620`

```rust
    let tmp_dir = std::env::temp_dir().join(format!("wx-cli-hook-{}", std::process::id()));
...
        &format!("command script import {}", script_path.display()),
```

```python
OUT = r"{keys_path}"
DONE = r"{done_path}"
```

`std::env::temp_dir()` 在 Unix 上遵循 `$TMPDIR`。路径里的 `"` 可以直接闭合
Python 原始字符串字面量，把后面的内容当 Python 代码执行（而这条路径按设计在 sudo 下运行）；
`script_path` 里的空格/分号也会破坏 lldb 的 `-o "command script import ..."` 解析。

**触发**：`TMPDIR='/tmp/a"; import os; os.system("id"); #' sudo -E wx key extract --hook-seconds 5`。

**修复**：不要拼命令行字符串（用带引号的 lldb 机制或脚本文件），
把 `keys_path`/`done_path` 通过 argv/env 传给 Python 助手而不是字符串插值；
或使用固定目录、不派生自环境变量。

---

### M10. LLDB 超时时直接 `kill()` 而不 detach → 微信可能被留在 SIGSTOP

**文件**：`src/scanner/macos.rs:551-555`（模块注释 `:469` 明确写了不能这么做）

```rust
        if started.elapsed() > wait_budget {
            eprintln!("LLDB 超时，尝试终止…");
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
```

唯一的 `process detach` 在 Python 线程里（`macos.rs:666-671`）；如果 lldb 卡在 attach /
`command script import` 阶段（此时该线程还没跑），强杀会把微信留在被调试器停住的状态。

**修复**：先尝试 `lldb -p <pid> -o "process detach" -o quit`，或 `kill -CONT <pid>` 兜底。

---

### M11. macOS LLDB hook 的临时目录名可预测 + `create_dir_all` 不排他 → 符号链接写

**文件**：`src/scanner/macos.rs:474-479`、`:495-502`

```rust
    let tmp_dir = std::env::temp_dir().join(format!("wx-cli-hook-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir)?;
    ...
    std::fs::write(&script_path, lldb_hook_script(...))?;
```

目录名只含 PID，`create_dir_all` 对已存在的路径（含符号链接指向的目录）会成功，
随后 `fs::write` 跟随符号链接。在共享 temp 根（或 `TMPDIR` 可控）时，
攻击者可预创建 `wx-cli-hook-<pid>` 符号链接 → 以 root 覆盖任意文件。
（macOS 默认 `$TMPDIR` 是每用户 0700，所以这条比 M2 弱。）

**修复**：用 `tempfile` / `mkdtemp` 语义（`create_dir` 遇 `EEXIST` 失败并重试）+ `O_NOFOLLOW`。

---


## 3. 低危 / 信息级

| # | 级别 | 文件:行 | 问题 | 建议 |
|---|------|---------|------|------|
| L1 | 低 | `src/scanner/macos.rs:97-105` | `pgrep -x WeChat` 返回多行（微信双开/同名进程）时 `s.trim().parse()` 失败 → 报"找不到 WeChat 进程" | 取 `lines().next()`，并同时尝试 `Weixin` |
| L2 | 低 | `src/scanner/macos.rs:400-403` | 跳过 `>=512MB` 区域与只读 `>64MB` 区域 → 漏 key（且静默） | 对 RW 区域不限大小，跳过时打日志 |
| L3 | 低 | `src/attachment/decoder/mod.rs:35-46` | `V2KeyMaterial::default()` 的 `xor_key = 0`，与文档/`with_aes` 的 `0x88` 不一致 → V1 magic 文件尾部 XOR 段解错（静默产出坏图） | 手写 `Default` 为 `0x88` |
| L4 | 低 | `src/daemon/meta.rs:100` | `s - c` 可能溢出 `i64`（DB 时间戳极端值） | `s.saturating_sub(c)` |
| L5 | 低 | `src/attachment/decoder/v2.rs:36-40` | `aligned_aes_size = aes_size + (16 - aes_size % 16)` 在 32 位 `usize` 上溢出 | `checked_add` |
| L6 | 低 | `src/daemon/cache.rs:653-662` | `hex_to_32bytes` 对含多字节字符的 64 字节字符串做 `&s[i*2..i*2+2]` → panic（单请求失败） | 用 `s.as_bytes().chunks_exact(2)` 或先校验 ASCII hex |
| L7 | 低 | `src/daemon/query.rs:5097`、`:1121`、`:857` | `offset + limit`、`limit * 3`、`limit * 4` 未做饱和运算 | `saturating_*` + 钳制 |
| L8 | 低 | `src/daemon/server.rs:58-63`、`:43` | 请求行无长度上限（可 OOM），连接无并发上限 | `AsyncReadExt::take(N)` + 信号量 |
| L9 | 低 | `src/daemon/query.rs:1306,1422`；`src/daemon/cache.rs:355-411` | async 上下文里直接做阻塞 fs/SQLite IO；shard-meta 读-改-写无锁 | 移到 `spawn_blocking`，加互斥 |
| L10 | 低/中 | `install.sh:36-51`、`install.ps1:24-35`、`.github/workflows/release.yml:100-114` | 安装脚本下载即执行，release 不发 `SHA256SUMS`，README 还推荐 `curl ... \| bash` | 发布校验和/签名并在安装脚本里校验 |
| L11 | 低 | `.github/workflows/release.yml:8-9,15,17,73,100,111,124,130` | Actions 全部用可变 tag/branch（含 `dtolnay/rust-toolchain@stable`），且 workflow 级 `contents: write` 被所有 job 继承 | pin 到 commit SHA；只给发布 job 写权限 |
| L12 | 信息 | `npm/wx-cli/package.json:2`、`npm/wx-cli/install.js:6-12` | npm 包名仍是 `@jackwener/wx-cli`，与仓库 `botiverse/wx-cli` 不一致（发布到 npm 的 token 也指向旧 scope） | 统一 scope |
| L13 | 信息 | `src/cli/key_cmd.rs:33` | `wx key list` 默认打印每个 key 前 12 hex（48 bit） | 缩短或仅在 `--show-secrets` 时输出 |
| L14 | 信息 | `src/daemon/query.rs:136-145` | `--debug-source` 会把绝对 DB 路径回给客户端 | 保留但文档化 |
| L15 | 信息 | `src/scanner/macos.rs:449`；`src/scanner/windows.rs:74`；`src/scanner/mod.rs:293,384,422,428` | `mach_vm_deallocate` 传 `dc` 而非请求的 `cs`；`scan_keys` 里 `?` 提前返回会漏 `CloseHandle`；macOS-only 辅助函数在 Linux/Windows 目标上是 dead code（若 CI 开 `-D warnings` 会构建失败） | 用 `cs`/RAII；加 `cfg_attr(not(macos), allow(dead_code))` |

---

## 4. 已核查、确认**不是** bug（避免误报）

这些点看起来可疑，但已核实实现是正确的：

1. **`Response::err()` 的 `#[serde(flatten)]` + `Value::Null` 会序列化失败** —— **不成立**。
   serde 的 `FlatMapSerializer::serialize_unit()` 返回 `Ok(())`（已核对 serde
   v1.0.190 / v1.0.210 / v1.0.219 / master 的 `serde/src/private/ser.rs`；本项目锁定
   serde 1.0.228），`Value::Null` 走 `serialize_unit`，因此错误响应能正常发出。
2. **SQL 注入** —— 不存在。表名要么是 `format!("Msg_{:x}", md5::compute(username))`
   （`query.rs:1301`），要么经 `^Msg_[0-9a-f]{32}$` 正则过滤（`query.rs:16,1043,4921`）；
   其余条件全部用 `?` 绑定参数，`IN (...)` 列表也只由 `?` 占位符拼成。
3. **`attachment_id.chat` 路径穿越** —— 不存在。`resolver.rs:167-168` 用
   `md5(chat)` 作目录名，文件名来自 `extract_md5_from_packed_info`（只接受 32 位 ASCII hex）。
4. **`verify_hmac_page1` 的密钥推导** —— 正确。
   `PBKDF2-HMAC-SHA512(rawkey, salt ^ 0x3a, 2, dklen=32)`，已用 SQLCipher 官方
   `sqlcipher-4.0-testkey.db` 实测命中（`dklen=64` / 64000 次迭代都不命中）。
5. **`VmRegionBasicInfo64` 结构体布局** —— 正确（40 字节，`offset` 在 24，与 C ABI 一致）。
   **只有 `info_count` 常量错**（见 H1）。
6. **Windows / Linux 扫描器的缓冲区与长度处理** —— 无内存安全问题：
   `ReadProcessMemory` 后 `buf.truncate(bytes_read)`；`Process32First/Next` 循环与
   `CloseHandle` 路径正确；`/proc/<pid>/mem` 分块读有边界检查。
7. **`collect_salt_adjacent_keys` / `scan_key_patterns` 的切片** —— 全部在界内
   （`i >= off`、`kstart + 32 <= buf.len()`、`i + 99 <= buf.len()`）。
8. **`extract_cdata` 的字节切片** —— 安全（`<![CDATA[` 与 `]]>` 都是 ASCII，
   切片边界必然落在字符边界上）。
9. **命令注入** —— `doctor.rs` / `transport.rs` / `daemon_cmd.rs` 里的
   `csrutil`/`codesign`/`which`/`pgrep`/`ps`/`taskkill`/`tail` 参数全部是字面量或数字，
   没有 `sh -c`。`npm/wx-cli/bin/wx.js` 用 `execFileSync(path, argv)`，无 shell。
   `config.wechat_process` 目前是死字段，未被拼进任何命令。
10. **`.gitignore`** 正确排除了 `all_keys.json` / `config.json` / `*.db` / WAL / hook 输出。

---

## 5. 建议的修复顺序

1. **H1**（一行改动，恢复 macOS 取钥主路径）→ **H2**（一行改动，止住静默数据损坏）。
2. **H3 / M7**（密钥文件权限 + 权限相关的 panic）——改动小、影响大。
3. **M2 + H4 + M1**（把"以 root 运行 + 用户可写目录 + 无对端认证"这一组一起收掉：
   运行期文件 O_NOFOLLOW / 移到 root 专属目录、校验对端、`Extract` 限制导出根目录）。
4. **M3 / L7 / L8**（限制 IPC 输入规模，防 DoS）。
5. **M4 / M5 / M6**（WAL 校验与页 HMAC，属于取证正确性）。
6. **M8 / M9 / M10 / M11**（配置信任与 LLDB hook 的健壮性/注入面）。
7. **L10 / L11 / L12**（供应链与 CI 加固）。

---

*本报告由只读审计产出，未修改任何源码。关键结论的验证材料：SQLCipher 4.5.6
`crypto.c`/`pager.c`/`wal.c`、xnu `osfmk/mach/vm_region.h` 与 `osfmk/vm/vm_map.c`、
serde `private/ser.rs`、本地 `gcc` 实测 `sizeof(vm_region_basic_info_data_64_t) == 40`。*

---
