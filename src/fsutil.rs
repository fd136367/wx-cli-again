//! 文件系统小工具：让「可能以 root 运行」的写盘动作不跟随符号链接、并按最小权限创建。
//!
//! 背景：`wx` 的推荐用法包含 `sudo wx ...`（见 `config::RECOMMENDED_KEY_EXTRACT`），
//! 而运行期文件（`all_keys.json` / `daemon.log` / `daemon.pid` / 解密缓存）都落在
//! 调用用户家目录下的 `~/.wx-cli/`——该目录的属主是非特权用户。若用普通的
//! `std::fs::write`，普通用户只要预先把目标路径做成符号链接，就能让 root 去
//! 覆写/追加任意文件（本地提权）。这里统一用 `O_NOFOLLOW` + 0600 收敛。

use std::io::Write;
use std::path::Path;

/// 打开（创建/截断）文件用于写入：**不跟随符号链接**，新建时权限 0600。
#[cfg(unix)]
pub fn create_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
pub fn create_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

/// 以追加方式打开文件（日志用）：**不跟随符号链接**，新建时权限 0600。
#[cfg(unix)]
pub fn open_append_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
pub fn open_append_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// 把已存在的文件权限收紧到 0600（`OpenOptions::mode` 只对新建生效）。
pub fn tighten_file_perms(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// 把目录权限收紧到 0700。
pub fn tighten_dir_perms(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// 写文件：不跟随符号链接 + 0600。
///
/// 只创建父目录，**不会**去改父目录权限（父目录可能是配置里指定的任意路径，
/// 乱 chmod 风险更大）；目录权限由调用方在确知是自己家目录时用
/// [`tighten_dir_perms`] 处理。
pub fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut file = create_nofollow(path)?;
    file.write_all(contents)?;
    file.flush()?;
    drop(file);
    tighten_file_perms(path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "wx-cli-fsutil-{}-{}-{}",
            tag,
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_private_file_creates_missing_parent_and_file() {
        let dir = tmp_dir("create");
        let path = dir.join("nested").join("secret.json");
        write_private_file(&path, b"{\"k\":1}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"k\":1}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_private_file_overwrites_existing() {
        let dir = tmp_dir("overwrite");
        let path = dir.join("secret.json");
        std::fs::write(&path, b"old").unwrap();
        write_private_file(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("mode");
        let path = dir.join("all_keys.json");
        write_private_file(&path, b"{}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "密钥文件必须是 0600，实际 {:o}", mode);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn create_nofollow_refuses_symlink() {
        let dir = tmp_dir("symlink");
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, b"original").unwrap();
        let link = dir.join("link.txt");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let err = write_private_file(&link, b"pwned").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
        // 目标文件没有被改写
        assert_eq!(std::fs::read(&victim).unwrap(), b"original");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn open_append_nofollow_refuses_symlink() {
        let dir = tmp_dir("append-symlink");
        let victim = dir.join("victim.log");
        std::fs::write(&victim, b"original").unwrap();
        let link = dir.join("daemon.log");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        assert!(open_append_nofollow(&link).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"original");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
