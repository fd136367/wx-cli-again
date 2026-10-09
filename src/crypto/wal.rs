use anyhow::Result;
use std::io::{SeekFrom, Seek, Write};
use std::path::Path;

use super::{decrypt_page, PAGE_SZ};

pub const WAL_HDR_SZ: usize = 32;
pub const WAL_FRAME_HDR: usize = 24;

/// 将 WAL 文件中的变更应用到已解密的数据库文件
///
/// WAL 格式（SQLite 标准，SQLCipher 4 的 WAL 帧也被加密）：
/// - WAL header (32 bytes): magic(4) + format(4) + page_sz(4) + ckpt_seq(4) + salt1(4) + salt2(4) + cksum1(4) + cksum2(4)
/// - 每帧：frame_header(24 bytes) + page_data(PAGE_SZ bytes)
///   - frame_header: pgno(4) + commit_pgcnt(4) + salt1(4) + salt2(4) + cksum1(4) + cksum2(4)
pub fn apply_wal(wal_path: &Path, out_path: &Path, enc_key: &[u8; 32]) -> Result<()> {
    if !wal_path.exists() {
        return Ok(());
    }

    let wal_data = std::fs::read(wal_path)?;
    if wal_data.len() <= WAL_HDR_SZ {
        return Ok(());
    }

    // 读取 WAL 头中的 salt1 / salt2
    let s1 = u32::from_be_bytes(wal_data[16..20].try_into().unwrap());
    let s2 = u32::from_be_bytes(wal_data[20..24].try_into().unwrap());

    let frame_size = WAL_FRAME_HDR + PAGE_SZ;
    let frame_area = &wal_data[WAL_HDR_SZ..];

    // 打开输出文件做随机写
    let mut db_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(out_path)?;

    let mut pos = 0usize;
    while pos + frame_size <= frame_area.len() {
        let fh = &frame_area[pos..pos + WAL_FRAME_HDR];
        let page_data = &frame_area[pos + WAL_FRAME_HDR..pos + frame_size];

        let pgno = u32::from_be_bytes(fh[0..4].try_into().unwrap());
        let fs1 = u32::from_be_bytes(fh[8..12].try_into().unwrap());
        let fs2 = u32::from_be_bytes(fh[12..16].try_into().unwrap());

        pos += frame_size;

        // 跳过无效页码
        if pgno == 0 || pgno > 1_000_000 {
            continue;
        }
        // salt 不匹配的帧属于已检查点或旧事务
        if fs1 != s1 || fs2 != s2 {
            continue;
        }

        let mut page_buf = page_data.to_vec();
        if page_buf.len() < PAGE_SZ {
            page_buf.resize(PAGE_SZ, 0);
        }

        // SQLCipher 的 pager codec 是按 `pgno` 分支的，与“主库还是 WAL”无关：
        // - src/crypto.c `CODEC_WRITE_OP`：`if(pgno == 1) offset = FILE_HEADER_SZ;`，
        //   并把 KDF salt 写进缓冲区前 16 字节（`memcpy(buffer, kdf_salt, offset)`）
        // - src/pager.c `sqlcipherPagerCodec()` 用 `CODEC2(..., pPg->pgno, 6, ...)`
        // - src/wal.c `walWriteOneFrame()` 对每个 WAL 帧都调用 sqlcipherPagerCodec
        // 因此 **WAL 里的页 1 帧同样以 16 字节 salt 开头**，必须和主库页 1 一样走
        // pgno==1 路径（跳过 salt、并写回 `SQLite format 3` 魔数）。
        // 曾经这里传 `2` 绕过 pgno==1 分支：salt 被当作密文解密，且不会写回魔数，
        // 结果是用垃圾覆盖掉输出库本来正确的第 1 页。
        let dec = decrypt_page(enc_key, &page_buf, pgno)?;
        let file_offset = (pgno as u64 - 1) * PAGE_SZ as u64;
        db_file.seek(SeekFrom::Start(file_offset))?;
        db_file.write_all(&dec)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SQLITE_HDR;

    /// 造一个只含单帧的合成 WAL。`page` 是帧里的 4096 字节"密文"载荷。
    fn synthetic_wal(pgno: u32, page: &[u8; PAGE_SZ], salt1: u32, salt2: u32) -> Vec<u8> {
        let mut wal = vec![0u8; WAL_HDR_SZ];
        wal[0..4].copy_from_slice(&0x377f_0682u32.to_be_bytes()); // magic
        wal[8..12].copy_from_slice(&(PAGE_SZ as u32).to_be_bytes()); // page size
        wal[16..20].copy_from_slice(&salt1.to_be_bytes());
        wal[20..24].copy_from_slice(&salt2.to_be_bytes());
        // frame header
        wal.extend_from_slice(&pgno.to_be_bytes());
        wal.extend_from_slice(&1u32.to_be_bytes()); // commit page count
        wal.extend_from_slice(&salt1.to_be_bytes());
        wal.extend_from_slice(&salt2.to_be_bytes());
        wal.extend_from_slice(&0u32.to_be_bytes()); // checksum1
        wal.extend_from_slice(&0u32.to_be_bytes()); // checksum2
        wal.extend_from_slice(page);
        wal
    }

    fn unique_tmp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "wx-cli-wal-test-{}-{}-{}",
            tag,
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pseudo_page() -> [u8; PAGE_SZ] {
        let mut page = [0u8; PAGE_SZ];
        for (i, b) in page.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        page
    }

    /// 回归测试：WAL 里 pgno=1 的帧必须走 `decrypt_page(.., 1)` 路径
    /// （跳过前 16 字节 salt，并把 `SQLite format 3\0` 魔数写回页首）。
    ///
    /// 修复前这里会走 pgno=2 路径：salt 被当密文解密，且首页魔数不写回，
    /// 于是输出库第 1 页被垃圾覆盖。本测试在修复前失败、修复后通过。
    #[test]
    fn wal_page1_frame_uses_page1_decrypt_path() {
        let key = [0x11u8; 32];
        let tmp = unique_tmp_dir("page1");
        let out = tmp.join("out.db");
        std::fs::write(&out, vec![0u8; PAGE_SZ * 2]).unwrap();

        let page = pseudo_page();
        let wal_path = tmp.join("out.db-wal");
        std::fs::write(&wal_path, synthetic_wal(1, &page, 0xAABB_CCDD, 0x1122_3344)).unwrap();

        apply_wal(&wal_path, &out, &key).unwrap();

        let written = std::fs::read(&out).unwrap();
        let expected = decrypt_page(&key, &page, 1).unwrap();
        assert_eq!(
            &written[..PAGE_SZ],
            &expected[..],
            "pgno=1 的 WAL 帧必须按 pgno=1 解密"
        );
        assert_eq!(
            &written[..16],
            SQLITE_HDR,
            "pgno=1 的 WAL 帧必须把 SQLite 文件头写回"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// 非首页帧仍按自身页码解密（不要被上面的修复带偏）。
    #[test]
    fn wal_non_first_page_frame_uses_its_own_pgno() {
        let key = [0x22u8; 32];
        let tmp = unique_tmp_dir("page3");
        let out = tmp.join("out.db");
        std::fs::write(&out, vec![0u8; PAGE_SZ * 4]).unwrap();

        let page = pseudo_page();
        let wal_path = tmp.join("out.db-wal");
        std::fs::write(&wal_path, synthetic_wal(3, &page, 0x0102_0304, 0x0506_0708)).unwrap();

        apply_wal(&wal_path, &out, &key).unwrap();

        let written = std::fs::read(&out).unwrap();
        let expected = decrypt_page(&key, &page, 3).unwrap();
        assert_eq!(&written[2 * PAGE_SZ..3 * PAGE_SZ], &expected[..]);
        // 第 1 页不应被这个帧碰到
        assert!(written[..PAGE_SZ].iter().all(|&b| b == 0));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}

