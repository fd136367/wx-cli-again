use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::cache::DbCache;
use super::query::Names;
use crate::ipc::{Request, Response};

/// 单个请求行的最大长度。`BufReader::lines()` 没有上限，客户端可以只发不换行
/// 地灌任意多字节把 daemon 读爆内存。
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
/// 并发连接上限：每个连接都会 spawn 一个任务，无上限时本地进程可刷爆 fd/内存。
const MAX_CONNECTIONS: usize = 64;

/// 启动 IPC server（Unix socket / Windows named pipe）
pub async fn serve(db: Arc<DbCache>, names: Arc<tokio::sync::RwLock<Arc<Names>>>) -> Result<()> {
    #[cfg(unix)]
    serve_unix(db, names).await?;
    #[cfg(windows)]
    serve_windows(db, names).await?;
    Ok(())
}

#[cfg(unix)]
async fn serve_unix(db: Arc<DbCache>, names: Arc<tokio::sync::RwLock<Arc<Names>>>) -> Result<()> {
    use tokio::net::UnixListener;
    let sock_path = crate::config::sock_path();

    // 删除旧 socket 文件
    if sock_path.exists() {
        let _ = tokio::fs::remove_file(&sock_path).await;
    }

    // `bind()` 按 `0777 & ~umask` 创建 socket，之后才 chmod 0600 —— 中间有一段窗口
    // 任意本地用户都能连上并下发命令（含 Extract 写盘）。这里先把 umask 收到 077。
    // 此刻 accept 循环尚未启动、运行时还没并发，改进程 umask 是安全的。
    let saved_umask = unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(&sock_path)?;
    unsafe {
        libc::umask(saved_umask);
    }
    // 设置权限 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;
    }

    eprintln!("[server] 监听 {}", sock_path.display());

    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = Arc::clone(&slots).acquire_owned().await?;
        let (stream, _) = listener.accept().await?;
        let db2 = Arc::clone(&db);
        let names2 = Arc::clone(&names);

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_connection_unix(stream, db2, names2).await {
                eprintln!("[server] 连接处理错误: {}", e);
            }
        });
    }
}

/// 连接方 uid；取不到时返回 `None`（调用方按"无法判定"处理）。
///
/// Linux 用 `SO_PEERCRED`，macOS/BSD 用 `getpeereid`。
#[cfg(target_os = "linux")]
fn peer_uid(stream: &tokio::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    // Linux `struct ucred { pid_t pid; uid_t uid; gid_t gid; }`（libc 未导出该类型）
    #[repr(C)]
    struct Ucred {
        pid: i32,
        uid: u32,
        gid: u32,
    }
    let fd = stream.as_raw_fd();
    let mut cred = Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<Ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut Ucred as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(cred.uid)
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
fn peer_uid(stream: &tokio::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    (rc == 0).then_some(uid as u32)
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd"
    ))
))]
fn peer_uid(_stream: &tokio::net::UnixStream) -> Option<u32> {
    None
}

/// 对端 uid 必须等于 daemon 自身 euid，否则拒绝。
///
/// 取不到 uid（未支持的平台/异常内核）时放行并告警——socket 本身是 0600 且位于
/// 0700 目录，不该因为探测失败把工具用挂。
#[cfg(unix)]
fn peer_allowed(stream: &tokio::net::UnixStream) -> bool {
    match peer_uid(stream) {
        Some(uid) => {
            let me = unsafe { libc::geteuid() };
            if uid != me {
                eprintln!("[server] 拒绝来自 uid={} 的连接（daemon euid={}）", uid, me);
                return false;
            }
            true
        }
        None => {
            eprintln!("[server] 警告：无法获取对端 uid，跳过同用户校验");
            true
        }
    }
}

/// 读一行请求，带上限；超限或连接提前关闭返回 `None`。
#[cfg(unix)]
async fn read_request_line<R>(reader: R) -> Result<Option<String>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut limited = BufReader::new(reader).take(MAX_REQUEST_BYTES);
    let mut line = String::new();
    let n = limited.read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    if !line.ends_with('\n') && n as u64 >= MAX_REQUEST_BYTES {
        anyhow::bail!("请求行超过 {} 字节上限", MAX_REQUEST_BYTES);
    }
    Ok(Some(line))
}

#[cfg(unix)]
async fn handle_connection_unix(
    stream: tokio::net::UnixStream,
    db: Arc<DbCache>,
    names: Arc<tokio::sync::RwLock<Arc<Names>>>,
) -> Result<()> {
    if !peer_allowed(&stream) {
        return Ok(());
    }
    let (reader, mut writer) = stream.into_split();

    let line = match read_request_line(reader).await? {
        Some(l) => l,
        None => return Ok(()),
    };

    // 解析请求
    let req: Request = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            let resp = Response::err(format!("JSON 解析错误: {}", e));
            writer.write_all(resp.to_json_line()?.as_bytes()).await?;
            return Ok(());
        }
    };

    let resp = dispatch(req, &db, &names).await;
    writer.write_all(resp.to_json_line()?.as_bytes()).await?;
    Ok(())
}

#[cfg(windows)]
async fn serve_windows(
    db: Arc<DbCache>,
    names: Arc<tokio::sync::RwLock<Arc<Names>>>,
) -> Result<()> {
    use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced, ListenerOptions};

    // interprocess 的 GenericNamespaced 在 Windows 上会自动拼接 `\\.\pipe\` 前缀，
    // 这里必须传相对名；client 端用 `\\.\pipe\wx-cli-daemon` 直接打开可以对上
    let name = "wx-cli-daemon".to_ns_name::<GenericNamespaced>()?;
    let opts = ListenerOptions::new().name(name);
    let listener = opts.create_tokio()?;

    eprintln!("[server] 监听 \\\\.\\pipe\\wx-cli-daemon");

    loop {
        let conn = listener.accept().await?;
        let db2 = Arc::clone(&db);
        let names2 = Arc::clone(&names);

        tokio::spawn(async move {
            if let Err(e) = handle_connection_windows(conn, db2, names2).await {
                eprintln!("[server] 连接处理错误: {}", e);
            }
        });
    }
}

#[cfg(windows)]
async fn handle_connection_windows(
    conn: interprocess::local_socket::tokio::Stream,
    db: Arc<DbCache>,
    names: Arc<tokio::sync::RwLock<Arc<Names>>>,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(conn);
    let mut lines = BufReader::new(reader).lines();

    let line = match lines.next_line().await? {
        Some(l) => l,
        None => return Ok(()),
    };

    let req: Request = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            let resp = Response::err(format!("JSON 解析错误: {}", e));
            writer.write_all(resp.to_json_line()?.as_bytes()).await?;
            return Ok(());
        }
    };

    let resp = dispatch(req, &db, &names).await;
    writer.write_all(resp.to_json_line()?.as_bytes()).await?;
    Ok(())
}

async fn dispatch(req: Request, db: &DbCache, names: &tokio::sync::RwLock<Arc<Names>>) -> Response {
    use super::query;
    use crate::ipc::Request::*;

    // 取 guard → O(1) clone Arc → 立即 drop 锁。后续 await 期间不持有锁，
    // 多个并发 IPC 请求可以真正并行。Names 本身不可变（由 daemon 启动时
    // 一次性构建），共享 Arc 即可。
    let names_arc: Arc<Names> = {
        let guard = names.read().await;
        Arc::clone(&*guard)
    };

    match req {
        Ping => Response::ok(serde_json::json!({ "pong": true })),
        Sessions {
            limit,
            with_meta,
            debug_source,
        } => match query::q_sessions(db, &names_arc, limit, with_meta, debug_source).await {
            Ok(v) => Response::ok(v),
            Err(e) => Response::err(e.to_string()),
        },
        History {
            chat,
            limit,
            offset,
            since,
            until,
            after_ts,
            before_ts,
            msg_type,
            with_meta,
            debug_source,
        } => {
            match query::q_history(
                db,
                &names_arc,
                &chat,
                limit,
                offset,
                since,
                until,
                after_ts,
                before_ts,
                msg_type,
                with_meta,
                debug_source,
            )
            .await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Search {
            keyword,
            chats,
            limit,
            since,
            until,
            msg_type,
            with_meta,
            debug_source,
        } => {
            match query::q_search(
                db,
                &names_arc,
                &keyword,
                chats,
                limit,
                since,
                until,
                msg_type,
                with_meta,
                debug_source,
            )
            .await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Contacts { query, limit } => {
            match query::q_contacts(&names_arc, query.as_deref(), limit).await {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Unread {
            limit,
            filter,
            with_meta,
            debug_source,
        } => match query::q_unread(db, &names_arc, limit, filter, with_meta, debug_source).await {
            Ok(v) => Response::ok(v),
            Err(e) => Response::err(e.to_string()),
        },
        Members { chat } => match query::q_members(db, &names_arc, &chat).await {
            Ok(v) => Response::ok(v),
            Err(e) => Response::err(e.to_string()),
        },
        NewMessages {
            state,
            limit,
            with_meta,
            debug_source,
        } => {
            match query::q_new_messages(db, &names_arc, state, limit, with_meta, debug_source).await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Favorites {
            limit,
            fav_type,
            query,
        } => match query::q_favorites(db, limit, fav_type, query).await {
            Ok(v) => Response::ok(v),
            Err(e) => Response::err(e.to_string()),
        },
        Stats {
            chat,
            since,
            until,
            with_meta,
            debug_source,
        } => {
            match query::q_stats(db, &names_arc, &chat, since, until, with_meta, debug_source).await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        SnsNotifications {
            limit,
            since,
            until,
            include_read,
        } => {
            match query::q_sns_notifications(db, &names_arc, limit, since, until, include_read)
                .await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        SnsFeed {
            limit,
            since,
            until,
            user,
        } => match query::q_sns_feed(db, &names_arc, limit, since, until, user.as_deref()).await {
            Ok(v) => Response::ok(v),
            Err(e) => Response::err(e.to_string()),
        },
        SnsSearch {
            keyword,
            limit,
            since,
            until,
            user,
        } => {
            match query::q_sns_search(
                db,
                &names_arc,
                &keyword,
                limit,
                since,
                until,
                user.as_deref(),
            )
            .await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Timeline {
            limit,
            offset,
            since,
            until,
            after_ts,
            msg_type,
            with_meta,
            debug_source,
        } => {
            match query::q_timeline(
                db,
                &names_arc,
                limit,
                offset,
                since,
                until,
                after_ts,
                msg_type,
                with_meta,
                debug_source,
            )
            .await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        ReloadConfig => match reload_config(db, names).await {
            Ok(v) => Response::ok(v),
            Err(e) => Response::err(e.to_string()),
        },
        BizArticles {
            limit,
            account,
            since,
            until,
            unread,
        } => {
            match query::q_biz_articles(db, &names_arc, limit, account, since, until, unread).await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Attachments {
            chat,
            kinds,
            limit,
            offset,
            since,
            until,
            with_meta,
            debug_source,
        } => {
            match query::q_attachments(
                db,
                &names_arc,
                &chat,
                kinds,
                limit,
                offset,
                since,
                until,
                with_meta,
                debug_source,
            )
            .await
            {
                Ok(v) => Response::ok(v),
                Err(e) => Response::err(e.to_string()),
            }
        }
        Extract {
            attachment_id,
            output,
            overwrite,
        } => match query::q_extract(db, &names_arc, &attachment_id, &output, overwrite).await {
            Ok(v) => Response::ok(v),
            Err(e) => Response::err(e.to_string()),
        },
    }
}

/// 重新加载 all_keys.json，并刷新 Names（msg_db_keys / contact 显示名）。
async fn reload_config(
    db: &DbCache,
    names: &tokio::sync::RwLock<Arc<Names>>,
) -> Result<serde_json::Value> {
    use super::{collect_db_keys, extract_keys, is_biz_msg_db_key, is_msg_db_key};
    use crate::config;

    let cfg = config::load_config()?;
    let keys_content = tokio::fs::read_to_string(&cfg.keys_file)
        .await
        .map_err(|e| anyhow::anyhow!("读取密钥文件 {:?} 失败: {}", cfg.keys_file, e))?;
    let keys_raw: serde_json::Value = serde_json::from_str(&keys_content)?;
    let all_keys = extract_keys(&keys_raw);
    let key_count = all_keys.len();
    db.replace_keys(all_keys.clone()).await;

    let msg_db_keys = collect_db_keys(&all_keys, is_msg_db_key);
    let biz_msg_db_keys = collect_db_keys(&all_keys, is_biz_msg_db_key);

    let names_raw = super::query::load_names(db).await.unwrap_or_else(|e| {
        eprintln!("[server] reload: 加载联系人失败: {}", e);
        Names {
            map: Default::default(),
            md5_to_uname: Default::default(),
            msg_db_keys: Vec::new(),
            biz_msg_db_keys: Vec::new(),
            verify_flags: Default::default(),
        }
    });
    let mut new_names = names_raw;
    new_names.msg_db_keys = msg_db_keys.clone();
    new_names.biz_msg_db_keys = biz_msg_db_keys;
    let contact_count = new_names.map.len();
    {
        let mut guard = names.write().await;
        *guard = Arc::new(new_names);
    }

    eprintln!(
        "[server] ReloadConfig: keys={} msg_shards={} contacts={}",
        key_count,
        msg_db_keys.len(),
        contact_count
    );

    Ok(serde_json::json!({
        "reloaded": true,
        "keys": key_count,
        "msg_shards": msg_db_keys.len(),
        "contacts": contact_count,
    }))
}
