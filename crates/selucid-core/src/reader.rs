// SPDX-License-Identifier: GPL-3.0-or-later
//! Async log reader: tail `/var/log/audit/audit.log` with `tokio`, surviving
//! truncation and rotation. Yields raw lines; parsing stays in [`crate::parser`].

use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};

/// Default audit log location on RHEL/Fedora.
pub const DEFAULT_AUDIT_LOG: &str = "/var/log/audit/audit.log";

/// Incremental tailer: remembers the byte offset between polls.
pub struct LogTailer {
    path: PathBuf,
    offset: u64,
}

impl LogTailer {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            offset: 0,
        }
    }

    pub fn audit_log() -> Self {
        Self::new(DEFAULT_AUDIT_LOG)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read every line appended since the last call. Seeks to the stored
    /// offset; if the file shrank (rotation/truncation) restarts from zero.
    pub async fn poll_new_lines(&mut self) -> std::io::Result<Vec<String>> {
        let mut file = match File::open(&self.path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Ok(Vec::new());
            }
            Err(e) => return Err(e),
        };
        let len = file.metadata().await?.len();
        if len < self.offset {
            self.offset = 0; // rotated or truncated
        }
        file.seek(SeekFrom::Start(self.offset)).await?;
        let mut reader = BufReader::new(file);
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break;
            }
            self.offset += n as u64;
            let line = line.trim_end_matches(['\n', '\r']).to_string();
            if !line.trim().is_empty() {
                lines.push(line);
            }
        }
        Ok(lines)
    }

    /// Read the whole file (used for one-shot `explain`/`suggest`).
    pub async fn read_all(&self) -> std::io::Result<Vec<String>> {
        let content = tokio::fs::read_to_string(&self.path).await?;
        Ok(content.lines().map(|l| l.to_string()).collect())
    }
}

/// A filesystem event observed while watching the audit log.
#[derive(Debug, Clone, PartialEq)]
pub enum WatchEvent {
    /// New denial events parsed since the last notification.
    Denials(Vec<crate::AvcEvent>),
    /// The log rotated or was truncated; consumers should refresh views.
    Rotated,
    /// The watcher itself failed (e.g. permission lost); carries the message.
    WatchError(String),
}

/// Watch the audit log with kernel filesystem notifications (`notify`),
/// falling back to polling when `notify` cannot be established.
///
/// The callback receives [`WatchEvent`]s. The returned handle must be kept
/// alive for the watch to continue; dropping it stops delivery. This is
/// synchronous by design: `notify` delivers on its own thread, and parsing
/// plus the callback are fast enough not to need async here.
pub struct LogWatcher {
    _watcher: notify::RecommendedWatcher,
}

impl LogWatcher {
    pub fn watch(
        path: impl Into<PathBuf>,
        on_event: impl Fn(WatchEvent) + Send + 'static,
    ) -> std::io::Result<Self> {
        use notify::{EventKind, RecursiveMode, Watcher};
        let path: PathBuf = path.into();
        let mut tailer = LogTailer::new(path.clone());
        // Prime the offset to EOF so pre-existing content is not replayed;
        // one-shot commands (`explain`) already cover history.
        let prime_offset = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        tailer.offset = prime_offset;

        let watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            match res {
                Ok(event) => {
                    if !matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    ) {
                        return;
                    }
                    let lines = futures_block_on(tailer.poll_new_lines()).unwrap_or_default();
                    // Detect rotation: the tailer resets its offset to 0.
                    let rotated = tailer.offset == 0 && !lines.is_empty();
                    let records = parse_lines(&lines);
                    let events = crate::extract_avc_events(&crate::group_by_serial(records));
                    if rotated {
                        on_event(WatchEvent::Rotated);
                    }
                    if !events.is_empty() {
                        on_event(WatchEvent::Denials(events));
                    }
                }
                Err(e) => on_event(WatchEvent::WatchError(e.to_string())),
            }
        })
        .map_err(std::io::Error::other)?;

        let mut watcher = watcher;
        watcher
            .watch(&path, RecursiveMode::NonRecursive)
            .map_err(std::io::Error::other)?;
        // Also watch the parent dir: rotation replaces the file (rename +
        // create), which a watch on the inode alone would miss.
        if let Some(parent) = path.parent() {
            let _ = watcher.watch(parent, RecursiveMode::NonRecursive);
        }
        Ok(Self { _watcher: watcher })
    }
}

/// Minimal block_on for the watch callback: `notify` invokes us on a plain
/// thread, so a throwaway single-thread runtime is the honest bridge into
/// the async tailer without adding a futures-executor dependency.
fn futures_block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for notify callback")
        .block_on(f)
}

/// Parse a batch of lines, silently skipping non-audit lines (e.g. auditd
/// comments) so one corrupt line never aborts a whole batch.
pub fn parse_lines(lines: &[String]) -> Vec<crate::AuditRecord> {
    lines
        .iter()
        .filter_map(|l| crate::parse_audit_line(l).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tails_appends_and_survives_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        tokio::fs::write(&path, "type=AVC msg=audit(1.0:1): avc: denied { read } for pid=1 comm=\"a\" scontext=u:r:t:s0 tcontext=u:o:x:s0 tclass=file\n").await.unwrap();
        let mut tailer = LogTailer::new(&path);
        assert_eq!(tailer.poll_new_lines().await.unwrap().len(), 1);
        // No new data → empty.
        assert!(tailer.poll_new_lines().await.unwrap().is_empty());
        // Append.
        tokio::fs::write(&path, "type=AVC msg=audit(1.0:1): avc: denied { read } for pid=1 comm=\"a\" scontext=u:r:t:s0 tcontext=u:o:x:s0 tclass=file\ntype=AVC msg=audit(2.0:2): avc: denied { write } for pid=2 comm=\"b\" scontext=u:r:t:s0 tcontext=u:o:x:s0 tclass=file\n").await.unwrap();
        assert_eq!(tailer.poll_new_lines().await.unwrap().len(), 1);
        // Truncate (rotation) → restarts from zero.
        tokio::fs::write(&path, "type=AVC msg=audit(3.0:3): avc: denied { open } for pid=3 comm=\"c\" scontext=u:r:t:s0 tcontext=u:o:x:s0 tclass=file\n").await.unwrap();
        assert_eq!(tailer.poll_new_lines().await.unwrap().len(), 1);
    }

    #[test]
    fn parse_lines_skips_garbage() {
        let lines = vec![
            "type=AVC msg=audit(1.0:1): avc: denied { read } for pid=1 comm=\"a\" scontext=u:r:t:s0 tcontext=u:o:x:s0 tclass=file".to_string(),
            "# auditd comment".to_string(),
        ];
        assert_eq!(parse_lines(&lines).len(), 1);
    }

    #[test]
    fn watcher_delivers_appended_denials() {
        use std::sync::{Arc, Mutex};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "type=AVC msg=audit(1.0:1): avc: denied { read } for pid=1 comm=\"a\" scontext=u:r:t:s0 tcontext=u:o:x:s0 tclass=file\n").unwrap();
        let got: Arc<Mutex<Vec<WatchEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let got_cb = Arc::clone(&got);
        let _watch = LogWatcher::watch(path.clone(), move |ev| {
            got_cb.lock().unwrap().push(ev);
        })
        .unwrap();
        // Append a new denial; inotify should fire within the wait below.
        std::fs::write(&path, "type=AVC msg=audit(1.0:1): avc: denied { read } for pid=1 comm=\"a\" scontext=u:r:t:s0 tcontext=u:o:x:s0 tclass=file\ntype=AVC msg=audit(2.0:2): avc: denied { write } for pid=2 comm=\"b\" scontext=u:r:t:s0 tcontext=u:o:x:s0 tclass=file\n").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            {
                let events = got.lock().unwrap();
                if events.iter().any(|e| matches!(e, WatchEvent::Denials(_))) {
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "watch event never arrived"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let events = got.lock().unwrap();
        let denials: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                WatchEvent::Denials(d) => Some(d),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].serial, 2);
    }
}
