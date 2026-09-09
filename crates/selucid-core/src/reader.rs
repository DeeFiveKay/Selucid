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
}
