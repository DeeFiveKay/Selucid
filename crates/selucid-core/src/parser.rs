// SPDX-License-Identifier: GPL-3.0-or-later
//! `nom`-based audit record parser.
//!
//! Format: `type=AVC msg=audit(1699999999.123:456): avc: denied { open } ...`
//! The `key=value` body is tokenized with `nom` primitives (quoted or bare
//! values); surrounding prose (`avc:`, `denied`, `for`, braces) is skipped by
//! the scanner. `avc: <result>` and `{ <perms> }` become synthetic fields
//! `avc_result` and `avc_perms`.

use crate::avc::AuditRecord;
use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{take_while, take_while1},
    character::complete::{char, multispace0},
    combinator::map,
    sequence::delimited,
};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("line is not an audit record: {0}")]
    NotAuditRecord(String),
    #[error("malformed audit header in line: {0}")]
    BadHeader(String),
    #[error("invalid timestamp or serial: {0}")]
    BadId(String),
}

/// Parse one audit log line into an [`AuditRecord`].
pub fn parse_audit_line(line: &str) -> Result<AuditRecord, ParseError> {
    let line = line.trim();
    if line.is_empty() {
        return Err(ParseError::NotAuditRecord("<empty>".to_string()));
    }
    let after_type = line
        .strip_prefix("type=")
        .ok_or_else(|| ParseError::NotAuditRecord(truncate(line)))?;
    let space = after_type
        .find(' ')
        .ok_or_else(|| ParseError::BadHeader(truncate(line)))?;
    let record_type = after_type[..space].to_ascii_uppercase();
    let rest = after_type[space..].trim_start();

    let header = rest
        .strip_prefix("msg=audit(")
        .ok_or_else(|| ParseError::BadHeader(truncate(line)))?;
    let close = header
        .find("):")
        .ok_or_else(|| ParseError::BadHeader(truncate(line)))?;
    let (timestamp, serial) = parse_audit_id(&header[..close])
        .map_err(|_| ParseError::BadId(header[..close].to_string()))?;
    let audit_id = header[..close].to_string();
    let body = header[close + 2..].trim_start();

    let mut fields = parse_kv_body(body);
    if let Some(result) = parse_avc_result(body) {
        fields.insert("avc_result".to_string(), result);
    }
    if let Some(perms) = parse_avc_perms(body) {
        fields.insert("avc_perms".to_string(), perms.join(","));
    }

    Ok(AuditRecord {
        record_type,
        audit_id,
        timestamp,
        serial,
        fields,
        raw: line.to_string(),
    })
}

fn parse_audit_id(id: &str) -> Result<(f64, u64), ()> {
    let (ts, serial) = id.split_once(':').ok_or(())?;
    Ok((ts.parse().map_err(|_| ())?, serial.parse().map_err(|_| ())?))
}

/// Word following `avc:`, i.e. `denied` or `granted`.
fn parse_avc_result(body: &str) -> Option<String> {
    let pos = body.find("avc:")?;
    body[pos + 4..]
        .split_whitespace()
        .next()
        .map(|w| w.trim_matches(|c| c == ',' || c == ':').to_string())
}

/// Permission names inside the first `{ ... }` set.
fn parse_avc_perms(body: &str) -> Option<Vec<String>> {
    let open = body.find('{')?;
    let close = body[open..].find('}')?;
    let perms: Vec<String> = body[open + 1..open + close]
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    if perms.is_empty() { None } else { Some(perms) }
}

fn is_key_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':')
}

fn kv_key(input: &str) -> IResult<&str, &str> {
    take_while1(is_key_char).parse(input)
}

fn kv_quoted(input: &str) -> IResult<&str, String> {
    map(
        delimited(char('"'), take_while(|c| c != '"'), char('"')),
        |s: &str| s.to_string(),
    )
    .parse(input)
}

fn kv_bare(input: &str) -> IResult<&str, String> {
    map(take_while1(|c: char| !c.is_whitespace()), |s: &str| {
        s.to_string()
    })
    .parse(input)
}

fn kv_value(input: &str) -> IResult<&str, String> {
    alt((kv_quoted, kv_bare)).parse(input)
}
/// Scan the record body, collecting every `key=value` pair and skipping prose.
fn parse_kv_body(body: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    let mut rest = body;
    loop {
        let (r, _) = multispace0::<&str, nom::error::Error<&str>>
            .parse(rest)
            .unwrap_or((rest, ""));
        rest = r;
        if rest.is_empty() {
            break;
        }
        match kv_key.parse(rest) {
            Ok((after_key, key)) if after_key.starts_with('=') => {
                match kv_value.parse(&after_key[1..]) {
                    Ok((after_value, value)) => {
                        fields.insert(key.to_string(), value);
                        rest = after_value;
                    }
                    Err(_) => rest = skip_junk(rest),
                }
            }
            _ => rest = skip_junk(rest),
        }
    }
    fields
}

/// Skip one whitespace-delimited token that is not a `key=value` pair.
fn skip_junk(rest: &str) -> &str {
    match take_while1::<_, _, nom::error::Error<&str>>(|c: char| !c.is_whitespace()).parse(rest) {
        Ok((r, _)) => r,
        Err(_) => rest.get(1..).unwrap_or(""),
    }
}

fn truncate(s: &str) -> String {
    if s.len() > 120 {
        format!("{}…", &s[..120])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AVC: &str = r#"type=AVC msg=audit(1788956400.123:456): avc:  denied  { open } for  pid=1234 comm="httpd" path="/var/www/html/index.html" dev="dm-0" ino=123456 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0"#;

    #[test]
    fn parses_avc_header_and_fields() {
        let rec = parse_audit_line(AVC).unwrap();
        assert_eq!(rec.record_type, "AVC");
        assert_eq!(rec.serial, 456);
        assert!((rec.timestamp - 1788956400.123).abs() < 0.001);
        assert_eq!(rec.fields["avc_result"], "denied");
        assert_eq!(rec.fields["avc_perms"], "open");
        assert_eq!(rec.fields["comm"], "httpd");
        assert_eq!(rec.fields["scontext"], "system_u:system_r:httpd_t:s0");
        assert_eq!(rec.fields["tclass"], "file");
    }

    #[test]
    fn parses_quoted_value_with_spaces() {
        let rec = parse_audit_line(
            r#"type=AVC msg=audit(1788956550.250:459): avc: denied { getattr } for pid=4567 comm="Web Content" path="/srv/data/report.pdf" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file permissive=0"#,
        )
        .unwrap();
        assert_eq!(rec.fields["comm"], "Web Content");
        assert_eq!(rec.fields["path"], "/srv/data/report.pdf");
    }

    #[test]
    fn parses_syscall_record() {
        let rec = parse_audit_line(
            r#"type=SYSCALL msg=audit(1788956400.123:456): arch=c000003e syscall=2 success=no exit=-13 pid=1234 comm="httpd" exe="/usr/sbin/httpd" subj=system_u:system_r:httpd_t:s0"#,
        )
        .unwrap();
        assert_eq!(rec.record_type, "SYSCALL");
        assert_eq!(rec.fields["exe"], "/usr/sbin/httpd");
        assert_eq!(rec.fields["exit"], "-13");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_audit_line("").is_err());
        assert!(parse_audit_line("not an audit line").is_err());
        assert!(parse_audit_line("type=AVC no header here").is_err());
    }
}
