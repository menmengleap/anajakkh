//! Logging utilities: secret redaction and safe log writers.
//!
//! ANAJAKKH never logs API keys, passwords, or tokens. The
//! [`RedactingWriter`] is layered under the tracing file writer, so *every*
//! line that reaches the log file is scrubbed by [`redact`] — even if a
//! log message embeds a secret it should not have.

use std::io::{self, Write};

/// Scrub common secret patterns from a single log line (or partial line).
///
/// Patterns handled (case-insensitive where sensible):
/// - `Bearer <token>` authorization headers;
/// - `Authorization:` header values;
/// - `sk-...` style API keys and common prefixed tokens (`ghp_`, `AKIA`...);
/// - `key=value` / `key: value` assignments for well-known secret names;
/// - userinfo embedded in URLs (`https://user:pass@host`).
///
/// Non-secret text passes through untouched.
pub fn redact(input: &str) -> String {
    let mut out = input.to_string();
    out = redact_bearer(&out);
    out = redact_authorization(&out);
    out = redact_url_userinfo(&out);
    out = redact_prefixed_tokens(&out);
    redact_assignments(&out)
}

/// `Bearer <token>` → `Bearer [REDACTED]`
fn redact_bearer(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let rest = &s[i..];
        let lower = rest.to_ascii_lowercase();
        if let Some(pos) = lower.find("bearer") {
            // Word boundary before "bearer".
            let abs = i + pos;
            let before_ok = abs == 0 || !bytes[abs - 1].is_ascii_alphanumeric();
            if before_ok {
                let after = abs + "bearer".len();
                out.push_str(&s[i..after]);
                // Consume the token following the keyword.
                let mut j = after;
                while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                    j += 1;
                }
                let mut k = j;
                while k < bytes.len() && !bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
                if k > j {
                    out.push_str(&s[after..j]);
                    out.push_str("[REDACTED]");
                    i = k;
                } else {
                    i = after;
                }
            } else {
                out.push_str(&s[i..after_end(s, i + pos + "bearer".len())]);
                i = after_end(s, i + pos + "bearer".len());
            }
        } else {
            out.push_str(rest);
            break;
        }
    }
    out
}

fn after_end(s: &str, pos: usize) -> usize {
    pos.min(s.len())
}

/// `Authorization: <value>` → `Authorization: [REDACTED]`
fn redact_authorization(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let rest = &s[i..];
        let lower = rest.to_ascii_lowercase();
        if let Some(pos) = lower.find("authorization") {
            let abs = i + pos;
            let before_ok = abs == 0 || !bytes[abs - 1].is_ascii_alphanumeric();
            let after = abs + "authorization".len();
            if before_ok {
                // Consume `:` (or `=`) and the value up to end of line.
                let mut j = after;
                while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                    j += 1;
                }
                if j < bytes.len() && (bytes[j] == b':' || bytes[j] == b'=') {
                    j += 1;
                    while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                        j += 1;
                    }
                    let mut k = j;
                    while k < bytes.len() && bytes[k] != b'\n' && bytes[k] != b'\r' {
                        k += 1;
                    }
                    out.push_str(&s[i..j]);
                    out.push_str("[REDACTED]");
                    i = k;
                } else {
                    out.push_str(&s[i..after]);
                    i = after;
                }
            } else {
                out.push_str(&s[i..after]);
                i = after;
            }
        } else {
            out.push_str(rest);
            break;
        }
    }
    out
}

/// `scheme://user:pass@host` → `scheme://[REDACTED]@host`
fn redact_url_userinfo(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let rest = &s[i..];
        if let Some(pos) = rest.find("://") {
            let scheme_end = i + pos + 3;
            // Find the next `@` before the end of the authority section
            // (next `/`, `?`, `#`, or whitespace).
            let mut j = scheme_end;
            let mut at = None;
            while j < bytes.len()
                && !matches!(bytes[j], b'/' | b'?' | b'#' | b' ' | b'\t' | b'\n' | b'\r')
            {
                if bytes[j] == b'@' {
                    at = Some(j);
                    break;
                }
                j += 1;
            }
            match at {
                Some(at_pos) => {
                    // Only redact when userinfo contains a password separator.
                    let userinfo = &s[scheme_end..at_pos];
                    if userinfo.contains(':') {
                        out.push_str(&s[i..scheme_end]);
                        out.push_str("[REDACTED]");
                        out.push('@');
                        i = at_pos + 1;
                    } else {
                        out.push_str(&s[i..at_pos + 1]);
                        i = at_pos + 1;
                    }
                }
                None => {
                    out.push_str(&s[i..scheme_end]);
                    i = scheme_end;
                }
            }
        } else {
            out.push_str(rest);
            break;
        }
    }
    out
}

/// `sk-<token>` and other well-known prefixed secrets → `sk-[REDACTED]`
fn redact_prefixed_tokens(s: &str) -> String {
    const PREFIXES: &[&str] = &[
        "sk-",
        "pk-",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "AKIA",
        "gho_",
    ];
    let mut out = s.to_string();
    for prefix in PREFIXES {
        out = redact_prefix(&out, prefix);
    }
    out
}

fn redact_prefix(s: &str, prefix: &str) -> String {
    let bytes = s.as_bytes();
    let p = prefix.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let rest = &s[i..];
        if rest.len() >= prefix.len() && rest.as_bytes()[..prefix.len()] == *p {
            let abs = i;
            let before_ok = abs == 0 || !bytes[abs - 1].is_ascii_alphanumeric();
            if before_ok {
                // Consume the alphanumeric token following the prefix.
                let mut k = i + prefix.len();
                while k < bytes.len()
                    && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_' || bytes[k] == b'-')
                {
                    k += 1;
                }
                if k > i + prefix.len() {
                    out.push_str(&s[i..i + prefix.len()]);
                    out.push_str("[REDACTED]");
                    i = k;
                    continue;
                }
            }
            out.push_str(&s[i..i + prefix.len()]);
            i += prefix.len();
        } else {
            // Advance to the next potential prefix occurrence.
            match rest[1..].find(prefix) {
                Some(pos) => {
                    out.push_str(&s[i..i + 1 + pos]);
                    i += 1 + pos;
                }
                None => {
                    out.push_str(rest);
                    break;
                }
            }
        }
    }
    out
}

/// Well-known secret key names in `key=value` / `key: value` form.
const SECRET_KEYS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "password",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "client-secret",
    "access_token",
    "access-token",
    "access_key",
    "access-key",
    "private_key",
    "private-key",
    "auth",
    "token",
];

/// `api_key=sk-...` / `password: hunter2` → value replaced with `[REDACTED]`.
fn redact_assignments(s: &str) -> String {
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0;
    while cursor < n {
        // Earliest key match at or after `cursor`, with a word boundary
        // before the key and a separator after it.
        let mut best: Option<(usize, usize)> = None;
        for key in SECRET_KEYS {
            let kb = key.as_bytes();
            let mut pos = cursor;
            while pos + kb.len() <= n {
                let slice = &bytes[pos..pos + kb.len()];
                if slice.iter().zip(kb).all(|(a, b)| a.eq_ignore_ascii_case(b)) {
                    let before_ok = pos == 0 || !bytes[pos - 1].is_ascii_alphanumeric();
                    if before_ok && has_separator(bytes, pos + kb.len()) {
                        best = Some((pos, kb.len()));
                    }
                    break;
                }
                pos += 1;
            }
        }
        match best {
            Some((kstart, klen)) => {
                out.push_str(&s[cursor..kstart]);
                let mut j = kstart + klen;
                while j < n && (bytes[j] == b' ' || bytes[j] == b'\t') {
                    j += 1;
                }
                debug_assert!(j < n && (bytes[j] == b'=' || bytes[j] == b':'));
                j += 1; // separator
                while j < n && (bytes[j] == b' ' || bytes[j] == b'\t') {
                    j += 1;
                }
                let mut k = j;
                while k < n
                    && !matches!(
                        bytes[k],
                        b' ' | b'\t'
                            | b'\n'
                            | b'\r'
                            | b'&'
                            | b';'
                            | b','
                            | b'"'
                            | b'\''
                            | b'<'
                            | b'>'
                    )
                {
                    k += 1;
                }
                out.push_str(&s[kstart..j]);
                if k > j {
                    out.push_str("[REDACTED]");
                    cursor = k;
                } else {
                    // `key=` with an empty value — nothing to hide.
                    cursor = j;
                }
            }
            None => {
                out.push_str(&s[cursor..]);
                break;
            }
        }
    }
    out
}

fn has_separator(bytes: &[u8], mut j: usize) -> bool {
    while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
        j += 1;
    }
    j < bytes.len() && (bytes[j] == b'=' || bytes[j] == b':')
}

/// A [`Write`] wrapper that redacts every complete line before writing it
/// to the underlying writer. Partial lines are buffered until a newline
/// arrives, so secrets split across writes are still scrubbed.
pub struct RedactingWriter<W: Write> {
    inner: W,
    buffer: String,
}

impl<W: Write> RedactingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            buffer: String::new(),
        }
    }

    /// Consume the buffered text and return the wrapped writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.push_str(&String::from_utf8_lossy(buf));
        while let Some(pos) = self.buffer.find('\n') {
            let line = self.buffer[..=pos].to_string();
            self.buffer.drain(..=pos);
            let redacted = redact(&line);
            self.inner.write_all(redacted.as_bytes())?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let redacted = redact(&self.buffer);
            self.inner.write_all(redacted.as_bytes())?;
            self.buffer.clear();
        }
        self.inner.flush()
    }
}

/// Lets tracing write through the redacting layer to the log file. Each
/// make_writer call borrows the file — [`Write`] for `&File` is provided
/// by std, so no interior mutability is needed.
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RedactingWriter<std::fs::File> {
    type Writer = RedactingWriter<&'a std::fs::File>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: &self.inner,
            buffer: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_bearer_tokens() {
        let out = redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret.payload");
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"));
    }

    #[test]
    fn redacts_authorization_header() {
        // The header value runs to the end of the line, so everything
        // after the colon is scrubbed.
        let out = redact("header Authorization: Basic dXNlcjpwYXNz end");
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("dXNlcjpwYXNz"));
        assert!(out.contains("header"));
    }

    #[test]
    fn redacts_sk_keys() {
        let out = redact("using key sk-abc123DEF456ghi789 for api");
        assert!(out.contains("sk-[REDACTED]"));
        assert!(!out.contains("sk-abc123DEF456ghi789"));
    }

    #[test]
    fn redacts_github_and_aws_tokens() {
        assert!(!redact("ghp_1234567890abcdefghij").contains("1234567890abcdefghij"));
        assert!(redact("AKIAIOSFODNN7EXAMPLE").contains("[REDACTED]"));
    }

    #[test]
    fn redacts_key_assignments() {
        let out = redact("api_key=sk-live-abc123 password: hunter2 token 12345");
        assert!(!out.contains("sk-live-abc123"));
        assert!(!out.contains("hunter2"));
        assert!(out.contains("[REDACTED]"));
        // `token 12345` (no separator) is left alone.
        assert!(out.contains("token 12345"));
    }

    #[test]
    fn redacts_url_userinfo() {
        let out = redact("https://user:supersecret@example.com/path");
        assert!(!out.contains("supersecret"));
        assert!(out.contains("[REDACTED]@example.com"));
        // No password → untouched.
        let plain = redact("https://user@example.com/path");
        assert!(plain.contains("user@example.com"));
    }

    #[test]
    fn plain_text_passes_through() {
        let msg = "step dns finished success=true summary=resolved 1 address(es)";
        assert_eq!(redact(msg), msg);
    }

    #[test]
    fn writer_redacts_split_secrets() {
        let mut buf = Vec::new();
        {
            let mut w = RedactingWriter::new(&mut buf);
            // Secret split across two writes.
            w.write_all(b"api_key=sk-live-abc").unwrap();
            w.write_all(b"123 def\\n").unwrap();
            w.flush().unwrap();
        }
        let text = String::from_utf8(buf).unwrap();
        assert!(!text.contains("sk-live-abc123"));
        assert!(text.contains("[REDACTED]"));
    }
}
