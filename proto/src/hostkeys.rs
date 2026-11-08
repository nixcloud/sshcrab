//! `~/.sshcrab/hostkeys`: one `hostname port keytype base64key` per line (spec §7.8).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::keys;

pub const KEYTYPE: &str = "ssh-ed25519";

#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    Known,
    /// The host is listed with a different key on this (1-based) line.
    Mismatch { line: usize },
    Unknown,
}

/// Lower-cased, IPv6 without brackets.
pub fn normalize_host(host: &str) -> String {
    host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase()
}

/// Look `host`/`port` up in the file contents.
pub fn lookup(contents: &str, host: &str, port: u16, key: &[u8; 32]) -> Lookup {
    let host = normalize_host(host);
    let mut mismatch = None;
    for (i, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(h), Some(p), Some(t), Some(b)) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if normalize_host(h) != host || p.parse::<u16>().ok() != Some(port) {
            continue;
        }
        match keys::parse_public_openssh(&format!("{t} {b}")) {
            Some(k) if &k == key => return Lookup::Known,
            _ => {
                mismatch.get_or_insert(i + 1);
            }
        }
    }
    match mismatch {
        Some(line) => Lookup::Mismatch { line },
        None => Lookup::Unknown,
    }
}

pub fn format_line(host: &str, port: u16, key: &[u8; 32]) -> String {
    let openssh = keys::public_openssh(key, "");
    format!("{} {} {}\n", normalize_host(host), port, openssh.trim())
}

/// Append an entry, replacing the file atomically (temp file + rename).
pub fn append(path: &Path, host: &str, port: u16, key: &[u8; 32]) -> std::io::Result<()> {
    let mut contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(&format_line(host, port, key));
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(0o400000) // O_NOFOLLOW
        .open(&tmp)?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_reports_mismatch_line() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let contents = format!(
            "# comment\n{}\n{}{}",
            "garbage line",
            format_line("Example.org", 22, &a),
            format_line("[::1]", 2222, &b)
        );
        assert_eq!(lookup(&contents, "example.org", 22, &a), Lookup::Known);
        assert_eq!(lookup(&contents, "example.org", 22, &b), Lookup::Mismatch { line: 3 });
        assert_eq!(lookup(&contents, "example.org", 23, &b), Lookup::Unknown);
        assert_eq!(lookup(&contents, "::1", 2222, &b), Lookup::Known);
        assert!(format_line("Host", 22, &a).starts_with("host 22 ssh-ed25519 AAAA"));
    }
}
