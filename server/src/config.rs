//! `sshcrabd.toml` (spec §3). Missing file = built-in defaults.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields, default)]
pub struct Config {
    pub listen_address: Vec<String>,
    pub permit_root_login: bool,
    pub allow_users: Vec<String>,
    pub allow_groups: Vec<String>,
    /// 0 = unlimited.
    pub max_sessions_per_user: usize,
    pub max_unauthenticated: usize,
    pub max_unauth_per_source: usize,
    pub session_buffer_bytes: usize,
    pub disconnected_timeout: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen_address: vec!["0.0.0.0:22".into(), "[::]:22".into()],
            permit_root_login: true,
            allow_users: vec![],
            allow_groups: vec![],
            max_sessions_per_user: 32,
            max_unauthenticated: 64,
            max_unauth_per_source: 8,
            session_buffer_bytes: 1 << 20,
            disconnected_timeout: "24h".into(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Listen addresses with the `-p` override applied.
    pub fn addresses(&self, port: Option<u16>) -> Result<Vec<SocketAddr>, String> {
        self.listen_address
            .iter()
            .map(|a| {
                let mut addr: SocketAddr = a.parse().map_err(|_| format!("invalid ListenAddress {a:?}"))?;
                if let Some(p) = port {
                    addr.set_port(p);
                }
                Ok(addr)
            })
            .collect()
    }

    pub fn disconnected_timeout(&self) -> Result<Duration, String> {
        parse_duration(&self.disconnected_timeout)
            .ok_or_else(|| format!("invalid DisconnectedTimeout {:?}", self.disconnected_timeout))
    }
}

/// `90s`, `30m`, `24h`, `2d`, or combinations like `1h30m`.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let mut total = 0u64;
    let mut num = String::new();
    for c in s.trim().chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let n: u64 = num.parse().ok()?;
        num.clear();
        total += n * match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            _ => return None,
        };
    }
    num.is_empty().then_some(Duration::from_secs(total)).filter(|d| !d.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let c: Config = toml::from_str("ListenAddress = [\"127.0.0.1:2222\"]\nMaxSessionsPerUser = 4").unwrap();
        assert_eq!(c.max_sessions_per_user, 4);
        assert_eq!(c.addresses(Some(20202)).unwrap(), vec!["127.0.0.1:20202".parse().unwrap()]);
        assert_eq!(Config::default().addresses(None).unwrap().len(), 2);
        assert!(toml::from_str::<Config>("Bogus = 1").is_err());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("24h"), Some(Duration::from_secs(86400)));
        assert_eq!(parse_duration("1h30m"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_duration("2d"), Some(Duration::from_secs(172800)));
        assert_eq!(parse_duration("10"), None);
        assert_eq!(parse_duration("0s"), None);
        assert_eq!(parse_duration("5x"), None);
    }
}
