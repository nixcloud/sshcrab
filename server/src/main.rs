//! sshcrabd (spec §3).

mod auth;
mod config;
mod conn;
mod p2p;
mod session;
mod sys;

use std::collections::HashMap;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use sshcrab_proto::handshake::{self, HANDSHAKE_TIMEOUT};
use sshcrab_proto::keys::{Identity, KeyError};
use sshcrab_proto::transport::{Conn, Limits, Listener, Remote};

use crate::config::Config;
use crate::session::Manager;

#[derive(Parser)]
#[command(name = "sshcrabd", version, about = "sshcrab daemon; host_key and sshcrabd.toml live in the working directory")]
struct Args {
    /// UDP port for every listen address.
    #[arg(short = 'p', long)]
    port: Option<u16>,
    /// Print this host's P2P address (from host_key in the working directory) and exit.
    #[arg(long)]
    p2p_address: bool,
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    if args.p2p_address {
        return print_p2p_address();
    }
    match tokio::runtime::Runtime::new().expect("tokio runtime").block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sshcrabd: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Workdir and config must be owned by us and not writable by others (spec §3).
fn check_owner(path: &Path, what: &str) -> Result<(), String> {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return Ok(()) };
    let euid = nix::unistd::Uid::effective().as_raw();
    if meta.uid() != euid {
        return Err(format!("{what} {} is not owned by uid {euid}", path.display()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!("{what} {} is group- or world-writable (mode {:04o})", path.display(), meta.mode() & 0o7777));
    }
    Ok(())
}

/// `--p2p-address`: never generates a key, so it is safe to run any time.
fn print_p2p_address() -> ExitCode {
    let path = Path::new("host_key");
    if path.symlink_metadata().is_err() {
        eprintln!("sshcrabd: no host_key in this directory yet; start sshcrabd once to generate it");
        return ExitCode::FAILURE;
    }
    match Identity::load(path) {
        Ok(id) => {
            let key = sshcrab_proto::p2p::public_key(&id.p2p_seed());
            println!("{}", sshcrab_proto::p2p::format_address(&key));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sshcrabd: cannot load host key: {e}");
            ExitCode::FAILURE
        }
    }
}

fn host_key() -> Result<Identity, String> {
    let path = Path::new("host_key");
    if path.symlink_metadata().is_err() {
        let id = Identity::generate();
        id.save(path, "sshcrabd").map_err(|e| e.to_string())?;
        let workdir = std::env::current_dir().map_err(|e| e.to_string())?;
        println!("Generated new host key in {}", workdir.join("host_key").display());
        return Ok(id);
    }
    check_owner(path, "host key")?;
    Identity::load(path).map_err(|e| match e {
        KeyError::Permissions { .. } => e.to_string(),
        e => format!("cannot load host key: {e}"),
    })
}

async fn run(args: Args) -> Result<(), String> {
    let workdir = std::env::current_dir().map_err(|e| e.to_string())?;
    check_owner(&workdir, "working directory")?;
    check_owner(Path::new("sshcrabd.toml"), "config")?;
    let cfg = Arc::new(Config::load(Path::new("sshcrabd.toml"))?);
    let host = Arc::new(host_key()?);
    log::info!("host key {}", sshcrab_proto::keys::fingerprint(&host.public()));
    if !nix::unistd::Uid::effective().is_root() {
        log::warn!("not running as root: only {} can log in", nix::unistd::User::from_uid(nix::unistd::Uid::effective()).ok().flatten().map(|u| u.name).unwrap_or_default());
    }

    let mgr = Manager::new(cfg.session_buffer_bytes, cfg.disconnected_timeout()?, cfg.max_sessions_per_user);
    let limits = Limits { max_pending: cfg.max_unauthenticated, max_pending_per_source: cfg.max_unauth_per_source, ..Limits::default() };
    let preauth = Arc::new(PreAuth::new(cfg.max_unauthenticated, cfg.max_unauth_per_source, cfg.max_unauth_p2p));

    for addr in cfg.addresses(args.port)? {
        let mut listener = Listener::bind(addr, limits.clone()).await.map_err(|e| format!("{addr}: {e}"))?;
        log::info!("listening on udp {}", listener.local_addr());
        let (cfg, host, mgr, preauth) = (cfg.clone(), host.clone(), mgr.clone(), preauth.clone());
        tokio::spawn(async move {
            while let Some(conn) = listener.accept().await {
                let (cfg, host, mgr, preauth) = (cfg.clone(), host.clone(), mgr.clone(), preauth.clone());
                tokio::spawn(async move { handle(conn, cfg, host, mgr, preauth).await });
            }
        });
    }

    if cfg.p2p {
        p2p::start(cfg.clone(), host.clone(), mgr.clone(), preauth.clone())?;
    }

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|e| e.to_string())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    log::info!("shutting down; all sessions end");
    // Clients would otherwise reconnect and find their sessions gone.
    mgr.kick_all("sshcrabd is shutting down; the session has ended").await;
    conn::wait_detached(Duration::from_secs(3)).await;
    // Let the transport send the SHUTDOWN chunks of the connections just closed.
    tokio::time::sleep(Duration::from_millis(300)).await;
    mgr.kill_all();
    Ok(())
}

pub(crate) async fn handle(conn: Conn, cfg: Arc<Config>, host: Arc<Identity>, mgr: Arc<Manager>, preauth: Arc<PreAuth>) {
    let remote = conn.remote();
    let Some(_slot) = preauth.enter(remote) else {
        log::debug!("{remote}: too many unauthenticated connections");
        return;
    };
    let auth = async move |username: &str, key: &[u8; 32]| {
        let (cfg, username, key) = (cfg.clone(), username.to_string(), *key);
        tokio::task::spawn_blocking(move || auth::authorize(&cfg, &username, &key)).await.unwrap_or(Err(None))
    };
    let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake::server(conn, &host, auth)).await;
    drop(_slot);
    match result {
        Ok(Ok((sc, peer))) => conn::serve(sc, peer, mgr).await,
        Ok(Err(e)) => log::info!("{remote}: handshake failed: {e}"),
        Err(_) => log::info!("{remote}: handshake timed out"),
    }
}

/// Unauthenticated connections in the Noise/auth phase (spec §7.2).
pub(crate) struct PreAuth {
    max: usize,
    per_source: usize,
    p2p: usize,
    active: Mutex<HashMap<Source, usize>>,
}

/// IPv4 address or IPv6 /64; all P2P connections are one source.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Source {
    Ip(IpAddr),
    P2p,
}

struct Slot<'a>(&'a PreAuth, Source);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut a = self.0.active.lock().unwrap();
        if let Some(n) = a.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                a.remove(&self.1);
            }
        }
    }
}

impl PreAuth {
    fn new(max: usize, per_source: usize, p2p: usize) -> Self {
        PreAuth { max, per_source, p2p, active: Mutex::new(HashMap::new()) }
    }

    fn enter(&self, remote: Remote) -> Option<Slot<'_>> {
        let (key, limit) = match remote {
            Remote::Udp(a) => (Source::Ip(source_prefix(a.ip())), self.per_source),
            Remote::P2p(_) => (Source::P2p, self.p2p),
        };
        let mut a = self.active.lock().unwrap();
        let total: usize = a.values().sum();
        let mine = a.get(&key).copied().unwrap_or(0);
        if total >= self.max || mine >= limit {
            return None;
        }
        *a.entry(key).or_default() += 1;
        Some(Slot(self, key))
    }
}

/// IPv4 address, or the /64 of an IPv6 address.
fn source_prefix(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none() => {
            let s = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        IpAddr::V6(v6) => IpAddr::V4(v6.to_ipv4_mapped().unwrap()),
        v4 => v4,
    }
}
