//! sshcrab client (spec §2, §4).

mod attach;
mod connect;
mod local;
mod outage;
mod ping;
mod term;
mod ui;

use clap::Parser;
use sshcrab_proto::channel::{Msg, SecureConn};
use sshcrab_proto::wire::{Attach, AttachRefusal, ControlOp, Ctrl, Offsets, SessionInfo};
use uuid::Uuid;

use crate::attach::{Outcome, Runner, Session};
use crate::connect::{Connector, Target};

#[derive(Parser)]
#[command(name = "sshcrab", version, about = "Remote shell over SCTP/UDP with resumable sessions")]
struct Args {
    /// UDP port.
    #[arg(short = 'p', long, default_value_t = 22)]
    port: u16,
    /// Always create a new session.
    #[arg(short = 'N', long = "new")]
    new: bool,
    /// Resume the session <UUID>, or choose one from a list.
    #[arg(short = 'R', long = "resume", num_args = 0..=1, default_missing_value = "", value_name = "UUID")]
    resume: Option<String>,
    /// List sessions.
    #[arg(short = 'L', long = "list")]
    list: bool,
    /// Control mode: detach or remove sessions.
    #[arg(short = 'C', long = "control")]
    control: bool,
    /// Measure round trips over the connection (the path keystrokes and their
    /// echo take) instead of opening a shell.
    #[arg(long)]
    ping: bool,
    /// Pings to send with --ping; 0 = until Ctrl+C.
    #[arg(long, default_value_t = 100, value_name = "N", requires = "ping")]
    ping_count: u32,
    /// Milliseconds between pings with --ping (about typing pace by default).
    #[arg(long, default_value_t = 100, value_name = "MS", requires = "ping", value_parser = clap::value_parser!(u64).range(1..))]
    ping_interval: u64,
    /// Trust an unknown host key without asking (never overrides a mismatch).
    #[arg(long)]
    accept_new: bool,
    /// DHT bootstrap node for `.p2p` hosts (`host:port`); repeatable. Overrides
    /// `P2PBootstrap` in ~/.sshcrab/config.toml.
    #[arg(long, value_name = "HOST:PORT")]
    bootstrap: Vec<String>,
    /// [user@]host [command…]
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true, value_name = "[USER@]HOST [COMMAND]")]
    rest: Vec<String>,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("off")).init();
    let args = Args::parse();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let code = rt.block_on(run(args));
    term::restore();
    std::process::exit(code);
}

fn fail(msg: impl std::fmt::Display, code: i32) -> i32 {
    term::restore();
    eprintln!("sshcrab: {msg}");
    code
}

/// Quote for a POSIX shell if needed.
fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"@%+=:,./_-".contains(&b)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

async fn run(args: Args) -> i32 {
    let mut rest = args.rest;
    // `-R user@host` lists: clap hands the destination to -R as its value.
    let resume: Option<Option<Uuid>> = match args.resume {
        None => None,
        Some(v) if v.is_empty() => Some(None),
        Some(v) => match Uuid::parse_str(&v) {
            Ok(id) => Some(Some(id)),
            Err(_) => {
                rest.insert(0, v);
                Some(None)
            }
        },
    };
    if args.new && resume.is_some() {
        return fail("-N/--new and -R/--resume cannot be combined", 2);
    }
    let modes = [args.list, args.control, args.new || resume.is_some(), args.ping].iter().filter(|m| **m).count();
    if modes > 1 {
        return fail("-L, -C, -N/-R and --ping cannot be combined", 2);
    }
    let Some(destination) = rest.first().cloned() else {
        return fail("missing [user@]host", 2);
    };
    let command = (rest.len() > 1).then(|| rest[1..].join(" "));
    if command.is_some() && (resume.is_some() || args.list || args.control || args.ping) {
        return fail("a remote command cannot be combined with -R, -L, -C or --ping", 2);
    }
    let (user, host) = match destination.rsplit_once('@') {
        Some((u, h)) => (u.to_string(), h.to_string()),
        None => (std::env::var("USER").unwrap_or_default(), destination.clone()),
    };
    if user.is_empty() {
        return fail("cannot determine the user name: $USER is empty; use user@host", 2);
    }
    let target = Target { user, host, port: args.port };

    local::gc();
    let config = match local::Config::load() {
        Ok(c) => c,
        Err(e) => return fail(e, 255),
    };
    let connector = match Connector::new(target.clone(), args.accept_new, config.bootstrap(&args.bootstrap)) {
        Ok(c) => c,
        Err(e) => return fail(e, 255),
    };
    let start = std::time::Instant::now();
    let mut sc = match connector.connect(true).await {
        Ok(sc) => sc,
        Err(e) => return fail(e.message(), 255),
    };

    if args.list {
        return list(&mut sc).await;
    }
    if args.control {
        return control(&mut sc).await;
    }
    if args.ping {
        let interval = std::time::Duration::from_millis(args.ping_interval);
        return ping::run(&mut sc, start.elapsed(), args.ping_count, interval).await;
    }

    let mut resume_command = format!("sshcrab -R {{id}}");
    if args.port != 22 {
        resume_command.push_str(&format!(" -p {}", args.port));
    }
    if args.accept_new {
        resume_command.push_str(" --accept-new");
    }
    for b in &args.bootstrap {
        resume_command.push_str(&format!(" --bootstrap {}", shell_quote(b)));
    }
    resume_command.push(' ');
    resume_command.push_str(&shell_quote(&format!("{}@{}", target.user, target.host)));

    attach_mode(&connector, sc, command, resume, args.new, resume_command).await
}

async fn request(sc: &mut SecureConn, msg: Ctrl) -> Option<Ctrl> {
    sc.send_ctrl(&msg).await.ok()?;
    loop {
        match sc.recv().await.ok()? {
            Msg::Ctrl(Ctrl::Pong) => continue,
            Msg::Ctrl(c) => return Some(c),
            Msg::Data(_) => return None,
        }
    }
}

async fn sessions(sc: &mut SecureConn, msg: Ctrl) -> Option<Vec<SessionInfo>> {
    match request(sc, msg).await? {
        Ctrl::Sessions(mut s) => {
            ui::sort_sessions(&mut s);
            Some(s)
        }
        _ => None,
    }
}

async fn list(sc: &mut SecureConn) -> i32 {
    let Some(list) = sessions(sc, Ctrl::ListSessions).await else { return fail("connection lost", 255) };
    for s in &list {
        println!("{}", ui::list_line(s, false));
    }
    sc_close(sc).await;
    0
}

async fn sc_close(sc: &mut SecureConn) {
    let _ = sc.send_ctrl(&Ctrl::Close).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async { while sc.recv().await.is_ok() {} }).await;
}

async fn control(sc: &mut SecureConn) -> i32 {
    let _ = cliclack::intro("sshcrab control");
    let Some(list) = sessions(sc, Ctrl::Control(ControlOp::List)).await else { return fail("connection lost", 255) };
    if list.is_empty() {
        let _ = cliclack::outro("no sessions");
        sc_close(sc).await;
        return 0;
    }
    let show_owner = list.iter().any(|s| s.owner != list[0].owner);
    let id = ui::pick_session("Which session?", &list, show_owner);
    let info = list.iter().find(|s| s.id == id).expect("picked from list");
    let op = match ui::control_action(info) {
        ui::ControlAction::Detach => ControlOp::Detach(id),
        ui::ControlAction::Remove => {
            if !ui::confirm(&format!("Remove {id} and end its processes?")) {
                ui::aborted();
            }
            ControlOp::Remove(id)
        }
    };
    let code = match request(sc, Ctrl::Control(op)).await {
        Some(Ctrl::Feedback { text }) => {
            let _ = cliclack::outro(ui::sanitize(&text));
            0
        }
        _ => fail("connection lost", 255),
    };
    sc_close(sc).await;
    code
}

fn local_env() -> Vec<(String, String)> {
    ["TERM", "LANG", "LC_ALL"]
        .iter()
        .filter_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()).map(|v| (k.to_string(), v)))
        .collect()
}

async fn attach_mode(
    connector: &Connector,
    mut sc: SecureConn,
    command: Option<String>,
    resume: Option<Option<Uuid>>,
    force_new: bool,
    resume_command: String,
) -> i32 {
    let interactive_new = command.is_none();
    let window = if interactive_new { term::window_size() } else { None };
    let new = Attach::New { command: command.clone(), env: local_env(), window };

    // Decide what to attach to (spec §4.4).
    let (attach, interactive) = if force_new || command.is_some() {
        (new, interactive_new)
    } else {
        let Some(list) = sessions(&mut sc, Ctrl::ListSessions).await else { return fail("connection lost", 255) };
        let resume_one = |s: &SessionInfo| {
            let window = if s.interactive { term::window_size() } else { None };
            (Attach::Resume { id: s.id, takeover: true, received: Offsets::default(), window }, s.interactive)
        };
        match resume {
            Some(Some(id)) => match list.iter().find(|s| s.id == id) {
                Some(s) => resume_one(s),
                None => return fail(format!("no session {id}"), 1),
            },
            Some(None) if list.is_empty() => return fail("no sessions to resume", 1),
            Some(None) => {
                let id = ui::pick_session("Resume which session?", &list, false);
                resume_one(list.iter().find(|s| s.id == id).expect("picked"))
            }
            None => match list.as_slice() {
                [] => (new, interactive_new),
                [s] if !s.connected => resume_one(s),
                [s] => match ui::new_or_takeover(s) {
                    ui::NewOrTakeover::New => (new, interactive_new),
                    ui::NewOrTakeover::Takeover => resume_one(s),
                },
                _ => {
                    let id = ui::pick_session("Resume which session?", &list, false);
                    resume_one(list.iter().find(|s| s.id == id).expect("picked"))
                }
            },
        }
    };

    let (id, replay, terminal) = match request(&mut sc, Ctrl::Attach(attach)).await {
        Some(Ctrl::Attached { id, replay, terminal, .. }) => (id, replay, terminal),
        Some(Ctrl::AttachRefused { reason }) => {
            let msg = match reason {
                AttachRefusal::NotFound => "session not found",
                AttachRefusal::AttachedElsewhere => "session is attached elsewhere",
                AttachRefusal::TooManySessions => "too many sessions on the server (MaxSessionsPerUser)",
                AttachRefusal::Failed => "the server could not start the session",
            };
            return fail(msg, 1);
        }
        _ => return fail("connection lost", 255),
    };

    let file = local::SessionFile::create(id);
    if interactive {
        term::enable_raw();
    }
    let mut session = Session::new(id, interactive);
    session.enter_terminal(&terminal);
    let runner = Runner::new(connector, session, resume_command.replace("{id}", &id.to_string()));
    match runner.run(sc, replay).await {
        Outcome::Exit(code) => {
            file.map(local::SessionFile::remove);
            code
        }
        Outcome::Kicked(reason) => {
            file.map(local::SessionFile::remove);
            fail(reason, 255)
        }
        Outcome::Gone => {
            file.map(local::SessionFile::remove);
            fail(format!("session {id} no longer exists"), 255)
        }
        Outcome::Aborted => 130,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("alice@host.example"), "alice@host.example");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }
}
