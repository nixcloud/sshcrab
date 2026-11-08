//! Session lists, menus and text output (spec §4.4–4.6).

use std::io;

use sshcrab_proto::wire::SessionInfo;
use uuid::Uuid;

/// `45s`, `2m15s`, `1h5m30s`, `2h15m`, `3d2h`: zero components omitted.
pub fn format_duration(secs: u64) -> String {
    if secs == 0 {
        return "0s".into();
    }
    let parts = [(secs / 86400, 'd'), (secs / 3600 % 24, 'h'), (secs / 60 % 60, 'm'), (secs % 60, 's')];
    parts.iter().filter(|(n, _)| *n > 0).map(|(n, u)| format!("{n}{u}")).collect()
}

/// Disconnected first (oldest disconnect first), then connected; ties by
/// creation time (oldest first), then UUID.
pub fn sort_sessions(sessions: &mut [SessionInfo]) {
    sessions.sort_by(|a, b| {
        (a.connected, std::cmp::Reverse(a.idle_secs), std::cmp::Reverse(a.age_secs), a.id).cmp(&(
            b.connected,
            std::cmp::Reverse(b.idle_secs),
            std::cmp::Reverse(b.age_secs),
            b.id,
        ))
    });
}

/// Server-provided text with control characters removed (spec §7.8).
pub fn sanitize(text: &str) -> String {
    text.chars().filter(|c| !c.is_control() || *c == '\n').collect()
}

/// One `-L` line.
pub fn list_line(s: &SessionInfo, show_owner: bool) -> String {
    let mut line = format!(
        "{} [{}] [{}]",
        s.id,
        if s.interactive { "interactive" } else { "non-interactive" },
        if s.connected { "connected" } else { "disconnected" }
    );
    if let Some(idle) = s.idle_secs {
        line.push(' ');
        line.push_str(&format_duration(idle));
    }
    if show_owner {
        line.push_str(&format!(" ({})", sanitize(&s.owner)));
    }
    line
}

fn menu_label(s: &SessionInfo) -> String {
    match s.idle_secs {
        Some(idle) => format!("{}  idle {}", s.id, format_duration(idle)),
        None => s.id.to_string(),
    }
}

fn menu_hint(s: &SessionInfo, show_owner: bool) -> String {
    let kind = if s.interactive { "interactive" } else { "non-interactive" };
    let state = if s.connected { "connected" } else { "disconnected" };
    if show_owner { format!("{kind}, {state}, {}", sanitize(&s.owner)) } else { format!("{kind}, {state}") }
}

/// Ctrl+C in a prompt: `aborted` on stderr, exit 0, no state touched.
pub fn aborted() -> ! {
    let _ = cliclack::outro_cancel("aborted");
    eprintln!("aborted");
    std::process::exit(0);
}

fn interact<T>(r: io::Result<T>) -> T {
    match r {
        Ok(v) => v,
        Err(_) => aborted(),
    }
}

/// Single-select numbered menu over sorted sessions.
pub fn pick_session(prompt: &str, sessions: &[SessionInfo], show_owner: bool) -> Uuid {
    let mut sel = cliclack::select(prompt);
    for (i, s) in sessions.iter().enumerate() {
        sel = sel.item(s.id, format!("{:>2}. {}", i + 1, menu_label(s)), menu_hint(s, show_owner));
    }
    interact(sel.interact())
}

#[derive(Clone, PartialEq, Eq)]
pub enum NewOrTakeover {
    New,
    Takeover,
}

pub fn new_or_takeover(s: &SessionInfo) -> NewOrTakeover {
    let sel = cliclack::select(format!("Session {} is attached from another client", s.id))
        .item(NewOrTakeover::New, "create a new session", "")
        .item(NewOrTakeover::Takeover, "take over the existing session", "the other client is disconnected");
    interact({ sel }.interact())
}

#[derive(Clone, PartialEq, Eq)]
pub enum ControlAction {
    Detach,
    Remove,
}

pub fn control_action(s: &SessionInfo) -> ControlAction {
    let sel = cliclack::select(format!("What should happen to {}?", s.id))
        .item(ControlAction::Detach, "detach", "kick the attached client, keep the session")
        .item(ControlAction::Remove, "remove", "end the session and its processes");
    interact({ sel }.interact())
}

pub fn confirm(prompt: &str) -> bool {
    interact(cliclack::confirm(prompt).interact())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(id: u128, connected: bool, idle: Option<u64>, age: u64) -> SessionInfo {
        SessionInfo { id: Uuid::from_u128(id), owner: "u".into(), interactive: true, connected, age_secs: age, idle_secs: idle }
    }

    #[test]
    fn durations() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(135), "2m15s");
        assert_eq!(format_duration(3930), "1h5m30s");
        assert_eq!(format_duration(8100), "2h15m");
        assert_eq!(format_duration(3 * 86400 + 2 * 3600), "3d2h");
        assert_eq!(format_duration(0), "0s");
    }

    #[test]
    fn sorting() {
        let mut v = vec![
            s(1, true, None, 100),
            s(2, false, Some(10), 50),
            s(3, false, Some(500), 600),
            s(4, true, None, 900),
            s(6, false, Some(10), 80),
            s(5, false, Some(10), 80),
        ];
        sort_sessions(&mut v);
        let ids: Vec<u128> = v.iter().map(|s| s.id.as_u128()).collect();
        // oldest disconnect first; equal disconnect → older creation; then UUID
        assert_eq!(ids, vec![3, 5, 6, 2, 4, 1]);
    }

    #[test]
    fn list_lines() {
        let line = list_line(&s(1, false, Some(135), 200), false);
        assert!(line.ends_with("[interactive] [disconnected] 2m15s"), "{line}");
        assert!(list_line(&s(1, true, None, 5), false).ends_with("[connected]"));
        assert_eq!(sanitize("a\x1b[2Jb\u{7}"), "a[2Jb");
    }
}
