//! Terminal modes a full-screen program switches on once, at startup (spec §4.3).
//!
//! A client that attaches later never saw those sequences, so the server tracks
//! them in the session's output and hands the client [`Modes::restore`]; a client
//! leaving the session puts its own terminal back with [`Modes::reset`].

/// DEC private modes (`CSI ? n h` / `CSI ? n l`) worth carrying over.
/// Order matters for restoring: the alternate screen first.
const TRACKED: &[u16] = &[
    1049, 1047, 47, // alternate screen
    1,    // application cursor keys
    25,   // cursor visible (on by default)
    1000, 1002, 1003, 1005, 1006, 1015, // mouse reporting and encodings
    1004, // focus events
    2004, // bracketed paste
];
const DEFAULT_ON: u16 = 25;
const MAX_PARAMS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    Esc,
    /// After `ESC [`, before the first parameter byte.
    CsiStart,
    /// Inside `ESC [ ?` parameters.
    Private,
    /// Some other control sequence: skip to its final byte.
    Skip,
}

#[derive(Debug, Clone)]
pub struct Modes {
    /// Bit i: `TRACKED[i]` differs from its default.
    changed: u16,
    state: State,
    params: Vec<u16>,
    cur: Option<u16>,
}

impl Default for Modes {
    fn default() -> Self {
        Modes { changed: 0, state: State::Ground, params: Vec::new(), cur: None }
    }
}

impl Modes {
    /// Follow the mode changes in a piece of terminal output.
    pub fn feed(&mut self, data: &[u8]) {
        for &b in data {
            self.state = match (self.state, b) {
                (_, 0x1b) => State::Esc,
                (State::Ground, _) => State::Ground,
                (State::Esc, b'[') => State::CsiStart,
                (State::Esc, _) => State::Ground,
                (State::CsiStart, b'?') => {
                    self.params.clear();
                    self.cur = None;
                    State::Private
                }
                (State::CsiStart | State::Skip, 0x40..=0x7e) => State::Ground,
                (State::CsiStart | State::Skip, _) => State::Skip,
                (State::Private, b'0'..=b'9') => {
                    let d = (b - b'0') as u16;
                    self.cur = Some(self.cur.unwrap_or(0).saturating_mul(10).saturating_add(d));
                    State::Private
                }
                (State::Private, b';') => {
                    self.push_param();
                    State::Private
                }
                (State::Private, b'h' | b'l') => {
                    self.push_param();
                    let on = b == b'h';
                    for i in 0..self.params.len() {
                        self.set(self.params[i], on);
                    }
                    State::Ground
                }
                (State::Private, 0x40..=0x7e) => State::Ground,
                (State::Private, _) => State::Skip,
            };
        }
    }

    fn push_param(&mut self) {
        if let Some(p) = self.cur.take() {
            if self.params.len() < MAX_PARAMS {
                self.params.push(p);
            }
        }
    }

    fn set(&mut self, mode: u16, on: bool) {
        if let Some(i) = TRACKED.iter().position(|&m| m == mode) {
            let changed = on != (mode == DEFAULT_ON);
            if changed {
                self.changed |= 1 << i;
            } else {
                self.changed &= !(1 << i);
            }
        }
    }

    fn sequence(&self, invert: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let order: Vec<usize> = if invert { (0..TRACKED.len()).rev().collect() } else { (0..TRACKED.len()).collect() };
        for i in order {
            if self.changed & (1 << i) != 0 {
                let mode = TRACKED[i];
                let on = (mode != DEFAULT_ON) != invert;
                out.extend_from_slice(format!("\x1b[?{mode}{}", if on { 'h' } else { 'l' }).as_bytes());
            }
        }
        out
    }

    /// Whether a program is using the alternate screen (a full-screen program).
    pub fn alt_screen(&self) -> bool {
        self.changed & 0b111 != 0
    }

    /// Puts a fresh terminal into the current modes.
    pub fn restore(&self) -> Vec<u8> {
        self.sequence(false)
    }

    /// Puts a terminal in the current modes back to the defaults.
    pub fn reset(&self) -> Vec<u8> {
        self.sequence(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_full_screen_program() {
        let mut m = Modes::default();
        // htop-like startup, split across chunks, with unrelated sequences around it.
        m.feed(b"hi \x1b[1mbold\x1b[0m \x1b[?10");
        m.feed(b"49h\x1b[22;0;0t\x1b[?1h\x1b=\x1b[?25l\x1b[?1000;1006h\x1b[H\x1b[2J");
        assert!(m.alt_screen());
        assert_eq!(m.restore(), b"\x1b[?1049h\x1b[?1h\x1b[?25l\x1b[?1000h\x1b[?1006h");
        assert_eq!(m.reset(), b"\x1b[?1006l\x1b[?1000l\x1b[?25h\x1b[?1l\x1b[?1049l");
        // ... and its exit.
        m.feed(b"\x1b[?1000;1006l\x1b[?25h\x1b[?1l\x1b[?1049l$ ");
        assert!(!m.alt_screen());
        assert!(m.restore().is_empty());
    }

    #[test]
    fn ignores_other_sequences() {
        let mut m = Modes::default();
        m.feed(b"\x1b[1049h\x1b[>4;1m\x1b]0;title\x07\x1b[?2004h");
        assert_eq!(m.restore(), b"\x1b[?2004h");
    }
}
