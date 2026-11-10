//! The dialog shown while a lost connection is re-established, drawn in
//! cliclack's style. cliclack's own widgets cannot be used here: its prompts
//! read the keyboard themselves (the session's stdin reader already does) and
//! its spinner draws from another thread, outside raw mode's rules.
//!
//! ```text
//! ◆  connection to alice@example.org lost
//! │  reconnecting… (elapsed 12s, next in 4s)
//! └  Ctrl+C to leave; the session keeps running
//! ```

use std::io::{IsTerminal, Write};

const CYAN: &str = "\x1b[36m";
const RED: &str = "\x1b[31m";
const GREY: &str = "\x1b[90m";
const RESET: &str = "\x1b[0m";

pub struct Dialog {
    title: String,
    tty: bool,
    drawn: bool,
    /// Column of the cursor in the session's output, restored on close.
    col: usize,
}

impl Dialog {
    /// Nothing is shown until the first [`Dialog::update`].
    pub fn new(title: String, col: usize) -> Dialog {
        Dialog { title, tty: std::io::stderr().is_terminal(), drawn: false, col }
    }

    pub fn update(&mut self, status: &str) {
        let mut err = std::io::stderr().lock();
        if !self.tty {
            // A log, not a display: say it once.
            if !self.drawn {
                let _ = writeln!(err, "sshcrab: {}; reconnecting…", self.title);
            }
            self.drawn = true;
            return;
        }
        let lines = [
            format!("{CYAN}◆{RESET}  {}", fit(&self.title)),
            format!("{CYAN}│{RESET}  {}", fit(status)),
            format!("{CYAN}└{RESET}  {GREY}{}{RESET}", fit("Ctrl+C to leave; the session keeps running")),
        ];
        let _ = if self.drawn {
            // Back to the first line of the dialog.
            write!(err, "\x1b[{}A\r", lines.len() - 1)
        } else {
            // Below the session's output, which is left untouched.
            write!(err, "\r\n")
        };
        let _ = write!(err, "{}", lines.map(|l| format!("\x1b[K{l}")).join("\r\n"));
        let _ = err.flush();
        self.drawn = true;
    }

    /// Remove the dialog and put the cursor back where the output left it.
    pub fn close(self) {
        if !self.drawn {
            return;
        }
        let mut err = std::io::stderr().lock();
        if !self.tty {
            let _ = writeln!(err, "sshcrab: reconnected");
            return;
        }
        let _ = write!(err, "\x1b[2A\r\x1b[J\x1b[1A");
        if self.col > 0 {
            let _ = write!(err, "\x1b[{}C", self.col);
        }
        let _ = err.flush();
    }

    /// Leave the dialog in cliclack's cancelled state, ending in a new line.
    pub fn cancel(mut self, status: &str, last: &str) {
        let mut err = std::io::stderr().lock();
        if !self.tty {
            let _ = writeln!(err, "sshcrab: {status}; {last}");
            return;
        }
        if !self.drawn {
            self.update("");
        }
        let _ = write!(
            err,
            "\x1b[2A\r\x1b[J{RED}■{RESET}  {GREY}{}{RESET}\r\n{GREY}│{RESET}  {}\r\n{GREY}└{RESET}  {last}\r\n",
            fit(&self.title),
            fit(status),
        );
        let _ = err.flush();
    }
}

/// Cut `text` to the terminal width (minus the frame), so no line wraps and
/// the relative cursor moves stay right.
fn fit(text: &str) -> String {
    let cols = crate::term::window_size().map_or(80, |(c, _)| c as usize);
    let max = cols.saturating_sub(4).max(10);
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut s: String = text.chars().take(max - 1).collect();
    s.push('…');
    s
}
