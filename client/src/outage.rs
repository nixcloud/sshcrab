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
//!
//! With a model of the session's screen (interactive sessions), the screen is
//! shown in grey behind the dialog, so it is clear at a glance that nothing
//! there is live. For a shell that happens on the alternate screen, which the
//! terminal itself swaps back on reconnect, so the real screen is never touched
//! and a wrong model could only spoil the grey copy. A full-screen program
//! already uses the alternate screen; there the copy is drawn over it, and on
//! reconnect the model's contents are put back (the program also repaints).

use std::io::{IsTerminal, Write};

const CYAN: &str = "\x1b[36m";
const RED: &str = "\x1b[31m";
const GREY: &str = "\x1b[90m";
/// The screen behind the dialog: barely visible.
const BACKDROP: &str = "\x1b[0;38;5;240m";
const RESET: &str = "\x1b[0m";
const HINT: &str = "Ctrl+C to leave; the session keeps running";

pub struct Dialog {
    title: String,
    tty: bool,
    drawn: bool,
    /// Column of the cursor in the session's output, restored on close.
    col: usize,
    backdrop: Option<vt100::Screen>,
    /// 1-based row of the dialog's first line on the backdrop.
    top: u16,
    status: String,
}

impl Dialog {
    /// Nothing is shown until the first [`Dialog::update`]. With `screen`, the
    /// session's screen is shown in grey behind the dialog.
    pub fn new(title: String, col: usize, screen: Option<vt100::Screen>) -> Dialog {
        let tty = std::io::stderr().is_terminal();
        let backdrop = screen.filter(|_| tty);
        Dialog { title, tty, drawn: false, col, backdrop, top: 0, status: String::new() }
    }

    pub fn update(&mut self, status: &str) {
        self.status = status.to_string();
        let mut err = std::io::stderr().lock();
        if !self.tty {
            // A log, not a display: say it once.
            if !self.drawn {
                let _ = writeln!(err, "sshcrab: {}; reconnecting…", self.title);
            }
            self.drawn = true;
            return;
        }
        let lines = self.lines();
        let out = if self.backdrop.is_some() {
            let mut out = if self.drawn { String::new() } else { self.paint_backdrop() };
            for (i, l) in lines.iter().enumerate() {
                out.push_str(&format!("\x1b[{};1H\x1b[K{l}", self.top + i as u16));
            }
            out
        } else {
            let mut out = if self.drawn {
                // Back to the first line of the dialog.
                format!("\x1b[{}A\r", lines.len() - 1)
            } else {
                // Below the session's output, which is left untouched.
                "\r\n".to_string()
            };
            out.push_str(&lines.map(|l| format!("\x1b[K{l}")).join("\r\n"));
            out
        };
        let _ = err.write_all(out.as_bytes());
        let _ = err.flush();
        self.drawn = true;
    }

    pub fn set_title(&mut self, title: String) {
        self.title = title;
    }

    /// The window changed size: draw everything again for the new size.
    pub fn resize(&mut self, screen: Option<vt100::Screen>) {
        if self.backdrop.is_some() && self.drawn {
            self.backdrop = screen;
            if self.backdrop.is_some() {
                let mut err = std::io::stderr().lock();
                let _ = err.write_all(self.paint_backdrop().as_bytes());
                let _ = err.flush();
                let status = std::mem::take(&mut self.status);
                self.update(&status);
            }
        }
    }

    fn lines(&self) -> [String; 3] {
        [
            format!("{CYAN}◆{RESET}  {}", fit(&self.title)),
            format!("{CYAN}│{RESET}  {}", fit(&self.status)),
            format!("{CYAN}└{RESET}  {GREY}{}{RESET}", fit(HINT)),
        ]
    }

    /// The grey copy of the screen, and where the dialog goes: below the last
    /// line written (the copy scrolled up if needed), or at the bottom over a
    /// full-screen program.
    fn paint_backdrop(&mut self) -> String {
        let Some(screen) = &self.backdrop else { return String::new() };
        let (rows, cols) = screen.size();
        let (rows, cols) = (rows.get(), cols.get());
        let (cursor_row, _) = screen.cursor_position();
        let full_screen = screen.alternate_screen();
        // Dialog: one blank line below the cursor's line, 3 lines high.
        let want = if full_screen { rows.saturating_sub(2) } else { cursor_row + 3 };
        let top = want.min(rows.saturating_sub(2)).max(1);
        let shift = want - top;
        let mut out = String::new();
        if !full_screen {
            out.push_str("\x1b[?1049h");
        }
        out.push_str("\x1b[?25l\x1b[0m\x1b[H\x1b[2J");
        out.push_str(BACKDROP);
        for (i, row) in screen.rows(0, cols).skip(shift as usize).enumerate() {
            if !row.trim_end().is_empty() {
                out.push_str(&format!("\x1b[{};1H{}", i + 1, row.trim_end()));
            }
        }
        out.push_str(RESET);
        self.top = top;
        out
    }

    /// Leave the backdrop: the real screen comes back.
    fn leave_backdrop(&self, restore_full_screen: bool) -> String {
        let Some(screen) = &self.backdrop else { return String::new() };
        let mut out = String::new();
        if !screen.alternate_screen() {
            out.push_str("\x1b[?1049l");
        } else if restore_full_screen {
            out.push_str("\x1b[0m\x1b[H\x1b[2J");
            out.push_str(&screen.contents_formatted());
        }
        if !screen.hide_cursor() {
            out.push_str("\x1b[?25h");
        }
        out
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
        if self.backdrop.is_some() {
            let _ = err.write_all(self.leave_backdrop(true).as_bytes());
        } else {
            let _ = write!(err, "\x1b[2A\r\x1b[J\x1b[1A");
            if self.col > 0 {
                let _ = write!(err, "\x1b[{}C", self.col);
            }
        }
        let _ = err.flush();
    }

    /// Leave the dialog in cliclack's cancelled state, below the session's
    /// output, ending in a new line. A full-screen program's screen is already
    /// gone (the caller left the session's terminal modes).
    pub fn cancel(mut self, status: &str, last: &str) {
        let mut err = std::io::stderr().lock();
        if !self.tty {
            let _ = writeln!(err, "sshcrab: {status}; {last}");
            return;
        }
        let mut out = String::new();
        if self.backdrop.is_some() && self.drawn {
            out.push_str(&self.leave_backdrop(false));
            out.push_str("\r\n");
        } else if self.drawn {
            out.push_str("\x1b[2A\r\x1b[J");
        } else {
            out.push_str("\r\n");
        }
        self.drawn = false;
        out.push_str(&format!(
            "{RED}■{RESET}  {GREY}{}{RESET}\r\n{GREY}│{RESET}  {}\r\n{GREY}└{RESET}  {last}\r\n",
            fit(&self.title),
            fit(status),
        ));
        let _ = err.write_all(out.as_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn screen(rows: u16, output: &[u8]) -> vt100::Screen {
        let mut p = vt100::Parser::new(rows.try_into().unwrap(), 40.try_into().unwrap(), 0);
        p.process(output);
        p.screen().clone()
    }

    fn dialog(s: vt100::Screen) -> Dialog {
        Dialog { title: "t".into(), tty: true, drawn: false, col: 0, backdrop: Some(s), top: 0, status: String::new() }
    }

    #[test]
    fn shell_goes_grey_on_the_alternate_screen_with_the_dialog_below_it() {
        let mut d = dialog(screen(10, b"\x1b[1;32mone\x1b[0m\r\ntwo\r\n$ "));
        let out = d.paint_backdrop();
        assert!(out.starts_with("\x1b[?1049h"), "the real screen stays untouched");
        assert!(out.contains(&format!("{BACKDROP}\x1b[1;1Hone\x1b[2;1Htwo\x1b[3;1H$")), "{out:?}");
        assert!(!out.contains("32m"), "no colours of its own");
        assert_eq!(d.top, 5, "a blank line below the prompt");
        assert_eq!(d.leave_backdrop(true), "\x1b[?1049l\x1b[?25h");
    }

    #[test]
    fn a_full_screen_shell_scrolls_up_to_make_room() {
        let lines: Vec<String> = (1..=10).map(|i| format!("line {i}")).collect();
        let mut d = dialog(screen(10, lines.join("\r\n").as_bytes()));
        let out = d.paint_backdrop();
        assert_eq!(d.top, 8);
        assert!(out.contains("\x1b[1;1Hline 5\x1b[2;1H"), "4 lines scrolled away: {out:?}");
    }

    #[test]
    fn a_full_screen_program_keeps_its_layout_and_is_put_back() {
        let mut d = dialog(screen(10, b"\x1b[?1049h\x1b[Htop line\x1b[10;1H:"));
        let out = d.paint_backdrop();
        assert!(!out.contains("1049h"), "already on the alternate screen");
        assert!(out.contains("\x1b[1;1Htop line") && out.contains("\x1b[10;1H:"), "{out:?}");
        assert_eq!(d.top, 8, "at the bottom");
        let back = d.leave_backdrop(true);
        assert!(!back.contains("1049l") && back.contains("top line"), "{back:?}");
    }
}
