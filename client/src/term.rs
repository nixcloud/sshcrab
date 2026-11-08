//! Local terminal: raw mode and window size.

use std::io::IsTerminal;
use std::os::fd::AsFd;
use std::sync::Mutex;

use nix::sys::termios::{self, SetArg, Termios};

/// Settings to restore; global so every exit path (including `process::exit`) can.
static SAVED: Mutex<Option<Termios>> = Mutex::new(None);

/// Raw mode on stdin, if it is a terminal.
pub fn enable_raw() -> bool {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return false;
    }
    let Ok(saved) = termios::tcgetattr(stdin.as_fd()) else { return false };
    let mut raw = saved.clone();
    termios::cfmakeraw(&mut raw);
    if termios::tcsetattr(stdin.as_fd(), SetArg::TCSANOW, &raw).is_err() {
        return false;
    }
    *SAVED.lock().unwrap() = Some(saved);
    true
}

/// Leave raw mode (no-op if not in it).
pub fn restore() {
    if let Some(saved) = SAVED.lock().unwrap().take() {
        let _ = termios::tcsetattr(std::io::stdin().as_fd(), SetArg::TCSANOW, &saved);
    }
}

/// (cols, rows) of the controlling terminal.
pub fn window_size() -> Option<(u16, u16)> {
    let mut ws = libc::winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCGWINSZ with a valid winsize pointer.
    let r = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    (r == 0 && ws.ws_col > 0).then_some((ws.ws_col, ws.ws_row))
}
