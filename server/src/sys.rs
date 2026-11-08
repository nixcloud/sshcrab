//! The daemon's only unsafe code: process spawning, PTYs, privilege drop (spec §7.6).

use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::process::Stdio;

use tokio::io::unix::AsyncFd;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

use crate::auth::Account;

pub struct Spawn<'a> {
    pub account: &'a Account,
    /// `None` = interactive login shell on a PTY.
    pub command: Option<&'a str>,
    pub env: Vec<(String, String)>,
    pub window: Option<(u16, u16)>,
}

pub enum ChildIo {
    Pty(PtyMaster),
    Pipes { stdin: ChildStdin, stdout: ChildStdout, stderr: ChildStderr },
}

pub fn spawn(spec: Spawn<'_>) -> io::Result<(Child, ChildIo)> {
    let acc = spec.account;
    let privileged = nix::unistd::Uid::effective().is_root();

    let mut cmd = Command::new(&acc.shell);
    match spec.command {
        Some(c) => {
            cmd.arg("-c").arg(c);
        }
        None => {
            // Login shell: argv[0] = "-bash" like login(1) and sshd.
            let base = acc.shell.file_name().map(|n| n.to_os_string()).unwrap_or_else(|| OsString::from("sh"));
            let mut arg0 = OsString::from("-");
            arg0.push(base);
            cmd.arg0(arg0);
        }
    }
    cmd.env_clear().envs(spec.env).kill_on_drop(false);

    let pty = if spec.command.is_none() {
        let pty = nix::pty::openpty(None, None).map_err(io::Error::from)?;
        set_cloexec(&pty.master)?;
        if let Some((cols, rows)) = spec.window {
            set_winsize(pty.master.as_raw_fd(), cols, rows)?;
        }
        if privileged {
            let tty_gid = nix::unistd::Group::from_name("tty").ok().flatten().map(|g| g.gid.as_raw());
            // SAFETY: plain syscalls on a valid fd.
            unsafe {
                if libc::fchown(pty.slave.as_raw_fd(), acc.uid, tty_gid.unwrap_or(acc.gid)) != 0
                    || libc::fchmod(pty.slave.as_raw_fd(), 0o620) != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        cmd.stdin(Stdio::from(pty.slave.try_clone()?))
            .stdout(Stdio::from(pty.slave.try_clone()?))
            .stderr(Stdio::from(pty.slave));
        Some(pty.master)
    } else {
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        None
    };

    // Everything the child needs is prepared here: after fork only
    // async-signal-safe calls are allowed (no NSS, no allocation).
    let groups: Vec<libc::gid_t> = acc.groups.clone();
    let (uid, gid) = (acc.uid, acc.gid);
    let home = CString::new(acc.home.as_os_str().as_bytes()).unwrap_or_else(|_| c"/".into());
    let loginuid = uid.to_string();
    let is_pty = pty.is_some();
    // SAFETY: the closure only performs async-signal-safe syscalls on data
    // allocated before the fork.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if is_pty && libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if privileged {
                // Audit trail; best effort (needs CAP_AUDIT_CONTROL).
                let fd = libc::open(c"/proc/self/loginuid".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                if fd >= 0 {
                    libc::write(fd, loginuid.as_ptr().cast(), loginuid.len());
                    libc::close(fd);
                }
                if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if uid != 0 && libc::setuid(0) == 0 {
                    return Err(io::Error::other("privileges could be regained"));
                }
            }
            if libc::chdir(home.as_ptr()) != 0 {
                libc::chdir(c"/".as_ptr());
            }
            // Mark every inherited descriptor close-on-exec (CLOSE_RANGE_CLOEXEC);
            // closing outright would break std's exec error pipe.
            libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32);
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            Ok(())
        });
    }

    let mut child = cmd.spawn()?;
    let io = match pty {
        Some(master) => ChildIo::Pty(PtyMaster::new(master)?),
        None => ChildIo::Pipes {
            stdin: child.stdin.take().expect("piped"),
            stdout: child.stdout.take().expect("piped"),
            stderr: child.stderr.take().expect("piped"),
        },
    };
    Ok((child, io))
}

fn set_cloexec(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: fcntl on a valid fd.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_winsize(fd: i32, cols: u16, rows: u16) -> io::Result<()> {
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCSWINSZ with a valid winsize pointer.
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Send `sig` to the session's process group.
pub fn kill_group(pid: u32, sig: i32) {
    // SAFETY: plain syscall.
    unsafe {
        libc::killpg(pid as libc::pid_t, sig);
    }
}

pub struct PtyMaster {
    fd: AsyncFd<OwnedFd>,
}

impl PtyMaster {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        // SAFETY: fcntl on a valid fd.
        unsafe {
            let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        // SAFETY: an OwnedFd stays open and keeps its descriptor until dropped.
        let fd = unsafe { AsyncFd::register(fd) }.map_err(|e| e.into_parts().1)?;
        Ok(PtyMaster { fd })
    }

    /// `Ok(0)` once the slave side is gone (EIO).
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|fd| nix::unistd::read(fd.get_ref(), buf).map_err(io::Error::from)) {
                Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => return Ok(0),
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write_all(&self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|fd| nix::unistd::write(fd.get_ref(), data).map_err(io::Error::from)) {
                Ok(Ok(n)) => data = &data[n..],
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
        Ok(())
    }

    pub fn set_size(&self, cols: u16, rows: u16) {
        let _ = set_winsize(self.fd.get_ref().as_raw_fd(), cols, rows);
    }
}
