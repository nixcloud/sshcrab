//! Unix `SOCK_SEQPACKET` sockets with file-descriptor passing, the control
//! channel between sshcrabd and sshcrabd-p2p (spec §13.4).

use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use nix::sys::socket::{
    self, AddressFamily, Backlog, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
    sockopt,
};
use tokio::io::unix::AsyncFd;

fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: an OwnedFd stays open and keeps its descriptor until dropped.
    unsafe { AsyncFd::register(fd) }.map_err(|e| e.into_parts().1)
}

fn new_socket() -> io::Result<OwnedFd> {
    Ok(socket::socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )?)
}

pub struct SeqListener {
    fd: AsyncFd<OwnedFd>,
}

impl SeqListener {
    /// Bind at `path`, replacing a stale socket file (never another kind of file).
    pub fn bind(path: &Path) -> io::Result<SeqListener> {
        use std::os::unix::fs::FileTypeExt;
        if let Ok(m) = std::fs::symlink_metadata(path) {
            if !m.file_type().is_socket() {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} exists and is not a socket", path.display())));
            }
            std::fs::remove_file(path)?;
        }
        let fd = new_socket()?;
        socket::bind(fd.as_raw_fd(), &UnixAddr::new(path)?)?;
        socket::listen(&fd, Backlog::new(8)?)?;
        Ok(SeqListener { fd: register(fd)? })
    }

    pub async fn accept(&self) -> io::Result<SeqPacket> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|fd| {
                socket::accept4(fd.as_raw_fd(), SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK).map_err(io::Error::from)
            }) {
                // SAFETY: accept4 returned a new descriptor that nothing else owns.
                Ok(r) => return SeqPacket::from_fd(unsafe { OwnedFd::from_raw_fd(r?) }),
                Err(_would_block) => continue,
            }
        }
    }
}

pub struct SeqPacket {
    fd: AsyncFd<OwnedFd>,
}

impl SeqPacket {
    pub fn connect(path: &Path) -> io::Result<SeqPacket> {
        let fd = new_socket()?;
        // A local stream-like connect completes at once (or fails).
        socket::connect(fd.as_raw_fd(), &UnixAddr::new(path)?)?;
        SeqPacket::from_fd(fd)
    }

    fn from_fd(fd: OwnedFd) -> io::Result<SeqPacket> {
        Ok(SeqPacket { fd: register(fd)? })
    }

    /// The peer's uid, from the kernel (`SO_PEERCRED`).
    pub fn peer_uid(&self) -> io::Result<u32> {
        Ok(socket::getsockopt(self.fd.get_ref(), sockopt::PeerCredentials)?.uid())
    }

    /// One message, optionally carrying a descriptor.
    pub async fn send(&self, msg: &[u8], pass: Option<BorrowedFd<'_>>) -> io::Result<()> {
        let fds: Vec<RawFd> = pass.iter().map(|f| f.as_raw_fd()).collect();
        loop {
            let mut guard = self.fd.writable().await?;
            let res = guard.try_io(|fd| {
                let cmsg = [ControlMessage::ScmRights(&fds)];
                let cmsgs: &[ControlMessage] = if fds.is_empty() { &[] } else { &cmsg };
                socket::sendmsg::<()>(fd.as_raw_fd(), &[IoSlice::new(msg)], cmsgs, MsgFlags::MSG_NOSIGNAL, None)
                    .map_err(io::Error::from)
            });
            match res {
                Ok(r) => {
                    let n = r?;
                    if n != msg.len() {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "short seqpacket write"));
                    }
                    return Ok(());
                }
                Err(_would_block) => continue,
            }
        }
    }

    /// One message into `buf` and the descriptor it carried, if any.
    /// `Ok((0, None))` once the peer hung up.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
        loop {
            let mut guard = self.fd.readable().await?;
            let res = guard.try_io(|fd| recv_once(fd.as_fd(), buf));
            match res {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }
}

fn recv_once(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 4]);
    let mut iov = [IoSliceMut::new(buf)];
    let msg = socket::recvmsg::<()>(fd.as_raw_fd(), &mut iov, Some(&mut cmsg_buf), MsgFlags::MSG_CMSG_CLOEXEC)?;
    let mut received = Vec::new();
    for c in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = c {
            // SAFETY: the kernel just installed these descriptors for us.
            received.extend(fds.into_iter().map(|f| unsafe { OwnedFd::from_raw_fd(f) }));
        }
    }
    if msg.flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated control message"));
    }
    let n = msg.bytes;
    // At most one descriptor per message; extra ones are closed (dropped) here.
    Ok((n, received.into_iter().next()))
}

/// A connected pair of `SOCK_STREAM` sockets for one P2P peer.
pub fn stream_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    Ok(socket::socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::SOCK_CLOEXEC)?)
}

/// A received or created stream socket as a tokio stream.
pub fn into_unix_stream(fd: OwnedFd) -> io::Result<tokio::net::UnixStream> {
    let std = std::os::unix::net::UnixStream::from(fd);
    std.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(std)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn passes_a_stream_socket() {
        let dir = std::env::temp_dir().join(format!("sshcrab-seqpacket-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ctl.sock");
        let listener = SeqListener::bind(&path).unwrap();
        let client = SeqPacket::connect(&path).unwrap();
        let server = listener.accept().await.unwrap();
        assert_eq!(server.peer_uid().unwrap(), nix::unistd::Uid::effective().as_raw());

        let (mine, theirs) = stream_pair().unwrap();
        client.send(b"peer", Some(theirs.as_fd())).await.unwrap();
        drop(theirs);
        let mut buf = [0u8; 64];
        let (n, fd) = server.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"peer");
        let mut got = into_unix_stream(fd.unwrap()).unwrap();
        let mut mine = into_unix_stream(mine).unwrap();
        mine.write_all(b"hello").await.unwrap();
        let mut five = [0u8; 5];
        got.read_exact(&mut five).await.unwrap();
        assert_eq!(&five, b"hello");

        drop(client);
        assert_eq!(server.recv(&mut buf).await.unwrap().0, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
