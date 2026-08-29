//! UNIX domain socket transport.
//!
//! The socket is either inherited from a systemd socket unit or bound by the
//! daemon itself. Peers are authenticated with `SO_PEERCRED`, so the identity
//! is established by the kernel and cannot be forged by the client.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::PathBuf;

use serde::Deserialize;
use tokio::net::{UnixListener, UnixStream};

use super::{Accepted, PeerIdentity, Transport};

/// Configuration keys owned by this transport.
#[derive(Debug, Deserialize)]
pub(crate) struct PlatformConfig {
    socket_path: String,
    allowed_uids: Vec<u32>,
}

/// UNIX domain socket listener with its peer allowlist.
pub(crate) struct PlatformTransport {
    listener: UnixListener,
    allowed_uids: Vec<u32>,
}

impl PlatformTransport {
    /// Prepares the listening socket.
    ///
    /// The socket is world writable because access is decided by the uid
    /// allowlist rather than by filesystem permissions.
    pub(crate) async fn bind(config: &PlatformConfig) -> io::Result<Self> {
        let socket_path = PathBuf::from(&config.socket_path);
        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let listener = if socket_activation_enabled() {
            let listener = unsafe { StdUnixListener::from_raw_fd(SOCKET_ACTIVATION_FD) };
            listener.set_nonblocking(true)?;
            UnixListener::from_std(listener)?
        } else {
            if socket_path.exists() {
                tokio::fs::remove_file(&socket_path).await?;
            }
            let listener = UnixListener::bind(&socket_path)?;
            tokio::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666))
                .await?;
            listener
        };
        Ok(Self {
            listener,
            allowed_uids: config.allowed_uids.clone(),
        })
    }
}

impl Transport for PlatformTransport {
    type Stream = UnixStream;

    async fn accept(&mut self) -> io::Result<Accepted<Self::Stream>> {
        let (stream, _) = self.listener.accept().await?;
        let Ok(uid) = peer_uid(&stream) else {
            return Ok(Accepted::Consumed);
        };
        if !self.allowed_uids.contains(&uid) {
            return Ok(Accepted::Consumed);
        }
        Ok(Accepted::Rpc {
            peer: PeerIdentity::Uid(uid),
            stream,
        })
    }
}

/// Descriptor of the socket passed by a systemd socket unit.
const SOCKET_ACTIVATION_FD: i32 = 3;

/// Reports whether systemd handed exactly one listening socket to this process.
fn socket_activation_enabled() -> bool {
    std::env::var("LISTEN_FDS").ok().as_deref() == Some("1")
        && std::env::var("LISTEN_PID").ok().as_deref() == Some(&std::process::id().to_string())
}

/// Reads the uid of the connected peer from the kernel.
fn peer_uid(stream: &UnixStream) -> Result<u32, io::Error> {
    let fd = stream.as_raw_fd();
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(credentials.uid)
}
