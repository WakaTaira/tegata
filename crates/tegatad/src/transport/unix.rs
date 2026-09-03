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
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;
use tokio::net::{UnixListener, UnixStream};

use super::{
    Accepted, CdpPortResolver, ClientStream, ListenConfig, PeerAuthenticator, PeerIdentity,
    TcpTransport, Transport,
};

/// Configuration keys owned by this transport.
#[derive(Debug, Deserialize)]
pub(crate) struct PlatformConfig {
    #[serde(default)]
    pub(crate) socket_path: Option<String>,
    #[serde(default)]
    pub(crate) allowed_uids: Option<Vec<u32>>,
}

/// UNIX domain socket and TCP listeners.
pub(crate) struct PlatformTransport {
    receiver: tokio::sync::mpsc::Receiver<io::Result<Accepted<Box<dyn ClientStream>>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

struct UnixTransport {
    listener: UnixListener,
    allowed_uids: Vec<u32>,
    operator_uids: Vec<u32>,
}

impl UnixTransport {
    /// Prepares the listening socket.
    ///
    /// The socket is world writable because access is decided by the uid
    /// allowlist rather than by filesystem permissions.
    async fn bind(path: &str, allowed_uids: &[u32], operator_uids: &[u32]) -> io::Result<Self> {
        let socket_path = PathBuf::from(path);
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
            allowed_uids: allowed_uids.to_owned(),
            operator_uids: operator_uids.to_owned(),
        })
    }
}

impl UnixTransport {
    async fn accept(&self) -> io::Result<Accepted<UnixStream>> {
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
            operator_uids: self.operator_uids.clone(),
        })
    }
}

impl PlatformTransport {
    pub(crate) async fn bind(
        listeners: &[ListenConfig],
        token_hash_path: &std::path::Path,
        cdp_port_resolver: CdpPortResolver,
        peer_authenticator: PeerAuthenticator,
        pending_connections: Arc<AtomicUsize>,
        max_pending_connections: usize,
    ) -> io::Result<Self> {
        let (sender, receiver) = tokio::sync::mpsc::channel(listeners.len().max(1) * 16);
        let mut tasks = Vec::new();
        for listener in listeners {
            match listener {
                ListenConfig::Unix {
                    path,
                    allowed_uids,
                    operator_uids,
                } => {
                    let unix = UnixTransport::bind(path, allowed_uids, operator_uids).await?;
                    let sender = sender.clone();
                    tasks.push(tokio::spawn(async move {
                        loop {
                            let accepted = unix.accept().await.map(|accepted| match accepted {
                                Accepted::Rpc {
                                    peer,
                                    stream,
                                    operator_uids,
                                } => Accepted::Rpc {
                                    peer,
                                    stream: Box::new(stream) as Box<dyn ClientStream>,
                                    operator_uids,
                                },
                                Accepted::Consumed => Accepted::Consumed,
                            });
                            if sender.send(accepted).await.is_err() {
                                return;
                            }
                        }
                    }));
                }
                ListenConfig::Tcp { bind, port } => {
                    let address = resolve_tcp_bind(bind, *port)?;
                    let mut tcp = TcpTransport::bind(
                        address,
                        token_hash_path,
                        cdp_port_resolver.clone(),
                        peer_authenticator.clone(),
                        pending_connections.clone(),
                        max_pending_connections,
                    )
                    .await?;
                    let sender = sender.clone();
                    tasks.push(tokio::spawn(async move {
                        loop {
                            let accepted = tcp.accept().await.map(|accepted| match accepted {
                                Accepted::Rpc {
                                    peer,
                                    stream,
                                    operator_uids,
                                } => Accepted::Rpc {
                                    peer,
                                    stream: Box::new(stream) as Box<dyn ClientStream>,
                                    operator_uids,
                                },
                                Accepted::Consumed => Accepted::Consumed,
                            });
                            if sender.send(accepted).await.is_err() {
                                return;
                            }
                        }
                    }));
                }
                ListenConfig::Pipe { .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "pipe listeners are only supported on Windows",
                    ));
                }
            }
        }
        drop(sender);
        Ok(Self { receiver, tasks })
    }
}

impl Transport for PlatformTransport {
    type Stream = Box<dyn ClientStream>;

    async fn accept(&mut self) -> io::Result<Accepted<Self::Stream>> {
        self.receiver.recv().await.unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "listener accept loop stopped",
            ))
        })
    }
}

impl Drop for PlatformTransport {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn resolve_tcp_bind(bind: &str, port: u16) -> io::Result<std::net::SocketAddr> {
    let address = bind.parse::<std::net::IpAddr>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "tcp bind must be an explicit IP address",
        )
    })?;
    if address.is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tcp bind must not be an unspecified address",
        ));
    }
    Ok(std::net::SocketAddr::new(address, port))
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
