//! Platform boundary of the daemon.
//!
//! Everything that depends on how a client reaches the daemon lives behind
//! [`Transport`]: the listener, the authentication of the peer, and the
//! authenticated peer identity. The RPC layer above sees only an
//! authenticated peer and a byte stream, so it is identical on every platform.
//!
//! Exactly one implementation is compiled per target. The UNIX build listens
//! on a UNIX domain socket and authenticates with `SO_PEERCRED`; the Windows
//! build listens on a named pipe and on a loopback TCP socket.

mod tcp;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use std::future::Future;
use std::io;

use serde::ser::SerializeMap;
use serde::{Deserialize, Serializer};
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) use tcp::{CdpPortResolver, PeerAuthenticator, TcpTransport};

#[cfg(unix)]
pub(crate) use unix::{PlatformConfig, PlatformTransport};
#[cfg(windows)]
pub(crate) use windows::{PlatformConfig, PlatformTransport, pipe_path};

/// Listener that hands authenticated client connections to the RPC layer.
pub(crate) trait Transport {
    /// Bidirectional stream of an accepted client.
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    /// Waits for the next client and authenticates it.
    ///
    /// Authentication belongs to the implementation: a client that fails it is
    /// refused inside `accept` and reported as [`Accepted::Consumed`], never as
    /// a stream. An error is returned only when the listener itself fails, in
    /// which case the daemon stops.
    fn accept(&mut self) -> impl Future<Output = io::Result<Accepted<Self::Stream>>> + Send;
}

/// Outcome of a single accept.
pub(crate) enum Accepted<S> {
    /// Authenticated client that speaks the JSON-RPC protocol.
    Rpc {
        peer: PeerIdentity,
        stream: S,
        operator_uids: Vec<u32>,
    },
    /// The connection was handled inside the transport and has no RPC surface,
    /// either because the peer was refused or because the connection was taken
    /// over for another purpose, such as a tunnel.
    Consumed,
}

/// Identity of an authenticated peer, as established by the transport.
#[allow(dead_code)]
pub(crate) enum PeerIdentity {
    /// Peer credentials of a UNIX domain socket client.
    Uid(u32),
    /// Named pipe client, identified by the SID of its access token. The
    /// elevation flag gates the administrative RPC surface.
    Sid {
        sid: String,
        elevated: bool,
        administrator: bool,
        normal_allowed: bool,
    },
    /// TCP client that presented a valid preamble token.
    Peer { peer_id: String, label: String },
    /// リース失効など、デーモンが起点となる活動を表す身元です。
    System,
}

impl PeerIdentity {
    #[allow(dead_code)]
    pub(crate) fn allows_normal_rpc(&self) -> bool {
        match self {
            Self::Uid(_) => true,
            Self::Sid { normal_allowed, .. } => *normal_allowed,
            Self::Peer { .. } => true,
            Self::System => false,
        }
    }

    pub(crate) fn allows_admin_rpc(&self, operator_uids: &[u32]) -> bool {
        match self {
            Self::Uid(uid) => *uid == 0 || operator_uids.contains(uid),
            Self::Sid {
                elevated,
                administrator,
                ..
            } => *elevated && *administrator,
            Self::Peer { .. } => false,
            Self::System => false,
        }
    }

    pub(crate) fn principal(&self) -> String {
        match self {
            Self::Uid(uid) => format!("uid:{uid}"),
            Self::Sid { sid, .. } => format!("sid:{sid}"),
            Self::Peer { peer_id, .. } => format!("peer:{peer_id}"),
            Self::System => "system".to_owned(),
        }
    }
}

/// Writes the peer as the audit log field of its platform. The map is
/// flattened into the audit record.
impl serde::Serialize for PeerIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(5))?;
        match self {
            Self::Uid(uid) => map.serialize_entry("peer_uid", uid)?,
            Self::Sid {
                sid,
                elevated,
                administrator,
                ..
            } => {
                map.serialize_entry("peer_sid", sid)?;
                map.serialize_entry("elevated", elevated)?;
                map.serialize_entry("administrator", administrator)?;
            }
            Self::Peer { peer_id, label } => {
                map.serialize_entry("peer_token", &true)?;
                map.serialize_entry("peer_id", peer_id)?;
                map.serialize_entry("peer_label", label)?;
            }
            Self::System => {
                map.serialize_entry("peer_system", &true)?;
            }
        }
        map.serialize_entry("principal", &self.principal())?;
        map.end()
    }
}

pub(crate) trait ClientStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> ClientStream for T {}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub(crate) enum ListenConfig {
    Unix {
        path: String,
        allowed_uids: Vec<u32>,
        #[serde(default)]
        operator_uids: Vec<u32>,
    },
    Tcp {
        bind: String,
        port: u16,
    },
    Pipe {
        name: String,
        allowed_sids: Vec<String>,
        #[serde(default)]
        operator_sid: Option<String>,
    },
}
