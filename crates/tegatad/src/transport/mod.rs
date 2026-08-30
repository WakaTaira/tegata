//! Platform boundary of the daemon.
//!
//! Everything that depends on how a client reaches the daemon lives behind
//! [`Transport`]: the listener, the authentication of the peer, and the
//! identity that the audit log records. The RPC layer above sees only an
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

use serde::Serializer;
use serde::ser::SerializeMap;
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(windows)]
pub(crate) use tcp::{Accepted as TcpAccepted, CdpPortResolver, TcpTransport};

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
    Rpc { peer: PeerIdentity, stream: S },
    /// The connection was handled inside the transport and has no RPC surface,
    /// either because the peer was refused or because the connection was taken
    /// over for another purpose, such as a tunnel.
    Consumed,
}

/// Identity of an authenticated peer, as established by the transport.
#[cfg(unix)]
pub(crate) enum PeerIdentity {
    /// Peer credentials of a UNIX domain socket client.
    Uid(u32),
    /// An audit event emitted by the daemon itself.
    System,
}

/// Identity of an authenticated peer, as established by the transport.
///
/// The Windows transport establishes both the ordinary-RPC and administrative
/// permissions before handing the stream to the RPC layer.
#[cfg(windows)]
pub(crate) enum PeerIdentity {
    /// Named pipe client, identified by the SID of its access token. The
    /// elevation flag gates the administrative RPC surface.
    Sid {
        sid: String,
        elevated: bool,
        administrator: bool,
        normal_allowed: bool,
    },
    /// Loopback TCP client that presented a valid preamble token. Such a peer
    /// carries no operating system identity.
    Token,
    /// An audit event emitted by the daemon itself.
    System,
}

#[cfg(windows)]
impl PeerIdentity {
    pub(crate) fn allows_normal_rpc(&self) -> bool {
        match self {
            Self::Sid { normal_allowed, .. } => *normal_allowed,
            Self::Token => true,
            Self::System => false,
        }
    }

    pub(crate) fn allows_admin_rpc(&self) -> bool {
        match self {
            Self::Sid {
                elevated,
                administrator,
                ..
            } => *elevated && *administrator,
            Self::Token => false,
            Self::System => false,
        }
    }
}

/// Writes the peer as the audit log field of its platform. The map is
/// flattened into the audit record.
impl serde::Serialize for PeerIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        match self {
            #[cfg(unix)]
            Self::Uid(uid) => map.serialize_entry("peer_uid", uid)?,
            #[cfg(unix)]
            Self::System => map.serialize_entry("peer_system", &true)?,
            #[cfg(windows)]
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
            #[cfg(windows)]
            Self::Token => map.serialize_entry("peer_token", &true)?,
            #[cfg(windows)]
            Self::System => map.serialize_entry("peer_system", &true)?,
        }
        map.end()
    }
}
