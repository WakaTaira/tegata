//! Token-authenticated TCP transport shared by the platform implementations.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tegata_core::wire::{PREAMBLE_VERSION, Preamble, PreambleError, PreambleResponse};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

const MAX_PREAMBLE_BYTES: usize = 4 * 1024;
const PREAMBLE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REFUSAL_DRAIN_BYTES: usize = 64 * 1024;
const REFUSAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) type CdpPortResolver =
    Arc<dyn Fn(&str, &super::PeerIdentity) -> Option<u16> + Send + Sync>;
pub(crate) type PeerAuthenticator =
    Arc<dyn Fn(&str, &[u8; 32]) -> Option<super::PeerIdentity> + Send + Sync>;

pub(crate) struct TcpTransport {
    listener: TcpListener,
    cdp_port_resolver: CdpPortResolver,
    peer_authenticator: PeerAuthenticator,
    pending_connections: Arc<AtomicUsize>,
    max_pending_connections: usize,
    accepted_sender: mpsc::Sender<io::Result<super::Accepted<TcpStream>>>,
    accepted: mpsc::Receiver<io::Result<super::Accepted<TcpStream>>>,
}

impl TcpTransport {
    pub(crate) async fn bind(
        address: SocketAddr,
        _token_hash_path: &Path,
        cdp_port_resolver: CdpPortResolver,
        peer_authenticator: PeerAuthenticator,
        pending_connections: Arc<AtomicUsize>,
        max_pending_connections: usize,
    ) -> io::Result<Self> {
        let listener = bind_tcp_listener(address).await?;
        let (accepted_sender, accepted) = mpsc::channel(max_pending_connections.max(1));
        Ok(Self {
            listener,
            cdp_port_resolver,
            peer_authenticator,
            pending_connections,
            max_pending_connections,
            accepted_sender,
            accepted,
        })
    }

    #[cfg(test)]
    async fn bind_for_test(token: &str, cdp_port_resolver: CdpPortResolver) -> io::Result<Self> {
        let token = token.to_owned();
        let peer_authenticator: PeerAuthenticator = Arc::new(move |candidate, _| {
            (candidate == token.as_str()).then(|| super::PeerIdentity::Peer {
                peer_id: "test".to_owned(),
                label: "test".to_owned(),
            })
        });
        Self::bind(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            Path::new("test-token-hash"),
            cdp_port_resolver,
            peer_authenticator,
            Arc::new(AtomicUsize::new(0)),
            8,
        )
        .await
    }

    #[cfg(test)]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub(crate) async fn accept(&mut self) -> io::Result<super::Accepted<TcpStream>> {
        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    let (stream, _) = result?;
                    if !reserve_pending_connection(
                        &self.pending_connections,
                        self.max_pending_connections,
                    ) {
                        let mut stream = stream;
                        let _ = stream.shutdown().await;
                        continue;
                    }
                    let cdp_port_resolver = self.cdp_port_resolver.clone();
                    let peer_authenticator = self.peer_authenticator.clone();
                    let pending_connections = self.pending_connections.clone();
                    let sender = self.accepted_sender.clone();
                    tokio::spawn(async move {
                        let accepted = handle_connection(
                            stream,
                            &cdp_port_resolver,
                            &peer_authenticator,
                            &pending_connections,
                        )
                        .await;
                        let _ = sender.send(accepted).await;
                    });
                }
                accepted = self.accepted.recv() => {
                    return accepted.unwrap_or_else(|| Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "TCP accept queue stopped",
                    )));
                }
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    cdp_port_resolver: &CdpPortResolver,
    peer_authenticator: &PeerAuthenticator,
    pending_connections: &AtomicUsize,
) -> io::Result<super::Accepted<TcpStream>> {
    let preamble = match timeout(PREAMBLE_TIMEOUT, read_preamble(&mut stream)).await {
        Ok(Ok(preamble)) => preamble,
        Ok(Err(_)) | Err(_) => {
            pending_connections.fetch_sub(1, Ordering::AcqRel);
            log_authentication_failure();
            refuse_connection(&mut stream, PreambleError::Unauthorized).await;
            return Ok(super::Accepted::Consumed);
        }
    };
    pending_connections.fetch_sub(1, Ordering::AcqRel);

    let token_digest: [u8; 32] = Sha256::digest(preamble.auth.as_bytes()).into();
    let peer = if preamble.v == PREAMBLE_VERSION {
        (peer_authenticator)(&preamble.auth, &token_digest)
    } else {
        None
    };
    let Some(peer) = peer else {
        log_authentication_failure();
        refuse_connection(&mut stream, PreambleError::Unauthorized).await;
        return Ok(super::Accepted::Consumed);
    };

    let Some(tunnel) = preamble.tunnel else {
        return Ok(super::Accepted::Rpc {
            peer,
            stream,
            operator_uids: Vec::new(),
        });
    };
    let Some(cdp_port) = (cdp_port_resolver)(&tunnel.session_id, &peer) else {
        refuse_connection(&mut stream, PreambleError::NotFound).await;
        return Ok(super::Accepted::Consumed);
    };
    if tunnel.port == 0 || cdp_port != tunnel.port {
        refuse_connection(&mut stream, PreambleError::Forbidden).await;
        return Ok(super::Accepted::Consumed);
    }

    let mut cdp_stream =
        match TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], tunnel.port))).await {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("tegatad: could not connect to the requested CDP endpoint: {error}");
                return Ok(super::Accepted::Consumed);
            }
        };
    let _ = write_response(&mut stream, &PreambleResponse::accepted()).await;
    tokio::spawn(async move {
        let _ = copy_bidirectional(&mut stream, &mut cdp_stream).await;
    });
    Ok(super::Accepted::Consumed)
}

fn reserve_pending_connection(pending: &AtomicUsize, limit: usize) -> bool {
    pending
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < limit).then_some(count + 1)
        })
        .is_ok()
}

pub(crate) async fn bind_tcp_listener(address: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(address).await
}

async fn read_preamble<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Preamble> {
    let mut line = Vec::with_capacity(128);
    loop {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return serde_json::from_slice(&line)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid TCP preamble"));
        }
        if line.len() >= MAX_PREAMBLE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TCP preamble exceeds 4 KiB",
            ));
        }
    }
}

async fn write_refusal<S: AsyncWrite + Unpin>(
    stream: &mut S,
    error: PreambleError,
) -> io::Result<()> {
    write_response(stream, &PreambleResponse::refused(error)).await
}

async fn refuse_connection(stream: &mut TcpStream, error: PreambleError) {
    let _ = write_refusal(stream, error).await;
    let _ = stream.shutdown().await;
    drain_refusal_input(stream).await;
}

async fn drain_refusal_input(stream: &mut TcpStream) {
    let _ = timeout(REFUSAL_DRAIN_TIMEOUT, async {
        let mut buffer = [0_u8; 4096];
        let mut remaining = MAX_REFUSAL_DRAIN_BYTES;
        while remaining > 0 {
            let length = remaining.min(buffer.len());
            match stream.read(&mut buffer[..length]).await {
                Ok(0) | Err(_) => break,
                Ok(read) => remaining -= read,
            }
        }
    })
    .await;
}

async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    response: &PreambleResponse,
) -> io::Result<()> {
    let mut line = serde_json::to_vec(response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    line.push(b'\n');
    stream.write_all(&line).await?;
    stream.flush().await
}

fn log_authentication_failure() {
    eprintln!("tegatad: TCP preamble authentication failed");
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, timeout};

    use super::super::Accepted;
    use super::{CdpPortResolver, TcpTransport};

    const TOKEN: &str = "test-token";
    const UNAUTHORIZED: &[u8] = b"{\"ok\":false,\"error\":\"UNAUTHORIZED\"}\n";
    const FORBIDDEN: &[u8] = b"{\"ok\":false,\"error\":\"FORBIDDEN\"}\n";
    const ACCEPTED: &[u8] = b"{\"ok\":true}\n";

    async fn transport(resolver: CdpPortResolver) -> TcpTransport {
        TcpTransport::bind_for_test(TOKEN, resolver)
            .await
            .expect("bind TCP transport")
    }

    async fn read_response(stream: &mut tokio::net::TcpStream, expected: &[u8]) {
        let mut response = vec![0_u8; expected.len()];
        stream
            .read_exact(&mut response)
            .await
            .expect("read preamble response");
        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn valid_token_without_tunnel_returns_rpc_stream() {
        let mut transport = transport(Arc::new(|_, _| None)).await;
        let mut client = tokio::net::TcpStream::connect(transport.local_addr().unwrap())
            .await
            .unwrap();
        client
            .write_all(b"{\"v\":1,\"auth\":\"test-token\"}\n")
            .await
            .unwrap();

        let accepted = transport.accept().await.expect("accept TCP connection");
        let Accepted::Rpc { mut stream, .. } = accepted else {
            panic!("expected RPC stream");
        };
        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"status\"}\n")
            .await
            .unwrap();
        let mut request = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request).unwrap()["method"],
            "status"
        );
    }

    #[tokio::test]
    async fn wrong_token_is_refused_without_rpc_processing() {
        let mut transport = transport(Arc::new(|_, _| None)).await;
        let mut client = tokio::net::TcpStream::connect(transport.local_addr().unwrap())
            .await
            .unwrap();
        client
            .write_all(b"{\"v\":1,\"auth\":\"wrong\"}\n")
            .await
            .unwrap();
        assert!(matches!(
            transport.accept().await.unwrap(),
            Accepted::Consumed
        ));
        read_response(&mut client, UNAUTHORIZED).await;
        let mut rest = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn missing_auth_is_refused() {
        let mut transport = transport(Arc::new(|_, _| None)).await;
        let mut client = tokio::net::TcpStream::connect(transport.local_addr().unwrap())
            .await
            .unwrap();
        client.write_all(b"{\"v\":1}\n").await.unwrap();
        assert!(matches!(
            transport.accept().await.unwrap(),
            Accepted::Consumed
        ));
        read_response(&mut client, UNAUTHORIZED).await;
    }

    #[tokio::test]
    async fn forbidden_tunnel_is_refused_when_port_does_not_match() {
        let resolver: CdpPortResolver =
            Arc::new(|session, _| (session == "session").then_some(9222));
        let mut transport = transport(resolver).await;
        let mut client = tokio::net::TcpStream::connect(transport.local_addr().unwrap())
            .await
            .unwrap();
        let preamble =
            json!({"v": 1, "auth": TOKEN, "tunnel": {"session_id": "session", "port": 9223}});
        client
            .write_all(format!("{preamble}\n").as_bytes())
            .await
            .unwrap();
        assert!(matches!(
            transport.accept().await.unwrap(),
            Accepted::Consumed
        ));
        read_response(&mut client, FORBIDDEN).await;
    }

    #[tokio::test]
    async fn matching_tunnel_splices_bytes_to_cdp() {
        let cdp_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let cdp_port = cdp_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = cdp_listener.accept().await.unwrap();
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let resolver: CdpPortResolver =
            Arc::new(move |session, _| (session == "session").then_some(cdp_port));
        let mut transport = transport(resolver).await;
        let mut client = tokio::net::TcpStream::connect(transport.local_addr().unwrap())
            .await
            .unwrap();
        let preamble =
            json!({"v": 1, "auth": TOKEN, "tunnel": {"session_id": "session", "port": cdp_port}});
        client
            .write_all(format!("{preamble}\n").as_bytes())
            .await
            .unwrap();
        assert!(matches!(
            transport.accept().await.unwrap(),
            Accepted::Consumed
        ));
        read_response(&mut client, ACCEPTED).await;
        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    }

    #[tokio::test]
    async fn malformed_and_oversized_preambles_are_refused() {
        for preamble in [b"not-json\n".to_vec(), vec![b'x'; 4097]] {
            let mut transport = transport(Arc::new(|_, _| None)).await;
            let mut client = tokio::net::TcpStream::connect(transport.local_addr().unwrap())
                .await
                .unwrap();
            client.write_all(&preamble).await.unwrap();
            assert!(matches!(
                transport.accept().await.unwrap(),
                Accepted::Consumed
            ));
            read_response(&mut client, UNAUTHORIZED).await;
        }
    }
}
