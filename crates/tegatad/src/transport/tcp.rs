//! Token-authenticated TCP transport shared by the platform implementations.

#![cfg_attr(not(windows), allow(dead_code))]

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tegata_core::wire::{PREAMBLE_VERSION, Preamble, PreambleError, PreambleResponse};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const MAX_PREAMBLE_BYTES: usize = 4 * 1024;
const PREAMBLE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REFUSAL_DRAIN_BYTES: usize = 64 * 1024;
const REFUSAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) type CdpPortResolver = Arc<dyn Fn(&str) -> Option<u16> + Send + Sync>;

pub(crate) enum Accepted {
    Rpc { stream: TcpStream },
    Consumed,
}

pub(crate) struct TcpTransport {
    listener: TcpListener,
    token_hash_path: Box<Path>,
    cdp_port_resolver: CdpPortResolver,
}

impl TcpTransport {
    pub(crate) async fn bind(
        address: SocketAddr,
        token_hash_path: &Path,
        cdp_port_resolver: CdpPortResolver,
    ) -> io::Result<Self> {
        let listener = bind_tcp_listener(address).await?;
        Ok(Self {
            listener,
            token_hash_path: token_hash_path.into(),
            cdp_port_resolver,
        })
    }

    #[cfg(test)]
    async fn bind_for_test(token: &str, cdp_port_resolver: CdpPortResolver) -> io::Result<Self> {
        let path =
            std::env::temp_dir().join(format!("tegatad-token-hash-{}", uuid::Uuid::new_v4()));
        let digest = Sha256::digest(token.as_bytes());
        let hash = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::fs::write(&path, format!("{hash}\n"))?;
        Self::bind(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            &path,
            cdp_port_resolver,
        )
        .await
    }

    #[cfg(test)]
    async fn replace_token_hash(&self, token: &str) {
        let digest = Sha256::digest(token.as_bytes());
        let hash = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        tokio::fs::write(&self.token_hash_path, format!("{hash}\n"))
            .await
            .expect("replace token hash");
    }

    #[cfg(test)]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub(crate) async fn accept(&self) -> io::Result<Accepted> {
        let (mut stream, _) = self.listener.accept().await?;
        let preamble = match timeout(PREAMBLE_TIMEOUT, read_preamble(&mut stream)).await {
            Ok(Ok(preamble)) => preamble,
            Ok(Err(_)) | Err(_) => {
                log_authentication_failure();
                refuse_connection(&mut stream, PreambleError::Unauthorized).await;
                return Ok(Accepted::Consumed);
            }
        };

        let token_digest = match load_token_digest(&self.token_hash_path).await {
            Ok(token_digest) => token_digest,
            Err(_) => {
                log_authentication_failure();
                refuse_connection(&mut stream, PreambleError::Unauthorized).await;
                return Ok(Accepted::Consumed);
            }
        };
        if preamble.v != PREAMBLE_VERSION
            || !constant_time_digest_matches(&preamble.auth, &token_digest)
        {
            log_authentication_failure();
            refuse_connection(&mut stream, PreambleError::Unauthorized).await;
            return Ok(Accepted::Consumed);
        }

        let Some(tunnel) = preamble.tunnel else {
            return Ok(Accepted::Rpc { stream });
        };
        if tunnel.port == 0 || (self.cdp_port_resolver)(&tunnel.session_id) != Some(tunnel.port) {
            refuse_connection(&mut stream, PreambleError::Forbidden).await;
            return Ok(Accepted::Consumed);
        }

        let mut cdp_stream =
            match TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], tunnel.port))).await {
                Ok(stream) => stream,
                Err(error) => {
                    eprintln!("tegatad: could not connect to the requested CDP endpoint: {error}");
                    return Ok(Accepted::Consumed);
                }
            };
        let _ = write_response(&mut stream, &PreambleResponse::accepted()).await;
        tokio::spawn(async move {
            let _ = copy_bidirectional(&mut stream, &mut cdp_stream).await;
        });
        Ok(Accepted::Consumed)
    }
}

pub(crate) async fn bind_tcp_listener(address: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(address).await
}

async fn load_token_digest(path: &Path) -> io::Result<[u8; 32]> {
    let contents = tokio::fs::read(path).await?;
    parse_token_digest(&contents)
}

fn parse_token_digest(contents: &[u8]) -> io::Result<[u8; 32]> {
    let contents = match contents.strip_suffix(b"\n") {
        Some(contents) => contents.strip_suffix(b"\r").unwrap_or(contents),
        None => contents,
    };
    if contents.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "token hash must contain one 64-character lowercase SHA-256 hex line",
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in contents.chunks_exact(2).enumerate() {
        let high = decode_hex_digit(pair[0])?;
        let low = decode_hex_digit(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

fn decode_hex_digit(digit: u8) -> io::Result<u8> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "token hash must contain one 64-character lowercase SHA-256 hex line",
        )),
    }
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

fn constant_time_digest_matches(token: &str, expected: &[u8; 32]) -> bool {
    let actual = Sha256::digest(token.as_bytes());
    actual
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (actual, expected)| {
            difference | (actual ^ expected)
        })
        == 0
}

fn log_authentication_failure() {
    eprintln!("tegatad: TCP preamble authentication failed");
}

#[cfg(test)]
impl Drop for TcpTransport {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.token_hash_path);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, timeout};

    use super::{Accepted, CdpPortResolver, TcpTransport, parse_token_digest};

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
        let transport = transport(Arc::new(|_| None)).await;
        let mut client = tokio::net::TcpStream::connect(transport.local_addr().unwrap())
            .await
            .unwrap();
        client
            .write_all(b"{\"v\":1,\"auth\":\"test-token\"}\n")
            .await
            .unwrap();

        let accepted = transport.accept().await.expect("accept TCP connection");
        let Accepted::Rpc { mut stream } = accepted else {
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
        let transport = transport(Arc::new(|_| None)).await;
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
        let transport = transport(Arc::new(|_| None)).await;
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
        let resolver: CdpPortResolver = Arc::new(|session| (session == "session").then_some(9222));
        let transport = transport(resolver).await;
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
            Arc::new(move |session| (session == "session").then_some(cdp_port));
        let transport = transport(resolver).await;
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
            let transport = transport(Arc::new(|_| None)).await;
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

    #[test]
    fn token_hash_parser_requires_lowercase_sha256_hex() {
        assert!(parse_token_digest(b"00").is_err());
        assert!(parse_token_digest(&[b'A'; 64]).is_err());
        assert!(parse_token_digest(&[b'0'; 64]).is_ok());
    }

    #[tokio::test]
    async fn token_hash_rotation_takes_effect_without_rebinding() {
        let transport = transport(Arc::new(|_| None)).await;
        let mut client = tokio::net::TcpStream::connect(transport.local_addr().unwrap())
            .await
            .unwrap();
        client
            .write_all(b"{\"v\":1,\"auth\":\"test-token\"}\n")
            .await
            .unwrap();
        assert!(matches!(
            transport.accept().await.unwrap(),
            Accepted::Rpc { .. }
        ));

        transport.replace_token_hash("rotated-token").await;
        let mut client = tokio::net::TcpStream::connect(transport.local_addr().unwrap())
            .await
            .unwrap();
        client
            .write_all(b"{\"v\":1,\"auth\":\"rotated-token\"}\n")
            .await
            .unwrap();
        assert!(matches!(
            transport.accept().await.unwrap(),
            Accepted::Rpc { .. }
        ));
    }

    #[tokio::test]
    async fn missing_token_hash_is_unauthorized() {
        let transport = transport(Arc::new(|_| None)).await;
        tokio::fs::remove_file(&transport.token_hash_path)
            .await
            .unwrap();
        let mut client = tokio::net::TcpStream::connect(transport.local_addr().unwrap())
            .await
            .unwrap();
        client
            .write_all(b"{\"v\":1,\"auth\":\"test-token\"}\n")
            .await
            .unwrap();
        assert!(matches!(
            transport.accept().await.unwrap(),
            Accepted::Consumed
        ));
        read_response(&mut client, UNAUTHORIZED).await;
    }
}
