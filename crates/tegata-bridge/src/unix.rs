use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
use tegata_core::wire::{
    PREAMBLE_VERSION, Preamble, PreambleResponse, PreambleTunnel, RpcError, RpcRequest, RpcResponse,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

const DEFAULT_DAEMON_PORT: u16 = 0x5447;
const CLASSIFICATION_ERROR_CODE: i32 = -32000;

pub struct BridgeConfig {
    pub socket_path: PathBuf,
    pub token_file: PathBuf,
    pub daemon_addr: String,
}

pub async fn run(config: BridgeConfig) -> io::Result<()> {
    let token = read_token(&config.token_file)?;
    let listener = UnixListener::bind(&config.socket_path)?;
    std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))?;

    loop {
        let (stream, _) = listener.accept().await?;
        let peer_uid = match stream.peer_cred() {
            Ok(credentials) => credentials.uid(),
            Err(_) => continue,
        };
        if peer_uid != unsafe { libc::geteuid() } {
            continue;
        }
        let daemon_addr = config.daemon_addr.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let _ = serve_client(stream, daemon_addr, token).await;
        });
    }
}

pub fn default_daemon_addr() -> io::Result<String> {
    let route = std::fs::read_to_string("/proc/net/route")?;
    for line in route.lines().skip(1) {
        let columns: Vec<_> = line.split_whitespace().collect();
        if columns.len() < 3 || columns[1] != "00000000" || columns[2] == "00000000" {
            continue;
        }
        let gateway = columns[2];
        if gateway.len() != 8 {
            continue;
        }
        let mut octets = [0_u8; 4];
        let mut valid = true;
        for (index, octet) in octets.iter_mut().enumerate() {
            match u8::from_str_radix(&gateway[index * 2..index * 2 + 2], 16) {
                Ok(value) => *octet = value,
                Err(_) => {
                    valid = false;
                    break;
                }
            }
        }
        if valid {
            return Ok(format!(
                "{}.{}.{}.{}:{DEFAULT_DAEMON_PORT}",
                octets[3], octets[2], octets[1], octets[0]
            ));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no default route in /proc/net/route",
    ))
}

fn read_token(path: &Path) -> io::Result<String> {
    let metadata = std::fs::metadata(path)?;
    if metadata.permissions().mode() & 0o7777 != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "token file must have permissions 0600",
        ));
    }
    Ok(std::fs::read_to_string(path)?.trim_end().to_owned())
}

async fn serve_client(stream: UnixStream, daemon_addr: String, token: String) -> io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut first_line = String::new();
    if reader.read_line(&mut first_line).await? == 0 {
        return Ok(());
    }

    let request_id = serde_json::from_str::<RpcRequest>(first_line.trim_end())
        .map(|request| request.id)
        .unwrap_or(Value::Null);
    if let Ok(request) = serde_json::from_str::<RpcRequest>(first_line.trim_end())
        && request.method == "bridge_open_tunnel"
    {
        return serve_open_tunnel(request, write_half, token, daemon_addr).await;
    }

    let mut daemon = match TcpStream::connect(&daemon_addr).await {
        Ok(stream) => stream,
        Err(_) => {
            write_rpc_error(&mut write_half, request_id, "INTERNAL").await?;
            return Ok(());
        }
    };
    if write_preamble(
        &mut daemon,
        Preamble {
            v: PREAMBLE_VERSION,
            auth: token,
            tunnel: None,
        },
    )
    .await
    .is_err()
    {
        write_rpc_error(&mut write_half, request_id, "INTERNAL").await?;
        return Ok(());
    }
    if daemon.write_all(first_line.as_bytes()).await.is_err() {
        write_rpc_error(&mut write_half, request_id, "INTERNAL").await?;
        return Ok(());
    }

    let (daemon_read, mut daemon_write) = daemon.into_split();
    let mut daemon_reader = BufReader::new(daemon_read);
    let local_to_daemon = forward_local(&mut reader, &mut daemon_write);
    let daemon_to_local = forward_daemon(&mut daemon_reader, &mut write_half, request_id);
    tokio::pin!(local_to_daemon);
    tokio::pin!(daemon_to_local);
    tokio::select! {
        result = &mut local_to_daemon => result,
        result = &mut daemon_to_local => result,
    }
}

async fn forward_local<R>(
    reader: &mut R,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
) -> io::Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        writer.write_all(line.as_bytes()).await?;
    }
}

async fn forward_daemon(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    request_id: Value,
) -> io::Result<()> {
    let mut line = String::new();
    let mut first_response = true;
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            if first_response {
                write_rpc_error(writer, request_id, "INTERNAL").await?;
            }
            return Ok(());
        }

        if first_response {
            first_response = false;
            if let Ok(response) = serde_json::from_str::<PreambleResponse>(line.trim_end())
                && !response.ok
            {
                let message = match response.error.as_deref() {
                    Some("UNAUTHORIZED") => "UNAUTHORIZED",
                    Some("FORBIDDEN") => "FORBIDDEN",
                    _ => "INTERNAL",
                };
                write_rpc_error(writer, request_id, message).await?;
                return Ok(());
            }
        }
        writer.write_all(line.as_bytes()).await?;
    }
}

async fn serve_open_tunnel(
    request: RpcRequest,
    mut writer: tokio::net::unix::OwnedWriteHalf,
    token: String,
    daemon_addr: String,
) -> io::Result<()> {
    let params = match serde_json::from_value::<OpenTunnelParams>(request.params) {
        Ok(params) => params,
        Err(_) => {
            write_rpc_error(&mut writer, request.id, "INTERNAL").await?;
            return Ok(());
        }
    };
    let mut daemon = match TcpStream::connect(&daemon_addr).await {
        Ok(stream) => stream,
        Err(_) => {
            write_rpc_error(&mut writer, request.id, "INTERNAL").await?;
            return Ok(());
        }
    };
    if write_preamble(
        &mut daemon,
        Preamble {
            v: PREAMBLE_VERSION,
            auth: token.clone(),
            tunnel: Some(PreambleTunnel {
                session_id: params.session_id.clone(),
                port: params.port,
            }),
        },
    )
    .await
    .is_err()
    {
        write_rpc_error(&mut writer, request.id, "INTERNAL").await?;
        return Ok(());
    }
    let line = match read_line(&mut daemon).await {
        Ok(Some(line)) => line,
        _ => {
            write_rpc_error(&mut writer, request.id, "INTERNAL").await?;
            return Ok(());
        }
    };
    let response = match serde_json::from_str::<PreambleResponse>(line.trim_end()) {
        Ok(response) => response,
        Err(_) => {
            write_rpc_error(&mut writer, request.id, "INTERNAL").await?;
            return Ok(());
        }
    };
    if !response.ok {
        let message = match response.error.as_deref() {
            Some("UNAUTHORIZED") => "UNAUTHORIZED",
            Some("FORBIDDEN") => "FORBIDDEN",
            _ => "INTERNAL",
        };
        write_rpc_error(&mut writer, request.id, message).await?;
        return Ok(());
    }
    drop(daemon);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_port = listener.local_addr()?.port();
    let response = RpcResponse {
        jsonrpc: "2.0",
        id: request.id,
        result: Some(serde_json::json!({ "local_port": local_port })),
        error: None,
    };
    write_json_line(&mut writer, &response).await?;
    tokio::spawn(async move {
        serve_tunnel_listener(listener, params, token, daemon_addr).await;
    });
    Ok(())
}

#[derive(Deserialize)]
struct OpenTunnelParams {
    session_id: String,
    port: u16,
}

async fn serve_tunnel_listener(
    listener: TcpListener,
    params: OpenTunnelParams,
    token: String,
    daemon_addr: String,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(connection) => connection,
            Err(_) => return,
        };
        let token = token.clone();
        let session_id = params.session_id.clone();
        let port = params.port;
        let daemon_addr = daemon_addr.clone();
        tokio::spawn(async move {
            let _ = serve_tunnel_connection(stream, session_id, port, token, daemon_addr).await;
        });
    }
}

async fn serve_tunnel_connection(
    mut local: TcpStream,
    session_id: String,
    port: u16,
    token: String,
    daemon_addr: String,
) -> io::Result<()> {
    let mut daemon = TcpStream::connect(&daemon_addr).await?;
    write_preamble(
        &mut daemon,
        Preamble {
            v: PREAMBLE_VERSION,
            auth: token,
            tunnel: Some(PreambleTunnel { session_id, port }),
        },
    )
    .await?;

    let Some(line) = read_line(&mut daemon).await? else {
        return Ok(());
    };
    let response = serde_json::from_str::<PreambleResponse>(line.trim_end())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid tunnel response"))?;
    if !response.ok {
        return Ok(());
    }
    tokio::io::copy_bidirectional(&mut local, &mut daemon).await?;
    Ok(())
}

async fn write_preamble(stream: &mut TcpStream, preamble: Preamble) -> io::Result<()> {
    write_json_line(stream, &preamble).await
}

async fn read_line(stream: &mut TcpStream) -> io::Result<Option<String>> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        if stream.read(&mut byte).await? == 0 {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unterminated line",
                ))
            };
        }
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            return String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response is not UTF-8"));
        }
    }
}

async fn write_rpc_error(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    id: Value,
    message: &str,
) -> io::Result<()> {
    let response = RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcError {
            code: CLASSIFICATION_ERROR_CODE,
            message: message.to_owned(),
        }),
    };
    write_json_line(writer, &response).await
}

async fn write_json_line<W, T>(writer: &mut W, value: &T) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let mut line = serde_json::to_vec(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "failed to serialize response"))?;
    line.push(b'\n');
    writer.write_all(&line).await
}
