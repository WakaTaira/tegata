//! Windows transport.
//!
//! The Windows service listens on two fronts at once:
//!
//! - a named pipe for local Windows clients, authenticated by the SID of the
//!   client access token and additionally gated by the pipe DACL,
//! - a loopback TCP socket for clients that live in WSL, authenticated by the
//!   one line preamble of [`tegata_core::wire::Preamble`]. A preamble that
//!   asks for a tunnel never reaches the RPC layer: the transport splices the
//!   connection to the CDP port of the named session and reports the
//!   connection as [`Accepted::Consumed`].
//!
use std::ffi::{OsStr, OsString};
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::pin::Pin;
use std::ptr::null_mut;
use std::task::{Context, Poll};
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    AllocateAndInitializeSid, CheckTokenMembership, FreeSid, GetTokenInformation, RevertToSelf,
    SECURITY_ATTRIBUTES, SECURITY_NT_AUTHORITY, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_QUERY,
    TOKEN_USER, TokenElevation, TokenUser,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::SystemServices::{
    DOMAIN_ALIAS_RID_ADMINS, SECURITY_BUILTIN_DOMAIN_RID,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use super::{Accepted, CdpPortResolver, TcpAccepted, TcpTransport, Transport};

/// Configuration keys owned by this transport.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct PlatformConfig {
    /// Name of the named pipe, without the `\\.\pipe\` prefix.
    #[serde(default = "default_pipe_name")]
    pub(crate) pipe_name: String,
    /// Port of the loopback TCP listener. Zero disables that front and leaves
    /// the named pipe as the only way in.
    #[serde(default = "default_tcp_port")]
    pub(crate) tcp_port: u16,
    /// IPv4 address for the TCP listener, or `auto` for the WSL adapter.
    #[serde(default = "default_tcp_bind")]
    pub(crate) tcp_bind: String,
    /// SIDs allowed to call the ordinary RPC surface over the named pipe.
    #[allow(dead_code)]
    #[serde(default)]
    pub(crate) allowed_sids: Vec<String>,
    /// SID allowed to start and stop the service.
    #[serde(default)]
    pub(crate) operator_sid: Option<String>,
    /// Optional path for the token hash. The state-directory default is
    /// resolved by the daemon configuration layer.
    #[serde(default)]
    pub(crate) token_hash_path: Option<String>,
    /// Optional path for the sealed provider blob. The state-directory
    /// default is resolved by the daemon configuration layer.
    #[serde(default)]
    pub(crate) sealed_blob_path: Option<String>,
    /// Optional Playwright browser directory.
    #[serde(default)]
    pub(crate) browsers_path: Option<String>,
    /// Optional Bitwarden CLI executable.
    #[serde(default)]
    pub(crate) bw_path: Option<String>,
    /// Optional Node.js executable.
    #[serde(default)]
    pub(crate) node_path: Option<String>,
}

fn default_pipe_name() -> String {
    "tegatad".to_owned()
}

/// Default TCP port, `0x5447` for "TG".
fn default_tcp_port() -> u16 {
    21575
}

fn default_tcp_bind() -> String {
    "auto".to_owned()
}

/// Client stream of the Windows transport.
///
/// The two fronts produce different concrete streams, so they are boxed behind
/// this trait rather than forcing the RPC layer to know about either of them.
pub(crate) trait ClientStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> ClientStream for T {}

/// Named pipe and loopback TCP listeners of the Windows service.
pub(crate) struct PlatformTransport {
    pipe: PipeTransport,
    tcp: Option<TcpTransport>,
}

struct PipeTransport {
    server: NamedPipeServer,
    name: OsString,
    allowed_sids: Vec<String>,
    /// SID of the account the daemon runs under. The pipe security descriptor
    /// must name it, because every additional pipe instance is created against
    /// the security descriptor of the existing one.
    daemon_sid: String,
}

/// Time a connected client is given to send its first byte.
///
/// A named pipe client cannot be impersonated before it has sent data, so the
/// transport reads one byte before establishing the peer identity. A client
/// that has reached this point writes its request immediately, so the bound is
/// short: it caps how long a silent client delays the accept loop.
const IDENTITY_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Client stream that replays the byte read to make the client impersonable.
pub(crate) struct PrefixedStream<S> {
    prefix: Option<u8>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: u8, inner: S) -> Self {
        Self {
            prefix: Some(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(prefix) = self.prefix {
            if buffer.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            buffer.put_slice(&[prefix]);
            self.prefix = None;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

struct ClientIdentity {
    sid: String,
    elevated: bool,
    administrator: bool,
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> io::Result<Self> {
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is held as a valid Windows handle.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

impl PipeTransport {
    fn bind(pipe_name: &str, allowed_sids: &[String]) -> io::Result<Self> {
        let name = pipe_path(pipe_name)?;
        let daemon_sid = crate::secure_fs::current_user_sid()?;
        let server = create_pipe_server(&name, allowed_sids, &daemon_sid, true)?;
        Ok(Self {
            server,
            name,
            allowed_sids: allowed_sids.to_owned(),
            daemon_sid,
        })
    }

    async fn accept(
        &mut self,
    ) -> io::Result<Option<(super::PeerIdentity, PrefixedStream<NamedPipeServer>)>> {
        self.server.connect().await?;
        let name = self.name.clone();
        let allowed_sids = self.allowed_sids.clone();
        let replacement = create_pipe_server(&name, &allowed_sids, &self.daemon_sid, false)?;
        let mut connected = std::mem::replace(&mut self.server, replacement);
        // The client becomes impersonable only once it has sent data, so the
        // first byte of its request is read here and replayed to the RPC layer.
        let mut prefix = [0_u8; 1];
        let read = tokio::time::timeout(IDENTITY_READ_TIMEOUT, connected.read(&mut prefix)).await;
        if !matches!(read, Ok(Ok(1))) {
            return Ok(None);
        }
        let identity = match client_identity(&connected) {
            Ok(identity) => identity,
            Err(_) => return Ok(None),
        };
        let normal_allowed = self.allowed_sids.iter().any(|sid| sid == &identity.sid);
        if !normal_allowed && !(identity.administrator && identity.elevated) {
            return Ok(None);
        }
        Ok(Some((
            super::PeerIdentity::Sid {
                sid: identity.sid,
                elevated: identity.elevated,
                administrator: identity.administrator,
                normal_allowed,
            },
            PrefixedStream::new(prefix[0], connected),
        )))
    }
}

pub(crate) fn pipe_path(pipe_name: &str) -> io::Result<OsString> {
    if pipe_name.is_empty()
        || pipe_name == "."
        || pipe_name.contains(['\\', '/'])
        || pipe_name.contains('\0')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pipe name must be a non-empty name without path separators",
        ));
    }
    Ok(OsString::from(format!(r"\\.\pipe\{pipe_name}")))
}

fn create_pipe_server(
    name: &OsStr,
    allowed_sids: &[String],
    daemon_sid: &str,
    first_pipe_instance: bool,
) -> io::Result<NamedPipeServer> {
    let descriptor = security_descriptor(allowed_sids, daemon_sid)?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options.first_pipe_instance(first_pipe_instance);
    // SAFETY: `attributes` and the descriptor remain valid until the named pipe is created.
    let result = unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
        )
    };
    // SAFETY: The descriptor was allocated by the preceding conversion call.
    unsafe {
        let _ = LocalFree(descriptor);
    }
    result
}

fn security_descriptor(
    allowed_sids: &[String],
    daemon_sid: &str,
) -> io::Result<*mut core::ffi::c_void> {
    if allowed_sids.iter().any(|sid| !valid_sid(sid)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "allowed_sids must contain Windows SIDs",
        ));
    }
    if !valid_sid(daemon_sid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the daemon account must resolve to a Windows SID",
        ));
    }
    // The daemon account needs FILE_CREATE_PIPE_INSTANCE on its own pipe:
    // every instance after the first is created against the security
    // descriptor of the existing instance, not against this one.
    let mut sddl = format!("D:(A;;GA;;;{daemon_sid})(A;;GA;;;BA)(A;;GA;;;SY)");
    for sid in allowed_sids {
        sddl.push_str("(A;;GA;;;");
        sddl.push_str(sid);
        sddl.push(')');
    }
    let wide = OsStr::new(&sddl)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor = null_mut();
    let mut descriptor_size = 0_u32;
    // SAFETY: `wide` is NUL-terminated, and all output pointers are valid.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut descriptor_size,
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(descriptor)
}

fn valid_sid(sid: &str) -> bool {
    let mut components = sid.split('-');
    components.next() == Some("S")
        && components.next() == Some("1")
        && components.next().is_some()
        && components.all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// Establishes the identity of the connected client from its access token.
///
/// The token is taken by impersonating the client, because a daemon that runs
/// under a virtual service account may not open the process of a client that
/// belongs to another account. Impersonation is bound to the calling thread,
/// so the token is opened and the impersonation reverted without an
/// intervening suspension point.
fn client_identity(pipe: &NamedPipeServer) -> io::Result<ClientIdentity> {
    let handle = pipe.as_raw_handle();
    // SAFETY: `handle` belongs to a connected named pipe whose client has already sent data.
    if unsafe { ImpersonateNamedPipeClient(handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut token = null_mut();
    // SAFETY: The thread impersonates the client, and `token` is a valid output pointer.
    // The token is opened as the daemon itself, since the impersonated client
    // need not hold the right to open its own token.
    let opened = unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            1,
            &mut token,
        )
    };
    let open_error = io::Error::last_os_error();
    // SAFETY: The impersonation started above is dropped here in every path.
    let reverted = unsafe { RevertToSelf() };
    if opened == 0 {
        return Err(open_error);
    }
    let token = OwnedHandle::new(token)?;
    if reverted == 0 {
        return Err(io::Error::other("RevertToSelf failed"));
    }
    // The impersonation token doubles as the membership token: it carries the
    // filtered groups of a client that runs without elevation.
    query_token_identity(token.get(), token.get())
}

fn query_token_identity(token: HANDLE, administrator_token: HANDLE) -> io::Result<ClientIdentity> {
    let user = token_information(token, TokenUser)?;
    let token_user = unsafe {
        // SAFETY: `token_information` stores the buffer in an 8-byte-aligned region.
        &*user.as_ptr().cast::<TOKEN_USER>()
    };
    let sid = sid_string(token_user.User.Sid)?;

    let elevation = token_information(token, TokenElevation)?;
    let elevated = unsafe {
        // SAFETY: `token_information` stores the buffer in an 8-byte-aligned region.
        (*elevation.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated != 0
    };
    let administrator = is_administrator(administrator_token)?;
    Ok(ClientIdentity {
        sid,
        elevated,
        administrator,
    })
}

fn token_information(
    token: HANDLE,
    information_class: windows_sys::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> io::Result<Vec<u64>> {
    let mut size = 0_u32;
    // SAFETY: No output buffer is passed for the size query.
    unsafe {
        let _ = GetTokenInformation(token, information_class, null_mut(), 0, &mut size);
    }
    if size == 0 {
        return Err(io::Error::last_os_error());
    }
    let units = (size as usize).div_ceil(size_of::<u64>());
    let mut information = vec![0_u64; units];
    // SAFETY: `information` is a sufficiently large, 8-byte-aligned write destination.
    if unsafe {
        GetTokenInformation(
            token,
            information_class,
            information.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

fn sid_string(sid: windows_sys::Win32::Security::PSID) -> io::Result<String> {
    let mut string_sid = null_mut();
    // SAFETY: `sid` comes from a valid token information buffer, and `string_sid` is a valid output pointer.
    if unsafe { ConvertSidToStringSidW(sid, &mut string_sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut length = 0;
    // SAFETY: The conversion result is a NUL-terminated UTF-16 string.
    while unsafe { *string_sid.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: `string_sid` points to `length` initialized UTF-16 code units.
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(string_sid, length) });
    // SAFETY: `string_sid` is the allocated region returned by ConvertSidToStringSidW.
    unsafe {
        let _ = LocalFree(string_sid.cast());
    }
    Ok(value)
}

fn is_administrator(token: HANDLE) -> io::Result<bool> {
    let authority = SECURITY_NT_AUTHORITY;
    let mut sid = null_mut();
    // SAFETY: `sid` is a valid output pointer, and the authority values are valid constants.
    let allocated = unsafe {
        AllocateAndInitializeSid(
            &authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID as u32,
            DOMAIN_ALIAS_RID_ADMINS as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut sid,
        )
    };
    if allocated == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut member = 0;
    // SAFETY: `token` and `sid` are valid values allocated for the query, and `member` is a valid output pointer.
    let result = unsafe { CheckTokenMembership(token, sid, &mut member) };
    // SAFETY: `sid` was allocated by AllocateAndInitializeSid and is freed exactly once here.
    unsafe {
        let _ = FreeSid(sid);
    }
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(member != 0)
}

impl PlatformTransport {
    /// Prepares the named pipe and, unless `tcp_port` is zero, the loopback
    /// TCP listener.
    pub(crate) async fn bind(
        config: &PlatformConfig,
        token_hash_path: &Path,
        cdp_port_resolver: CdpPortResolver,
    ) -> io::Result<Self> {
        let pipe = PipeTransport::bind(&config.pipe_name, &config.allowed_sids)?;
        let tcp = if config.tcp_port == 0 {
            None
        } else {
            let address = resolve_tcp_bind(&config.tcp_bind, config.tcp_port)?;
            Some(TcpTransport::bind(address, token_hash_path, cdp_port_resolver).await?)
        };
        Ok(Self { pipe, tcp })
    }

    fn pipe_result(
        result: io::Result<Option<(super::PeerIdentity, PrefixedStream<NamedPipeServer>)>>,
    ) -> io::Result<Accepted<Box<dyn ClientStream>>> {
        match result? {
            Some((peer, stream)) => Ok(Accepted::Rpc {
                peer,
                stream: Box::new(stream),
            }),
            None => Ok(Accepted::Consumed),
        }
    }
}

impl Transport for PlatformTransport {
    type Stream = Box<dyn ClientStream>;

    async fn accept(&mut self) -> io::Result<Accepted<Self::Stream>> {
        if let Some(tcp) = &self.tcp {
            tokio::select! {
                result = tcp.accept() => match result? {
                    TcpAccepted::Rpc { stream } => Ok(Accepted::Rpc {
                        peer: super::PeerIdentity::Token,
                        stream: Box::new(stream),
                    }),
                    TcpAccepted::Consumed => Ok(Accepted::Consumed),
                },
                result = self.pipe.accept() => Self::pipe_result(result),
            }
        } else {
            Self::pipe_result(self.pipe.accept().await)
        }
    }
}

fn resolve_tcp_bind(bind: &str, port: u16) -> io::Result<SocketAddr> {
    let address = if bind == "auto" {
        resolve_wsl_ipv4()?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "could not resolve an IPv4 address for a vEthernet (WSL adapter)",
            )
        })?
    } else {
        bind.parse::<Ipv4Addr>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcp_bind must be `auto` or an IPv4 address",
            )
        })?
    };
    Ok(SocketAddr::from((address, port)))
}

fn resolve_wsl_ipv4() -> io::Result<Option<Ipv4Addr>> {
    let mut size = 0_u32;
    // SAFETY: A null adapter buffer and a valid size pointer are passed for the size query.
    let result = unsafe {
        GetAdaptersAddresses(
            0,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null(),
            null_mut(),
            &mut size,
        )
    };
    if result != 111 && result != 0 {
        return Err(io::Error::other(format!(
            "GetAdaptersAddresses failed with error {result}"
        )));
    }
    if size == 0 {
        return Ok(None);
    }
    let units = (size as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
    let mut storage = Vec::<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>::with_capacity(units);
    // SAFETY: `storage` has sufficient capacity for the reported adapter list.
    let result = unsafe {
        GetAdaptersAddresses(
            0,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null(),
            storage.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if result != 0 {
        return Err(io::Error::other(format!(
            "GetAdaptersAddresses failed with error {result}"
        )));
    }
    let mut adapter = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !adapter.is_null() {
        // SAFETY: The buffer is populated by GetAdaptersAddresses, and the linked elements are valid.
        let adapter_ref = unsafe { &*adapter };
        // SAFETY: FriendlyName is a valid NUL-terminated string held by the adapter element.
        if unsafe { wide_string(adapter_ref.FriendlyName) }.starts_with("vEthernet (WSL") {
            let mut unicast = adapter_ref.FirstUnicastAddress;
            while !unicast.is_null() {
                // SAFETY: The unicast element is a valid linked element obtained from the adapter list.
                let address = unsafe { &*unicast }.Address.lpSockaddr;
                // SAFETY: `address` is confirmed non-null, and the family is read from the WinSock header.
                if !address.is_null() && unsafe { (*address).sa_family } == AF_INET {
                    // SAFETY: The address family check guarantees that this is an IPv4 SOCKADDR_IN.
                    let address = unsafe { &*(address.cast::<SOCKADDR_IN>()) };
                    // SAFETY: `address` points to a valid SOCKADDR_IN.
                    let value = unsafe { address.sin_addr.S_un.S_addr };
                    return Ok(Some(Ipv4Addr::from(u32::from_be(value))));
                }
                // SAFETY: `unicast` points to a valid linked element.
                unicast = unsafe { (*unicast).Next };
            }
        }
        adapter = adapter_ref.Next;
    }
    Ok(None)
}

unsafe fn wide_string(pointer: *const u16) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let mut length = 0;
    // SAFETY: The caller guarantees that `pointer` points to a NUL-terminated UTF-16 string.
    while unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: The preceding scan established the length of the initialized string.
    unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(pointer, length)) }
}

#[cfg(test)]
mod tests {
    use super::PlatformConfig;

    #[test]
    fn minimal_windows_transport_config_uses_optional_defaults() {
        let config: PlatformConfig = toml::from_str(
            r#"
pipe_name = "tegatad-test"
tcp_port = 0
state_dir = "C:\\Temp\\tegata\\state"
audit_log_path = "C:\\Temp\\tegata\\state\\audit.log"
allowed_sids = ["S-1-5-21-1"]

[[providers]]
namespace = "mock"
type = "mock"
"#,
        )
        .expect("parse minimal Windows config");

        assert_eq!(config.pipe_name, "tegatad-test");
        assert_eq!(config.tcp_port, 0);
        assert_eq!(config.tcp_bind, "auto");
        assert_eq!(config.allowed_sids, ["S-1-5-21-1"]);
        assert!(config.operator_sid.is_none());
        assert!(config.token_hash_path.is_none());
        assert!(config.sealed_blob_path.is_none());
        assert!(config.browsers_path.is_none());
        assert!(config.bw_path.is_none());
        assert!(config.node_path.is_none());
    }
}
