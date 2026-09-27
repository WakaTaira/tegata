use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tegata_core::Secret;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::{Instant, sleep, timeout};

use super::{CredentialProvider, CredentialRef, ProviderFuture, ResolvedCredential};
use crate::ErrorCode;
#[cfg(windows)]
use crate::UnlockMode;

const BW_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const BW_SYNC_TIMEOUT: Duration = Duration::from_secs(30);
const BW_RESYNC_INTERVAL: Duration = Duration::from_secs(60);
const BW_PROCESS_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct BitwardenCliProvider {
    namespace: String,
    server_url: String,
    email: String,
    askpass_cmd: String,
    appdata_dir: PathBuf,
    bw_path: Option<PathBuf>,
    totp_exposable: Vec<String>,
    session_ttl: Duration,
    session: Option<Secret>,
    unlocked_at: Option<Instant>,
    last_sync_at: Option<Instant>,
    locked: bool,
    autolock_event_pending: bool,
    catalog: Vec<BitwardenCatalogItem>,
    #[cfg(windows)]
    unlock_mode: UnlockMode,
    #[cfg(windows)]
    sealed_blob_path: PathBuf,
}

pub(crate) struct BitwardenCliConfig {
    pub(crate) namespace: String,
    pub(crate) server_url: String,
    pub(crate) email: String,
    pub(crate) askpass_cmd: String,
    pub(crate) appdata_dir: PathBuf,
    pub(crate) bw_path: Option<PathBuf>,
    pub(crate) totp_exposable: Vec<String>,
    pub(crate) session_ttl: Duration,
    #[cfg(windows)]
    pub(crate) unlock_mode: UnlockMode,
    #[cfg(windows)]
    pub(crate) sealed_blob_path: PathBuf,
}

struct BitwardenCatalogItem {
    id: String,
    name: String,
}

#[derive(Debug, serde::Deserialize)]
struct BitwardenItem {
    id: String,
    name: String,
    login: Option<BitwardenLogin>,
}

#[derive(Debug, serde::Deserialize)]
struct BitwardenLogin {
    #[serde(default)]
    uris: Vec<BitwardenUri>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct BitwardenUri {
    uri: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct BitwardenStatus {
    status: String,
}

struct BwOutput {
    stdout: Vec<u8>,
    diagnostic: Option<BwDiagnosticBase>,
}

#[derive(Clone, Copy)]
struct BwAttemptContext {
    cold_start: bool,
    attempt: u32,
}

impl BwAttemptContext {
    const fn new(cold_start: bool, attempt: u32) -> Self {
        Self {
            cold_start,
            attempt,
        }
    }

    const fn with_attempt(self, attempt: u32) -> Self {
        Self { attempt, ..self }
    }
}

struct BwDiagnosticBase {
    rpc_id: serde_json::Value,
    namespace: String,
    cold_start: bool,
    op: String,
    attempt: u32,
    elapsed_ms: u64,
    branch: Option<String>,
    session_present: bool,
    exit_code: Option<i32>,
    stderr: String,
    io_error: Option<String>,
}

struct BwDiagnosticInput<'a> {
    args: &'a [String],
    session: Option<&'a Secret>,
    password: Option<&'a Secret>,
    context: BwAttemptContext,
    started_at: Instant,
    exit_code: Option<i32>,
    stderr: &'a [u8],
    issued_secrets: &'a [String],
    io_error: Option<io::ErrorKind>,
}

fn duration_from_env(name: &str, default: Duration) -> Duration {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(default)
}

fn bw_sync_timeout() -> Duration {
    duration_from_env("TEGATA_BW_SYNC_TIMEOUT_MS", BW_SYNC_TIMEOUT)
}

fn bw_resync_interval() -> Duration {
    duration_from_env("TEGATA_BW_RESYNC_INTERVAL_MS", BW_RESYNC_INTERVAL)
}

#[derive(Debug)]
enum BwRunError {
    CreateDir(io::Error),
    Process(io::Error, Vec<u8>),
    NonZeroExit(std::process::ExitStatus, Vec<u8>),
    Timeout(Vec<u8>),
}

impl fmt::Display for BwRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDir(error) => {
                write!(formatter, "could not create appdata directory: {error}")
            }
            Self::Process(error, _) => write!(formatter, "could not run bw: {error}"),
            Self::NonZeroExit(status, _) => write!(
                formatter,
                "bw exited unsuccessfully with status {}",
                status
                    .code()
                    .map_or_else(|| "signal".to_owned(), |code| code.to_string()),
            ),
            Self::Timeout(_) => write!(formatter, "bw command timed out"),
        }
    }
}

impl std::error::Error for BwRunError {}

enum BwOperationError {
    Normal(ErrorCode),
    NoColdStartRetry(ErrorCode),
}

impl From<ErrorCode> for BwOperationError {
    fn from(error: ErrorCode) -> Self {
        Self::Normal(error)
    }
}

impl BwOperationError {
    fn into_error_code(self) -> ErrorCode {
        match self {
            Self::Normal(error) | Self::NoColdStartRetry(error) => error,
        }
    }

    fn can_retry_cold_start(&self) -> bool {
        matches!(self, Self::Normal(ErrorCode::ProviderUnavailable))
    }
}

impl BwRunError {
    fn stderr(&self) -> &[u8] {
        match self {
            Self::CreateDir(_) => &[],
            Self::Process(_, stderr) | Self::NonZeroExit(_, stderr) | Self::Timeout(stderr) => {
                stderr
            }
        }
    }

    fn failure(&self) -> &'static str {
        match self {
            Self::CreateDir(_) => "create_dir",
            Self::Process(_, _) => "spawn",
            Self::NonZeroExit(_, _) => "exit",
            Self::Timeout(_) => "timeout",
        }
    }

    fn exit_code(&self) -> Option<i32> {
        match self {
            Self::NonZeroExit(status, _) => status.code(),
            Self::CreateDir(_) | Self::Process(_, _) | Self::Timeout(_) => None,
        }
    }

    /// spawn・appdata ディレクトリ作成に伴う `io::Error` の種類のみを返す。パスを含み得る
    /// `Display` 文は診断行に載せないため、`ErrorKind` の `Debug` 表現に限定する。
    fn io_error_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::CreateDir(error) | Self::Process(error, _) => Some(error.kind()),
            Self::NonZeroExit(_, _) | Self::Timeout(_) => None,
        }
    }
}

fn classify_bw_run_error(error: &BwRunError) -> ErrorCode {
    match error {
        BwRunError::Process(_, _) | BwRunError::NonZeroExit(_, _) | BwRunError::Timeout(_) => {
            ErrorCode::ProviderUnavailable
        }
        BwRunError::CreateDir(_) => ErrorCode::Internal,
    }
}

fn log_bw_parse_error(operation: &str) {
    eprintln!("tegatad: bw {operation} returned invalid JSON");
}

fn truncate_utf8(value: String) -> String {
    if value.len() <= 300 {
        return value;
    }
    let mut end = 300;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn sanitize_stderr(
    stderr: &[u8],
    appdata_dir: &Path,
    email: &str,
    session: Option<&Secret>,
    password: Option<&Secret>,
    issued_secrets: &[String],
) -> String {
    let mut value = String::from_utf8_lossy(stderr).into_owned();
    let appdata_dir = appdata_dir.to_string_lossy();
    for sensitive in [
        Some(appdata_dir.as_ref()),
        (!email.is_empty()).then_some(email),
        session.map(Secret::as_str),
        password.map(Secret::as_str),
    ]
    .into_iter()
    .flatten()
    .chain(issued_secrets.iter().map(String::as_str))
    .filter(|sensitive| !sensitive.is_empty())
    {
        value = value.replace(sensitive, "[REDACTED]");
    }
    truncate_utf8(value)
}

fn session_key_from_stdout(stdout: &[u8]) -> Option<String> {
    std::str::from_utf8(stdout)
        .ok()
        .and_then(|value| value.lines().next())
        .map(|value| value.trim_end_matches('\r').to_owned())
        .filter(|value| !value.is_empty())
}

/// `login --raw` / `unlock --raw` の stdout は新たに払い出された session key そのものである。
/// 診断行の stderr を切り詰める前にマスクするため、stdout から得た session key と stdout 全体の
/// trim 値を秘匿対象として返す。
fn issued_session_secrets(args: &[String], stdout: &[u8]) -> Vec<String> {
    let issues_session = match args.first().map(String::as_str) {
        Some("unlock") => true,
        Some("login") => args.get(1).is_none_or(|arg| arg != "--check"),
        _ => false,
    };
    if !issues_session || !args.iter().any(|arg| arg == "--raw") {
        return Vec::new();
    }
    let mut secrets = Vec::new();
    if let Some(session_key) = session_key_from_stdout(stdout) {
        secrets.push(session_key);
    }
    let whole = String::from_utf8_lossy(stdout).trim().to_owned();
    if !whole.is_empty() && !secrets.contains(&whole) {
        secrets.push(whole);
    }
    secrets
}

fn operation_name(args: &[String]) -> String {
    match args.first().map(String::as_str) {
        Some("--version") => "version".to_owned(),
        Some("config") if args.get(1).is_some_and(|arg| arg == "server") => {
            "config_server".to_owned()
        }
        Some("login") if args.get(1).is_some_and(|arg| arg == "--check") => {
            "login_check".to_owned()
        }
        Some("list") if args.get(1).is_some_and(|arg| arg == "items") => "list_items".to_owned(),
        Some("get") if args.get(1).is_some_and(|arg| arg == "item") => "get_item".to_owned(),
        Some(operation) => operation.to_owned(),
        None => "unknown".to_owned(),
    }
}

fn emit_bw_diag(base: BwDiagnosticBase, failure: Option<&str>, status: Option<&str>) {
    let diagnostic = serde_json::json!({
        "rpc_id": base.rpc_id,
        "namespace": base.namespace,
        "cold_start": base.cold_start,
        "op": base.op,
        "attempt": base.attempt,
        "elapsed_ms": base.elapsed_ms,
        "branch": base.branch,
        "session_present": base.session_present,
        "status": status,
        "failure": failure,
        "exit_code": base.exit_code,
        "stderr": base.stderr,
        "io_error": base.io_error,
    });
    if let Ok(json) = serde_json::to_string(&diagnostic) {
        eprintln!("tegatad: bw_diag {json}");
    }
}

impl BwOutput {
    fn finish(mut self, failure: Option<&str>, status: Option<&str>) {
        if let Some(base) = self.diagnostic.take() {
            emit_bw_diag(base, failure, status);
        }
    }
}

impl Drop for BwOutput {
    fn drop(&mut self) {
        if let Some(base) = self.diagnostic.take() {
            emit_bw_diag(base, None, None);
        }
    }
}

impl BitwardenCliProvider {
    pub(crate) fn new(config: BitwardenCliConfig) -> Self {
        Self {
            namespace: config.namespace,
            server_url: config.server_url,
            email: config.email,
            askpass_cmd: config.askpass_cmd,
            appdata_dir: config.appdata_dir,
            bw_path: config.bw_path,
            totp_exposable: config.totp_exposable,
            session_ttl: config.session_ttl,
            session: None,
            unlocked_at: None,
            last_sync_at: None,
            locked: false,
            autolock_event_pending: false,
            catalog: Vec::new(),
            #[cfg(windows)]
            unlock_mode: config.unlock_mode,
            #[cfg(windows)]
            sealed_blob_path: config.sealed_blob_path,
        }
    }

    pub(crate) async fn log_version(&self) {
        let args = vec!["--version".to_owned()];
        let output = match self.run_bw(&args, None, None).await {
            Ok(output) => output,
            Err(_) => return,
        };
        let version = std::str::from_utf8(&output.stdout)
            .ok()
            .and_then(|value| value.lines().next().map(str::trim).map(ToOwned::to_owned))
            .filter(|value| !value.is_empty());
        if let Some(version) = version {
            output.finish(None, None);
            eprintln!("tegatad: bw_version {version}");
        } else {
            output.finish(Some("parse"), None);
        }
    }

    async fn run_bw(
        &self,
        args: &[String],
        session: Option<&Secret>,
        password: Option<&Secret>,
    ) -> Result<BwOutput, BwRunError> {
        self.run_bw_with_context(args, session, password, BwAttemptContext::new(false, 1))
            .await
    }

    async fn run_bw_with_context(
        &self,
        args: &[String],
        session: Option<&Secret>,
        password: Option<&Secret>,
        context: BwAttemptContext,
    ) -> Result<BwOutput, BwRunError> {
        self.run_bw_with_timeout(args, session, password, context, BW_COMMAND_TIMEOUT)
            .await
    }

    async fn run_bw_with_timeout(
        &self,
        args: &[String],
        session: Option<&Secret>,
        password: Option<&Secret>,
        context: BwAttemptContext,
        command_timeout: Duration,
    ) -> Result<BwOutput, BwRunError> {
        self.run_bw_unreported(args, session, password, context, command_timeout)
            .await
            .map_err(|(error, diagnostic)| {
                emit_bw_diag(diagnostic, Some(error.failure()), None);
                error
            })
    }

    /// 失敗時の診断行を出さずに、失敗と診断の材料を呼び出し側へ返す。失敗が正常な回答を
    /// 意味する呼び出し（`login --check` の exit 1 など）は、呼び出し側の意味論で診断行を出す。
    async fn run_bw_unreported(
        &self,
        args: &[String],
        session: Option<&Secret>,
        password: Option<&Secret>,
        context: BwAttemptContext,
        command_timeout: Duration,
    ) -> Result<BwOutput, (BwRunError, BwDiagnosticBase)> {
        let started_at = Instant::now();
        if let Err(error) = tokio::fs::create_dir_all(&self.appdata_dir).await {
            let error = BwRunError::CreateDir(error);
            let diagnostic = self.diagnostic_base(BwDiagnosticInput {
                args,
                session,
                password,
                context,
                started_at,
                exit_code: error.exit_code(),
                stderr: error.stderr(),
                issued_secrets: &[],
                io_error: error.io_error_kind(),
            });
            return Err((error, diagnostic));
        }
        let mut command_args = args.to_vec();
        if password.is_some() {
            command_args.push("--passwordenv".to_owned());
            command_args.push("BW_PASSWORD".to_owned());
        }
        let bw_path = self.bw_path.as_deref().unwrap_or_else(|| Path::new("bw"));
        let mut command = Command::new(bw_path);
        command
            .args(&command_args)
            .env("BW_APPDATA_DIR", &self.appdata_dir)
            .env("BITWARDENCLI_APPDATA_DIR", &self.appdata_dir)
            .env_remove("BW_PASSWORD")
            .env_remove("BW_SESSION")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if let Some(session) = session {
            command.env("BW_SESSION", session.as_str());
        }
        if let Some(password) = password {
            command.env("BW_PASSWORD", password.as_str());
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.as_std_mut().process_group(0);
        }
        let result = match command.spawn() {
            Ok(mut child) => {
                #[cfg(unix)]
                let process_group_id = child.id();
                match (child.stdout.take(), child.stderr.take()) {
                    (Some(mut stdout), Some(mut stderr)) => {
                        let mut stdout_output = Vec::new();
                        let mut stderr_output = Vec::new();
                        match timeout(command_timeout, async {
                            let (status, stdout_result, stderr_result) = tokio::join!(
                                child.wait(),
                                stdout.read_to_end(&mut stdout_output),
                                stderr.read_to_end(&mut stderr_output),
                            );
                            let status = match status {
                                Ok(status) => status,
                                Err(error) => {
                                    return Err(BwRunError::Process(
                                        error,
                                        std::mem::take(&mut stderr_output),
                                    ));
                                }
                            };
                            if let Err(error) = stdout_result {
                                return Err(BwRunError::Process(
                                    error,
                                    std::mem::take(&mut stderr_output),
                                ));
                            }
                            if let Err(error) = stderr_result {
                                return Err(BwRunError::Process(
                                    error,
                                    std::mem::take(&mut stderr_output),
                                ));
                            }
                            if status.success() {
                                Ok((
                                    std::mem::take(&mut stdout_output),
                                    std::mem::take(&mut stderr_output),
                                    status.code(),
                                ))
                            } else {
                                Err(BwRunError::NonZeroExit(
                                    status,
                                    std::mem::take(&mut stderr_output),
                                ))
                            }
                        })
                        .await
                        {
                            Ok(result) => result,
                            Err(_) => {
                                #[cfg(unix)]
                                if let Some(process_group_id) = process_group_id {
                                    crate::kill_process_group_id(process_group_id);
                                }
                                #[cfg(windows)]
                                let _ = child.start_kill();
                                let _ = timeout(BW_PROCESS_CLEANUP_TIMEOUT, async {
                                    let _ = tokio::join!(
                                        child.wait(),
                                        stdout.read_to_end(&mut stdout_output),
                                        stderr.read_to_end(&mut stderr_output),
                                    );
                                })
                                .await;
                                Err(BwRunError::Timeout(stderr_output))
                            }
                        }
                    }
                    (stdout, stderr) => {
                        #[cfg(unix)]
                        if let Some(process_group_id) = process_group_id {
                            crate::kill_process_group_id(process_group_id);
                        }
                        #[cfg(windows)]
                        let _ = child.start_kill();
                        let mut stderr_output = Vec::new();
                        let _ = timeout(BW_PROCESS_CLEANUP_TIMEOUT, async {
                            let _ = child.wait().await;
                            if let Some(mut stderr) = stderr {
                                let _ = stderr.read_to_end(&mut stderr_output).await;
                            }
                        })
                        .await;
                        let message = if stdout.is_none() {
                            "bw stdout was not piped"
                        } else {
                            "bw stderr was not piped"
                        };
                        let error = io::Error::new(io::ErrorKind::BrokenPipe, message);
                        Err(BwRunError::Process(error, stderr_output))
                    }
                }
            }
            Err(error) => Err(BwRunError::Process(error, Vec::new())),
        };
        match result {
            Ok((stdout, stderr, exit_code)) => {
                let issued_secrets = issued_session_secrets(args, &stdout);
                let diagnostic = self.diagnostic_base(BwDiagnosticInput {
                    args,
                    session,
                    password,
                    context,
                    started_at,
                    exit_code,
                    stderr: &stderr,
                    issued_secrets: &issued_secrets,
                    io_error: None,
                });
                Ok(BwOutput {
                    stdout,
                    diagnostic: Some(diagnostic),
                })
            }
            Err(error) => {
                let diagnostic = self.diagnostic_base(BwDiagnosticInput {
                    args,
                    session,
                    password,
                    context,
                    started_at,
                    exit_code: error.exit_code(),
                    stderr: error.stderr(),
                    issued_secrets: &[],
                    io_error: error.io_error_kind(),
                });
                Err((error, diagnostic))
            }
        }
    }

    fn diagnostic_base(&self, input: BwDiagnosticInput<'_>) -> BwDiagnosticBase {
        BwDiagnosticBase {
            rpc_id: crate::current_diagnostic_rpc_id(),
            namespace: self.namespace.clone(),
            cold_start: input.context.cold_start,
            op: operation_name(input.args),
            attempt: input.context.attempt,
            elapsed_ms: input.started_at.elapsed().as_millis().min(u64::MAX as u128) as u64,
            branch: match input.args.first().map(String::as_str) {
                Some("unlock") => Some("unlock".to_owned()),
                Some("login") if input.args.get(1).is_none_or(|arg| arg != "--check") => {
                    Some("login".to_owned())
                }
                _ => None,
            },
            session_present: input.session.is_some(),
            exit_code: input.exit_code,
            stderr: sanitize_stderr(
                input.stderr,
                &self.appdata_dir,
                &self.email,
                input.session,
                input.password,
                input.issued_secrets,
            ),
            io_error: input.io_error.map(|kind| format!("{kind:?}")),
        }
    }

    async fn run_askpass(&self) -> Result<Secret, ErrorCode> {
        tokio::fs::create_dir_all(&self.appdata_dir)
            .await
            .map_err(|_| ErrorCode::Internal)?;
        let mut command = Command::new("sh");
        command
            .args(["-c", self.askpass_cmd.as_str()])
            .env("BW_APPDATA_DIR", &self.appdata_dir)
            .env("BITWARDENCLI_APPDATA_DIR", &self.appdata_dir)
            .env_remove("BW_PASSWORD")
            .env_remove("BW_SESSION")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.as_std_mut().process_group(0);
        }
        let mut child = command.spawn().map_err(|_| ErrorCode::Internal)?;
        let Some(mut stdout) = child.stdout.take() else {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(ErrorCode::Internal);
        };
        let (status, output) = match timeout(BW_COMMAND_TIMEOUT, async {
            let mut output = Vec::new();
            let (status, read_result) = tokio::join!(child.wait(), stdout.read_to_end(&mut output));
            (status, read_result.map(|_| output))
        })
        .await
        {
            Ok((status, Ok(output))) => (status.map_err(|_| ErrorCode::Internal)?, output),
            Ok((_, Err(_))) => return Err(ErrorCode::Internal),
            Err(_) => {
                #[cfg(unix)]
                crate::kill_process_group(&child);
                #[cfg(windows)]
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(ErrorCode::Internal);
            }
        };
        if !status.success() {
            return Err(ErrorCode::Internal);
        }
        let first_line = String::from_utf8(output)
            .ok()
            .and_then(|value| value.lines().next().map(ToOwned::to_owned))
            .map(|value| value.trim_end_matches('\r').to_owned())
            .filter(|value| !value.is_empty())
            .ok_or(ErrorCode::Internal)?;
        Ok(Secret::new(first_line))
    }

    async fn password(&self) -> Result<Secret, ErrorCode> {
        #[cfg(windows)]
        if self.unlock_mode == UnlockMode::Sealed {
            return crate::dpapi::unseal(&self.sealed_blob_path)
                .map_err(|_| ErrorCode::AdminSealUnavailable);
        }
        self.run_askpass().await
    }

    async fn login_with_password(
        &self,
        login_args: &[String],
        password: &Secret,
        context: BwAttemptContext,
    ) -> Result<String, ErrorCode> {
        let mut session = self
            .run_bw_with_context(login_args, None, Some(password), context)
            .await
            .map_err(|error| classify_bw_run_error(&error))?;
        let value = session_key_from_stdout(&std::mem::take(&mut session.stdout));
        match value {
            Some(value) => {
                session.finish(None, None);
                Ok(value)
            }
            None => {
                session.finish(Some("parse"), None);
                Err(ErrorCode::Internal)
            }
        }
    }

    async fn session_is_unlocked(
        &self,
        session: &Secret,
        context: BwAttemptContext,
    ) -> Result<bool, ErrorCode> {
        let output = match self
            .run_bw_with_context(&["status".to_owned()], Some(session), None, context)
            .await
        {
            Ok(output) => output,
            Err(error) => return Err(classify_bw_run_error(&error)),
        };
        match serde_json::from_slice::<BitwardenStatus>(&output.stdout) {
            Ok(status) => {
                let unlocked = status.status == "unlocked";
                output.finish(None, Some(&status.status));
                Ok(unlocked)
            }
            Err(_) => {
                log_bw_parse_error("status");
                output.finish(Some("parse"), None);
                Ok(false)
            }
        }
    }

    async fn establish_session(
        &mut self,
        login_args: &[String],
        password: &Secret,
        context: BwAttemptContext,
    ) -> Result<(), ErrorCode> {
        let session = Secret::new(
            self.login_with_password(login_args, password, context)
                .await?,
        );
        // A fresh session is verified once with `bw status`. CLI releases before 2025.12.1 can lose
        // the session-key persistence race (bitwarden/clients#17707) and hand back a session that
        // later commands treat as locked; the daemon requires 2025.12.1 or newer and reports such a
        // session as a failure.
        if self.session_is_unlocked(&session, context).await? {
            self.session = Some(session);
            return Ok(());
        }
        self.session = None;
        self.unlocked_at = None;
        Err(ErrorCode::Internal)
    }

    async fn sync_session(&mut self, context: BwAttemptContext) -> Result<(), BwRunError> {
        self.last_sync_at = Some(Instant::now());
        let output = self
            .run_bw_with_timeout(
                &["sync".to_owned()],
                self.session.as_ref(),
                None,
                context,
                bw_sync_timeout(),
            )
            .await?;
        output.finish(None, None);
        Ok(())
    }

    async fn login_check(&self, context: BwAttemptContext) -> Result<bool, ErrorCode> {
        let args = vec!["login".to_owned(), "--check".to_owned()];
        match self
            .run_bw_unreported(&args, None, None, context, BW_COMMAND_TIMEOUT)
            .await
        {
            Ok(output) => {
                output.finish(None, Some("logged_in"));
                Ok(true)
            }
            // exit 1 は「未ログイン」という正常な回答であり、障害として診断行に載せない。
            Err((error @ BwRunError::NonZeroExit(_, _), diagnostic)) => {
                if error.exit_code() == Some(1) {
                    emit_bw_diag(diagnostic, None, Some("logged_out"));
                } else {
                    emit_bw_diag(diagnostic, Some(error.failure()), None);
                }
                Ok(false)
            }
            Err((error, diagnostic)) => {
                emit_bw_diag(diagnostic, Some(error.failure()), None);
                Err(classify_bw_run_error(&error))
            }
        }
    }

    async fn ensure_session(&mut self, context: BwAttemptContext) -> Result<(), BwOperationError> {
        if let (Some(_session), Some(unlocked_at)) = (&self.session, self.unlocked_at) {
            if unlocked_at.elapsed() < self.session_ttl {
                if should_resync(self.last_sync_at, Instant::now(), bw_resync_interval()) {
                    let _ = self.sync_session(context).await;
                }
                return Ok(());
            }
            self.expire_session().await;
        }

        let password = self.password().await?;
        // The bw CLI rejects `config server` for appdata with an active login. After a daemon
        // restart, the previous login state remains in appdata, so unconditional reconfiguration
        // always fails. Check the current configuration and do not reconfigure when it matches.
        let current_server = match self
            .run_bw_with_context(
                &["config".to_owned(), "server".to_owned()],
                None,
                None,
                context,
            )
            .await
        {
            Ok(output) => {
                let current_server = std::str::from_utf8(&output.stdout)
                    .ok()
                    .map(|value| value.trim().to_owned());
                output.finish(None, None);
                current_server
            }
            Err(error) => {
                return Err(BwOperationError::Normal(classify_bw_run_error(&error)));
            }
        };
        if current_server.as_deref() != Some(self.server_url.as_str()) {
            // If the server differs, the login state must be discarded before changing the configuration.
            let logged_in = self.login_check(context).await?;
            if logged_in {
                // logout の失敗は従来どおり致命としない。失敗は診断行にのみ残して続行する。
                let _ = self
                    .run_bw_with_context(&["logout".to_owned()], None, None, context)
                    .await;
            }
            self.run_bw_with_context(
                &[
                    "config".to_owned(),
                    "server".to_owned(),
                    self.server_url.clone(),
                ],
                None,
                None,
                context,
            )
            .await
            .map_err(|error| classify_bw_run_error(&error))?;
        }
        let logged_in = self.login_check(context).await?;
        let login_args = if logged_in {
            vec!["unlock".to_owned(), "--raw".to_owned()]
        } else {
            vec!["login".to_owned(), self.email.clone(), "--raw".to_owned()]
        };
        self.establish_session(&login_args, &password, context)
            .await?;
        drop(password);
        if let Err(error) = self.sync_session(context).await {
            self.session = None;
            self.unlocked_at = None;
            if !should_retry_login_after_sync(&error) {
                return Err(BwOperationError::NoColdStartRetry(classify_bw_run_error(
                    &error,
                )));
            }
            let _ = self
                .run_bw_with_context(&["logout".to_owned()], None, None, context)
                .await;

            let password = self.password().await?;
            let login_args = vec!["login".to_owned(), self.email.clone(), "--raw".to_owned()];
            self.establish_session(&login_args, &password, context)
                .await?;
            drop(password);
            if let Err(error) = self.sync_session(context).await {
                self.session = None;
                self.unlocked_at = None;
                return Err(classify_second_sync_failure(&error));
            }
        }
        self.unlocked_at = Some(Instant::now());
        self.locked = false;
        Ok(())
    }

    async fn lock_session(&mut self) -> Result<(), ErrorCode> {
        let result = if let Some(session) = self.session.as_ref() {
            self.run_bw(&["lock".to_owned()], Some(session), None)
                .await
                .map(|_| ())
                .map_err(|error| classify_bw_run_error(&error))
        } else {
            Ok(())
        };
        self.session = None;
        self.unlocked_at = None;
        result
    }

    async fn expire_session(&mut self) {
        if self
            .unlocked_at
            .is_some_and(|unlocked_at| unlocked_at.elapsed() >= self.session_ttl)
        {
            let _ = self.lock_session().await;
            self.locked = true;
            self.autolock_event_pending = true;
        }
    }

    async fn list_items(
        &mut self,
        context: BwAttemptContext,
    ) -> Result<Vec<BitwardenItem>, BwOperationError> {
        self.ensure_session(context).await?;
        let output = self
            .run_bw_with_context(
                &["list".to_owned(), "items".to_owned()],
                self.session.as_ref(),
                None,
                context,
            )
            .await
            .map_err(|error| BwOperationError::Normal(classify_bw_run_error(&error)))?;
        match serde_json::from_slice::<Vec<BitwardenItem>>(&output.stdout) {
            Ok(items) => {
                output.finish(None, None);
                Ok(items)
            }
            Err(_) => {
                log_bw_parse_error("list items");
                output.finish(Some("parse"), None);
                Err(BwOperationError::Normal(ErrorCode::Internal))
            }
        }
    }

    async fn get_item(&mut self, item_id: &str) -> Result<BitwardenItem, ErrorCode> {
        let context = BwAttemptContext::new(false, 1);
        self.ensure_session(context)
            .await
            .map_err(BwOperationError::into_error_code)?;
        let output = self
            .run_bw_with_context(
                &["get".to_owned(), "item".to_owned(), item_id.to_owned()],
                self.session.as_ref(),
                None,
                context,
            )
            .await
            .map_err(|_| ErrorCode::InvalidCredential)?;
        match serde_json::from_slice::<BitwardenItem>(&output.stdout) {
            Ok(item) => {
                output.finish(None, None);
                Ok(item)
            }
            Err(_) => {
                log_bw_parse_error("get item");
                output.finish(Some("parse"), None);
                Err(ErrorCode::InvalidCredential)
            }
        }
    }

    async fn list_refs_inner(&mut self) -> Result<Vec<CredentialRef>, ErrorCode> {
        if self.locked {
            return Ok(self
                .catalog
                .iter()
                .map(|item| CredentialRef {
                    id: item.id.clone(),
                    name: item.name.clone(),
                    uri: None,
                    kind: None,
                })
                .collect());
        }
        // cold start は、ロックされておらず catalog がまだ一度も埋まっていない状態を指す。
        // ロック中は直前の分岐で返しているため、ここでは catalog の空判定のみで足りる。
        let context = BwAttemptContext::new(self.catalog.is_empty(), 1);
        let method = crate::current_rpc_method();
        let retry_cold_start = can_retry_cold_start(context, method.as_deref());
        let items = match self.list_items(context).await {
            Err(error) if retry_cold_start && error.can_retry_cold_start() => {
                sleep(Duration::from_secs(2)).await;
                self.list_items(context.with_attempt(2))
                    .await
                    .map_err(BwOperationError::into_error_code)?
            }
            result => result.map_err(BwOperationError::into_error_code)?,
        };
        self.catalog = items
            .iter()
            .filter_map(|item| {
                item.login.as_ref()?;
                Some(BitwardenCatalogItem {
                    id: item.id.clone(),
                    name: item.name.clone(),
                })
            })
            .collect();
        Ok(items
            .into_iter()
            .filter_map(|item| {
                let login = item.login?;
                let uri = login
                    .uris
                    .first()
                    .and_then(|uri| uri.uri.clone())
                    .unwrap_or_default();
                Some(CredentialRef {
                    id: item.id,
                    name: item.name,
                    uri: Some(uri),
                    kind: Some("login".to_owned()),
                })
            })
            .collect())
    }

    async fn resolve_inner(
        &mut self,
        item_id: String,
    ) -> Result<Option<ResolvedCredential>, ErrorCode> {
        let item = self.get_item(&item_id).await?;
        let login = item.login.ok_or(ErrorCode::InvalidCredential)?;
        if !self.catalog.iter().any(|cached| cached.id == item.id) {
            self.catalog.push(BitwardenCatalogItem {
                id: item.id.clone(),
                name: item.name.clone(),
            });
        }
        let expose_totp = self.totp_exposable.iter().any(|name| name == &item.name);
        let uri = login.uris.into_iter().next().and_then(|uri| uri.uri);
        Ok(Some(ResolvedCredential {
            locked: self.locked,
            secrets_preregistered: false,
            uri,
            username: Secret::new(login.username.unwrap_or_default()),
            password: Secret::new(login.password.unwrap_or_default()),
            totp_seed: login.totp.map(Secret::new),
            totp_exposable: expose_totp,
        }))
    }
}

fn can_retry_cold_start(context: BwAttemptContext, method: Option<&str>) -> bool {
    context.cold_start && method == Some("list_credentials")
}

fn should_resync(last_sync_at: Option<Instant>, now: Instant, interval: Duration) -> bool {
    last_sync_at.is_none_or(|last_sync_at| now.duration_since(last_sync_at) >= interval)
}

fn should_retry_login_after_sync(error: &BwRunError) -> bool {
    matches!(error, BwRunError::NonZeroExit(_, _))
}

fn classify_second_sync_failure(error: &BwRunError) -> BwOperationError {
    let error_code = classify_bw_run_error(error);
    if should_retry_login_after_sync(error) {
        BwOperationError::Normal(error_code)
    } else {
        BwOperationError::NoColdStartRetry(error_code)
    }
}

impl CredentialProvider for BitwardenCliProvider {
    fn list_refs(&mut self) -> ProviderFuture<'_, Vec<CredentialRef>> {
        Box::pin(self.list_refs_inner())
    }

    fn resolve(&mut self, entry_id: &str) -> ProviderFuture<'_, Option<ResolvedCredential>> {
        let entry_id = entry_id.to_owned();
        Box::pin(self.resolve_inner(entry_id))
    }

    fn lock(&mut self) -> ProviderFuture<'_, ()> {
        Box::pin(async move {
            self.lock_session().await?;
            self.locked = true;
            Ok(())
        })
    }

    fn expire(&mut self) -> ProviderFuture<'_, ()> {
        Box::pin(async move {
            self.expire_session().await;
            Ok(())
        })
    }

    fn locked(&self) -> bool {
        self.locked
    }

    fn take_autolock_event(&mut self) -> bool {
        std::mem::take(&mut self.autolock_event_pending)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BwAttemptContext, BwOperationError, BwRunError, can_retry_cold_start,
        classify_bw_run_error, classify_second_sync_failure, issued_session_secrets,
        sanitize_stderr, should_resync, should_retry_login_after_sync,
    };
    use crate::ErrorCode;
    use std::path::Path;
    use std::time::Duration;
    use tokio::time::Instant;

    #[test]
    fn classifies_process_and_timeout_as_provider_unavailable() {
        assert!(matches!(
            classify_bw_run_error(&BwRunError::Process(
                std::io::Error::other("process"),
                Vec::new(),
            )),
            ErrorCode::ProviderUnavailable
        ));
        assert!(matches!(
            classify_bw_run_error(&BwRunError::Timeout(Vec::new())),
            ErrorCode::ProviderUnavailable
        ));
    }

    #[test]
    fn classifies_nonzero_exit_as_provider_unavailable() {
        #[cfg(unix)]
        let status = std::process::Command::new("sh")
            .args(["-c", "exit 1"])
            .status()
            .expect("spawn shell");
        #[cfg(windows)]
        let status = std::process::Command::new("cmd")
            .args(["/C", "exit", "1"])
            .status()
            .expect("spawn command shell");
        assert!(matches!(
            classify_bw_run_error(&BwRunError::NonZeroExit(status, Vec::new())),
            ErrorCode::ProviderUnavailable
        ));
    }

    #[test]
    fn classifies_create_dir_as_internal() {
        assert!(matches!(
            classify_bw_run_error(&BwRunError::CreateDir(std::io::Error::other("directory"))),
            ErrorCode::Internal
        ));
    }

    #[test]
    fn masks_issued_session_key_in_stderr() {
        let args = vec![
            "login".to_owned(),
            "user@example.test".to_owned(),
            "--raw".to_owned(),
        ];
        let issued = issued_session_secrets(&args, b"issued-session-key\r\n");
        let stderr = format!("{}issued-session-key", "x".repeat(290));
        let sanitized = sanitize_stderr(
            stderr.as_bytes(),
            Path::new("/nonexistent/appdata"),
            "user@example.test",
            None,
            None,
            &issued,
        );
        // 切り詰めより前にマスクされるため、300 バイト境界をまたぐ session key の断片も残らない。
        assert_eq!(sanitized, format!("{}[REDACTED]", "x".repeat(290)));
        assert_eq!(
            issued_session_secrets(&["unlock".to_owned(), "--raw".to_owned()], b"key\n"),
            vec!["key".to_owned()]
        );
    }

    #[test]
    fn does_not_treat_other_stdout_as_session_key() {
        assert!(
            issued_session_secrets(&["login".to_owned(), "--check".to_owned()], b"out").is_empty()
        );
        assert!(issued_session_secrets(&["sync".to_owned()], b"out").is_empty());
    }

    #[test]
    fn io_error_kind_reports_not_found_for_missing_binary() {
        let error = std::process::Command::new("tegata-bw-that-does-not-exist")
            .status()
            .expect_err("missing binary should fail to spawn");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        let run_error = BwRunError::Process(error, Vec::new());
        assert_eq!(
            run_error.io_error_kind(),
            Some(std::io::ErrorKind::NotFound)
        );
        assert_eq!(
            format!("{:?}", run_error.io_error_kind().unwrap()),
            "NotFound"
        );
    }

    #[test]
    fn retries_cold_start_only_for_list_credentials_rpc() {
        let context = BwAttemptContext::new(true, 1);
        assert!(can_retry_cold_start(context, Some("list_credentials")));
        assert!(!can_retry_cold_start(context, Some("login")));
        assert!(!can_retry_cold_start(context, Some("status")));
        assert!(!can_retry_cold_start(context, None));
    }

    #[test]
    fn resyncs_when_the_last_attempt_is_missing_or_due() {
        let std_now = std::time::Instant::now();
        let now = Instant::from_std(std_now);
        let old = Instant::from_std(std_now - Duration::from_secs(60));
        assert!(should_resync(None, now, Duration::from_secs(60)));
        assert!(!should_resync(Some(now), now, Duration::from_secs(60)));
        assert!(should_resync(Some(old), now, Duration::from_secs(60)));
        assert!(should_resync(Some(now), now, Duration::ZERO));
    }

    #[test]
    fn retries_login_only_after_a_nonzero_sync_exit() {
        assert!(!should_retry_login_after_sync(&BwRunError::Timeout(
            Vec::new()
        )));
        assert!(!should_retry_login_after_sync(&BwRunError::Process(
            std::io::Error::other("process"),
            Vec::new(),
        )));
        assert!(!should_retry_login_after_sync(&BwRunError::CreateDir(
            std::io::Error::other("directory"),
        )));

        #[cfg(unix)]
        let status = std::process::Command::new("sh")
            .args(["-c", "exit 1"])
            .status()
            .expect("spawn shell");
        #[cfg(windows)]
        let status = std::process::Command::new("cmd")
            .args(["/C", "exit", "1"])
            .status()
            .expect("spawn command shell");
        assert!(should_retry_login_after_sync(&BwRunError::NonZeroExit(
            status,
            Vec::new(),
        )));
    }

    #[test]
    fn classifies_second_sync_failure_by_failure_kind() {
        assert!(matches!(
            classify_second_sync_failure(&BwRunError::Timeout(Vec::new())),
            BwOperationError::NoColdStartRetry(ErrorCode::ProviderUnavailable)
        ));
        assert!(matches!(
            classify_second_sync_failure(&BwRunError::Process(
                std::io::Error::other("process"),
                Vec::new(),
            )),
            BwOperationError::NoColdStartRetry(ErrorCode::ProviderUnavailable)
        ));

        #[cfg(unix)]
        let status = std::process::Command::new("sh")
            .args(["-c", "exit 1"])
            .status()
            .expect("spawn shell");
        #[cfg(windows)]
        let status = std::process::Command::new("cmd")
            .args(["/C", "exit", "1"])
            .status()
            .expect("spawn command shell");
        assert!(matches!(
            classify_second_sync_failure(&BwRunError::NonZeroExit(status, Vec::new())),
            BwOperationError::Normal(ErrorCode::ProviderUnavailable)
        ));
    }
}
