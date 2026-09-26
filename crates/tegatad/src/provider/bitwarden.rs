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
}

struct BwDiagnosticInput<'a> {
    args: &'a [String],
    session: Option<&'a Secret>,
    password: Option<&'a Secret>,
    cold_start: bool,
    attempt: u32,
    started_at: Instant,
    exit_code: Option<i32>,
    stderr: &'a [u8],
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
            Self::CreateDir(_) => "spawn",
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
}

fn classify_bw_run_error(error: &BwRunError) -> ErrorCode {
    match error {
        BwRunError::Process(_, _) | BwRunError::NonZeroExit(_, _) | BwRunError::Timeout(_) => {
            ErrorCode::ProviderUnavailable
        }
        BwRunError::CreateDir(_) => ErrorCode::Internal,
    }
}

fn log_bw_error(operation: &str, error: &BwRunError) {
    eprintln!("tegatad: bw {operation} failed: {error}");
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
    .filter(|sensitive| !sensitive.is_empty())
    {
        value = value.replace(sensitive, "[REDACTED]");
    }
    truncate_utf8(value)
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
        let version = String::from_utf8(output.stdout.clone())
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
        self.run_bw_with_context(args, session, password, false, 1)
            .await
    }

    async fn run_bw_with_context(
        &self,
        args: &[String],
        session: Option<&Secret>,
        password: Option<&Secret>,
        cold_start: bool,
        attempt: u32,
    ) -> Result<BwOutput, BwRunError> {
        tokio::fs::create_dir_all(&self.appdata_dir)
            .await
            .map_err(BwRunError::CreateDir)?;
        let started_at = Instant::now();
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
        let result = match command.spawn() {
            Ok(mut child) => match (child.stdout.take(), child.stderr.take()) {
                (Some(mut stdout), Some(mut stderr)) => {
                    let mut stdout_output = Vec::new();
                    let mut stderr_output = Vec::new();
                    match timeout(BW_COMMAND_TIMEOUT, async {
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
                            let _ = child.start_kill();
                            let _ = child.wait().await;
                            let _ = stderr.read_to_end(&mut stderr_output).await;
                            Err(BwRunError::Timeout(stderr_output))
                        }
                    }
                }
                (stdout, stderr) => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    let mut stderr_output = Vec::new();
                    if let Some(mut stderr) = stderr {
                        let _ = stderr.read_to_end(&mut stderr_output).await;
                    }
                    let message = if stdout.is_none() {
                        "bw stdout was not piped"
                    } else {
                        "bw stderr was not piped"
                    };
                    let error = io::Error::new(io::ErrorKind::BrokenPipe, message);
                    Err(BwRunError::Process(error, stderr_output))
                }
            },
            Err(error) => Err(BwRunError::Process(error, Vec::new())),
        };
        match result {
            Ok((stdout, stderr, exit_code)) => Ok(BwOutput {
                stdout,
                diagnostic: Some(self.diagnostic_base(BwDiagnosticInput {
                    args,
                    session,
                    password,
                    cold_start,
                    attempt,
                    started_at,
                    exit_code,
                    stderr: &stderr,
                })),
            }),
            Err(error) => {
                if !matches!(error, BwRunError::CreateDir(_)) {
                    let diagnostic = self.diagnostic_base(BwDiagnosticInput {
                        args,
                        session,
                        password,
                        cold_start,
                        attempt,
                        started_at,
                        exit_code: error.exit_code(),
                        stderr: error.stderr(),
                    });
                    emit_bw_diag(diagnostic, Some(error.failure()), None);
                }
                Err(error)
            }
        }
    }

    fn diagnostic_base(&self, input: BwDiagnosticInput<'_>) -> BwDiagnosticBase {
        BwDiagnosticBase {
            rpc_id: crate::current_rpc_id().map_or_else(
                || serde_json::json!("startup"),
                |rpc_id| serde_json::json!(rpc_id),
            ),
            namespace: self.namespace.clone(),
            cold_start: input.cold_start,
            op: operation_name(input.args),
            attempt: input.attempt,
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
            ),
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
        cold_start: bool,
        attempt: u32,
    ) -> Result<String, ErrorCode> {
        let mut session = self
            .run_bw_with_context(login_args, None, Some(password), cold_start, attempt)
            .await
            .map_err(|error| {
                log_bw_error("login or unlock", &error);
                classify_bw_run_error(&error)
            })?;
        let value = String::from_utf8(std::mem::take(&mut session.stdout))
            .ok()
            .and_then(|value| value.lines().next().map(ToOwned::to_owned))
            .map(|value| value.trim_end_matches('\r').to_owned())
            .filter(|value| !value.is_empty());
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
        cold_start: bool,
        attempt: u32,
    ) -> Result<bool, ErrorCode> {
        let output = match self
            .run_bw_with_context(
                &["status".to_owned()],
                Some(session),
                None,
                cold_start,
                attempt,
            )
            .await
        {
            Ok(output) => output,
            Err(error) => {
                log_bw_error("status", &error);
                return Err(classify_bw_run_error(&error));
            }
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
        cold_start: bool,
        attempt: u32,
    ) -> Result<(), ErrorCode> {
        let session = Secret::new(
            self.login_with_password(login_args, password, cold_start, attempt)
                .await?,
        );
        // A fresh session is verified once with `bw status`. CLI releases before 2025.12.1 can lose
        // the session-key persistence race (bitwarden/clients#17707) and hand back a session that
        // later commands treat as locked; the daemon requires 2025.12.1 or newer and reports such a
        // session as a failure.
        if self
            .session_is_unlocked(&session, cold_start, attempt)
            .await?
        {
            self.session = Some(session);
            return Ok(());
        }
        self.session = None;
        self.unlocked_at = None;
        Err(ErrorCode::Internal)
    }

    async fn login_check(&self, cold_start: bool, attempt: u32) -> Result<bool, ErrorCode> {
        let args = vec!["login".to_owned(), "--check".to_owned()];
        match self
            .run_bw_with_context(&args, None, None, cold_start, attempt)
            .await
        {
            Ok(output) => {
                output.finish(None, None);
                Ok(true)
            }
            Err(BwRunError::NonZeroExit(_, _)) => Ok(false),
            Err(error) => {
                log_bw_error("login check", &error);
                Err(classify_bw_run_error(&error))
            }
        }
    }

    async fn ensure_session(&mut self, cold_start: bool, attempt: u32) -> Result<(), ErrorCode> {
        if let (Some(_session), Some(unlocked_at)) = (&self.session, self.unlocked_at) {
            if unlocked_at.elapsed() < self.session_ttl {
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
                cold_start,
                attempt,
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
                log_bw_error("config server", &error);
                None
            }
        };
        if current_server.as_deref() != Some(self.server_url.as_str()) {
            // If the server differs, the login state must be discarded before changing the configuration.
            let logged_in = self.login_check(cold_start, attempt).await?;
            if logged_in
                && let Err(error) = self
                    .run_bw_with_context(&["logout".to_owned()], None, None, cold_start, attempt)
                    .await
            {
                log_bw_error("logout", &error);
            }
            self.run_bw_with_context(
                &[
                    "config".to_owned(),
                    "server".to_owned(),
                    self.server_url.clone(),
                ],
                None,
                None,
                cold_start,
                attempt,
            )
            .await
            .map_err(|error| {
                log_bw_error("config server", &error);
                ErrorCode::Internal
            })?;
        }
        let logged_in = self.login_check(cold_start, attempt).await?;
        let login_args = if logged_in {
            vec!["unlock".to_owned(), "--raw".to_owned()]
        } else {
            vec!["login".to_owned(), self.email.clone(), "--raw".to_owned()]
        };
        self.establish_session(&login_args, &password, cold_start, attempt)
            .await?;
        drop(password);
        if let Err(error) = self
            .run_bw_with_context(
                &["sync".to_owned()],
                self.session.as_ref(),
                None,
                cold_start,
                attempt,
            )
            .await
        {
            log_bw_error("sync", &error);
            self.session = None;
            self.unlocked_at = None;
            if let Err(error) = self
                .run_bw_with_context(&["logout".to_owned()], None, None, cold_start, attempt)
                .await
            {
                log_bw_error("logout", &error);
            }

            let password = self.password().await?;
            let login_args = vec!["login".to_owned(), self.email.clone(), "--raw".to_owned()];
            self.establish_session(&login_args, &password, cold_start, attempt)
                .await?;
            drop(password);
            if let Err(error) = self
                .run_bw_with_context(
                    &["sync".to_owned()],
                    self.session.as_ref(),
                    None,
                    cold_start,
                    attempt,
                )
                .await
            {
                log_bw_error("sync", &error);
                self.session = None;
                self.unlocked_at = None;
                return Err(classify_bw_run_error(&error));
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
                .map_err(|error| {
                    log_bw_error("lock", &error);
                    classify_bw_run_error(&error)
                })
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
        cold_start: bool,
        attempt: u32,
    ) -> Result<Vec<BitwardenItem>, ErrorCode> {
        self.ensure_session(cold_start, attempt).await?;
        let output = self
            .run_bw_with_context(
                &["list".to_owned(), "items".to_owned()],
                self.session.as_ref(),
                None,
                cold_start,
                attempt,
            )
            .await
            .map_err(|error| {
                log_bw_error("list items", &error);
                classify_bw_run_error(&error)
            })?;
        match serde_json::from_slice::<Vec<BitwardenItem>>(&output.stdout) {
            Ok(items) => {
                output.finish(None, None);
                Ok(items)
            }
            Err(_) => {
                log_bw_parse_error("list items");
                output.finish(Some("parse"), None);
                Err(ErrorCode::Internal)
            }
        }
    }

    async fn get_item(&mut self, item_id: &str) -> Result<BitwardenItem, ErrorCode> {
        self.ensure_session(false, 1).await?;
        let output = self
            .run_bw_with_context(
                &["get".to_owned(), "item".to_owned(), item_id.to_owned()],
                self.session.as_ref(),
                None,
                false,
                1,
            )
            .await
            .map_err(|error| {
                log_bw_error("get item", &error);
                ErrorCode::InvalidCredential
            })?;
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
        let cold_start = self.catalog.is_empty() && !self.locked;
        let items = match self.list_items(cold_start, 1).await {
            Err(ErrorCode::ProviderUnavailable) if cold_start => {
                sleep(Duration::from_secs(2)).await;
                self.list_items(cold_start, 2).await?
            }
            result => result?,
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
        Ok(Some(ResolvedCredential {
            locked: self.locked,
            secrets_preregistered: false,
            username: Secret::new(login.username.unwrap_or_default()),
            password: Secret::new(login.password.unwrap_or_default()),
            totp_seed: login.totp.map(Secret::new),
            totp_exposable: expose_totp,
        }))
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
    use super::{BwRunError, classify_bw_run_error};
    use crate::ErrorCode;

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
}
