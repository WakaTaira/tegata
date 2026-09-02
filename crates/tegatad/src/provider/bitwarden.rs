use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tegata_core::Secret;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::{Instant, timeout};

use super::{CredentialProvider, CredentialRef, ProviderFuture, ResolvedCredential};
use crate::ErrorCode;
#[cfg(windows)]
use crate::UnlockMode;

const BW_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct BitwardenCliProvider {
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
    stderr: Vec<u8>,
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
}

fn log_bw_stderr(operation: &str, stderr: &[u8]) {
    if !stderr.is_empty() {
        let end = stderr.len().min(300);
        eprintln!(
            "tegatad: bw {operation} stderr: {}",
            String::from_utf8_lossy(&stderr[..end])
        );
    }
}

fn log_bw_error(operation: &str, error: &BwRunError) {
    eprintln!("tegatad: bw {operation} failed: {error}");
    log_bw_stderr(operation, error.stderr());
}

fn log_bw_parse_error(operation: &str, stderr: &[u8]) {
    eprintln!("tegatad: bw {operation} returned invalid JSON");
    log_bw_stderr(operation, stderr);
}

impl BitwardenCliProvider {
    pub(crate) fn new(config: BitwardenCliConfig) -> Self {
        Self {
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

    async fn run_bw(
        &self,
        args: &[String],
        session: Option<&Secret>,
        password: Option<&Secret>,
    ) -> Result<BwOutput, BwRunError> {
        tokio::fs::create_dir_all(&self.appdata_dir)
            .await
            .map_err(BwRunError::CreateDir)?;
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
        match command.spawn() {
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
                            Ok(BwOutput {
                                stdout: std::mem::take(&mut stdout_output),
                                stderr: std::mem::take(&mut stderr_output),
                            })
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
    ) -> Result<String, ErrorCode> {
        let session = self
            .run_bw(login_args, None, Some(password))
            .await
            .map_err(|error| {
                log_bw_error("login or unlock", &error);
                ErrorCode::Internal
            })?;
        String::from_utf8(session.stdout)
            .ok()
            .and_then(|value| value.lines().next().map(ToOwned::to_owned))
            .map(|value| value.trim_end_matches('\r').to_owned())
            .filter(|value| !value.is_empty())
            .ok_or(ErrorCode::Internal)
    }

    async fn session_is_unlocked(&self, session: &Secret) -> bool {
        let output = match self
            .run_bw(&["status".to_owned()], Some(session), None)
            .await
        {
            Ok(output) => output,
            Err(error) => {
                log_bw_error("status", &error);
                return false;
            }
        };
        match serde_json::from_slice::<BitwardenStatus>(&output.stdout) {
            Ok(status) => status.status == "unlocked",
            Err(_) => {
                log_bw_parse_error("status", &output.stderr);
                false
            }
        }
    }

    async fn establish_session(
        &mut self,
        login_args: &[String],
        password: &Secret,
    ) -> Result<(), ErrorCode> {
        let session = Secret::new(self.login_with_password(login_args, password).await?);
        // A fresh session is verified once with `bw status`. CLI releases before 2025.12.1 can lose
        // the session-key persistence race (bitwarden/clients#17707) and hand back a session that
        // later commands treat as locked; the daemon requires 2025.12.1 or newer and reports such a
        // session as a failure.
        if self.session_is_unlocked(&session).await {
            self.session = Some(session);
            return Ok(());
        }
        self.session = None;
        self.unlocked_at = None;
        Err(ErrorCode::Internal)
    }

    async fn ensure_session(&mut self) -> Result<(), ErrorCode> {
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
            .run_bw(&["config".to_owned(), "server".to_owned()], None, None)
            .await
        {
            Ok(output) => String::from_utf8(output.stdout)
                .ok()
                .map(|value| value.trim().to_owned()),
            Err(error) => {
                log_bw_error("config server", &error);
                None
            }
        };
        if current_server.as_deref() != Some(self.server_url.as_str()) {
            // If the server differs, the login state must be discarded before changing the configuration.
            let logged_in = match self
                .run_bw(&["login".to_owned(), "--check".to_owned()], None, None)
                .await
            {
                Ok(_) => true,
                Err(error) => {
                    log_bw_error("login check", &error);
                    false
                }
            };
            if logged_in && let Err(error) = self.run_bw(&["logout".to_owned()], None, None).await {
                log_bw_error("logout", &error);
            }
            self.run_bw(
                &[
                    "config".to_owned(),
                    "server".to_owned(),
                    self.server_url.clone(),
                ],
                None,
                None,
            )
            .await
            .map_err(|error| {
                log_bw_error("config server", &error);
                ErrorCode::Internal
            })?;
        }
        let logged_in = match self
            .run_bw(&["login".to_owned(), "--check".to_owned()], None, None)
            .await
        {
            Ok(_) => true,
            Err(error) => {
                log_bw_error("login check", &error);
                false
            }
        };
        let login_args = if logged_in {
            vec!["unlock".to_owned(), "--raw".to_owned()]
        } else {
            vec!["login".to_owned(), self.email.clone(), "--raw".to_owned()]
        };
        self.establish_session(&login_args, &password).await?;
        drop(password);
        if let Err(error) = self
            .run_bw(&["sync".to_owned()], self.session.as_ref(), None)
            .await
        {
            log_bw_error("sync", &error);
            self.session = None;
            self.unlocked_at = None;
            if let Err(error) = self.run_bw(&["logout".to_owned()], None, None).await {
                log_bw_error("logout", &error);
            }

            let password = self.password().await?;
            let login_args = vec!["login".to_owned(), self.email.clone(), "--raw".to_owned()];
            self.establish_session(&login_args, &password).await?;
            drop(password);
            if let Err(error) = self
                .run_bw(&["sync".to_owned()], self.session.as_ref(), None)
                .await
            {
                log_bw_error("sync", &error);
                self.session = None;
                self.unlocked_at = None;
                return Err(ErrorCode::Internal);
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
                    ErrorCode::Internal
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

    async fn list_items(&mut self) -> Result<Vec<BitwardenItem>, ErrorCode> {
        self.ensure_session().await?;
        let output = self
            .run_bw(
                &["list".to_owned(), "items".to_owned()],
                self.session.as_ref(),
                None,
            )
            .await
            .map_err(|error| {
                log_bw_error("list items", &error);
                ErrorCode::Internal
            })?;
        match serde_json::from_slice::<Vec<BitwardenItem>>(&output.stdout) {
            Ok(items) => Ok(items),
            Err(_) => {
                log_bw_parse_error("list items", &output.stderr);
                Err(ErrorCode::Internal)
            }
        }
    }

    async fn get_item(&mut self, item_id: &str) -> Result<BitwardenItem, ErrorCode> {
        self.ensure_session().await?;
        let output = self
            .run_bw(
                &["get".to_owned(), "item".to_owned(), item_id.to_owned()],
                self.session.as_ref(),
                None,
            )
            .await
            .map_err(|error| {
                log_bw_error("get item", &error);
                ErrorCode::InvalidCredential
            })?;
        match serde_json::from_slice::<BitwardenItem>(&output.stdout) {
            Ok(item) => Ok(item),
            Err(_) => {
                log_bw_parse_error("get item", &output.stderr);
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
        let items = self.list_items().await?;
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
