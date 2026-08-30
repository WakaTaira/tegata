use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tegata_core::Secret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time::{Instant, timeout};
use uuid::Uuid;

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
    password_dir: PathBuf,
    bw_path: Option<PathBuf>,
    totp_exposable: Vec<String>,
    session_ttl: Duration,
    session: Option<Secret>,
    unlocked_at: Option<Instant>,
    locked: bool,
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
    pub(crate) password_dir: PathBuf,
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

#[derive(Debug)]
enum BwRunError {
    CreateDir(io::Error),
    PasswordFile(io::Error),
    Process(io::Error),
    NonZeroExit(std::process::ExitStatus),
    Timeout,
}

impl fmt::Display for BwRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDir(error) => {
                write!(formatter, "could not create appdata directory: {error}")
            }
            Self::PasswordFile(error) => {
                write!(formatter, "could not prepare password file: {error}")
            }
            Self::Process(error) => write!(formatter, "could not run bw: {error}"),
            Self::NonZeroExit(status) => write!(
                formatter,
                "bw exited unsuccessfully with status {}",
                status
                    .code()
                    .map_or_else(|| "signal".to_owned(), |code| code.to_string()),
            ),
            Self::Timeout => write!(formatter, "bw command timed out"),
        }
    }
}

impl std::error::Error for BwRunError {}

fn log_bw_error(operation: &str, error: &BwRunError) {
    eprintln!("tegatad: bw {operation} failed: {error}");
}

impl BitwardenCliProvider {
    pub(crate) fn new(config: BitwardenCliConfig) -> Self {
        Self {
            server_url: config.server_url,
            email: config.email,
            askpass_cmd: config.askpass_cmd,
            appdata_dir: config.appdata_dir,
            password_dir: config.password_dir,
            bw_path: config.bw_path,
            totp_exposable: config.totp_exposable,
            session_ttl: config.session_ttl,
            session: None,
            unlocked_at: None,
            locked: false,
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
    ) -> Result<Vec<u8>, BwRunError> {
        tokio::fs::create_dir_all(&self.appdata_dir)
            .await
            .map_err(BwRunError::CreateDir)?;
        tokio::fs::create_dir_all(&self.password_dir)
            .await
            .map_err(BwRunError::CreateDir)?;
        crate::secure_fs::restrict_directory(&self.password_dir)
            .await
            .map_err(BwRunError::CreateDir)?;
        let password_file = if let Some(password) = password {
            let path = self
                .password_dir
                .join(format!(".bw-password-{}", Uuid::new_v4()));
            let guard = PasswordFileGuard::new(path.clone());
            let mut file = match crate::secure_fs::create_private_file(&path).await {
                Ok(file) => file,
                Err(error) => {
                    drop(guard);
                    return Err(BwRunError::PasswordFile(error));
                }
            };
            let mut bytes = password.as_str().as_bytes().to_vec();
            let write_result = file.write_all(&bytes).await;
            let write_result = match write_result {
                Ok(()) => file.flush().await,
                Err(error) => Err(error),
            };
            bytes.fill(0);
            if let Err(error) = write_result {
                drop(file);
                remove_password_file(&path).await;
                return Err(BwRunError::PasswordFile(error));
            }
            drop(file);
            Some((path, guard))
        } else {
            None
        };
        let mut command_args = args.to_vec();
        if let Some((path, _)) = &password_file {
            command_args.push("--passwordfile".to_owned());
            command_args.push(path.to_string_lossy().into_owned());
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
            .stderr(std::process::Stdio::null());
        if let Some(session) = session {
            command.env("BW_SESSION", session.as_str());
        }
        let result = match command.spawn() {
            Ok(mut child) => match child.stdout.take() {
                Some(mut stdout) => match timeout(BW_COMMAND_TIMEOUT, async {
                    let mut output = Vec::new();
                    let (status, read_result) =
                        tokio::join!(child.wait(), stdout.read_to_end(&mut output));
                    let status = status.map_err(BwRunError::Process)?;
                    read_result.map_err(BwRunError::Process)?;
                    if status.success() {
                        Ok(output)
                    } else {
                        Err(BwRunError::NonZeroExit(status))
                    }
                })
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        let _ = child.start_kill();
                        let _ = child.wait().await;
                        Err(BwRunError::Timeout)
                    }
                },
                None => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    let error =
                        io::Error::new(io::ErrorKind::BrokenPipe, "bw stdout was not piped");
                    Err(BwRunError::Process(error))
                }
            },
            Err(error) => Err(BwRunError::Process(error)),
        };
        if let Some((path, _)) = password_file {
            remove_password_file(&path).await;
        }
        result
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
        String::from_utf8(session)
            .ok()
            .and_then(|value| value.lines().next().map(ToOwned::to_owned))
            .map(|value| value.trim_end_matches('\r').to_owned())
            .filter(|value| !value.is_empty())
            .ok_or(ErrorCode::Internal)
    }

    async fn ensure_session(&mut self) -> Result<(), ErrorCode> {
        if let (Some(_session), Some(unlocked_at)) = (&self.session, self.unlocked_at) {
            if unlocked_at.elapsed() < self.session_ttl {
                return Ok(());
            }
            let _ = self.lock_session().await;
            self.locked = true;
            return Err(ErrorCode::VaultLocked);
        }

        let password = self.password().await?;
        // bw CLI はログイン済みの appdata に対して `config server` を拒否する。デーモン
        // 再起動後は前回のログイン状態が appdata に残っているため、無条件の再設定は
        // 必ず失敗する。現在の設定値を確認し、一致している場合は再設定しない。
        let current_server = self
            .run_bw(&["config".to_owned(), "server".to_owned()], None, None)
            .await
            .ok()
            .and_then(|output| String::from_utf8(output).ok())
            .map(|value| value.trim().to_owned());
        if current_server.as_deref() != Some(self.server_url.as_str()) {
            // If the server differs, the login state must be discarded before changing the configuration.
            if self
                .run_bw(&["login".to_owned(), "--check".to_owned()], None, None)
                .await
                .is_ok()
            {
                let _ = self.run_bw(&["logout".to_owned()], None, None).await;
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
            Err(BwRunError::NonZeroExit(_)) => false,
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
        let session = self.login_with_password(&login_args, &password).await?;
        drop(password);
        self.session = Some(Secret::new(session));
        if let Err(_error) = self
            .run_bw(&["sync".to_owned()], self.session.as_ref(), None)
            .await
        {
            self.session = None;
            self.unlocked_at = None;
            let _ = self.run_bw(&["logout".to_owned()], None, None).await;

            let password = self.password().await?;
            let login_args = vec!["login".to_owned(), self.email.clone(), "--raw".to_owned()];
            let session = self.login_with_password(&login_args, &password).await?;
            drop(password);
            self.session = Some(Secret::new(session));
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
        serde_json::from_slice(&output).map_err(|_| ErrorCode::Internal)
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
        serde_json::from_slice(&output).map_err(|_| ErrorCode::InvalidCredential)
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
            register_secrets: false,
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
}

struct PasswordFileGuard {
    path: Option<PathBuf>,
}

impl PasswordFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }
}

impl Drop for PasswordFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            remove_password_file_sync(&path);
        }
    }
}

fn remove_password_file_sync(path: &Path) {
    if let Ok(metadata) = std::fs::metadata(path)
        && let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(path)
    {
        let mut remaining = metadata.len();
        let zeros = [0_u8; 8192];
        while remaining > 0 {
            let count = remaining.min(zeros.len() as u64) as usize;
            if std::io::Write::write_all(&mut file, &zeros[..count]).is_err() {
                break;
            }
            remaining -= count as u64;
        }
        let _ = std::io::Write::flush(&mut file);
    }
    let _ = std::fs::remove_file(path);
}

pub(crate) async fn remove_password_file(path: &Path) {
    if let Ok(metadata) = tokio::fs::metadata(path).await
        && let Ok(mut file) = tokio::fs::OpenOptions::new().write(true).open(path).await
    {
        let mut remaining = metadata.len();
        let zeros = [0_u8; 8192];
        while remaining > 0 {
            let count = remaining.min(zeros.len() as u64) as usize;
            if file.write_all(&zeros[..count]).await.is_err() {
                break;
            }
            remaining -= count as u64;
        }
        let _ = file.flush().await;
    }
    let _ = tokio::fs::remove_file(path).await;
}
