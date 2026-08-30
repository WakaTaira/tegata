use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tegata_core::Secret;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::{Instant, timeout};
use zeroize::Zeroize;

use super::{CredentialProvider, CredentialRef, ProviderFuture, ResolvedCredential};
use crate::ErrorCode;

const PASS_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct PassProviderConfig {
    pub(crate) store_dir: PathBuf,
    pub(crate) gnupghome: Option<PathBuf>,
    pub(crate) pass_bin: Option<PathBuf>,
    pub(crate) totp_exposable: Vec<String>,
    pub(crate) session_ttl: Duration,
}

struct PassCatalogItem {
    name: String,
}

struct PassEntry {
    username: Secret,
    password: Secret,
    totp_seed: Option<Secret>,
    totp_exposable: bool,
}

#[derive(Debug)]
enum PassRunError {
    Process(io::Error),
    NonZeroExit,
    InvalidOutput,
    Timeout,
}

impl fmt::Display for PassRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Process(error) => write!(formatter, "could not run pass: {error}"),
            Self::NonZeroExit => formatter.write_str("pass exited unsuccessfully"),
            Self::InvalidOutput => formatter.write_str("pass returned invalid output"),
            Self::Timeout => formatter.write_str("pass command timed out"),
        }
    }
}

impl std::error::Error for PassRunError {}

pub(crate) struct PassProvider {
    store_dir: PathBuf,
    gnupghome: Option<PathBuf>,
    pass_bin: PathBuf,
    totp_exposable: Vec<String>,
    session_ttl: Duration,
    catalog: Vec<PassCatalogItem>,
    entries: HashMap<String, PassEntry>,
    unlocked_at: Option<Instant>,
    locked: bool,
    autolock_event_pending: bool,
}

impl PassProvider {
    pub(crate) fn new(config: PassProviderConfig) -> Self {
        Self {
            store_dir: config.store_dir,
            gnupghome: config.gnupghome,
            pass_bin: config.pass_bin.unwrap_or_else(|| PathBuf::from("pass")),
            totp_exposable: config.totp_exposable,
            session_ttl: config.session_ttl,
            catalog: Vec::new(),
            entries: HashMap::new(),
            unlocked_at: None,
            locked: true,
            autolock_event_pending: false,
        }
    }

    fn clear_session(&mut self) {
        self.entries.clear();
        self.unlocked_at = None;
        self.locked = true;
    }

    fn scan_store(&mut self) -> Result<(), ErrorCode> {
        let mut names = Vec::new();
        scan_directory(&self.store_dir, &self.store_dir, &mut names)
            .map_err(|error| self.log_error("scan", error))?;
        names.sort();
        self.catalog = names
            .into_iter()
            .map(|name| PassCatalogItem { name })
            .collect();
        Ok(())
    }

    async fn run_pass(&self, name: &str) -> Result<String, PassRunError> {
        let mut command = Command::new(&self.pass_bin);
        command
            .args(["show", name])
            .env("PASSWORD_STORE_DIR", &self.store_dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        if let Some(gnupghome) = &self.gnupghome {
            command.env("GNUPGHOME", gnupghome);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.as_std_mut().process_group(0);
        }
        let mut child = command.spawn().map_err(PassRunError::Process)?;
        let Some(mut stdout) = child.stdout.take() else {
            #[cfg(unix)]
            crate::kill_process_group(&child);
            #[cfg(windows)]
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(PassRunError::InvalidOutput);
        };
        match timeout(PASS_COMMAND_TIMEOUT, async {
            let mut output = Vec::new();
            let (status, read_result) = tokio::join!(child.wait(), stdout.read_to_end(&mut output));
            let status = status.map_err(PassRunError::Process)?;
            read_result.map_err(PassRunError::Process)?;
            if status.success() {
                String::from_utf8(output).map_err(|error| {
                    let mut bytes = error.into_bytes();
                    bytes.zeroize();
                    PassRunError::InvalidOutput
                })
            } else {
                output.zeroize();
                Err(PassRunError::NonZeroExit)
            }
        })
        .await
        {
            Ok(result) => result,
            Err(_) => {
                crate::kill_process_group(&child);
                let _ = child.wait().await;
                Err(PassRunError::Timeout)
            }
        }
    }

    async fn resolve_inner(
        &mut self,
        entry_name: String,
    ) -> Result<Option<ResolvedCredential>, ErrorCode> {
        if self
            .unlocked_at
            .is_some_and(|unlocked_at| unlocked_at.elapsed() >= self.session_ttl)
        {
            self.clear_session();
            self.autolock_event_pending = true;
        }
        if let Some(entry) = self.entries.get(&entry_name) {
            return Ok(Some(to_resolved(entry)));
        }
        let mut output = self
            .run_pass(&entry_name)
            .await
            .map_err(|error| self.log_error("show", error))?;
        let entry = parse_entry(&output, &self.totp_exposable, &entry_name);
        output.zeroize();
        let entry = entry.ok_or_else(|| self.log_error("parse", PassRunError::InvalidOutput))?;
        let credential = to_resolved(&entry);
        self.entries.insert(entry_name, entry);
        self.unlocked_at = Some(Instant::now());
        self.locked = false;
        Ok(Some(credential))
    }

    fn log_error(&self, operation: &str, error: impl fmt::Display) -> ErrorCode {
        eprintln!("tegatad: pass {operation} failed: {error}");
        ErrorCode::Internal
    }
}

fn scan_directory(root: &Path, directory: &Path, names: &mut Vec<String>) -> io::Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            scan_directory(root, &path, names)?;
        } else if path.extension().is_some_and(|extension| extension == "gpg") {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| io::Error::other(error.to_string()))?;
            names.push(relative.with_extension("").to_string_lossy().into_owned());
        }
    }
    Ok(())
}

fn parse_entry(output: &str, totp_exposable: &[String], name: &str) -> Option<PassEntry> {
    let mut lines = output.lines();
    let password = lines.next()?.trim_end_matches('\r').to_owned();
    let mut username = None;
    let mut login = None;
    let mut totp_seed = None;
    for line in lines {
        if let Some(value) = line.strip_prefix("username:") {
            username = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("login:") {
            login = Some(value.trim().to_owned());
        }
        if let Some(value) = extract_totp_seed(line) {
            totp_seed = Some(value);
        }
    }
    Some(PassEntry {
        username: Secret::new(username.or(login).unwrap_or_default()),
        password: Secret::new(password),
        totp_seed: totp_seed.map(Secret::new),
        totp_exposable: totp_exposable.iter().any(|entry| entry == name),
    })
}

fn extract_totp_seed(line: &str) -> Option<String> {
    let start = line.find("otpauth://")?;
    let uri = line.get(start..)?;
    let query = uri.split_once('?')?.1;
    query.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == "secret").then(|| value.split('#').next().unwrap_or(value).to_owned())
    })
}

fn to_resolved(entry: &PassEntry) -> ResolvedCredential {
    ResolvedCredential {
        locked: false,
        secrets_preregistered: false,
        username: Secret::new(entry.username.as_str()),
        password: Secret::new(entry.password.as_str()),
        totp_seed: entry
            .totp_seed
            .as_ref()
            .map(|seed| Secret::new(seed.as_str())),
        totp_exposable: entry.totp_exposable,
    }
}

impl CredentialProvider for PassProvider {
    fn list_refs(&mut self) -> ProviderFuture<'_, Vec<CredentialRef>> {
        Box::pin(async move {
            self.scan_store()?;
            Ok(self
                .catalog
                .iter()
                .map(|entry| CredentialRef {
                    id: entry.name.clone(),
                    name: entry.name.clone(),
                    uri: Some(String::new()),
                    kind: Some("login".to_owned()),
                })
                .collect())
        })
    }

    fn resolve(&mut self, entry_id: &str) -> ProviderFuture<'_, Option<ResolvedCredential>> {
        let entry_id = entry_id.to_owned();
        Box::pin(self.resolve_inner(entry_id))
    }

    fn lock(&mut self) -> ProviderFuture<'_, ()> {
        Box::pin(async move {
            self.clear_session();
            // Locking only drops retrieved values; it deliberately does not touch the gpg-agent cache.
            Ok(())
        })
    }

    fn expire(&mut self) -> ProviderFuture<'_, ()> {
        Box::pin(async move {
            if self
                .unlocked_at
                .is_some_and(|unlocked_at| unlocked_at.elapsed() >= self.session_ttl)
            {
                self.clear_session();
                self.autolock_event_pending = true;
            }
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
