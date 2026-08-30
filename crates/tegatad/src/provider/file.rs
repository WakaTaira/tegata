use std::io::{self, Cursor};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use age::Decryptor;
use age::x25519::Identity;
use tokio::time::Instant;
use zeroize::Zeroize;

use super::{
    CredentialProvider, CredentialRef, ProviderFuture, ResolvedCredential, StaticProvider,
};
use crate::{EntryConfig, ErrorCode};

pub(crate) struct FileProviderConfig {
    pub(crate) entries_path: PathBuf,
    pub(crate) identity_path: PathBuf,
    pub(crate) session_ttl: Duration,
}

#[derive(serde::Deserialize)]
struct EntriesFile {
    #[serde(default)]
    entries: Vec<EntryConfig>,
}

pub(crate) struct FileProvider {
    entries_path: PathBuf,
    identity_path: PathBuf,
    session_ttl: Duration,
    session: Option<StaticProvider>,
    catalog: Vec<CredentialRef>,
    unlocked_at: Option<Instant>,
    locked: bool,
    autolock_event_pending: bool,
}

impl FileProvider {
    pub(crate) fn new(config: FileProviderConfig) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(&config.identity_path)?
                .permissions()
                .mode()
                & 0o7777;
            if mode != 0o600 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "age identity file must have permissions 0600",
                ));
            }
        }
        Ok(Self {
            entries_path: config.entries_path,
            identity_path: config.identity_path,
            session_ttl: config.session_ttl,
            session: None,
            catalog: Vec::new(),
            unlocked_at: None,
            locked: true,
            autolock_event_pending: false,
        })
    }

    async fn unlock(&mut self) -> Result<(), ErrorCode> {
        if let Some(unlocked_at) = self.unlocked_at {
            if unlocked_at.elapsed() < self.session_ttl {
                return Ok(());
            }
            self.session = None;
            self.unlocked_at = None;
            self.locked = true;
            self.autolock_event_pending = true;
        }
        let encrypted = tokio::fs::read(&self.entries_path)
            .await
            .map_err(|error| self.log_decryption_error(error))?;
        let identity_text = tokio::fs::read_to_string(&self.identity_path)
            .await
            .map_err(|error| self.log_decryption_error(error))?;
        let identity = identity_text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .find_map(|line| Identity::from_str(line).ok())
            .ok_or_else(|| self.log_decryption_error("no X25519 identity"))?;
        let decryptor = Decryptor::new(Cursor::new(encrypted))
            .map_err(|error| self.log_decryption_error(error))?;
        let mut decrypted = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|error| self.log_decryption_error(error))?;
        let mut plaintext = Vec::new();
        std::io::Read::read_to_end(&mut decrypted, &mut plaintext)
            .map_err(|error| self.log_decryption_error(error))?;
        let entries = match toml::from_slice::<EntriesFile>(&plaintext) {
            Ok(entries) => entries.entries,
            Err(_error) => {
                plaintext.zeroize();
                eprintln!("tegatad: age entries file is not valid TOML");
                return Err(ErrorCode::Internal);
            }
        };
        plaintext.zeroize();
        let mut registry = Vec::new();
        self.session = Some(StaticProvider::from_config(entries, &mut registry));
        registry.iter_mut().for_each(String::zeroize);
        registry.clear();
        self.unlocked_at = Some(Instant::now());
        self.locked = false;
        Ok(())
    }

    fn log_decryption_error(&self, error: impl std::fmt::Display) -> ErrorCode {
        eprintln!("tegatad: age decryption failed: {error}");
        ErrorCode::Internal
    }

    fn locked_refs(&self) -> Vec<CredentialRef> {
        self.catalog
            .iter()
            .map(|credential| CredentialRef {
                id: credential.id.clone(),
                name: credential.name.clone(),
                uri: None,
                kind: None,
            })
            .collect()
    }

    async fn list_refs_inner(&mut self) -> Result<Vec<CredentialRef>, ErrorCode> {
        if self.locked && !self.catalog.is_empty() {
            return Ok(self.locked_refs());
        }
        self.unlock().await?;
        let refs = self
            .session
            .as_mut()
            .expect("age session exists after unlock")
            .list_refs()
            .await?;
        self.catalog = refs.clone();
        Ok(refs)
    }

    async fn resolve_inner(
        &mut self,
        entry_id: String,
    ) -> Result<Option<ResolvedCredential>, ErrorCode> {
        self.unlock().await?;
        let credential = self
            .session
            .as_mut()
            .expect("age session exists after unlock")
            .resolve(&entry_id)
            .await?;
        let Some(mut credential) = credential else {
            return Ok(None);
        };
        credential.secrets_preregistered = false;
        Ok(Some(credential))
    }
}

impl CredentialProvider for FileProvider {
    fn list_refs(&mut self) -> ProviderFuture<'_, Vec<CredentialRef>> {
        Box::pin(self.list_refs_inner())
    }

    fn resolve(&mut self, entry_id: &str) -> ProviderFuture<'_, Option<ResolvedCredential>> {
        let entry_id = entry_id.to_owned();
        Box::pin(self.resolve_inner(entry_id))
    }

    fn lock(&mut self) -> ProviderFuture<'_, ()> {
        Box::pin(async move {
            self.session = None;
            self.unlocked_at = None;
            self.locked = true;
            Ok(())
        })
    }

    fn expire(&mut self) -> ProviderFuture<'_, ()> {
        Box::pin(async move {
            if self
                .unlocked_at
                .is_some_and(|unlocked_at| unlocked_at.elapsed() >= self.session_ttl)
            {
                self.session = None;
                self.unlocked_at = None;
                self.locked = true;
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
