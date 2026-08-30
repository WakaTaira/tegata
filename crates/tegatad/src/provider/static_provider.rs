use tegata_core::Secret;

use super::{CredentialProvider, CredentialRef, ProviderFuture, ResolvedCredential};
use crate::EntryConfig;

struct Entry {
    id: String,
    name: String,
    uri: String,
    kind: String,
    username: Secret,
    password: Secret,
    totp_seed: Option<Secret>,
    totp_exposable: bool,
}

pub(crate) struct StaticProvider {
    entries: Vec<Entry>,
    locked: bool,
}

impl StaticProvider {
    pub(crate) fn from_config(entries: Vec<EntryConfig>, registry: &mut Vec<String>) -> Self {
        let entries = entries
            .into_iter()
            .map(|entry| {
                registry.push(entry.username.clone());
                registry.push(entry.password.clone());
                if let Some(seed) = &entry.totp_seed {
                    registry.push(seed.clone());
                }
                Entry {
                    id: entry.id,
                    name: entry.name,
                    uri: entry.uri,
                    kind: entry.kind,
                    username: Secret::new(entry.username),
                    password: Secret::new(entry.password),
                    totp_seed: entry.totp_seed.map(Secret::new),
                    totp_exposable: entry.totp_exposable.unwrap_or(false),
                }
            })
            .collect();
        Self {
            entries,
            locked: false,
        }
    }
}

impl CredentialProvider for StaticProvider {
    fn list_refs(&mut self) -> ProviderFuture<'_, Vec<CredentialRef>> {
        Box::pin(async move {
            Ok(self
                .entries
                .iter()
                .map(|entry| CredentialRef {
                    id: entry.id.clone(),
                    name: entry.name.clone(),
                    uri: (!self.locked).then(|| entry.uri.clone()),
                    kind: (!self.locked).then(|| entry.kind.clone()),
                })
                .collect())
        })
    }

    fn resolve(&mut self, entry_id: &str) -> ProviderFuture<'_, Option<ResolvedCredential>> {
        let entry_id = entry_id.to_owned();
        Box::pin(async move {
            let Some(entry) = self.entries.iter().find(|entry| entry.id == entry_id) else {
                return Ok(None);
            };
            Ok(Some(ResolvedCredential {
                locked: self.locked,
                secrets_preregistered: true,
                username: Secret::new(entry.username.as_str()),
                password: Secret::new(entry.password.as_str()),
                totp_seed: entry
                    .totp_seed
                    .as_ref()
                    .map(|seed| Secret::new(seed.as_str())),
                totp_exposable: entry.totp_exposable,
            }))
        })
    }

    fn lock(&mut self) -> ProviderFuture<'_, ()> {
        Box::pin(async move {
            self.locked = true;
            Ok(())
        })
    }

    fn expire(&mut self) -> ProviderFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn locked(&self) -> bool {
        self.locked
    }
}
