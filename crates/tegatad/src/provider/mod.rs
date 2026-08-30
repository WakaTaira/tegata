mod bitwarden;
#[cfg(feature = "mock-provider")]
mod static_provider;

use std::future::Future;
use std::pin::Pin;

use tegata_core::Secret;

use crate::ErrorCode;

pub(crate) use bitwarden::remove_password_file;
pub(crate) use bitwarden::{BitwardenCliConfig, BitwardenCliProvider};
#[cfg(feature = "mock-provider")]
pub(crate) use static_provider::StaticProvider;

pub(crate) struct CredentialRef {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) uri: Option<String>,
    pub(crate) kind: Option<String>,
}

pub(crate) struct ResolvedCredential {
    pub(crate) locked: bool,
    pub(crate) register_secrets: bool,
    pub(crate) username: Secret,
    pub(crate) password: Secret,
    pub(crate) totp_seed: Option<Secret>,
    pub(crate) totp_exposable: bool,
}

pub(crate) type ProviderFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ErrorCode>> + Send + 'a>>;

pub(crate) trait CredentialProvider: Send {
    fn list_refs(&mut self) -> ProviderFuture<'_, Vec<CredentialRef>>;

    fn resolve(&mut self, entry_id: &str) -> ProviderFuture<'_, Option<ResolvedCredential>>;

    fn lock(&mut self) -> ProviderFuture<'_, ()>;

    fn expire(&mut self) -> ProviderFuture<'_, ()>;

    fn locked(&self) -> bool;
}
