//! Shared secret and executor-sidecar protocol primitives.
//!
//! The executor sidecar is started as `node <executor_entry>`, where
//! `executor_entry` is resolved from the daemon configuration, then
//! `TEGATA_EXECUTOR_ENTRY`, then the path obtained from
//! `current_exe()`/`../../../packages/tegata-executor/dist/index.js`.
//! One sidecar is started for each login. The daemon writes one JSON object
//! per line to stdin:
//! `{"op":"login","target_url":<string>,"steps":[{"action":"fill"|"click","selector":<string>,"value":<string|null>}]|null,"success_selector":<string|null>,"failure_selector":<string|null>,"secret":{"username":<string>,"password":<string>,"totp":<string|null>}}`.
//! The sidecar responds with one JSON line, either
//! `{"ok":true,"endpoint":"ws://..."}` or
//! `{"ok":false,"error":"<classification code>"}`, and stays alive after
//! a successful response while retaining the browser. The daemon shuts it
//! down by writing `{"op":"shutdown"}` or sending SIGTERM. Stderr is
//! discarded, and secrets are sent only through the stdin pipe, never in
//! argv or environment variables. Sessions exceeding `session_ttl_secs`
//! (default 300 seconds) are stopped automatically.

use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use zeroize::Zeroize;

/// A secret string that never exposes its value through formatting.
pub struct Secret(String);

impl Secret {
    /// Creates a secret from its in-memory value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrows the secret for an operation that must use its value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("***")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("***")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Generates a six-digit RFC 6238 TOTP and its remaining lifetime.
pub fn totp(seed: &str, unix_time_secs: u64) -> (String, u64) {
    let key = decode_seed(seed);
    let counter = unix_time_secs / 30;
    let mut message = [0_u8; 8];
    message.copy_from_slice(&counter.to_be_bytes());
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).expect("HMAC accepts every key length");
    mac.update(&message);
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    let code = binary % 1_000_000;
    let expires_in = 30 - (unix_time_secs % 30);
    (format!("{code:06}"), expires_in)
}

fn decode_seed(seed: &str) -> Vec<u8> {
    BASE32
        .decode(seed.as_bytes())
        .or_else(|_| BASE32_NOPAD.decode(seed.as_bytes()))
        .or_else(|_| BASE32.decode(seed.to_ascii_uppercase().as_bytes()))
        .or_else(|_| BASE32_NOPAD.decode(seed.to_ascii_uppercase().as_bytes()))
        .unwrap_or_else(|_| seed.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::{Secret, totp};

    #[test]
    fn secret_formatting_is_constant() {
        let secret = Secret::new("hidden");
        assert_eq!(format!("{secret:?}"), "***");
        assert_eq!(secret.to_string(), "***");
    }

    #[test]
    fn totp_matches_rfc_6238_vector() {
        let (code, expires_in) = totp("12345678901234567890", 59);
        assert_eq!(code, "287082");
        assert_eq!(expires_in, 1);
    }
}
