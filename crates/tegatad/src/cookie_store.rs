//! Storage of persistent cookies per credential.
//!
//! The storage unit is (principal, namespace, cred_id), kept as one file per unit under
//! `<state_dir>/cookies/`.
//! The file name is the hexadecimal SHA-256 of the unit, so no credential or caller name appears in
//! a directory listing.
//! The executor is outside the trust boundary, so cookies received from it are validated and
//! filtered here before they are stored.
//! Cookie values appear in neither errors nor logs.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::secure_fs;
use crate::sessions::BrowserKey;

const STORE_DIR: &str = "cookies";
const STORE_VERSION: u32 = 1;
/// Upper limit on the number of cookies to store. Nothing is stored beyond it.
const MAX_COOKIES: usize = 3000;
/// Upper limit on the size of the document to store (JSON before sealing). Nothing is stored beyond
/// it.
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
/// The element of `persist_cookies` that stands for all credentials of that provider.
const ALL_CREDENTIALS: &str = "*";
#[cfg(not(windows))]
const STORE_EXTENSION: &str = "json";
#[cfg(windows)]
const STORE_EXTENSION: &str = "bin";

/// The Playwright `Cookie` shape. It contains values, so `Debug` prints them redacted.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub(crate) struct Cookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    expires: f64,
    #[serde(rename = "httpOnly")]
    http_only: bool,
    secure: bool,
    #[serde(rename = "sameSite")]
    same_site: SameSite,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
enum SameSite {
    Strict,
    Lax,
    None,
}

impl fmt::Debug for Cookie {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cookie")
            .field("name", &self.name)
            .field("value", &"[redacted]")
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

impl Cookie {
    /// Returns whether the cookie is well formed, has an expiry, and expires after `now` (UNIX
    /// seconds).
    /// Session cookies (`expires` of -1) and expired cookies yield false.
    fn is_persistent_at(&self, now: f64) -> bool {
        !self.name.is_empty()
            && !self.domain.is_empty()
            && self.path.starts_with('/')
            && self.expires.is_finite()
            && self.expires > now
    }
}

/// Extracts only the cookies that may be stored from the array received from the executor.
/// Returns `None` if the value is not an array. Malformed elements, session cookies and expired
/// cookies are dropped.
fn persistent_cookies(raw: &Value, now: f64) -> Option<Vec<Cookie>> {
    let elements = raw.as_array()?;
    Some(
        elements
            .iter()
            .filter_map(|element| Cookie::deserialize(element).ok())
            .filter(|cookie| cookie.is_persistent_at(now))
            .collect(),
    )
}

/// Returns the current time in UNIX seconds.
pub(crate) fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Deserialize, Serialize)]
struct StoredCookies {
    version: u32,
    principal: String,
    namespace: String,
    cred_id: String,
    saved_at: u64,
    cookies: Vec<Cookie>,
}

impl StoredCookies {
    /// Returns whether the document version and storage unit match `key`.
    fn matches(&self, key: &BrowserKey) -> bool {
        self.version == STORE_VERSION
            && self.principal == key.principal
            && self.namespace == key.namespace
            && self.cred_id == key.cred_id
    }

    fn key(&self) -> BrowserKey {
        BrowserKey::new(
            self.principal.clone(),
            self.namespace.clone(),
            self.cred_id.clone(),
        )
    }
}

/// Decides from each provider's `persist_cookies` whether a credential is a persistence target.
#[derive(Default)]
pub(crate) struct CookiePolicy {
    by_namespace: HashMap<String, Vec<String>>,
}

impl CookiePolicy {
    /// Registers the `persist_cookies` of a namespace.
    /// To keep precedence consistent with credential resolution (the first provider wins when
    /// several
    /// providers share a namespace), the first provider seen is adopted even if its list is empty,
    /// and later registrations for the same namespace are ignored.
    pub(crate) fn insert(&mut self, namespace: String, backend_ids: Vec<String>) {
        self.by_namespace.entry(namespace).or_insert(backend_ids);
    }

    fn is_empty(&self) -> bool {
        self.by_namespace.values().all(Vec::is_empty)
    }

    /// Returns whether `cred_id` (`<namespace>:<backend id>`) is a persistence target.
    pub(crate) fn persists(&self, cred_id: &str) -> bool {
        let Some((namespace, backend_id)) = cred_id.split_once(':') else {
            return false;
        };
        self.by_namespace.get(namespace).is_some_and(|ids| {
            ids.iter()
                .any(|id| id == ALL_CREDENTIALS || id == backend_id)
        })
    }
}

/// The reason a save was skipped.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SaveRejected {
    NotAnArray,
    TooManyCookies,
    TooLarge,
}

impl fmt::Display for SaveRejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnArray => write!(formatter, "the executor returned no cookie array"),
            Self::TooManyCookies => write!(formatter, "more than {MAX_COOKIES} cookies"),
            Self::TooLarge => write!(formatter, "the cookies exceed {MAX_DOCUMENT_BYTES} bytes"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum SaveError {
    Rejected(SaveRejected),
    Io(io::Error),
}

impl fmt::Display for SaveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(reason) => write!(formatter, "not stored: {reason}"),
            Self::Io(error) => write!(formatter, "not written: {error}"),
        }
    }
}

/// The target of `forget`.
pub(crate) enum ForgetTarget<'a> {
    /// All principals of that cred_id.
    Credential(&'a str),
    All,
}

/// The store under `<state_dir>/cookies/`.
pub(crate) struct CookieStore {
    dir: PathBuf,
    policy: CookiePolicy,
}

impl CookieStore {
    pub(crate) fn new(state_dir: &Path, policy: CookiePolicy) -> Self {
        Self {
            dir: state_dir.join(STORE_DIR),
            policy,
        }
    }

    pub(crate) fn persists(&self, cred_id: &str) -> bool {
        self.policy.persists(cred_id)
    }

    /// Startup preparation. If there are persistence targets, creates the storage directory, and
    /// sweeps an existing directory according to the current configuration.
    /// Does nothing in the default configuration, which has no persistence targets and no
    /// directory.
    pub(crate) fn prepare(&self) -> io::Result<()> {
        let exists = std::fs::symlink_metadata(&self.dir).is_ok();
        if self.policy.is_empty() && !exists {
            return Ok(());
        }
        self.ensure_dir()?;
        self.sweep()
    }

    /// Reads the stored cookies. Expired ones are dropped, and `None` is returned if none remain.
    /// If reading the file itself fails, logs one line to stderr and returns `None`
    /// (the file is not deleted). If decryption or parsing fails, or the storage unit
    /// does not match `key`, deletes the file, logs one line to stderr and returns `None`.
    pub(crate) fn load(&self, key: &BrowserKey, now: f64) -> Option<Vec<Cookie>> {
        let path = self.path_for(key);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
            Err(error) => {
                eprintln!(
                    "tegatad: cookie store: could not read {}: {error}",
                    path.display()
                );
                return None;
            }
        };
        let Some(document) = decode_document(&bytes).filter(|document| document.matches(key))
        else {
            self.discard_unreadable(&path);
            return None;
        };
        let cookies = document
            .cookies
            .into_iter()
            .filter(|cookie| cookie.is_persistent_at(now))
            .collect::<Vec<_>>();
        (!cookies.is_empty()).then_some(cookies)
    }

    /// Validates and filters the cookie array received from the executor, then stores it.
    /// If a limit is exceeded, nothing is stored and the existing file is kept.
    pub(crate) fn save(&self, key: &BrowserKey, raw: &Value, now: f64) -> Result<(), SaveError> {
        let cookies =
            persistent_cookies(raw, now).ok_or(SaveError::Rejected(SaveRejected::NotAnArray))?;
        if cookies.len() > MAX_COOKIES {
            return Err(SaveError::Rejected(SaveRejected::TooManyCookies));
        }
        let document = StoredCookies {
            version: STORE_VERSION,
            principal: key.principal.clone(),
            namespace: key.namespace.clone(),
            cred_id: key.cred_id.clone(),
            saved_at: now as u64,
            cookies,
        };
        // The error display of serde_json can contain values, so only the classification is
        // returned.
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&document)
                .map_err(|_| SaveError::Io(io::Error::other("cookie serialization failed")))?,
        );
        if plaintext.len() > MAX_DOCUMENT_BYTES {
            return Err(SaveError::Rejected(SaveRejected::TooLarge));
        }
        let sealed = seal_bytes(&plaintext).map_err(SaveError::Io)?;
        self.ensure_dir().map_err(SaveError::Io)?;
        secure_fs::write_private_file_atomic(&self.path_for(key), &sealed).map_err(SaveError::Io)
    }

    /// Deletes stored files and returns the number of files deleted. If the storage directory does
    /// not exist, the count is 0.
    /// When a cred_id is given, an unreadable (corrupt) file is kept because its attribution to the
    /// cred_id cannot be determined.
    /// This avoids deleting a file of another credential by mistake, or a healthy file that is
    /// unreadable because of a
    /// transient I/O failure or insufficient permissions. The purpose of `forget` (that the cookies
    /// of that credential
    /// are not restored afterwards) is still met, since cookies cannot be restored from an
    /// unreadable file.
    /// These unreadable files become deletion targets again with `--all`, on the next read, or in
    /// the
    /// startup sweep (`sweep`).
    pub(crate) fn forget(&self, target: ForgetTarget<'_>) -> io::Result<usize> {
        let mut removed = 0;
        for path in self.store_files()? {
            let matched = match target {
                ForgetTarget::All => true,
                ForgetTarget::Credential(cred_id) => {
                    read_document(&path).is_some_and(|document| document.cred_id == cred_id)
                }
            };
            if matched && remove_if_present(&path)? {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Deletes files that are not persistence targets in the current configuration, unreadable
    /// files, and temporary files left from an interrupted write.
    fn sweep(&self) -> io::Result<()> {
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') {
                remove_if_present(&path)?;
                continue;
            }
            if !is_store_file_name(&name) {
                continue;
            }
            match read_document(&path) {
                Some(document)
                    if self.policy.persists(&document.cred_id)
                        && self.path_for(&document.key()) == path => {}
                Some(_) => {
                    remove_if_present(&path)?;
                }
                None => self.discard_unreadable(&path),
            }
        }
        Ok(())
    }

    fn store_files(&self) -> io::Result<Vec<PathBuf>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut files = Vec::new();
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && is_store_file_name(&entry.file_name().to_string_lossy())
            {
                files.push(entry.path());
            }
        }
        Ok(files)
    }

    fn discard_unreadable(&self, path: &Path) {
        match remove_if_present(path) {
            Ok(_) => eprintln!(
                "tegatad: cookie store: removed an unreadable cookie file {}",
                path.display()
            ),
            Err(error) => eprintln!(
                "tegatad: cookie store: could not remove an unreadable cookie file {}: {error}",
                path.display()
            ),
        }
    }

    fn path_for(&self, key: &BrowserKey) -> PathBuf {
        self.dir.join(store_file_name(key))
    }

    #[cfg(unix)]
    fn ensure_dir(&self) -> io::Result<()> {
        secure_fs::ensure_private_dir(&self.dir)
    }

    #[cfg(windows)]
    fn ensure_dir(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        secure_fs::restrict_path(&self.dir, true, &secure_fs::daemon_principals()?)
    }
}

/// The file name: the hexadecimal form of `sha256(principal \0 namespace \0 cred_id)` plus an
/// extension.
fn store_file_name(key: &BrowserKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.principal.as_bytes());
    hasher.update([0]);
    hasher.update(key.namespace.as_bytes());
    hasher.update([0]);
    hasher.update(key.cred_id.as_bytes());
    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{digest}.{STORE_EXTENSION}")
}

fn is_store_file_name(name: &str) -> bool {
    name.strip_suffix(STORE_EXTENSION)
        .and_then(|stem| stem.strip_suffix('.'))
        .is_some_and(|stem| {
            stem.len() == 64
                && stem
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn read_document(path: &Path) -> Option<StoredCookies> {
    let bytes = Zeroizing::new(std::fs::read(path).ok()?);
    decode_document(&bytes)
}

fn decode_document(bytes: &[u8]) -> Option<StoredCookies> {
    let plaintext = unseal_bytes(bytes).ok()?;
    serde_json::from_slice::<StoredCookies>(&plaintext).ok()
}

fn remove_if_present(path: &Path) -> io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// On Linux the document is stored as plain text, and protection is left to directory and file
/// permissions.
#[cfg(not(windows))]
fn seal_bytes(plaintext: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(plaintext.to_vec()))
}

#[cfg(not(windows))]
fn unseal_bytes(sealed: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(sealed.to_vec()))
}

/// On Windows the whole document is sealed with the DPAPI of the service account.
#[cfg(windows)]
fn seal_bytes(plaintext: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    crate::dpapi::protect(plaintext)
        .map(Zeroizing::new)
        .map_err(|_| io::Error::other("DPAPI could not seal the cookie file"))
}

#[cfg(windows)]
fn unseal_bytes(sealed: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    crate::dpapi::unprotect(sealed)
        .map_err(|_| io::Error::other("DPAPI could not unseal the cookie file"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: f64 = 1_800_000_000.0;
    const VALUE_CANARY: &str = "cookie-value-canary-7f3a";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "tegatad-cookie-store-{label}-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir(&dir).expect("create test state dir");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .expect("restrict test state dir");
            }
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn key(principal: &str, cred_id: &str) -> BrowserKey {
        let namespace = cred_id.split_once(':').expect("namespaced").0;
        BrowserKey::new(
            principal.to_owned(),
            namespace.to_owned(),
            cred_id.to_owned(),
        )
    }

    fn cookie(name: &str, expires: f64) -> Value {
        json!({
            "name": name,
            "value": VALUE_CANARY,
            "domain": "127.0.0.1",
            "path": "/",
            "expires": expires,
            "httpOnly": true,
            "secure": false,
            "sameSite": "Lax",
        })
    }

    fn policy(namespace: &str, ids: &[&str]) -> CookiePolicy {
        let mut policy = CookiePolicy::default();
        policy.insert(
            namespace.to_owned(),
            ids.iter().map(|id| (*id).to_owned()).collect(),
        );
        policy
    }

    fn store(dir: &TempDir, ids: &[&str]) -> CookieStore {
        CookieStore::new(&dir.0, policy("mock", ids))
    }

    fn names(cookies: &[Cookie]) -> Vec<&str> {
        cookies.iter().map(|cookie| cookie.name.as_str()).collect()
    }

    #[test]
    fn policy_matches_listed_ids_and_the_wildcard() {
        let listed = policy("mock", &["site"]);
        assert!(listed.persists("mock:site"));
        assert!(!listed.persists("mock:site-b"));
        assert!(!listed.persists("other:site"));
        assert!(!listed.persists("site"));
        let all = policy("mock", &["*"]);
        assert!(all.persists("mock:site"));
        assert!(all.persists("mock:site-b"));
        assert!(!all.persists("other:site"));
        let empty = policy("mock", &[]);
        assert!(empty.is_empty());
        assert!(!empty.persists("mock:site"));
    }

    #[test]
    fn insert_keeps_the_first_providers_list_for_a_namespace() {
        // Credential resolution adopts the first provider of a namespace, so the policy
        // must also adopt the list of the first provider (including an empty one).
        let mut leading_empty = CookiePolicy::default();
        leading_empty.insert("mock".to_owned(), Vec::new());
        leading_empty.insert("mock".to_owned(), vec!["site".to_owned()]);
        assert!(leading_empty.is_empty());
        assert!(!leading_empty.persists("mock:site"));

        let mut leading_wins = CookiePolicy::default();
        leading_wins.insert("mock".to_owned(), vec!["site".to_owned()]);
        leading_wins.insert("mock".to_owned(), Vec::new());
        assert!(!leading_wins.is_empty());
        assert!(leading_wins.persists("mock:site"));
    }

    #[test]
    fn filtering_keeps_only_well_formed_unexpired_persistent_cookies() {
        let mut no_expires = cookie("no-expires", NOW + 60.0);
        no_expires
            .as_object_mut()
            .expect("object")
            .remove("expires");
        let raw = json!([
            cookie("device", NOW + 86_400.0),
            cookie("sid", -1.0),
            cookie("past", NOW - 1.0),
            cookie("now", NOW),
            no_expires,
            cookie("", NOW + 60.0),
            {"name": "bad-type", "value": 1, "domain": "x", "path": "/", "expires": NOW + 60.0,
             "httpOnly": false, "secure": false, "sameSite": "Lax"},
            {"name": "bad-same-site", "value": "v", "domain": "x", "path": "/",
             "expires": NOW + 60.0, "httpOnly": false, "secure": false, "sameSite": "Weird"},
            "not-an-object",
        ]);
        let kept = persistent_cookies(&raw, NOW).expect("array");
        assert_eq!(names(&kept), ["device"]);
        assert!(persistent_cookies(&json!({"cookies": []}), NOW).is_none());
    }

    #[test]
    fn save_then_load_round_trips_and_drops_cookies_expired_since() {
        let dir = TempDir::new("round-trip");
        let store = store(&dir, &["site"]);
        let key = key("uid:1000", "mock:site");
        let raw = json!([
            cookie("long", NOW + 86_400.0),
            cookie("short", NOW + 10.0),
            cookie("sid", -1.0)
        ]);
        store.save(&key, &raw, NOW).expect("save");
        let loaded = store.load(&key, NOW).expect("stored cookies");
        assert_eq!(names(&loaded), ["long", "short"]);
        let later = store.load(&key, NOW + 60.0).expect("stored cookies");
        assert_eq!(names(&later), ["long"]);
        assert!(store.load(&key, NOW + 100_000.0).is_none());
    }

    #[test]
    fn keys_are_separated_by_principal_and_credential() {
        let dir = TempDir::new("separation");
        let store = store(&dir, &["*"]);
        store
            .save(
                &key("uid:1000", "mock:site"),
                &json!([cookie("a", NOW + 60.0)]),
                NOW,
            )
            .expect("save");
        assert!(store.load(&key("peer:p2", "mock:site"), NOW).is_none());
        assert!(store.load(&key("uid:1000", "mock:site-b"), NOW).is_none());
        assert!(store.load(&key("uid:1000", "mock:site"), NOW).is_some());
    }

    #[test]
    fn file_name_is_the_hex_digest_and_hides_the_key() {
        let name = store_file_name(&key("uid:1000", "mock:site"));
        assert!(is_store_file_name(&name), "{name}");
        assert!(!name.contains("mock"));
        assert!(!name.contains("uid"));
        let expected = Sha256::digest(b"uid:1000\0mock\0mock:site")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(name, format!("{expected}.{STORE_EXTENSION}"));
        assert!(!is_store_file_name("abc.json.tmp"));
        assert!(!is_store_file_name(&format!(
            "{}.{STORE_EXTENSION}",
            "G".repeat(64)
        )));
    }

    #[test]
    fn too_many_cookies_are_not_stored_and_the_existing_file_is_kept() {
        let dir = TempDir::new("too-many");
        let store = store(&dir, &["site"]);
        let key = key("uid:1000", "mock:site");
        store
            .save(&key, &json!([cookie("kept", NOW + 60.0)]), NOW)
            .expect("save");
        let many = Value::Array(
            (0..=MAX_COOKIES)
                .map(|index| cookie(&format!("c{index}"), NOW + 60.0))
                .collect(),
        );
        assert!(matches!(
            store.save(&key, &many, NOW),
            Err(SaveError::Rejected(SaveRejected::TooManyCookies))
        ));
        // Session cookies are not counted, so the cookies are stored if they fit after filtering
        // even when the raw count exceeds the limit.
        let mut mostly_session = vec![cookie("persistent", NOW + 60.0)];
        mostly_session.extend((0..MAX_COOKIES).map(|index| cookie(&format!("s{index}"), -1.0)));
        let loaded = store.load(&key, NOW).expect("kept file");
        assert_eq!(names(&loaded), ["kept"]);
        store
            .save(&key, &Value::Array(mostly_session), NOW)
            .expect("save filtered");
        assert_eq!(
            names(&store.load(&key, NOW).expect("stored")),
            ["persistent"]
        );
    }

    #[test]
    fn oversized_cookies_are_not_stored_and_the_existing_file_is_kept() {
        let dir = TempDir::new("too-large");
        let store = store(&dir, &["site"]);
        let key = key("uid:1000", "mock:site");
        store
            .save(&key, &json!([cookie("kept", NOW + 60.0)]), NOW)
            .expect("save");
        let mut large = cookie("large", NOW + 60.0);
        large["value"] = Value::String("x".repeat(MAX_DOCUMENT_BYTES));
        assert!(matches!(
            store.save(&key, &json!([large]), NOW),
            Err(SaveError::Rejected(SaveRejected::TooLarge))
        ));
        assert!(matches!(
            store.save(&key, &json!({"not": "an array"}), NOW),
            Err(SaveError::Rejected(SaveRejected::NotAnArray))
        ));
        assert_eq!(names(&store.load(&key, NOW).expect("kept")), ["kept"]);
    }

    #[test]
    fn a_corrupt_file_is_removed_and_reads_as_no_cookies() {
        let dir = TempDir::new("corrupt");
        let store = store(&dir, &["site"]);
        let key = key("uid:1000", "mock:site");
        store
            .save(&key, &json!([cookie("device", NOW + 60.0)]), NOW)
            .expect("save");
        let path = store.path_for(&key);
        std::fs::write(&path, b"{ this is not json").expect("corrupt the file");
        assert!(store.load(&key, NOW).is_none());
        assert!(!path.exists());
        store
            .save(&key, &json!([cookie("device", NOW + 60.0)]), NOW)
            .expect("save again");
        assert!(store.load(&key, NOW).is_some());
    }

    #[test]
    fn a_file_whose_content_names_another_key_is_treated_as_corrupt() {
        let dir = TempDir::new("mismatch");
        let store = store(&dir, &["*"]);
        let owner = key("uid:1000", "mock:site");
        let other = key("peer:p2", "mock:site");
        store
            .save(&owner, &json!([cookie("device", NOW + 60.0)]), NOW)
            .expect("save");
        std::fs::rename(store.path_for(&owner), store.path_for(&other)).expect("move the file");
        assert!(store.load(&other, NOW).is_none());
        assert!(!store.path_for(&other).exists());
    }

    #[test]
    fn startup_sweep_removes_files_the_config_no_longer_persists() {
        let dir = TempDir::new("sweep");
        let wide = CookieStore::new(&dir.0, {
            let mut policy = policy("mock", &["*"]);
            policy.insert("gone".to_owned(), vec!["*".to_owned()]);
            policy
        });
        let site = key("uid:1000", "mock:site");
        let site_b = key("uid:1000", "mock:site-b");
        let gone = key("uid:1000", "gone:site");
        for key in [&site, &site_b, &gone] {
            wide.save(key, &json!([cookie("device", NOW + 60.0)]), NOW)
                .expect("save");
        }
        let corrupt = wide.dir.join(store_file_name(&key("uid:1000", "mock:x")));
        std::fs::write(&corrupt, b"garbage").expect("write corrupt file");
        let leftover = wide.dir.join(".leftover.json.tmp-1");
        std::fs::write(&leftover, b"partial").expect("write temp file");
        let unrelated = wide.dir.join("README");
        std::fs::write(&unrelated, b"keep").expect("write unrelated file");

        let narrow = store(&dir, &["site-b"]);
        narrow.prepare().expect("prepare");
        assert!(!narrow.path_for(&site).exists());
        assert!(narrow.path_for(&site_b).exists());
        assert!(!narrow.path_for(&gone).exists());
        assert!(!corrupt.exists());
        assert!(!leftover.exists());
        assert!(unrelated.exists());
    }

    #[test]
    fn prepare_without_any_persisted_credential_creates_nothing() {
        let dir = TempDir::new("default");
        let store = CookieStore::new(&dir.0, CookiePolicy::default());
        store.prepare().expect("prepare");
        assert!(!dir.0.join(STORE_DIR).exists());
    }

    #[test]
    fn prepare_with_an_empty_policy_still_sweeps_an_existing_store() {
        let dir = TempDir::new("disabled");
        let enabled = store(&dir, &["site"]);
        let key = key("uid:1000", "mock:site");
        enabled
            .save(&key, &json!([cookie("device", NOW + 60.0)]), NOW)
            .expect("save");
        let disabled = CookieStore::new(&dir.0, CookiePolicy::default());
        disabled.prepare().expect("prepare");
        assert!(!disabled.path_for(&key).exists());
    }

    #[test]
    fn forget_removes_one_credential_for_every_principal_or_everything() {
        let dir = TempDir::new("forget");
        let store = store(&dir, &["*"]);
        let raw = json!([cookie("device", NOW + 60.0)]);
        for key in [
            key("uid:1000", "mock:site"),
            key("peer:p2", "mock:site"),
            key("uid:1000", "mock:site-b"),
        ] {
            store.save(&key, &raw, NOW).expect("save");
        }
        assert_eq!(
            store
                .forget(ForgetTarget::Credential("mock:site"))
                .expect("forget"),
            2
        );
        assert!(store.load(&key("uid:1000", "mock:site-b"), NOW).is_some());
        assert_eq!(store.forget(ForgetTarget::All).expect("forget all"), 1);
        assert_eq!(store.forget(ForgetTarget::All).expect("forget none"), 0);
    }

    #[test]
    fn forget_by_credential_leaves_unreadable_and_other_credential_files() {
        let dir = TempDir::new("forget-unreadable");
        let store = store(&dir, &["*"]);
        let target = key("uid:1000", "mock:site");
        let other = key("uid:1000", "mock:site-b");
        store
            .save(&target, &json!([cookie("device", NOW + 60.0)]), NOW)
            .expect("save target");
        store
            .save(&other, &json!([cookie("device", NOW + 60.0)]), NOW)
            .expect("save other");
        let corrupt = store.dir.join(store_file_name(&key("uid:1000", "mock:x")));
        std::fs::write(&corrupt, b"garbage").expect("write corrupt file");
        // Verifies that only files whose attribution to the cred_id can be determined are deleted,
        // and that
        // healthy files of other credentials and unreadable (unattributable) files are kept by
        // forget.
        assert_eq!(
            store
                .forget(ForgetTarget::Credential("mock:site"))
                .expect("forget"),
            1
        );
        assert!(corrupt.exists());
        assert!(store.load(&other, NOW).is_some());
        assert_eq!(store.forget(ForgetTarget::All).expect("forget all"), 2);
    }

    #[test]
    fn forget_without_a_store_directory_removes_nothing() {
        let dir = TempDir::new("forget-empty");
        let store = store(&dir, &["*"]);
        assert_eq!(store.forget(ForgetTarget::All).expect("forget"), 0);
    }

    #[test]
    fn debug_output_redacts_the_cookie_value() {
        let cookies =
            persistent_cookies(&json!([cookie("device", NOW + 60.0)]), NOW).expect("array");
        let rendered = format!("{cookies:?}");
        assert!(rendered.contains("device"));
        assert!(!rendered.contains(VALUE_CANARY));
    }

    #[cfg(unix)]
    #[test]
    fn store_directory_and_files_are_private() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = TempDir::new("permissions");
        let store = store(&dir, &["site"]);
        store.prepare().expect("prepare");
        let key = key("uid:1000", "mock:site");
        store
            .save(&key, &json!([cookie("device", NOW + 60.0)]), NOW)
            .expect("save");
        let dir_metadata = std::fs::symlink_metadata(&store.dir).expect("dir metadata");
        assert_eq!(dir_metadata.permissions().mode() & 0o777, 0o700);
        let file_metadata = std::fs::symlink_metadata(store.path_for(&key)).expect("file metadata");
        assert_eq!(file_metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(file_metadata.uid(), unsafe { libc::geteuid() });
        let entries = std::fs::read_dir(&store.dir)
            .expect("list store")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1, "no temporary file is left behind");
    }

    #[cfg(unix)]
    #[test]
    fn a_store_directory_with_loose_permissions_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("loose");
        let store = store(&dir, &["site"]);
        std::fs::create_dir(&store.dir).expect("create store dir");
        std::fs::set_permissions(&store.dir, std::fs::Permissions::from_mode(0o755))
            .expect("loosen store dir");
        assert!(store.prepare().is_err());
        assert!(
            store
                .save(
                    &key("uid:1000", "mock:site"),
                    &json!([cookie("device", NOW + 60.0)]),
                    NOW
                )
                .is_err()
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn linux_files_are_the_documented_plain_json() {
        let dir = TempDir::new("plain");
        let store = store(&dir, &["site"]);
        let key = key("uid:1000", "mock:site");
        store
            .save(&key, &json!([cookie("device", NOW + 60.0)]), NOW)
            .expect("save");
        let document: Value =
            serde_json::from_slice(&std::fs::read(store.path_for(&key)).expect("read"))
                .expect("plain JSON");
        assert_eq!(document["version"], 1);
        assert_eq!(document["principal"], "uid:1000");
        assert_eq!(document["namespace"], "mock");
        assert_eq!(document["cred_id"], "mock:site");
        assert_eq!(document["saved_at"], NOW as u64);
        assert_eq!(document["cookies"][0]["name"], "device");
    }

    #[cfg(windows)]
    #[test]
    fn windows_files_are_dpapi_sealed_and_round_trip() {
        let dir = TempDir::new("dpapi");
        let store = store(&dir, &["site"]);
        let key = key("uid:1000", "mock:site");
        store
            .save(&key, &json!([cookie("device", NOW + 60.0)]), NOW)
            .expect("save");
        let path = store.path_for(&key);
        assert!(path.to_string_lossy().ends_with(".bin"));
        let bytes = std::fs::read(&path).expect("read sealed file");
        let canary = VALUE_CANARY.as_bytes();
        assert!(
            !bytes.windows(canary.len()).any(|window| window == canary),
            "the cookie value must not appear in the sealed bytes"
        );
        assert!(
            !bytes
                .windows(b"mock:site".len())
                .any(|window| window == b"mock:site")
        );
        let loaded = store.load(&key, NOW).expect("unsealed cookies");
        assert_eq!(names(&loaded), ["device"]);
        assert_eq!(loaded[0].value, VALUE_CANARY);
    }
}
