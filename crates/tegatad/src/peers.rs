use std::io;
#[cfg(unix)]
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::secure_fs;
use crate::transport::{PeerAuthenticator, PeerIdentity};

const CROCKFORD_BASE32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub(crate) type SharedPeerStore = Arc<RwLock<PeerStore>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct PeerRecord {
    pub(crate) peer_id: String,
    pub(crate) label: String,
    pub(crate) token_sha256: String,
    pub(crate) issued_at: String,
    pub(crate) revoked_at: Option<String>,
}

#[derive(Debug)]
pub(crate) struct IssuedPeer {
    pub(crate) peer_id: String,
    pub(crate) token: String,
}

#[derive(Debug)]
pub(crate) struct PeerStore {
    path: PathBuf,
    peers: Vec<PeerRecord>,
}

impl PeerStore {
    pub(crate) fn load_or_import(
        path: &Path,
        legacy_token_hash_path: &Path,
    ) -> io::Result<SharedPeerStore> {
        let mut peers = if path.exists() {
            let contents = std::fs::read(path)?;
            serde_json::from_slice::<Vec<PeerRecord>>(&contents).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid peers.json: {error}"),
                )
            })?
        } else {
            Vec::new()
        };
        for peer in &peers {
            parse_token_digest(peer.token_sha256.as_bytes())?;
        }

        let imported = if !peers.iter().any(|peer| peer.peer_id == "legacy")
            && legacy_token_hash_path.exists()
        {
            let hash = std::fs::read(legacy_token_hash_path)?;
            let digest = parse_token_digest(&hash)?;
            peers.push(PeerRecord {
                peer_id: "legacy".to_owned(),
                label: "legacy".to_owned(),
                token_sha256: digest_to_hex(&digest),
                issued_at: current_timestamp(),
                revoked_at: None,
            });
            true
        } else {
            false
        };

        let contents = serde_json::to_vec(&peers)
            .map_err(|error| io::Error::other(format!("could not serialize peers: {error}")))?;
        secure_fs::write_private_file_atomic(path, &contents)?;
        if imported {
            let imported_path =
                PathBuf::from(format!("{}.imported", legacy_token_hash_path.display()));
            std::fs::rename(legacy_token_hash_path, imported_path)?;
        }
        Ok(Arc::new(RwLock::new(Self {
            path: path.to_owned(),
            peers,
        })))
    }
}

pub(crate) fn authenticator(store: &SharedPeerStore) -> PeerAuthenticator {
    let store = store.clone();
    Arc::new(move |_token, digest| {
        let hash = digest_to_hex_bytes(digest);
        let peers = store.read().ok()?;
        let mut identity = None;
        for peer in peers.peers.iter().filter(|peer| peer.revoked_at.is_none()) {
            if constant_time_equal(peer.token_sha256.as_bytes(), &hash) {
                identity = Some(PeerIdentity::Peer {
                    peer_id: peer.peer_id.clone(),
                    label: peer.label.clone(),
                });
            }
        }
        identity
    })
}

pub(crate) fn issue(store: &SharedPeerStore, label: &str) -> io::Result<IssuedPeer> {
    let token = generate_token()?;
    let digest = Sha256::digest(token.as_bytes());
    let peer = PeerRecord {
        peer_id: format!("p_{}", generate_ulid()?),
        label: label.to_owned(),
        token_sha256: digest_to_hex(&digest),
        issued_at: current_timestamp(),
        revoked_at: None,
    };
    let result = IssuedPeer {
        peer_id: peer.peer_id.clone(),
        token,
    };
    let mut store = store
        .write()
        .map_err(|_| io::Error::other("peer store lock poisoned"))?;
    store.peers.push(peer);
    persist(&store)?;
    Ok(result)
}

pub(crate) fn revoke(store: &SharedPeerStore, peer_id: &str) -> io::Result<bool> {
    let mut store = store
        .write()
        .map_err(|_| io::Error::other("peer store lock poisoned"))?;
    let Some(peer) = store.peers.iter_mut().find(|peer| peer.peer_id == peer_id) else {
        return Ok(false);
    };
    if peer.revoked_at.is_none() {
        peer.revoked_at = Some(current_timestamp());
        persist(&store)?;
    }
    Ok(true)
}

pub(crate) fn list(store: &SharedPeerStore) -> io::Result<Vec<PeerRecord>> {
    let store = store
        .read()
        .map_err(|_| io::Error::other("peer store lock poisoned"))?;
    Ok(store.peers.clone())
}

fn persist(store: &PeerStore) -> io::Result<()> {
    let contents = serde_json::to_vec(&store.peers)
        .map_err(|error| io::Error::other(format!("could not serialize peers: {error}")))?;
    secure_fs::write_private_file_atomic(&store.path, &contents)
}

fn generate_token() -> io::Result<String> {
    let mut bytes = [0_u8; 32];
    fill_random(&mut bytes)?;
    Ok(base64url(&bytes))
}

fn generate_ulid() -> io::Result<String> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
        & ((1_u64 << 48) - 1);
    let mut bytes = [0_u8; 16];
    bytes[..6].copy_from_slice(&milliseconds.to_be_bytes()[2..]);
    fill_random(&mut bytes[6..16])?;
    let value = u128::from_be_bytes(bytes);
    let mut encoded = String::with_capacity(26);
    for index in 0..26 {
        let shift = 125 - index * 5;
        encoded.push(CROCKFORD_BASE32[((value >> shift) & 0x1f) as usize] as char);
    }
    Ok(encoded)
}

fn fill_random(bytes: &mut [u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open("/dev/urandom")?.read_exact(bytes)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::Cryptography::{
            BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
        };

        let status = unsafe {
            // SAFETY: バッファは指定した長さだけ有効であり、システム RNG ではハンドルを null にします。
            BCryptGenRandom(
                std::ptr::null_mut(),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "BCryptGenRandom failed: {status}"
            )))
        }
    }
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        encoded.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
        encoded.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            encoded.push(ALPHABET[((value >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            encoded.push(ALPHABET[(value & 0x3f) as usize] as char);
        }
    }
    encoded
}

fn current_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{seconds}")
}

fn digest_to_hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest_to_hex_bytes(digest: &[u8; 32]) -> [u8; 64] {
    let mut hex = [0_u8; 64];
    for (index, byte) in digest.iter().enumerate() {
        hex[index * 2] = b"0123456789abcdef"[(byte >> 4) as usize];
        hex[index * 2 + 1] = b"0123456789abcdef"[(byte & 0x0f) as usize];
    }
    hex
}

fn constant_time_equal(left: &[u8], right: &[u8; 64]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

pub(crate) fn parse_token_digest(contents: &[u8]) -> io::Result<[u8; 32]> {
    let contents = match contents.strip_suffix(b"\n") {
        Some(contents) => contents.strip_suffix(b"\r").unwrap_or(contents),
        None => contents,
    };
    if contents.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "token hash must contain one 64-character lowercase SHA-256 hex line",
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in contents.chunks_exact(2).enumerate() {
        let high = decode_hex_digit(pair[0])?;
        let low = decode_hex_digit(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

fn decode_hex_digit(digit: u8) -> io::Result<u8> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "token hash must contain one 64-character lowercase SHA-256 hex line",
        )),
    }
}
