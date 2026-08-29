use std::fs;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::slice;

use tegata_core::Secret;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Read,
    Write,
    InvalidBlob,
    Protect,
    Unprotect,
    InvalidPlaintext,
}

struct LocalBuffer {
    pointer: *mut u8,
    length: usize,
}

impl LocalBuffer {
    fn new(blob: CRYPT_INTEGER_BLOB) -> Self {
        Self {
            pointer: blob.pbData,
            length: blob.cbData as usize,
        }
    }

    fn copy(&self) -> Result<Vec<u8>, Error> {
        if self.pointer.is_null() || self.length == 0 {
            return Err(Error::InvalidBlob);
        }
        // SAFETY: The pointer and length are returned as a pair for the DPAPI output managed by LocalAlloc.
        let bytes = unsafe { slice::from_raw_parts(self.pointer, self.length) };
        Ok(bytes.to_vec())
    }
}

impl Drop for LocalBuffer {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            if self.length != 0 {
                // SAFETY: The pointer and length identify the owned DPAPI buffer.
                unsafe { self.pointer.write_bytes(0, self.length) };
            }
            // SAFETY: The pointer was allocated by Windows's local allocator.
            unsafe {
                let _ = LocalFree(self.pointer.cast());
            }
        }
    }
}

pub(crate) fn seal(master_password: &mut String, path: &Path) -> Result<(), Error> {
    let mut plaintext = master_password.as_bytes().to_vec();
    let length = match u32::try_from(plaintext.len()) {
        Ok(length) if length != 0 => length,
        _ => {
            plaintext.fill(0);
            return Err(Error::InvalidPlaintext);
        }
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: length,
        pbData: plaintext.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: Each input and output blob points to valid writable memory for this call.
    let protected = unsafe {
        CryptProtectData(
            &input,
            null(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    plaintext.fill(0);
    let output = LocalBuffer::new(output);
    if protected == 0 {
        return Err(Error::Protect);
    }

    let mut sealed = output.copy()?;
    let result = fs::write(path, &sealed).map_err(|_| Error::Write);
    sealed.fill(0);
    result
}

pub(crate) fn unseal(path: &Path) -> Result<Secret, Error> {
    let mut sealed = fs::read(path).map_err(|_| Error::Read)?;
    let length = match u32::try_from(sealed.len()) {
        Ok(length) if length != 0 => length,
        _ => {
            sealed.fill(0);
            return Err(Error::InvalidBlob);
        }
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: length,
        pbData: sealed.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: Each input and output blob points to valid writable memory for this call.
    let unprotected = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    sealed.fill(0);
    let output = LocalBuffer::new(output);
    if unprotected == 0 {
        return Err(Error::Unprotect);
    }

    let plaintext = output.copy()?;
    match String::from_utf8(plaintext) {
        Ok(value) => Ok(Secret::new(value)),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.fill(0);
            Err(Error::InvalidPlaintext)
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{Error, seal, unseal};

    fn test_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tegatad-dpapi-{name}-{}.blob",
            uuid::Uuid::new_v4()
        ))
    }

    #[test]
    fn seal_and_unseal_round_trip() {
        let path = test_path("round-trip");
        let mut password = "dpapi-test-password".to_owned();
        seal(&mut password, &path).expect("seal password");
        let password = unseal(&path).expect("unseal password");
        assert_eq!(password.as_str(), "dpapi-test-password");
        fs::remove_file(path).expect("remove test blob");
    }

    #[test]
    fn tampered_blob_returns_a_classified_error() {
        let path = test_path("tampered");
        let mut password = "dpapi-test-password".to_owned();
        seal(&mut password, &path).expect("seal password");
        let mut blob = fs::read(&path).expect("read test blob");
        blob[0] ^= 1;
        fs::write(&path, blob).expect("write tampered blob");
        assert!(matches!(
            unseal(&path),
            Err(Error::Unprotect | Error::InvalidBlob)
        ));
        fs::remove_file(path).expect("remove test blob");
    }

    #[test]
    fn empty_blob_returns_a_classified_error() {
        let path = test_path("empty");
        fs::write(&path, []).expect("write empty blob");
        assert!(matches!(unseal(&path), Err(Error::InvalidBlob)));
        fs::remove_file(path).expect("remove test blob");
    }
}
