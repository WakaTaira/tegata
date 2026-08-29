//! Filesystem restrictions for files that hold, or briefly hold, secrets.
//!
//! UNIX expresses the restriction with mode bits. Windows uses a protected DACL
//! that names the account the daemon runs under, SYSTEM and the local
//! administrators group. Interactive accounts are never named, so the agent
//! side of the machine cannot read the daemon state even when it created the
//! directory as an installer.

use std::io;
use std::path::Path;

use tokio::fs::File;

/// Restricts a directory to the account that runs the daemon.
pub(crate) async fn restrict_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await
    }
    #[cfg(not(unix))]
    {
        restrict_directory_sync(path)
    }
}

/// Creates a file readable only by the account that runs the daemon, failing
/// if the path already exists.
pub(crate) async fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).await?;
    #[cfg(not(unix))]
    if let Err(error) = restrict_file(path) {
        drop(file);
        let _ = tokio::fs::remove_file(path).await;
        return Err(error);
    }
    Ok(file)
}

/// SDDL alias of the local SYSTEM account.
#[cfg(windows)]
pub(crate) const SDDL_SYSTEM: &str = "SY";

/// Principals of the protected DACL used by the running daemon: its own
/// account and SYSTEM.
///
/// The local administrators group is deliberately absent. The WSL file server
/// that backs `/mnt/c` reads with a token in which that group is enabled, so
/// granting it would expose the daemon state to the agent side of the machine.
/// Administrators keep ownership of the paths they create during installation,
/// which is enough to repair the DACL.
#[cfg(windows)]
pub(crate) fn daemon_principals() -> io::Result<Vec<String>> {
    Ok(vec![current_user_sid()?, SDDL_SYSTEM.to_owned()])
}

#[cfg(windows)]
pub(crate) fn restrict_directory_sync(path: &Path) -> io::Result<()> {
    restrict_path(path, true, &daemon_principals()?)
}

#[cfg(windows)]
fn restrict_file(path: &Path) -> io::Result<()> {
    restrict_path(path, false, &daemon_principals()?)
}

/// Applies a protected DACL that grants full access to `principals` only.
///
/// `principals` holds SID strings or SDDL aliases. The call is idempotent: a
/// path whose DACL already equals the requested one is accepted even when the
/// current account may not rewrite it, which happens for state that a
/// different identity created during installation.
#[cfg(windows)]
pub(crate) fn restrict_path(path: &Path, directory: bool, principals: &[String]) -> io::Result<()> {
    let sddl = protected_dacl_sddl(directory, principals);
    match set_protected_dacl(path, &sddl) {
        Ok(()) => Ok(()),
        Err(error) => {
            if dacl_matches(path, &sddl).unwrap_or(false) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

#[cfg(windows)]
fn protected_dacl_sddl(directory: bool, principals: &[String]) -> String {
    let inheritance = if directory { "OICI" } else { "" };
    let mut sddl = String::from("D:P");
    for principal in principals {
        sddl.push_str(&format!("(A;{inheritance};FA;;;{principal})"));
    }
    sddl
}

#[cfg(windows)]
fn set_protected_dacl(path: &Path, sddl: &str) -> io::Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };

    let descriptor_wide = OsStr::new(sddl)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let mut descriptor_size = 0_u32;
    let converted = unsafe {
        // SAFETY: `descriptor_wide` is NUL-terminated, and all output pointers are valid.
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut descriptor_size,
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut present = 0;
    let mut dacl = null_mut();
    let mut defaulted = 0;
    let dacl_result = unsafe {
        // SAFETY: `descriptor` was allocated by the preceding Win32 call, and the output pointers are valid.
        GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
    };
    if dacl_result == 0 || present == 0 || dacl.is_null() {
        unsafe {
            // SAFETY: This function owns `descriptor` and frees it exactly once here.
            let _ = LocalFree(descriptor);
        }
        return Err(io::Error::last_os_error());
    }

    let path_wide = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        // SAFETY: All strings and the DACL remain valid for the duration of the call.
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    unsafe {
        // SAFETY: `descriptor` is the allocated region returned by the conversion call.
        let _ = LocalFree(descriptor);
    }
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(())
}

/// Reports whether the DACL of `path` already equals the one described by
/// `sddl`. Both sides are rendered by the same Win32 conversion, so the
/// comparison is unaffected by alias spelling.
#[cfg(windows)]
fn dacl_matches(path: &Path, sddl: &str) -> io::Result<bool> {
    Ok(requested_dacl_string(sddl)? == current_dacl_string(path)?)
}

#[cfg(windows)]
fn requested_dacl_string(sddl: &str) -> io::Result<String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;

    let descriptor_wide = OsStr::new(sddl)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let mut descriptor_size = 0_u32;
    let converted = unsafe {
        // SAFETY: `descriptor_wide` is NUL-terminated, and all output pointers are valid.
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut descriptor_size,
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    let value = dacl_string(descriptor);
    unsafe {
        // SAFETY: `descriptor` is the allocated region returned by the conversion call.
        let _ = LocalFree(descriptor);
    }
    value
}

#[cfg(windows)]
fn current_dacl_string(path: &Path) -> io::Result<String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    let path_wide = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let result = unsafe {
        // SAFETY: `path_wide` is NUL-terminated, and `descriptor` is a valid output pointer.
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let value = dacl_string(descriptor);
    unsafe {
        // SAFETY: `descriptor` is the allocated region returned by GetNamedSecurityInfoW.
        let _ = LocalFree(descriptor);
    }
    value
}

#[cfg(windows)]
fn dacl_string(
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> io::Result<String> {
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

    let mut string_descriptor = null_mut();
    let mut length = 0_u32;
    let converted = unsafe {
        // SAFETY: `descriptor` is a valid security descriptor, and the output pointers are valid.
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut string_descriptor,
            &mut length,
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The conversion result is a NUL-terminated UTF-16 string.
    let value = unsafe { wide_string(string_descriptor) };
    unsafe {
        // SAFETY: `string_descriptor` is the allocated region returned by the conversion call.
        let _ = LocalFree(string_descriptor.cast());
    }
    Ok(value)
}

/// Reads a NUL-terminated UTF-16 string.
///
/// # Safety
///
/// `pointer` must point to a NUL-terminated UTF-16 string.
#[cfg(windows)]
unsafe fn wide_string(pointer: *const u16) -> String {
    let mut length = 0;
    while unsafe {
        // SAFETY: The caller guarantees NUL termination.
        *pointer.add(length)
    } != 0
    {
        length += 1;
    }
    String::from_utf16_lossy(unsafe {
        // SAFETY: The preceding scan established the length of the initialized string.
        std::slice::from_raw_parts(pointer, length)
    })
}

/// SID of the account the current process runs under.
#[cfg(windows)]
pub(crate) fn current_user_sid() -> io::Result<String> {
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = null_mut();
    let opened = unsafe {
        // SAFETY: The current process handle is valid, and `token` is a valid output pointer.
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
    };
    if opened == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = current_user_sid_from_token(token);
    unsafe {
        // SAFETY: `token` was returned by OpenProcessToken and is closed exactly once here.
        let _ = CloseHandle(token);
    }
    result
}

#[cfg(windows)]
fn current_user_sid_from_token(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> io::Result<String> {
    use std::mem::size_of;
    use std::ptr::{null_mut, read};

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_USER, TokenUser};

    let mut size = 0_u32;
    unsafe {
        // SAFETY: No output buffer is passed for this size query.
        let _ = GetTokenInformation(token, TokenUser, null_mut(), 0, &mut size);
    }
    if size == 0 {
        return Err(io::Error::last_os_error());
    }
    let units = (size as usize).div_ceil(size_of::<u64>());
    let mut information = vec![0_u64; units];
    let queried = unsafe {
        // SAFETY: `information` is a sufficiently large, 8-byte-aligned write destination.
        GetTokenInformation(
            token,
            TokenUser,
            information.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    };
    if queried == 0 {
        return Err(io::Error::last_os_error());
    }
    let token_user = unsafe {
        // SAFETY: The buffer is 8-byte aligned and contains the TOKEN_USER returned by Win32.
        read(information.as_ptr().cast::<TOKEN_USER>())
    };
    let mut string_sid = null_mut();
    let converted = unsafe {
        // SAFETY: `token_user.User.Sid` points within a valid token information buffer.
        ConvertSidToStringSidW(token_user.User.Sid, &mut string_sid)
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The conversion result is a NUL-terminated UTF-16 string.
    let value = unsafe { wide_string(string_sid) };
    unsafe {
        // SAFETY: `string_sid` is the allocated region returned by ConvertSidToStringSidW.
        let _ = LocalFree(string_sid.cast());
    }
    Ok(value)
}
