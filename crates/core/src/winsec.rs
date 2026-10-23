//! The two Windows security calls Fogu needs and neither std nor a crate in the tree offers: a
//! private DACL for the files Fogu writes, and the owner of a named pipe. This is the only module
//! of the workspace allowed to use `unsafe`; every block says why it holds, and every handle or
//! buffer the system allocates is released by a guard, also on the error paths.

#![allow(
    unsafe_code,
    reason = "Win32 security APIs, see the module docs; nowhere else in the workspace"
)]

use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorDacl, GetTokenInformation,
    IsWellKnownSid, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Memory a Win32 call allocated with `LocalAlloc`, freed once on drop.
struct LocalMem<T>(*mut T);

impl<T> Drop for LocalMem<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API documented to allocate it with `LocalAlloc`,
            // and this guard is its only owner.
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

/// An owned kernel handle, closed once on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by us and is closed only here.
        unsafe { CloseHandle(self.0) };
    }
}

/// The current user's SID: a `TOKEN_USER` buffer whose SID points into the buffer itself.
struct UserSid(Vec<u64>);

impl UserSid {
    fn current() -> io::Result<Self> {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle that is always valid; `token` is a
        // valid out-pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(token);
        let mut len = 0_u32;
        // SAFETY: a size query (null buffer, length 0); it fails by design and sets `len`.
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &raw mut len) };
        let words = usize::try_from(len).map_err(io::Error::other)?.div_ceil(8);
        // u64 words: `TOKEN_USER` holds a pointer, so the buffer must be 8-byte aligned.
        let mut buf = vec![0_u64; words];
        // SAFETY: `buf` holds at least `len` bytes and lives across the call.
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buf.as_mut_ptr().cast(),
                len,
                &raw mut len,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(buf))
    }

    fn sid(&self) -> PSID {
        // SAFETY: `GetTokenInformation(TokenUser)` filled the buffer, which starts with a
        // `TOKEN_USER`; its SID points into the same buffer, alive as long as `self`.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    /// `S-1-5-21-…`, for an SDDL string.
    fn to_text(&self) -> io::Result<String> {
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: `self.sid()` is a valid SID; `text` receives a `LocalAlloc`ed string.
        if unsafe { ConvertSidToStringSidW(self.sid(), &raw mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let text = LocalMem(text);
        let mut len = 0;
        // SAFETY: the API returns a NUL-terminated string; we stop at the terminator.
        while unsafe { *text.0.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` UTF-16 units before the terminator, all inside the allocation.
        Ok(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(text.0, len)
        }))
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

/// Gives `path` a protected DACL (nothing inherited from the folder above) that grants full
/// control to the current user and SYSTEM only: the Windows side of `0700`/`0600`. A directory's
/// entries are inherited by what is later created inside it. A filesystem without ACLs (FAT,
/// exFAT) is left alone, like `chmod` on `vfat`.
pub fn restrict_to_user(path: &Path) -> io::Result<()> {
    let inherit = if path.is_dir() { "OICI" } else { "" };
    let user = UserSid::current()?.to_text()?;
    let sddl: Vec<u16> = format!("D:P(A;{inherit};FA;;;{user})(A;{inherit};FA;;;SY)")
        .encode_utf16()
        .chain([0])
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; `descriptor` receives a `LocalAlloc`ed descriptor.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalMem(descriptor);
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: a valid descriptor; the DACL pointer points into it, alive until the end.
    let ok = unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated and `dacl` is valid for the call; owner, group and SACL
    // are not changed (null).
    let code = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    match code {
        0 | ERROR_NOT_SUPPORTED | ERROR_INVALID_FUNCTION => Ok(()),
        code => Err(io::Error::from_raw_os_error(
            i32::try_from(code).map_err(io::Error::other)?,
        )),
    }
}

/// Whether the named pipe behind `pipe` is owned by SYSTEM, Administrators or the current user.
/// Any other owner is another user who created the pipe first (it was free because the real
/// service was not running) and must not see what we send.
pub fn pipe_owner_trusted(pipe: BorrowedHandle<'_>) -> io::Result<bool> {
    let mut owner: PSID = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `BorrowedHandle` guarantees an open handle for the call; the out-pointers are
    // valid; the descriptor is `LocalAlloc`ed and `owner` points into it.
    let code = unsafe {
        GetSecurityInfo(
            pipe.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    let _descriptor = LocalMem(descriptor);
    if code != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(code).map_err(io::Error::other)?,
        ));
    }
    Ok(trusted_owner(owner, UserSid::current()?.sid()))
}

fn trusted_owner(owner: PSID, user: PSID) -> bool {
    // SAFETY: both are valid SIDs that outlive the calls.
    unsafe {
        IsWellKnownSid(owner, WinLocalSystemSid) != 0
            || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
            || EqualSid(owner, user) != 0
    }
}

#[cfg(test)]
mod tests {

    use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
    use windows_sys::Win32::Security::{
        ACL_SIZE_INFORMATION, AclSizeInformation, CreateWellKnownSid, GetAclInformation,
        GetSecurityDescriptorControl, SE_DACL_PROTECTED, WinWorldSid,
    };

    use super::*;

    /// (protected, number of entries) of `path`'s DACL.
    fn dacl(path: &Path) -> (bool, u32) {
        let name = wide(path);
        let mut acl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: as in `restrict_to_user`; the descriptor is freed by the guard.
        let code = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut acl,
                ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        assert_eq!(code, 0);
        let descriptor = LocalMem(descriptor);
        let (mut control, mut revision) = (0_u16, 0_u32);
        // SAFETY: a valid descriptor and out-pointers.
        unsafe { GetSecurityDescriptorControl(descriptor.0, &raw mut control, &raw mut revision) };
        let mut size = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        // SAFETY: `acl` points into the live descriptor; `size` is the right struct for the class.
        let ok = unsafe {
            GetAclInformation(
                acl,
                (&raw mut size).cast(),
                u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap(),
                AclSizeInformation,
            )
        };
        assert_ne!(ok, 0);
        (control & SE_DACL_PROTECTED != 0, size.AceCount)
    }

    #[test]
    fn restricted_dirs_and_files_inherit_nothing_and_allow_only_two_principals() {
        let dir = std::env::temp_dir().join(format!("fogu-winsec-{}", std::process::id()));
        let _stale = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.toml");
        std::fs::write(&file, "x").unwrap();
        assert!(!dacl(&dir).0, "a temp dir inherits its ACL");
        restrict_to_user(&dir).unwrap();
        restrict_to_user(&file).unwrap();
        assert_eq!(dacl(&dir), (true, 2));
        assert_eq!(dacl(&file), (true, 2));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_system_administrators_and_the_user_own_a_trusted_pipe() {
        let user = UserSid::current().unwrap();
        let well_known = |kind| {
            let mut sid = vec![0_u64; 9];
            let mut len = u32::try_from(sid.len() * 8).unwrap();
            // SAFETY: `sid` has `len` bytes, 8-aligned, enough for any well-known SID (68).
            let ok = unsafe {
                CreateWellKnownSid(kind, ptr::null_mut(), sid.as_mut_ptr().cast(), &raw mut len)
            };
            assert_ne!(ok, 0);
            sid
        };
        let mut system = well_known(WinLocalSystemSid);
        let mut admins = well_known(WinBuiltinAdministratorsSid);
        let mut everyone = well_known(WinWorldSid);
        assert!(trusted_owner(system.as_mut_ptr().cast(), user.sid()));
        assert!(trusted_owner(admins.as_mut_ptr().cast(), user.sid()));
        assert!(trusted_owner(user.sid(), user.sid()));
        assert!(!trusted_owner(everyone.as_mut_ptr().cast(), user.sid()));
    }
}
