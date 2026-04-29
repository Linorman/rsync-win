use std::io;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDescriptorSummary {
    pub captured: bool,
    pub byte_len: Option<u32>,
    pub stable_hash: Option<String>,
    pub message: Option<String>,
}

impl SecurityDescriptorSummary {
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            captured: false,
            byte_len: None,
            stable_hash: None,
            message: Some(message.into()),
        }
    }
}

pub fn capture_security_descriptor_summary(path: &Path) -> io::Result<SecurityDescriptorSummary> {
    platform_security_descriptor_summary(path)
}

pub fn password_file_has_broad_access(path: &Path) -> io::Result<bool> {
    platform_password_file_has_broad_access(path)
}

#[cfg(windows)]
fn platform_security_descriptor_summary(path: &Path) -> io::Result<SecurityDescriptorSummary> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorLength, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    let path = crate::path::to_long_path_safe(path);
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if descriptor.is_null() {
        return Ok(SecurityDescriptorSummary::unavailable(
            "Windows returned an empty security descriptor",
        ));
    }

    let byte_len = unsafe { GetSecurityDescriptorLength(descriptor) };
    let bytes = unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), byte_len as usize) };
    let stable_hash = stable_hash_hex(bytes);
    let _ = unsafe { LocalFree(descriptor.cast()) };

    Ok(SecurityDescriptorSummary {
        captured: true,
        byte_len: Some(byte_len),
        stable_hash: Some(stable_hash),
        message: None,
    })
}

#[cfg(not(windows))]
fn platform_security_descriptor_summary(path: &Path) -> io::Result<SecurityDescriptorSummary> {
    let _ = std::fs::metadata(path)?;
    Ok(SecurityDescriptorSummary::unavailable(
        "NTFS security descriptors are only available on Windows",
    ))
}

#[cfg(windows)]
fn platform_password_file_has_broad_access(path: &Path) -> io::Result<bool> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    let path = crate::path::to_long_path_safe(path);
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if descriptor.is_null() {
        return Ok(true);
    }

    let result = password_file_descriptor_has_broad_access(descriptor);
    let _ = unsafe { LocalFree(descriptor.cast()) };
    result
}

#[cfg(windows)]
fn password_file_descriptor_has_broad_access(
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> io::Result<bool> {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::ptr::null_mut;

    use windows_sys::Win32::Security::{
        AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorDacl,
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, PSID,
    };

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl: *mut ACL = null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if dacl_present == 0 || dacl.is_null() {
        return Ok(true);
    }

    let mut size_info: ACL_SIZE_INFORMATION = unsafe { zeroed() };
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut size_info as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let broad_sids = broad_windows_principal_sids()?;
    for index in 0..size_info.AceCount {
        let mut ace: *mut c_void = null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = unsafe { &*(ace.cast::<ACE_HEADER>()) };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
            continue;
        }
        let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
        if !file_read_access_allowed(allowed.Mask) {
            continue;
        }
        let sid = (&allowed.SidStart as *const u32).cast::<c_void>() as PSID;
        if broad_sids
            .iter()
            .any(|known_sid| unsafe { EqualSid(sid, known_sid.as_ptr() as PSID) } != 0)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(windows)]
fn broad_windows_principal_sids() -> io::Result<Vec<Vec<u8>>> {
    use std::ptr::null_mut;

    use windows_sys::Win32::Security::{
        CreateWellKnownSid, WinAuthenticatedUserSid, WinBuiltinUsersSid, WinWorldSid,
        SECURITY_MAX_SID_SIZE,
    };

    [WinWorldSid, WinAuthenticatedUserSid, WinBuiltinUsersSid]
        .into_iter()
        .map(|sid_type| {
            let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
            let mut sid_len = SECURITY_MAX_SID_SIZE;
            let ok = unsafe {
                CreateWellKnownSid(sid_type, null_mut(), sid.as_mut_ptr().cast(), &mut sid_len)
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            sid.truncate(sid_len as usize);
            Ok(sid)
        })
        .collect()
}

#[cfg(windows)]
fn file_read_access_allowed(mask: u32) -> bool {
    use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_READ};
    use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_READ_DATA};

    mask & (GENERIC_ALL | GENERIC_READ | FILE_GENERIC_READ | FILE_READ_DATA) != 0
}

#[cfg(not(windows))]
fn platform_password_file_has_broad_access(path: &Path) -> io::Result<bool> {
    let _ = std::fs::metadata(path)?;
    Ok(false)
}

fn stable_hash_hex(bytes: &[u8]) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_security_summary_has_no_hash() {
        let summary = SecurityDescriptorSummary::unavailable("not available");

        assert!(!summary.captured);
        assert!(summary.byte_len.is_none());
        assert!(summary.stable_hash.is_none());
        assert_eq!(summary.message.as_deref(), Some("not available"));
    }
}
