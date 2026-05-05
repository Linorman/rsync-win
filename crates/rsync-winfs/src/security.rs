use std::io;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDescriptorSummary {
    pub captured: bool,
    pub byte_len: Option<u32>,
    pub stable_hash: Option<String>,
    pub sddl: Option<String>,
    pub message: Option<String>,
}

impl SecurityDescriptorSummary {
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            captured: false,
            byte_len: None,
            stable_hash: None,
            sddl: None,
            message: Some(message.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDescriptorRestore {
    pub requested: bool,
    pub applied: bool,
    pub available: bool,
    pub message: Option<String>,
}

pub fn capture_security_descriptor_summary(path: &Path) -> io::Result<SecurityDescriptorSummary> {
    platform_security_descriptor_summary(path)
}

pub fn restore_security_descriptor(
    path: &Path,
    descriptor: &SecurityDescriptorSummary,
    include_owner_group: bool,
) -> io::Result<SecurityDescriptorRestore> {
    platform_restore_security_descriptor(path, descriptor, include_owner_group)
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
    let sddl = security_descriptor_sddl(
        descriptor,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
    )?;
    let _ = unsafe { LocalFree(descriptor.cast()) };

    Ok(SecurityDescriptorSummary {
        captured: true,
        byte_len: Some(byte_len),
        stable_hash: Some(stable_hash),
        sddl: Some(sddl),
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
fn platform_restore_security_descriptor(
    path: &Path,
    descriptor: &SecurityDescriptorSummary,
    include_owner_group: bool,
) -> io::Result<SecurityDescriptorRestore> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    if !descriptor.captured {
        return Ok(SecurityDescriptorRestore {
            requested: false,
            applied: false,
            available: false,
            message: descriptor.message.clone(),
        });
    }
    let Some(sddl) = descriptor.sddl.as_deref() else {
        return Ok(SecurityDescriptorRestore {
            requested: true,
            applied: false,
            available: false,
            message: Some("security descriptor SDDL payload was not captured".to_string()),
        });
    };

    let wide_sddl: Vec<u16> = std::ffi::OsStr::new(sddl)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut parsed: PSECURITY_DESCRIPTOR = null_mut();
    let mut parsed_len = 0;
    let parsed_ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut parsed,
            &mut parsed_len,
        )
    };
    if parsed_ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let path = crate::path::to_long_path_safe(path);
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut security_info = DACL_SECURITY_INFORMATION;
    if include_owner_group {
        security_info |= OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
    }
    let applied = unsafe { SetFileSecurityW(wide_path.as_ptr(), security_info, parsed) };
    let error = (applied == 0).then(io::Error::last_os_error);
    let _ = unsafe { LocalFree(parsed.cast()) };
    if let Some(error) = error {
        return Err(error);
    }

    Ok(SecurityDescriptorRestore {
        requested: true,
        applied: true,
        available: true,
        message: None,
    })
}

#[cfg(not(windows))]
fn platform_restore_security_descriptor(
    path: &Path,
    descriptor: &SecurityDescriptorSummary,
    _include_owner_group: bool,
) -> io::Result<SecurityDescriptorRestore> {
    let _ = std::fs::metadata(path)?;
    Ok(SecurityDescriptorRestore {
        requested: descriptor.captured,
        applied: false,
        available: false,
        message: Some("NTFS security descriptor restore is only available on Windows".to_string()),
    })
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

#[cfg(windows)]
fn security_descriptor_sddl(
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    security_information: windows_sys::Win32::Security::OBJECT_SECURITY_INFORMATION,
) -> io::Result<String> {
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
    };

    let mut sddl_ptr: *mut u16 = null_mut();
    let mut sddl_len = 0;
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            security_information,
            &mut sddl_ptr,
            &mut sddl_len,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if sddl_ptr.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an empty SDDL security descriptor",
        ));
    }
    let len = if sddl_len == 0 {
        let mut len = 0;
        while unsafe { *sddl_ptr.add(len) } != 0 {
            len += 1;
        }
        len
    } else {
        sddl_len as usize
    };
    let mut sddl = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sddl_ptr, len) });
    while sddl.ends_with('\0') {
        sddl.pop();
    }
    let _ = unsafe { LocalFree(sddl_ptr.cast()) };
    Ok(sddl)
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
        assert!(summary.sddl.is_none());
        assert_eq!(summary.message.as_deref(), Some("not available"));
    }

    #[cfg(windows)]
    #[test]
    fn security_descriptor_sddl_round_trips_and_restores_dacl() {
        let root = unique_temp_dir("rsync-winfs-security-restore");
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("source.txt");
        let dest = root.join("dest.txt");
        std::fs::write(&source, b"source").unwrap();
        std::fs::write(&dest, b"dest").unwrap();

        let source_descriptor = SecurityDescriptorSummary {
            captured: true,
            byte_len: None,
            stable_hash: None,
            sddl: Some("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)".to_string()),
            message: None,
        };
        restore_security_descriptor(&source, &source_descriptor, false).unwrap();
        let captured = capture_security_descriptor_summary(&source).unwrap();
        assert!(captured
            .sddl
            .as_deref()
            .is_some_and(|sddl| sddl.contains("D:P")));

        let restore = restore_security_descriptor(&dest, &captured, false).unwrap();

        assert!(restore.applied);
        let restored = capture_security_descriptor_summary(&dest).unwrap();
        assert_eq!(
            dacl_fragment(restored.sddl.as_deref().unwrap()),
            dacl_fragment(captured.sddl.as_deref().unwrap())
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    fn dacl_fragment(sddl: &str) -> &str {
        let Some(start) = sddl.find("D:") else {
            return "";
        };
        let rest = &sddl[start..];
        let end = rest.find("S:").unwrap_or(rest.len());
        &rest[..end]
    }

    #[cfg(windows)]
    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        path.push(format!("{prefix}-{}-{nanos}", std::process::id()));
        path
    }
}
