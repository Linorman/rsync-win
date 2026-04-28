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
