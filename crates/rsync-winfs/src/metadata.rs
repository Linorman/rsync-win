use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rsync_fs::{FileType, PortableMetadata};

#[cfg(windows)]
use crate::links::{FILE_ATTRIBUTE_REPARSE_POINT, IO_REPARSE_TAG_SYMLINK};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsMetadata {
    pub portable: PortableMetadata,
    pub creation_time: Option<SystemTime>,
    pub attributes: Option<u32>,
    pub file_id: Option<u64>,
    pub volume_serial: Option<u32>,
    pub reparse_tag: Option<u32>,
    pub link_count: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlatformFileIdentity {
    file_id: u64,
    volume_serial: u32,
    link_count: u64,
}

pub fn read_windows_metadata(path: &Path) -> std::io::Result<WindowsMetadata> {
    let metadata = fs::symlink_metadata(path)?;
    let identity = platform_file_identity(path);
    let file_type = if metadata.file_type().is_dir() {
        FileType::Directory
    } else if metadata.file_type().is_file() {
        FileType::File
    } else if metadata.file_type().is_symlink() {
        FileType::Symlink
    } else {
        FileType::Other
    };

    let portable = PortableMetadata {
        file_type,
        len: metadata.len(),
        modified: metadata.modified().ok(),
        mode: None,
        symlink_target: if file_type == FileType::Symlink {
            fs::read_link(path).ok()
        } else {
            None
        },
    };

    Ok(WindowsMetadata {
        portable,
        creation_time: platform_creation_time(&metadata),
        attributes: platform_file_attributes(&metadata),
        file_id: identity.map(|identity| identity.file_id),
        volume_serial: identity.map(|identity| identity.volume_serial),
        reparse_tag: platform_reparse_tag(&metadata, file_type),
        link_count: identity.map(|identity| identity.link_count),
    })
}

#[cfg(windows)]
fn platform_creation_time(metadata: &fs::Metadata) -> Option<SystemTime> {
    use std::os::windows::fs::MetadataExt;

    windows_filetime_to_system_time(metadata.creation_time())
}

#[cfg(not(windows))]
fn platform_creation_time(_metadata: &fs::Metadata) -> Option<SystemTime> {
    None
}

#[cfg(windows)]
fn platform_file_attributes(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::windows::fs::MetadataExt;

    Some(metadata.file_attributes())
}

#[cfg(not(windows))]
fn platform_file_attributes(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

#[cfg(windows)]
fn platform_reparse_tag(metadata: &fs::Metadata, file_type: FileType) -> Option<u32> {
    use std::os::windows::fs::MetadataExt;

    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return None;
    }

    if file_type == FileType::Symlink {
        Some(IO_REPARSE_TAG_SYMLINK)
    } else {
        None
    }
}

#[cfg(not(windows))]
fn platform_reparse_tag(_metadata: &fs::Metadata, _file_type: FileType) -> Option<u32> {
    None
}

#[cfg(windows)]
fn platform_file_identity(path: &Path) -> Option<PlatformFileIdentity> {
    use std::mem::zeroed;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let path = crate::path::to_long_path_safe(path);
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    let _ = unsafe { CloseHandle(handle) };
    if ok == 0 {
        return None;
    }

    Some(PlatformFileIdentity {
        file_id: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        volume_serial: info.dwVolumeSerialNumber,
        link_count: u64::from(info.nNumberOfLinks),
    })
}

#[cfg(not(windows))]
fn platform_file_identity(_path: &Path) -> Option<PlatformFileIdentity> {
    None
}

#[cfg(windows)]
fn windows_filetime_to_system_time(filetime: u64) -> Option<SystemTime> {
    if filetime == 0 {
        return None;
    }

    const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    if filetime < WINDOWS_TO_UNIX_EPOCH_100NS {
        return None;
    }
    let unix_100ns = filetime - WINDOWS_TO_UNIX_EPOCH_100NS;
    Some(UNIX_EPOCH + Duration::from_nanos(unix_100ns.saturating_mul(100)))
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn windows_filetime_to_system_time(_filetime: u64) -> Option<SystemTime> {
    None
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn reads_regular_file_metadata_without_following_symlinks() {
        let root = unique_temp_dir("rsync-winfs-metadata");
        fs::create_dir_all(&root).unwrap();
        let file = root.join("file.txt");
        let mut handle = fs::File::create(&file).unwrap();
        handle.write_all(b"abc").unwrap();

        let metadata = read_windows_metadata(&file).unwrap();
        assert_eq!(metadata.portable.file_type, FileType::File);
        assert_eq!(metadata.portable.len, 3);

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn reads_hardlink_identity_fields_on_windows() {
        let root = unique_temp_dir("rsync-winfs-hardlink-metadata");
        fs::create_dir_all(&root).unwrap();
        let file = root.join("file.txt");
        let link = root.join("link.txt");
        fs::write(&file, b"abc").unwrap();
        fs::hard_link(&file, &link).unwrap();

        let file_metadata = read_windows_metadata(&file).unwrap();
        let link_metadata = read_windows_metadata(&link).unwrap();

        assert_eq!(file_metadata.file_id, link_metadata.file_id);
        assert_eq!(file_metadata.volume_serial, link_metadata.volume_serial);
        assert!(file_metadata.link_count.is_some_and(|count| count >= 2));

        fs::remove_dir_all(root).unwrap();
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        path.push(format!("{prefix}-{}-{nanos}", std::process::id()));
        path
    }
}
