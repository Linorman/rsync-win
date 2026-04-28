use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rsync_fs::{default_permissions, FileType, PortableMetadata};

use crate::security::{capture_security_descriptor_summary, SecurityDescriptorSummary};
use crate::streams::{enumerate_alternate_data_streams, AlternateDataStream};
use crate::vss::{vss_snapshot_status, VssSnapshotStatus};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsNativeSidecar {
    pub path: PathBuf,
    pub file_type: FileType,
    pub len: u64,
    pub modified_unix_nanos: Option<i128>,
    pub creation_time_unix_nanos: Option<i128>,
    pub attributes: Option<u32>,
    pub sparse_file: bool,
    pub reparse_tag: Option<u32>,
    pub file_id: Option<u64>,
    pub volume_serial: Option<u32>,
    pub link_count: Option<u64>,
    pub security: SecurityDescriptorSummary,
    pub streams: Vec<AlternateDataStream>,
    pub vss: VssSnapshotStatus,
}

impl NtfsNativeSidecar {
    pub fn manifest(&self) -> String {
        let mut output = String::new();
        output.push_str("rsync-win ntfs-native sidecar v1\n");
        output.push_str(&format!("path={}\n", self.path.display()));
        output.push_str(&format!("file_type={:?}\n", self.file_type));
        output.push_str(&format!("len={}\n", self.len));
        output.push_str(&format!("modified={:?}\n", self.modified_unix_nanos));
        output.push_str(&format!(
            "creation_time={:?}\n",
            self.creation_time_unix_nanos
        ));
        output.push_str(&format!("attributes={:?}\n", self.attributes));
        output.push_str(&format!("sparse_file={}\n", self.sparse_file));
        output.push_str(&format!("reparse_tag={:?}\n", self.reparse_tag));
        output.push_str(&format!("file_id={:?}\n", self.file_id));
        output.push_str(&format!("volume_serial={:?}\n", self.volume_serial));
        output.push_str(&format!("link_count={:?}\n", self.link_count));
        output.push_str(&format!("security_captured={}\n", self.security.captured));
        output.push_str(&format!("security_len={:?}\n", self.security.byte_len));
        output.push_str(&format!("security_hash={:?}\n", self.security.stable_hash));
        output.push_str(&format!("streams={}\n", self.streams.len()));
        for stream in &self.streams {
            output.push_str(&format!("stream={},{}\n", stream.name, stream.size));
        }
        output.push_str(&format!("vss_requested={}\n", self.vss.requested));
        output.push_str(&format!("vss_available={}\n", self.vss.available));
        output
    }
}

const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;

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
        mode: Some(default_permissions(file_type)),
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

pub fn capture_ntfs_native_sidecar(
    path: &Path,
    request_vss: bool,
) -> std::io::Result<NtfsNativeSidecar> {
    let metadata = read_windows_metadata(path)?;
    let attributes = metadata.attributes;
    Ok(NtfsNativeSidecar {
        path: path.to_path_buf(),
        file_type: metadata.portable.file_type,
        len: metadata.portable.len,
        modified_unix_nanos: metadata
            .portable
            .modified
            .and_then(system_time_to_unix_nanos),
        creation_time_unix_nanos: metadata.creation_time.and_then(system_time_to_unix_nanos),
        attributes,
        sparse_file: attributes.is_some_and(|attrs| attrs & FILE_ATTRIBUTE_SPARSE_FILE != 0),
        reparse_tag: metadata.reparse_tag,
        file_id: metadata.file_id,
        volume_serial: metadata.volume_serial,
        link_count: metadata.link_count,
        security: capture_security_descriptor_summary(path)?,
        streams: enumerate_alternate_data_streams(path)?,
        vss: vss_snapshot_status(request_vss),
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

fn system_time_to_unix_nanos(time: SystemTime) -> Option<i128> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => Some(
            i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos()),
        ),
        Err(err) => {
            let duration = err.duration();
            Some(
                -(i128::from(duration.as_secs()) * 1_000_000_000
                    + i128::from(duration.subsec_nanos())),
            )
        }
    }
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
        assert_eq!(metadata.portable.mode, Some(0o644));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn captures_ntfs_native_sidecar_manifest_for_regular_file() {
        let root = unique_temp_dir("rsync-winfs-sidecar");
        fs::create_dir_all(&root).unwrap();
        let file = root.join("file.txt");
        fs::write(&file, b"abc").unwrap();

        let sidecar = capture_ntfs_native_sidecar(&file, false).unwrap();
        let manifest = sidecar.manifest();

        assert_eq!(sidecar.file_type, FileType::File);
        assert_eq!(sidecar.len, 3);
        assert!(manifest.contains("rsync-win ntfs-native sidecar v1"));
        assert!(manifest.contains("file_type=File"));
        assert!(manifest.contains("streams="));
        assert!(manifest.contains("vss_requested=false"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sidecar_marks_requested_vss_as_unavailable() {
        let root = unique_temp_dir("rsync-winfs-sidecar-vss");
        fs::create_dir_all(&root).unwrap();
        let file = root.join("file.txt");
        fs::write(&file, b"abc").unwrap();

        let sidecar = capture_ntfs_native_sidecar(&file, true).unwrap();

        assert!(sidecar.vss.requested);
        assert!(!sidecar.vss.available);

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
