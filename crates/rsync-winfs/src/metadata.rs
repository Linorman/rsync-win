use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rsync_fs::{default_permissions, FileType, HardlinkId, PortableMetadata};

use crate::security::capture_security_descriptor_summary;
use crate::sidecar::NtfsNativeSidecar;
use crate::streams::enumerate_alternate_data_streams;
use crate::vss::vss_snapshot_status;

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

const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const SAFE_RESTORE_ATTRIBUTE_MASK: u32 = FILE_ATTRIBUTE_READONLY
    | FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM
    | FILE_ATTRIBUTE_ARCHIVE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsAttributeRestore {
    pub requested: Option<u32>,
    pub applied_mask: u32,
    pub degraded_mask: u32,
    pub available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseRange {
    pub offset: u64,
    pub len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseRangeRestore {
    pub requested: bool,
    pub applied: bool,
    pub available: bool,
    pub zeroed_ranges: usize,
    pub message: Option<String>,
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
        mode: Some(default_permissions(file_type)),
        symlink_target: if file_type == FileType::Symlink {
            fs::read_link(path).ok()
        } else {
            None
        },
        hardlink_id: identity.map(|identity| HardlinkId {
            volume: u64::from(identity.volume_serial),
            file: identity.file_id,
        }),
        hardlink_count: identity.map(|identity| identity.link_count),
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
    let sparse_file = attributes.is_some_and(|attrs| attrs & FILE_ATTRIBUTE_SPARSE_FILE != 0);
    let sparse_ranges = if sparse_file && metadata.portable.file_type == FileType::File {
        query_sparse_allocated_ranges(path, metadata.portable.len)?
    } else {
        Vec::new()
    };
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
        sparse_file,
        sparse_ranges,
        reparse_tag: metadata.reparse_tag,
        file_id: metadata.file_id,
        volume_serial: metadata.volume_serial,
        link_count: metadata.link_count,
        security: capture_security_descriptor_summary(path)?,
        streams: enumerate_alternate_data_streams(path)?,
        vss: vss_snapshot_status(request_vss),
    })
}

pub fn restore_safe_windows_attributes(
    path: &Path,
    attributes: Option<u32>,
) -> std::io::Result<WindowsAttributeRestore> {
    platform_restore_safe_windows_attributes(path, attributes)
}

pub fn restore_creation_time(
    path: &Path,
    creation_time: Option<SystemTime>,
) -> std::io::Result<bool> {
    platform_restore_creation_time(path, creation_time)
}

pub fn query_sparse_allocated_ranges(
    path: &Path,
    file_len: u64,
) -> std::io::Result<Vec<SparseRange>> {
    platform_query_sparse_allocated_ranges(path, file_len)
}

pub fn restore_sparse_ranges(
    path: &Path,
    file_len: u64,
    allocated_ranges: &[SparseRange],
) -> std::io::Result<SparseRangeRestore> {
    validate_sparse_ranges(file_len, allocated_ranges)?;
    platform_restore_sparse_ranges(path, file_len, allocated_ranges)
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
fn platform_restore_creation_time(
    path: &Path,
    creation_time: Option<SystemTime>,
) -> std::io::Result<bool> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, SetFileTime, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING,
    };

    let Some(creation_time) = creation_time else {
        return Ok(false);
    };
    let filetime = system_time_to_windows_filetime(creation_time)?;
    let creation = FILETIME {
        dwLowDateTime: filetime as u32,
        dwHighDateTime: (filetime >> 32) as u32,
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
            FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let ok = unsafe { SetFileTime(handle, &creation, null(), null()) };
    let close_result = unsafe { CloseHandle(handle) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if close_result == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(true)
}

#[cfg(not(windows))]
fn platform_restore_creation_time(
    path: &Path,
    _creation_time: Option<SystemTime>,
) -> std::io::Result<bool> {
    let _ = fs::metadata(path)?;
    Ok(false)
}

#[cfg(windows)]
fn platform_query_sparse_allocated_ranges(
    path: &Path,
    file_len: u64,
) -> std::io::Result<Vec<SparseRange>> {
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_MORE_DATA, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_DATA,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Ioctl::{
        FILE_ALLOCATED_RANGE_BUFFER, FSCTL_QUERY_ALLOCATED_RANGES,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    if file_len == 0 {
        return Ok(Vec::new());
    }

    let path = crate::path::to_long_path_safe(path);
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_READ_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    let mut ranges = Vec::new();
    let mut next_offset = 0;
    while next_offset < file_len {
        let mut query = FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: next_offset as i64,
            Length: (file_len - next_offset) as i64,
        };
        let mut output = vec![unsafe { zeroed::<FILE_ALLOCATED_RANGE_BUFFER>() }; 1024];
        let mut bytes_returned = 0;
        let result = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_QUERY_ALLOCATED_RANGES,
                (&mut query as *mut FILE_ALLOCATED_RANGE_BUFFER).cast(),
                size_of::<FILE_ALLOCATED_RANGE_BUFFER>() as u32,
                output.as_mut_ptr().cast(),
                (output.len() * size_of::<FILE_ALLOCATED_RANGE_BUFFER>()) as u32,
                &mut bytes_returned,
                null_mut(),
            )
        };
        if result == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_MORE_DATA as i32) || bytes_returned == 0 {
                let _ = unsafe { CloseHandle(handle) };
                return Err(error);
            }
        }

        let count = bytes_returned as usize / size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
        if count == 0 {
            break;
        }
        output.truncate(count);
        let mut last_end = next_offset;
        for range in output {
            if range.Length <= 0 || range.FileOffset < 0 {
                continue;
            }
            let offset = range.FileOffset as u64;
            let len = range.Length as u64;
            last_end = offset.saturating_add(len);
            ranges.push(SparseRange { offset, len });
        }
        if result != 0 {
            break;
        }
        if last_end <= next_offset {
            let _ = unsafe { CloseHandle(handle) };
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Windows returned sparse ranges without forward progress",
            ));
        }
        next_offset = last_end;
    }
    let close_result = unsafe { CloseHandle(handle) };
    if close_result == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(ranges)
}

#[cfg(not(windows))]
fn platform_query_sparse_allocated_ranges(
    path: &Path,
    file_len: u64,
) -> std::io::Result<Vec<SparseRange>> {
    let _ = fs::metadata(path)?;
    Ok((file_len > 0)
        .then_some(SparseRange {
            offset: 0,
            len: file_len,
        })
        .into_iter()
        .collect())
}

#[cfg(windows)]
fn platform_restore_sparse_ranges(
    path: &Path,
    file_len: u64,
    allocated_ranges: &[SparseRange],
) -> std::io::Result<SparseRangeRestore> {
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Ioctl::{FILE_ZERO_DATA_INFORMATION, FSCTL_SET_ZERO_DATA};
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const FSCTL_SET_SPARSE: u32 = 0x000900C4;

    if file_len == 0 {
        return Ok(SparseRangeRestore {
            requested: false,
            applied: false,
            available: true,
            zeroed_ranges: 0,
            message: None,
        });
    }

    let path = crate::path::to_long_path_safe(path);
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    let mut bytes_returned = 0;
    let sparse_result = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_SPARSE,
            null(),
            0,
            null_mut(),
            0,
            &mut bytes_returned,
            null_mut(),
        )
    };
    if sparse_result == 0 {
        let error = std::io::Error::last_os_error();
        let _ = unsafe { CloseHandle(handle) };
        return Err(error);
    }

    let mut zeroed_ranges = 0;
    for hole in sparse_holes(file_len, allocated_ranges) {
        let mut zero = FILE_ZERO_DATA_INFORMATION {
            FileOffset: hole.offset as i64,
            BeyondFinalZero: (hole.offset + hole.len) as i64,
        };
        let zero_result = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_SET_ZERO_DATA,
                (&mut zero as *mut FILE_ZERO_DATA_INFORMATION).cast(),
                size_of::<FILE_ZERO_DATA_INFORMATION>() as u32,
                null_mut(),
                0,
                &mut bytes_returned,
                null_mut(),
            )
        };
        if zero_result == 0 {
            let error = std::io::Error::last_os_error();
            let _ = unsafe { CloseHandle(handle) };
            return Err(error);
        }
        zeroed_ranges += 1;
    }

    let close_result = unsafe { CloseHandle(handle) };
    if close_result == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(SparseRangeRestore {
        requested: true,
        applied: true,
        available: true,
        zeroed_ranges,
        message: None,
    })
}

#[cfg(not(windows))]
fn platform_restore_sparse_ranges(
    path: &Path,
    file_len: u64,
    allocated_ranges: &[SparseRange],
) -> std::io::Result<SparseRangeRestore> {
    let _ = fs::metadata(path)?;
    Ok(SparseRangeRestore {
        requested: file_len > 0,
        applied: false,
        available: false,
        zeroed_ranges: 0,
        message: Some(format!(
            "sparse range restore is only available on Windows; requested {} allocated ranges",
            allocated_ranges.len()
        )),
    })
}

fn validate_sparse_ranges(file_len: u64, allocated_ranges: &[SparseRange]) -> std::io::Result<()> {
    let mut previous_end = 0;
    for range in allocated_ranges {
        if range.len == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sparse allocated ranges must not be empty",
            ));
        }
        let end = range.offset.checked_add(range.len).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sparse allocated range overflows u64",
            )
        })?;
        if end > file_len || range.offset < previous_end {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sparse allocated ranges must be sorted, non-overlapping, and within file length",
            ));
        }
        previous_end = end;
    }
    Ok(())
}

fn sparse_holes(file_len: u64, allocated_ranges: &[SparseRange]) -> Vec<SparseRange> {
    let mut holes = Vec::new();
    let mut cursor = 0;
    for range in allocated_ranges {
        if cursor < range.offset {
            holes.push(SparseRange {
                offset: cursor,
                len: range.offset - cursor,
            });
        }
        cursor = range.offset + range.len;
    }
    if cursor < file_len {
        holes.push(SparseRange {
            offset: cursor,
            len: file_len - cursor,
        });
    }
    holes
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
fn platform_restore_safe_windows_attributes(
    path: &Path,
    attributes: Option<u32>,
) -> std::io::Result<WindowsAttributeRestore> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, SetFileAttributesW, INVALID_FILE_ATTRIBUTES,
    };

    let requested = attributes;
    let Some(attributes) = attributes else {
        return Ok(WindowsAttributeRestore {
            requested,
            applied_mask: 0,
            degraded_mask: 0,
            available: true,
        });
    };
    let path = crate::path::to_long_path_safe(path);
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let current = unsafe { GetFileAttributesW(wide_path.as_ptr()) };
    if current == INVALID_FILE_ATTRIBUTES {
        return Err(std::io::Error::last_os_error());
    }
    let safe_bits = attributes & SAFE_RESTORE_ATTRIBUTE_MASK;
    let next = (current & !SAFE_RESTORE_ATTRIBUTE_MASK) | safe_bits;
    if unsafe { SetFileAttributesW(wide_path.as_ptr(), next) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(WindowsAttributeRestore {
        requested,
        applied_mask: safe_bits,
        degraded_mask: attributes & !SAFE_RESTORE_ATTRIBUTE_MASK,
        available: true,
    })
}

#[cfg(not(windows))]
fn platform_restore_safe_windows_attributes(
    path: &Path,
    attributes: Option<u32>,
) -> std::io::Result<WindowsAttributeRestore> {
    let _ = fs::metadata(path)?;
    Ok(WindowsAttributeRestore {
        requested: attributes,
        applied_mask: 0,
        degraded_mask: attributes.unwrap_or(0) & SAFE_RESTORE_ATTRIBUTE_MASK,
        available: false,
    })
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

#[cfg(windows)]
fn system_time_to_windows_filetime(time: SystemTime) -> std::io::Result<u64> {
    const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    let duration = time.duration_since(UNIX_EPOCH).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "creation time predates the Unix epoch",
        )
    })?;
    Ok(WINDOWS_TO_UNIX_EPOCH_100NS
        + duration.as_secs().saturating_mul(10_000_000)
        + u64::from(duration.subsec_nanos() / 100))
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
    fn windows_attributes_restores_safe_attribute_subset() {
        let root = unique_temp_dir("rsync-winfs-windows-attributes");
        fs::create_dir_all(&root).unwrap();
        let file = root.join("file.txt");
        fs::write(&file, b"abc").unwrap();

        let report = restore_safe_windows_attributes(
            &file,
            Some(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_SPARSE_FILE),
        )
        .unwrap();
        let metadata = read_windows_metadata(&file).unwrap();

        assert_eq!(
            report.applied_mask,
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE
        );
        assert_eq!(report.degraded_mask, FILE_ATTRIBUTE_SPARSE_FILE);
        assert!(metadata
            .attributes
            .is_some_and(|attrs| attrs & FILE_ATTRIBUTE_READONLY != 0));

        restore_safe_windows_attributes(&file, Some(FILE_ATTRIBUTE_ARCHIVE)).unwrap();
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

    #[cfg(windows)]
    #[test]
    fn windows_creation_time_restore_applies_requested_time() {
        let root = unique_temp_dir("rsync-winfs-creation-time");
        fs::create_dir_all(&root).unwrap();
        let file = root.join("file.txt");
        fs::write(&file, b"abc").unwrap();
        let requested = UNIX_EPOCH + Duration::from_secs(1_600_000_123);

        assert!(restore_creation_time(&file, Some(requested)).unwrap());

        let restored = read_windows_metadata(&file).unwrap().creation_time.unwrap();
        assert_eq!(restored, requested);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn sparse_ranges_restore_punches_unallocated_gaps() {
        let root = unique_temp_dir("rsync-winfs-sparse-ranges");
        fs::create_dir_all(&root).unwrap();
        let file = root.join("sparse.bin");
        let len = 1024 * 1024;
        let range_len = 64 * 1024;
        fs::write(&file, vec![0_u8; len]).unwrap();
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut handle = fs::OpenOptions::new().write(true).open(&file).unwrap();
            handle.write_all(&vec![1_u8; range_len]).unwrap();
            handle
                .seek(SeekFrom::Start((len - range_len) as u64))
                .unwrap();
            handle.write_all(&vec![2_u8; range_len]).unwrap();
        }
        let ranges = vec![
            SparseRange {
                offset: 0,
                len: range_len as u64,
            },
            SparseRange {
                offset: (len - range_len) as u64,
                len: range_len as u64,
            },
        ];

        let restore = restore_sparse_ranges(&file, len as u64, &ranges).unwrap();

        assert!(restore.applied);
        assert_eq!(
            query_sparse_allocated_ranges(&file, len as u64).unwrap(),
            ranges
        );
        assert_eq!(fs::metadata(&file).unwrap().len(), len as u64);

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
