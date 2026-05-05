use std::io;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternateDataStream {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlternateDataStreamCopyReport {
    pub copied: usize,
    pub bytes: u64,
    pub unavailable: bool,
}

pub fn enumerate_alternate_data_streams(path: &Path) -> io::Result<Vec<AlternateDataStream>> {
    platform_alternate_data_streams(path)
}

pub fn copy_alternate_data_streams(
    source: &Path,
    dest: &Path,
) -> io::Result<AlternateDataStreamCopyReport> {
    platform_copy_alternate_data_streams(source, dest)
}

#[cfg(windows)]
fn platform_alternate_data_streams(path: &Path) -> io::Result<Vec<AlternateDataStream>> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::{GetLastError, ERROR_HANDLE_EOF, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
        WIN32_FIND_STREAM_DATA,
    };

    let path = crate::path::to_long_path_safe(path);
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut data = WIN32_FIND_STREAM_DATA::default();
    let handle = unsafe {
        FindFirstStreamW(
            wide_path.as_ptr(),
            FindStreamInfoStandard,
            (&mut data as *mut WIN32_FIND_STREAM_DATA).cast(),
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        if err == ERROR_HANDLE_EOF {
            return Ok(Vec::new());
        }
        return Err(io::Error::from_raw_os_error(err as i32));
    }

    let mut streams = Vec::new();
    loop {
        if let Some(stream) = stream_from_find_data(&data) {
            streams.push(stream);
        }

        let ok =
            unsafe { FindNextStreamW(handle, (&mut data as *mut WIN32_FIND_STREAM_DATA).cast()) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            let _ = unsafe { FindClose(handle) };
            if err == ERROR_HANDLE_EOF {
                break;
            }
            return Err(io::Error::from_raw_os_error(err as i32));
        }
    }

    Ok(streams)
}

#[cfg(windows)]
fn platform_copy_alternate_data_streams(
    source: &Path,
    dest: &Path,
) -> io::Result<AlternateDataStreamCopyReport> {
    let streams = platform_alternate_data_streams(source)?;
    let mut copied = 0;
    let mut bytes = 0;
    for stream in streams {
        if !is_valid_stream_name(&stream.name) {
            continue;
        }
        let mut input = std::fs::File::open(stream_data_path(source, &stream.name))?;
        let mut output = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(stream_data_path(dest, &stream.name))?;
        std::io::copy(&mut input, &mut output)?;
        copied += 1;
        bytes += stream.size;
    }
    Ok(AlternateDataStreamCopyReport {
        copied,
        bytes,
        unavailable: false,
    })
}

#[cfg(not(windows))]
fn platform_alternate_data_streams(path: &Path) -> io::Result<Vec<AlternateDataStream>> {
    let _ = std::fs::metadata(path)?;
    Ok(Vec::new())
}

#[cfg(not(windows))]
fn platform_copy_alternate_data_streams(
    source: &Path,
    dest: &Path,
) -> io::Result<AlternateDataStreamCopyReport> {
    let _ = std::fs::metadata(source)?;
    let _ = std::fs::metadata(dest)?;
    Ok(AlternateDataStreamCopyReport {
        copied: 0,
        bytes: 0,
        unavailable: true,
    })
}

#[cfg(windows)]
fn stream_from_find_data(
    data: &windows_sys::Win32::Storage::FileSystem::WIN32_FIND_STREAM_DATA,
) -> Option<AlternateDataStream> {
    let nul = data
        .cStreamName
        .iter()
        .position(|code| *code == 0)
        .unwrap_or(data.cStreamName.len());
    let raw = String::from_utf16_lossy(&data.cStreamName[..nul]);
    let name = normalize_stream_name(&raw)?;
    let size = u64::try_from(data.StreamSize).unwrap_or(0);
    Some(AlternateDataStream { name, size })
}

#[cfg(windows)]
fn normalize_stream_name(raw: &str) -> Option<String> {
    if raw == "::$DATA" {
        return None;
    }
    let without_prefix = raw.strip_prefix(':')?;
    let name = without_prefix.strip_suffix(":$DATA")?;
    (!name.is_empty()).then(|| name.to_string())
}

#[cfg(windows)]
fn stream_data_path(path: &Path, stream_name: &str) -> std::path::PathBuf {
    let mut stream_path = crate::path::to_long_path_safe(path).into_os_string();
    stream_path.push(format!(":{stream_name}"));
    std::path::PathBuf::from(stream_path)
}

fn is_valid_stream_name(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(|ch| matches!(ch, '\0' | ':' | '\\' | '/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alternate_data_stream_struct_records_name_and_size() {
        let stream = AlternateDataStream {
            name: "Zone.Identifier".to_string(),
            size: 26,
        };

        assert_eq!(stream.name, "Zone.Identifier");
        assert_eq!(stream.size, 26);
    }

    #[test]
    fn default_data_stream_name_is_not_valid_ads_name() {
        assert!(is_valid_stream_name("Zone.Identifier"));
        assert!(!is_valid_stream_name(""));
        assert!(!is_valid_stream_name(":$DATA"));
        assert!(!is_valid_stream_name("bad:name"));
    }

    #[cfg(windows)]
    #[test]
    fn streams_copy_named_payloads_without_treating_default_data_as_ads() {
        let root = unique_temp_dir("rsync-winfs-streams");
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("source.txt");
        let dest = root.join("dest.txt");
        std::fs::write(&source, b"default-source").unwrap();
        std::fs::write(&dest, b"default-dest").unwrap();
        std::fs::write(stream_data_path(&source, "Zone.Identifier"), b"zone").unwrap();

        let streams = enumerate_alternate_data_streams(&source).unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].name, "Zone.Identifier");

        let report = copy_alternate_data_streams(&source, &dest).unwrap();

        assert_eq!(report.copied, 1);
        assert_eq!(report.bytes, 4);
        assert_eq!(std::fs::read(&dest).unwrap(), b"default-dest");
        assert_eq!(
            std::fs::read(stream_data_path(&dest, "Zone.Identifier")).unwrap(),
            b"zone"
        );

        std::fs::remove_dir_all(root).unwrap();
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
