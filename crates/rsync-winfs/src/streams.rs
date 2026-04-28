use std::io;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternateDataStream {
    pub name: String,
    pub size: u64,
}

pub fn enumerate_alternate_data_streams(path: &Path) -> io::Result<Vec<AlternateDataStream>> {
    platform_alternate_data_streams(path)
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

#[cfg(not(windows))]
fn platform_alternate_data_streams(path: &Path) -> io::Result<Vec<AlternateDataStream>> {
    let _ = std::fs::metadata(path)?;
    Ok(Vec::new())
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
}
