use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VssSnapshotStatus {
    pub requested: bool,
    pub available: bool,
    pub message: String,
}

pub fn vss_snapshot_status(requested: bool) -> VssSnapshotStatus {
    if requested {
        VssSnapshotStatus {
            requested: true,
            available: false,
            message:
                "VSS snapshot source mode is available only while a runtime snapshot is active"
                    .to_string(),
        }
    } else {
        VssSnapshotStatus {
            requested: false,
            available: false,
            message: "VSS snapshot source mode was not requested".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct VssSnapshot {
    original_root: PathBuf,
    snapshot_root: PathBuf,
    shadow_id: String,
}

impl VssSnapshot {
    pub fn create_for_source(source: &Path) -> io::Result<Self> {
        platform_create_for_source(source)
    }

    pub fn original_root(&self) -> &Path {
        &self.original_root
    }

    pub fn snapshot_root(&self) -> &Path {
        &self.snapshot_root
    }

    pub fn map_source_path(&self, source_path: &Path) -> Option<PathBuf> {
        let path = canonicalize_existing(source_path).ok()?;
        if path == self.original_root {
            return Some(self.snapshot_root.clone());
        }
        path.strip_prefix(&self.original_root)
            .ok()
            .map(|relative| self.snapshot_root.join(relative))
    }
}

impl Drop for VssSnapshot {
    fn drop(&mut self) {
        let _ = platform_delete_shadow_copy(&self.shadow_id);
    }
}

#[cfg(windows)]
fn platform_create_for_source(source: &Path) -> io::Result<VssSnapshot> {
    let original_root = canonicalize_existing(source)?;
    let volume_root = volume_root_for_path(&original_root)?;
    let relative_root = original_root
        .strip_prefix(&volume_root)
        .unwrap_or(Path::new(""));
    let created = create_shadow_copy(&volume_root)?;
    let snapshot_root = append_snapshot_relative(&created.device_object, relative_root);

    Ok(VssSnapshot {
        original_root,
        snapshot_root,
        shadow_id: created.shadow_id,
    })
}

#[cfg(not(windows))]
fn platform_create_for_source(_source: &Path) -> io::Result<VssSnapshot> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "VSS snapshot source mode is only available on Windows",
    ))
}

#[cfg(windows)]
#[derive(Debug)]
struct CreatedShadowCopy {
    shadow_id: String,
    device_object: PathBuf,
}

#[cfg(windows)]
fn volume_root_for_path(path: &Path) -> io::Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    use windows_sys::Win32::Storage::FileSystem::GetVolumePathNameW;

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut buffer = vec![0_u16; 32_768];
    let ok = unsafe {
        GetVolumePathNameW(
            wide_path.as_ptr(),
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).unwrap_or(u32::MAX),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let nul = buffer
        .iter()
        .position(|code| *code == 0)
        .unwrap_or(buffer.len());
    Ok(PathBuf::from(OsString::from_wide(&buffer[..nul])))
}

#[cfg(windows)]
fn create_shadow_copy(volume_root: &Path) -> io::Result<CreatedShadowCopy> {
    let volume = volume_root.as_os_str().to_string_lossy();
    let volume = powershell_single_quoted(&volume);
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $result = ([WMIClass]'root\\cimv2:Win32_ShadowCopy').Create({volume}, 'ClientAccessible'); \
         if ($result.ReturnValue -ne 0) {{ Write-Error ('VSS snapshot creation failed with return value ' + $result.ReturnValue); exit 1 }}; \
         $shadow = Get-WmiObject Win32_ShadowCopy | Where-Object {{ $_.ID -eq $result.ShadowID }} | Select-Object -First 1; \
         if ($null -eq $shadow) {{ Write-Error 'VSS snapshot was created but could not be found'; exit 1 }}; \
         Write-Output ($result.ShadowID + \"`t\" + $shadow.DeviceObject)"
    );
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .output()
        .map_err(|err| io::Error::new(err.kind(), format!("start PowerShell for VSS: {err}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("VSS snapshot creation failed: {stderr}{stdout}"),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "VSS returned no snapshot id"))?;
    let (shadow_id, device_object) = line.split_once('\t').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("VSS returned malformed snapshot descriptor `{line}`"),
        )
    })?;

    Ok(CreatedShadowCopy {
        shadow_id: shadow_id.trim().to_string(),
        device_object: PathBuf::from(device_object.trim()),
    })
}

#[cfg(windows)]
fn append_snapshot_relative(device_object: &Path, relative: &Path) -> PathBuf {
    let mut text = device_object
        .as_os_str()
        .to_string_lossy()
        .replace('/', "\\");
    if !text.ends_with('\\') {
        text.push('\\');
    }
    let mut path = PathBuf::from(text);
    if relative.as_os_str().is_empty() {
        return path;
    }
    path.push(relative);
    path
}

#[cfg(windows)]
fn platform_delete_shadow_copy(shadow_id: &str) -> io::Result<()> {
    if shadow_id.trim().is_empty() {
        return Ok(());
    }
    let shadow_id = powershell_single_quoted(shadow_id);
    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
         Get-WmiObject Win32_ShadowCopy | Where-Object {{ $_.ID -eq {shadow_id} }} | ForEach-Object {{ $_.Delete() | Out-Null }}"
    );
    let _ = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .output()?;
    Ok(())
}

#[cfg(not(windows))]
fn platform_delete_shadow_copy(_shadow_id: &str) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn powershell_single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn canonicalize_existing(path: &Path) -> io::Result<PathBuf> {
    std::fs::canonicalize(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_vss_status_is_explicitly_unavailable() {
        let status = vss_snapshot_status(true);

        assert!(status.requested);
        assert!(!status.available);
        assert!(status.message.contains("runtime snapshot"));
    }

    #[cfg(windows)]
    #[test]
    fn snapshot_source_maps_child_paths_under_shadow_copy_or_skips_cleanly() {
        let root = unique_temp_dir("rsync-winfs-vss-source");
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("locked.txt");
        std::fs::write(&file, b"snapshot source").unwrap();

        let snapshot = match VssSnapshot::create_for_source(&root) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                eprintln!("SKIP: VSS snapshot creation unavailable in this environment: {err}");
                std::fs::remove_dir_all(root).unwrap();
                return;
            }
        };

        let mapped = snapshot
            .map_source_path(&file)
            .expect("source child path should map into the snapshot");

        assert_eq!(std::fs::read(mapped).unwrap(), b"snapshot source");
        drop(snapshot);
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
