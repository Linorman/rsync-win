use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsDriveKind {
    Unknown,
    NoRootDir,
    Removable,
    Fixed,
    Remote,
    Cdrom,
    RamDisk,
}

impl WindowsDriveKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::NoRootDir => "missing root",
            Self::Removable => "removable",
            Self::Fixed => "fixed",
            Self::Remote => "network",
            Self::Cdrom => "optical",
            Self::RamDisk => "ram disk",
        }
    }
}

#[cfg(windows)]
pub fn drive_kind_for_path(path: &Path) -> Option<WindowsDriveKind> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Component, PathBuf, Prefix};
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

    const DRIVE_UNKNOWN: u32 = 0;
    const DRIVE_NO_ROOT_DIR: u32 = 1;
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;
    const DRIVE_REMOTE: u32 = 4;
    const DRIVE_CDROM: u32 = 5;
    const DRIVE_RAMDISK: u32 = 6;

    fn root_for_path(path: &Path) -> Option<PathBuf> {
        let Component::Prefix(prefix) = path.components().next()? else {
            return None;
        };
        match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                Some(PathBuf::from(format!("{}:\\", char::from(letter))))
            }
            Prefix::UNC(server, share) => {
                let mut root = OsString::from(r"\\");
                root.push(server);
                root.push(r"\");
                root.push(share);
                root.push(r"\");
                Some(PathBuf::from(root))
            }
            Prefix::VerbatimUNC(server, share) => {
                let mut root = OsString::from(r"\\?\UNC\");
                root.push(server);
                root.push(r"\");
                root.push(share);
                root.push(r"\");
                Some(PathBuf::from(root))
            }
            _ => None,
        }
    }

    let root = root_for_path(path)?;
    let root_wide: Vec<u16> = root.as_os_str().encode_wide().chain([0]).collect();
    let kind = unsafe { GetDriveTypeW(root_wide.as_ptr()) };
    Some(match kind {
        DRIVE_UNKNOWN => WindowsDriveKind::Unknown,
        DRIVE_NO_ROOT_DIR => WindowsDriveKind::NoRootDir,
        DRIVE_REMOVABLE => WindowsDriveKind::Removable,
        DRIVE_FIXED => WindowsDriveKind::Fixed,
        DRIVE_REMOTE => WindowsDriveKind::Remote,
        DRIVE_CDROM => WindowsDriveKind::Cdrom,
        DRIVE_RAMDISK => WindowsDriveKind::RamDisk,
        _ => WindowsDriveKind::Unknown,
    })
}

#[cfg(not(windows))]
pub fn drive_kind_for_path(_path: &Path) -> Option<WindowsDriveKind> {
    None
}
