use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkCapabilities {
    pub symlink_files: bool,
    pub symlink_dirs: bool,
    pub hardlinks: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReparsePointKind {
    NotReparsePoint,
    Symlink,
    JunctionOrMountPoint,
    Other(u32),
    UnknownReparsePoint,
}

pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

pub fn detect_link_capabilities() -> LinkCapabilities {
    let root = unique_temp_dir("rsync-winfs-links");
    if fs::create_dir_all(&root).is_err() {
        return LinkCapabilities {
            symlink_files: false,
            symlink_dirs: false,
            hardlinks: false,
        };
    }

    let source_file = root.join("source.txt");
    let source_dir = root.join("source-dir");
    let file_link = root.join("file-link.txt");
    let dir_link = root.join("dir-link");
    let hard_link = root.join("hard-link.txt");
    let _ = fs::write(&source_file, b"x");
    let _ = fs::create_dir(&source_dir);

    let symlink_files = create_file_symlink(&source_file, &file_link).is_ok();
    let symlink_dirs = create_dir_symlink(&source_dir, &dir_link).is_ok();
    let hardlinks = fs::hard_link(&source_file, hard_link).is_ok();

    let _ = fs::remove_dir_all(&root);

    LinkCapabilities {
        symlink_files,
        symlink_dirs,
        hardlinks,
    }
}

pub fn classify_reparse_point(attributes: u32, reparse_tag: Option<u32>) -> ReparsePointKind {
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return ReparsePointKind::NotReparsePoint;
    }

    match reparse_tag {
        Some(IO_REPARSE_TAG_SYMLINK) => ReparsePointKind::Symlink,
        Some(IO_REPARSE_TAG_MOUNT_POINT) => ReparsePointKind::JunctionOrMountPoint,
        Some(tag) => ReparsePointKind::Other(tag),
        None => ReparsePointKind::UnknownReparsePoint,
    }
}

pub fn should_traverse_reparse_point(kind: ReparsePointKind, follow_explicitly: bool) -> bool {
    matches!(kind, ReparsePointKind::NotReparsePoint)
        || (follow_explicitly && matches!(kind, ReparsePointKind::Symlink))
}

#[cfg(windows)]
pub fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(unix)]
pub fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(any(windows, unix)))]
pub fn create_file_symlink(_target: &Path, _link: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file symlink creation is unsupported on this platform",
    ))
}

#[cfg(windows)]
pub fn create_dir_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

#[cfg(unix)]
pub fn create_dir_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(any(windows, unix)))]
pub fn create_dir_symlink(_target: &Path, _link: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "directory symlink creation is unsupported on this platform",
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_reparse_tags() {
        assert_eq!(
            classify_reparse_point(0, Some(IO_REPARSE_TAG_SYMLINK)),
            ReparsePointKind::NotReparsePoint
        );
        assert_eq!(
            classify_reparse_point(FILE_ATTRIBUTE_REPARSE_POINT, Some(IO_REPARSE_TAG_SYMLINK)),
            ReparsePointKind::Symlink
        );
        assert_eq!(
            classify_reparse_point(
                FILE_ATTRIBUTE_REPARSE_POINT,
                Some(IO_REPARSE_TAG_MOUNT_POINT)
            ),
            ReparsePointKind::JunctionOrMountPoint
        );
    }

    #[test]
    fn refuses_to_traverse_reparse_points_by_default() {
        assert!(should_traverse_reparse_point(
            ReparsePointKind::NotReparsePoint,
            false
        ));
        assert!(!should_traverse_reparse_point(
            ReparsePointKind::Symlink,
            false
        ));
        assert!(!should_traverse_reparse_point(
            ReparsePointKind::JunctionOrMountPoint,
            true
        ));
        assert!(should_traverse_reparse_point(
            ReparsePointKind::Symlink,
            true
        ));
    }

    #[test]
    fn detects_link_capabilities_without_requiring_them() {
        let capabilities = detect_link_capabilities();
        let _ = capabilities.symlink_files;
        let _ = capabilities.symlink_dirs;
        let _ = capabilities.hardlinks;
    }
}
