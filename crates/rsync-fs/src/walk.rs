use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use filetime::FileTime;
use thiserror::Error;

use crate::metadata::{FileType, PortableMetadata};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileWriteMode {
    Atomic,
    InPlace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWriteOptions {
    pub mode: FileWriteMode,
    pub keep_partial: bool,
    pub partial_dir: Option<PathBuf>,
}

impl Default for FileWriteOptions {
    fn default() -> Self {
        Self {
            mode: FileWriteMode::Atomic,
            keep_partial: false,
            partial_dir: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum FsError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid portable path `{0}`")]
    InvalidPortablePath(PathBuf),
    #[error("path does not exist: {0}")]
    NotFound(PathBuf),
    #[error("path is not a directory: {0}")]
    NotDirectory(PathBuf),
    #[error("refusing to sync a destination inside the source tree")]
    DestinationInsideSource,
    #[error("destination path preflight failed: {0}")]
    DestinationPathPreflight(String),
    #[error("operation is unsupported by this filesystem: {0}")]
    Unsupported(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkEntry {
    pub path: PathBuf,
    pub metadata: PortableMetadata,
}

pub trait PortableFileSystem {
    fn metadata(&self, path: &Path) -> Result<PortableMetadata, FsError>;
    fn metadata_follow(&self, path: &Path) -> Result<PortableMetadata, FsError> {
        self.metadata(path)
    }
    fn resolve_path_for_prefix_check(&self, path: &Path) -> Result<PathBuf, FsError>;
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, FsError>;
    fn write_file_atomic(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError>;
    fn write_file_direct(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        self.write_file_atomic(path, bytes)
    }
    fn write_file_with_options(
        &mut self,
        path: &Path,
        bytes: &[u8],
        options: &FileWriteOptions,
    ) -> Result<(), FsError> {
        match options.mode {
            FileWriteMode::Atomic => self.write_file_atomic(path, bytes),
            FileWriteMode::InPlace => self.write_file_direct(path, bytes),
        }
    }
    fn append_file(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        let mut existing = self.read_file(path)?;
        existing.extend_from_slice(bytes);
        self.write_file_atomic(path, &existing)
    }
    fn create_dir_all(&mut self, path: &Path) -> Result<(), FsError>;
    fn remove_file(&mut self, path: &Path) -> Result<(), FsError>;
    fn remove_dir_all(&mut self, path: &Path) -> Result<(), FsError>;
    fn list(&self, path: &Path) -> Result<Vec<WalkEntry>, FsError>;
    fn set_mtime(&mut self, path: &Path, modified: SystemTime) -> Result<(), FsError>;

    fn exists(&self, path: &Path) -> bool {
        self.metadata(path).is_ok()
    }
}

#[derive(Debug, Clone)]
struct MemoryNode {
    metadata: PortableMetadata,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MemoryFileSystem {
    nodes: BTreeMap<PathBuf, MemoryNode>,
}

impl Default for MemoryFileSystem {
    fn default() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            PathBuf::new(),
            MemoryNode {
                metadata: PortableMetadata::directory(),
                bytes: Vec::new(),
            },
        );
        Self { nodes }
    }
}

impl MemoryFileSystem {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_dir(&mut self, path: impl AsRef<Path>) -> Result<(), FsError> {
        self.create_dir_all(path.as_ref())
    }

    pub fn add_file(
        &mut self,
        path: impl AsRef<Path>,
        bytes: impl AsRef<[u8]>,
    ) -> Result<(), FsError> {
        let path = normalize_portable_path(path.as_ref())?;
        if let Some(parent) = path.parent() {
            self.create_dir_all(parent)?;
        }
        self.nodes.insert(
            path,
            MemoryNode {
                metadata: PortableMetadata::file(bytes.as_ref().len() as u64),
                bytes: bytes.as_ref().to_vec(),
            },
        );
        Ok(())
    }

    pub fn add_symlink(
        &mut self,
        path: impl AsRef<Path>,
        target: impl AsRef<Path>,
    ) -> Result<(), FsError> {
        let path = normalize_portable_path(path.as_ref())?;
        if let Some(parent) = path.parent() {
            self.create_dir_all(parent)?;
        }
        self.nodes.insert(
            path,
            MemoryNode {
                metadata: PortableMetadata::symlink(target.as_ref().to_path_buf()),
                bytes: Vec::new(),
            },
        );
        Ok(())
    }

    pub fn paths(&self) -> Vec<PathBuf> {
        self.nodes.keys().cloned().collect()
    }
}

impl PortableFileSystem for MemoryFileSystem {
    fn metadata(&self, path: &Path) -> Result<PortableMetadata, FsError> {
        let path = normalize_portable_path(path)?;
        self.nodes
            .get(&path)
            .map(|node| node.metadata.clone())
            .ok_or(FsError::NotFound(path))
    }

    fn metadata_follow(&self, path: &Path) -> Result<PortableMetadata, FsError> {
        let path = normalize_portable_path(path)?;
        let node = self
            .nodes
            .get(&path)
            .ok_or_else(|| FsError::NotFound(path.clone()))?;
        if node.metadata.file_type != FileType::Symlink {
            return Ok(node.metadata.clone());
        }
        let target = resolve_memory_symlink_target(&path, &node.metadata)?;
        self.metadata(&target)
    }

    fn resolve_path_for_prefix_check(&self, path: &Path) -> Result<PathBuf, FsError> {
        normalize_portable_path(path)
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        let path = normalize_portable_path(path)?;
        let node = self
            .nodes
            .get(&path)
            .ok_or_else(|| FsError::NotFound(path.clone()))?;
        if node.metadata.file_type == FileType::Symlink {
            let target = resolve_memory_symlink_target(&path, &node.metadata)?;
            return self.read_file(&target);
        }
        if node.metadata.file_type != FileType::File {
            return Err(FsError::Unsupported("reading non-file memory nodes"));
        }
        Ok(node.bytes.clone())
    }

    fn write_file_atomic(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        let path = normalize_portable_path(path)?;
        if let Some(parent) = path.parent() {
            self.create_dir_all(parent)?;
        }
        self.nodes.insert(
            path,
            MemoryNode {
                metadata: PortableMetadata::file(bytes.len() as u64),
                bytes: bytes.to_vec(),
            },
        );
        Ok(())
    }

    fn write_file_direct(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        self.write_file_atomic(path, bytes)
    }

    fn append_file(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        let path = normalize_portable_path(path)?;
        let node = self
            .nodes
            .get_mut(&path)
            .ok_or_else(|| FsError::NotFound(path.clone()))?;
        if node.metadata.file_type != FileType::File {
            return Err(FsError::Unsupported("append_file on non-file memory nodes"));
        }
        node.bytes.extend_from_slice(bytes);
        node.metadata.len = node.bytes.len() as u64;
        Ok(())
    }

    fn create_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
        let path = normalize_portable_path(path)?;
        let mut current = PathBuf::new();
        self.nodes
            .entry(current.clone())
            .or_insert_with(|| MemoryNode {
                metadata: PortableMetadata::directory(),
                bytes: Vec::new(),
            });

        for component in path.components() {
            if let Component::Normal(name) = component {
                current.push(name);
                self.nodes
                    .entry(current.clone())
                    .or_insert_with(|| MemoryNode {
                        metadata: PortableMetadata::directory(),
                        bytes: Vec::new(),
                    });
            }
        }

        Ok(())
    }

    fn remove_file(&mut self, path: &Path) -> Result<(), FsError> {
        let path = normalize_portable_path(path)?;
        let Some(node) = self.nodes.get(&path) else {
            return Err(FsError::NotFound(path));
        };
        if node.metadata.file_type == FileType::Directory {
            return Err(FsError::Unsupported("remove_file on directory"));
        }
        self.nodes.remove(&path);
        Ok(())
    }

    fn remove_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
        let path = normalize_portable_path(path)?;
        if path.as_os_str().is_empty() {
            return Err(FsError::Unsupported("remove root directory"));
        }
        let keys: Vec<_> = self
            .nodes
            .keys()
            .filter(|candidate| *candidate == &path || candidate.starts_with(&path))
            .cloned()
            .collect();
        if keys.is_empty() {
            return Err(FsError::NotFound(path));
        }
        for key in keys {
            self.nodes.remove(&key);
        }
        Ok(())
    }

    fn list(&self, path: &Path) -> Result<Vec<WalkEntry>, FsError> {
        let path = normalize_portable_path(path)?;
        let metadata = self.metadata(&path)?;
        if metadata.file_type != FileType::Directory {
            return Err(FsError::NotDirectory(path));
        }

        let mut entries = Vec::new();
        for (candidate, node) in &self.nodes {
            if candidate.as_os_str().is_empty() || candidate == &path {
                continue;
            }
            if candidate.parent().unwrap_or_else(|| Path::new("")) == path {
                entries.push(WalkEntry {
                    path: candidate.clone(),
                    metadata: node.metadata.clone(),
                });
            }
        }
        Ok(entries)
    }

    fn set_mtime(&mut self, path: &Path, modified: SystemTime) -> Result<(), FsError> {
        let path = normalize_portable_path(path)?;
        let node = self
            .nodes
            .get_mut(&path)
            .ok_or_else(|| FsError::NotFound(path.clone()))?;
        node.metadata.modified = Some(modified);
        Ok(())
    }
}

fn resolve_memory_symlink_target(
    link_path: &Path,
    metadata: &PortableMetadata,
) -> Result<PathBuf, FsError> {
    let target = metadata
        .symlink_target
        .as_ref()
        .ok_or_else(|| FsError::InvalidPortablePath(link_path.to_path_buf()))?;
    let resolved = if target.is_absolute() {
        target.clone()
    } else {
        link_path
            .parent()
            .map(|parent| parent.join(target))
            .unwrap_or_else(|| target.clone())
    };
    normalize_portable_path(&resolved)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LocalFileSystem;

impl PortableFileSystem for LocalFileSystem {
    fn metadata(&self, path: &Path) -> Result<PortableMetadata, FsError> {
        let metadata = fs::symlink_metadata(path)?;
        let mut portable = portable_metadata_from_std(metadata, None);
        if portable.file_type == FileType::Symlink {
            portable.symlink_target = fs::read_link(path).ok();
        }
        Ok(portable)
    }

    fn metadata_follow(&self, path: &Path) -> Result<PortableMetadata, FsError> {
        Ok(portable_metadata_from_std(fs::metadata(path)?, None))
    }

    fn resolve_path_for_prefix_check(&self, path: &Path) -> Result<PathBuf, FsError> {
        canonicalize_existing_or_missing(path).map_err(FsError::Io)
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        Ok(fs::read(path)?)
    }

    fn write_file_atomic(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        self.write_file_atomic_to_temp(path, bytes, None, false)
    }

    fn write_file_direct(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = File::create(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn write_file_with_options(
        &mut self,
        path: &Path,
        bytes: &[u8],
        options: &FileWriteOptions,
    ) -> Result<(), FsError> {
        match options.mode {
            FileWriteMode::Atomic => self.write_file_atomic_to_temp(
                path,
                bytes,
                options.partial_dir.as_deref(),
                options.keep_partial || options.partial_dir.is_some(),
            ),
            FileWriteMode::InPlace => self.write_file_direct(path, bytes),
        }
    }

    fn append_file(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn create_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
        Ok(fs::create_dir_all(path)?)
    }

    fn remove_file(&mut self, path: &Path) -> Result<(), FsError> {
        Ok(fs::remove_file(path)?)
    }

    fn remove_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
        Ok(fs::remove_dir_all(path)?)
    }

    fn list(&self, path: &Path) -> Result<Vec<WalkEntry>, FsError> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            entries.push(WalkEntry {
                path: entry.path(),
                metadata: self.metadata(&entry.path())?,
            });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(entries)
    }

    fn set_mtime(&mut self, path: &Path, modified: SystemTime) -> Result<(), FsError> {
        let file_time = FileTime::from_system_time(modified);
        filetime::set_file_mtime(path, file_time)?;
        Ok(())
    }
}

impl LocalFileSystem {
    fn write_file_atomic_to_temp(
        &mut self,
        path: &Path,
        bytes: &[u8],
        partial_dir: Option<&Path>,
        keep_partial: bool,
    ) -> Result<(), FsError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temp_path = temp_path_for(path, partial_dir);
        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let write_result = (|| {
            let mut file = File::create(&temp_path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            replace_file(&temp_path, path)
        })();

        if write_result.is_err() && !keep_partial {
            let _ = fs::remove_file(&temp_path);
        }

        write_result.map_err(FsError::Io)
    }
}

fn portable_metadata_from_std(
    metadata: fs::Metadata,
    symlink_target: Option<PathBuf>,
) -> PortableMetadata {
    let file_type = if is_reparse_point(&metadata) && !metadata.file_type().is_symlink() {
        FileType::Other
    } else if metadata.file_type().is_symlink() {
        FileType::Symlink
    } else if metadata.file_type().is_dir() {
        FileType::Directory
    } else if metadata.file_type().is_file() {
        FileType::File
    } else {
        FileType::Other
    };

    PortableMetadata {
        file_type,
        len: metadata.len(),
        modified: metadata.modified().ok(),
        mode: None,
        symlink_target,
    }
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn replace_file(source: &Path, dest: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let dest: Vec<u16> = dest
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let ok = unsafe {
        MoveFileExW(
            source.as_ptr(),
            dest.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(not(windows))]
fn replace_file(source: &Path, dest: &Path) -> io::Result<()> {
    fs::rename(source, dest)
}

pub fn walk_tree<F: PortableFileSystem>(fs: &F, root: &Path) -> Result<Vec<WalkEntry>, FsError> {
    let mut entries = Vec::new();
    walk_tree_inner(fs, root, &mut entries)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn walk_tree_inner<F: PortableFileSystem>(
    fs: &F,
    root: &Path,
    entries: &mut Vec<WalkEntry>,
) -> Result<(), FsError> {
    for entry in fs.list(root)? {
        let is_dir = entry.metadata.file_type == FileType::Directory;
        let path = entry.path.clone();
        entries.push(entry);
        if is_dir {
            walk_tree_inner(fs, &path, entries)?;
        }
    }
    Ok(())
}

fn normalize_portable_path(path: &Path) -> Result<PathBuf, FsError> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => out.push(name),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FsError::InvalidPortablePath(path.to_path_buf()));
            }
        }
    }
    Ok(out)
}

fn temp_path_for(path: &Path, partial_dir: Option<&Path>) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "rsync-win".into());
    let temp_name = temp_file_name(&file_name);
    match partial_dir {
        Some(dir) if dir.is_absolute() => dir.join(temp_name),
        Some(dir) => path
            .parent()
            .map(|parent| parent.join(dir).join(&temp_name))
            .unwrap_or_else(|| dir.join(temp_name)),
        None => path.with_file_name(temp_name),
    }
}

fn temp_file_name(file_name: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    format!(".{file_name}.{pid}.{now}.tmp")
}

fn canonicalize_existing_or_missing(path: &Path) -> io::Result<PathBuf> {
    if let Ok(canonical) = fs::canonicalize(path) {
        return Ok(canonical);
    }

    let mut missing = Vec::<OsString>::new();
    let mut current = path;

    loop {
        if let Some(name) = current.file_name() {
            missing.push(name.to_os_string());
        }

        match current.parent() {
            Some(parent) if parent != current => {
                if let Ok(mut base) = fs::canonicalize(parent) {
                    for component in missing.iter().rev() {
                        base.push(component);
                    }
                    return Ok(base);
                }
                current = parent;
            }
            _ => break,
        }
    }

    let mut absolute = if path.is_absolute() {
        PathBuf::new()
    } else {
        fs::canonicalize(std::env::current_dir()?)?
    };
    absolute.push(path);
    Ok(absolute)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_filesystem_walks_sorted_tree() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/b.txt", b"b").unwrap();
        fs.add_file("src/a.txt", b"a").unwrap();

        let paths: Vec<_> = walk_tree(&fs, Path::new("src"))
            .unwrap()
            .into_iter()
            .map(|entry| entry.path)
            .collect();

        assert_eq!(
            paths,
            vec![PathBuf::from("src/a.txt"), PathBuf::from("src/b.txt"),]
        );
    }

    #[test]
    fn memory_filesystem_rejects_parent_escape() {
        let mut fs = MemoryFileSystem::new();
        let err = fs.add_file("../escape.txt", b"x").unwrap_err();
        assert!(matches!(err, FsError::InvalidPortablePath(_)));
    }

    #[test]
    fn local_atomic_write_uses_destination_bytes() {
        let root = unique_temp_dir("rsync-fs-atomic");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("out.txt");

        let mut fs_adapter = LocalFileSystem;
        fs_adapter.write_file_atomic(&path, b"new").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
        fs::remove_dir_all(root).unwrap();
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        path.push(format!("{prefix}-{}-{nanos}", std::process::id()));
        path
    }
}
