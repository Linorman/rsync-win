use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use filetime::FileTime;
use thiserror::Error;

use crate::metadata::{default_permissions, FileType, HardlinkId, PortableMetadata};

const LOCAL_COPY_BUFFER_SIZE: usize = 64 * 1024;

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
    pub temp_dir: Option<PathBuf>,
    pub fsync: bool,
    pub sparse: bool,
    pub preallocate: bool,
}

impl Default for FileWriteOptions {
    fn default() -> Self {
        Self {
            mode: FileWriteMode::Atomic,
            keep_partial: false,
            partial_dir: None,
            temp_dir: None,
            fsync: false,
            sparse: false,
            preallocate: false,
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
    #[error("deleting would exceed --max-delete={limit}")]
    MaxDeleteExceeded { limit: usize },
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
    fn same_file_system(&self, _root: &Path, _path: &Path) -> Result<bool, FsError> {
        Ok(true)
    }
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
    fn copy_file_with_options(
        &mut self,
        source: &Path,
        dest: &Path,
        options: &FileWriteOptions,
    ) -> Result<u64, FsError> {
        let bytes = self.read_file(source)?;
        let len = bytes.len() as u64;
        self.write_file_with_options(dest, &bytes, options)?;
        Ok(len)
    }
    fn rename_file(&mut self, source: &Path, dest: &Path) -> Result<(), FsError> {
        let bytes = self.read_file(source)?;
        self.write_file_atomic(dest, &bytes)?;
        self.remove_file(source)
    }
    fn append_file_from(
        &mut self,
        path: &Path,
        source: &Path,
        offset: u64,
    ) -> Result<u64, FsError> {
        let bytes = self.read_file(source)?;
        let offset = usize::try_from(offset)
            .map_err(|_| FsError::Unsupported("file offset exceeds memory address size"))?;
        if offset > bytes.len() {
            return Err(FsError::Unsupported(
                "append offset exceeds source file length",
            ));
        }
        let suffix = &bytes[offset..];
        let len = suffix.len() as u64;
        self.append_file(path, suffix)?;
        Ok(len)
    }
    fn files_equal(&self, left: &Path, right: &Path) -> Result<bool, FsError> {
        let left_metadata = self.metadata(left)?;
        let right_metadata = self.metadata(right)?;
        if left_metadata.len != right_metadata.len {
            return Ok(false);
        }
        Ok(self.read_file(left)? == self.read_file(right)?)
    }
    fn file_prefix_matches(&self, path: &Path, prefix: &Path) -> Result<bool, FsError> {
        let path_bytes = self.read_file(path)?;
        let prefix_bytes = self.read_file(prefix)?;
        Ok(path_bytes.starts_with(&prefix_bytes))
    }
    fn create_symlink(
        &mut self,
        _path: &Path,
        _target: &Path,
        _target_kind: FileType,
    ) -> Result<(), FsError> {
        Err(FsError::Unsupported(
            "creating symlinks is unsupported by this filesystem",
        ))
    }
    fn create_hard_link(&mut self, _existing: &Path, _link: &Path) -> Result<(), FsError> {
        Err(FsError::Unsupported(
            "creating hard links is unsupported by this filesystem",
        ))
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
    next_hardlink_file: u64,
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
        Self {
            nodes,
            next_hardlink_file: 1,
        }
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

    pub fn add_hardlink(
        &mut self,
        existing: impl AsRef<Path>,
        link: impl AsRef<Path>,
    ) -> Result<(), FsError> {
        let existing = normalize_portable_path(existing.as_ref())?;
        let link = normalize_portable_path(link.as_ref())?;
        self.create_hard_link(&existing, &link)
    }

    pub fn add_device(&mut self, path: impl AsRef<Path>) -> Result<(), FsError> {
        self.add_metadata_only_node(path.as_ref(), PortableMetadata::device())
    }

    pub fn add_special(&mut self, path: impl AsRef<Path>) -> Result<(), FsError> {
        self.add_metadata_only_node(path.as_ref(), PortableMetadata::special())
    }

    pub fn paths(&self) -> Vec<PathBuf> {
        self.nodes.keys().cloned().collect()
    }

    fn add_metadata_only_node(
        &mut self,
        path: &Path,
        metadata: PortableMetadata,
    ) -> Result<(), FsError> {
        let path = normalize_portable_path(path)?;
        if let Some(parent) = path.parent() {
            self.create_dir_all(parent)?;
        }
        self.nodes.insert(
            path,
            MemoryNode {
                metadata,
                bytes: Vec::new(),
            },
        );
        Ok(())
    }

    fn ensure_hardlink_id(&mut self, path: &Path) -> Result<HardlinkId, FsError> {
        let existing = self
            .nodes
            .get(path)
            .ok_or_else(|| FsError::NotFound(path.to_path_buf()))?;
        if existing.metadata.file_type != FileType::File {
            return Err(FsError::Unsupported("hard link source is not a file"));
        }

        if let Some(id) = existing.metadata.hardlink_id {
            return Ok(id);
        }

        let id = HardlinkId {
            volume: 0,
            file: self.next_hardlink_file,
        };
        self.next_hardlink_file += 1;
        if let Some(node) = self.nodes.get_mut(path) {
            node.metadata.hardlink_id = Some(id);
            node.metadata.hardlink_count = Some(1);
        }
        Ok(id)
    }

    fn refresh_hardlink_count(&mut self, id: HardlinkId) {
        let count = self
            .nodes
            .values()
            .filter(|node| node.metadata.hardlink_id == Some(id))
            .count() as u64;
        for node in self.nodes.values_mut() {
            if node.metadata.hardlink_id == Some(id) {
                node.metadata.hardlink_count = Some(count);
            }
        }
    }

    fn resolve_write_path(&self, path: &Path) -> Result<PathBuf, FsError> {
        resolve_memory_path_prefix(&self.nodes, &normalize_portable_path(path)?)
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
        let path = self.resolve_write_path(path)?;
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
        let path = self.resolve_write_path(path)?;
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

    fn copy_file_with_options(
        &mut self,
        source: &Path,
        dest: &Path,
        options: &FileWriteOptions,
    ) -> Result<u64, FsError> {
        let bytes = self.read_file(source)?;
        let len = bytes.len() as u64;
        self.write_file_with_options(dest, &bytes, options)?;
        Ok(len)
    }

    fn rename_file(&mut self, source: &Path, dest: &Path) -> Result<(), FsError> {
        let source = normalize_portable_path(source)?;
        let dest = self.resolve_write_path(dest)?;
        if let Some(parent) = dest.parent() {
            self.create_dir_all(parent)?;
        }
        let node = self
            .nodes
            .remove(&source)
            .ok_or_else(|| FsError::NotFound(source.clone()))?;
        self.nodes.insert(dest, node);
        Ok(())
    }

    fn create_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
        let path = self.resolve_write_path(path)?;
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

    fn create_symlink(
        &mut self,
        path: &Path,
        target: &Path,
        _target_kind: FileType,
    ) -> Result<(), FsError> {
        let path = normalize_portable_path(path)?;
        if let Some(parent) = path.parent() {
            self.create_dir_all(parent)?;
        }
        self.nodes.insert(
            path,
            MemoryNode {
                metadata: PortableMetadata::symlink(target.to_path_buf()),
                bytes: Vec::new(),
            },
        );
        Ok(())
    }

    fn create_hard_link(&mut self, existing: &Path, link: &Path) -> Result<(), FsError> {
        let existing = self.resolve_write_path(existing)?;
        let link = self.resolve_write_path(link)?;
        let id = self.ensure_hardlink_id(&existing)?;
        let mut node = self
            .nodes
            .get(&existing)
            .cloned()
            .ok_or_else(|| FsError::NotFound(existing.clone()))?;
        node.metadata.hardlink_id = Some(id);
        node.metadata.hardlink_count = Some(1);
        if let Some(parent) = link.parent() {
            self.create_dir_all(parent)?;
        }
        self.nodes.insert(link, node);
        self.refresh_hardlink_count(id);
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
    normalize_memory_resolved_path(&resolved)
}

fn resolve_memory_path_prefix(
    nodes: &BTreeMap<PathBuf, MemoryNode>,
    path: &Path,
) -> Result<PathBuf, FsError> {
    resolve_memory_path_prefix_at(nodes, path, 32)
}

fn resolve_memory_path_prefix_at(
    nodes: &BTreeMap<PathBuf, MemoryNode>,
    path: &Path,
    remaining_limit: usize,
) -> Result<PathBuf, FsError> {
    let mut resolved = PathBuf::new();
    let mut components = path.components().peekable();

    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(FsError::InvalidPortablePath(path.to_path_buf()));
        };
        resolved.push(name);
        if let Some(node) = nodes.get(&resolved) {
            if node.metadata.file_type == FileType::Symlink {
                if remaining_limit == 0 {
                    return Err(FsError::Unsupported("too many nested memory symlinks"));
                }
                let mut target = resolve_memory_symlink_target(&resolved, &node.metadata)?;
                for rest in components {
                    let Component::Normal(name) = rest else {
                        return Err(FsError::InvalidPortablePath(path.to_path_buf()));
                    };
                    target.push(name);
                }
                return resolve_memory_path_prefix_at(nodes, &target, remaining_limit - 1);
            }
        }
    }

    Ok(resolved)
}

fn normalize_memory_resolved_path(path: &Path) -> Result<PathBuf, FsError> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => out.push(name),
            Component::ParentDir => {
                if !out.pop() {
                    return Err(FsError::InvalidPortablePath(path.to_path_buf()));
                }
            }
            _ => return Err(FsError::InvalidPortablePath(path.to_path_buf())),
        }
    }
    Ok(out)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LocalFileSystem;

impl PortableFileSystem for LocalFileSystem {
    fn metadata(&self, path: &Path) -> Result<PortableMetadata, FsError> {
        let os_path = local_os_path(path);
        let metadata = fs::symlink_metadata(&os_path)?;
        let mut portable = portable_metadata_from_std(metadata, None);
        if portable.file_type == FileType::Symlink {
            portable.symlink_target = fs::read_link(&os_path).ok();
        }
        if let Some(identity) = local_file_identity(&os_path)? {
            portable.hardlink_id = Some(identity.hardlink_id);
            portable.hardlink_count = Some(identity.link_count);
        }
        Ok(portable)
    }

    fn metadata_follow(&self, path: &Path) -> Result<PortableMetadata, FsError> {
        let os_path = local_os_path(path);
        let mut portable = portable_metadata_from_std(fs::metadata(&os_path)?, None);
        if let Some(identity) = local_file_identity(&os_path)? {
            portable.hardlink_id = Some(identity.hardlink_id);
            portable.hardlink_count = Some(identity.link_count);
        }
        Ok(portable)
    }

    fn resolve_path_for_prefix_check(&self, path: &Path) -> Result<PathBuf, FsError> {
        canonicalize_existing_or_missing(path).map_err(FsError::Io)
    }

    fn same_file_system(&self, root: &Path, path: &Path) -> Result<bool, FsError> {
        match (file_system_id(root)?, file_system_id(path)?) {
            (Some(root_id), Some(path_id)) => Ok(root_id == path_id),
            _ => Ok(true),
        }
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        Ok(fs::read(local_os_path(path))?)
    }

    fn write_file_atomic(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        let options = FileWriteOptions {
            mode: FileWriteMode::Atomic,
            fsync: true,
            ..Default::default()
        };
        self.write_file_atomic_with_options(path, bytes, &options)
    }

    fn write_file_direct(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        let options = FileWriteOptions {
            mode: FileWriteMode::InPlace,
            fsync: true,
            ..Default::default()
        };
        self.write_file_direct_with_options(path, bytes, &options)
    }

    fn write_file_with_options(
        &mut self,
        path: &Path,
        bytes: &[u8],
        options: &FileWriteOptions,
    ) -> Result<(), FsError> {
        match options.mode {
            FileWriteMode::Atomic => self.write_file_atomic_with_options(path, bytes, options),
            FileWriteMode::InPlace => self.write_file_direct_with_options(path, bytes, options),
        }
    }

    fn append_file(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(local_os_path(path))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn copy_file_with_options(
        &mut self,
        source: &Path,
        dest: &Path,
        options: &FileWriteOptions,
    ) -> Result<u64, FsError> {
        match options.mode {
            FileWriteMode::Atomic => self.copy_file_atomic_with_options(source, dest, options),
            FileWriteMode::InPlace => self.copy_file_direct_with_options(source, dest, options),
        }
    }

    fn rename_file(&mut self, source: &Path, dest: &Path) -> Result<(), FsError> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }
        replace_file(source, dest).map_err(FsError::Io)
    }

    fn append_file_from(
        &mut self,
        path: &Path,
        source: &Path,
        offset: u64,
    ) -> Result<u64, FsError> {
        let source_len = fs::metadata(local_os_path(source))?.len();
        if offset > source_len {
            return Err(FsError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "append offset exceeds source file length",
            )));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }

        let mut input = File::open(local_os_path(source))?;
        input.seek(SeekFrom::Start(offset))?;
        let mut output = OpenOptions::new()
            .create(true)
            .append(true)
            .open(local_os_path(path))?;
        let copied = copy_stream_bounded(&mut input, &mut output)?;
        output.sync_all()?;
        Ok(copied)
    }

    fn files_equal(&self, left: &Path, right: &Path) -> Result<bool, FsError> {
        Ok(files_equal_streaming(left, right)?)
    }

    fn file_prefix_matches(&self, path: &Path, prefix: &Path) -> Result<bool, FsError> {
        Ok(file_prefix_matches_streaming(path, prefix)?)
    }

    fn create_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
        Ok(fs::create_dir_all(local_os_path(path))?)
    }

    fn create_symlink(
        &mut self,
        path: &Path,
        target: &Path,
        target_kind: FileType,
    ) -> Result<(), FsError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }
        create_local_symlink(target, &local_os_path(path), target_kind).map_err(FsError::Io)
    }

    fn create_hard_link(&mut self, existing: &Path, link: &Path) -> Result<(), FsError> {
        if let Some(parent) = link.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }
        Ok(fs::hard_link(local_os_path(existing), local_os_path(link))?)
    }

    fn remove_file(&mut self, path: &Path) -> Result<(), FsError> {
        Ok(fs::remove_file(local_os_path(path))?)
    }

    fn remove_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
        Ok(fs::remove_dir_all(local_os_path(path))?)
    }

    fn list(&self, path: &Path) -> Result<Vec<WalkEntry>, FsError> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(local_os_path(path))? {
            let entry = entry?;
            let logical_path = path.join(entry.file_name());
            entries.push(WalkEntry {
                metadata: self.metadata(&logical_path)?,
                path: logical_path,
            });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(entries)
    }

    fn set_mtime(&mut self, path: &Path, modified: SystemTime) -> Result<(), FsError> {
        let file_time = FileTime::from_system_time(modified);
        filetime::set_file_mtime(local_os_path(path), file_time)?;
        Ok(())
    }
}

impl LocalFileSystem {
    fn write_file_direct_with_options(
        &mut self,
        path: &Path,
        bytes: &[u8],
        options: &FileWriteOptions,
    ) -> Result<(), FsError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }

        let mut file = File::create(local_os_path(path))?;
        apply_sparse_and_preallocate(&file, path, bytes.len() as u64, options)
            .map_err(|e| io::Error::other(e.to_string()))?;
        file.write_all(bytes)?;
        if options.fsync {
            file.sync_all()?;
        }
        Ok(())
    }

    fn write_file_atomic_with_options(
        &mut self,
        path: &Path,
        bytes: &[u8],
        options: &FileWriteOptions,
    ) -> Result<(), FsError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }

        let partial_dir = options
            .temp_dir
            .as_deref()
            .or(options.partial_dir.as_deref());
        let keep_partial = options.keep_partial || options.partial_dir.is_some();
        let temp_path = temp_path_for(path, partial_dir);
        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }
        let write_result = (|| -> io::Result<()> {
            let mut file = File::create(local_os_path(&temp_path))?;
            apply_sparse_and_preallocate(&file, &temp_path, bytes.len() as u64, options)
                .map_err(|e| io::Error::other(e.to_string()))?;
            file.write_all(bytes)?;
            if options.fsync {
                file.sync_all()?;
            }
            replace_file(&temp_path, path)
        })();

        if write_result.is_err() && !keep_partial {
            let _ = fs::remove_file(local_os_path(&temp_path));
        }

        write_result.map_err(FsError::Io)
    }

    fn copy_file_direct_with_options(
        &mut self,
        source: &Path,
        dest: &Path,
        options: &FileWriteOptions,
    ) -> Result<u64, FsError> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }

        let source_len = fs::metadata(local_os_path(source))?.len();
        let mut input = File::open(local_os_path(source))?;
        let mut output = File::create(local_os_path(dest))?;
        apply_sparse_and_preallocate(&output, dest, source_len, options)?;
        let copied = copy_stream_bounded(&mut input, &mut output)?;
        if options.fsync {
            output.sync_all()?;
        }
        Ok(copied)
    }

    fn copy_file_atomic_with_options(
        &mut self,
        source: &Path,
        dest: &Path,
        options: &FileWriteOptions,
    ) -> Result<u64, FsError> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }

        let partial_dir = options
            .temp_dir
            .as_deref()
            .or(options.partial_dir.as_deref());
        let keep_partial = options.keep_partial || options.partial_dir.is_some();
        let temp_path = temp_path_for(dest, partial_dir);
        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }
        let write_result = (|| {
            let copied = self.copy_file_direct_with_options(source, &temp_path, options)?;
            replace_file(&temp_path, dest)?;
            Ok(copied)
        })();

        if write_result.is_err() && !keep_partial {
            let _ = fs::remove_file(local_os_path(&temp_path));
        }

        write_result
    }
}

#[cfg(windows)]
fn apply_sparse_and_preallocate(
    file: &File,
    _path: &Path,
    file_len: u64,
    options: &FileWriteOptions,
) -> Result<(), FsError> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{
        FileAllocationInfo, SetFileInformationByHandle, FILE_ALLOCATION_INFO,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const FSCTL_SET_SPARSE: u32 = 0x000900C4;

    if options.sparse && file_len > 0 {
        let mut _unused: u32 = 0;
        let result = unsafe {
            DeviceIoControl(
                file.as_raw_handle() as _,
                FSCTL_SET_SPARSE,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut _unused,
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            return Err(FsError::Io(io::Error::last_os_error()));
        }
    }

    if options.preallocate && !options.sparse && file_len > 0 {
        let alloc_info = FILE_ALLOCATION_INFO {
            AllocationSize: file_len as i64,
        };
        let result = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle() as _,
                FileAllocationInfo,
                &alloc_info as *const _ as _,
                size_of::<FILE_ALLOCATION_INFO>() as u32,
            )
        };
        if result == 0 {
            return Err(FsError::Io(io::Error::last_os_error()));
        }
    }

    Ok(())
}

#[cfg(not(windows))]
fn apply_sparse_and_preallocate(
    _file: &File,
    _path: &Path,
    _file_len: u64,
    _options: &FileWriteOptions,
) -> Result<(), FsError> {
    // Non-Windows platforms: sparse and preallocate are no-ops at the
    // PortableFileSystem trait level.  Platform-specific filesystem
    // crates can implement these via sidecar metadata.
    Ok(())
}

#[cfg(windows)]
fn file_system_id(path: &Path) -> Result<Option<u64>, FsError> {
    use std::mem::zeroed;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let path = local_os_path(path);
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(FsError::Io(io::Error::last_os_error()));
    }

    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    let _ = unsafe { CloseHandle(handle) };
    if ok == 0 {
        return Err(FsError::Io(io::Error::last_os_error()));
    }

    Ok(Some(u64::from(info.dwVolumeSerialNumber)))
}

#[cfg(unix)]
fn file_system_id(path: &Path) -> Result<Option<u64>, FsError> {
    use std::os::unix::fs::MetadataExt;

    Ok(Some(fs::symlink_metadata(local_os_path(path))?.dev()))
}

#[cfg(not(any(windows, unix)))]
fn file_system_id(_path: &Path) -> Result<Option<u64>, FsError> {
    Ok(None)
}

fn files_equal_streaming(left: &Path, right: &Path) -> io::Result<bool> {
    let left_os_path = local_os_path(left);
    let right_os_path = local_os_path(right);
    let left_len = fs::metadata(&left_os_path)?.len();
    let right_len = fs::metadata(&right_os_path)?.len();
    if left_len != right_len {
        return Ok(false);
    }

    let mut left_file = File::open(left_os_path)?;
    let mut right_file = File::open(right_os_path)?;
    streams_equal_for_len(&mut left_file, &mut right_file, left_len)
}

fn file_prefix_matches_streaming(path: &Path, prefix: &Path) -> io::Result<bool> {
    let path_os_path = local_os_path(path);
    let prefix_os_path = local_os_path(prefix);
    let path_len = fs::metadata(&path_os_path)?.len();
    let prefix_len = fs::metadata(&prefix_os_path)?.len();
    if prefix_len > path_len {
        return Ok(false);
    }

    let mut path_file = File::open(path_os_path)?;
    let mut prefix_file = File::open(prefix_os_path)?;
    streams_equal_for_len(&mut path_file, &mut prefix_file, prefix_len)
}

fn streams_equal_for_len<L: Read, R: Read>(
    left: &mut L,
    right: &mut R,
    mut remaining: u64,
) -> io::Result<bool> {
    let mut left_buf = [0_u8; LOCAL_COPY_BUFFER_SIZE];
    let mut right_buf = [0_u8; LOCAL_COPY_BUFFER_SIZE];

    while remaining > 0 {
        let len = if remaining > left_buf.len() as u64 {
            left_buf.len()
        } else {
            remaining as usize
        };
        left.read_exact(&mut left_buf[..len])?;
        right.read_exact(&mut right_buf[..len])?;
        if left_buf[..len] != right_buf[..len] {
            return Ok(false);
        }
        remaining -= len as u64;
    }

    Ok(true)
}

fn copy_stream_bounded<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<u64> {
    let mut buf = [0_u8; LOCAL_COPY_BUFFER_SIZE];
    let mut total = 0_u64;
    loop {
        let read = input.read(&mut buf)?;
        if read == 0 {
            return Ok(total);
        }
        output.write_all(&buf[..read])?;
        total += read as u64;
    }
}

fn portable_metadata_from_std(
    metadata: fs::Metadata,
    symlink_target: Option<PathBuf>,
) -> PortableMetadata {
    let std_file_type = metadata.file_type();
    let file_type = if is_reparse_point(&metadata) && !std_file_type.is_symlink() {
        FileType::Other
    } else if std_file_type.is_symlink() {
        FileType::Symlink
    } else if std_file_type.is_dir() {
        FileType::Directory
    } else if std_file_type.is_file() {
        FileType::File
    } else if is_device_file_type(&std_file_type) {
        FileType::Device
    } else if is_special_file_type(&std_file_type) {
        FileType::Special
    } else {
        FileType::Other
    };

    let mode = platform_mode(&metadata, file_type);

    PortableMetadata {
        file_type,
        len: metadata.len(),
        modified: metadata.modified().ok(),
        mode: Some(mode),
        symlink_target,
        hardlink_id: None,
        hardlink_count: None,
    }
}

#[derive(Debug, Clone, Copy)]
struct LocalFileIdentity {
    hardlink_id: HardlinkId,
    link_count: u64,
}

#[cfg(windows)]
fn local_file_identity(path: &Path) -> Result<Option<LocalFileIdentity>, FsError> {
    use std::mem::zeroed;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(FsError::Io(io::Error::last_os_error()));
    }

    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    let _ = unsafe { CloseHandle(handle) };
    if ok == 0 {
        return Err(FsError::Io(io::Error::last_os_error()));
    }

    let file = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Ok(Some(LocalFileIdentity {
        hardlink_id: HardlinkId {
            volume: u64::from(info.dwVolumeSerialNumber),
            file,
        },
        link_count: u64::from(info.nNumberOfLinks),
    }))
}

#[cfg(unix)]
fn local_file_identity(path: &Path) -> Result<Option<LocalFileIdentity>, FsError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    Ok(Some(LocalFileIdentity {
        hardlink_id: HardlinkId {
            volume: metadata.dev(),
            file: metadata.ino(),
        },
        link_count: metadata.nlink(),
    }))
}

#[cfg(not(any(windows, unix)))]
fn local_file_identity(_path: &Path) -> Result<Option<LocalFileIdentity>, FsError> {
    Ok(None)
}

#[cfg(windows)]
fn create_local_symlink(target: &Path, link: &Path, target_kind: FileType) -> io::Result<()> {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    match target_kind {
        FileType::Directory => symlink_dir(target, link),
        _ => symlink_file(target, link),
    }
}

#[cfg(unix)]
fn create_local_symlink(target: &Path, link: &Path, _target_kind: FileType) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(any(windows, unix)))]
fn create_local_symlink(_target: &Path, _link: &Path, _target_kind: FileType) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "creating symlinks is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn is_device_file_type(file_type: &fs::FileType) -> bool {
    use std::os::unix::fs::FileTypeExt;

    file_type.is_block_device() || file_type.is_char_device()
}

#[cfg(not(unix))]
fn is_device_file_type(_file_type: &fs::FileType) -> bool {
    false
}

#[cfg(unix)]
fn is_special_file_type(file_type: &fs::FileType) -> bool {
    use std::os::unix::fs::FileTypeExt;

    file_type.is_fifo() || file_type.is_socket()
}

#[cfg(not(unix))]
fn is_special_file_type(_file_type: &fs::FileType) -> bool {
    false
}

#[cfg(unix)]
fn platform_mode(metadata: &fs::Metadata, _file_type: FileType) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o7777
}

#[cfg(windows)]
fn platform_mode(metadata: &fs::Metadata, file_type: FileType) -> u32 {
    let mut permissions = default_permissions(file_type);
    if metadata.permissions().readonly() && file_type == FileType::File {
        permissions &= !0o222;
    }
    permissions
}

#[cfg(not(any(unix, windows)))]
fn platform_mode(_metadata: &fs::Metadata, file_type: FileType) -> u32 {
    default_permissions(file_type)
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

    let source = local_os_path(source);
    let dest = local_os_path(dest);
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
    fs::rename(local_os_path(source), local_os_path(dest))
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
    if let Ok(canonical) = canonicalize_local_path(path) {
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
                if let Ok(mut base) = canonicalize_local_path(parent) {
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
        let current_dir = std::env::current_dir()?;
        canonicalize_local_path(&current_dir)?
    };
    absolute.push(path);
    Ok(absolute)
}

fn canonicalize_local_path(path: &Path) -> io::Result<PathBuf> {
    fs::canonicalize(path)
        .or_else(|_| fs::canonicalize(local_os_path(path)))
        .map(logical_path_from_os_path)
}

#[cfg(windows)]
fn logical_path_from_os_path(path: PathBuf) -> PathBuf {
    let text = path.as_os_str().to_string_lossy();
    if let Some(stripped) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{stripped}"));
    }
    if let Some(stripped) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(stripped);
    }
    path
}

#[cfg(not(windows))]
fn logical_path_from_os_path(path: PathBuf) -> PathBuf {
    path
}

#[cfg(windows)]
fn local_os_path(path: &Path) -> PathBuf {
    use std::path::Prefix;

    let text = path.as_os_str().to_string_lossy();
    if text.starts_with(r"\\?\") {
        return path.to_path_buf();
    }

    if let Some(Component::Prefix(prefix)) = path.components().next() {
        match prefix.kind() {
            Prefix::Verbatim(_) | Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) => {
                return path.to_path_buf();
            }
            Prefix::DeviceNS(_) => return path.to_path_buf(),
            Prefix::UNC(_, _) => return unc_verbatim_path(path),
            _ => {}
        }
    }

    if path.is_absolute() {
        let normalized = verbatim_path_text(path);
        return PathBuf::from(format!(r"\\?\{normalized}"));
    }

    path.to_path_buf()
}

#[cfg(windows)]
fn unc_verbatim_path(path: &Path) -> PathBuf {
    let normalized = verbatim_path_text(path);
    let stripped = normalized.strip_prefix(r"\\").unwrap_or(&normalized);
    PathBuf::from(format!(r"\\?\UNC\{stripped}"))
}

#[cfg(windows)]
fn verbatim_path_text(path: &Path) -> String {
    path.as_os_str().to_string_lossy().replace('/', r"\")
}

#[cfg(not(windows))]
fn local_os_path(path: &Path) -> PathBuf {
    path.to_path_buf()
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

    #[cfg(windows)]
    #[test]
    fn local_sparse_write_marks_file_sparse() {
        let root = unique_temp_dir("rsync-fs-sparse");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("sparse.bin");

        let mut fs_adapter = LocalFileSystem;
        fs_adapter
            .write_file_with_options(
                &path,
                &[0; 4096],
                &FileWriteOptions {
                    sparse: true,
                    ..FileWriteOptions::default()
                },
            )
            .unwrap();

        assert!(file_has_sparse_attribute(&path));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn local_preallocate_write_preserves_file_length() {
        let root = unique_temp_dir("rsync-fs-preallocate");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("preallocated.bin");

        let mut fs_adapter = LocalFileSystem;
        fs_adapter
            .write_file_with_options(
                &path,
                b"preallocated",
                &FileWriteOptions {
                    preallocate: true,
                    ..FileWriteOptions::default()
                },
            )
            .unwrap();

        assert_eq!(fs::metadata(&path).unwrap().len(), 12);
        assert_eq!(fs::read(&path).unwrap(), b"preallocated");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn local_filesystem_handles_windows_long_paths_without_leaking_verbatim_prefixes() {
        let root = unique_temp_dir("rsync-fs-long-path");
        let mut long_dir = root.clone();
        while long_dir.as_os_str().to_string_lossy().len() < 280 {
            long_dir.push("segment0123456789");
        }
        let file_path = long_dir.join("file.txt");
        let copy_path = long_dir.join("copy.txt");
        assert!(file_path.as_os_str().to_string_lossy().len() > 260);

        let mut fs_adapter = LocalFileSystem;
        fs_adapter.write_file_atomic(&file_path, b"abc").unwrap();
        fs_adapter.append_file(&file_path, b"def").unwrap();
        fs_adapter
            .copy_file_with_options(&file_path, &copy_path, &FileWriteOptions::default())
            .unwrap();
        fs_adapter.set_mtime(&copy_path, UNIX_EPOCH).unwrap();

        assert_eq!(fs_adapter.read_file(&file_path).unwrap(), b"abcdef");
        assert!(fs_adapter.files_equal(&file_path, &copy_path).unwrap());
        assert!(fs_adapter
            .file_prefix_matches(&copy_path, &file_path)
            .unwrap());

        let paths: Vec<_> = fs_adapter
            .list(&long_dir)
            .unwrap()
            .into_iter()
            .map(|entry| entry.path)
            .collect();
        assert!(paths.contains(&file_path));
        assert!(paths.contains(&copy_path));
        assert!(paths
            .iter()
            .all(|path| !path.as_os_str().to_string_lossy().starts_with(r"\\?\")));

        fs_adapter.remove_dir_all(&root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn local_os_path_normalizes_forward_slashes_before_verbatim_prefix() {
        let path = local_os_path(Path::new(r"C:/temp/rsync-win/source/"));
        let text = path.as_os_str().to_string_lossy();

        assert_eq!(text, r"\\?\C:\temp\rsync-win\source\");
    }

    #[cfg(windows)]
    #[test]
    fn local_os_path_uses_unc_verbatim_prefix_for_unc_paths() {
        let backslash = local_os_path(Path::new(r"\\server\share\rsync-win/source/"));
        let forward = local_os_path(Path::new("//server/share/rsync-win/source/"));

        assert_eq!(
            backslash.as_os_str().to_string_lossy(),
            r"\\?\UNC\server\share\rsync-win\source\"
        );
        assert_eq!(
            forward.as_os_str().to_string_lossy(),
            r"\\?\UNC\server\share\rsync-win\source\"
        );
    }

    #[test]
    fn memory_bound_large_copy_uses_fixed_read_buffer() {
        let total_len = (LOCAL_COPY_BUFFER_SIZE * 3 + 17) as u64;
        let mut reader = TrackingReader {
            remaining: total_len,
            position: 0,
            max_read_request: 0,
        };
        let mut output = Vec::new();

        let copied = copy_stream_bounded(&mut reader, &mut output).unwrap();

        assert_eq!(copied, total_len);
        assert_eq!(output.len() as u64, total_len);
        assert!(reader.max_read_request <= LOCAL_COPY_BUFFER_SIZE);
        assert_eq!(output[0], 0);
        assert_eq!(
            output[LOCAL_COPY_BUFFER_SIZE],
            (LOCAL_COPY_BUFFER_SIZE as u64 % 251) as u8
        );
    }

    struct TrackingReader {
        remaining: u64,
        position: u64,
        max_read_request: usize,
    }

    impl std::io::Read for TrackingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.max_read_request = self.max_read_request.max(buf.len());
            if self.remaining == 0 {
                return Ok(0);
            }
            let read = if self.remaining > buf.len() as u64 {
                buf.len()
            } else {
                self.remaining as usize
            };
            for byte in &mut buf[..read] {
                *byte = (self.position % 251) as u8;
                self.position += 1;
            }
            self.remaining -= read as u64;
            Ok(read)
        }
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

    #[cfg(windows)]
    fn file_has_sparse_attribute(path: &Path) -> bool {
        use std::os::windows::ffi::OsStrExt;

        use windows_sys::Win32::Storage::FileSystem::{
            GetFileAttributesW, FILE_ATTRIBUTE_SPARSE_FILE,
        };

        let os_path = local_os_path(path);
        let wide: Vec<u16> = os_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
        assert_ne!(attrs, u32::MAX);
        attrs & FILE_ATTRIBUTE_SPARSE_FILE != 0
    }
}
