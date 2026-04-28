use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use filetime::FileTime;
use thiserror::Error;

use crate::metadata::{default_permissions, FileType, PortableMetadata};

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
        let os_path = local_os_path(path);
        let metadata = fs::symlink_metadata(&os_path)?;
        let mut portable = portable_metadata_from_std(metadata, None);
        if portable.file_type == FileType::Symlink {
            portable.symlink_target = fs::read_link(&os_path).ok();
        }
        Ok(portable)
    }

    fn metadata_follow(&self, path: &Path) -> Result<PortableMetadata, FsError> {
        Ok(portable_metadata_from_std(
            fs::metadata(local_os_path(path))?,
            None,
        ))
    }

    fn resolve_path_for_prefix_check(&self, path: &Path) -> Result<PathBuf, FsError> {
        canonicalize_existing_or_missing(path).map_err(FsError::Io)
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        Ok(fs::read(local_os_path(path))?)
    }

    fn write_file_atomic(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        self.write_file_atomic_to_temp(path, bytes, None, false)
    }

    fn write_file_direct(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }

        let mut file = File::create(local_os_path(path))?;
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
            FileWriteMode::Atomic => self.copy_file_atomic_to_temp(
                source,
                dest,
                options.partial_dir.as_deref(),
                options.keep_partial || options.partial_dir.is_some(),
            ),
            FileWriteMode::InPlace => self.copy_file_direct(source, dest),
        }
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
    fn write_file_atomic_to_temp(
        &mut self,
        path: &Path,
        bytes: &[u8],
        partial_dir: Option<&Path>,
        keep_partial: bool,
    ) -> Result<(), FsError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }

        let temp_path = temp_path_for(path, partial_dir);
        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }
        let write_result = (|| {
            let mut file = File::create(local_os_path(&temp_path))?;
            file.write_all(bytes)?;
            file.sync_all()?;
            replace_file(&temp_path, path)
        })();

        if write_result.is_err() && !keep_partial {
            let _ = fs::remove_file(local_os_path(&temp_path));
        }

        write_result.map_err(FsError::Io)
    }

    fn copy_file_direct(&mut self, source: &Path, dest: &Path) -> Result<u64, FsError> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }

        let mut input = File::open(local_os_path(source))?;
        let mut output = File::create(local_os_path(dest))?;
        let copied = copy_stream_bounded(&mut input, &mut output)?;
        output.sync_all()?;
        Ok(copied)
    }

    fn copy_file_atomic_to_temp(
        &mut self,
        source: &Path,
        dest: &Path,
        partial_dir: Option<&Path>,
        keep_partial: bool,
    ) -> Result<u64, FsError> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }

        let temp_path = temp_path_for(dest, partial_dir);
        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(local_os_path(parent))?;
        }
        let write_result = (|| {
            let copied = self.copy_file_direct(source, &temp_path)?;
            replace_file(&temp_path, dest)?;
            Ok(copied)
        })();

        if write_result.is_err() && !keep_partial {
            let _ = fs::remove_file(local_os_path(&temp_path));
        }

        write_result
    }
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

    let mode = platform_mode(&metadata, file_type);

    PortableMetadata {
        file_type,
        len: metadata.len(),
        modified: metadata.modified().ok(),
        mode: Some(mode),
        symlink_target,
    }
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

    if let Ok(stripped) = path.strip_prefix(r"\\") {
        return PathBuf::from(format!(r"\\?\UNC\{}", stripped.display()));
    }

    if path.is_absolute() {
        return PathBuf::from(format!(r"\\?\{}", path.display()));
    }

    if let Some(Component::Prefix(prefix)) = path.components().next() {
        if matches!(prefix.kind(), Prefix::Verbatim(_) | Prefix::VerbatimDisk(_)) {
            return path.to_path_buf();
        }
    }

    path.to_path_buf()
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
}
