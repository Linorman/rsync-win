//! File-list codecs used by early session scaffolding and remote-shell tests.
//!
//! The `internal` codec is not upstream rsync's flist wire format. The
//! `rsync27` helpers implement the limited protocol-27 file-list subset used by
//! the current ordinary-file remote-shell compatibility path. The `rsync31`
//! helpers cover the non-incremental-recursion ordinary-file subset of the
//! upstream protocol-31 flist format.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::io::{
    read_bytes_with_u32_len, read_i32_le, read_i64_le, read_u32_le, read_u8, read_varint,
    read_varlong, write_bytes_with_u32_len, write_i32_le, write_i64_le, write_u32_le, write_u8,
    write_varint, write_varlong,
};

const XMIT_TOP_DIR: u8 = 0x01;
const XMIT_SAME_MODE: u8 = 0x02;
const XMIT_SAME_NAME: u8 = 0x20;
const XMIT_LONG_NAME: u8 = 0x40;
const XMIT_SAME_TIME: u8 = 0x80;
const XMIT31_TOP_DIR: u32 = 1 << 0;
const XMIT31_SAME_MODE: u32 = 1 << 1;
const XMIT31_EXTENDED_FLAGS: u32 = 1 << 2;
const XMIT31_SAME_UID: u32 = 1 << 3;
const XMIT31_SAME_GID: u32 = 1 << 4;
const XMIT31_SAME_NAME: u32 = 1 << 5;
const XMIT31_LONG_NAME: u32 = 1 << 6;
const XMIT31_SAME_TIME: u32 = 1 << 7;
const XMIT31_HLINKED: u32 = 1 << 9;
const XMIT31_USER_NAME_FOLLOWS: u32 = 1 << 10;
const XMIT31_GROUP_NAME_FOLLOWS: u32 = 1 << 11;
const XMIT31_HLINK_FIRST: u32 = 1 << 12;
const XMIT31_MOD_NSEC: u32 = 1 << 13;
const XMIT31_SAME_ATIME: u32 = 1 << 14;
const XMIT31_CRTIME_EQ_MTIME: u32 = 1 << 17;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const MAX_INLINE_XATTR_VALUE: usize = 32;

pub const RSYNC_REGULAR_FILE_MODE: u32 = S_IFREG | 0o644;
pub const RSYNC_DIRECTORY_MODE: u32 = S_IFDIR | 0o755;
pub const RSYNC_SYMLINK_MODE: u32 = S_IFLNK | 0o777;
pub const DEFAULT_MAX_FILE_LIST_ENTRIES: usize = 100_000;
pub const DEFAULT_MAX_FILE_LIST_PATH_LEN: usize = 32 * 1024;
const FILE_LIST_ENTRY_ALLOC_OVERHEAD: usize = std::mem::size_of::<RsyncFileListEntry>() + 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireFileType {
    File = 1,
    Directory = 2,
    Symlink = 3,
}

impl WireFileType {
    fn from_byte(byte: u8) -> Result<Self, FileListError> {
        match byte {
            1 => Ok(Self::File),
            2 => Ok(Self::Directory),
            3 => Ok(Self::Symlink),
            _ => Err(FileListError::InvalidFileType(byte)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileListEntry {
    pub path: PathBuf,
    pub file_type: WireFileType,
    pub len: u64,
    pub mtime_unix: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RsyncHardLinkGroup {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsyncFileListEntry {
    pub path: PathBuf,
    pub file_type: WireFileType,
    pub len: u64,
    pub mtime_unix: i64,
    pub mode: u32,
    pub checksum: Option<[u8; 16]>,
    pub hardlink_group: Option<RsyncHardLinkGroup>,
    pub metadata: RsyncFileListMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RsyncFileListMetadata {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub user_name: Option<String>,
    pub group_name: Option<String>,
    pub atime_unix: Option<i64>,
    pub crtime_unix: Option<i64>,
    pub xattrs: Vec<RsyncXattrPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsyncXattrPayload {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileListBatch {
    pub base_index: usize,
    pub entries: Vec<RsyncFileListEntry>,
    pub is_final: bool,
}

#[derive(Debug, Clone)]
pub struct FileListBatchBuilder {
    max_entries: usize,
    max_alloc: Option<u64>,
    next_base_index: usize,
    current_entries: Vec<RsyncFileListEntry>,
    current_alloc: usize,
}

impl FileListBatchBuilder {
    pub fn new(max_entries: usize) -> Result<Self, FileListError> {
        Self::with_max_alloc(max_entries, None)
    }

    pub fn with_max_alloc(
        max_entries: usize,
        max_alloc: Option<u64>,
    ) -> Result<Self, FileListError> {
        if max_entries == 0 {
            return Err(FileListError::Io(io::Error::new(
                ErrorKind::InvalidInput,
                "file-list batch size must be greater than zero",
            )));
        }

        Ok(Self {
            max_entries,
            max_alloc,
            next_base_index: 0,
            current_entries: Vec::with_capacity(max_entries.min(1024)),
            current_alloc: 0,
        })
    }

    pub fn push(
        &mut self,
        entry: RsyncFileListEntry,
    ) -> Result<Option<FileListBatch>, FileListError> {
        let entry_alloc = estimated_file_list_entry_alloc(&entry);
        if self.should_flush_before(entry_alloc) {
            let batch = self.emit(false);
            self.push_current(entry, entry_alloc)?;
            return Ok(Some(batch));
        }

        self.push_current(entry, entry_alloc)?;
        if self.current_entries.len() >= self.max_entries {
            Ok(Some(self.emit(false)))
        } else {
            Ok(None)
        }
    }

    pub fn finish(&mut self) -> FileListBatch {
        self.emit(true)
    }

    fn should_flush_before(&self, entry_alloc: usize) -> bool {
        if self.current_entries.is_empty() {
            return false;
        }
        if self.current_entries.len() >= self.max_entries {
            return true;
        }
        if let Some(limit) = self.max_alloc.filter(|limit| *limit > 0) {
            return self.current_alloc.saturating_add(entry_alloc) as u64 > limit;
        }
        false
    }

    fn push_current(
        &mut self,
        entry: RsyncFileListEntry,
        entry_alloc: usize,
    ) -> Result<(), FileListError> {
        AllocationBudget::new(self.max_alloc).check("file-list batch entry", entry_alloc)?;
        self.current_alloc = self.current_alloc.saturating_add(entry_alloc);
        self.current_entries.push(entry);
        Ok(())
    }

    fn emit(&mut self, is_final: bool) -> FileListBatch {
        let entries = std::mem::take(&mut self.current_entries);
        let base_index = self.next_base_index;
        self.next_base_index += entries.len();
        self.current_alloc = 0;
        FileListBatch {
            base_index,
            entries,
            is_final,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationBudget {
    max_alloc: Option<u64>,
}

impl AllocationBudget {
    pub fn new(max_alloc: Option<u64>) -> Self {
        Self { max_alloc }
    }

    pub fn check(self, label: &'static str, bytes: usize) -> Result<(), FileListError> {
        if let Some(limit) = self.max_alloc.filter(|limit| *limit > 0) {
            if bytes as u64 > limit {
                return Err(FileListError::Io(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("{label} would require a {bytes} byte allocation, exceeding --max-alloc={limit}"),
                )));
            }
        }
        Ok(())
    }
}

pub fn check_rsync_file_list_budget(
    entries: &[RsyncFileListEntry],
    max_alloc: Option<u64>,
) -> Result<(), FileListError> {
    let budget = AllocationBudget::new(max_alloc);
    let mut total = 0_usize;
    for entry in entries {
        total = total
            .checked_add(estimated_file_list_entry_alloc(entry))
            .ok_or_else(|| {
                FileListError::Io(io::Error::new(
                    ErrorKind::InvalidData,
                    "file-list allocation estimate overflow",
                ))
            })?;
        budget.check("file-list entries", total)?;
    }
    Ok(())
}

fn estimated_file_list_entry_alloc(entry: &RsyncFileListEntry) -> usize {
    let mut total = FILE_LIST_ENTRY_ALLOC_OVERHEAD
        .saturating_add(entry.path.as_os_str().to_string_lossy().len());
    if let Some(user_name) = &entry.metadata.user_name {
        total = total.saturating_add(user_name.len());
    }
    if let Some(group_name) = &entry.metadata.group_name {
        total = total.saturating_add(group_name.len());
    }
    for xattr in &entry.metadata.xattrs {
        total = total
            .saturating_add(xattr.name.len())
            .saturating_add(xattr.value.len());
    }
    total
}

pub fn estimated_rsync_file_list_entry_alloc(entry: &RsyncFileListEntry) -> usize {
    estimated_file_list_entry_alloc(entry)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RsyncFileListOptions {
    pub include_checksums: bool,
    pub preserve_owner: bool,
    pub preserve_group: bool,
    pub numeric_ids: bool,
    pub acls: bool,
    pub xattrs: bool,
    pub fake_super: bool,
    pub atimes: bool,
    pub crtimes: bool,
}

#[derive(Debug, Error)]
pub enum FileListError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid file type byte {0}")]
    InvalidFileType(u8),
    #[error("file path is not valid UTF-8")]
    InvalidUtf8,
    #[error("wire file path `{0}` contains a backslash; this transfer subset requires slash-separated rsync paths")]
    BackslashInPath(String),
    #[error("wire file path `{0}` is not a portable relative rsync path")]
    UnsafePath(String),
    #[error("file length {0} cannot be represented on the wire")]
    LengthTooLarge(u64),
    #[error("file path length {0} cannot be represented in protocol 27")]
    PathTooLong(usize),
    #[error("wire file mode {0:o} is not supported by this transfer subset")]
    UnsupportedMode(u32),
    #[error("missing checksum for regular file `{0}`")]
    MissingChecksum(PathBuf),
    #[error("xattr name `{0}` is not valid for protocol 31")]
    InvalidXattrName(String),
    #[error("xattr `{name}` value length {len} exceeds inline protocol support")]
    XattrValueTooLarge { name: String, len: usize },
}

pub fn write_internal_file_list<W: Write>(
    writer: &mut W,
    entries: &[FileListEntry],
) -> Result<(), FileListError> {
    let count = u32::try_from(entries.len()).map_err(|_| {
        FileListError::Io(io::Error::new(
            ErrorKind::InvalidInput,
            "file list has too many entries",
        ))
    })?;
    write_u32_le(writer, count)?;

    for entry in entries {
        write_bytes_with_u32_len(writer, entry.path.to_string_lossy().as_bytes())?;
        write_u8(writer, entry.file_type as u8)?;
        let len = i64::try_from(entry.len).map_err(|_| FileListError::LengthTooLarge(entry.len))?;
        write_i64_le(writer, len)?;
        write_i64_le(writer, entry.mtime_unix.unwrap_or(-1))?;
    }

    Ok(())
}

pub fn write_file_list<W: Write>(
    writer: &mut W,
    entries: &[FileListEntry],
) -> Result<(), FileListError> {
    write_internal_file_list(writer, entries)
}

pub fn read_internal_file_list<R: Read>(
    reader: &mut R,
    max_entries: usize,
    max_path_len: usize,
) -> Result<Vec<FileListEntry>, FileListError> {
    let count = read_u32_le(reader)? as usize;
    if count > max_entries {
        return Err(FileListError::Io(io::Error::new(
            ErrorKind::InvalidData,
            format!("file list entry count {count} exceeds limit {max_entries}"),
        )));
    }

    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let path_bytes = read_bytes_with_u32_len(reader, max_path_len)?;
        let path = wire_path_from_bytes(&path_bytes)?;
        let file_type = WireFileType::from_byte(read_u8(reader)?)?;
        let len = read_i64_le(reader)?;
        if len < 0 {
            return Err(FileListError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "negative file length",
            )));
        }
        let mtime = read_i64_le(reader)?;
        entries.push(FileListEntry {
            path,
            file_type,
            len: len as u64,
            mtime_unix: (mtime >= 0).then_some(mtime),
        });
    }

    Ok(entries)
}

pub fn read_file_list<R: Read>(
    reader: &mut R,
    max_entries: usize,
    max_path_len: usize,
) -> Result<Vec<FileListEntry>, FileListError> {
    read_internal_file_list(reader, max_entries, max_path_len)
}

pub fn write_rsync27_file_list<W: Write>(
    writer: &mut W,
    entries: &[RsyncFileListEntry],
) -> Result<(), FileListError> {
    write_rsync27_file_list_with_options(writer, entries, false)
}

pub fn write_rsync27_file_list_with_options<W: Write>(
    writer: &mut W,
    entries: &[RsyncFileListEntry],
    include_checksums: bool,
) -> Result<(), FileListError> {
    let mut list_writer = Rsync27FileListWriter::new(include_checksums);
    list_writer.write_batch(writer, entries)?;
    list_writer.finish(writer)
}

#[derive(Debug, Clone)]
pub struct Rsync27FileListWriter {
    include_checksums: bool,
    last_mode: Option<u32>,
    last_mtime: Option<i64>,
    finished: bool,
}

impl Rsync27FileListWriter {
    pub fn new(include_checksums: bool) -> Self {
        Self {
            include_checksums,
            last_mode: None,
            last_mtime: None,
            finished: false,
        }
    }

    pub fn write_batch<W: Write>(
        &mut self,
        writer: &mut W,
        entries: &[RsyncFileListEntry],
    ) -> Result<(), FileListError> {
        if self.finished {
            return Err(FileListError::Io(io::Error::new(
                ErrorKind::InvalidInput,
                "cannot write entries after finishing file-list",
            )));
        }

        for entry in entries {
            let path = wire_path_bytes(&entry.path);
            let mut status = XMIT_LONG_NAME;

            if self.last_mode == Some(entry.mode) {
                status |= XMIT_SAME_MODE;
            }
            if self.last_mtime == Some(entry.mtime_unix) {
                status |= XMIT_SAME_TIME;
            }
            if entry.file_type == WireFileType::Directory && entry.path == Path::new(".") {
                status |= XMIT_TOP_DIR;
            }

            write_u8(writer, status)?;
            if status & XMIT_LONG_NAME != 0 {
                let len = i32::try_from(path.len())
                    .map_err(|_| FileListError::PathTooLong(path.len()))?;
                write_i32_le(writer, len)?;
            } else {
                write_u8(writer, path.len() as u8)?;
            }
            writer.write_all(&path)?;
            write_rsync_long(writer, entry.len)?;
            if status & XMIT_SAME_TIME == 0 {
                let mtime = i32::try_from(entry.mtime_unix).map_err(|_| {
                    FileListError::Io(io::Error::new(
                        ErrorKind::InvalidInput,
                        "mtime is outside protocol 27 time_t range",
                    ))
                })?;
                write_i32_le(writer, mtime)?;
            }
            if status & XMIT_SAME_MODE == 0 {
                write_i32_le(writer, entry.mode as i32)?;
            }
            if self.include_checksums && entry.file_type == WireFileType::File {
                writer.write_all(
                    entry
                        .checksum
                        .as_ref()
                        .ok_or_else(|| FileListError::MissingChecksum(entry.path.clone()))?,
                )?;
            }

            self.last_mode = Some(entry.mode);
            self.last_mtime = Some(entry.mtime_unix);
        }

        Ok(())
    }

    pub fn finish<W: Write>(&mut self, writer: &mut W) -> Result<(), FileListError> {
        if !self.finished {
            write_u8(writer, 0)?;
            self.finished = true;
        }
        Ok(())
    }
}

pub fn read_rsync27_file_list<R: Read>(
    reader: &mut R,
    max_entries: usize,
    max_path_len: usize,
) -> Result<Vec<RsyncFileListEntry>, FileListError> {
    read_rsync27_file_list_with_options(reader, max_entries, max_path_len, false)
}

pub fn read_rsync27_file_list_with_options<R: Read>(
    reader: &mut R,
    max_entries: usize,
    max_path_len: usize,
    expect_checksums: bool,
) -> Result<Vec<RsyncFileListEntry>, FileListError> {
    let mut entries = Vec::<RsyncFileListEntry>::new();
    let mut last_path = Vec::<u8>::new();
    let mut last_mode = None::<u32>;
    let mut last_mtime = None::<i64>;

    loop {
        let status = read_u8(reader)?;
        if status == 0 {
            break;
        }
        if entries.len() >= max_entries {
            return Err(FileListError::Io(io::Error::new(
                ErrorKind::InvalidData,
                format!("file list entry count exceeds limit {max_entries}"),
            )));
        }

        let inherited = if status & XMIT_SAME_NAME != 0 {
            read_u8(reader)? as usize
        } else {
            0
        };
        if inherited > last_path.len() {
            return Err(FileListError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "file list inherited name prefix exceeds previous path",
            )));
        }

        let suffix_len = if status & XMIT_LONG_NAME != 0 {
            let len = read_i32_le(reader)?;
            if len < 0 {
                return Err(FileListError::Io(io::Error::new(
                    ErrorKind::InvalidData,
                    "negative file name length",
                )));
            }
            len as usize
        } else {
            read_u8(reader)? as usize
        };
        let total_len = inherited.checked_add(suffix_len).ok_or_else(|| {
            FileListError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "file name length overflow",
            ))
        })?;
        if total_len > max_path_len {
            return Err(FileListError::Io(io::Error::new(
                ErrorKind::InvalidData,
                format!("file path length {total_len} exceeds limit {max_path_len}"),
            )));
        }

        let mut path_bytes = last_path[..inherited].to_vec();
        path_bytes.resize(total_len, 0);
        reader.read_exact(&mut path_bytes[inherited..])?;

        let len = read_rsync_long(reader)?;
        let mtime = if status & XMIT_SAME_TIME != 0 {
            last_mtime.ok_or_else(|| {
                FileListError::Io(io::Error::new(
                    ErrorKind::InvalidData,
                    "file list repeated mtime without previous value",
                ))
            })?
        } else {
            i64::from(read_i32_le(reader)?)
        };
        let mode = if status & XMIT_SAME_MODE != 0 {
            last_mode.ok_or_else(|| {
                FileListError::Io(io::Error::new(
                    ErrorKind::InvalidData,
                    "file list repeated mode without previous value",
                ))
            })?
        } else {
            read_i32_le(reader)? as u32
        };

        let path = wire_path_from_bytes(&path_bytes)?;
        let file_type = file_type_from_mode(mode)?;
        let checksum = if expect_checksums && file_type == WireFileType::File {
            Some(read_checksum(reader)?)
        } else {
            None
        };
        entries.push(RsyncFileListEntry {
            path,
            file_type,
            len,
            mtime_unix: mtime,
            mode,
            checksum,
            hardlink_group: None,
            metadata: RsyncFileListMetadata::default(),
        });
        last_path = path_bytes;
        last_mtime = Some(mtime);
        last_mode = Some(mode);
    }

    Ok(entries)
}

pub fn write_rsync31_file_list<W: Write>(
    writer: &mut W,
    entries: &[RsyncFileListEntry],
) -> Result<(), FileListError> {
    write_rsync31_file_list_with_options(writer, entries, false)
}

pub fn write_rsync31_file_list_with_options<W: Write>(
    writer: &mut W,
    entries: &[RsyncFileListEntry],
    include_checksums: bool,
) -> Result<(), FileListError> {
    write_rsync31_file_list_with_metadata(
        writer,
        entries,
        RsyncFileListOptions {
            include_checksums,
            ..RsyncFileListOptions::default()
        },
    )
}

pub fn write_rsync31_file_list_with_metadata<W: Write>(
    writer: &mut W,
    entries: &[RsyncFileListEntry],
    options: RsyncFileListOptions,
) -> Result<(), FileListError> {
    let mut list_writer = Rsync31FileListWriter::new(options);
    list_writer.write_batch(writer, entries)?;
    list_writer.finish(writer)
}

#[derive(Debug, Clone)]
pub struct Rsync31FileListWriter {
    options: RsyncFileListOptions,
    last_path: Vec<u8>,
    last_mode: Option<u32>,
    last_mtime: Option<i64>,
    last_uid: Option<u32>,
    last_gid: Option<u32>,
    last_atime: Option<i64>,
    hardlink_groups: BTreeMap<RsyncHardLinkGroup, usize>,
    next_index: usize,
    finished: bool,
}

impl Rsync31FileListWriter {
    pub fn new(options: RsyncFileListOptions) -> Self {
        Self {
            options,
            last_path: Vec::new(),
            last_mode: None,
            last_mtime: None,
            last_uid: None,
            last_gid: None,
            last_atime: None,
            hardlink_groups: BTreeMap::new(),
            next_index: 0,
            finished: false,
        }
    }

    pub fn write_batch<W: Write>(
        &mut self,
        writer: &mut W,
        entries: &[RsyncFileListEntry],
    ) -> Result<(), FileListError> {
        if self.finished {
            return Err(FileListError::Io(io::Error::new(
                ErrorKind::InvalidInput,
                "cannot write entries after finishing file-list",
            )));
        }

        for entry in entries {
            let path = wire_path_bytes(&entry.path);
            let inherited = common_prefix_len(&self.last_path, &path);
            let suffix = &path[inherited..];
            let mut flags = 0;
            let mut hardlink_reference = None;
            let uid = entry.metadata.uid.unwrap_or(0);
            let gid = entry.metadata.gid.unwrap_or(0);
            let user_name = entry.metadata.user_name.as_deref();
            let group_name = entry.metadata.group_name.as_deref();
            let atime = entry.metadata.atime_unix.unwrap_or(entry.mtime_unix);
            let crtime = entry.metadata.crtime_unix.unwrap_or(entry.mtime_unix);

            if entry.file_type == WireFileType::Directory && entry.path == Path::new(".") {
                flags |= XMIT31_TOP_DIR;
            }
            if entry.file_type == WireFileType::File {
                if let Some(group) = entry.hardlink_group {
                    flags |= XMIT31_HLINKED;
                    if let Some(first_index) = self.hardlink_groups.get(&group) {
                        hardlink_reference = Some(*first_index);
                    } else {
                        self.hardlink_groups.insert(group, self.next_index);
                        flags |= XMIT31_HLINK_FIRST;
                    }
                }
            }
            if self.last_mode == Some(entry.mode) {
                flags |= XMIT31_SAME_MODE;
            }
            if self.last_mtime == Some(entry.mtime_unix) {
                flags |= XMIT31_SAME_TIME;
            }
            if !self.options.preserve_owner || self.last_uid == Some(uid) {
                flags |= XMIT31_SAME_UID;
            } else if !self.options.numeric_ids && user_name.is_some() {
                flags |= XMIT31_USER_NAME_FOLLOWS;
            }
            if !self.options.preserve_group || self.last_gid == Some(gid) {
                flags |= XMIT31_SAME_GID;
            } else if !self.options.numeric_ids && group_name.is_some() {
                flags |= XMIT31_GROUP_NAME_FOLLOWS;
            }
            if self.options.atimes
                && entry.file_type != WireFileType::Directory
                && self.last_atime == Some(atime)
            {
                flags |= XMIT31_SAME_ATIME;
            }
            if self.options.crtimes && crtime == entry.mtime_unix {
                flags |= XMIT31_CRTIME_EQ_MTIME;
            }
            if inherited > 0 {
                flags |= XMIT31_SAME_NAME;
            }
            if suffix.len() > u8::MAX as usize {
                flags |= XMIT31_LONG_NAME;
            }
            if flags == 0 {
                flags = XMIT31_EXTENDED_FLAGS;
            }

            write_varint(writer, flags)?;
            if flags & XMIT31_SAME_NAME != 0 {
                write_u8(writer, inherited as u8)?;
            }
            if flags & XMIT31_LONG_NAME != 0 {
                let len = u32::try_from(suffix.len())
                    .map_err(|_| FileListError::PathTooLong(suffix.len()))?;
                write_varint(writer, len)?;
            } else {
                write_u8(writer, suffix.len() as u8)?;
            }
            writer.write_all(suffix)?;
            if let Some(first_index) = hardlink_reference {
                let first_index = u32::try_from(first_index).map_err(|_| {
                    FileListError::Io(io::Error::new(
                        ErrorKind::InvalidInput,
                        "hardlink file-list index exceeds protocol 31 varint range",
                    ))
                })?;
                write_varint(writer, first_index)?;
                write_rsync31_metadata_payloads(writer, entry, self.options)?;
                self.record_entry_state(path, entry, uid, gid, atime);
                continue;
            }
            write_varlong(writer, entry.len, 3)?;
            if flags & XMIT31_SAME_TIME == 0 {
                let mtime = u64::try_from(entry.mtime_unix).map_err(|_| {
                    FileListError::Io(io::Error::new(
                        ErrorKind::InvalidInput,
                        "negative mtime is not supported by protocol 31 ordinary-file flist writer",
                    ))
                })?;
                write_varlong(writer, mtime, 4)?;
            }
            if flags & XMIT31_SAME_MODE == 0 {
                write_i32_le(writer, entry.mode as i32)?;
            }
            if self.options.crtimes && flags & XMIT31_CRTIME_EQ_MTIME == 0 {
                write_varlong(writer, nonnegative_time(crtime)?, 4)?;
            }
            if self.options.atimes
                && entry.file_type != WireFileType::Directory
                && flags & XMIT31_SAME_ATIME == 0
            {
                write_varlong(writer, nonnegative_time(atime)?, 4)?;
            }
            if self.options.preserve_owner && flags & XMIT31_SAME_UID == 0 {
                write_varint(writer, uid)?;
                if flags & XMIT31_USER_NAME_FOLLOWS != 0 {
                    write_name(writer, user_name.unwrap_or_default())?;
                }
            }
            if self.options.preserve_group && flags & XMIT31_SAME_GID == 0 {
                write_varint(writer, gid)?;
                if flags & XMIT31_GROUP_NAME_FOLLOWS != 0 {
                    write_name(writer, group_name.unwrap_or_default())?;
                }
            }
            if self.options.include_checksums && entry.file_type == WireFileType::File {
                writer.write_all(
                    entry
                        .checksum
                        .as_ref()
                        .ok_or_else(|| FileListError::MissingChecksum(entry.path.clone()))?,
                )?;
            }
            write_rsync31_metadata_payloads(writer, entry, self.options)?;

            self.record_entry_state(path, entry, uid, gid, atime);
        }

        Ok(())
    }

    pub fn finish<W: Write>(&mut self, writer: &mut W) -> Result<(), FileListError> {
        if !self.finished {
            write_varint(writer, 0)?;
            write_varint(writer, 0)?;
            if !self.options.numeric_ids {
                if self.options.preserve_owner || self.options.acls {
                    write_id0_name(writer, "root")?;
                }
                if self.options.preserve_group || self.options.acls {
                    write_id0_name(writer, "root")?;
                }
            }
            self.finished = true;
        }
        Ok(())
    }

    fn record_entry_state(
        &mut self,
        path: Vec<u8>,
        entry: &RsyncFileListEntry,
        uid: u32,
        gid: u32,
        atime: i64,
    ) {
        self.last_path = path;
        self.last_mode = Some(entry.mode);
        self.last_mtime = Some(entry.mtime_unix);
        if self.options.preserve_owner {
            self.last_uid = Some(uid);
        }
        if self.options.preserve_group {
            self.last_gid = Some(gid);
        }
        if self.options.atimes && entry.file_type != WireFileType::Directory {
            self.last_atime = Some(atime);
        }
        self.next_index += 1;
    }
}

fn write_id0_name<W: Write>(writer: &mut W, name: &str) -> Result<(), FileListError> {
    write_varint(writer, 0)?;
    write_name(writer, name)
}

fn nonnegative_time(value: i64) -> Result<u64, FileListError> {
    u64::try_from(value).map_err(|_| {
        FileListError::Io(io::Error::new(
            ErrorKind::InvalidInput,
            "negative protocol 31 timestamp is not supported",
        ))
    })
}

fn write_name<W: Write>(writer: &mut W, name: &str) -> Result<(), FileListError> {
    if name.len() > u8::MAX as usize {
        return Err(FileListError::Io(io::Error::new(
            ErrorKind::InvalidInput,
            "protocol 31 user/group name exceeds 255 bytes",
        )));
    }
    write_u8(writer, name.len() as u8)?;
    writer.write_all(name.as_bytes())?;
    Ok(())
}

fn write_rsync31_metadata_payloads<W: Write>(
    writer: &mut W,
    entry: &RsyncFileListEntry,
    options: RsyncFileListOptions,
) -> Result<(), FileListError> {
    if options.acls && entry.file_type != WireFileType::Symlink {
        write_empty_acl_payload(writer, entry.file_type)?;
    }
    if options.xattrs {
        write_xattr_payload(writer, &entry.metadata.xattrs)?;
    }
    Ok(())
}

fn write_empty_acl_payload<W: Write>(
    writer: &mut W,
    file_type: WireFileType,
) -> Result<(), FileListError> {
    write_varint(writer, 0)?;
    write_u8(writer, 0)?;
    if file_type == WireFileType::Directory {
        write_varint(writer, 0)?;
        write_u8(writer, 0)?;
    }
    Ok(())
}

fn write_xattr_payload<W: Write>(
    writer: &mut W,
    xattrs: &[RsyncXattrPayload],
) -> Result<(), FileListError> {
    write_varint(writer, 0)?;
    write_varint(writer, xattrs.len() as u32)?;
    for xattr in xattrs {
        if xattr.name.is_empty() || xattr.name.as_bytes().contains(&0) {
            return Err(FileListError::InvalidXattrName(xattr.name.clone()));
        }
        if xattr.value.len() > MAX_INLINE_XATTR_VALUE {
            return Err(FileListError::XattrValueTooLarge {
                name: xattr.name.clone(),
                len: xattr.value.len(),
            });
        }
        let name_len = xattr.name.len() + 1;
        write_varint(writer, name_len as u32)?;
        write_varint(writer, xattr.value.len() as u32)?;
        writer.write_all(xattr.name.as_bytes())?;
        write_u8(writer, 0)?;
        writer.write_all(&xattr.value)?;
    }
    Ok(())
}

pub fn write_rsync31_file_list_batch<W: Write>(
    writer: &mut W,
    batch: &FileListBatch,
) -> Result<(), FileListError> {
    write_rsync31_file_list_batch_with_metadata(writer, batch, RsyncFileListOptions::default())
}

pub fn write_rsync31_file_list_batch_with_metadata<W: Write>(
    writer: &mut W,
    batch: &FileListBatch,
    options: RsyncFileListOptions,
) -> Result<(), FileListError> {
    let base_index = u64::try_from(batch.base_index).map_err(|_| {
        FileListError::Io(io::Error::new(
            ErrorKind::InvalidInput,
            "file-list batch base index exceeds u64 range",
        ))
    })?;
    let count = u32::try_from(batch.entries.len()).map_err(|_| {
        FileListError::Io(io::Error::new(
            ErrorKind::InvalidInput,
            "file-list batch has too many entries",
        ))
    })?;

    write_varlong(writer, base_index, 3)?;
    write_u8(writer, u8::from(batch.is_final))?;
    write_u32_le(writer, count)?;
    write_rsync31_file_list_with_metadata(writer, &batch.entries, options)
}

pub fn read_rsync31_file_list<R: Read>(
    reader: &mut R,
    max_entries: usize,
    max_path_len: usize,
) -> Result<Vec<RsyncFileListEntry>, FileListError> {
    read_rsync31_file_list_with_options(reader, max_entries, max_path_len, false)
}

pub fn read_rsync31_file_list_with_options<R: Read>(
    reader: &mut R,
    max_entries: usize,
    max_path_len: usize,
    expect_checksums: bool,
) -> Result<Vec<RsyncFileListEntry>, FileListError> {
    read_rsync31_file_list_with_metadata(
        reader,
        max_entries,
        max_path_len,
        RsyncFileListOptions {
            include_checksums: expect_checksums,
            ..RsyncFileListOptions::default()
        },
    )
}

pub fn read_rsync31_file_list_with_metadata<R: Read>(
    reader: &mut R,
    max_entries: usize,
    max_path_len: usize,
    options: RsyncFileListOptions,
) -> Result<Vec<RsyncFileListEntry>, FileListError> {
    let mut entries = Vec::<RsyncFileListEntry>::new();
    let mut last_path = Vec::<u8>::new();
    let mut last_mode = None::<u32>;
    let mut last_mtime = None::<i64>;
    let mut last_uid = None::<u32>;
    let mut last_gid = None::<u32>;
    let mut last_user_name = None::<String>;
    let mut last_group_name = None::<String>;
    let mut last_atime = None::<i64>;

    loop {
        let flags = read_varint(reader)?;
        if flags == 0 {
            let io_error = read_varint(reader)?;
            if io_error != 0 {
                return Err(FileListError::Io(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("remote sender reported file-list I/O error {io_error}"),
                )));
            }
            break;
        }
        if entries.len() >= max_entries {
            return Err(FileListError::Io(io::Error::new(
                ErrorKind::InvalidData,
                format!("file list entry count exceeds limit {max_entries}"),
            )));
        }

        let inherited = if flags & XMIT31_SAME_NAME != 0 {
            read_u8(reader)? as usize
        } else {
            0
        };
        if inherited > last_path.len() {
            return Err(FileListError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "file list inherited name prefix exceeds previous path",
            )));
        }

        let suffix_len = if flags & XMIT31_LONG_NAME != 0 {
            read_varint(reader)? as usize
        } else {
            read_u8(reader)? as usize
        };
        let total_len = inherited.checked_add(suffix_len).ok_or_else(|| {
            FileListError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "file name length overflow",
            ))
        })?;
        if total_len > max_path_len {
            return Err(FileListError::Io(io::Error::new(
                ErrorKind::InvalidData,
                format!("file path length {total_len} exceeds limit {max_path_len}"),
            )));
        }

        let mut path_bytes = last_path[..inherited].to_vec();
        path_bytes.resize(total_len, 0);
        reader.read_exact(&mut path_bytes[inherited..])?;

        let path = wire_path_from_bytes(&path_bytes)?;
        let hardlink_reference = if flags & XMIT31_HLINKED != 0 && flags & XMIT31_HLINK_FIRST == 0 {
            let first_index = read_varint(reader)? as usize;
            if first_index >= entries.len() {
                return Err(FileListError::Io(io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "hardlink reference {first_index} exceeds file-list entries read so far"
                    ),
                )));
            }
            Some(first_index)
        } else {
            None
        };
        let (file_type, len, mtime, mode, checksum, hardlink_group, metadata) =
            if let Some(first_index) = hardlink_reference {
                let first = &entries[first_index];
                let group = first.hardlink_group.unwrap_or(RsyncHardLinkGroup {
                    device: 0,
                    inode: first_index as u64,
                });
                (
                    first.file_type,
                    first.len,
                    first.mtime_unix,
                    first.mode,
                    first.checksum,
                    Some(group),
                    first.metadata.clone(),
                )
            } else {
                let len = read_varlong(reader, 3)?;
                let mtime = if flags & XMIT31_SAME_TIME != 0 {
                    last_mtime.ok_or_else(|| {
                        FileListError::Io(io::Error::new(
                            ErrorKind::InvalidData,
                            "file list repeated mtime without previous value",
                        ))
                    })?
                } else {
                    let value = read_varlong(reader, 4)?;
                    i64::try_from(value).map_err(|_| {
                        FileListError::Io(io::Error::new(
                            ErrorKind::InvalidData,
                            "protocol 31 mtime is outside i64 range",
                        ))
                    })?
                };
                if flags & XMIT31_MOD_NSEC != 0 {
                    let _mtime_nsec = read_varint(reader)?;
                }
                let mode = if flags & XMIT31_SAME_MODE != 0 {
                    last_mode.ok_or_else(|| {
                        FileListError::Io(io::Error::new(
                            ErrorKind::InvalidData,
                            "file list repeated mode without previous value",
                        ))
                    })?
                } else {
                    read_i32_le(reader)? as u32
                };
                let crtime = if options.crtimes {
                    if flags & XMIT31_CRTIME_EQ_MTIME != 0 {
                        Some(mtime)
                    } else {
                        Some(read_protocol_time(reader, "crtime")?)
                    }
                } else {
                    None
                };
                let file_type = file_type_from_mode(mode)?;
                let atime = if options.atimes && file_type != WireFileType::Directory {
                    if flags & XMIT31_SAME_ATIME != 0 {
                        Some(last_atime.ok_or_else(|| {
                            FileListError::Io(io::Error::new(
                                ErrorKind::InvalidData,
                                "file list repeated atime without previous value",
                            ))
                        })?)
                    } else {
                        Some(read_protocol_time(reader, "atime")?)
                    }
                } else {
                    None
                };

                let (uid, user_name) = if options.preserve_owner {
                    if flags & XMIT31_SAME_UID != 0 {
                        (last_uid, last_user_name.clone())
                    } else {
                        let uid = read_varint(reader)?;
                        let user_name = if flags & XMIT31_USER_NAME_FOLLOWS != 0 {
                            Some(read_name(reader)?)
                        } else {
                            None
                        };
                        (Some(uid), user_name)
                    }
                } else if flags & XMIT31_SAME_UID == 0 {
                    let _ = read_varint(reader)?;
                    if flags & XMIT31_USER_NAME_FOLLOWS != 0 {
                        read_ignored_name(reader)?;
                    }
                    (None, None)
                } else {
                    (None, None)
                };
                let (gid, group_name) = if options.preserve_group {
                    if flags & XMIT31_SAME_GID != 0 {
                        (last_gid, last_group_name.clone())
                    } else {
                        let gid = read_varint(reader)?;
                        let group_name = if flags & XMIT31_GROUP_NAME_FOLLOWS != 0 {
                            Some(read_name(reader)?)
                        } else {
                            None
                        };
                        (Some(gid), group_name)
                    }
                } else if flags & XMIT31_SAME_GID == 0 {
                    let _ = read_varint(reader)?;
                    if flags & XMIT31_GROUP_NAME_FOLLOWS != 0 {
                        read_ignored_name(reader)?;
                    }
                    (None, None)
                } else {
                    (None, None)
                };
                let checksum = if options.include_checksums && file_type == WireFileType::File {
                    Some(read_checksum(reader)?)
                } else {
                    None
                };
                let hardlink_group = if flags & XMIT31_HLINKED != 0 {
                    Some(RsyncHardLinkGroup {
                        device: 0,
                        inode: entries.len() as u64,
                    })
                } else {
                    None
                };
                let mut metadata = RsyncFileListMetadata {
                    uid,
                    gid,
                    user_name,
                    group_name,
                    atime_unix: atime,
                    crtime_unix: crtime,
                    xattrs: Vec::new(),
                };
                metadata.xattrs = read_rsync31_metadata_payloads(reader, file_type, options)?;
                (
                    file_type,
                    len,
                    mtime,
                    mode,
                    checksum,
                    hardlink_group,
                    metadata,
                )
            };
        let mut metadata = metadata;
        if hardlink_reference.is_some() {
            metadata.xattrs = read_rsync31_metadata_payloads(reader, file_type, options)?;
        }
        entries.push(RsyncFileListEntry {
            path,
            file_type,
            len,
            mtime_unix: mtime,
            mode,
            checksum,
            hardlink_group,
            metadata,
        });
        let entry = entries.last().expect("entry just pushed");
        last_path = path_bytes;
        last_mtime = Some(mtime);
        last_mode = Some(mode);
        if options.preserve_owner {
            last_uid = entry.metadata.uid;
            if entry.metadata.user_name.is_some() {
                last_user_name = entry.metadata.user_name.clone();
            }
        }
        if options.preserve_group {
            last_gid = entry.metadata.gid;
            if entry.metadata.group_name.is_some() {
                last_group_name = entry.metadata.group_name.clone();
            }
        }
        if options.atimes && file_type != WireFileType::Directory {
            last_atime = entry.metadata.atime_unix;
        }
    }

    if !options.numeric_ids {
        if options.preserve_owner || options.acls {
            read_id_list_terminator(reader)?;
        }
        if options.preserve_group || options.acls {
            read_id_list_terminator(reader)?;
        }
    }

    Ok(entries)
}

pub fn read_rsync31_file_list_batch<R: Read>(
    reader: &mut R,
    max_entries: usize,
    max_path_len: usize,
) -> Result<FileListBatch, FileListError> {
    read_rsync31_file_list_batch_with_metadata(
        reader,
        max_entries,
        max_path_len,
        RsyncFileListOptions::default(),
    )
}

pub fn read_rsync31_file_list_batch_with_metadata<R: Read>(
    reader: &mut R,
    max_entries: usize,
    max_path_len: usize,
    options: RsyncFileListOptions,
) -> Result<FileListBatch, FileListError> {
    let base_index = usize::try_from(read_varlong(reader, 3)?).map_err(|_| {
        FileListError::Io(io::Error::new(
            ErrorKind::InvalidData,
            "file-list batch base index exceeds usize range",
        ))
    })?;
    let is_final = match read_u8(reader)? {
        0 => false,
        1 => true,
        value => {
            return Err(FileListError::Io(io::Error::new(
                ErrorKind::InvalidData,
                format!("invalid file-list batch final flag {value}"),
            )));
        }
    };
    let count = read_u32_le(reader)? as usize;
    if count > max_entries {
        return Err(FileListError::Io(io::Error::new(
            ErrorKind::InvalidData,
            format!("file-list batch entry count {count} exceeds limit {max_entries}"),
        )));
    }

    let entries = read_rsync31_file_list_with_metadata(reader, count, max_path_len, options)?;
    if entries.len() != count {
        return Err(FileListError::Io(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "file-list batch header declared {count} entries but decoded {}",
                entries.len()
            ),
        )));
    }

    Ok(FileListBatch {
        base_index,
        entries,
        is_final,
    })
}

fn read_protocol_time<R: Read>(reader: &mut R, field: &'static str) -> Result<i64, FileListError> {
    let value = read_varlong(reader, 4)?;
    i64::try_from(value).map_err(|_| {
        FileListError::Io(io::Error::new(
            ErrorKind::InvalidData,
            format!("protocol 31 {field} is outside i64 range"),
        ))
    })
}

fn read_name<R: Read>(reader: &mut R) -> Result<String, FileListError> {
    let len = read_u8(reader)? as usize;
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| FileListError::InvalidUtf8)
}

fn read_rsync31_metadata_payloads<R: Read>(
    reader: &mut R,
    file_type: WireFileType,
    options: RsyncFileListOptions,
) -> Result<Vec<RsyncXattrPayload>, FileListError> {
    if options.acls && file_type != WireFileType::Symlink {
        read_empty_acl_payload(reader)?;
        if file_type == WireFileType::Directory {
            read_empty_acl_payload(reader)?;
        }
    }
    if options.xattrs || options.fake_super {
        read_xattr_payload(reader)
    } else {
        Ok(Vec::new())
    }
}

fn read_empty_acl_payload<R: Read>(reader: &mut R) -> Result<(), FileListError> {
    let ndx = read_varint(reader)?;
    if ndx != 0 {
        return Err(FileListError::Io(io::Error::new(
            ErrorKind::InvalidData,
            format!("unsupported ACL payload index {ndx}"),
        )));
    }
    let flags = read_u8(reader)?;
    if flags != 0 {
        return Err(FileListError::Io(io::Error::new(
            ErrorKind::InvalidData,
            format!("unsupported ACL payload flags {flags}"),
        )));
    }
    Ok(())
}

fn read_xattr_payload<R: Read>(reader: &mut R) -> Result<Vec<RsyncXattrPayload>, FileListError> {
    let ndx = read_varint(reader)?;
    if ndx != 0 {
        return Err(FileListError::Io(io::Error::new(
            ErrorKind::InvalidData,
            format!("unsupported xattr payload index {ndx}"),
        )));
    }
    let count = read_varint(reader)? as usize;
    let mut xattrs = Vec::with_capacity(count);
    for _ in 0..count {
        let name_len = read_varint(reader)? as usize;
        let value_len = read_varint(reader)? as usize;
        if name_len == 0 {
            return Err(FileListError::InvalidXattrName(String::new()));
        }
        let mut name_bytes = vec![0; name_len];
        reader.read_exact(&mut name_bytes)?;
        if name_bytes.last() != Some(&0) {
            return Err(FileListError::InvalidXattrName(
                String::from_utf8_lossy(&name_bytes).into_owned(),
            ));
        }
        name_bytes.pop();
        let name = String::from_utf8(name_bytes).map_err(|_| FileListError::InvalidUtf8)?;
        let mut value = vec![0; value_len];
        reader.read_exact(&mut value)?;
        xattrs.push(RsyncXattrPayload { name, value });
    }
    Ok(xattrs)
}

fn read_id_list_terminator<R: Read>(reader: &mut R) -> Result<(), FileListError> {
    loop {
        let id = read_varint(reader)?;
        if id == 0 {
            read_ignored_name(reader)?;
            return Ok(());
        }
        read_ignored_name(reader)?;
    }
}

pub fn write_rsync_long<W: Write>(writer: &mut W, value: u64) -> Result<(), FileListError> {
    if value <= i32::MAX as u64 {
        write_i32_le(writer, value as i32)?;
    } else {
        let value_i64 = i64::try_from(value).map_err(|_| FileListError::LengthTooLarge(value))?;
        write_i32_le(writer, -1)?;
        write_i64_le(writer, value_i64)?;
    }
    Ok(())
}

pub fn read_rsync_long<R: Read>(reader: &mut R) -> Result<u64, FileListError> {
    let value = read_i32_le(reader)?;
    if value >= 0 {
        return Ok(value as u64);
    }
    if value != -1 {
        return Err(FileListError::Io(io::Error::new(
            ErrorKind::InvalidData,
            "negative protocol long marker",
        )));
    }
    let value = read_i64_le(reader)?;
    if value < 0 {
        return Err(FileListError::Io(io::Error::new(
            ErrorKind::InvalidData,
            "negative protocol long value",
        )));
    }
    Ok(value as u64)
}

fn wire_path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().replace('\\', "/").into_bytes()
}

fn wire_path_from_bytes(path_bytes: &[u8]) -> Result<PathBuf, FileListError> {
    let path = std::str::from_utf8(path_bytes).map_err(|_| FileListError::InvalidUtf8)?;
    if path.contains('\\') {
        return Err(FileListError::BackslashInPath(path.to_owned()));
    }
    validate_wire_path(path)?;
    Ok(PathBuf::from(path))
}

fn validate_wire_path(path: &str) -> Result<(), FileListError> {
    if path == "." {
        return Ok(());
    }
    if path.is_empty() || path.starts_with('/') {
        return Err(FileListError::UnsafePath(path.to_owned()));
    }

    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(FileListError::UnsafePath(path.to_owned()));
        }
        if component.ends_with(' ') || component.ends_with('.') {
            return Err(FileListError::UnsafePath(path.to_owned()));
        }
        if component
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        {
            return Err(FileListError::UnsafePath(path.to_owned()));
        }
        if is_reserved_windows_name(component) {
            return Err(FileListError::UnsafePath(path.to_owned()));
        }
    }

    Ok(())
}

fn is_reserved_windows_name(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(component)
        .trim_end_matches(' ')
        .to_ascii_uppercase();

    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || is_numbered_reserved_name(&stem, "COM")
        || is_numbered_reserved_name(&stem, "LPT")
}

fn is_numbered_reserved_name(stem: &str, prefix: &str) -> bool {
    let Some(number) = stem.strip_prefix(prefix) else {
        return false;
    };
    matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
}

fn common_prefix_len(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right.iter())
        .take(u8::MAX as usize)
        .take_while(|(left, right)| left == right)
        .count()
}

fn read_ignored_name<R: Read>(reader: &mut R) -> Result<(), FileListError> {
    let len = read_u8(reader)? as usize;
    let mut bytes = vec![0_u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(())
}

fn read_checksum<R: Read>(reader: &mut R) -> Result<[u8; 16], FileListError> {
    let mut checksum = [0_u8; 16];
    reader.read_exact(&mut checksum)?;
    Ok(checksum)
}

fn file_type_from_mode(mode: u32) -> Result<WireFileType, FileListError> {
    match mode & S_IFMT {
        S_IFREG => Ok(WireFileType::File),
        S_IFDIR => Ok(WireFileType::Directory),
        S_IFLNK => Ok(WireFileType::Symlink),
        _ => Err(FileListError::UnsupportedMode(mode)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_minimal_file_list() {
        let entries = vec![
            FileListEntry {
                path: PathBuf::from("dir"),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: Some(1_700_000_000),
            },
            FileListEntry {
                path: PathBuf::from("dir/file.txt"),
                file_type: WireFileType::File,
                len: 3,
                mtime_unix: None,
            },
        ];

        let mut bytes = Vec::new();
        write_internal_file_list(&mut bytes, &entries).unwrap();

        assert_eq!(
            read_internal_file_list(&mut bytes.as_slice(), 8, 128).unwrap(),
            entries
        );
    }

    #[test]
    fn security_internal_reader_rejects_excessive_file_count() {
        let mut bytes = Vec::new();
        write_u32_le(&mut bytes, 2).unwrap();
        let err = read_file_list(&mut bytes.as_slice(), 1, 128).unwrap_err();
        assert!(matches!(err, FileListError::Io(_)));
    }

    #[test]
    fn security_internal_reader_rejects_excessive_path_length() {
        let mut bytes = Vec::new();
        write_u32_le(&mut bytes, 1).unwrap();
        write_bytes_with_u32_len(&mut bytes, b"abcde").unwrap();

        let err = read_internal_file_list(&mut bytes.as_slice(), 16, 4).unwrap_err();

        assert!(matches!(err, FileListError::Io(_)));
    }

    #[test]
    fn security_rsync31_reader_rejects_excessive_file_count() {
        let mut bytes = Vec::new();
        write_varint(&mut bytes, XMIT31_SAME_UID | XMIT31_SAME_GID).unwrap();

        let err = read_rsync31_file_list(&mut bytes.as_slice(), 0, 256).unwrap_err();

        assert!(matches!(err, FileListError::Io(_)));
    }

    #[test]
    fn security_rsync31_reader_rejects_excessive_path_length() {
        let mut bytes = Vec::new();
        write_varint(&mut bytes, XMIT31_SAME_UID | XMIT31_SAME_GID).unwrap();
        write_u8(&mut bytes, 5).unwrap();
        bytes.extend_from_slice(b"abcde");

        let err = read_rsync31_file_list(&mut bytes.as_slice(), 16, 4).unwrap_err();

        assert!(matches!(err, FileListError::Io(_)));
    }

    #[test]
    fn security_internal_reader_rejects_backslash_paths_before_pathbuf_conversion() {
        let mut bytes = Vec::new();
        write_u32_le(&mut bytes, 1).unwrap();
        write_bytes_with_u32_len(&mut bytes, b"a\\b").unwrap();
        write_u8(&mut bytes, WireFileType::File as u8).unwrap();
        write_i64_le(&mut bytes, 1).unwrap();
        write_i64_le(&mut bytes, 1_700_000_000).unwrap();

        let err = read_internal_file_list(&mut bytes.as_slice(), 16, 256).unwrap_err();

        assert!(matches!(
            err,
            FileListError::BackslashInPath(path) if path == "a\\b"
        ));
    }

    #[test]
    fn security_protocol27_reader_rejects_backslash_paths_before_pathbuf_conversion() {
        let mut bytes = Vec::new();
        write_u8(&mut bytes, XMIT_LONG_NAME).unwrap();
        write_i32_le(&mut bytes, 3).unwrap();
        bytes.extend_from_slice(b"a\\b");
        write_i32_le(&mut bytes, 1).unwrap();
        write_i32_le(&mut bytes, 1_700_000_000).unwrap();
        write_i32_le(&mut bytes, RSYNC_REGULAR_FILE_MODE as i32).unwrap();
        write_u8(&mut bytes, 0).unwrap();

        let err = read_rsync27_file_list(&mut bytes.as_slice(), 16, 256).unwrap_err();

        assert!(matches!(
            err,
            FileListError::BackslashInPath(path) if path == "a\\b"
        ));
    }

    #[test]
    fn security_protocol31_reader_rejects_backslash_paths_before_pathbuf_conversion() {
        let mut bytes = Vec::new();
        write_varint(&mut bytes, XMIT31_SAME_UID | XMIT31_SAME_GID).unwrap();
        write_u8(&mut bytes, 3).unwrap();
        bytes.extend_from_slice(b"a\\b");
        write_varlong(&mut bytes, 1, 3).unwrap();
        write_varlong(&mut bytes, 1_700_000_000, 4).unwrap();
        write_i32_le(&mut bytes, RSYNC_REGULAR_FILE_MODE as i32).unwrap();
        write_varint(&mut bytes, 0).unwrap();
        write_varint(&mut bytes, 0).unwrap();

        let err = read_rsync31_file_list(&mut bytes.as_slice(), 16, 256).unwrap_err();

        assert!(matches!(
            err,
            FileListError::BackslashInPath(path) if path == "a\\b"
        ));
    }

    #[test]
    fn writes_and_reads_protocol27_file_list() {
        let entries = vec![
            RsyncFileListEntry {
                path: PathBuf::from("dir"),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("dir/file.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 1_700_000_001,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
        ];

        let mut bytes = Vec::new();
        write_rsync27_file_list(&mut bytes, &entries).unwrap();

        assert_eq!(
            read_rsync27_file_list(&mut bytes.as_slice(), 16, 256).unwrap(),
            entries
        );
    }

    #[test]
    fn protocol27_reader_handles_repeated_mode_and_prefix() {
        let mut encoded = Vec::new();
        write_u8(&mut encoded, XMIT_LONG_NAME).unwrap();
        write_i32_le(&mut encoded, 3).unwrap();
        encoded.extend_from_slice(b"dir");
        write_i32_le(&mut encoded, 0).unwrap();
        write_i32_le(&mut encoded, 1).unwrap();
        write_i32_le(&mut encoded, RSYNC_DIRECTORY_MODE as i32).unwrap();

        write_u8(&mut encoded, XMIT_SAME_NAME | XMIT_SAME_MODE).unwrap();
        write_u8(&mut encoded, 3).unwrap();
        write_u8(&mut encoded, 9).unwrap();
        encoded.extend_from_slice(b"/file.txt");
        write_i32_le(&mut encoded, 1).unwrap();
        write_i32_le(&mut encoded, 2).unwrap();
        write_u8(&mut encoded, 0).unwrap();

        let decoded = read_rsync27_file_list(&mut encoded.as_slice(), 16, 256).unwrap();
        assert_eq!(decoded[1].path, PathBuf::from("dir/file.txt"));
        assert_eq!(decoded[1].mode, RSYNC_DIRECTORY_MODE);
    }

    #[test]
    fn reads_captured_protocol31_no_inc_recursive_file_list() {
        let captured = [
            0xa0, 0x19, 0x01, b'.', 0x00, 0x00, 0x10, 0x69, 0x34, 0x28, 0xec, 0xeb, 0x09, 0xa4,
            0x6d, 0xed, 0x41, 0x00, 0x00, 0xa0, 0x9a, 0x03, b'd', b'i', b'r', 0x00, 0x00, 0x10,
            0xeb, 0x09, 0xa4, 0x6d, 0xa0, 0xb8, 0x03, 0x09, b'/', b'f', b'i', b'l', b'e', b'.',
            b't', b'x', b't', 0x00, 0x05, 0x00, 0xeb, 0x09, 0xa4, 0x6d, 0xa4, 0x81, 0x00, 0x00,
            0x00, 0x00,
        ];

        let entries = read_rsync31_file_list(&mut captured.as_slice(), 16, 256).unwrap();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, PathBuf::from("."));
        assert_eq!(entries[0].file_type, WireFileType::Directory);
        assert_eq!(entries[0].mode, RSYNC_DIRECTORY_MODE);
        assert_eq!(entries[1].path, PathBuf::from("dir"));
        assert_eq!(entries[1].file_type, WireFileType::Directory);
        assert_eq!(entries[2].path, PathBuf::from("dir/file.txt"));
        assert_eq!(entries[2].file_type, WireFileType::File);
        assert_eq!(entries[2].len, 5);
        assert_eq!(entries[2].mode, RSYNC_REGULAR_FILE_MODE);
    }

    #[test]
    fn writes_and_reads_protocol31_file_list() {
        let entries = vec![
            RsyncFileListEntry {
                path: PathBuf::from("."),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("dir"),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("dir/file.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
        ];

        let mut bytes = Vec::new();
        write_rsync31_file_list(&mut bytes, &entries).unwrap();

        assert_eq!(
            read_rsync31_file_list(&mut bytes.as_slice(), 16, 256).unwrap(),
            entries
        );
    }

    #[test]
    fn writes_and_reads_protocol31_file_list_batches_in_order() {
        let entries = vec![
            RsyncFileListEntry {
                path: PathBuf::from("."),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("alpha"),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 1_700_000_001,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("alpha/file.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 1_700_000_002,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
        ];
        let batches = vec![
            FileListBatch {
                base_index: 0,
                entries: entries[..2].to_vec(),
                is_final: false,
            },
            FileListBatch {
                base_index: 2,
                entries: entries[2..].to_vec(),
                is_final: true,
            },
        ];

        let mut bytes = Vec::new();
        for batch in &batches {
            write_rsync31_file_list_batch_with_metadata(
                &mut bytes,
                batch,
                RsyncFileListOptions::default(),
            )
            .unwrap();
        }

        let mut cursor = bytes.as_slice();
        let decoded: Vec<_> = (0..2)
            .map(|_| {
                read_rsync31_file_list_batch_with_metadata(
                    &mut cursor,
                    16,
                    256,
                    RsyncFileListOptions::default(),
                )
                .unwrap()
            })
            .collect();

        assert_eq!(decoded, batches);
        assert!(cursor.is_empty());
        assert_eq!(
            decoded
                .iter()
                .flat_map(|batch| batch.entries.iter().map(|entry| entry.path.clone()))
                .collect::<Vec<_>>(),
            vec![
                PathBuf::from("."),
                PathBuf::from("alpha"),
                PathBuf::from("alpha/file.txt"),
            ]
        );
    }

    #[test]
    fn streamed_protocol31_batches_match_single_file_list_encoding() {
        let entries = vec![
            RsyncFileListEntry {
                path: PathBuf::from("."),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("alpha"),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("alpha/file.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 1_700_000_001,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
        ];

        let mut single = Vec::new();
        write_rsync31_file_list_with_metadata(
            &mut single,
            &entries,
            RsyncFileListOptions::default(),
        )
        .unwrap();

        let mut streamed = Vec::new();
        let mut writer = Rsync31FileListWriter::new(RsyncFileListOptions::default());
        writer.write_batch(&mut streamed, &entries[..2]).unwrap();
        writer.write_batch(&mut streamed, &entries[2..]).unwrap();
        writer.finish(&mut streamed).unwrap();

        assert_eq!(streamed, single);
        assert_eq!(
            read_rsync31_file_list(&mut streamed.as_slice(), 16, 256).unwrap(),
            entries
        );
    }

    #[test]
    fn streamed_protocol31_batches_preserve_hardlink_indexes_across_batches() {
        let group = RsyncHardLinkGroup {
            device: 7,
            inode: 42,
        };
        let mut first = test_file("first.txt");
        first.hardlink_group = Some(group);
        let mut second = test_file("second.txt");
        second.hardlink_group = Some(group);
        let entries = vec![first, test_file("middle.txt"), second];

        let mut single = Vec::new();
        write_rsync31_file_list_with_metadata(
            &mut single,
            &entries,
            RsyncFileListOptions::default(),
        )
        .unwrap();

        let mut streamed = Vec::new();
        let mut writer = Rsync31FileListWriter::new(RsyncFileListOptions::default());
        writer.write_batch(&mut streamed, &entries[..2]).unwrap();
        writer.write_batch(&mut streamed, &entries[2..]).unwrap();
        writer.finish(&mut streamed).unwrap();

        assert_eq!(streamed, single);
        let decoded = read_rsync31_file_list(&mut streamed.as_slice(), 16, 256).unwrap();
        assert_eq!(
            decoded.iter().map(|entry| &entry.path).collect::<Vec<_>>(),
            entries.iter().map(|entry| &entry.path).collect::<Vec<_>>()
        );
        assert_eq!(decoded[0].hardlink_group, decoded[2].hardlink_group);
        assert!(decoded[0].hardlink_group.is_some());
    }

    #[test]
    fn file_list_batch_builder_flushes_at_configured_window() {
        let mut builder = FileListBatchBuilder::new(2).unwrap();

        assert!(builder.push(test_file("one.txt")).unwrap().is_none());
        let first = builder.push(test_file("two.txt")).unwrap().unwrap();
        assert_eq!(first.base_index, 0);
        assert_eq!(first.entries.len(), 2);
        assert!(!first.is_final);

        assert!(builder.push(test_file("three.txt")).unwrap().is_none());
        let final_batch = builder.finish();

        assert_eq!(final_batch.base_index, 2);
        assert_eq!(final_batch.entries.len(), 1);
        assert!(final_batch.is_final);
    }

    #[test]
    fn protocol_file_list_marks_dot_as_content_top_directory() {
        let entries = vec![RsyncFileListEntry {
            path: PathBuf::from("."),
            file_type: WireFileType::Directory,
            len: 0,
            mtime_unix: 1_700_000_000,
            mode: RSYNC_DIRECTORY_MODE,
            checksum: None,
            hardlink_group: None,
            metadata: RsyncFileListMetadata::default(),
        }];

        let mut protocol27 = Vec::new();
        write_rsync27_file_list(&mut protocol27, &entries).unwrap();
        assert_eq!(protocol27[0] & XMIT_TOP_DIR, XMIT_TOP_DIR);

        let mut protocol31 = Vec::new();
        write_rsync31_file_list(&mut protocol31, &entries).unwrap();
        let flags = read_varint(&mut protocol31.as_slice()).unwrap();
        assert_eq!(flags & XMIT31_TOP_DIR, XMIT31_TOP_DIR);
        assert_eq!(flags & (1 << 8), 0);
    }

    #[test]
    fn writes_and_reads_protocol31_file_list_with_checksums() {
        let checksum = [7_u8; 16];
        let entries = vec![
            RsyncFileListEntry {
                path: PathBuf::from("."),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("file.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: Some(checksum),
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
        ];

        let mut bytes = Vec::new();
        write_rsync31_file_list_with_options(&mut bytes, &entries, true).unwrap();

        assert_eq!(
            read_rsync31_file_list_with_options(&mut bytes.as_slice(), 16, 256, true).unwrap(),
            entries
        );
    }

    #[test]
    fn writes_and_reads_protocol31_hardlink_groups() {
        let group = RsyncHardLinkGroup {
            device: 7,
            inode: 11,
        };
        let entries = vec![
            RsyncFileListEntry {
                path: PathBuf::from("original.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: Some([3_u8; 16]),
                hardlink_group: Some(group),
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("alias.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: Some([3_u8; 16]),
                hardlink_group: Some(group),
                metadata: RsyncFileListMetadata::default(),
            },
        ];

        let mut bytes = Vec::new();
        write_rsync31_file_list_with_options(&mut bytes, &entries, true).unwrap();
        let decoded =
            read_rsync31_file_list_with_options(&mut bytes.as_slice(), 16, 256, true).unwrap();

        assert_eq!(decoded[0].hardlink_group, decoded[1].hardlink_group);
        assert!(decoded[0].hardlink_group.is_some());
        assert_eq!(decoded[1].len, decoded[0].len);
        assert_eq!(decoded[1].checksum, decoded[0].checksum);
    }

    #[test]
    fn writes_and_reads_protocol31_posix_metadata_payloads() {
        let entries = vec![
            RsyncFileListEntry {
                path: PathBuf::from("dir"),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata {
                    uid: Some(1000),
                    gid: Some(100),
                    user_name: Some("alice".to_string()),
                    group_name: Some("staff".to_string()),
                    atime_unix: None,
                    crtime_unix: Some(1_600_000_000),
                    xattrs: Vec::new(),
                },
            },
            RsyncFileListEntry {
                path: PathBuf::from("dir/file.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 1_700_000_001,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata {
                    uid: Some(1000),
                    gid: Some(100),
                    user_name: Some("alice".to_string()),
                    group_name: Some("staff".to_string()),
                    atime_unix: Some(1_700_000_011),
                    crtime_unix: Some(1_600_000_001),
                    xattrs: vec![RsyncXattrPayload {
                        name: "user.rsync-win".to_string(),
                        value: b"chunk7".to_vec(),
                    }],
                },
            },
        ];
        let options = RsyncFileListOptions {
            preserve_owner: true,
            preserve_group: true,
            acls: true,
            xattrs: true,
            atimes: true,
            crtimes: true,
            ..RsyncFileListOptions::default()
        };

        let mut bytes = Vec::new();
        write_rsync31_file_list_with_metadata(&mut bytes, &entries, options).unwrap();
        let decoded =
            read_rsync31_file_list_with_metadata(&mut bytes.as_slice(), 16, 256, options).unwrap();

        assert_eq!(decoded, entries);
    }

    #[test]
    fn fake_super_does_not_imply_protocol31_xattr_payloads() {
        let entry = RsyncFileListEntry {
            path: PathBuf::from("file.txt"),
            file_type: WireFileType::File,
            len: 5,
            mtime_unix: 1_700_000_000,
            mode: RSYNC_REGULAR_FILE_MODE,
            checksum: None,
            hardlink_group: None,
            metadata: RsyncFileListMetadata::default(),
        };
        let mut default_bytes = Vec::new();
        write_rsync31_file_list_with_metadata(
            &mut default_bytes,
            std::slice::from_ref(&entry),
            RsyncFileListOptions::default(),
        )
        .unwrap();

        let mut fake_super_bytes = Vec::new();
        write_rsync31_file_list_with_metadata(
            &mut fake_super_bytes,
            &[entry],
            RsyncFileListOptions {
                fake_super: true,
                ..RsyncFileListOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fake_super_bytes, default_bytes);
    }

    fn test_file(path: &str) -> RsyncFileListEntry {
        RsyncFileListEntry {
            path: PathBuf::from(path),
            file_type: WireFileType::File,
            len: 1,
            mtime_unix: 1_700_000_000,
            mode: RSYNC_REGULAR_FILE_MODE,
            checksum: None,
            hardlink_group: None,
            metadata: RsyncFileListMetadata::default(),
        }
    }
}
