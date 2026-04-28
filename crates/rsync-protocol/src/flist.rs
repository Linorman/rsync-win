//! File-list codecs used by early session scaffolding and remote-shell tests.
//!
//! The `internal` codec is not upstream rsync's flist wire format. The
//! `rsync27` helpers implement the limited protocol-27 file-list subset used by
//! the current ordinary-file remote-shell compatibility path. The `rsync31`
//! helpers cover the non-incremental-recursion ordinary-file subset of the
//! upstream protocol-31 flist format.

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
const XMIT31_USER_NAME_FOLLOWS: u32 = 1 << 10;
const XMIT31_GROUP_NAME_FOLLOWS: u32 = 1 << 11;
const XMIT31_MOD_NSEC: u32 = 1 << 13;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

pub const RSYNC_REGULAR_FILE_MODE: u32 = S_IFREG | 0o644;
pub const RSYNC_DIRECTORY_MODE: u32 = S_IFDIR | 0o755;
pub const RSYNC_SYMLINK_MODE: u32 = S_IFLNK | 0o777;
pub const DEFAULT_MAX_FILE_LIST_ENTRIES: usize = 100_000;
pub const DEFAULT_MAX_FILE_LIST_PATH_LEN: usize = 32 * 1024;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsyncFileListEntry {
    pub path: PathBuf,
    pub file_type: WireFileType,
    pub len: u64,
    pub mtime_unix: i64,
    pub mode: u32,
    pub checksum: Option<[u8; 16]>,
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
    #[error("file length {0} cannot be represented on the wire")]
    LengthTooLarge(u64),
    #[error("file path length {0} cannot be represented in protocol 27")]
    PathTooLong(usize),
    #[error("wire file mode {0:o} is not supported by this transfer subset")]
    UnsupportedMode(u32),
    #[error("missing checksum for regular file `{0}`")]
    MissingChecksum(PathBuf),
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
    let mut last_mode = None::<u32>;
    let mut last_mtime = None::<i64>;

    for entry in entries {
        let path = wire_path_bytes(&entry.path);
        let mut status = XMIT_LONG_NAME;

        if last_mode == Some(entry.mode) {
            status |= XMIT_SAME_MODE;
        }
        if last_mtime == Some(entry.mtime_unix) {
            status |= XMIT_SAME_TIME;
        }
        if entry.file_type == WireFileType::Directory && entry.path == Path::new(".") {
            status |= XMIT_TOP_DIR;
        }

        write_u8(writer, status)?;
        if status & XMIT_LONG_NAME != 0 {
            let len =
                i32::try_from(path.len()).map_err(|_| FileListError::PathTooLong(path.len()))?;
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
        if include_checksums && entry.file_type == WireFileType::File {
            writer.write_all(
                entry
                    .checksum
                    .as_ref()
                    .ok_or_else(|| FileListError::MissingChecksum(entry.path.clone()))?,
            )?;
        }

        last_mode = Some(entry.mode);
        last_mtime = Some(entry.mtime_unix);
    }

    write_u8(writer, 0)?;
    Ok(())
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
    let mut entries = Vec::new();
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
    let mut last_path = Vec::<u8>::new();
    let mut last_mode = None::<u32>;
    let mut last_mtime = None::<i64>;

    for entry in entries {
        let path = wire_path_bytes(&entry.path);
        let inherited = common_prefix_len(&last_path, &path);
        let suffix = &path[inherited..];
        let mut flags = XMIT31_SAME_UID | XMIT31_SAME_GID;

        if entry.file_type == WireFileType::Directory && entry.path == Path::new(".") {
            flags |= XMIT31_TOP_DIR;
        }
        if last_mode == Some(entry.mode) {
            flags |= XMIT31_SAME_MODE;
        }
        if last_mtime == Some(entry.mtime_unix) {
            flags |= XMIT31_SAME_TIME;
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
        if include_checksums && entry.file_type == WireFileType::File {
            writer.write_all(
                entry
                    .checksum
                    .as_ref()
                    .ok_or_else(|| FileListError::MissingChecksum(entry.path.clone()))?,
            )?;
        }

        last_path = path;
        last_mode = Some(entry.mode);
        last_mtime = Some(entry.mtime_unix);
    }

    write_varint(writer, 0)?;
    write_varint(writer, 0)?;
    Ok(())
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
    let mut entries = Vec::new();
    let mut last_path = Vec::<u8>::new();
    let mut last_mode = None::<u32>;
    let mut last_mtime = None::<i64>;

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

        if flags & XMIT31_SAME_UID == 0 {
            let _uid = read_varint(reader)?;
            if flags & XMIT31_USER_NAME_FOLLOWS != 0 {
                read_ignored_name(reader)?;
            }
        }
        if flags & XMIT31_SAME_GID == 0 {
            let _gid = read_varint(reader)?;
            if flags & XMIT31_GROUP_NAME_FOLLOWS != 0 {
                read_ignored_name(reader)?;
            }
        }
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
        });
        last_path = path_bytes;
        last_mtime = Some(mtime);
        last_mode = Some(mode);
    }

    Ok(entries)
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
    Ok(PathBuf::from(path))
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
            },
            RsyncFileListEntry {
                path: PathBuf::from("dir/file.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 1_700_000_001,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
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
            },
            RsyncFileListEntry {
                path: PathBuf::from("dir"),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
            },
            RsyncFileListEntry {
                path: PathBuf::from("dir/file.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
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
    fn protocol_file_list_marks_dot_as_content_top_directory() {
        let entries = vec![RsyncFileListEntry {
            path: PathBuf::from("."),
            file_type: WireFileType::Directory,
            len: 0,
            mtime_unix: 1_700_000_000,
            mode: RSYNC_DIRECTORY_MODE,
            checksum: None,
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
            },
            RsyncFileListEntry {
                path: PathBuf::from("file.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 1_700_000_000,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: Some(checksum),
            },
        ];

        let mut bytes = Vec::new();
        write_rsync31_file_list_with_options(&mut bytes, &entries, true).unwrap();

        assert_eq!(
            read_rsync31_file_list_with_options(&mut bytes.as_slice(), 16, 256, true).unwrap(),
            entries
        );
    }
}
