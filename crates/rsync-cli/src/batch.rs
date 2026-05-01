//! Rsync batch mode: --write-batch, --only-write-batch, --read-batch.
//!
//! Batch files record file-list metadata and file contents so a transfer can
//! be replayed later against the same (or a similar) destination tree.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use rsync_fs::walk::PortableFileSystem;

const BATCH_MAGIC: &[u8; 12] = b"RSYNC-BATCH1";
const BATCH_VERSION: u32 = 1;
const BATCH_HEADER_LEN: usize = 64;

/// Record written during --write-batch.
#[derive(Debug, Clone)]
pub struct BatchRecord {
    /// File-list entry kind.
    pub kind: BatchRecordKind,
    /// Relative path from destination root.
    pub relative: PathBuf,
    /// File length in bytes.
    pub len: u64,
    /// File modification time (None = omit).
    pub modified: Option<SystemTime>,
    /// Offset in the batch file data section where file content starts.
    pub data_offset: u64,
    /// Whole-file checksum for validating replay input.
    pub checksum: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchRecordKind {
    File,
    Directory,
}

impl BatchRecordKind {
    fn to_byte(self) -> u8 {
        match self {
            Self::File => 1,
            Self::Directory => 2,
        }
    }

    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::File),
            2 => Ok(Self::Directory),
            other => bail!("batch file corrupted: unknown record kind {other}"),
        }
    }
}

/// Batch metadata needed to understand how the file-list was produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchManifest {
    pub options: Vec<String>,
    pub filters: Vec<String>,
    pub token_stream: String,
}

/// Write a batch file header and return the writer + the header's data-section
/// start offset so records can be appended.
pub struct BatchWriter {
    writer: BufWriter<File>,
    records: Vec<BatchRecord>,
    dry_run: bool,
}

impl BatchWriter {
    pub fn create(path: &Path, dry_run: bool) -> Result<Self> {
        Self::create_with_manifest(path, dry_run, BatchManifest::default())
    }

    pub fn create_with_manifest(
        path: &Path,
        dry_run: bool,
        manifest: BatchManifest,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut writer = BufWriter::new(File::create(path)?);
        writer.write_all(BATCH_MAGIC)?;
        writer.write_all(&BATCH_VERSION.to_le_bytes())?;
        let dry_run_byte: u8 = if dry_run { 1 } else { 0 };
        writer.write_all(&[dry_run_byte])?;
        // Header padding to 64 bytes for future extensibility.
        let header_pad = [0u8; BATCH_HEADER_LEN - 12 - 4 - 1];
        writer.write_all(&header_pad)?;
        write_manifest_block(&mut writer, &manifest)?;
        writer.flush()?;
        Ok(Self {
            writer,
            records: Vec::new(),
            dry_run,
        })
    }

    pub fn append_file(
        &mut self,
        fs: &mut impl PortableFileSystem,
        relative: &Path,
        source: &Path,
        _dest_root: &Path,
        len: u64,
        modified: Option<SystemTime>,
    ) -> Result<BatchRecord> {
        let pos = self.writer.stream_position()?;
        let source_bytes = fs
            .read_file(source)
            .map_err(|e| anyhow::anyhow!("batch read error for {}: {e}", source.display()))?;
        let actual_len = u64::try_from(source_bytes.len())
            .map_err(|_| anyhow::anyhow!("batch record is too large"))?;
        if actual_len != len {
            bail!(
                "batch length mismatch for {}: metadata says {len}, read {actual_len}",
                source.display()
            );
        }
        let checksum = rsync_protocol::rsync_plain_md4_checksum(&source_bytes);
        let record = BatchRecord {
            kind: BatchRecordKind::File,
            relative: relative.to_path_buf(),
            len,
            modified,
            data_offset: pos,
            checksum,
        };

        if !self.dry_run {
            // Copy file content from source into the batch data stream.
            self.writer.write_all(&source_bytes)?;
        }

        self.records.push(record.clone());
        Ok(record)
    }

    pub fn append_directory(
        &mut self,
        relative: &Path,
        modified: Option<SystemTime>,
    ) -> Result<BatchRecord> {
        let record = BatchRecord {
            kind: BatchRecordKind::Directory,
            relative: relative.to_path_buf(),
            len: 0,
            modified,
            data_offset: self.writer.stream_position()?,
            checksum: [0u8; 16],
        };
        self.records.push(record.clone());
        Ok(record)
    }

    pub fn finish(mut self) -> Result<Vec<BatchRecord>> {
        // Write the index at the end of the file.
        let index_offset = self.writer.stream_position()?;
        self.writer.write_all(b"IDX1")?;
        let record_count = u32::try_from(self.records.len())
            .map_err(|_| anyhow::anyhow!("too many batch records"))?;
        self.writer.write_all(&record_count.to_le_bytes())?;

        for record in &self.records {
            let rel = record.relative.to_string_lossy();
            let rel_bytes = rel.as_bytes();
            let rel_len = u16::try_from(rel_bytes.len()).map_err(|_| {
                anyhow::anyhow!("batch path too long: {}", record.relative.display())
            })?;
            self.writer.write_all(&rel_len.to_le_bytes())?;
            self.writer.write_all(rel_bytes)?;
            self.writer.write_all(&[record.kind.to_byte()])?;
            self.writer.write_all(&record.len.to_le_bytes())?;
            self.writer.write_all(&record.data_offset.to_le_bytes())?;
            let mtime_secs = record
                .modified
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            self.writer.write_all(&mtime_secs.to_le_bytes())?;
            self.writer.write_all(&record.checksum)?;
        }

        // Index trailer
        self.writer.write_all(&index_offset.to_le_bytes())?;
        self.writer.write_all(b"END1")?;
        self.writer.flush()?;
        Ok(self.records)
    }
}

/// Read a batch file and replay its transfers.
pub struct BatchReader {
    records: BTreeMap<PathBuf, BatchRecord>,
    file: BufReader<File>,
    dry_run: bool,
    manifest: BatchManifest,
}

impl BatchReader {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = BufReader::new(File::open(path)?);

        // Read magic
        let mut magic = [0u8; 12];
        file.read_exact(&mut magic)?;
        if &magic != BATCH_MAGIC {
            bail!("not a valid rsync batch file (bad magic)");
        }

        // Read version
        let mut version_bytes = [0u8; 4];
        file.read_exact(&mut version_bytes)?;
        let version = u32::from_le_bytes(version_bytes);
        if version != BATCH_VERSION {
            bail!("batch file version {version} is not supported (expected {BATCH_VERSION})");
        }

        // Dry run flag
        let mut dry_run_byte = [0u8; 1];
        file.read_exact(&mut dry_run_byte)?;
        let dry_run = dry_run_byte[0] != 0;

        // Skip padding
        let mut pad = [0u8; BATCH_HEADER_LEN - 12 - 4 - 1];
        file.read_exact(&mut pad)?;
        let manifest = read_manifest_block(&mut file)?;

        // Read index at end
        let file_len = file.get_ref().metadata()?.len();
        if file_len < 12 {
            bail!("batch file too short");
        }
        let mut trailer_buf = [0u8; 4];
        file.seek(SeekFrom::End(-4))?;
        file.read_exact(&mut trailer_buf)?;
        if &trailer_buf != b"END1" {
            bail!("batch file corrupted: missing END1 trailer");
        }

        // Read index offset
        let mut index_offset_bytes = [0u8; 8];
        file.seek(SeekFrom::End(-12))?;
        file.read_exact(&mut index_offset_bytes)?;
        let index_offset = u64::from_le_bytes(index_offset_bytes);

        // Seek to index
        file.seek(SeekFrom::Start(index_offset))?;

        // Read I D X 1 marker
        let mut idx_marker = [0u8; 4];
        file.read_exact(&mut idx_marker)?;
        if &idx_marker != b"IDX1" {
            bail!("batch file corrupted: missing IDX1 marker");
        }

        let mut count_bytes = [0u8; 4];
        file.read_exact(&mut count_bytes)?;
        let count = u32::from_le_bytes(count_bytes);

        let mut records = BTreeMap::new();
        for _ in 0..count {
            let mut rel_len_bytes = [0u8; 2];
            file.read_exact(&mut rel_len_bytes)?;
            let rel_len = u16::from_le_bytes(rel_len_bytes) as usize;

            let mut rel_bytes = vec![0u8; rel_len];
            file.read_exact(&mut rel_bytes)?;
            let relative_str =
                String::from_utf8(rel_bytes).context("invalid UTF-8 in batch file record path")?;

            let mut kind_byte = [0u8; 1];
            file.read_exact(&mut kind_byte)?;
            let kind = BatchRecordKind::from_byte(kind_byte[0])?;

            let mut len_bytes = [0u8; 8];
            file.read_exact(&mut len_bytes)?;
            let len = u64::from_le_bytes(len_bytes);

            let mut offset_bytes = [0u8; 8];
            file.read_exact(&mut offset_bytes)?;
            let data_offset = u64::from_le_bytes(offset_bytes);

            let mut mtime_bytes = [0u8; 8];
            file.read_exact(&mut mtime_bytes)?;
            let mtime_secs = u64::from_le_bytes(mtime_bytes);
            let modified = (mtime_secs > 0)
                .then(|| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(mtime_secs));

            let mut checksum = [0u8; 16];
            file.read_exact(&mut checksum)?;

            records.insert(
                PathBuf::from(relative_str),
                BatchRecord {
                    kind,
                    relative: PathBuf::new(),
                    len,
                    modified,
                    data_offset,
                    checksum,
                },
            );
        }

        // Fix up relative paths
        let mut fixed_records = BTreeMap::new();
        for (path, mut record) in records {
            record.relative = path.clone();
            fixed_records.insert(path, record);
        }

        Ok(Self {
            records: fixed_records,
            file,
            dry_run,
            manifest,
        })
    }

    pub fn records(&self) -> Vec<&BatchRecord> {
        self.records.values().collect()
    }

    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    pub fn manifest(&self) -> &BatchManifest {
        &self.manifest
    }

    pub fn file_data(&mut self, record: &BatchRecord) -> Result<Vec<u8>> {
        if record.kind != BatchRecordKind::File {
            bail!(
                "batch record does not contain file data: {}",
                record.relative.display()
            );
        }
        let len = usize::try_from(record.len)
            .map_err(|_| anyhow::anyhow!("batch record too large for this platform"))?;
        let mut buf = vec![0u8; len];
        self.file.seek(SeekFrom::Start(record.data_offset))?;
        self.file.read_exact(&mut buf)?;
        let actual = rsync_protocol::rsync_plain_md4_checksum(&buf);
        if actual != record.checksum {
            bail!(
                "batch file corrupted: checksum mismatch for {}",
                record.relative.display()
            );
        }
        Ok(buf)
    }
}

/// Replay a batch file onto the local filesystem.
pub fn replay_batch(batch_file: &Path, dest: &Path, dry_run_override: Option<bool>) -> Result<()> {
    let mut reader = BatchReader::open(batch_file)?;
    let dry_run = dry_run_override.unwrap_or(reader.dry_run());
    let mut fs = rsync_fs::walk::LocalFileSystem;

    let records: Vec<BatchRecord> = reader.records().iter().map(|r| (*r).clone()).collect();

    for record in &records {
        let target = safe_batch_target(
            dest,
            &record.relative,
            record.kind == BatchRecordKind::Directory,
        )?;

        if dry_run {
            match record.kind {
                BatchRecordKind::File => eprintln!(
                    "batch replay (dry-run): would write {} ({} bytes)",
                    target.display(),
                    record.len
                ),
                BatchRecordKind::Directory => eprintln!(
                    "batch replay (dry-run): would create directory {}",
                    target.display()
                ),
            }
            continue;
        }

        match record.kind {
            BatchRecordKind::File => {
                let file_data = reader.file_data(record)?;
                fs.write_file_direct(&target, &file_data).map_err(|e| {
                    anyhow::anyhow!("batch replay failed for {}: {e}", target.display())
                })?;
            }
            BatchRecordKind::Directory => {
                fs.create_dir_all(&target).map_err(|e| {
                    anyhow::anyhow!("batch replay failed for {}: {e}", target.display())
                })?;
            }
        }

        if let Some(mtime) = record.modified {
            fs.set_mtime(&target, mtime).ok();
        }
    }

    Ok(())
}

fn safe_batch_target(dest: &Path, relative: &Path, allow_root: bool) -> Result<PathBuf> {
    let mut safe = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => safe.push(name),
            Component::CurDir => {}
            _ => bail!("unsafe batch path: {}", relative.display()),
        }
    }
    if safe.as_os_str().is_empty() {
        if allow_root {
            return Ok(dest.to_path_buf());
        }
        bail!("unsafe batch path: {}", relative.display());
    }
    Ok(dest.join(safe))
}

fn write_manifest_block(writer: &mut BufWriter<File>, manifest: &BatchManifest) -> Result<()> {
    let text = render_manifest(manifest);
    let bytes = text.as_bytes();
    let len = u32::try_from(bytes.len()).context("batch manifest is too large")?;
    writer.write_all(b"MAN1")?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(bytes)?;
    Ok(())
}

fn read_manifest_block(file: &mut BufReader<File>) -> Result<BatchManifest> {
    let mut marker = [0u8; 4];
    file.read_exact(&mut marker)?;
    if &marker != b"MAN1" {
        bail!("batch file corrupted: missing MAN1 manifest marker");
    }
    let mut len_bytes = [0u8; 4];
    file.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes)?;
    let text = String::from_utf8(bytes).context("invalid UTF-8 in batch manifest")?;
    parse_manifest(&text)
}

fn render_manifest(manifest: &BatchManifest) -> String {
    let mut text = String::new();
    text.push_str("token_stream=");
    text.push_str(&escape_manifest_value(
        if manifest.token_stream.is_empty() {
            "literal-file-contents"
        } else {
            &manifest.token_stream
        },
    ));
    text.push('\n');
    for option in &manifest.options {
        text.push_str("option=");
        text.push_str(&escape_manifest_value(option));
        text.push('\n');
    }
    for filter in &manifest.filters {
        text.push_str("filter=");
        text.push_str(&escape_manifest_value(filter));
        text.push('\n');
    }
    text
}

fn parse_manifest(text: &str) -> Result<BatchManifest> {
    let mut manifest = BatchManifest::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = unescape_manifest_value(value)?;
        match key {
            "token_stream" => manifest.token_stream = value,
            "option" => manifest.options.push(value),
            "filter" => manifest.filters.push(value),
            _ => {}
        }
    }
    Ok(manifest)
}

fn escape_manifest_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn unescape_manifest_value(value: &str) -> Result<String> {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let Some(escaped) = chars.next() else {
            bail!("invalid escape in batch manifest");
        };
        match escaped {
            '\\' => out.push('\\'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsync_fs::walk::MemoryFileSystem;

    #[test]
    fn write_and_read_batch_roundtrip() {
        let dir = std::env::temp_dir().join("rsync-batch-test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let batch_path = dir.join("test.batch");

        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/a.txt", b"hello a").unwrap();
        fs.add_file("src/b.txt", b"hello b").unwrap();

        {
            let mut writer = BatchWriter::create(&batch_path, false).unwrap();
            writer
                .append_file(
                    &mut fs,
                    Path::new("a.txt"),
                    Path::new("src/a.txt"),
                    Path::new("dst"),
                    7,
                    None,
                )
                .unwrap();
            writer
                .append_file(
                    &mut fs,
                    Path::new("b.txt"),
                    Path::new("src/b.txt"),
                    Path::new("dst"),
                    7,
                    None,
                )
                .unwrap();
            writer.finish().unwrap();
        }

        let mut reader = BatchReader::open(&batch_path).unwrap();
        let records: Vec<BatchRecord> = reader.records().iter().map(|r| (*r).clone()).collect();
        assert_eq!(records.len(), 2);

        let data_a = reader.file_data(&records[0]).unwrap();
        assert_eq!(data_a, b"hello a");

        let data_b = reader.file_data(&records[1]).unwrap();
        assert_eq!(data_b, b"hello b");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_batch_rejects_bad_magic() {
        let dir = std::env::temp_dir().join("rsync-batch-bad");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let bad_path = dir.join("bad.batch");
        fs::write(&bad_path, b"not a batch file").unwrap();
        assert!(BatchReader::open(&bad_path).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn replay_rejects_parent_escape_record() {
        let dir = std::env::temp_dir().join(format!("rsync-batch-escape-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let batch_path = dir.join("escape.batch");
        let dest = dir.join("dest");
        fs::create_dir_all(&dest).unwrap();

        let mut mem = MemoryFileSystem::new();
        mem.add_file("src/payload.txt", b"escape").unwrap();
        {
            let mut writer = BatchWriter::create(&batch_path, false).unwrap();
            writer
                .append_file(
                    &mut mem,
                    Path::new("../escape.txt"),
                    Path::new("src/payload.txt"),
                    Path::new("dst"),
                    6,
                    None,
                )
                .unwrap();
            writer.finish().unwrap();
        }

        let err = replay_batch(&batch_path, &dest, None).unwrap_err();
        assert!(
            err.to_string().contains("unsafe batch path"),
            "unexpected error: {err:#}"
        );
        assert!(!dir.join("escape.txt").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
