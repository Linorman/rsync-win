use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use digest::Digest;
#[cfg(test)]
use rsync_delta::DeltaToken;
use rsync_delta::{rolling_checksum, BlockSignature, StrongChecksum};
use rsync_protocol::{
    read_i32_le, read_multiplexed_i32, read_u8, read_vstring, write_i32_le, write_rsync_i32,
    write_vstring, MultiplexReadState, MultiplexedReader, RemoteSessionError, RsyncDeflatedToken,
    RsyncDeflatedTokenMode, RsyncDeflatedTokenReader, RsyncDeflatedTokenWriter, RsyncMd4Checksum,
};
use rsync_winfs::to_long_path_safe;

use crate::format::{format_bytes, transfer_rate_label};
use crate::plan::{check_transfer_deadline, TransferPlan};
use crate::ProgressLog;
#[derive(Debug, Default, Clone)]
pub(crate) struct RemoteExecutionStats {
    pub(crate) files: usize,
    pub(crate) bytes: u64,
    pub(crate) transferred_entry_indexes: Vec<usize>,
}

#[derive(Debug)]
pub(crate) struct FileProgress {
    progress: ProgressLog,
    operation: &'static str,
    path: String,
    total: Option<u64>,
    started: Instant,
    last_report: Instant,
    transferred: u64,
}

impl FileProgress {
    pub(crate) fn start(
        progress: ProgressLog,
        operation: &'static str,
        path: &Path,
        total: Option<u64>,
    ) -> Self {
        let now = Instant::now();
        let meter = Self {
            progress,
            operation,
            path: path.display().to_string(),
            total,
            started: now,
            last_report: now,
            transferred: 0,
        };
        if progress.enabled() {
            match total {
                Some(total) => progress.info(format!(
                    "{}: {} ({})",
                    operation,
                    meter.path,
                    format_bytes(total)
                )),
                None => progress.info(format!("{}: {}", operation, meter.path)),
            }
        }
        meter
    }

    pub(crate) fn advance(&mut self, bytes: u64) {
        self.transferred += bytes;
        if !self.progress.enabled() || self.last_report.elapsed() < Duration::from_secs(2) {
            return;
        }

        self.report_progress();
        self.last_report = Instant::now();
    }

    pub(crate) fn finish(&mut self) {
        if self.progress.enabled() {
            self.report_finished();
        }
    }

    pub(crate) fn report_progress(&self) {
        let elapsed = self.started.elapsed();
        let rate = transfer_rate_label(self.transferred, elapsed);
        match self.total {
            Some(total) if total > 0 => {
                let percent = (self.transferred as f64 / total as f64 * 100.0).min(100.0);
                self.progress.info(format!(
                    "{}: {} {} / {} ({:.1}%, {})",
                    self.operation,
                    self.path,
                    format_bytes(self.transferred),
                    format_bytes(total),
                    percent,
                    rate
                ));
            }
            Some(_) | None => self.progress.info(format!(
                "{}: {} {} ({})",
                self.operation,
                self.path,
                format_bytes(self.transferred),
                rate
            )),
        }
    }

    pub(crate) fn report_finished(&self) {
        let elapsed = self.started.elapsed();
        let rate = transfer_rate_label(self.transferred, elapsed);
        match self.total {
            Some(total) if total > 0 => {
                let percent = (self.transferred as f64 / total as f64 * 100.0).min(100.0);
                self.progress.info(format!(
                    "{} done: {} {} / {} ({:.1}%, {}, {:.2}s)",
                    self.operation,
                    self.path,
                    format_bytes(self.transferred),
                    format_bytes(total),
                    percent,
                    rate,
                    elapsed.as_secs_f64()
                ));
            }
            Some(_) | None => self.progress.info(format!(
                "{} done: {} {} ({}, {:.2}s)",
                self.operation,
                self.path,
                format_bytes(self.transferred),
                rate,
                elapsed.as_secs_f64()
            )),
        }
    }
}

pub(crate) const RSYNC31_MUX_FRAME_SIZE: usize = 32 * 1024;
pub(crate) const REMOTE_FILE_LIST_BATCH_ENTRIES: usize = 4096;
pub(crate) const RSYNC_ITEM_BASIS_TYPE_FOLLOWS: u16 = 1 << 11;
pub(crate) const RSYNC_ITEM_XNAME_FOLLOWS: u16 = 1 << 12;
pub(crate) const RSYNC_ITEM_IS_NEW: u16 = 1 << 13;
pub(crate) const RSYNC_ITEM_LOCAL_CHANGE: u16 = 1 << 14;
pub(crate) const RSYNC_ITEM_TRANSFER: u16 = 1 << 15;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RemoteSumHead {
    pub(crate) block_count: usize,
    pub(crate) block_len: usize,
    pub(crate) checksum_len: usize,
    pub(crate) remainder: usize,
}

#[derive(Debug, Default)]
pub(crate) struct Rsync31ItemAttrs {
    basis_type: Option<u8>,
    xname: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteChecksumAlgorithm {
    Md4,
    Md5,
}

impl RemoteChecksumAlgorithm {
    pub(crate) fn from_protocol31_choice(choice: Option<&str>) -> Result<Self> {
        match choice.map(normalize_checksum_choice).as_deref() {
            None | Some("md4") => Ok(Self::Md4),
            Some("md5") => Ok(Self::Md5),
            Some(other) => bail!("unsupported negotiated checksum algorithm `{other}`"),
        }
    }
}

pub(crate) fn normalize_checksum_choice(choice: &str) -> String {
    choice.trim().to_ascii_lowercase()
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum RemoteFileChecksum {
    SeededMd4(i32),
    PlainMd4,
    SeededMd5(i32),
    PlainMd5,
}

impl RemoteFileChecksum {
    pub(crate) fn md4_with_seed(seed: i32) -> Self {
        if seed == 0 {
            Self::PlainMd4
        } else {
            Self::SeededMd4(seed)
        }
    }

    pub(crate) fn protocol31(choice: Option<&str>, seed: i32) -> Result<Self> {
        Ok(
            match RemoteChecksumAlgorithm::from_protocol31_choice(choice)? {
                RemoteChecksumAlgorithm::Md4 => Self::md4_with_seed(seed),
                RemoteChecksumAlgorithm::Md5 if seed == 0 => Self::PlainMd5,
                RemoteChecksumAlgorithm::Md5 => Self::SeededMd5(seed),
            },
        )
    }

    pub(crate) fn algorithm(self) -> RemoteChecksumAlgorithm {
        match self {
            Self::SeededMd4(_) | Self::PlainMd4 => RemoteChecksumAlgorithm::Md4,
            Self::SeededMd5(_) | Self::PlainMd5 => RemoteChecksumAlgorithm::Md5,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum RemoteFinalChecksum {
    PlainMd4,
    SeededMd4Prefix(i32),
    PlainMd5,
}

impl RemoteFinalChecksum {
    pub(crate) fn protocol27(seed: i32) -> Self {
        if seed == 0 {
            Self::PlainMd4
        } else {
            Self::SeededMd4Prefix(seed)
        }
    }

    pub(crate) fn protocol31(choice: Option<&str>) -> Result<Self> {
        Ok(Self::protocol31_for_algorithm(
            RemoteChecksumAlgorithm::from_protocol31_choice(choice)?,
        ))
    }

    pub(crate) fn protocol31_for_algorithm(algorithm: RemoteChecksumAlgorithm) -> Self {
        match algorithm {
            RemoteChecksumAlgorithm::Md4 => Self::PlainMd4,
            RemoteChecksumAlgorithm::Md5 => Self::PlainMd5,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoteDeltaStats {
    pub(crate) literal_bytes: u64,
    pub(crate) copied_bytes: u64,
}

pub(crate) struct RemoteTransferRuntime<'a> {
    pub(crate) compression: Option<&'a RemoteCompressionConfig>,
    pub(crate) progress: ProgressLog,
    pub(crate) max_alloc: Option<u64>,
    pub(crate) stop_deadline: Option<Instant>,
}

pub(crate) struct DeltaWriteRuntime<'a> {
    pub(crate) compression: Option<&'a RemoteCompressionConfig>,
    pub(crate) progress: Option<&'a mut FileProgress>,
    pub(crate) max_alloc: Option<u64>,
    pub(crate) stop_deadline: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RemoteDeltaChecksums {
    pub(crate) block: RemoteFileChecksum,
    pub(crate) final_file: RemoteFinalChecksum,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TransferLimits {
    pub(crate) max_alloc: Option<u64>,
    pub(crate) stop_deadline: Option<Instant>,
}

#[derive(Debug, Clone)]
pub(crate) struct RemoteCompressionConfig {
    pub(crate) mode: RsyncDeflatedTokenMode,
    pub(crate) level: u32,
    pub(crate) skip_suffixes: Vec<String>,
}

impl RemoteCompressionConfig {
    pub(crate) fn for_plan(plan: &TransferPlan) -> Result<Option<Self>> {
        if !plan.compress {
            return Ok(None);
        }
        let mode =
            RsyncDeflatedTokenMode::from_choice(plan.compress_choice.as_deref()).map_err(|_| {
                anyhow::anyhow!(
                    "unsupported compression choice; rsync-win currently supports zlibx and zlib"
                )
            })?;
        Ok(Some(Self {
            mode,
            level: plan.compress_level.unwrap_or(6).min(9),
            skip_suffixes: plan.skip_compress.clone(),
        }))
    }

    pub(crate) fn remote_choice(&self) -> &'static str {
        self.mode.remote_choice()
    }

    pub(crate) fn level_for_path(&self, path: &Path) -> u32 {
        if self.should_skip_path(path) {
            0
        } else {
            self.level
        }
    }

    pub(crate) fn should_skip_path(&self, path: &Path) -> bool {
        let path = path.to_string_lossy().to_ascii_lowercase();
        self.skip_suffixes
            .iter()
            .map(|suffix| {
                suffix
                    .trim()
                    .trim_start_matches("*.")
                    .trim_start_matches('.')
            })
            .filter(|suffix| !suffix.is_empty())
            .any(|suffix| path.ends_with(&format!(".{}", suffix.to_ascii_lowercase())))
    }
}

pub(crate) fn read_rsync31_optional_item_attrs<R: Read>(
    reader: &mut R,
    iflags: u16,
) -> Result<Rsync31ItemAttrs> {
    let basis_type = if iflags & RSYNC_ITEM_BASIS_TYPE_FOLLOWS != 0 {
        Some(read_u8(reader)?)
    } else {
        None
    };
    let xname = if iflags & RSYNC_ITEM_XNAME_FOLLOWS != 0 {
        Some(read_vstring(reader, 32 * 1024)?)
    } else {
        None
    };
    Ok(Rsync31ItemAttrs { basis_type, xname })
}

pub(crate) fn write_rsync31_optional_item_attrs<W: Write>(
    writer: &mut W,
    iflags: u16,
    attrs: &Rsync31ItemAttrs,
) -> Result<()> {
    if iflags & RSYNC_ITEM_BASIS_TYPE_FOLLOWS != 0 {
        let basis_type = attrs
            .basis_type
            .context("protocol 31 item flags omitted basis type attribute")?;
        writer.write_all(&[basis_type])?;
    }
    if iflags & RSYNC_ITEM_XNAME_FOLLOWS != 0 {
        let xname = attrs
            .xname
            .as_deref()
            .context("protocol 31 item flags omitted xname attribute")?;
        write_vstring(writer, xname)?;
    }
    Ok(())
}

pub(crate) fn read_sum_head<R: Read>(reader: &mut R) -> Result<RemoteSumHead> {
    Ok(RemoteSumHead {
        block_count: read_nonnegative_i32(reader, "block count")?,
        block_len: read_nonnegative_i32(reader, "block length")?,
        checksum_len: read_nonnegative_i32(reader, "checksum length")?,
        remainder: read_nonnegative_i32(reader, "remainder length")?,
    })
}

pub(crate) fn read_nonnegative_i32<R: Read>(reader: &mut R, label: &str) -> Result<usize> {
    let value = read_i32_le(reader)?;
    if value < 0 {
        bail!("remote sent negative {label}: {value}");
    }
    Ok(value as usize)
}

pub(crate) fn write_sum_head<W: Write>(writer: &mut W, sum_head: RemoteSumHead) -> Result<()> {
    write_i32_le(writer, sum_head.block_count as i32)?;
    write_i32_le(writer, sum_head.block_len as i32)?;
    write_i32_le(writer, sum_head.checksum_len as i32)?;
    write_i32_le(writer, sum_head.remainder as i32)?;
    Ok(())
}

pub(crate) fn remote_sum_head_file_len(sum_head: RemoteSumHead) -> Result<usize> {
    if sum_head.block_count == 0 {
        return Ok(0);
    }
    if sum_head.block_len == 0 {
        bail!("append basis sum head has zero block length");
    }
    if sum_head.remainder > sum_head.block_len {
        bail!("append basis sum head has a remainder larger than its block length");
    }

    let full_len = sum_head
        .block_count
        .checked_mul(sum_head.block_len)
        .context("append basis length overflow")?;
    if sum_head.remainder == 0 {
        Ok(full_len)
    } else {
        full_len
            .checked_sub(sum_head.block_len - sum_head.remainder)
            .context("append basis length underflow")
    }
}

pub(crate) fn read_remote_block_signatures_multiplexed<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    sum_head: RemoteSumHead,
    checksum: RemoteFileChecksum,
    max_alloc: Option<u64>,
) -> Result<Vec<BlockSignature>> {
    let mut reader = MultiplexedReader::new(transport, mux);
    read_remote_block_signatures_from_reader(&mut reader, sum_head, checksum, max_alloc)
}

pub(crate) fn read_remote_block_signatures_from_reader<R: Read>(
    reader: &mut R,
    sum_head: RemoteSumHead,
    checksum: RemoteFileChecksum,
    max_alloc: Option<u64>,
) -> Result<Vec<BlockSignature>> {
    validate_sum_head(sum_head)?;
    ensure_signature_table_budget(
        "remote signature table",
        sum_head.block_count,
        sum_head.checksum_len,
        max_alloc,
    )?;
    let mut signatures = Vec::with_capacity(sum_head.block_count);
    for index in 0..sum_head.block_count {
        let weak = read_i32_le(reader)? as u32;
        let mut strong = vec![0_u8; sum_head.checksum_len];
        reader.read_exact(&mut strong)?;
        let (offset, len) = block_span(&sum_head, index)?;
        signatures.push(BlockSignature {
            index,
            offset,
            len,
            weak,
            strong: normalize_remote_strong_checksum(strong, checksum, sum_head.checksum_len),
        });
    }
    Ok(signatures)
}

pub(crate) fn normalize_remote_strong_checksum(
    strong: Vec<u8>,
    _checksum: RemoteFileChecksum,
    _checksum_len: usize,
) -> Vec<u8> {
    strong
}

pub(crate) fn write_remote_block_signatures<W: Write>(
    writer: &mut W,
    signatures: &[BlockSignature],
) -> Result<()> {
    for signature in signatures {
        write_i32_le(writer, signature.weak as i32)?;
        writer.write_all(&signature.strong)?;
    }
    Ok(())
}

pub(crate) fn local_basis_signature_request(
    path: &Path,
    block_size: usize,
    checksum: RemoteFileChecksum,
    whole_file: bool,
    max_alloc: Option<u64>,
) -> Result<(RemoteSumHead, Vec<BlockSignature>)> {
    let empty = RemoteSumHead {
        block_count: 0,
        block_len: block_size,
        checksum_len: 16,
        remainder: 0,
    };
    if whole_file {
        return Ok((empty, Vec::new()));
    }
    let Ok(metadata) = fs::metadata(to_long_path_safe(path)) else {
        return Ok((empty, Vec::new()));
    };
    if !metadata.is_file() {
        return Ok((empty, Vec::new()));
    }

    let checksum_len = 16;
    let strong = RsyncStrongChecksum {
        checksum,
        checksum_len,
    };
    let file_len =
        usize::try_from(metadata.len()).context("basis file length did not fit usize")?;
    let block_count = file_len
        .checked_add(block_size - 1)
        .context("basis signature block count overflow")?
        / block_size;
    ensure_signature_table_budget(
        "basis signature table",
        block_count,
        checksum_len,
        max_alloc,
    )?;
    ensure_allocation_within_limit("basis checksum block", block_size, max_alloc)?;
    let signatures = generate_signatures_from_path(path, block_size, &strong)?;
    if signatures.is_empty() {
        return Ok((empty, Vec::new()));
    }
    let sum_head = RemoteSumHead {
        block_count: signatures.len(),
        block_len: block_size,
        checksum_len,
        remainder: file_len % block_size,
    };
    Ok((sum_head, signatures))
}

pub(crate) fn generate_signatures_from_path<S: StrongChecksum>(
    path: &Path,
    block_size: usize,
    strong_checksum: &S,
) -> Result<Vec<BlockSignature>> {
    if block_size == 0 {
        bail!("remote delta block size must be greater than zero");
    }

    let mut file = open_local_file(path)?;
    let mut block = vec![0_u8; block_size];
    let mut signatures = Vec::new();
    let mut offset = 0_usize;
    loop {
        let mut read = 0_usize;
        while read < block_size {
            let chunk_read = file
                .read(&mut block[read..])
                .with_context(|| format!("failed to read basis block from {}", path.display()))?;
            if chunk_read == 0 {
                break;
            }
            read = read
                .checked_add(chunk_read)
                .context("basis signature block length overflow")?;
        }
        if read == 0 {
            break;
        }
        signatures.push(BlockSignature {
            index: signatures.len(),
            offset,
            len: read,
            weak: rolling_checksum(&block[..read]),
            strong: strong_checksum.digest(&block[..read]),
        });
        offset = offset
            .checked_add(read)
            .context("basis signature offset overflow")?;
        if read < block_size {
            break;
        }
    }
    Ok(signatures)
}

pub(crate) fn remote_delta_block_size(plan: &TransferPlan) -> Result<usize> {
    let block_size = plan.block_size.unwrap_or(32 * 1024);
    usize::try_from(block_size)
        .ok()
        .filter(|value| *value > 0)
        .context("remote delta block size must fit usize and be greater than zero")
}

pub(crate) fn write_delta_tokens_from_path<T: Write>(
    transport: &mut T,
    block_checksum: RemoteFileChecksum,
    final_checksum: RemoteFinalChecksum,
    path: &Path,
    signatures: &[BlockSignature],
    runtime: DeltaWriteRuntime<'_>,
) -> Result<RemoteDeltaStats> {
    check_transfer_deadline(runtime.stop_deadline)?;
    let mut file = open_local_file(path)?;
    let compression_level = runtime
        .compression
        .map(|compression| compression.level_for_path(path));
    if signatures.is_empty() {
        let literal_bytes = write_literal_tokens_from_reader_with_checksum(
            transport,
            &mut file,
            final_checksum,
            compression_level,
            runtime.progress,
            runtime.stop_deadline,
        )?;
        return Ok(RemoteDeltaStats {
            literal_bytes,
            copied_bytes: 0,
        });
    }

    write_delta_tokens_from_reader_with_checksum(
        transport,
        &mut file,
        RemoteDeltaChecksums {
            block: block_checksum,
            final_file: final_checksum,
        },
        signatures,
        compression_level,
        runtime.progress,
        TransferLimits {
            max_alloc: runtime.max_alloc,
            stop_deadline: runtime.stop_deadline,
        },
    )
}

pub(crate) fn write_delta_tokens_from_reader_with_checksum<T: Write, R: Read>(
    transport: &mut T,
    reader: &mut R,
    checksums: RemoteDeltaChecksums,
    signatures: &[BlockSignature],
    compression_level: Option<u32>,
    mut progress: Option<&mut FileProgress>,
    limits: TransferLimits,
) -> Result<RemoteDeltaStats> {
    let index = RemoteSignatureIndex::new(signatures)?;
    ensure_allocation_within_limit("delta match window", index.max_len, limits.max_alloc)?;
    ensure_allocation_within_limit("delta literal buffer", 32 * 1024, limits.max_alloc)?;

    let checksum_len = signatures
        .first()
        .map(|signature| signature.strong.len())
        .unwrap_or(16);
    let strong = RsyncStrongChecksum {
        checksum: checksums.block,
        checksum_len,
    };
    let mut final_checksum = remote_final_checksum_builder(checksums.final_file);
    let mut compressor = compression_level.map(RsyncDeflatedTokenWriter::new);
    let mut stats = RemoteDeltaStats::default();
    let mut window = Vec::with_capacity(index.max_len);
    let mut literal = Vec::with_capacity(32 * 1024);
    let mut eof = false;

    fill_delta_window(
        reader,
        &mut window,
        index.max_len,
        &mut final_checksum,
        &mut eof,
        limits.stop_deadline,
    )?;

    while !window.is_empty() {
        check_transfer_deadline(limits.stop_deadline)?;
        if let Some(signature) = index.find_match(&window, &strong) {
            write_pending_literal_token(
                transport,
                compressor.as_mut(),
                &mut literal,
                &mut stats,
                progress.as_deref_mut(),
            )?;
            write_copy_token(transport, compressor.as_mut(), signature.index)?;
            stats.copied_bytes += signature.len as u64;
            if let Some(progress) = progress.as_deref_mut() {
                progress.advance(signature.len as u64);
            }
            window.drain(..signature.len);
        } else {
            literal.push(window.remove(0));
            if literal.len() >= 32 * 1024 {
                write_pending_literal_token(
                    transport,
                    compressor.as_mut(),
                    &mut literal,
                    &mut stats,
                    progress.as_deref_mut(),
                )?;
            }
        }
        fill_delta_window(
            reader,
            &mut window,
            index.max_len,
            &mut final_checksum,
            &mut eof,
            limits.stop_deadline,
        )?;
    }

    write_pending_literal_token(
        transport,
        compressor.as_mut(),
        &mut literal,
        &mut stats,
        progress,
    )?;
    if let Some(compressor) = compressor.as_mut() {
        compressor.finish(transport)?;
    } else {
        write_rsync_i32(transport, 0)?;
    }
    transport.write_all(&final_checksum.finalize())?;
    Ok(stats)
}

struct RemoteSignatureIndex<'a> {
    signatures: &'a [BlockSignature],
    lengths_desc: Vec<usize>,
    max_len: usize,
}

impl<'a> RemoteSignatureIndex<'a> {
    pub(crate) fn new(signatures: &'a [BlockSignature]) -> Result<Self> {
        let mut lengths_desc = signatures
            .iter()
            .map(|signature| signature.len)
            .filter(|len| *len > 0)
            .collect::<Vec<_>>();
        lengths_desc.sort_unstable_by(|left, right| right.cmp(left));
        lengths_desc.dedup();
        let max_len = lengths_desc.first().copied().unwrap_or(0);
        if max_len == 0 {
            bail!("remote delta signatures did not include any non-empty blocks");
        }
        Ok(Self {
            signatures,
            lengths_desc,
            max_len,
        })
    }

    pub(crate) fn find_match<S: StrongChecksum>(
        &self,
        window: &[u8],
        strong_checksum: &S,
    ) -> Option<&'a BlockSignature> {
        for len in &self.lengths_desc {
            if window.len() < *len {
                continue;
            }
            let candidate = &window[..*len];
            let weak = rolling_checksum(candidate);
            let mut strong = None;
            for signature in self
                .signatures
                .iter()
                .filter(|signature| signature.len == *len && signature.weak == weak)
            {
                let strong = strong.get_or_insert_with(|| strong_checksum.digest(candidate));
                if signature.strong == *strong {
                    return Some(signature);
                }
            }
        }
        None
    }
}

pub(crate) fn fill_delta_window<R: Read>(
    reader: &mut R,
    window: &mut Vec<u8>,
    max_len: usize,
    checksum: &mut RemoteChecksumBuilder,
    eof: &mut bool,
    stop_deadline: Option<Instant>,
) -> Result<()> {
    while !*eof && window.len() < max_len {
        check_transfer_deadline(stop_deadline)?;
        let old_len = window.len();
        window.resize(max_len, 0);
        let read = reader.read(&mut window[old_len..])?;
        window.truncate(old_len + read);
        if read == 0 {
            *eof = true;
            break;
        }
        checksum.update(&window[old_len..old_len + read]);
    }
    Ok(())
}

pub(crate) fn write_pending_literal_token<T: Write>(
    transport: &mut T,
    compressor: Option<&mut RsyncDeflatedTokenWriter>,
    literal: &mut Vec<u8>,
    stats: &mut RemoteDeltaStats,
    progress: Option<&mut FileProgress>,
) -> Result<()> {
    if literal.is_empty() {
        return Ok(());
    }
    write_literal_token(transport, compressor, literal, stats, progress)?;
    literal.clear();
    Ok(())
}

pub(crate) fn write_literal_token<T: Write>(
    transport: &mut T,
    compressor: Option<&mut RsyncDeflatedTokenWriter>,
    literal: &[u8],
    stats: &mut RemoteDeltaStats,
    progress: Option<&mut FileProgress>,
) -> Result<()> {
    if let Some(compressor) = compressor {
        compressor.send_literal(transport, literal)?;
    } else {
        write_rsync_i32(transport, literal.len() as i32)?;
        transport.write_all(literal)?;
    }
    stats.literal_bytes += literal.len() as u64;
    if let Some(progress) = progress {
        progress.advance(literal.len() as u64);
    }
    Ok(())
}

pub(crate) fn write_copy_token<T: Write>(
    transport: &mut T,
    compressor: Option<&mut RsyncDeflatedTokenWriter>,
    block_index: usize,
) -> Result<()> {
    if let Some(compressor) = compressor {
        compressor.send_copy(transport, block_index)?;
    } else {
        write_rsync_i32(transport, block_index_to_copy_token(block_index)?)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn write_delta_tokens_from_bytes_with_checksum<T: Write>(
    transport: &mut T,
    bytes: &[u8],
    block_checksum: RemoteFileChecksum,
    final_checksum: RemoteFinalChecksum,
    signatures: &[BlockSignature],
    compression_level: Option<u32>,
    mut progress: Option<&mut FileProgress>,
) -> Result<RemoteDeltaStats> {
    if signatures.is_empty() {
        let mut reader = bytes;
        let literal_bytes = write_literal_tokens_from_reader_with_checksum(
            transport,
            &mut reader,
            final_checksum,
            compression_level,
            progress,
            None,
        )?;
        return Ok(RemoteDeltaStats {
            literal_bytes,
            copied_bytes: 0,
        });
    }

    let checksum_len = signatures
        .first()
        .map(|signature| signature.strong.len())
        .unwrap_or(16);
    let strong = RsyncStrongChecksum {
        checksum: block_checksum,
        checksum_len,
    };
    let tokens = rsync_delta::generate_delta_with(signatures, bytes, &strong);
    let mut stats = RemoteDeltaStats::default();
    let final_checksum = remote_final_checksum_for_bytes(final_checksum, bytes);
    let mut compressor = compression_level.map(RsyncDeflatedTokenWriter::new);

    for token in tokens {
        match token {
            DeltaToken::Literal(literal) => {
                for chunk in literal.chunks(32 * 1024) {
                    if let Some(compressor) = compressor.as_mut() {
                        compressor.send_literal(transport, chunk)?;
                    } else {
                        write_rsync_i32(transport, chunk.len() as i32)?;
                        transport.write_all(chunk)?;
                    }
                    stats.literal_bytes += chunk.len() as u64;
                    if let Some(progress) = progress.as_deref_mut() {
                        progress.advance(chunk.len() as u64);
                    }
                }
            }
            DeltaToken::Copy { offset, len } => {
                let block_index = signatures
                    .iter()
                    .find(|signature| signature.offset == offset && signature.len == len)
                    .map(|signature| signature.index)
                    .context("delta matcher emitted a copy span without a block signature")?;
                if let Some(compressor) = compressor.as_mut() {
                    compressor.send_copy(transport, block_index)?;
                } else {
                    let token = block_index_to_copy_token(block_index)?;
                    write_rsync_i32(transport, token)?;
                }
                stats.copied_bytes += len as u64;
                if let Some(progress) = progress.as_deref_mut() {
                    progress.advance(len as u64);
                }
            }
        }
    }

    if let Some(compressor) = compressor.as_mut() {
        compressor.finish(transport)?;
    } else {
        write_rsync_i32(transport, 0)?;
    }
    transport.write_all(&final_checksum)?;
    Ok(stats)
}

pub(crate) fn write_append_verify_file_tokens_from_path<T: Write>(
    transport: &mut T,
    checksum: RemoteFinalChecksum,
    path: &Path,
    prefix_len: usize,
    compression: Option<&RemoteCompressionConfig>,
    progress: Option<&mut FileProgress>,
    stop_deadline: Option<Instant>,
) -> Result<u64> {
    let mut file = open_local_file(path)?;
    write_append_verify_literal_tokens_from_reader_with_checksum(
        transport,
        &mut file,
        checksum,
        prefix_len,
        compression.map(|compression| compression.level_for_path(path)),
        progress,
        stop_deadline,
    )
}

pub(crate) fn write_literal_tokens_from_reader_with_checksum<T: Write, R: Read>(
    transport: &mut T,
    reader: &mut R,
    checksum: RemoteFinalChecksum,
    compression_level: Option<u32>,
    mut progress: Option<&mut FileProgress>,
    stop_deadline: Option<Instant>,
) -> Result<u64> {
    let mut checksum = remote_final_checksum_builder(checksum);
    let mut buf = [0_u8; 32 * 1024];
    let mut total = 0_u64;
    let mut compressor = compression_level.map(RsyncDeflatedTokenWriter::new);
    loop {
        check_transfer_deadline(stop_deadline)?;
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        checksum.update(&buf[..read]);
        if let Some(compressor) = compressor.as_mut() {
            compressor.send_literal(transport, &buf[..read])?;
        } else {
            write_rsync_i32(transport, read as i32)?;
            transport.write_all(&buf[..read])?;
        }
        total += read as u64;
        if let Some(progress) = progress.as_deref_mut() {
            progress.advance(read as u64);
        }
    }
    if let Some(compressor) = compressor.as_mut() {
        compressor.finish(transport)?;
    } else {
        write_rsync_i32(transport, 0)?;
    }
    transport.write_all(&checksum.finalize())?;
    Ok(total)
}

pub(crate) fn write_append_verify_literal_tokens_from_reader_with_checksum<T: Write, R: Read>(
    transport: &mut T,
    reader: &mut R,
    checksum: RemoteFinalChecksum,
    prefix_len: usize,
    compression_level: Option<u32>,
    mut progress: Option<&mut FileProgress>,
    stop_deadline: Option<Instant>,
) -> Result<u64> {
    let mut checksum = remote_final_checksum_builder(checksum);
    let mut buf = [0_u8; 32 * 1024];
    let mut remaining_prefix = prefix_len;
    let mut total = 0_u64;
    let mut compressor = compression_level.map(RsyncDeflatedTokenWriter::new);
    loop {
        check_transfer_deadline(stop_deadline)?;
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        let chunk = &buf[..read];
        checksum.update(chunk);
        let literal = if remaining_prefix >= read {
            remaining_prefix -= read;
            continue;
        } else if remaining_prefix > 0 {
            let offset = remaining_prefix;
            remaining_prefix = 0;
            &chunk[offset..]
        } else {
            chunk
        };
        if let Some(compressor) = compressor.as_mut() {
            compressor.send_literal(transport, literal)?;
        } else {
            write_rsync_i32(transport, literal.len() as i32)?;
            transport.write_all(literal)?;
        }
        total += literal.len() as u64;
        if let Some(progress) = progress.as_deref_mut() {
            progress.advance(literal.len() as u64);
        }
    }
    if remaining_prefix > 0 {
        bail!("append-verify prefix length exceeds source file length");
    }
    if let Some(compressor) = compressor.as_mut() {
        compressor.finish(transport)?;
    } else {
        write_rsync_i32(transport, 0)?;
    }
    transport.write_all(&checksum.finalize())?;
    Ok(total)
}

pub(crate) fn remote_checksum_for_bytes(checksum: RemoteFileChecksum, bytes: &[u8]) -> [u8; 16] {
    let mut checksum = remote_file_checksum_builder(checksum);
    checksum.update(bytes);
    checksum.finalize()
}

#[cfg(test)]
pub(crate) fn remote_final_checksum_for_bytes(
    checksum: RemoteFinalChecksum,
    bytes: &[u8],
) -> [u8; 16] {
    let mut checksum = remote_final_checksum_builder(checksum);
    checksum.update(bytes);
    checksum.finalize()
}

pub(crate) enum RemoteChecksumBuilder {
    Md4(RsyncMd4Checksum),
    Md5 { hasher: md5::Md5, seed: Option<i32> },
}

impl RemoteChecksumBuilder {
    pub(crate) fn md5(seed: Option<i32>, prefix_seed: bool) -> Self {
        let mut hasher = md5::Md5::new();
        if prefix_seed {
            if let Some(seed) = seed {
                hasher.update(seed.to_le_bytes());
            }
        }
        Self::Md5 {
            hasher,
            seed: (!prefix_seed).then_some(seed).flatten(),
        }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Md4(checksum) => checksum.update(bytes),
            Self::Md5 { hasher, .. } => hasher.update(bytes),
        }
    }

    pub(crate) fn finalize(self) -> [u8; 16] {
        match self {
            Self::Md4(checksum) => checksum.finalize(),
            Self::Md5 { mut hasher, seed } => {
                if let Some(seed) = seed {
                    hasher.update(seed.to_le_bytes());
                }
                let digest = hasher.finalize();
                let mut out = [0_u8; 16];
                out.copy_from_slice(&digest);
                out
            }
        }
    }
}

pub(crate) fn remote_file_checksum_builder(checksum: RemoteFileChecksum) -> RemoteChecksumBuilder {
    match checksum {
        RemoteFileChecksum::SeededMd4(seed) => {
            RemoteChecksumBuilder::Md4(RsyncMd4Checksum::seeded(seed))
        }
        RemoteFileChecksum::PlainMd4 => RemoteChecksumBuilder::Md4(RsyncMd4Checksum::plain()),
        RemoteFileChecksum::SeededMd5(seed) => RemoteChecksumBuilder::md5(Some(seed), false),
        RemoteFileChecksum::PlainMd5 => RemoteChecksumBuilder::md5(None, false),
    }
}

pub(crate) fn remote_final_checksum_builder(
    checksum: RemoteFinalChecksum,
) -> RemoteChecksumBuilder {
    match checksum {
        RemoteFinalChecksum::PlainMd4 => RemoteChecksumBuilder::Md4(RsyncMd4Checksum::plain()),
        RemoteFinalChecksum::SeededMd4Prefix(seed) => {
            RemoteChecksumBuilder::Md4(RsyncMd4Checksum::seeded_prefix(seed))
        }
        RemoteFinalChecksum::PlainMd5 => RemoteChecksumBuilder::md5(None, false),
    }
}

#[derive(Debug, Clone, Copy)]
struct RsyncStrongChecksum {
    checksum: RemoteFileChecksum,
    checksum_len: usize,
}

impl StrongChecksum for RsyncStrongChecksum {
    fn digest(&self, block: &[u8]) -> Vec<u8> {
        let checksum = remote_checksum_for_bytes(self.checksum, block);
        checksum[..self.checksum_len.min(checksum.len())].to_vec()
    }
}

pub(crate) fn validate_sum_head(sum_head: RemoteSumHead) -> Result<()> {
    if sum_head.block_count > 0 && sum_head.block_len == 0 {
        bail!("remote sum head has a zero block length");
    }
    if sum_head.remainder > sum_head.block_len && sum_head.block_count > 0 {
        bail!("remote sum head has a remainder larger than its block length");
    }
    Ok(())
}

pub(crate) fn block_span(sum_head: &RemoteSumHead, block_index: usize) -> Result<(usize, usize)> {
    validate_sum_head(*sum_head)?;
    if block_index >= sum_head.block_count {
        bail!("copy token references missing basis block {block_index}");
    }
    let offset = block_index
        .checked_mul(sum_head.block_len)
        .context("basis block offset overflow")?;
    let is_last = block_index + 1 == sum_head.block_count;
    let len = if is_last && sum_head.remainder != 0 {
        sum_head.remainder
    } else {
        sum_head.block_len
    };
    Ok((offset, len))
}

pub(crate) fn block_index_to_copy_token(block_index: usize) -> Result<i32> {
    let token = i32::try_from(block_index).context("basis block index exceeded i32 range")?;
    token
        .checked_add(1)
        .and_then(|value| value.checked_neg())
        .context("basis block token overflow")
}

pub(crate) fn copy_token_to_block_index(token: i32) -> Result<usize> {
    if token >= 0 {
        bail!("copy token must be negative");
    }
    let raw = token
        .checked_neg()
        .and_then(|value| value.checked_sub(1))
        .context("copy token overflow")?;
    usize::try_from(raw).context("copy token block index did not fit usize")
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn read_file_tokens_to_path_with_basis<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    checksum: RemoteFinalChecksum,
    path: &Path,
    output_path: &Path,
    expected_len: u64,
    basis: Option<(&Path, RemoteSumHead)>,
    compression: Option<&RemoteCompressionConfig>,
    mut progress: Option<&mut FileProgress>,
    max_alloc: Option<u64>,
    stop_deadline: Option<Instant>,
) -> Result<u64> {
    if let Some(parent) = output_path.parent() {
        create_local_dir_all(parent)?;
    }
    let mut output = create_local_file(output_path)?;
    let mut basis_file = match basis {
        Some((basis_path, sum_head)) if sum_head.block_count > 0 => {
            ensure_basis_copy_budget(sum_head, max_alloc)?;
            Some((open_local_file(basis_path)?, sum_head))
        }
        _ => None,
    };
    let mut total = 0_u64;
    let mut buf = [0_u8; 32 * 1024];

    if let Some(compression) = compression {
        let mut token_reader = RsyncDeflatedTokenReader::new(compression.mode);
        loop {
            check_transfer_deadline(stop_deadline)?;
            let token = {
                let mut reader = MultiplexedReader::new(transport, mux);
                token_reader.next_token(&mut reader)?
            };
            match token {
                RsyncDeflatedToken::Literal(literal) => {
                    let next_total = total.checked_add(literal.len() as u64).ok_or(
                        RemoteSessionError::FileLengthExceeded {
                            path: path.display().to_string(),
                            expected: expected_len,
                            actual: u64::MAX,
                        },
                    )?;
                    if next_total > expected_len {
                        return Err(RemoteSessionError::FileLengthExceeded {
                            path: path.display().to_string(),
                            expected: expected_len,
                            actual: next_total,
                        }
                        .into());
                    }
                    output.write_all(&literal)?;
                    total = next_total;
                    if let Some(progress) = progress.as_deref_mut() {
                        progress.advance(literal.len() as u64);
                    }
                }
                RsyncDeflatedToken::Copy { block_index } => {
                    let Some((basis_file, sum_head)) = basis_file.as_mut() else {
                        return Err(RemoteSessionError::UnexpectedToken {
                            token: block_index_to_copy_token(block_index)?,
                            path: path.display().to_string(),
                        }
                        .into());
                    };
                    let bytes = read_basis_block(basis_file, *sum_head, block_index, path)?;
                    token_reader.observe_copy_data(&bytes)?;
                    let next_total = total.checked_add(bytes.len() as u64).ok_or(
                        RemoteSessionError::FileLengthExceeded {
                            path: path.display().to_string(),
                            expected: expected_len,
                            actual: u64::MAX,
                        },
                    )?;
                    if next_total > expected_len {
                        return Err(RemoteSessionError::FileLengthExceeded {
                            path: path.display().to_string(),
                            expected: expected_len,
                            actual: next_total,
                        }
                        .into());
                    }
                    output.write_all(&bytes)?;
                    total = next_total;
                    if let Some(progress) = progress.as_deref_mut() {
                        progress.advance(bytes.len() as u64);
                    }
                }
                RsyncDeflatedToken::End => {
                    output.sync_all()?;
                    drop(output);
                    if total != expected_len {
                        return Err(RemoteSessionError::FileLengthShort {
                            path: path.display().to_string(),
                            expected: expected_len,
                            actual: total,
                        }
                        .into());
                    }
                    let mut remote_checksum = [0_u8; 16];
                    read_multiplexed_exact(transport, mux, &mut remote_checksum)?;
                    let local_checksum = remote_file_checksum_for_path(checksum, output_path)?;
                    if remote_checksum != local_checksum {
                        return Err(RemoteSessionError::FileChecksumMismatch {
                            path: path.display().to_string(),
                        }
                        .into());
                    }
                    return Ok(total);
                }
            }
        }
    }

    loop {
        check_transfer_deadline(stop_deadline)?;
        let token = read_multiplexed_i32(transport, mux)?;
        if token > 0 {
            let literal_len = token as u64;
            let next_total =
                total
                    .checked_add(literal_len)
                    .ok_or(RemoteSessionError::FileLengthExceeded {
                        path: path.display().to_string(),
                        expected: expected_len,
                        actual: u64::MAX,
                    })?;
            if next_total > expected_len {
                return Err(RemoteSessionError::FileLengthExceeded {
                    path: path.display().to_string(),
                    expected: expected_len,
                    actual: next_total,
                }
                .into());
            }

            let mut remaining = token as usize;
            while remaining > 0 {
                let len = buf.len().min(remaining);
                read_multiplexed_exact(transport, mux, &mut buf[..len])?;
                output.write_all(&buf[..len])?;
                remaining -= len;
                total += len as u64;
                if let Some(progress) = progress.as_deref_mut() {
                    progress.advance(len as u64);
                }
            }
        } else if token == 0 {
            output.sync_all()?;
            drop(output);
            if total != expected_len {
                return Err(RemoteSessionError::FileLengthShort {
                    path: path.display().to_string(),
                    expected: expected_len,
                    actual: total,
                }
                .into());
            }
            let mut remote_checksum = [0_u8; 16];
            read_multiplexed_exact(transport, mux, &mut remote_checksum)?;
            let local_checksum = remote_file_checksum_for_path(checksum, output_path)?;
            if remote_checksum != local_checksum {
                return Err(RemoteSessionError::FileChecksumMismatch {
                    path: path.display().to_string(),
                }
                .into());
            }
            return Ok(total);
        } else {
            let Some((basis_file, sum_head)) = basis_file.as_mut() else {
                return Err(RemoteSessionError::UnexpectedToken {
                    token,
                    path: path.display().to_string(),
                }
                .into());
            };
            let block_index = copy_token_to_block_index(token)?;
            let bytes = read_basis_block(basis_file, *sum_head, block_index, path)?;
            let next_total = total.checked_add(bytes.len() as u64).ok_or(
                RemoteSessionError::FileLengthExceeded {
                    path: path.display().to_string(),
                    expected: expected_len,
                    actual: u64::MAX,
                },
            )?;
            if next_total > expected_len {
                return Err(RemoteSessionError::FileLengthExceeded {
                    path: path.display().to_string(),
                    expected: expected_len,
                    actual: next_total,
                }
                .into());
            }
            output.write_all(&bytes)?;
            total = next_total;
            if let Some(progress) = progress.as_deref_mut() {
                progress.advance(bytes.len() as u64);
            }
        }
    }
}

pub(crate) fn remote_file_checksum_for_path(
    checksum: RemoteFinalChecksum,
    path: &Path,
) -> Result<[u8; 16]> {
    let mut file = open_local_file(path)?;
    let mut checksum = remote_final_checksum_builder(checksum);
    let mut buf = [0_u8; 32 * 1024];
    loop {
        let read = file
            .read(&mut buf)
            .with_context(|| format!("failed to checksum {}", path.display()))?;
        if read == 0 {
            break;
        }
        checksum.update(&buf[..read]);
    }
    Ok(checksum.finalize())
}

pub(crate) fn read_local_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(to_long_path_safe(path))
        .with_context(|| format!("failed to read {}", path.display()))
}

pub(crate) fn ensure_basis_copy_budget(
    sum_head: RemoteSumHead,
    max_alloc: Option<u64>,
) -> Result<()> {
    validate_sum_head(sum_head)?;
    if sum_head.block_count == 0 {
        return Ok(());
    }
    ensure_allocation_within_limit("basis copy block", sum_head.block_len, max_alloc)
}

pub(crate) fn read_basis_block(
    basis_file: &mut File,
    sum_head: RemoteSumHead,
    block_index: usize,
    path: &Path,
) -> Result<Vec<u8>> {
    let (offset, len) = block_span(&sum_head, block_index)?;
    basis_file.seek(SeekFrom::Start(offset as u64))?;
    let mut bytes = vec![0_u8; len];
    basis_file.read_exact(&mut bytes).with_context(|| {
        format!(
            "remote copy token {} references bytes outside the basis file for {}",
            block_index_to_copy_token(block_index).unwrap_or(i32::MIN),
            path.display()
        )
    })?;
    Ok(bytes)
}

pub(crate) fn ensure_allocation_within_limit(
    label: &'static str,
    bytes: usize,
    max_alloc: Option<u64>,
) -> Result<()> {
    if let Some(limit) = max_alloc.filter(|limit| *limit > 0) {
        if bytes as u64 > limit {
            bail!("{label} would require a {bytes} byte allocation, exceeding --max-alloc={limit}");
        }
    }
    Ok(())
}

pub(crate) fn ensure_signature_table_budget(
    label: &'static str,
    block_count: usize,
    checksum_len: usize,
    max_alloc: Option<u64>,
) -> Result<()> {
    let per_signature = std::mem::size_of::<BlockSignature>()
        .checked_add(checksum_len)
        .context("signature table allocation estimate overflow")?;
    let bytes = block_count
        .checked_mul(per_signature)
        .context("signature table allocation estimate overflow")?;
    ensure_allocation_within_limit(label, bytes, max_alloc)
}

pub(crate) fn open_local_file(path: &Path) -> Result<File> {
    File::open(to_long_path_safe(path))
        .with_context(|| format!("failed to open {}", path.display()))
}

pub(crate) fn create_local_file(path: &Path) -> Result<File> {
    File::create(to_long_path_safe(path))
        .with_context(|| format!("failed to create {}", path.display()))
}

pub(crate) fn create_local_dir_all(path: &Path) -> Result<()> {
    std::fs::create_dir_all(to_long_path_safe(path))
        .with_context(|| format!("failed to create {}", path.display()))
}

pub(crate) fn remove_local_file_best_effort(path: &Path) {
    let _ = std::fs::remove_file(to_long_path_safe(path));
}

pub(crate) fn receive_temp_path(target: &Path) -> PathBuf {
    let file_name = target
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "rsync-win".into());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temp_name = format!(".{file_name}.{}.{}.recv", std::process::id(), nanos);
    target
        .parent()
        .map(|parent| parent.join(&temp_name))
        .unwrap_or_else(|| PathBuf::from(temp_name))
}

pub(crate) fn sync_action_len(len: u64) -> Result<usize> {
    usize::try_from(len).context("file length exceeds this platform's address size")
}

pub(crate) fn read_multiplexed_exact<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    buf: &mut [u8],
) -> Result<()> {
    let mut reader = MultiplexedReader::new(transport, mux);
    reader.read_exact(buf)?;
    Ok(())
}
