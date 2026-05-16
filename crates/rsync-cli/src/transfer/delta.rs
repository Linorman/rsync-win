#[cfg(test)]
use super::checksum::remote_final_checksum_for_bytes;
use super::checksum::{
    normalize_remote_strong_checksum, remote_final_checksum_builder, RemoteChecksumBuilder,
    RemoteFileChecksum, RemoteFinalChecksum, RsyncStrongChecksum,
};
use super::fs_ops::open_local_file;
use super::limits::{
    ensure_allocation_within_limit, ensure_signature_table_budget, TransferLimits,
};
use super::prelude::*;
use super::progress::{FileProgress, RemoteCompressionConfig};
use super::sum_head::{block_index_to_copy_token, block_span, validate_sum_head, RemoteSumHead};
use super::tokens::write_literal_tokens_from_reader_with_checksum;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoteDeltaStats {
    pub(crate) literal_bytes: u64,
    pub(crate) copied_bytes: u64,
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

pub(super) struct RemoteSignatureIndex<'a> {
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
