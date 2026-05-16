use super::checksum::{
    remote_file_checksum_for_path, remote_final_checksum_builder, RemoteFinalChecksum,
};
use super::fs_ops::{create_local_dir_all, create_local_file, open_local_file};
use super::limits::ensure_basis_copy_budget;
use super::prelude::*;
use super::progress::{FileProgress, RemoteCompressionConfig};
use super::sum_head::{
    block_index_to_copy_token, block_span, copy_token_to_block_index, RemoteSumHead,
};

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

pub(crate) fn read_multiplexed_exact<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    buf: &mut [u8],
) -> Result<()> {
    let mut reader = MultiplexedReader::new(transport, mux);
    reader.read_exact(buf)?;
    Ok(())
}
