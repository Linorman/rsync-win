use super::prelude::*;
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
