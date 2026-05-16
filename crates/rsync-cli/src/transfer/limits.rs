use super::prelude::*;
use super::sum_head::{validate_sum_head, RemoteSumHead};

#[derive(Debug, Clone, Copy)]
pub(crate) struct TransferLimits {
    pub(crate) max_alloc: Option<u64>,
    pub(crate) stop_deadline: Option<Instant>,
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

pub(crate) fn sync_action_len(len: u64) -> Result<usize> {
    usize::try_from(len).context("file length exceeds this platform's address size")
}
