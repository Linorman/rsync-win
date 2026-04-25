use thiserror::Error;

use crate::rollsum::rolling_checksum;

#[cfg(any(feature = "md4", feature = "md5"))]
use digest::Digest;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignatureError {
    #[error("block size must be greater than zero")]
    ZeroBlockSize,
}

pub trait StrongChecksum {
    fn digest(&self, block: &[u8]) -> Vec<u8>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DeterministicStrongChecksum;

impl StrongChecksum for DeterministicStrongChecksum {
    fn digest(&self, block: &[u8]) -> Vec<u8> {
        let first = fnv1a64(block, 0xcbf2_9ce4_8422_2325);
        let second = fnv1a64(block, 0x9e37_79b9_7f4a_7c15 ^ block.len() as u64);

        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&first.to_le_bytes());
        out.extend_from_slice(&second.to_le_bytes());
        out
    }
}

#[cfg(feature = "md4")]
#[derive(Debug, Default, Clone, Copy)]
pub struct Md4StrongChecksum;

#[cfg(feature = "md4")]
impl StrongChecksum for Md4StrongChecksum {
    fn digest(&self, block: &[u8]) -> Vec<u8> {
        md4::Md4::digest(block).to_vec()
    }
}

#[cfg(feature = "md5")]
#[derive(Debug, Default, Clone, Copy)]
pub struct Md5StrongChecksum;

#[cfg(feature = "md5")]
impl StrongChecksum for Md5StrongChecksum {
    fn digest(&self, block: &[u8]) -> Vec<u8> {
        md5::Md5::digest(block).to_vec()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSignature {
    pub index: usize,
    pub offset: usize,
    pub len: usize,
    pub weak: u32,
    pub strong: Vec<u8>,
}

pub fn generate_test_signatures(
    basis: &[u8],
    block_size: usize,
) -> Result<Vec<BlockSignature>, SignatureError> {
    generate_signatures_with(basis, block_size, &DeterministicStrongChecksum)
}

pub fn generate_signatures_with<S: StrongChecksum>(
    basis: &[u8],
    block_size: usize,
    strong_checksum: &S,
) -> Result<Vec<BlockSignature>, SignatureError> {
    if block_size == 0 {
        return Err(SignatureError::ZeroBlockSize);
    }

    let signatures = basis
        .chunks(block_size)
        .enumerate()
        .map(|(index, block)| {
            let offset = index * block_size;
            BlockSignature {
                index,
                offset,
                len: block.len(),
                weak: rolling_checksum(block),
                strong: strong_checksum.digest(block),
            }
        })
        .collect();

    Ok(signatures)
}

fn fnv1a64(bytes: &[u8], seed: u64) -> u64 {
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = seed;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_block_size() {
        let err = generate_test_signatures(b"abc", 0).unwrap_err();
        assert_eq!(err, SignatureError::ZeroBlockSize);
    }

    #[test]
    fn generates_full_and_partial_block_signatures() {
        let signatures = generate_test_signatures(b"abcdefg", 3).unwrap();

        assert_eq!(signatures.len(), 3);
        assert_eq!(signatures[0].offset, 0);
        assert_eq!(signatures[0].len, 3);
        assert_eq!(signatures[1].offset, 3);
        assert_eq!(signatures[1].len, 3);
        assert_eq!(signatures[2].offset, 6);
        assert_eq!(signatures[2].len, 1);
    }

    #[test]
    fn empty_basis_has_no_signatures() {
        let signatures = generate_test_signatures(b"", 4).unwrap();
        assert!(signatures.is_empty());
    }

    #[cfg(feature = "md4")]
    #[test]
    fn md4_strong_checksum_is_feature_gated() {
        assert_eq!(Md4StrongChecksum.digest(b"abc").len(), 16);
    }

    #[cfg(feature = "md5")]
    #[test]
    fn md5_strong_checksum_is_feature_gated() {
        assert_eq!(Md5StrongChecksum.digest(b"abc").len(), 16);
    }
}
