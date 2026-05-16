use super::fs_ops::open_local_file;
use super::prelude::*;
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

pub(crate) fn normalize_remote_strong_checksum(
    strong: Vec<u8>,
    _checksum: RemoteFileChecksum,
    _checksum_len: usize,
) -> Vec<u8> {
    strong
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
pub(super) struct RsyncStrongChecksum {
    pub(super) checksum: RemoteFileChecksum,
    pub(super) checksum_len: usize,
}

impl StrongChecksum for RsyncStrongChecksum {
    fn digest(&self, block: &[u8]) -> Vec<u8> {
        let checksum = remote_checksum_for_bytes(self.checksum, block);
        checksum[..self.checksum_len.min(checksum.len())].to_vec()
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
