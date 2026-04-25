use std::io::{self, Read, Write};

use thiserror::Error;

use crate::io::{read_u32_le, write_u32_le};

pub const MIN_PROTOCOL_VERSION: u32 = 20;
pub const MAX_PROTOCOL_VERSION: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    pub fn selected(value: u32) -> Result<Self, VersionError> {
        if !(MIN_PROTOCOL_VERSION..=MAX_PROTOCOL_VERSION).contains(&value) {
            return Err(VersionError::InvalidSelected(value));
        }
        Ok(Self(value))
    }

    pub fn value(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VersionError {
    #[error("peer sent invalid protocol version {0}")]
    InvalidPeer(u32),
    #[error("peer protocol version {peer} is older than supported minimum {minimum}")]
    UnsupportedOld { peer: u32, minimum: u32 },
    #[error("selected protocol version {0} is outside the supported range")]
    InvalidSelected(u32),
}

pub fn negotiate_protocol_version(peer_version: u32) -> Result<ProtocolVersion, VersionError> {
    negotiate_protocol_version_with_local(peer_version, MAX_PROTOCOL_VERSION)
}

pub fn negotiate_protocol_version_with_local(
    peer_version: u32,
    local_max: u32,
) -> Result<ProtocolVersion, VersionError> {
    if peer_version == 0 {
        return Err(VersionError::InvalidPeer(peer_version));
    }
    if peer_version < MIN_PROTOCOL_VERSION {
        return Err(VersionError::UnsupportedOld {
            peer: peer_version,
            minimum: MIN_PROTOCOL_VERSION,
        });
    }
    if local_max < MIN_PROTOCOL_VERSION {
        return Err(VersionError::InvalidSelected(local_max));
    }

    ProtocolVersion::selected(peer_version.min(local_max).min(MAX_PROTOCOL_VERSION))
}

pub fn read_peer_version<R: Read>(reader: &mut R) -> io::Result<u32> {
    read_u32_le(reader)
}

pub fn write_local_version<W: Write>(writer: &mut W) -> io::Result<()> {
    write_local_version_with(writer, MAX_PROTOCOL_VERSION)
}

pub fn write_local_version_with<W: Write>(writer: &mut W, version: u32) -> io::Result<()> {
    write_u32_le(writer, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiates_supported_peer_version() {
        let version = negotiate_protocol_version(31).unwrap();
        assert_eq!(version.value(), 31);
    }

    #[test]
    fn negotiates_future_peer_down_to_local_max() {
        let version = negotiate_protocol_version(MAX_PROTOCOL_VERSION + 5).unwrap();
        assert_eq!(version.value(), MAX_PROTOCOL_VERSION);
    }

    #[test]
    fn negotiates_down_to_explicit_local_protocol() {
        let version = negotiate_protocol_version_with_local(32, 27).unwrap();
        assert_eq!(version.value(), 27);
    }

    #[test]
    fn rejects_old_peer_version() {
        let err = negotiate_protocol_version(MIN_PROTOCOL_VERSION - 1).unwrap_err();
        assert_eq!(
            err,
            VersionError::UnsupportedOld {
                peer: MIN_PROTOCOL_VERSION - 1,
                minimum: MIN_PROTOCOL_VERSION
            }
        );
    }

    #[test]
    fn rejects_invalid_peer_version() {
        let err = negotiate_protocol_version(0).unwrap_err();
        assert_eq!(err, VersionError::InvalidPeer(0));
    }

    #[test]
    fn writes_and_reads_local_version() {
        let mut bytes = Vec::new();
        write_local_version(&mut bytes).unwrap();
        assert_eq!(read_peer_version(&mut bytes.as_slice()).unwrap(), 32);
    }

    #[test]
    fn writes_explicit_local_version() {
        let mut bytes = Vec::new();
        write_local_version_with(&mut bytes, 27).unwrap();
        assert_eq!(read_peer_version(&mut bytes.as_slice()).unwrap(), 27);
    }
}
