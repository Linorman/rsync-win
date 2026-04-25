pub mod apply;
pub mod matcher;
pub mod rollsum;
pub mod signature;

pub use apply::{apply_delta, ApplyError};
pub use matcher::{generate_delta_with, generate_test_delta, DeltaToken};
pub use rollsum::{rolling_checksum, RollingChecksum};
pub use signature::{
    generate_signatures_with, generate_test_signatures, BlockSignature,
    DeterministicStrongChecksum, SignatureError, StrongChecksum,
};

#[cfg(feature = "md4")]
pub use signature::Md4StrongChecksum;

#[cfg(feature = "md5")]
pub use signature::Md5StrongChecksum;
