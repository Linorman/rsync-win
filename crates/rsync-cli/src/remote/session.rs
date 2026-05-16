use std::fmt;

use rsync_protocol::{RemoteSessionError, SessionError};

pub(crate) fn should_fallback_to_protocol27(err: &anyhow::Error) -> bool {
    if let Some(setup_err) = err.downcast_ref::<Protocol31SetupError>() {
        return should_fallback_to_protocol27_from_setup(&setup_err.source);
    }

    should_fallback_to_protocol27_from_negotiation(err)
}

fn should_fallback_to_protocol27_from_setup(err: &anyhow::Error) -> bool {
    should_fallback_to_protocol27_from_negotiation(err) || is_unexpected_eof(err)
}

fn should_fallback_to_protocol27_from_negotiation(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<RemoteSessionError>(),
        Some(
            RemoteSessionError::UnsupportedProtocol { .. }
                | RemoteSessionError::UnsupportedChecksumNegotiation
                | RemoteSessionError::InvalidChecksumList
                | RemoteSessionError::Session(
                    SessionError::NonProtocolOutput(_)
                        | SessionError::IncompleteProtocolPrefix
                        | SessionError::InvalidProtocolPrefix(_)
                )
        )
    )
}

fn is_unexpected_eof(err: &anyhow::Error) -> bool {
    if let Some(io_error) = err.downcast_ref::<std::io::Error>() {
        return io_error.kind() == std::io::ErrorKind::UnexpectedEof;
    }
    matches!(
        err.downcast_ref::<RemoteSessionError>(),
        Some(RemoteSessionError::Io(io_error))
            if io_error.kind() == std::io::ErrorKind::UnexpectedEof
    )
}

#[derive(Debug)]
struct Protocol31SetupError {
    source: anyhow::Error,
}

impl fmt::Display for Protocol31SetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "protocol 31 setup failed: {}", self.source)
    }
}

impl std::error::Error for Protocol31SetupError {}

pub(crate) fn protocol31_setup_error<E>(err: E) -> anyhow::Error
where
    E: Into<anyhow::Error>,
{
    anyhow::Error::new(Protocol31SetupError { source: err.into() })
}
