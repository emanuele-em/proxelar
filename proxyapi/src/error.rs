use rama::error::BoxError;
use thiserror::Error;

/// Errors that can occur during proxy operation.
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error from TCP or file operations.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A spawned background task panicked or was cancelled.
    #[error("task join: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),
    /// TLS / certificate configuration or handshake error.
    #[error("tls: {0}")]
    Tls(String),
    /// Lua script error (load failure, runtime error, etc.).
    #[error("script: {0}")]
    Script(String),
    /// Catch-all for errors that don't fit other variants.
    #[error("{0}")]
    Other(String),
}

impl From<BoxError> for Error {
    fn from(error: BoxError) -> Self {
        Self::Other(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::Other("test error".to_string());
        assert_eq!(err.to_string(), "test error");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::other("io fail");
        let err: Error = io_err.into();
        assert!(err.to_string().contains("io"));
    }
}
