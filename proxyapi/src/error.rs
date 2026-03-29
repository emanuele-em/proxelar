use thiserror::Error;

/// Errors that can occur during proxy operation.
#[derive(Debug, Error)]
pub enum Error {
    /// Hyper HTTP error (e.g. malformed response, protocol violation).
    #[error("network: {0}")]
    Network(#[from] hyper::Error),
    /// HTTP client error when forwarding requests upstream.
    #[error("client: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),
    /// I/O error from TCP or file operations.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// TLS configuration or handshake error.
    #[error("tls: {0}")]
    Tls(#[from] tokio_rustls::rustls::Error),
    /// OpenSSL certificate generation/parsing error.
    #[error("certificate: {0}")]
    Certificate(#[from] openssl::error::ErrorStack),
    /// System clock error.
    #[error("time: {0}")]
    Time(#[from] std::time::SystemTimeError),
    /// Invalid HTTP header value.
    #[error("invalid header: {0}")]
    InvalidHeader(#[from] hyper::header::InvalidHeaderValue),
    /// A spawned background task panicked or was cancelled.
    #[error("task join: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),
    /// Lua script error (load failure, runtime error, etc.).
    #[error("script: {0}")]
    Script(String),
    /// Catch-all for errors that don't fit other variants.
    #[error("{0}")]
    Other(String),
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
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "io fail");
        let err: Error = io_err.into();
        assert!(err.to_string().contains("io"));
    }
}
