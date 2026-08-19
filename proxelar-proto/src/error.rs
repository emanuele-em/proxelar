use std::fmt;

/// Stable categories shared by protocol adapters and connection drivers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    MalformedMessage,
    ProtocolViolation,
    Io,
    Timeout,
    Reset,
    Unsupported,
}

/// An engine-independent protocol failure.
///
/// The text is diagnostic rather than machine-readable; callers should branch
/// on [`ErrorKind`]. Keeping engine errors behind this boundary prevents public
/// APIs from depending on Hyper, h2, quiche, or Tokio error types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolError {
    kind: ErrorKind,
    message: String,
}

impl ProtocolError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProtocolError {}
