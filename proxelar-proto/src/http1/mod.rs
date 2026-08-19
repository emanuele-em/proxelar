//! Strict sans-I/O HTTP/1 head parsing.
//!
//! Callers retain their receive buffer and invoke [`HeadParser`] whenever more
//! bytes arrive. A complete parse reports the exact number of consumed bytes,
//! leaving pipelined messages untouched for the connection driver.

mod parser;
mod validation;

pub use parser::{
    HeadParser, HeadParserLimits, ParseStatus, ParsedRequestHead, ParsedResponseHead,
};
pub use validation::{HeaderSemantics, Http1Error, Http1ErrorKind};
