//! Strict sans-I/O HTTP/1 head parsing.
//!
//! Callers retain their receive buffer and invoke [`HeadParser`] whenever more
//! bytes arrive. A complete parse reports the exact number of consumed bytes,
//! leaving pipelined messages untouched for the connection driver.

mod connection;
mod framing;
mod parser;
mod serialize;
mod validation;

pub use connection::{
    serve_connection, serve_connection_with_upgrades, AsyncIo, BoxIo, ConnectionConfig,
    Http1Client, Http1ClientResponse, Http1Connector, Http1Pool, PoolKey, ServerConnection,
    UpgradeReceiver, UpgradedIo,
};
pub use framing::{
    BodyDecodeStatus, BodyDecoder, BodyDecoderLimits, BodyFraming, DecodedBodyFrame,
};
pub use parser::{
    HeadParser, HeadParserLimits, ParseStatus, ParsedRequestHead, ParsedResponseHead,
};
pub use serialize::{encode_request_head, encode_response_head, BodyEncoder};
pub use validation::{HeaderSemantics, Http1Error, Http1ErrorKind};
