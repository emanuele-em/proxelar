//! Transport-neutral HTTP messages and protocol interfaces for Proxelar.
//!
//! This crate deliberately contains no socket, TLS, HTTP/1, HTTP/2, or HTTP/3
//! engine. Protocol adapters translate their wire representation into these
//! ordered heads and streaming body frames.

#![forbid(unsafe_code)]

mod body;
mod error;
pub mod http1;
pub mod http2;
mod message;
mod service;

pub use body::{BodyFrame, BodyResult, CollectedBody, ProxyBody};
pub use error::{ErrorKind, ProtocolError};
pub use message::{
    response_body_is_forbidden, ProxyRequest, ProxyResponse, RequestHead, ResponseHead,
};
pub use service::{BoxFuture, HttpClient, HttpService};
