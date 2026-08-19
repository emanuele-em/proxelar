use http::{Method, StatusCode, Uri, Version};
use proxyapi_models::HeaderBlock;

use crate::ProxyBody;

/// Transport-neutral request metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestHead {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: HeaderBlock,
}

impl RequestHead {
    pub const fn new(method: Method, uri: Uri, version: Version, headers: HeaderBlock) -> Self {
        Self {
            method,
            uri,
            version,
            headers,
        }
    }
}

/// Transport-neutral response metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseHead {
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderBlock,
}

impl ResponseHead {
    pub const fn new(status: StatusCode, version: Version, headers: HeaderBlock) -> Self {
        Self {
            status,
            version,
            headers,
        }
    }
}

/// A request head paired with its streaming body.
#[derive(Debug)]
pub struct ProxyRequest {
    pub head: RequestHead,
    pub body: ProxyBody,
}

impl ProxyRequest {
    pub const fn new(head: RequestHead, body: ProxyBody) -> Self {
        Self { head, body }
    }

    pub fn into_parts(self) -> (RequestHead, ProxyBody) {
        (self.head, self.body)
    }

    pub const fn method(&self) -> &Method {
        &self.head.method
    }

    pub const fn uri(&self) -> &Uri {
        &self.head.uri
    }

    pub const fn version(&self) -> Version {
        self.head.version
    }

    pub const fn headers(&self) -> &HeaderBlock {
        &self.head.headers
    }

    pub fn into_body(self) -> ProxyBody {
        self.body
    }
}

/// A response head paired with its streaming body.
#[derive(Debug)]
pub struct ProxyResponse {
    pub head: ResponseHead,
    pub body: ProxyBody,
}

impl ProxyResponse {
    pub const fn new(head: ResponseHead, body: ProxyBody) -> Self {
        Self { head, body }
    }

    pub fn into_parts(self) -> (ResponseHead, ProxyBody) {
        (self.head, self.body)
    }

    pub const fn status(&self) -> StatusCode {
        self.head.status
    }

    pub const fn version(&self) -> Version {
        self.head.version
    }

    pub const fn headers(&self) -> &HeaderBlock {
        &self.head.headers
    }

    pub fn into_body(self) -> ProxyBody {
        self.body
    }
}
