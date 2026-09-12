use std::future::Future;
use std::pin::Pin;

use crate::{ProtocolError, ProxyRequest, ProxyResponse};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Client-side request dispatch independent of a concrete HTTP version.
pub trait HttpClient: Send {
    fn send(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>>;
}

/// Server-side request handling independent of a concrete HTTP version.
pub trait HttpService: Send {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>>;
}
