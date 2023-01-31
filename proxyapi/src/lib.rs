mod decoder;
mod error;
mod rewind;
mod proxy;
mod noop;

pub mod ca;

use hyper::{Body, Request, Response, Uri};
use std::net::SocketAddr;
use tokio_tungstenite::tungstenite::Message;

pub use async_trait;
pub use openssl;
pub use hyper;
pub use tokio_rustls;
pub use tokio_tungstenite;

//decoder
// pub use decoder;
// pub use error;
// pub use noop;
// pub use proxy::*;

#[derive(Debug)]
pub enum RequestResponse{
    Request(Request<Body>),
    Response(Response<Body>),
}

impl From<Request<Body>> for RequestResponse{
    fn from(req: Request<Body>) -> Self{
        Self::Request(req)
    }
}

impl From<Response<Body>> for RequestResponse{
    fn from(res: Response<Body>) -> Self{
        Self::Response(res)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HttpContext {
    pub remote_addr: SocketAddr,
}

pub enum WebSocketContext{
    ClientToServer{
        src: SocketAddr,
        dst: Uri,
    },
    ServerToClient{
        src: Uri,
        dst: SocketAddr,
    }
}

#[async_trait::async_trait]
pub trait HttpHandler: Clone + Send + Sync + 'static{
    async fn handle_request( &mut self, _ctx: &HttpContext, req: Request<Body>,) -> RequestResponse {
        req.into()
    }

    async fn handle_response( &mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        res
    }
}

#[async_trait::async_trait]
pub trait WebSocketHandler: Clone + Send + Sync +'static{
    async fn handle_message( &mut self, _ctx: &WebSocketContext, message: Message, ) -> Option<Message> {
        Some(message)
    }
}