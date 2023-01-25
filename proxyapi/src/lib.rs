use std::net::SocketAddr;

use bytes::Bytes;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::client::conn::http1::Builder;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};

use tokio::net::{TcpListener, TcpStream};

#[derive(Debug)]
pub struct ProxyAPI{
    listener: TcpListener
}

#[derive(Copy, Clone)]
pub struct ProxyAPIResponse{
    req: bool,
    res: bool,
}

impl ProxyAPIResponse {
    fn new() -> Self{
        Self { req: false, res: false }
    }

    fn load(&mut self, req: bool, res: bool){
        self.req = req;
        self.res = res;
    }
}

impl ProxyAPI{
    
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 8100))).await?;
        
        Ok(Self { listener })
    }

    pub async fn listen(&mut self) -> Result<ProxyAPIResponse, std::io::Error>{
            let (stream, _) = self.listener.accept().await?;

            let proxy_api_response = ProxyAPIResponse::new();

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(stream,service_fn(move |req| Self::proxy(req, proxy_api_response)) )
                    .with_upgrades()
                    .await
                {
                    eprintln!("Failed to serve connection: {:?}", err);
                }
            });

            Ok(proxy_api_response)
    }



    async fn proxy(
        req: Request<hyper::body::Incoming>,
        mut proxy_api_response: ProxyAPIResponse,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {

        println!("req: {:?}", req);

        if req.method() == Method::CONNECT {
            if let Some(addr) = Self::host_addr(req.uri()) {
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            if let Err(err) = Self::tunnel(upgraded, addr).await {
                                eprintln!("server io error: {}", err);
                            };
                        }
                        Err(err) => eprintln!("upgrade error: {}", err),
                    }
                });

                Ok(Response::new(Self::empty()))
            } else {
                eprintln!("CONNECT host is not a socked addr: {:?}", req.uri());
                let mut resp = Response::new(Self::full("CONNECT must be to a socket addr"));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                Ok(resp)
            }
        } else {
            let host = req.uri().host().expect("no host");
            let port = req.uri().port_u16().unwrap_or(80);
            let addr = format!("{}:{}", host, port);

            let stream = TcpStream::connect(addr).await.unwrap();

            let (mut sender, conn) = Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(stream)
                .await?;

            tokio::task::spawn(async move {
                if let Err(err) = conn.await {
                    eprintln!("Connection failed:{:?}", err)
                }
            });

            let resp = sender.send_request(req).await?;
            
            proxy_api_response.load(true, true);

            Ok(resp.map(|b| b.boxed()))

            
        }
    }

    fn empty() -> BoxBody<Bytes, hyper::Error> {
        Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed()
    }
    fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
        Full::new(chunk.into())
            .map_err(|never| match never {})
            .boxed()
    }

    fn host_addr(uri: &hyper::Uri) -> Option<String> {
        uri.authority().and_then(|u| Some(u.to_string()))
    }

    async fn tunnel(mut upgraded: Upgraded, addr: String) -> std::io::Result<()> {
        let mut server = TcpStream::connect(addr).await?;

        let (from_client, from_server) =
            tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

        println!(
            "client wrote {} bytes and received {} bytes",
            from_client, from_server
        );

        Ok(())
    }
}
