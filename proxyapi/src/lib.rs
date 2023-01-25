use std::net::SocketAddr;
use std::sync::mpsc::{SyncSender};

use bytes::Bytes;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::Builder;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};

use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

#[derive(Debug)]
pub struct ProxyAPI{
    pub listener: TcpListener,
    pub test: String
}

pub struct ProxyAPIResponse{
    req: String,
    res: Option<String>,
}

impl ProxyAPIResponse {
    
    fn new(req: String, res: Option<String>) -> Self{
        Self { req, res }
    }

}

impl ProxyAPI{
    
    pub async fn new(tx: SyncSender<ProxyAPIResponse>){
        let addr = SocketAddr::from(([127, 0, 0, 1], 8100));
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 8100))).await.unwrap();
        println!("Listening on http://{}", addr);

        let mut rt = Runtime::new().unwrap();
        
                loop {                    
                    if let Ok((stream, _)) = listener.accept().await{
                        let tx = tx.clone();
                        if let Err(err) = http1::Builder::new()
                            .preserve_header_case(true)
                            .title_case_headers(true)
                            .serve_connection(stream,service_fn(move |req| {
                                let tx = tx.clone();
                                Self::proxy(req, tx)
                            }))
                            .with_upgrades()
                            .await
                        {
                            eprintln!("Failed to serve connection: {:?}", err);
                        }
                    }
                }
        
    }



    async fn proxy(
        req: Request<hyper::body::Incoming>,
        tx : SyncSender<ProxyAPIResponse>,
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

                let res = Ok(Response::new(Self::empty()));
                tx.send(ProxyAPIResponse::new("test".to_string(), Some("test".to_string())));
                res
                //tx.send(ProxyAPIResponse::new());
                //Ok(Response::new(Self::empty()))
            } else {
                eprintln!("CONNECT host is not a socked addr: {:?}", req.uri());
                let mut resp = Response::new(Self::full("CONNECT must be to a socket addr"));
                *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                //tx.send(ProxyAPIResponse::new(req, resp));
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
            tx.send(ProxyAPIResponse::new("test".to_string(), Some("test".to_string())));
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
