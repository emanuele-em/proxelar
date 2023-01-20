mod app;
pub use app::MitmApp;

use std::net::SocketAddr;
use std::result;

use bytes::Bytes;

use http_body_util::{Empty, Full, BodyExt};
use http_body_util::combinators::BoxBody;
use hyper::client::conn::http1::Builder;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};

use tokio::net::{TcpListener, TcpStream};

static ADDR: std::net::SocketAddr = SocketAddr::from(([127, 0, 0, 1], 8100));

pub fn get_string_from_lib() -> String{
    String::from("hol!")
}



pub async fn init() -> Result<TcpListener, Box<dyn std::error::Error>> {

    let listener = TcpListener::bind(ADDR).await?;
    Ok(listener)

}

pub async fn listen(addr: SocketAddr, listener: TcpListener) -> Result<(), Box<dyn std::error::Error>>{
    let (stream, _) = listener.accept().await?;

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(stream, service_fn(proxy))
                .with_upgrades()
                .await
            {
                eprintln!("Failed to serve connection: {:?}", err);
            }
        });
    Ok(())
}

async fn proxy(
    req: Request<hyper::body::Incoming>
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {


    if req.method() == Method::CONNECT {
        if let Some(addr) = host_addr(req.uri()){
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(err) = tunnel(upgraded, addr).await{
                            eprintln!("server io error: {}", err);
                        };
                    },
                    Err(err) => eprintln!("upgrade error: {}", err),
                }
            });

            Ok(Response::new(empty()))
        } else {
            eprintln!("CONNECT host is not a socked addr: {:?}", req.uri());
            let mut resp = Response::new(full("CONNECT must be to a socket addr"));
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

        tokio::task::spawn( async move {
            if let Err(err) = conn.await {
                eprintln!("Connection failed:{:?}", err)
            }
        });

        let resp = sender.send_request(req).await?;
        
        Ok(resp.map(|b| b.boxed()))
        

    }
    
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
fn full< T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(| never | match never {})
        .boxed()
}

fn host_addr(uri: &hyper::Uri) -> Option<String> {
    uri.authority().and_then(|u| Some(u.to_string()))
}

async fn tunnel(mut upgraded: Upgraded, addr: String) -> std::io::Result<()>{
    let mut server = TcpStream::connect(addr).await?;

    let (from_client, from_server) = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    println!("client wrote {} bytes and received {} bytes", from_client, from_server);

    Ok(())
}



