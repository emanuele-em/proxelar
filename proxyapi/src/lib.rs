use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::mpsc::{SyncSender};

use bytes::Bytes;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Incoming};
use hyper::client::conn::http1::Builder;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, Version, HeaderMap};

use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use http_body_util;

trait ToString {
    fn to_string(&self) -> String;
}

trait ToHashString{
    fn to_hash_string(&self) -> HashMap<String, String>;
}

impl ToHashString for HeaderMap{
    fn to_hash_string(&self) -> HashMap<String, String>{
        let mut headers: HashMap<String, String> = HashMap::new();

        for (k, v) in self.iter(){
            headers.insert(k.as_str().to_string(), v.to_str().unwrap().to_string()).unwrap_or("NO header".to_string());
        }
        headers
    }
}

impl ToString for Version{
    fn to_string(&self) -> String{

        match *self {
            Version::HTTP_09 => "HTTP_09".to_string(),
            Version::HTTP_10 => "HTTP_10".to_string(),
            Version::HTTP_11 => "HTTP_11".to_string(),
            Version::HTTP_2 => "HTTP_2".to_string(),
            Version::HTTP_3 => "HTTP_3".to_string(),
            _ => "__NonExhaustive".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct ProxyAPI{
    pub listener: TcpListener,
    pub test: String
}

type Req = Request<Incoming>;
type Res = Response<BoxBody<Bytes, hyper::Error>>;

#[derive(Clone)]
pub struct ProxyAPIResponse{
    req: ReqResponse,
    res: Option<ResResponse>,
}

impl ProxyAPIResponse{
    fn new(req: ReqResponse, res: Option<ResResponse>) -> Self{
        Self { req, res }
    }

    pub fn req(&self) -> &ReqResponse{
        &self.req
    }
    
    pub fn res(&self) -> &Option<ResResponse>{
        &self.res
    }
}
#[derive(Clone)]
pub struct ReqResponse{
    method: String,
    uri: String,
    version: String,
    headers: HashMap<String, String>,
    body: String,
    time: i64,
}


impl ReqResponse {
    fn new(
        method: String,
        uri: String,
        version: String,
        headers: HashMap<String, String>,
        body: String,
        time: i64
    ) -> Self{
        Self { 
            method,
            uri,
            version,
            headers,
            body,
            time
        }
    }

    pub fn method(&self) -> &String{
        &self.method
    }

    pub fn uri(&self) -> &String{
        &self.uri
    }

    pub fn version(&self) -> &String{
        &self.version
    }

    pub fn headers(&self) -> &HashMap<String, String>{
        &self.headers
    }

    pub fn body(&self) -> &String{
        &self.body
    }

    pub fn time(&self) -> i64{
        self.time
    }
}

#[derive(Clone)]
pub struct ResResponse{
    status: String,
    version: String,
    headers: HashMap<String, String>,
    body: String,
    time: i64,
}

impl ResResponse {
    fn new(
        status: String,
        version: String,
        headers: HashMap<String, String>,
        body: String,
        time: i64
    ) -> Self{
        Self { 
            status,
            version,
            headers,
            body,
            time
         }
    }

    pub fn status(&self) -> &String{
        &self.status
    }

    pub fn version(&self) -> &String{
        &self.version
    }

    pub fn headers(&self) -> &HashMap<String, String>{
        &self.headers
    }

    pub fn body(&self) -> &String{
        &self.body
    }

    pub fn time(&self) -> i64{
        self.time
    }
}



impl ProxyAPI{
    
    pub async fn new(tx: SyncSender<ProxyAPIResponse>){
        let addr = SocketAddr::from(([127, 0, 0, 1], 8100));
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 8100))).await.unwrap();
        println!("Listening on http://{}", addr);
        
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

    

    async fn get_body(body: &mut Incoming) -> String{
        body.collect().await.unwrap().to_bytes().to_vec().iter().map(|c| c.to_string()).collect::<String>()
    }



    async fn proxy(
        mut req: Req,
        tx : SyncSender<ProxyAPIResponse>,
    ) -> Result<Res, hyper::Error> {

        // let req_response = ReqResponse::new(
        //     req.method().to_string(),
        //     req.uri().to_string(),
        //     req.version().to_string(),
        //     req.headers().to_hash_string(),
        //     Self::get_body(req.body_mut()).await,
        //     chrono::Local::now().timestamp_nanos()
        // );
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
                let res = Response::new(Self::empty()); 
                let res_response =  Some(ResResponse::new(
                    res.status().to_string(),
                    res.version().to_string(),
                    res.headers().to_hash_string(),
                    String::from(""),
                    chrono::Local::now().timestamp_nanos()
                ));
                // if let Err(e) = tx.send(ProxyAPIResponse { req: req_response, res: res_response }) {
                //     eprintln!("Error on sending Response to main thread: {}", e);
                // }

                Ok(res)
            } else {

                eprintln!("CONNECT host is not a socked addr: {:?}", req.uri());
                let body = Self::full("CONNECT must be to a socket addr");
                let mut res = Response::new(body);
                *res.status_mut() = hyper::StatusCode::BAD_REQUEST;
                
                let res_response =  Some(ResResponse::new(
                    res.status().to_string(),
                    res.version().to_string(),
                    res.headers().to_hash_string(),
                    String::from("CONNECT must be to a socket addr"),
                    chrono::Local::now().timestamp_nanos()
                ));

                // if let Err(e) = tx.send(ProxyAPIResponse { req: req_response, res: res_response }){
                //     eprintln!("Error on sending Response to main thread: {}", e);
                // }
                Ok(res)
            }


        } else {

            let host = req.uri().host().unwrap_or("/");
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

            let mut res = sender.send_request(req).await?; //send the request and wait the response
            let body = Self::get_body(res.body_mut()).await;
            let res =  res.map(|b| b.boxed());  
            
            

            let res_response =  Some(
                ResResponse::new(
                    res.status().to_string(), 
                    res.version().to_string(), 
                    res.headers().to_hash_string(),
                    body,
                    chrono::Local::now().timestamp_nanos()
                )
            );

            
            
            // if let Err(e) = tx.send(ProxyAPIResponse::new(req_response, res_response)){
            //     eprintln!("Error on sending Response to main thread: {}", e);
            // }
            Ok(res)
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
        let mut server = TcpStream::connect(addr).await?; //it should be the stream

        //addr is the https domain

        //let mut res = sender.send_request(req).await?; //send the request and wait the response

        let (from_client, from_server) =
            tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

        println!(
            "client wrote {} bytes and received {} bytes",
            from_client, from_server
        );

        Ok(())
    }
}
