use std::{collections::HashMap, sync::mpsc::SyncSender};


use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Version, Response, Request, Method, Uri, StatusCode};
use hyper::{Body, body::to_bytes};

use crate::{HttpHandler, HttpContext, RequestResponse};

#[derive(Clone, Debug)]
pub struct ProxyHandler{
    tx: SyncSender<ProxyHandler>,
    req: Option<ProxiedRequest>,
    res: Option<ProxiedResponse>
}

impl ProxyHandler {
    pub fn new(tx: SyncSender<ProxyHandler>) -> Self {
        Self { tx, req: None, res: None }
    }

    pub fn to_parts(self) -> (Option<ProxiedRequest>, Option<ProxiedResponse>) {
        (self.req,self.res)
    }

    pub fn set_req(&mut self, req: ProxiedRequest) -> Self {
        Self { 
            tx: self.clone().tx, 
            req: Some(req),
            res: None,
        }
    }

    pub fn set_res(&mut self, res: ProxiedResponse) -> Self{
        Self { 
            tx: self.clone().tx, 
            req: self.clone().req,
            res: Some(res),
        }
    }

    pub fn send_output(self) {
        if let Err(e) = self.tx.send(self.clone()) {
            eprintln!("Error on sending Response to main thread: {}", e);
        }
    }

    pub fn req(&self) -> &Option<ProxiedRequest>{
        &self.req
    }

    pub fn res(&self) -> &Option<ProxiedResponse>{
        &self.res
    }
}


#[async_trait]
impl HttpHandler for ProxyHandler {
    async fn handle_request(&mut self, _ctx: &HttpContext, mut req: Request<Body>, ) -> RequestResponse {
        //println!("request{:?}\n", req);
        let mut body_mut = req.body_mut();
        let body_bytes = to_bytes(&mut body_mut).await.unwrap_or_default();
        *body_mut = Body::from(body_bytes.clone()); // Replacing the potentially mutated body with a reference to the entire contents
        
        let output_request = ProxiedRequest::new(
            req.method().clone(),
            req.uri().clone(),
            req.version(),
            req.headers().clone(),
            body_bytes,
            chrono::Local::now().timestamp_nanos(),
        );
        *self = self.set_req(output_request);
        
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, mut res: Response<Body>) -> Response<Body> {
        //println!("res: {:?}\n\n", res);
        let mut body_mut = res.body_mut();
        let body_bytes = to_bytes(&mut body_mut).await.unwrap_or_default();
        *body_mut = Body::from(body_bytes.clone()); // Replacing the potentially mutated body with a reference to the entire contents
        
        let output_response =  ProxiedResponse::new(
            res.status(),
            res.version(),
            res.headers().clone(),
            body_bytes,
            chrono::Local::now().timestamp_nanos()
        );

        self
        .set_res(output_response)
        .send_output();

        //Self::sanitize_body(res.body_mut());
        res
    }
    
}

#[derive(Debug,Clone)]
pub struct ProxiedRequest {
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
    time: i64,
}

impl ProxiedRequest {
    fn new(
        method: Method,
        uri: Uri,
        version: Version,
        headers: HeaderMap,
        body: Bytes,
        time: i64,
    ) -> Self {
        Self {
            method,
            uri,
            version,
            headers,
            body,
            time,
        }
    }


    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    pub fn time(&self) -> i64 {
        self.time
    }
}


#[derive(Debug,Clone)]
pub struct ProxiedResponse {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
    time: i64,
}


impl ProxiedResponse {
    fn new(
        status: StatusCode,
        version: Version,
        headers: HeaderMap,
        body: Bytes,
        time: i64,
    ) -> Self {
        Self {
            status,
            version,
            headers,
            body,
            time,
        }
    }

    pub fn status(&self) -> &StatusCode {
        &self.status
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    pub fn time(&self) -> i64 {
        self.time
    }
}

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

