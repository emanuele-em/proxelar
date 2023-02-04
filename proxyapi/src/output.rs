use std::{collections::HashMap, sync::mpsc::SyncSender, ops::Deref};


use async_trait::async_trait;
use http::{HeaderMap, Version, Response, Request};
use hyper::{Body, body::HttpBody};

use crate::{HttpHandler, HttpContext, RequestResponse};

#[derive(Clone, Debug)]
pub struct Output{
    tx: SyncSender<Output>,
    req: Option<OutputRequest>,
    res: Option<OutputResponse>
}

impl Output {
    pub fn new(tx: SyncSender<Output>) -> Self {
        Self { tx, req: None, res: None }
    }

    async fn get_body(body: &mut Body) -> String{
        if let Some(body) = body.data().await {
            return body.unwrap()
            .to_vec()
            .iter()
            .map(|c| c.to_string())
            .collect::<String>()
        }

        "".to_string()
        
    }

    pub fn set_req(&mut self, req: OutputRequest) -> Self{
        Self { 
            tx: self.clone().tx, 
            req: Some(req),
            res: None,
        }
    }

    pub fn set_res(&mut self, res: OutputResponse) -> Self{
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

    pub fn req(&self) -> &Option<OutputRequest>{
        &self.req
    }

    pub fn res(&self) -> &Option<OutputResponse>{
        &self.res
    }
}

#[async_trait]
impl HttpHandler for Output {
    async fn handle_request(&mut self, _ctx: &HttpContext, mut req: Request<Body>, ) -> RequestResponse {
        println!("request{:?}\n", req);
        let output_request = OutputRequest::new(
            req.method().to_string(),
            req.uri().to_string(),
            req.version().to_string(),
            req.headers().to_hash_string(),
            Self::get_body(req.body_mut()).await,
            chrono::Local::now().timestamp_nanos(),
        );

        *self = self.set_req(output_request);
        
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, mut res: Response<Body>) -> Response<Body> {
        println!("res: {:?}\n\n", res);

        let output_response =  OutputResponse::new(
            res.status().to_string(),
            res.version().to_string(),
            res.headers().to_hash_string(),
            Self::get_body(res.body_mut()).await,
            chrono::Local::now().timestamp_nanos()
        );

        self
        .set_res(output_response)
        .send_output();
        
        res
    }
    
}

#[derive(Clone, Debug)]
pub struct OutputRequest {
    method: String,
    uri: String,
    version: String,
    headers: HashMap<String, String>,
    body: String,
    time: i64,
}

impl OutputRequest {
    fn new(
        method: String,
        uri: String,
        version: String,
        headers: HashMap<String, String>,
        body: String,
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

    pub fn method(&self) -> &String {
        &self.method
    }

    pub fn uri(&self) -> &String {
        &self.uri
    }

    pub fn version(&self) -> &String {
        &self.version
    }

    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn body(&self) -> &String {
        &self.body
    }

    pub fn time(&self) -> i64 {
        self.time
    }
}

#[derive(Clone, Debug)]
pub struct OutputResponse {
    status: String,
    version: String,
    headers: HashMap<String, String>,
    body: String,
    time: i64,
}

impl OutputResponse {
    fn new(
        status: String,
        version: String,
        headers: HashMap<String, String>,
        body: String,
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

    pub fn status(&self) -> &String {
        &self.status
    }

    pub fn version(&self) -> &String {
        &self.version
    }

    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn body(&self) -> &String {
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

