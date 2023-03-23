use std::sync::mpsc::SyncSender;

use async_trait::async_trait;
use http::{Request, Response};
use hyper::{body::to_bytes, Body};
pub use proxyapi_models::{ProxiedRequest, ProxiedResponse};

use crate::{HttpContext, HttpHandler, RequestResponse};

#[derive(Clone, Debug)]
pub struct ProxyHandler {
    tx: SyncSender<ProxyHandler>,
    req: Option<ProxiedRequest>,
    res: Option<ProxiedResponse>,
}

impl ProxyHandler {
    pub fn new(tx: SyncSender<ProxyHandler>) -> Self {
        Self {
            tx,
            req: None,
            res: None,
        }
    }

    pub fn to_parts(self) -> (Option<ProxiedRequest>, Option<ProxiedResponse>) {
        (self.req, self.res)
    }

    pub fn set_req(&mut self, req: ProxiedRequest) -> Self {
        Self {
            tx: self.clone().tx,
            req: Some(req),
            res: None,
        }
    }

    pub fn set_res(&mut self, res: ProxiedResponse) -> Self {
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

    pub fn req(&self) -> &Option<ProxiedRequest> {
        &self.req
    }

    pub fn res(&self) -> &Option<ProxiedResponse> {
        &self.res
    }
}

#[async_trait]
impl HttpHandler for ProxyHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        mut req: Request<Body>,
    ) -> RequestResponse {
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

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        mut res: Response<Body>,
    ) -> Response<Body> {
        //println!("res: {:?}\n\n", res);
        let mut body_mut = res.body_mut();
        let body_bytes = to_bytes(&mut body_mut).await.unwrap_or_default();
        *body_mut = Body::from(body_bytes.clone()); // Replacing the potentially mutated body with a reference to the entire contents

        let output_response = ProxiedResponse::new(
            res.status(),
            res.version(),
            res.headers().clone(),
            body_bytes,
            chrono::Local::now().timestamp_nanos(),
        );

        self.set_res(output_response).send_output();

        //Self::sanitize_body(res.body_mut());
        res
    }
}
