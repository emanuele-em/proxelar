use std::collections::HashMap;

use eframe::egui::{self};
use egui_extras::TableRow;
use proxyapi::ProxyAPIResponse;
use rand::{Rng, distributions::uniform::SampleBorrow};

use crate::PADDING;

struct Request {
    method: String,
    uri: String,
    version: String,
    headers: HashMap<String, String>,
    body: String,
    time: i64
}

impl Request{
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
            time,
        }
    }
}

pub struct Response {
    status: String,
    version: String,
    headers: HashMap<String, String>,
    body: String,
    time: i64,
}

impl Response{
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
}

pub struct Details;

impl Details{
    fn new() -> Self{
        Self
    }
}

#[derive(PartialEq)]
pub enum InfoOptions {
    Request,
    Response,
    Details,
}

impl Default for InfoOptions {
    fn default() -> Self {
        InfoOptions::Request
    }
}
pub struct RequestInfo {
    request: Option<Request>,
    response: Option<Response>,
    details: Option<Details>,
}

impl Default for RequestInfo {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let a = rng.gen::<u32>();
        RequestInfo {
            request: None,
            response: None,
            details: None,
        }
    }
}

impl From<ProxyAPIResponse> for RequestInfo{
    fn from(value: ProxyAPIResponse) -> Self {

        let request = if let r = value.req(){
            Some(Request::new(
                r.method().to_string(),
               r.uri().to_string(),
               r.version().to_string(),
               r.headers().into_iter().map(|h| (h.0.to_string(), h.1.to_string())).collect(),
               r.body().to_string(),
               r.time()
           ))
        } else {
            None
        };
        

        let response = if let Some(r) = value.res(){
            Some(
                Response::new(
                    r.status().to_string(),
                    r.version().to_string(),
                    r.headers().into_iter().map(|h| (h.0.to_string(), h.1.to_string())).collect(),
                    r.body().to_string(),
                    r.time(),
                )
            )
        } else {
            None
        };

        let details = None;

        RequestInfo { request, response, details }
    }
}

impl RequestInfo {

    pub fn show_request(&mut self, ui: &mut egui::Ui) {
        if let Some(r) = &self.request {
            ui.strong("Method");
            ui.label(&r.method);

            ui.strong("Method");
            ui.label(&r.method);

            ui.strong("Version");
            ui.label(&r.version);

            ui.strong("Headers");
            for (k, v) in r.headers.iter(){
                ui.label(format!("{}: {}", &k, &v));
            }

            ui.strong("body");
            ui.label(&r.body);

            ui.strong("Time");
            ui.label(&r.time.to_string());
        } else {
            ui.label("No requests");
        }
    }

    pub fn show_response(&mut self, ui: &mut egui::Ui) {
        if let Some(r) = &self.response {
            ui.strong("Status");
            ui.label(&r.status);

            ui.strong("Version");
            ui.label(&r.version);

            ui.strong("Status");
            ui.label(&r.status);

            ui.strong("Headers");
            for (k, v) in r.headers.iter(){
                ui.label(format!("{}: {}", &k, &v));
            }

            ui.strong("body");
            ui.label(&r.body);

            ui.strong("Time");
            ui.label(&r.time.to_string());
        } else {
            ui.label("No Response");
        }
    }

    pub fn show_details(&mut self, ui: &mut egui::Ui) {
        if let Some(d) = &self.details {
            ui.label("some details");
        } else {
            ui.label("No Details");
        }
    }

    pub fn render_row(&mut self, row: &mut TableRow) {
        let req = self.request.as_ref().unwrap();
        let res = self.response.as_ref().unwrap();
        let time = (res.time as f64 - req.time as f64) * 10_f64.powf(-9.0) as f64;
        row.col(|ui| {
            ui.label(&req.uri);
        });

        row.col(|ui| {
            ui.label(&req.method);
        });

        row.col(|ui| {
            ui.label(&res.status);
        });

        row.col(|ui| {
            ui.label(&res.body);
        });

        row.col(|ui| {
            ui.label(time.to_string());
        });

    }
}


