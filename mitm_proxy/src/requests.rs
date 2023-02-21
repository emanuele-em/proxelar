use std::collections::HashMap;

use eframe::egui::{self};
use egui_extras::TableRow;
use proxyapi::{*, hyper::Method};

struct Request {
    http_method: Method,    
    method: String,
    uri: String,
    version: String,
    headers: HashMap<String, String>,
    body: String,
    time: i64,
}

impl Request {
    fn new(
        http_method: Method,
        method: String,
        uri: String,
        version: String,
        headers: HashMap<String, String>,
        body: String,
        time: i64,
    ) -> Self {
        Self {
            http_method,
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

impl Response {
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
}

pub struct Details;

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
        RequestInfo {
            request: None,
            response: None,
            details: None,
        }
    }
}

impl From<Output> for RequestInfo {
    fn from(value: Output) -> Self {
        let request = match value.req() {
            Some(r) => Some(Request::new(
                r.http_method().clone(),
                r.method().to_string(),
                r.uri().to_string(),
                r.version().to_string(),
                r.headers()
                    .into_iter()
                    .map(|h| (h.0.to_string(), h.1.to_string()))
                    .collect(),
                r.body().to_string(),
                r.time(),
            )),
            None => None,
        };

        let response = match value.res() {
            Some(r) => Some(Response::new(
                r.status().to_string(),
                r.version().to_string(),
                r.headers()
                    .into_iter()
                    .map(|h| (h.0.to_string(), h.1.to_string()))
                    .collect(),
                r.body().to_string(),
                r.time(),
            )),
            None => None,
        };

        let details = None;

        RequestInfo {
            request,
            response,
            details,
        }
    }
}

impl RequestInfo {
    pub fn show_request(&mut self, ui: &mut egui::Ui) {
        if let Some(r) = &self.request {
            ui.strong("Method");
            ui.label(&r.method);

            ui.strong("Version");
            ui.label(&r.version);

            ui.strong("Headers");
            for (k, v) in r.headers.iter() {
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
            for (k, v) in r.headers.iter() {
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

    pub fn should_show(&self, method:&Method)->bool {
        if let Some(req) = &self.request {
            req.http_method == method
        }else{
            false
        }
    }

    pub fn show_details(&mut self, ui: &mut egui::Ui) {
        ui.label(match &self.details {
            Some(_) => "Some details",
            None => "No details",
        });
    }

    pub fn render_row(&self, row: &mut TableRow) {
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
            ui.label(format!("{} bytes", &res.body.len()));
        });

        row.col(|ui| {
            ui.label(time.to_string());
        });
    }
}
