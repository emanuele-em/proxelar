use eframe::egui::{self};
use egui_extras::TableRow;

use crate::PADDING;

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
            request: Some(Request {
                path: format!("path"),
                method: format!("method"),
                status: format!("status"),
                size: format!("size"),
                time: format!("time"),
            }),
            response: None,
            details: None,
        }
    }
}

impl RequestInfo {
    pub fn show_request(&mut self, ui: &mut egui::Ui) {
        let r = self.request.as_ref().unwrap();
        ui.heading("Path");
        ui.label(&r.path);

        ui.heading("Method");
        ui.label(&r.method);

        ui.heading("Status");
        ui.label(&r.status);

        ui.heading("Size");
        ui.label(&r.size);

        ui.heading("Time");
        ui.label(&r.time);
    }

    pub fn show_response(&mut self, ui: &mut egui::Ui) {
        if let Some(r) = &self.response {
            ui.heading("Path");
            ui.label(&r.path);

            ui.heading("Method");
            ui.label(&r.method);

            ui.heading("Status");
            ui.label(&r.status);

            ui.heading("Size");
            ui.label(&r.size);

            ui.heading("Time");
            ui.label(&r.time);
        } else {
            ui.label("No Response");
        }
    }

    pub fn show_details(&mut self, ui: &mut egui::Ui) {
        if let Some(d) = &self.details {
            ui.heading("Path");
            ui.label(&d.path);

            ui.heading("Method");
            ui.label(&d.method);

            ui.heading("Status");
            ui.label(&d.status);

            ui.heading("Size");
            ui.label(&d.size);

            ui.heading("Time");
            ui.label(&d.time);
        } else {
            ui.label("No Details");
        }
    }

    pub fn render_row(&mut self, row: &mut TableRow) {
        let r = self.request.as_ref().unwrap();
        row.col(|ui| {
            ui.label(r.path.to_string());
        });

        row.col(|ui| {
            ui.label(r.method.to_string());
        });

        row.col(|ui| {
            ui.label(r.status.to_string());
        });

        row.col(|ui| {
            ui.label(r.size.to_string());
        });

        row.col(|ui| {
            ui.label(r.time.to_string());
        });

    }
}

struct Request {
    path: String,
    method: String,
    status: String,
    size: String,
    time: String,
}

pub struct Response {
    path: String,
    method: String,
    status: String,
    size: String,
    time: String,
}

pub struct Details {
    path: String,
    method: String,
    status: String,
    size: String,
    time: String,
}
