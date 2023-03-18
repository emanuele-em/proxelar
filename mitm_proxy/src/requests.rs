use eframe::{
    egui::{self, Visuals},
    epaint::Color32,
};
use egui_extras::TableRow;
use proxyapi::{*, hyper::Method};

#[derive(Clone)]
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

#[derive(Clone)]
pub struct RequestInfo {
    request: Option<ProxiedRequest>,
    response: Option<ProxiedResponse>,
    details: Option<Details>,
}
impl RequestInfo {
    pub fn new(request: Option<ProxiedRequest>, response: Option<ProxiedResponse>)->Self{
        Self {
            request,
            response,
            details:None
        }
    }
}
impl RequestInfo {
    pub fn show_request(&self, ui: &mut egui::Ui) {
        if let Some(r) = &self.request {
            ui.strong("Method");
            ui.label(r.method().to_string());

            ui.strong("Version");
            ui.label(format!("{:?}",r.version()));

            ui.strong("Headers");
            for (k, v) in r.headers().iter() {
                if let Ok(value_str) = v.to_str(){
                    ui.label(format!("{}: {}", &k, &value_str));
                }
            }

            ui.strong("Body");
            ui.label(format!("{:?}",r.body().as_ref()));

            ui.strong("Time");
            ui.label(&r.time().to_string());
        } else {
            ui.label("No requests");
        }
    }

    pub fn show_response(&self, ui: &mut egui::Ui) {
        if let Some(r) = &self.response {
            ui.strong("Status");
            ui.label(&r.status().to_string());

            ui.strong("Version");
            ui.label(format!("{:?}",r.version()));

            ui.strong("Headers");
            for (k, v) in r.headers().iter() {
                if let Ok(value_str) = v.to_str(){
                    ui.label(format!("{}: {}", &k, &value_str));
                }
            }

            ui.strong("Body");
            ui.label(format!("{:?}",r.body().as_ref()));

            ui.strong("Time");
            ui.label(&r.time().to_string());
        } else {
            ui.label("No Response");
        }
    }

    pub fn should_show(&self, method:&Method)->bool {
        if let Some(req) = &self.request {
            req.method() == method
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
        let time = (res.time() as f64 - req.time() as f64) * 10_f64.powf(-9.0) as f64;
        let time = f64::trunc(time * 1000.);
        row.col(|ui| {
            ui.label(req.uri().to_string());
        });

        row.col(|ui| {
            let method = req.method();
            let color = Self::get_method_color(&method, ui.visuals());
            ui.colored_label(color, method.to_string());
        });

        row.col(|ui| {
            ui.label(res.status().to_string());
        });

        row.col(|ui| {
            ui.label(format!("{} b", res.body().len()));
        });

        row.col(|ui| {
            ui.label(time.to_string());
        });
    }

    fn get_method_color(method: &Method, visuals: &Visuals) -> Color32 {
        if visuals.dark_mode {
            match *method {
                Method::POST => Color32::from_rgb(73, 204, 144),
                Method::GET => Color32::from_rgb(97, 175, 254),
                Method::PUT => Color32::from_rgb(252, 161, 48),
                Method::DELETE => Color32::from_rgb(249, 62, 62),
                Method::OPTIONS => Color32::from_rgb(13, 90, 167),
                Method::HEAD => Color32::from_rgb(144, 18, 254),
                Method::PATCH => Color32::from_rgb(80, 227, 194),
                _ => Color32::LIGHT_GRAY,
            }
        } else {
            match *method {
                Method::POST => Color32::from_rgb(72, 203, 144),
                Method::GET => Color32::from_rgb(42, 105, 167),
                Method::PUT => Color32::from_rgb(213, 157, 88),
                Method::DELETE => Color32::from_rgb(200, 50, 50),
                Method::OPTIONS => Color32::from_rgb(36, 89, 143),
                Method::HEAD => Color32::from_rgb(140, 63, 207),
                Method::PATCH => Color32::from_rgb(92, 214, 188),
                _ => Color32::DARK_GRAY,
            }
        }
    }
}
