use std::{fmt::Display, net::SocketAddr};

use crate::{
    managed_proxy::ManagedProxy,
    requests::{InfoOptions, RequestInfo},
    FONT_SIZE, PADDING,
};

use eframe::{
    egui::{
        self, popup, ComboBox, FontData, FontDefinitions, FontFamily, Grid, Layout, RichText,
        ScrollArea, Style, TextEdit, TextStyle::*, TopBottomPanel, Visuals,
    },
    emath::Align2,
    epaint::{Color32, FontId},
    Frame,
};
use egui_extras::{Column, TableBuilder};
use proxyapi::hyper::Method;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct MitmProxyConfig {
    dark_mode: bool,
    striped: bool,
    resizable: bool,
    row_height: Option<f32>,
    scroll_to_row: Option<usize>,
}

impl Default for MitmProxyConfig {
    fn default() -> Self {
        Self {
            dark_mode: true,
            striped: true,
            resizable: false,
            row_height: None,
            scroll_to_row: None,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub enum MethodFilter {
    #[default]
    All,
    Only(Method),
}
impl MethodFilter {
    const METHODS: [(&'static str, Self); 10] = [
        ("All", MethodFilter::All),
        ("GET", MethodFilter::Only(Method::GET)),
        ("POST", MethodFilter::Only(Method::POST)),
        ("PUT", MethodFilter::Only(Method::PUT)),
        ("DELETE", MethodFilter::Only(Method::DELETE)),
        ("PATCH", MethodFilter::Only(Method::PATCH)),
        ("HEAD", MethodFilter::Only(Method::HEAD)),
        ("OPTIONS", MethodFilter::Only(Method::OPTIONS)),
        ("CONNECT", MethodFilter::Only(Method::CONNECT)),
        ("TRACE", MethodFilter::Only(Method::TRACE)),
    ];
}
impl Display for MethodFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Self::Only(method) = self {
            Display::fmt(method, f)
        } else {
            f.write_str("All")
        }
    }
}

struct MitmProxyState {
    selected_request: Option<usize>,
    selected_request_method: MethodFilter,
    detail_option: InfoOptions,
    listen_on: String,
}

impl MitmProxyState {
    fn new() -> Self {
        Self {
            selected_request: None,
            selected_request_method: MethodFilter::All,
            detail_option: InfoOptions::Request,
            listen_on: "127.0.0.1:8100".to_string(),
        }
    }
}

pub struct MitmProxy {
    requests: Vec<RequestInfo>,
    config: MitmProxyConfig,
    state: MitmProxyState,
    proxy: Option<ManagedProxy>,
}

impl MitmProxy {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::configure_fonts(cc);
        let config: MitmProxyConfig = confy::load("MitmProxy", None).unwrap_or_default();
        let state = MitmProxyState::new();

        MitmProxy {
            requests: vec![],
            config,
            state,
            proxy: None,
        }
    }

    pub fn manage_theme(&mut self, ctx: &egui::Context) {
        match self.config.dark_mode {
            true => ctx.set_visuals(Visuals::dark()),
            false => ctx.set_visuals(Visuals::light()),
        }
    }

    fn start_proxy(&mut self, addr: SocketAddr) {
        assert!(self.proxy.is_none());

        self.proxy = Some(ManagedProxy::new(addr));
        self.requests = vec![];
    }

    fn stop_proxy(&mut self){
        if self.proxy.is_some() {
            self.proxy.take();
            self.state.selected_request.take();
        }
    }

    fn is_listening(&self) -> bool {
        return self.proxy.is_some();
    }

    fn configure_fonts(cc: &eframe::CreationContext<'_>) {
        let mut fonts = FontDefinitions::default();

        fonts.font_data.insert(
            "OpenSans".to_owned(),
            FontData::from_static(include_bytes!("../../fonts/OpenSans.ttf")),
        );

        fonts
            .families
            .get_mut(&FontFamily::Proportional)
            .unwrap()
            .insert(0, "OpenSans".to_owned());

        cc.egui_ctx.set_fonts(fonts);

        let mut style = Style::default();

        style.text_styles = [
            (Heading, FontId::new(30.0, FontFamily::Proportional)),
            (Body, FontId::new(12., FontFamily::Proportional)),
            (Button, FontId::new(20.0, FontFamily::Proportional)),
        ]
        .into();

        cc.egui_ctx.set_style(style);
    }

    pub fn table_ui(&mut self,frame: &mut eframe::Frame, ui: &mut egui::Ui) {
        let text_height = match self.config.row_height {
            Some(h) => h,
            _ => egui::TextStyle::Button.resolve(ui.style()).size + PADDING,
        };

        let table = TableBuilder::new(ui)
            .auto_shrink([false;2])
            .stick_to_bottom(true)
            .striped(self.config.striped)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::exact( match self.state.selected_request.is_some() {
                true => (frame.info().window_info.size.x - 320.) / 2. - 220.,
                false => frame.info().window_info.size.x - 320. - 55.
            }))
            .column(Column::exact(50.))
            .column(Column::exact(100.))
            .column(Column::exact(50.))
            .column(Column::exact(50.))
            .column(Column::exact(70.))
            .min_scrolled_height(0.0);

        //table = table.scroll_to_row(self.requests.len(), None);

        table
            .header(PADDING, |mut header| {
                header.col(|ui| {
                    ui.strong("Path");
                });

                header.col(|ui| {
                    ui.strong("Method");
                });

                header.col(|ui| {
                    ui.strong("Status");
                });

                header.col(|ui| {
                    ui.strong("Size");
                });

                header.col(|ui| {
                    ui.strong("Time");
                });

                header.col(|_ui| ());
            })
            .body(|body| {
                let mut requests = self.requests.clone();

                if let MethodFilter::Only(filter_method) = &self.state.selected_request_method {
                    requests = requests
                        .drain(..)
                        .filter(|r| r.should_show(filter_method))
                        .collect();
                }

                body.rows(text_height, requests.len(), |row_index, mut row| {
                    requests
                        .get_mut(row_index)
                        .expect("Problem with index")
                        .render_row(&mut row);
                    row.col(|ui| {
                        if self.state.selected_request == Some(row_index) {
                            if ui.button(RichText::new("✖").size(FONT_SIZE)).clicked() {
                                self.state.selected_request = None;
                                self.requests.remove(row_index);
                            }
                        } else if ui.button(RichText::new("🔎").size(FONT_SIZE)).clicked() {
                            self.state.selected_request = Some(row_index);
                        }
                        if ui.button(RichText::new("🗑 ").size(FONT_SIZE)).clicked() {
                            self.state.selected_request = None;
                            self.requests.remove(row_index);
                        }
                    });
                });
            });
    }

    pub fn render_right_panel(&mut self, ui: &mut egui::Ui, i: usize) {
        if self.requests.is_empty() || i >= self.requests.len() {
            return;
        }
        Grid::new("controls").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(
                    &mut self.state.detail_option,
                    InfoOptions::Request,
                    "Request",
                );
                ui.selectable_value(
                    &mut self.state.detail_option,
                    InfoOptions::Response,
                    "Response",
                );
                ui.selectable_value(
                    &mut self.state.detail_option,
                    InfoOptions::Details,
                    "Details",
                );
            });
        });

        ui.separator();

        ScrollArea::vertical()
            .id_source("details")
            .show(ui, |ui| match self.state.detail_option {
                InfoOptions::Request => self.requests[i].show_request(ui),
                InfoOptions::Response => self.requests[i].show_response(ui),
                InfoOptions::Details => self.requests[i].show_details(ui),
            });
    }

    pub fn render_columns(&mut self,frame: &mut eframe::Frame,  ctx: &egui::Context, ui: &mut egui::Ui) {
        if !self.is_listening() {
            egui::Window::new("Modal Window")
                .title_bar(false)
                .resizable(false)
                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                .default_height(30.0)
                .show(ctx, |ui| {
                    ui.horizontal_centered(|ui| {
                        ScrollArea::neither().show(ui, |ui| {
                            ui.label("Listen on:");
                            TextEdit::singleline(&mut self.state.listen_on).show(ui);
                            match self.state.listen_on.parse::<SocketAddr>() {
                                Ok(addr) => {
                                    let start_button = ui.button("▶").on_hover_text("Start");
                                    if start_button.clicked() {
                                        self.start_proxy(addr);
                                    }
                                }
                                Err(_err) => {
                                    ui.label(
                                        RichText::new("Provided invalid IP address")
                                            .color(Color32::RED),
                                    );
                                }
                            };
                        });
                    });
                });

            return;
        }

        if let Some(ref mut proxy) = self.proxy {
            if let Some(request) = proxy.try_recv_request() {
                self.requests.push(request);
            }
        }

        if let Some(i) = self.state.selected_request {
            ui.columns(2, |columns| {
                ScrollArea::vertical()
                    .id_source("requests_table")
                    .auto_shrink([false;2])
                    .show(&mut columns[0], |ui| self.table_ui(frame, ui));

                ScrollArea::vertical()
                    .id_source("request_details")
                    .show(&mut columns[1], |ui| {
                        self.render_right_panel(ui, i);
                    });
            })
        } else {
            ScrollArea::vertical()
                .id_source("requests_table")
                .show(ui, |ui| self.table_ui(frame, ui));
        }
    }

    pub fn render_top_panel(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(PADDING);

            egui::menu::bar(ui, |ui| -> egui::InnerResponse<_> {
                if self.is_listening() {
                    ui.with_layout(Layout::left_to_right(eframe::emath::Align::Min), |ui| {
                        let clean_btn = ui.button("🚫").on_hover_text("Clear");

                        if clean_btn.clicked() {
                            self.requests = vec![];
                            self.state.selected_request = None;
                        }

                        ui.separator();

                        ComboBox::from_label("")
                            .selected_text(
                                RichText::new(format!(
                                    "{} Requests",
                                    &self.state.selected_request_method
                                ))
                                .size(FONT_SIZE),
                            )
                            .wrap(false)
                            .show_ui(ui, |ui| {
                                ui.style_mut().wrap = Some(false);
                                for (method_str, method) in MethodFilter::METHODS {
                                    if ui
                                        .selectable_value(
                                            &mut self.state.selected_request_method,
                                            method,
                                            RichText::new(method_str).size(FONT_SIZE),
                                        )
                                        .clicked()
                                    {
                                        self.state.selected_request = None
                                    };
                                }
                            });
                    });
                }

                ui.with_layout(Layout::right_to_left(eframe::emath::Align::Min), |ui| {
                    let theme_btn = ui
                        .button(match self.config.dark_mode {
                            true => "🔆",
                            false => "🌙",
                        })
                        .on_hover_text("Toggle theme");

                    if theme_btn.clicked() {
                        self.config.dark_mode = !self.config.dark_mode
                    }
                })
            });
            ui.add_space(PADDING);
        });
    }

    pub fn render_bottom_panel(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        if self.is_listening() {
                egui::Window::new("bottom_stop")
                .title_bar(false)
                .resizable(false)
                .anchor(Align2::CENTER_BOTTOM, [0.0, -10.0])
                .default_height(30.0)
                .show(ctx, |ui|{
                    ui.horizontal_centered(|ui|{
                        ScrollArea::neither().show(ui, |ui| {
                            ui.label("Proxy listening on: ");
                            ui.label(RichText::new(&self.state.listen_on).color(Color32::DARK_GREEN));
                            let stop_button = ui.button(RichText::new("⏹").size(FONT_SIZE-3.0)).on_hover_text("Stop");
                            if stop_button.clicked() {
                                self.stop_proxy();
                            }
                        });
                    });
                });
        }
    }
}
