use std::{
    default,
    fmt::{format, Display},
    sync::mpsc::Receiver,
};

use crate::{
    requests::{InfoOptions, RequestInfo},
    PADDING,
};

use eframe::{
    egui::{
        self, ComboBox, FontData, FontDefinitions, FontFamily, Grid, Layout, RichText, ScrollArea,
        Style, TextStyle::*, TopBottomPanel, Visuals,
    },
    epaint::FontId,
    Frame,
};
use egui_extras::{Column, TableBuilder};
use proxyapi::{hyper::Method, *};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct MitmProxyConfig {
    dark_mode: bool,
    striped: bool,
    resizable: bool,
    row_height: Option<f32>,
    scroll_to_row_slider: usize,
    scroll_to_row: Option<usize>,
}

impl Default for MitmProxyConfig {
    fn default() -> Self {
        Self {
            dark_mode: true,
            striped: true,
            resizable: false,
            row_height: None,
            scroll_to_row_slider: 0,
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
}

impl MitmProxyState {
    fn new() -> Self {
        Self {
            selected_request: None,
            selected_request_method: MethodFilter::All,
            detail_option: InfoOptions::Request,
        }
    }
}

pub struct MitmProxy {
    requests: Vec<RequestInfo>,
    config: MitmProxyConfig,
    state: MitmProxyState,
    rx: Receiver<Output>,
}

impl MitmProxy {
    pub fn new(cc: &eframe::CreationContext<'_>, rx: Receiver<Output>) -> Self {
        Self::configure_fonts(cc);
        let config: MitmProxyConfig = confy::load("MitmProxy", None).unwrap_or_default();
        let state = MitmProxyState::new();

        MitmProxy {
            requests: vec![],
            config,
            state,
            rx,
        }
    }

    pub fn manage_theme(&mut self, ctx: &egui::Context) {
        match self.config.dark_mode {
            true => ctx.set_visuals(Visuals::dark()),
            false => ctx.set_visuals(Visuals::light()),
        }
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

    pub fn table_ui(&mut self, ui: &mut egui::Ui) {
        let text_height = match self.config.row_height {
            Some(h) => h,
            _ => egui::TextStyle::Button.resolve(ui.style()).size + PADDING,
        };

        let table = TableBuilder::new(ui)
            .auto_shrink([false; 2])
            .stick_to_bottom(true)
            .striped(self.config.striped)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::remainder().resizable(true).clip(true))
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::auto())
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
            .body(|mut body| {
                if let MethodFilter::Only(filter_method) = &self.state.selected_request_method {
                    for (row_index, request) in self
                        .requests
                        .iter()
                        .enumerate()
                        .filter(|r| r.1.should_show(&filter_method))
                    {
                        body.row(text_height, |mut row| {
                            request.render_row(&mut row);
                            row.col(|ui| {
                                if ui.button("🔎").clicked() {
                                    self.state.selected_request = Some(row_index);
                                }
                            });
                        });
                    }
                } else {
                    body.rows(text_height, self.requests.len(), |row_index, mut row| {
                        self.requests
                            .get_mut(row_index)
                            .expect("Problem with index")
                            .render_row(&mut row);
                        row.col(|ui| {
                            if ui.button("🔎").clicked() {
                                self.state.selected_request = Some(row_index);
                            }
                        });
                    })
                }
            });
    }

    pub fn render_right_panel(&mut self, ui: &mut egui::Ui, i: usize) {
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

    pub fn update_requests(&mut self) -> Option<RequestInfo> {
        match self.rx.try_recv() {
            Ok(l) => Some(RequestInfo::from(l)),
            _ => None,
        }
    }

    pub fn render_columns(&mut self, ui: &mut egui::Ui) {
        if let Some(request) = self.update_requests() {
            self.requests.push(request);
        }

        if let Some(i) = self.state.selected_request {
            ui.columns(2, |columns| {
                ScrollArea::both()
                    .id_source("requests_table")
                    .show(&mut columns[0], |ui| self.table_ui(ui));

                ScrollArea::vertical()
                    .id_source("request_details")
                    .show(&mut columns[1], |ui| {
                        self.render_right_panel(ui, i);
                    });
            })
        } else {
            ScrollArea::vertical()
                .id_source("requests_table")
                .show(ui, |ui| self.table_ui(ui));
        }
    }

    pub fn render_top_panel(&mut self, ctx: &egui::Context, frame: &mut Frame) {
        TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(PADDING);
            egui::menu::bar(ui, |ui| -> egui::InnerResponse<_> {
                ui.with_layout(Layout::left_to_right(eframe::emath::Align::Min), |ui| {
                    let clean_btn = ui.button("🚫").on_hover_text("Clear");

                    if clean_btn.clicked() {
                        self.requests = vec![];
                    }

                    ui.separator();

                    const COMBOBOX_TEXT_SIZE: f32 = 15.;
                    ComboBox::from_label("")
                        .selected_text(
                            RichText::new(format!(
                                "{} Requests",
                                &self.state.selected_request_method
                            ))
                            .size(COMBOBOX_TEXT_SIZE),
                        )
                        .wrap(false)
                        .show_ui(ui, |ui| {
                            ui.style_mut().wrap = Some(false);
                            for (method_str, method) in MethodFilter::METHODS {
                                ui.selectable_value(
                                    &mut self.state.selected_request_method,
                                    method,
                                    RichText::new(method_str).size(COMBOBOX_TEXT_SIZE),
                                );
                            }
                        });
                });

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
}
