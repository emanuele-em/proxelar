use std::{
    sync::mpsc::{channel, sync_channel, Receiver, SyncSender, Sender},
    thread,
};

use crate::{
    requests::{self, InfoOptions, RequestInfo},
    PADDING,
};

use eframe::{
    egui::{
        self, FontData, FontDefinitions, FontFamily, Grid, Layout, ScrollArea, Style, TextStyle::*,
        TopBottomPanel, Visuals,
    },
    epaint::FontId,
    Frame,
};
use egui_extras::{Column, TableBuilder};
use proxyapi::{ProxyAPI, ProxyAPIResponse};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

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

struct MitmProxyState {
    selected_request: Option<usize>,
    detail_option: InfoOptions,
}

impl MitmProxyState {
    fn new() -> Self {
        Self {
            selected_request: None,
            detail_option: InfoOptions::Request,
        }
    }
}

pub struct MitmProxy {
    listener_rx: Receiver<ProxyAPI>,
    listener: Option<ProxyAPI>,
    requests: Vec<RequestInfo>,
    config: MitmProxyConfig,
    state: MitmProxyState,

    tx: SyncSender<RequestInfo>,
    rx: Receiver<RequestInfo>,
}

impl MitmProxy {
    pub fn new(cc: &eframe::CreationContext<'_>, listener_rx: Receiver<ProxyAPI>) -> Self {
        Self::configure_fonts(cc);
        let iter = (0..20).map(|a| requests::RequestInfo::default());
        let config: MitmProxyConfig = confy::load("MitmProxy", None).unwrap_or_default();
        let state = MitmProxyState::new();

        let (tx, rx) = sync_channel(1);

        //thread::spawn(move || fetch_listener(&mut listener_tx));

        MitmProxy {
            listener_rx: listener_rx,
            listener: None,
            requests: vec![],
            config,
            state,
            tx,
            rx
        }
        //listen here and push inside MitmProxy.requests
    }

    pub fn check_listener(&mut self) -> bool {
       match self.listener_rx.try_recv(){
        Ok(l) => {
            self.listener = Some(l);
            true
        }
        _ => false
       }
    }

    pub fn fetch_requests(&mut self) {

        let mut rt = Runtime::new().unwrap();


        rt.block_on( async move{
                if let Ok(request_info) = self.listener
                .as_mut()
                .unwrap()
                .listen()
                .await {
                    self.requests.push(RequestInfo::default());
                }
        });

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

        //let mut style = (*cc.egui_ctx.style()).clone();
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

        let mut table = TableBuilder::new(ui)
            .striped(self.config.striped)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .columns(Column::remainder().resizable(self.config.resizable), 5)
            .column(Column::auto())
            .min_scrolled_height(0.0);

        if let Some(row_nr) = self.config.scroll_to_row.take() {
            table = table.scroll_to_row(row_nr, None)
        }

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
                body.rows(
                    text_height,
                    self.requests.len(),
                    |row_index, mut row| {
                        self.requests[row_index].render_row(&mut row);
                        row.col(|ui| {
                            if ui.button("🔎").clicked() {
                                self.state.selected_request = Some(row_index);
                            }
                        });
                    },
                )
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

    pub fn render_columns(&mut self, ui: &mut egui::Ui) {
        if let Some(i) = self.state.selected_request {
            ui.columns(2, |columns| {
                ScrollArea::vertical()
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
                ui.with_layout(Layout::right_to_left(eframe::emath::Align::Min), |ui| {
                    let close_btn = ui.button("❌");
                    let refresh_btn = ui.button("🔄");
                    let theme_btn = ui.button(match self.config.dark_mode {
                        true => "🔆",
                        false => "🌙",
                    });

                    if close_btn.clicked() {
                        frame.close();
                    }
                    if refresh_btn.clicked() {}

                    if theme_btn.clicked() {
                        self.config.dark_mode = !self.config.dark_mode
                    }
                })
            });
            ui.add_space(PADDING);
        });
    }
}
