mod managed_proxy;
mod mitm_proxy;
mod models;
mod requests;

use crate::mitm_proxy::MitmProxy;

use clap::Parser;
use eframe::{
    egui::{self, CentralPanel, Vec2},
    run_native, App,
};
use models::Opts;

const X: f32 = 980.;
const Y: f32 = 960.0;
const PADDING: f32 = 20.;
const FONT_SIZE: f32 = 17.;
const LOGO_ASSET_PATH: &str = "./assets/logo.png";

impl App for MitmProxy {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        ctx.request_repaint();

        self.manage_theme(ctx);

        self.render_top_panel(ctx, frame);

        CentralPanel::default().show(ctx, |ui| {
            self.render_columns(frame, ctx, ui);
        });

        self.render_bottom_panel(ctx, frame);
    }
}

fn load_icon(path: &str) -> eframe::IconData {
    let (icon_rgba, icon_width, icon_height) = {
        let image = image::open(path)
            .expect("Failed to open icon path")
            .into_rgba8();
        let (width, height) = image.dimensions();
        let rgba = image.into_raw();
        (rgba, width, height)
    };

    eframe::IconData {
        rgba: icon_rgba,
        width: icon_width,
        height: icon_height,
    }
}

fn main() {
    let opts = Opts::parse();

    let native_options = eframe::NativeOptions {
        initial_window_size: Some(Vec2::new(X, Y)),
        icon_data: Some(load_icon(LOGO_ASSET_PATH)),
        ..eframe::NativeOptions::default()
    };

    run_native(
        "Man In The Middle Proxy",
        native_options,
        Box::new(|cc| Box::new(MitmProxy::new(cc, opts.cert, opts.key))),
    );
}
