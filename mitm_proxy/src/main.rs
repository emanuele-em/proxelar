mod mitm_proxy;
mod requests;

use std::{
    sync::mpsc::{ sync_channel},
    thread,
};

use crate::mitm_proxy::MitmProxy;

use eframe::{
    egui::{self, CentralPanel, Vec2},
    run_native, App,
};
use proxyapi::ProxyAPI;
use tokio::runtime::Runtime;

static X: f32 = 980.;
static Y: f32 = 960.0;
static PADDING: f32 = 20.;

// fn fetch_requests(){
//     ProxyAPI::new().fetch();
// }

impl App for MitmProxy {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.manage_theme(ctx);

        self.render_top_panel(ctx, frame);

        
        CentralPanel::default().show(ctx, |ui|{

                // self.fetch_requests();
                self.render_columns(ui);

        });
    }
}

fn main() {
    let mut native_options = eframe::NativeOptions::default();
    native_options.initial_window_size = Some(Vec2::new(X, Y));

    // create the app with listener false
    // update listener when it is true

    let (tx, rx) = sync_channel(1);
    let rt = Runtime::new().unwrap();

    thread::spawn(move || {
        rt.block_on( async move {
                ProxyAPI::new(tx.clone()).await;
        })
    });

    run_native(
        "Man In The Middle Proxy",
        native_options,
        Box::new(|cc| Box::new(MitmProxy::new(cc, rx))),
    )
}
