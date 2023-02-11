mod mitm_proxy;
mod requests;

use std::{
    sync::mpsc::{ sync_channel},
    thread, net::SocketAddr,
};

use crate::mitm_proxy::MitmProxy;

use eframe::{
    egui::{self, CentralPanel, Vec2},
    run_native, App
};
use proxyapi::proxy::Proxy;
use tokio::runtime::Runtime;

static X: f32 = 980.;
static Y: f32 = 960.0;
static PADDING: f32 = 20.;

// fn fetch_requests(){
//     ProxyAPI::new().fetch();
// }

impl App for MitmProxy {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {

        ctx.request_repaint();

        self.manage_theme(ctx);

        self.render_top_panel(ctx, frame);
        
        CentralPanel::default().show(ctx, |ui|{
                self.render_columns(ui);
        });
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
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
    let mut native_options = eframe::NativeOptions::default();
    native_options.initial_window_size = Some(Vec2::new(X, Y));
    native_options.icon_data = Some(load_icon("./assets/logo.png"));

    // create the app with listener false
    // update listener when it is true

    let (tx, rx) = sync_channel(1);
    let rt = Runtime::new().unwrap();
    let addr = SocketAddr::new([192,168,1,10].into(), 8080);

    thread::spawn(move || {
        rt.block_on( async move {
                if let Err(e) = Proxy::new(addr, Some(tx.clone())).start(shutdown_signal()).await{
                    eprintln!("Error running proxy on {:?}: {e}", addr);
                }
        })
    });

    run_native(
        "Man In The Middle Proxy",
        native_options,
        Box::new(|cc| Box::new(MitmProxy::new(cc, rx))),
    )
}
