mod mitm_proxy;
mod requests;

use crate::mitm_proxy::MitmProxy;

use eframe::{
    egui::{
        self, CentralPanel, Vec2,
    },
    run_native, App,
};
use proxyapi::ProxyAPI;

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

        if(self.check_listener()){
            self.fetch_requests();
            CentralPanel::default().show(ctx, |ui| self.render_columns(ui));
        } else {
            CentralPanel::default().show(ctx, |ui| ui.label("wait for connection"));
        }
    }
}


fn main() {
    let mut native_options = eframe::NativeOptions::default();
    native_options.initial_window_size = Some(Vec2::new(X, Y));
    
    run_native(
        "Man In The Middle Proxy",
        native_options,
        Box::new(|cc| Box::new(MitmProxy::new(cc))),
    )
    
}
