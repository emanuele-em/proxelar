use eframe::{egui::{self, CentralPanel}, App, run_native, glow::NativeBuffer};

struct MitmProxy{
    requests: Vec<RequestInfo>
}

impl MitmProxy{
    fn new() -> Self{
        let iter = (0..20).map(|a| RequestInfo{
            path: format!("path{}", a),
            method: format!("method{}", a),
            status: format!("status{}", a),
            size: format!("size{}", a),
            time: format!("time{}", a),
        });

        MitmProxy { requests: Vec::from_iter(iter) }
    }
}

struct RequestInfo{
    path: String,
    method: String,
    status: String,
    size: String,
    time: String,
}

impl App for MitmProxy{
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        CentralPanel::default().show(ctx, |ui|{
            ui.label("ciao pulce, possiamo andare, ti voglio bene")
        });
    }

    
}

fn main(){
    let native_options = eframe::NativeOptions::default();
    run_native("Man In The Middle Proxy", native_options, Box::new(|cc| Box::new(MitmProxy::new())))
}