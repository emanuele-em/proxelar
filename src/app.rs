use std::{net::TcpListener, vec};


use tokio::runtime;

use crate::{listen, ADDR, init};

/// We derive Deserialize/Serialize so we can persist app state on shutdown.
//#[derive(serde::Deserialize, serde::Serialize)]
//#[serde(default)] // if we add new fields, give them default values when deserializing old state
pub struct MitmApp {
    rt: runtime::Runtime,
    listener: Option<TcpListener>,
    requests: Vec<String>,
    responses: Vec<String>,
}

impl MitmApp {
    /// Called once before the first frame.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // This is also where you can customize the look and feel of egui using
        // `cc.egui_ctx.set_visuals` and `cc.egui_ctx.set_fonts`.

        // Load previous app state (if any).
        // Note that you must enable the `persistence` feature for this to work.
        //if let Some(storage) = cc.storage {
        //    return eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default();
        //}
        Self {
            rt: runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap(),
            listener: None,
            requests: vec![String::new()],
            responses: vec![String::new()],
        }
    }

    fn set_listener(&mut self){
       self.rt.spawn(async move {
        
       });
    }

}

impl eframe::App for MitmApp {
    /// Called by the frame work to save state before shutdown.
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }

    /// Called each time the UI needs repainting, which may be many times per second.
    /// Put your widgets into a `SidePanel`, `TopPanel`, `CentralPanel`, `Window` or `Area`.
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // let Self { listener, requests, responses } = self;

        // Examples of how to create different panels and windows.
        // Pick whichever suits you.
        // Tip: a good default choice is to just keep the `CentralPanel`.
        // For inspiration and more examples, go to https://emilk.github.io/egui
        

        egui::TopBottomPanel::bottom("tcp_listener").show(ctx, |ui| {
            ui.label(*listener);
        });

        egui::SidePanel::left("side_panel").show(ctx, |ui| {});

        egui::CentralPanel::default().show(ctx, |ui| {
            // The central panel the region left after adding TopPanel's and SidePanel's
            
        });

        if false {
            egui::Window::new("Window").show(ctx, |ui| {
                ui.label("Windows can be moved by dragging them.");
                ui.label("They are automatically sized based on contents.");
                ui.label("You can turn on resizing and scrolling if you like.");
                ui.label("You would normally choose either panels OR windows.");
            });
        }
    }
}
