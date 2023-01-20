#![warn(clippy::all, rust_2018_idioms)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release


use man_in_the_middle_proxy as mitm;

#[tokio::main]
async fn main() {
    
    
    
    // Log to stdout (if you run with `RUST_LOG=debug`).
    tracing_subscriber::fmt::init();

    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Main In The Middle proxy",
        native_options,
        Box::new(|cc| Box::new(mitm::MitmApp::new(cc))),
    );

    if let Err(err) = mitm::init().await {
        eprintln!("Error: {:?}", err);
    }
}
