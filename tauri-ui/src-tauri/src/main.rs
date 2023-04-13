// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod proxy;

fn main() {
    tauri::Builder::default()
        .plugin(proxy::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
