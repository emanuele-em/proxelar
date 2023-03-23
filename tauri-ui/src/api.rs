use gloo_utils::format::JsValueSerdeExt;
use proxyapi_models::RequestInfo;
use serde::Serialize;
use std::net::SocketAddr;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use yew::Callback;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window.__TAURI__.tauri"])]
    async fn invoke(cmd: &str, args: JsValue) -> JsValue;
}

#[derive(Serialize)]
struct Start {
    addr: SocketAddr,
}

pub fn start_proxy(addr: SocketAddr, on_start: Option<Callback<()>>) {
    let args = JsValue::from_serde(&Start { addr }).unwrap();
    spawn_local(async move {
        invoke("plugin:proxy|start_proxy", args).await;
        if let Some(on_start) = on_start {
            on_start.emit(());
        }
    });
}

pub fn stop_proxy(on_stop: Option<Callback<()>>) {
    spawn_local(async move {
        invoke("plugin:proxy|stop_proxy", JsValue::NULL).await;
        if let Some(on_stop) = on_stop {
            on_stop.emit(());
        }
    });
}

pub fn poll_proxy(on_request: Option<Callback<RequestInfo>>) {
    spawn_local(async move {
        let value = invoke("plugin:proxy|fetch_request", JsValue::NULL).await;
        if let Ok(request_info) = value.into_serde() {
            if let Some(on_request) = on_request {
                on_request.emit(request_info);
            }
        }
    });
}
