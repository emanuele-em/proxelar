use gloo_utils::format::JsValueSerdeExt;
use js_sys::{Function, Promise};
use proxyapi_models::RequestInfo;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use yew::Callback;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window.__TAURI__.tauri"])]
    async fn invoke(cmd: &str, args: JsValue) -> JsValue;

    #[wasm_bindgen(js_namespace = ["window.__TAURI__.event"], js_name = "listen")]
    fn listen_(event: &str, handler: &Closure<dyn FnMut(JsValue)>) -> Promise;
}

pub struct EventListener(Promise, Closure<dyn FnMut(JsValue)>);
impl Drop for EventListener {
    fn drop(&mut self) {
        let promise = self.0.clone();
        spawn_local(async move {
            let unlisten: Function = wasm_bindgen_futures::JsFuture::from(promise)
                .await
                .unwrap()
                .into();
            unlisten.call0(&JsValue::undefined()).unwrap();
        });
    }
}

fn listen(event: &str, handler: Closure<dyn FnMut(JsValue)>) -> EventListener {
    let promise = listen_(event, &handler);
    EventListener(promise, handler)
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

#[derive(Deserialize)]
struct ProxyEvent {
    payload: RequestInfo,
}

pub fn listen_proxy_event(on_request: Option<Callback<RequestInfo>>) -> EventListener {
    let closure = Closure::new(move |event: JsValue| {
        let on_request = on_request.clone();
        if let Ok(ProxyEvent { payload }) = event.into_serde() {
            if let Some(on_request) = on_request {
                on_request.emit(payload);
            }
        }
    });
    listen("proxy_event", closure)
}
