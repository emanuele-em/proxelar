use std::net::SocketAddr;

use tauri::{
    async_runtime::Mutex,
    plugin::{Builder, TauriPlugin},
    Manager, Runtime, State,
};

use crate::managed_proxy::ManagedProxy;
use proxyapi_models::RequestInfo;

type ProxyState = Mutex<Option<ManagedProxy>>;

#[tauri::command]
async fn start_proxy(proxy: State<'_, ProxyState>, addr: SocketAddr) -> Result<(), String> {
    let mut proxy = proxy.lock().await;
    assert!(proxy.is_none());
    proxy.replace(ManagedProxy::new(addr));
    Ok(())
}

#[tauri::command]
async fn fetch_request(proxy: State<'_, ProxyState>) -> Result<Option<RequestInfo>, String> {
    let mut proxy = proxy.lock().await;
    if let Some(ref mut proxy) = *proxy {
        return Ok(proxy.try_recv_request());
    };
    Ok(None)
}

#[tauri::command]
async fn stop_proxy(proxy: State<'_, ProxyState>) -> Result<(), String> {
    let mut proxy = proxy.lock().await;
    assert!(proxy.is_some());
    proxy.take();
    Ok(())
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("proxy")
        .setup(|app_handle| {
            app_handle.manage(Mutex::new(None) as ProxyState);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_proxy,
            stop_proxy,
            fetch_request
        ])
        .build()
}
