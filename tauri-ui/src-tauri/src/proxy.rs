use proxyapi::Proxy;
use std::net::SocketAddr;
use tokio::sync::oneshot::Sender;

use tauri::{
    async_runtime::Mutex,
    plugin::{Builder, TauriPlugin},
    AppHandle, Manager, Runtime, State,
};

use proxyapi_models::RequestInfo;

type ProxyState = Mutex<Option<(Sender<()>, tauri::async_runtime::JoinHandle<()>)>>;

#[tauri::command]
async fn start_proxy<R: Runtime>(
    app: AppHandle<R>,
    proxy: State<'_, ProxyState>,
    addr: SocketAddr,
) -> Result<(), String> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let (close_tx, close_rx) = tokio::sync::oneshot::channel();
    let thread = tauri::async_runtime::spawn(async move {
        if let Err(e) = Proxy::new(addr, Some(tx.clone()))
            .start(async move {
                let _ = close_rx.await;
            })
            .await
        {
            eprintln!("Error running proxy on {:?}: {e}", addr);
        }
    });

    let mut proxy = proxy.lock().await;
    assert!(proxy.is_none());
    proxy.replace((close_tx, thread));

    tauri::async_runtime::spawn(async move {
        for exchange in rx.iter() {
            let (request, response) = exchange.to_parts();
            app.emit_all("proxy_event", RequestInfo(request, response))
                .unwrap();
        }
    });

    Ok(())
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
        .invoke_handler(tauri::generate_handler![start_proxy, stop_proxy,])
        .build()
}
