use std::{net::SocketAddr, sync::mpsc::Receiver};

use proxyapi::{Proxy, ProxyHandler};
use proxyapi_models::RequestInfo;
use tokio::sync::oneshot::Sender;

pub struct ManagedProxy {
    rx: Receiver<ProxyHandler>,
    // TODO: handle the cleanup
    _close: Sender<()>,
    _thread: tauri::async_runtime::JoinHandle<()>,
}

impl ManagedProxy {
    pub fn new(addr: SocketAddr) -> ManagedProxy {
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

        ManagedProxy {
            rx,
            _close: close_tx,
            _thread: thread,
        }
    }

    pub fn try_recv_request(&mut self) -> Option<RequestInfo> {
        match self.rx.try_recv() {
            Ok(l) => {
                let (request, response) = l.to_parts();
                Some(RequestInfo(request, response))
            }
            _ => None,
        }
    }
}
