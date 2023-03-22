use std::{
    net::SocketAddr,
    sync::mpsc::Receiver,
    thread::{self},
};

use proxyapi::{ProxiedRequest, ProxiedResponse};
use proxyapi::{Proxy, ProxyHandler};
use tokio::{runtime::Runtime, sync::oneshot::Sender};
#[derive(Clone)]
pub struct RequestInfo {
    request: Option<ProxiedRequest>,
    response: Option<ProxiedResponse>,
}
impl RequestInfo {
    pub fn new(request: Option<ProxiedRequest>, response: Option<ProxiedResponse>) -> Self {
        Self { request, response }
    }
}

pub struct ManagedProxy {
    rx: Receiver<ProxyHandler>,
    close: Option<Sender<()>>,
    thread: Option<tauri::async_runtime::JoinHandle<()>>,
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
            close: Some(close_tx),
            thread: Some(thread),
        }
    }

    pub fn try_recv_request(&mut self) -> Option<RequestInfo> {
        match self.rx.try_recv() {
            Ok(l) => {
                let (request, response) = l.to_parts();
                Some(RequestInfo::new(request, response))
            }
            _ => None,
        }
    }
}

impl Drop for ManagedProxy {
    fn drop(&mut self) {
        if let Some(t) = self.thread.take() {
            if let Some(close) = self.close.take() {
                let _ = close.send(());
            }
            // t.join().expect("Couldn't gracefully shutdown the proxy.")
        }
    }
}
