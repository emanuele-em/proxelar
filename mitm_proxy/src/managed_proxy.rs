use std::{
    net::SocketAddr,
    sync::mpsc::Receiver,
    thread::{self, JoinHandle},
};

use proxyapi::{Proxy, ProxyHandler};
use tokio::{runtime::Runtime, sync::oneshot::Sender};

use crate::requests::RequestInfo;

pub struct ManagedProxy {
    rx: Receiver<ProxyHandler>,
    close: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl ManagedProxy {
    pub fn new(addr: SocketAddr) -> ManagedProxy {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let (close_tx, close_rx) = tokio::sync::oneshot::channel();

        let rt = Runtime::new().unwrap();

        let thread = thread::spawn(move || {
            rt.block_on(async move {
                if let Err(e) = Proxy::new(addr, Some(tx.clone()))
                    .start(async move {
                        let _ = close_rx.await;
                    })
                    .await
                {
                    eprintln!("Error running proxy on {:?}: {e}", addr);
                }
            })
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
            t.join().expect("Couldn't gracefully shutdown the proxy.")
        }
    }
}
