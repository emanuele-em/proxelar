use crate::{ca::Ca, HttpHandler, NoopHandler, Proxy, WebSocketHandler};

use hyper::{ client::{connect::Connect, Client, HttpConnector}, server::conn::AddrIncoming};

use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};

use std::{net::{SocketAddr, TcpListener}, sync::Arc};

use tokio_tungstenite::Connector;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProxyBuilder;

pub(crate) enum AddrListServ {
    Addr(SocketAddr),
    List(TcpListener),
    Serv(Box<hyper::server::Builder<AddrIncoming>>),
}

pub struct NeedsAddr(());

impl ProxyBuilder<NeedsAddr>{
    pub fn new() -> Self{
        Self::default()
    }

    pub fn addr(self, addr: TcpListener) -> ProxyBuilder<NeedsCa>{
        ProxyBuilder (NeedsCa {
            addr_list_serv: AddrListServ::Addr(addr),
        })
    }

    pub fn listener(self, list: TcpListener) -> ProxyBuilder<NeedCa>{
        ProxyBuilder(NeedsCa{
            addr_list_serv: AddrListServ::List(list),
        })
    }

    pub fn server(self, serv: hyper::server::Builder<AddrIncoming>) -> ProxyBuilder<NeedCa>{
        ProxyBuilder(NeedsCa{
            addr_list_serv: AddrListServ::Serv(serv),
        })
    }
}

impl Default for ProxyBuilder<NeedsAddr> {
    fn default() -> Self {
        ProxyBuilder(NeedsAddr(()))
    }
}

pub struct NeedsCa<C> {
    addr_list_serv: AddrListServ
}

