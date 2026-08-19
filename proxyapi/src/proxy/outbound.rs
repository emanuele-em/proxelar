use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};

use base64::Engine as _;
use http::uri::Authority;
use http::Uri;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tower_service::Service;

use crate::rewind::Rewind;

use super::BoxError;

const MAX_CONNECT_RESPONSE_HEAD: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProxyKind {
    Http,
    Socks5,
}

/// Upstream HTTP CONNECT or SOCKS5 proxy configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamProxyConfig {
    kind: ProxyKind,
    destination: Uri,
    username: Option<String>,
    password: Option<String>,
}

impl UpstreamProxyConfig {
    /// Attach credentials used for Basic (HTTP) or username/password (SOCKS5)
    /// authentication.
    #[must_use]
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    pub fn destination(&self) -> &Uri {
        &self.destination
    }
}

impl FromStr for UpstreamProxyConfig {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (kind, rest) = if let Some(rest) = value.strip_prefix("http://") {
            (ProxyKind::Http, rest)
        } else if let Some(rest) = value.strip_prefix("socks5://") {
            (ProxyKind::Socks5, rest)
        } else {
            return Err("upstream proxy must use http:// or socks5://".to_owned());
        };
        if rest.contains('@') {
            return Err(
                "put credentials in --upstream-proxy-auth, not in the proxy URL".to_owned(),
            );
        }
        let destination: Uri = format!("http://{rest}")
            .parse()
            .map_err(|error: http::uri::InvalidUri| error.to_string())?;
        if destination.host().is_none() || destination.port_u16().is_none() {
            return Err("upstream proxy URL must include host and port".to_owned());
        }
        Ok(Self {
            kind,
            destination,
            username: None,
            password: None,
        })
    }
}

#[derive(Clone)]
pub(crate) enum OutboundConnector {
    Direct,
    Http(UpstreamProxyConfig),
    Socks5(UpstreamProxyConfig),
}

impl OutboundConnector {
    pub(crate) fn new(proxy: Option<&UpstreamProxyConfig>) -> Result<Self, crate::Error> {
        match proxy {
            None => Ok(Self::Direct),
            Some(config) if config.kind == ProxyKind::Http => Ok(Self::Http(config.clone())),
            Some(config) => Ok(Self::Socks5(config.clone())),
        }
    }
}

impl Service<Uri> for OutboundConnector {
    type Response = Rewind<TcpStream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, destination: Uri) -> Self::Future {
        let connector = self.clone();
        Box::pin(async move {
            let destination = with_default_port(destination);
            let authority = destination
                .authority()
                .cloned()
                .ok_or_else(|| invalid_input("outbound destination has no authority"))?;
            match connector {
                Self::Direct => {
                    let stream = TcpStream::connect(authority.as_str()).await?;
                    Ok(Rewind::new(stream))
                }
                Self::Http(proxy) => connect_http_proxy(proxy, authority).await,
                Self::Socks5(proxy) => connect_socks5_proxy(proxy, authority).await,
            }
        })
    }
}

async fn connect_http_proxy(
    proxy: UpstreamProxyConfig,
    destination: Authority,
) -> Result<Rewind<TcpStream>, BoxError> {
    let proxy_authority = proxy
        .destination
        .authority()
        .ok_or_else(|| invalid_input("HTTP proxy has no authority"))?;
    let mut stream = TcpStream::connect(proxy_authority.as_str()).await?;
    let mut request = format!(
        "CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\nProxy-Connection: keep-alive\r\n"
    );
    if let Some(username) = proxy.username {
        let password = proxy.password.as_deref().unwrap_or("");
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut response = Vec::with_capacity(1024);
    loop {
        if response.len() >= MAX_CONNECT_RESPONSE_HEAD {
            return Err(invalid_data(
                "HTTP proxy CONNECT response head is too large",
            ));
        }
        let mut buffer = [0_u8; 1024];
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Err(invalid_data("HTTP proxy closed during CONNECT response"));
        }
        response.extend_from_slice(&buffer[..read]);
        if let Some(end) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let consumed = end + 4;
            validate_connect_response(&response[..consumed])?;
            return Ok(Rewind::new_buffered(
                stream,
                response[consumed..].to_vec().into(),
            ));
        }
    }
}

fn validate_connect_response(response: &[u8]) -> Result<(), BoxError> {
    let line_end = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| invalid_data("HTTP proxy response has no status line"))?;
    let line = std::str::from_utf8(&response[..line_end])
        .map_err(|_| invalid_data("HTTP proxy response status is not ASCII"))?;
    let mut parts = line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || status != "200" {
        return Err(invalid_data(format!(
            "HTTP proxy CONNECT failed with {line}"
        )));
    }
    Ok(())
}

async fn connect_socks5_proxy(
    proxy: UpstreamProxyConfig,
    destination: Authority,
) -> Result<Rewind<TcpStream>, BoxError> {
    let proxy_authority = proxy
        .destination
        .authority()
        .ok_or_else(|| invalid_input("SOCKS5 proxy has no authority"))?;
    let mut stream = TcpStream::connect(proxy_authority.as_str()).await?;
    let authenticated = proxy.username.is_some();
    if authenticated {
        stream.write_all(&[5, 2, 0, 2]).await?;
    } else {
        stream.write_all(&[5, 1, 0]).await?;
    }
    let mut selection = [0_u8; 2];
    stream.read_exact(&mut selection).await?;
    if selection[0] != 5 || selection[1] == 0xff {
        return Err(invalid_data("SOCKS5 proxy rejected authentication methods"));
    }
    match selection[1] {
        0 => {}
        2 if authenticated => authenticate_socks5(&mut stream, &proxy).await?,
        _ => return Err(invalid_data("SOCKS5 proxy selected an unsupported method")),
    }

    let port = destination
        .port_u16()
        .ok_or_else(|| invalid_input("SOCKS5 destination has no port"))?;
    let mut request = vec![5, 1, 0];
    if let Ok(address) = destination.host().parse::<IpAddr>() {
        match address {
            IpAddr::V4(address) => {
                request.push(1);
                request.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                request.push(4);
                request.extend_from_slice(&address.octets());
            }
        }
    } else {
        let host = destination.host().as_bytes();
        let length = u8::try_from(host.len())
            .map_err(|_| invalid_input("SOCKS5 destination name exceeds 255 bytes"))?;
        request.extend_from_slice(&[3, length]);
        request.extend_from_slice(host);
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 5 || response[1] != 0 || response[2] != 0 {
        return Err(invalid_data(format!(
            "SOCKS5 CONNECT failed with status {}",
            response[1]
        )));
    }
    match response[3] {
        1 => {
            let mut ignored = [0_u8; 4];
            stream.read_exact(&mut ignored).await?;
            let _ = Ipv4Addr::from(ignored);
        }
        3 => {
            let length = stream.read_u8().await?;
            let mut ignored = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut ignored).await?;
        }
        4 => {
            let mut ignored = [0_u8; 16];
            stream.read_exact(&mut ignored).await?;
            let _ = Ipv6Addr::from(ignored);
        }
        _ => {
            return Err(invalid_data(
                "SOCKS5 proxy returned an invalid address type",
            ))
        }
    }
    let _ = stream.read_u16().await?;
    Ok(Rewind::new(stream))
}

async fn authenticate_socks5(
    stream: &mut TcpStream,
    proxy: &UpstreamProxyConfig,
) -> Result<(), BoxError> {
    let username = proxy.username.as_deref().unwrap_or("").as_bytes();
    let password = proxy.password.as_deref().unwrap_or("").as_bytes();
    let username_length = u8::try_from(username.len())
        .map_err(|_| invalid_input("SOCKS5 username exceeds 255 bytes"))?;
    let password_length = u8::try_from(password.len())
        .map_err(|_| invalid_input("SOCKS5 password exceeds 255 bytes"))?;
    let mut request = Vec::with_capacity(username.len() + password.len() + 3);
    request.extend_from_slice(&[1, username_length]);
    request.extend_from_slice(username);
    request.push(password_length);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;
    let mut response = [0_u8; 2];
    stream.read_exact(&mut response).await?;
    if response != [1, 0] {
        return Err(invalid_data(
            "SOCKS5 username/password authentication failed",
        ));
    }
    Ok(())
}

fn with_default_port(destination: Uri) -> Uri {
    if destination.port_u16().is_some() {
        return destination;
    }
    let Some(port) = destination.scheme_str().and_then(|scheme| match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }) else {
        return destination;
    };
    let Some(authority) = destination.authority() else {
        return destination;
    };
    let Ok(authority) = Authority::from_str(&format!("{authority}:{port}")) else {
        return destination;
    };

    let mut parts = destination.clone().into_parts();
    parts.authority = Some(authority);
    Uri::from_parts(parts).unwrap_or(destination)
}

fn invalid_input(message: impl Into<String>) -> BoxError {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

fn invalid_data(message: impl Into<String>) -> BoxError {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_and_socks5_proxies_and_rejects_ambiguous_values() {
        let http: UpstreamProxyConfig = "http://proxy.test:8080".parse().unwrap();
        assert_eq!(http.kind, ProxyKind::Http);
        assert_eq!(
            http.destination(),
            &"http://proxy.test:8080".parse::<Uri>().unwrap()
        );

        let socks: UpstreamProxyConfig = "socks5://127.0.0.1:1080".parse().unwrap();
        assert_eq!(socks.kind, ProxyKind::Socks5);
        assert_eq!(socks.username, None);

        assert!("https://proxy.test:443"
            .parse::<UpstreamProxyConfig>()
            .is_err());
        assert!("http://user:pass@proxy.test:8080"
            .parse::<UpstreamProxyConfig>()
            .is_err());
        assert!("http://proxy.test".parse::<UpstreamProxyConfig>().is_err());
    }

    #[test]
    fn adds_the_scheme_default_port_for_proxy_tunnels() {
        let http = with_default_port("http://example.test/path?q=1".parse().unwrap());
        assert_eq!(http, "http://example.test:80/path?q=1");

        let https = with_default_port("https://[::1]/".parse().unwrap());
        assert_eq!(https, "https://[::1]:443/");

        let explicit = "https://example.test:8443/".parse::<Uri>().unwrap();
        assert_eq!(with_default_port(explicit.clone()), explicit);

        let unknown = "custom://example.test/path".parse::<Uri>().unwrap();
        assert_eq!(with_default_port(unknown.clone()), unknown);
        let relative = "/path".parse::<Uri>().unwrap();
        assert_eq!(with_default_port(relative.clone()), relative);
    }

    #[tokio::test]
    async fn constructs_and_calls_each_connector_kind() {
        use std::future::poll_fn;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        let direct_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let direct_address = direct_listener.local_addr().unwrap();
        let direct_server = tokio::spawn(async move {
            let (_stream, _) = direct_listener.accept().await.unwrap();
        });
        let mut direct = OutboundConnector::new(None).unwrap();
        poll_fn(|context| direct.poll_ready(context)).await.unwrap();
        direct
            .call(format!("http://{direct_address}/").parse().unwrap())
            .await
            .unwrap();
        direct_server.await.unwrap();

        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_address = http_listener.local_addr().unwrap();
        let http_server = tokio::spawn(async move {
            let (mut stream, _) = http_listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut chunk = [0_u8; 128];
                let length = stream.read(&mut chunk).await.unwrap();
                assert_ne!(length, 0);
                request.extend_from_slice(&chunk[..length]);
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("CONNECT example.test:80 HTTP/1.1\r\n"));
            assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nprefetched")
                .await
                .unwrap();
        });
        let http_config: UpstreamProxyConfig = format!("http://{http_address}").parse().unwrap();
        let authenticated = http_config.clone().with_auth("user", "password");
        assert_eq!(authenticated.username.as_deref(), Some("user"));
        assert_eq!(authenticated.password.as_deref(), Some("password"));
        let mut http = OutboundConnector::new(Some(&authenticated)).unwrap();
        assert!(matches!(http, OutboundConnector::Http(_)));
        poll_fn(|context| http.poll_ready(context)).await.unwrap();
        let mut tunneled = http
            .call("http://example.test/".parse().unwrap())
            .await
            .unwrap();
        let mut prefetched = [0_u8; 10];
        tunneled.read_exact(&mut prefetched).await.unwrap();
        assert_eq!(&prefetched, b"prefetched");
        http_server.await.unwrap();

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_address = socks_listener.local_addr().unwrap();
        let socks_server = tokio::spawn(async move {
            let (mut stream, _) = socks_listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..3], &[5, 1, 0]);
            match request[3] {
                1 => {
                    let mut rest = [0_u8; 6];
                    stream.read_exact(&mut rest).await.unwrap();
                }
                3 => {
                    let length = stream.read_u8().await.unwrap();
                    let mut rest = vec![0_u8; usize::from(length) + 2];
                    stream.read_exact(&mut rest).await.unwrap();
                }
                4 => {
                    let mut rest = [0_u8; 18];
                    stream.read_exact(&mut rest).await.unwrap();
                }
                other => panic!("unexpected SOCKS address type {other}"),
            }
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
        });
        let socks_config: UpstreamProxyConfig =
            format!("socks5://{socks_address}").parse().unwrap();
        let mut socks = OutboundConnector::new(Some(&socks_config)).unwrap();
        assert!(matches!(socks, OutboundConnector::Socks5(_)));
        poll_fn(|context| socks.poll_ready(context)).await.unwrap();
        socks
            .call("http://example.test/".parse().unwrap())
            .await
            .unwrap();
        socks_server.await.unwrap();

        let authenticated_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authenticated_address = authenticated_listener.local_addr().unwrap();
        let authenticated_server = tokio::spawn(async move {
            let (mut stream, _) = authenticated_listener.accept().await.unwrap();
            let mut greeting = [0_u8; 4];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 2, 0, 2]);
            stream.write_all(&[5, 2]).await.unwrap();

            let mut auth_prefix = [0_u8; 2];
            stream.read_exact(&mut auth_prefix).await.unwrap();
            assert_eq!(auth_prefix, [1, 4]);
            let mut username = [0_u8; 4];
            stream.read_exact(&mut username).await.unwrap();
            assert_eq!(&username, b"user");
            assert_eq!(stream.read_u8().await.unwrap(), 8);
            let mut password = [0_u8; 8];
            stream.read_exact(&mut password).await.unwrap();
            assert_eq!(&password, b"password");
            stream.write_all(&[1, 0]).await.unwrap();

            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, &[5, 1, 0, 3]);
            let length = stream.read_u8().await.unwrap();
            let mut destination = vec![0_u8; usize::from(length) + 2];
            stream.read_exact(&mut destination).await.unwrap();
            assert_eq!(&destination[..usize::from(length)], b"example.test");
            assert_eq!(
                &destination[usize::from(length)..],
                80_u16.to_be_bytes().as_slice()
            );
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
        });
        let authenticated_config: UpstreamProxyConfig =
            format!("socks5://{authenticated_address}").parse().unwrap();
        let authenticated_socks = authenticated_config.with_auth("user", "password");
        let mut authenticated = OutboundConnector::new(Some(&authenticated_socks)).unwrap();
        authenticated
            .call("http://example.test/".parse().unwrap())
            .await
            .unwrap();
        authenticated_server.await.unwrap();
    }
}
