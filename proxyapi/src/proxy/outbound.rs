use std::str::FromStr;

use rama::net::address::{HostWithPort, ProxyAddress};
use rama::net::user::{credentials::Basic, ProxyCredential};
use rama::net::Protocol;
use rama::utils::str::NonEmptyStr;

use crate::error::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProxyKind {
    Http,
    Socks5,
}

/// Upstream HTTP CONNECT or SOCKS5 proxy configuration.
///
/// The chosen proxy is compiled into the shared rama transport connector used
/// by HTTP requests and raw tunnels alike.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamProxyConfig {
    kind: ProxyKind,
    authority: HostWithPort,
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

    /// The upstream proxy destination as a `host:port` string.
    #[must_use]
    pub fn destination(&self) -> String {
        self.authority.to_string()
    }

    /// Build the rama [`ProxyAddress`] used to chain upstream requests.
    pub(crate) fn proxy_address(&self) -> Result<ProxyAddress, Error> {
        let protocol = match self.kind {
            ProxyKind::Http => Protocol::HTTP,
            ProxyKind::Socks5 => Protocol::SOCKS5,
        };
        let credential = match &self.username {
            Some(username) => {
                let username = NonEmptyStr::try_from(username.clone()).map_err(|_| {
                    Error::Other("upstream proxy username must not be empty".into())
                })?;
                let basic = match self.password.as_deref() {
                    Some(password) if !password.is_empty() => Basic::new(
                        username,
                        NonEmptyStr::try_from(password.to_owned()).map_err(|_| {
                            Error::Other("upstream proxy password must not be empty".into())
                        })?,
                    ),
                    _ => Basic::new_insecure(username),
                };
                Some(ProxyCredential::Basic(basic))
            }
            None => None,
        };
        Ok(ProxyAddress {
            protocol: Some(protocol),
            address: self.authority.clone(),
            credential,
        })
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
        let rest = rest.trim_end_matches('/');
        let authority = HostWithPort::from_str(rest)
            .map_err(|_| "upstream proxy URL must include host and port".to_owned())?;
        Ok(Self {
            kind,
            authority,
            username: None,
            password: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_and_socks5_proxies_and_rejects_ambiguous_values() {
        let http: UpstreamProxyConfig = "http://proxy.test:8080".parse().unwrap();
        assert_eq!(http.kind, ProxyKind::Http);
        assert_eq!(http.destination(), "proxy.test:8080");

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
    fn builds_proxy_address_with_credentials() {
        let config: UpstreamProxyConfig = "socks5://127.0.0.1:1080".parse().unwrap();
        let config = config.with_auth("user", "password");
        let address = config.proxy_address().unwrap();
        assert_eq!(address.protocol, Some(Protocol::SOCKS5));
        assert!(address.credential.is_some());
    }
}
