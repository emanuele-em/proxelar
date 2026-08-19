//! Declarative request routing rules for mocks, redirects, and local/remote maps.

use std::path::{Component, Path, PathBuf};

use rama::bytes::Bytes;
use rama::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use rama::net::uri::Uri;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RouteRules {
    #[serde(default)]
    pub rules: Vec<RouteRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RouteRule {
    MapRemote {
        url_prefix: String,
        target_prefix: String,
    },
    MapLocal {
        url_prefix: String,
        directory: PathBuf,
        #[serde(default = "default_index")]
        index: String,
    },
    Redirect {
        url_prefix: String,
        location: String,
        #[serde(default = "default_redirect_status")]
        status: u16,
    },
    Mock {
        url_prefix: String,
        #[serde(default)]
        method: Option<String>,
        #[serde(default = "default_mock_status")]
        status: u16,
        #[serde(default)]
        headers: Vec<RuleHeader>,
        #[serde(default)]
        body: String,
    },
    SetRequestHeader {
        #[serde(default)]
        url_prefix: String,
        name: String,
        value: String,
    },
    RemoveRequestHeader {
        #[serde(default)]
        url_prefix: String,
        name: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug)]
pub enum RuleOutcome {
    Forward,
    Respond {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    },
}

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("rule file I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid rule file: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid rule: {0}")]
    Invalid(String),
}

impl RouteRules {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuleError> {
        let rules: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        rules.validate()?;
        Ok(rules)
    }

    pub fn validate(&self) -> Result<(), RuleError> {
        for rule in &self.rules {
            match rule {
                RouteRule::MapRemote {
                    url_prefix,
                    target_prefix,
                } => {
                    require_prefix(url_prefix)?;
                    require_prefix(target_prefix)?;
                }
                RouteRule::MapLocal {
                    url_prefix,
                    directory,
                    index,
                } => {
                    require_prefix(url_prefix)?;
                    if directory.as_os_str().is_empty() || index.is_empty() {
                        return Err(RuleError::Invalid(
                            "map_local requires a directory and index".to_owned(),
                        ));
                    }
                }
                RouteRule::Redirect {
                    url_prefix,
                    location,
                    status,
                } => {
                    require_prefix(url_prefix)?;
                    require_prefix(location)?;
                    let status = StatusCode::from_u16(*status)
                        .map_err(|error| RuleError::Invalid(error.to_string()))?;
                    if !status.is_redirection() {
                        return Err(RuleError::Invalid(
                            "redirect status must be in the 3xx range".to_owned(),
                        ));
                    }
                }
                RouteRule::Mock {
                    url_prefix,
                    method,
                    status,
                    headers,
                    ..
                } => {
                    require_prefix(url_prefix)?;
                    if let Some(method) = method {
                        method
                            .parse::<Method>()
                            .map_err(|error| RuleError::Invalid(error.to_string()))?;
                    }
                    StatusCode::from_u16(*status)
                        .map_err(|error| RuleError::Invalid(error.to_string()))?;
                    validate_headers(headers)?;
                }
                RouteRule::SetRequestHeader {
                    name,
                    value,
                    url_prefix,
                } => {
                    validate_optional_prefix(url_prefix)?;
                    HeaderName::from_bytes(name.as_bytes())
                        .map_err(|error| RuleError::Invalid(error.to_string()))?;
                    HeaderValue::from_str(value)
                        .map_err(|error| RuleError::Invalid(error.to_string()))?;
                }
                RouteRule::RemoveRequestHeader { name, url_prefix } => {
                    validate_optional_prefix(url_prefix)?;
                    HeaderName::from_bytes(name.as_bytes())
                        .map_err(|error| RuleError::Invalid(error.to_string()))?;
                }
            }
        }
        Ok(())
    }

    pub fn map_remote(
        &mut self,
        url_prefix: impl Into<String>,
        target_prefix: impl Into<String>,
    ) -> Result<(), RuleError> {
        self.rules.push(RouteRule::MapRemote {
            url_prefix: url_prefix.into(),
            target_prefix: target_prefix.into(),
        });
        self.validate()
    }

    pub fn map_local(
        &mut self,
        url_prefix: impl Into<String>,
        directory: impl Into<PathBuf>,
    ) -> Result<(), RuleError> {
        self.rules.push(RouteRule::MapLocal {
            url_prefix: url_prefix.into(),
            directory: directory.into(),
            index: default_index(),
        });
        self.validate()
    }

    pub async fn apply(
        &self,
        method: &Method,
        uri: &mut Uri,
        headers: &mut HeaderMap,
    ) -> Result<RuleOutcome, RuleError> {
        for rule in &self.rules {
            let current = uri.to_string();
            match rule {
                RouteRule::SetRequestHeader {
                    url_prefix,
                    name,
                    value,
                } if current.starts_with(url_prefix) => {
                    let name = HeaderName::from_bytes(name.as_bytes())
                        .map_err(|error| RuleError::Invalid(error.to_string()))?;
                    let value = HeaderValue::from_str(value)
                        .map_err(|error| RuleError::Invalid(error.to_string()))?;
                    headers.insert(name, value);
                }
                RouteRule::RemoveRequestHeader { url_prefix, name }
                    if current.starts_with(url_prefix) =>
                {
                    headers.remove(name);
                }
                RouteRule::MapRemote {
                    url_prefix,
                    target_prefix,
                } if current.starts_with(url_prefix) => {
                    let mapped = format!("{target_prefix}{}", &current[url_prefix.len()..]);
                    *uri = mapped
                        .parse()
                        .map_err(|error: rama::net::uri::ParseError| {
                            RuleError::Invalid(error.to_string())
                        })?;
                }
                RouteRule::MapLocal {
                    url_prefix,
                    directory,
                    index,
                } if current.starts_with(url_prefix) => {
                    if method != Method::GET && method != Method::HEAD {
                        return Ok(response(
                            StatusCode::METHOD_NOT_ALLOWED,
                            HeaderMap::new(),
                            "",
                        ));
                    }
                    let suffix = current[url_prefix.len()..]
                        .split(['?', '#'])
                        .next()
                        .unwrap_or("");
                    let path = safe_local_path(directory, suffix, index)?;
                    let canonical_root = match tokio::fs::canonicalize(directory).await {
                        Ok(root) => root,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            return Ok(response(
                                StatusCode::NOT_FOUND,
                                HeaderMap::new(),
                                "Mapped local directory not found",
                            ));
                        }
                        Err(error) => return Err(RuleError::Io(error)),
                    };
                    let canonical_path = match tokio::fs::canonicalize(&path).await {
                        Ok(path) => path,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            return Ok(response(
                                StatusCode::NOT_FOUND,
                                HeaderMap::new(),
                                "Mapped local file not found",
                            ));
                        }
                        Err(error) => return Err(RuleError::Io(error)),
                    };
                    if !canonical_path.starts_with(&canonical_root) {
                        return Err(RuleError::Invalid(
                            "map_local symlink escapes the configured directory".to_owned(),
                        ));
                    }
                    return match tokio::fs::read(&canonical_path).await {
                        Ok(mut body) => {
                            if method == Method::HEAD {
                                body.clear();
                            }
                            let mut response_headers = HeaderMap::new();
                            response_headers.insert(
                                rama::http::header::CONTENT_TYPE,
                                HeaderValue::from_static(content_type_for_path(&canonical_path)),
                            );
                            Ok(response(StatusCode::OK, response_headers, body))
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(response(
                            StatusCode::NOT_FOUND,
                            HeaderMap::new(),
                            "Mapped local file not found",
                        )),
                        Err(error) => Err(RuleError::Io(error)),
                    };
                }
                RouteRule::Redirect {
                    url_prefix,
                    location,
                    status,
                } if current.starts_with(url_prefix) => {
                    let target = format!("{location}{}", &current[url_prefix.len()..]);
                    let mut response_headers = HeaderMap::new();
                    response_headers.insert(
                        rama::http::header::LOCATION,
                        HeaderValue::from_str(&target)
                            .map_err(|error| RuleError::Invalid(error.to_string()))?,
                    );
                    return Ok(response(
                        StatusCode::from_u16(*status)
                            .map_err(|error| RuleError::Invalid(error.to_string()))?,
                        response_headers,
                        "",
                    ));
                }
                RouteRule::Mock {
                    url_prefix,
                    method: required_method,
                    status,
                    headers,
                    body,
                } if current.starts_with(url_prefix)
                    && required_method
                        .as_ref()
                        .is_none_or(|required| required.eq_ignore_ascii_case(method.as_str())) =>
                {
                    return Ok(response(
                        StatusCode::from_u16(*status)
                            .map_err(|error| RuleError::Invalid(error.to_string()))?,
                        build_headers(headers)?,
                        body.clone(),
                    ));
                }
                _ => {}
            }
        }
        Ok(RuleOutcome::Forward)
    }
}

fn response(status: StatusCode, headers: HeaderMap, body: impl Into<Bytes>) -> RuleOutcome {
    RuleOutcome::Respond {
        status,
        headers,
        body: body.into(),
    }
}

fn safe_local_path(directory: &Path, suffix: &str, index: &str) -> Result<PathBuf, RuleError> {
    let relative = suffix.trim_start_matches('/');
    let relative = if relative.is_empty() { index } else { relative };
    let path = Path::new(relative);
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(RuleError::Invalid(
            "map_local path traversal is not allowed".to_owned(),
        ));
    }
    Ok(directory.join(path))
}

fn validate_headers(headers: &[RuleHeader]) -> Result<(), RuleError> {
    for header in headers {
        HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|error| RuleError::Invalid(error.to_string()))?;
        HeaderValue::from_str(&header.value)
            .map_err(|error| RuleError::Invalid(error.to_string()))?;
    }
    Ok(())
}

fn build_headers(headers: &[RuleHeader]) -> Result<HeaderMap, RuleError> {
    let mut output = HeaderMap::new();
    for header in headers {
        output.append(
            HeaderName::from_bytes(header.name.as_bytes())
                .map_err(|error| RuleError::Invalid(error.to_string()))?,
            HeaderValue::from_str(&header.value)
                .map_err(|error| RuleError::Invalid(error.to_string()))?,
        );
    }
    Ok(output)
}

fn require_prefix(prefix: &str) -> Result<(), RuleError> {
    if prefix.is_empty() {
        Err(RuleError::Invalid("URL prefix cannot be empty".to_owned()))
    } else {
        Ok(())
    }
}

fn validate_optional_prefix(prefix: &str) -> Result<(), RuleError> {
    if prefix.is_empty() {
        Ok(())
    } else {
        require_prefix(prefix)
    }
}

fn default_index() -> String {
    "index.html".to_owned()
}

const fn default_redirect_status() -> u16 {
    302
}

const fn default_mock_status() -> u16 {
    200
}

fn content_type_for_path(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("txt" | "md") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn applies_remote_header_mock_redirect_and_local_rules() {
        let directory = tempdir().unwrap();
        std::fs::write(directory.path().join("index.html"), "local home").unwrap();
        let mut rules = RouteRules {
            rules: vec![
                RouteRule::SetRequestHeader {
                    url_prefix: "https://api.test/".to_owned(),
                    name: "x-proxelar".to_owned(),
                    value: "yes".to_owned(),
                },
                RouteRule::MapRemote {
                    url_prefix: "https://api.test/v1".to_owned(),
                    target_prefix: "http://localhost:3000/v2".to_owned(),
                },
            ],
        };
        let mut uri: Uri = "https://api.test/v1/items".parse().unwrap();
        let mut headers = HeaderMap::new();
        assert!(matches!(
            rules
                .apply(&Method::GET, &mut uri, &mut headers)
                .await
                .unwrap(),
            RuleOutcome::Forward
        ));
        assert_eq!(uri.to_string(), "http://localhost:3000/v2/items");
        assert_eq!(headers["x-proxelar"], "yes");

        rules.rules = vec![RouteRule::MapLocal {
            url_prefix: "https://site.test/".to_owned(),
            directory: directory.path().to_owned(),
            index: "index.html".to_owned(),
        }];
        let mut uri = "https://site.test/".parse().unwrap();
        match rules
            .apply(&Method::GET, &mut uri, &mut headers)
            .await
            .unwrap()
        {
            RuleOutcome::Respond { status, body, .. } => {
                assert_eq!(status, StatusCode::OK);
                assert_eq!(body, "local home");
            }
            RuleOutcome::Forward => panic!("expected local response"),
        }

        rules.rules = vec![RouteRule::Mock {
            url_prefix: "https://api.test/mock".to_owned(),
            method: Some("POST".to_owned()),
            status: 201,
            headers: vec![],
            body: "created".to_owned(),
        }];
        let mut uri = "https://api.test/mock".parse().unwrap();
        assert!(matches!(
            rules
                .apply(&Method::POST, &mut uri, &mut headers)
                .await
                .unwrap(),
            RuleOutcome::Respond {
                status: StatusCode::CREATED,
                ..
            }
        ));
    }

    #[test]
    fn rejects_local_path_traversal_and_invalid_redirect_status() {
        assert!(safe_local_path(Path::new("/tmp/safe"), "../secret", "index.html").is_err());
        let rules = RouteRules {
            rules: vec![RouteRule::Redirect {
                url_prefix: "https://old.test".to_owned(),
                location: "https://new.test".to_owned(),
                status: 200,
            }],
        };
        assert!(rules.validate().is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_map_local_symlinks_that_escape_the_root() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            root.path().join("escape.txt"),
        )
        .unwrap();
        let rules = RouteRules {
            rules: vec![RouteRule::MapLocal {
                url_prefix: "https://site.test/".to_owned(),
                directory: root.path().to_owned(),
                index: "index.html".to_owned(),
            }],
        };
        let mut uri = "https://site.test/escape.txt".parse().unwrap();

        let error = rules
            .apply(&Method::GET, &mut uri, &mut HeaderMap::new())
            .await
            .unwrap_err();

        assert!(error.to_string().contains("symlink escapes"));
    }

    #[test]
    fn loads_builds_and_validates_every_rule_shape() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("rules.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "rules": [
                    {
                        "action": "redirect",
                        "url_prefix": "https://old.test/",
                        "location": "https://new.test/"
                    },
                    {
                        "action": "mock",
                        "url_prefix": "https://api.test/",
                        "headers": [{"name": "x-test", "value": "yes"}],
                        "body": "ok"
                    }
                ]
            })
            .to_string(),
        )
        .unwrap();
        let loaded = RouteRules::load(&path).unwrap();
        assert_eq!(loaded.rules.len(), 2);
        assert!(matches!(
            loaded.rules[0],
            RouteRule::Redirect { status: 302, .. }
        ));
        assert!(matches!(
            loaded.rules[1],
            RouteRule::Mock { status: 200, .. }
        ));

        let mut built = RouteRules::default();
        built
            .map_remote("https://old.test/", "https://new.test/")
            .unwrap();
        built
            .map_local("https://local.test/", directory.path())
            .unwrap();
        assert_eq!(built.rules.len(), 2);

        assert!(matches!(
            RouteRules::load(directory.path().join("missing.json")),
            Err(RuleError::Io(_))
        ));
        std::fs::write(&path, "{not json").unwrap();
        assert!(matches!(RouteRules::load(&path), Err(RuleError::Json(_))));

        let invalid_rules = [
            RouteRule::MapRemote {
                url_prefix: String::new(),
                target_prefix: "https://target.test".to_owned(),
            },
            RouteRule::MapRemote {
                url_prefix: "https://source.test".to_owned(),
                target_prefix: String::new(),
            },
            RouteRule::MapLocal {
                url_prefix: "https://source.test".to_owned(),
                directory: PathBuf::new(),
                index: "index.html".to_owned(),
            },
            RouteRule::MapLocal {
                url_prefix: "https://source.test".to_owned(),
                directory: directory.path().to_owned(),
                index: String::new(),
            },
            RouteRule::Redirect {
                url_prefix: "https://source.test".to_owned(),
                location: String::new(),
                status: 302,
            },
            RouteRule::Mock {
                url_prefix: "https://source.test".to_owned(),
                method: Some("bad method".to_owned()),
                status: 200,
                headers: Vec::new(),
                body: String::new(),
            },
            RouteRule::Mock {
                url_prefix: "https://source.test".to_owned(),
                method: None,
                status: 99,
                headers: Vec::new(),
                body: String::new(),
            },
            RouteRule::Mock {
                url_prefix: "https://source.test".to_owned(),
                method: None,
                status: 200,
                headers: vec![RuleHeader {
                    name: "bad header".to_owned(),
                    value: "value".to_owned(),
                }],
                body: String::new(),
            },
            RouteRule::SetRequestHeader {
                url_prefix: String::new(),
                name: "bad header".to_owned(),
                value: "value".to_owned(),
            },
            RouteRule::SetRequestHeader {
                url_prefix: String::new(),
                name: "x-test".to_owned(),
                value: "bad\nvalue".to_owned(),
            },
            RouteRule::RemoveRequestHeader {
                url_prefix: String::new(),
                name: "bad header".to_owned(),
            },
        ];
        for rule in invalid_rules {
            assert!(RouteRules { rules: vec![rule] }.validate().is_err());
        }
    }

    #[tokio::test]
    async fn applies_header_redirect_mock_and_local_edge_cases() {
        let directory = tempdir().unwrap();
        std::fs::write(directory.path().join("index.html"), "home").unwrap();
        std::fs::write(directory.path().join("styles.css"), "body {}").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-remove", "gone".parse().unwrap());
        let rules = RouteRules {
            rules: vec![
                RouteRule::SetRequestHeader {
                    url_prefix: String::new(),
                    name: "x-added".to_owned(),
                    value: "present".to_owned(),
                },
                RouteRule::RemoveRequestHeader {
                    url_prefix: "https://site.test/".to_owned(),
                    name: "x-remove".to_owned(),
                },
                RouteRule::Redirect {
                    url_prefix: "https://site.test/old".to_owned(),
                    location: "https://site.test/new".to_owned(),
                    status: 307,
                },
            ],
        };
        let mut uri: Uri = "https://site.test/old/path".parse().unwrap();
        let outcome = rules
            .apply(&Method::GET, &mut uri, &mut headers)
            .await
            .unwrap();
        assert_eq!(headers["x-added"], "present");
        assert!(!headers.contains_key("x-remove"));
        let RuleOutcome::Respond {
            status,
            headers,
            body,
        } = outcome
        else {
            panic!("expected redirect");
        };
        assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            headers[rama::http::header::LOCATION],
            "https://site.test/new/path"
        );
        assert!(body.is_empty());

        let local = RouteRules {
            rules: vec![RouteRule::MapLocal {
                url_prefix: "https://site.test/".to_owned(),
                directory: directory.path().to_owned(),
                index: "index.html".to_owned(),
            }],
        };
        let mut uri = "https://site.test/styles.css?cache=1".parse().unwrap();
        let RuleOutcome::Respond {
            status,
            headers,
            body,
        } = local
            .apply(&Method::HEAD, &mut uri, &mut HeaderMap::new())
            .await
            .unwrap()
        else {
            panic!("expected local response");
        };
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers[rama::http::header::CONTENT_TYPE],
            "text/css; charset=utf-8"
        );
        assert!(body.is_empty());

        let mut uri = "https://site.test/index.html".parse().unwrap();
        assert!(matches!(
            local
                .apply(&Method::POST, &mut uri, &mut HeaderMap::new())
                .await
                .unwrap(),
            RuleOutcome::Respond {
                status: StatusCode::METHOD_NOT_ALLOWED,
                ..
            }
        ));

        let missing_directory = RouteRules {
            rules: vec![RouteRule::MapLocal {
                url_prefix: "https://missing.test/".to_owned(),
                directory: directory.path().join("missing"),
                index: "index.html".to_owned(),
            }],
        };
        let mut uri = "https://missing.test/".parse().unwrap();
        assert!(matches!(
            missing_directory
                .apply(&Method::GET, &mut uri, &mut HeaderMap::new())
                .await
                .unwrap(),
            RuleOutcome::Respond {
                status: StatusCode::NOT_FOUND,
                ..
            }
        ));

        let mut uri = "https://site.test/missing.txt".parse().unwrap();
        assert!(matches!(
            local
                .apply(&Method::GET, &mut uri, &mut HeaderMap::new())
                .await
                .unwrap(),
            RuleOutcome::Respond {
                status: StatusCode::NOT_FOUND,
                ..
            }
        ));

        let mock = RouteRules {
            rules: vec![RouteRule::Mock {
                url_prefix: "https://api.test/".to_owned(),
                method: Some("POST".to_owned()),
                status: 202,
                headers: vec![
                    RuleHeader {
                        name: "x-repeat".to_owned(),
                        value: "one".to_owned(),
                    },
                    RuleHeader {
                        name: "x-repeat".to_owned(),
                        value: "two".to_owned(),
                    },
                ],
                body: "accepted".to_owned(),
            }],
        };
        let mut uri = "https://api.test/items".parse().unwrap();
        assert!(matches!(
            mock.apply(&Method::GET, &mut uri, &mut HeaderMap::new())
                .await
                .unwrap(),
            RuleOutcome::Forward
        ));
        let RuleOutcome::Respond { headers, body, .. } = mock
            .apply(&Method::POST, &mut uri, &mut HeaderMap::new())
            .await
            .unwrap()
        else {
            panic!("expected mock response");
        };
        assert_eq!(headers.get_all("x-repeat").iter().count(), 2);
        assert_eq!(body, "accepted");

        let invalid_remote = RouteRules {
            rules: vec![RouteRule::MapRemote {
                url_prefix: "https://source.test/".to_owned(),
                target_prefix: "http://[".to_owned(),
            }],
        };
        let mut uri = "https://source.test/path".parse().unwrap();
        assert!(invalid_remote
            .apply(&Method::GET, &mut uri, &mut HeaderMap::new())
            .await
            .is_err());

        for (extension, expected) in [
            ("index.htm", "text/html; charset=utf-8"),
            ("app.js", "text/javascript; charset=utf-8"),
            ("app.mjs", "text/javascript; charset=utf-8"),
            ("data.json", "application/json"),
            ("icon.svg", "image/svg+xml"),
            ("image.png", "image/png"),
            ("image.jpg", "image/jpeg"),
            ("image.jpeg", "image/jpeg"),
            ("image.gif", "image/gif"),
            ("image.webp", "image/webp"),
            ("readme.txt", "text/plain; charset=utf-8"),
            ("readme.md", "text/plain; charset=utf-8"),
            ("archive.bin", "application/octet-stream"),
        ] {
            assert_eq!(content_type_for_path(Path::new(extension)), expected);
        }
    }
}
