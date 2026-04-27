//! Lua scripting engine for request/response transformation.
//!
//! Users write Lua scripts defining `on_request` and/or `on_response` hooks.
//! The proxy calls these hooks for every request/response passing through.

use std::path::Path;
use std::sync::Mutex;

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::HeaderMap;
use mlua::{Lua, Result as LuaResult, Value};

/// Action returned by the Lua `on_request` hook.
#[derive(Debug)]
pub enum ScriptRequestAction {
    /// Forward the (possibly modified) request to upstream.
    Forward {
        method: String,
        url: String,
        headers: HeaderMap,
        body: Bytes,
    },
    /// Short-circuit: return this response directly without contacting upstream.
    ShortCircuit {
        status: u16,
        headers: HeaderMap,
        body: Bytes,
    },
    /// No script or script returned nil — pass through unchanged.
    PassThrough,
}

/// Action returned by the Lua `on_response` hook.
#[derive(Debug)]
pub enum ScriptResponseAction {
    /// Return the modified response to the client.
    Modified {
        status: u16,
        headers: HeaderMap,
        body: Bytes,
    },
    /// No script or script returned nil — pass through unchanged.
    PassThrough,
}

/// Lua scripting engine that loads a user script and invokes its hooks.
///
/// Thread-safe: the internal `Lua` VM is protected by a `std::sync::Mutex`.
/// The mutex is only held during synchronous Lua calls (microseconds),
/// never across `.await` points.
///
/// `Lua` with the `send` feature is `Send`, and `Mutex<T: Send>` is both
/// `Send` and `Sync`, so `ScriptEngine` is automatically `Send + Sync`.
pub struct ScriptEngine {
    lua: Mutex<Lua>,
}

impl ScriptEngine {
    /// Create a new engine by loading and executing the given Lua script file.
    ///
    /// The script should define `on_request(request)` and/or `on_response(request, response)`.
    pub fn new(script_path: &Path) -> Result<Self, crate::Error> {
        let lua = Lua::new();

        let script = std::fs::read_to_string(script_path).map_err(|e| {
            crate::Error::Script(format!(
                "Failed to read script {}: {e}",
                script_path.display()
            ))
        })?;

        lua.load(&script).exec().map_err(|e| {
            crate::Error::Script(format!(
                "Failed to execute script {}: {e}",
                script_path.display()
            ))
        })?;

        Ok(Self {
            lua: Mutex::new(lua),
        })
    }

    /// Call the Lua `on_request` hook if it exists.
    pub fn on_request(
        &self,
        method: &str,
        url: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<ScriptRequestAction, crate::Error> {
        let lua = self.lua.lock().unwrap_or_else(|e| e.into_inner());

        let globals = lua.globals();
        let func: mlua::Function = match globals.get("on_request") {
            Ok(f) => f,
            Err(_) => return Ok(ScriptRequestAction::PassThrough),
        };

        let req_table = request_to_lua_table(&lua, method, url, headers, body)
            .map_err(|e| crate::Error::Script(format!("Failed to build request table: {e}")))?;

        let result: Value = func
            .call(req_table)
            .map_err(|e| crate::Error::Script(format!("on_request error: {e}")))?;

        match result {
            Value::Nil => Ok(ScriptRequestAction::PassThrough),
            Value::Table(t) => {
                // If the table has a "status" field, it's a short-circuit response
                if t.contains_key("status").unwrap_or(false) {
                    let status: u16 = t
                        .get("status")
                        .map_err(|e| crate::Error::Script(format!("Invalid status: {e}")))?;
                    let headers = lua_table_to_headermap(
                        &t.get::<mlua::Table>("headers")
                            .unwrap_or_else(|_| lua.create_table().unwrap()),
                    )
                    .map_err(|e| crate::Error::Script(format!("Invalid response headers: {e}")))?;
                    let body: Bytes = t
                        .get::<mlua::String>("body")
                        .map(|s| Bytes::copy_from_slice(&s.as_bytes()))
                        .unwrap_or_default();
                    Ok(ScriptRequestAction::ShortCircuit {
                        status,
                        headers,
                        body,
                    })
                } else {
                    // It's a (modified) request table
                    let method: String = t
                        .get("method")
                        .map_err(|e| crate::Error::Script(format!("Invalid method: {e}")))?;
                    let url: String = t
                        .get("url")
                        .map_err(|e| crate::Error::Script(format!("Invalid url: {e}")))?;
                    let headers = lua_table_to_headermap(
                        &t.get::<mlua::Table>("headers")
                            .unwrap_or_else(|_| lua.create_table().unwrap()),
                    )
                    .map_err(|e| crate::Error::Script(format!("Invalid request headers: {e}")))?;
                    let body: Bytes = t
                        .get::<mlua::String>("body")
                        .map(|s| Bytes::copy_from_slice(&s.as_bytes()))
                        .unwrap_or_default();
                    Ok(ScriptRequestAction::Forward {
                        method,
                        url,
                        headers,
                        body,
                    })
                }
            }
            other => Err(crate::Error::Script(format!(
                "on_request must return a table or nil, got: {other:?}"
            ))),
        }
    }

    /// Call the Lua `on_response` hook if it exists.
    pub fn on_response(
        &self,
        req_method: &str,
        req_url: &str,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<ScriptResponseAction, crate::Error> {
        let lua = self.lua.lock().unwrap_or_else(|e| e.into_inner());

        let globals = lua.globals();
        let func: mlua::Function = match globals.get("on_response") {
            Ok(f) => f,
            Err(_) => return Ok(ScriptResponseAction::PassThrough),
        };

        // Build the request context table (lightweight — just method + url)
        let req_table = lua
            .create_table()
            .and_then(|t| {
                t.set("method", req_method)?;
                t.set("url", req_url)?;
                Ok(t)
            })
            .map_err(|e| crate::Error::Script(format!("Failed to build request context: {e}")))?;

        let res_table = response_to_lua_table(&lua, status, headers, body)
            .map_err(|e| crate::Error::Script(format!("Failed to build response table: {e}")))?;

        let result: Value = func
            .call((req_table, res_table))
            .map_err(|e| crate::Error::Script(format!("on_response error: {e}")))?;

        match result {
            Value::Nil => Ok(ScriptResponseAction::PassThrough),
            Value::Table(t) => {
                let status: u16 = t
                    .get("status")
                    .map_err(|e| crate::Error::Script(format!("Invalid status: {e}")))?;
                let headers = lua_table_to_headermap(
                    &t.get::<mlua::Table>("headers")
                        .unwrap_or_else(|_| lua.create_table().unwrap()),
                )
                .map_err(|e| crate::Error::Script(format!("Invalid response headers: {e}")))?;
                let body: Bytes = t
                    .get::<mlua::String>("body")
                    .map(|s| Bytes::copy_from_slice(&s.as_bytes()))
                    .unwrap_or_default();
                Ok(ScriptResponseAction::Modified {
                    status,
                    headers,
                    body,
                })
            }
            other => Err(crate::Error::Script(format!(
                "on_response must return a table or nil, got: {other:?}"
            ))),
        }
    }
}

/// Convert an HTTP `HeaderMap` to a Lua table.
///
/// Single-value headers become plain strings, multi-value headers become arrays.
fn headermap_to_lua_table(lua: &Lua, headers: &HeaderMap) -> LuaResult<mlua::Table> {
    let table = lua.create_table()?;

    // Group header values by name
    let mut seen = std::collections::HashMap::<&str, Vec<&[u8]>>::new();
    for (name, value) in headers.iter() {
        seen.entry(name.as_str())
            .or_default()
            .push(value.as_bytes());
    }

    for (name, values) in seen {
        if values.len() == 1 {
            // Single value → plain string
            table.set(name, lua.create_string(values[0])?)?;
        } else {
            // Multiple values → array
            let arr = lua.create_table()?;
            for (i, v) in values.iter().enumerate() {
                arr.set(i + 1, lua.create_string(v)?)?;
            }
            table.set(name, arr)?;
        }
    }

    Ok(table)
}

/// Convert a Lua table back to an HTTP `HeaderMap`.
///
/// Accepts both plain strings and arrays of strings as values.
fn lua_table_to_headermap(table: &mlua::Table) -> LuaResult<HeaderMap> {
    let mut headers = HeaderMap::new();

    for pair in table.pairs::<mlua::String, Value>() {
        let (key, value) = pair?;
        let header_name = HeaderName::from_bytes(&key.as_bytes())
            .map_err(|e| mlua::Error::external(format!("Invalid header name: {e}")))?;

        match value {
            Value::String(s) => {
                let header_value = HeaderValue::from_bytes(&s.as_bytes())
                    .map_err(|e| mlua::Error::external(format!("Invalid header value: {e}")))?;
                headers.append(header_name, header_value);
            }
            Value::Table(arr) => {
                for v in arr.sequence_values::<mlua::String>() {
                    let s = v?;
                    let header_value = HeaderValue::from_bytes(&s.as_bytes())
                        .map_err(|e| mlua::Error::external(format!("Invalid header value: {e}")))?;
                    headers.append(header_name.clone(), header_value);
                }
            }
            _ => {
                return Err(mlua::Error::external(format!(
                    "Header value for '{}' must be a string or array of strings",
                    key.to_string_lossy()
                )));
            }
        }
    }

    Ok(headers)
}

/// Build a Lua request table from its parts.
fn request_to_lua_table(
    lua: &Lua,
    method: &str,
    url: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> LuaResult<mlua::Table> {
    let table = lua.create_table()?;
    table.set("method", method)?;
    table.set("url", url)?;
    table.set("headers", headermap_to_lua_table(lua, headers)?)?;
    table.set("body", lua.create_string(body)?)?;
    Ok(table)
}

/// Build a Lua response table from its parts.
fn response_to_lua_table(
    lua: &Lua,
    status: u16,
    headers: &HeaderMap,
    body: &[u8],
) -> LuaResult<mlua::Table> {
    let table = lua.create_table()?;
    table.set("status", status)?;
    table.set("headers", headermap_to_lua_table(lua, headers)?)?;
    table.set("body", lua.create_string(body)?)?;
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn engine_from_script(script: &str) -> ScriptEngine {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(script.as_bytes()).unwrap();
        f.flush().unwrap();
        ScriptEngine::new(f.path()).unwrap()
    }

    #[test]
    fn test_headermap_roundtrip_single_value() {
        let lua = Lua::new();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("x-custom", "hello".parse().unwrap());

        let table = headermap_to_lua_table(&lua, &headers).unwrap();
        let back = lua_table_to_headermap(&table).unwrap();

        assert_eq!(back.get("content-type").unwrap(), "application/json");
        assert_eq!(back.get("x-custom").unwrap(), "hello");
    }

    #[test]
    fn test_headermap_roundtrip_multi_value() {
        let lua = Lua::new();
        let mut headers = HeaderMap::new();
        headers.append("set-cookie", "a=1".parse().unwrap());
        headers.append("set-cookie", "b=2".parse().unwrap());

        let table = headermap_to_lua_table(&lua, &headers).unwrap();
        let back = lua_table_to_headermap(&table).unwrap();

        let values: Vec<&str> = back
            .get_all("set-cookie")
            .into_iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(values, vec!["a=1", "b=2"]);
    }

    #[test]
    fn test_on_request_passthrough_no_function() {
        let engine = engine_from_script("-- empty script");
        let headers = HeaderMap::new();
        let result = engine
            .on_request("GET", "http://example.com", &headers, b"")
            .unwrap();
        assert!(matches!(result, ScriptRequestAction::PassThrough));
    }

    #[test]
    fn test_on_request_passthrough_nil() {
        let engine = engine_from_script("function on_request(req) return nil end");
        let headers = HeaderMap::new();
        let result = engine
            .on_request("GET", "http://example.com", &headers, b"")
            .unwrap();
        assert!(matches!(result, ScriptRequestAction::PassThrough));
    }

    #[test]
    fn test_on_request_modify() {
        let engine = engine_from_script(
            r#"
            function on_request(req)
                req.headers["x-added"] = "yes"
                return req
            end
            "#,
        );
        let headers = HeaderMap::new();
        let result = engine
            .on_request("GET", "http://example.com", &headers, b"")
            .unwrap();
        match result {
            ScriptRequestAction::Forward { headers, .. } => {
                assert_eq!(headers.get("x-added").unwrap(), "yes");
            }
            _ => panic!("Expected Forward"),
        }
    }

    #[test]
    fn test_on_request_short_circuit() {
        let engine = engine_from_script(
            r#"
            function on_request(req)
                return { status = 403, headers = {}, body = "blocked" }
            end
            "#,
        );
        let headers = HeaderMap::new();
        let result = engine
            .on_request("GET", "http://example.com", &headers, b"")
            .unwrap();
        match result {
            ScriptRequestAction::ShortCircuit { status, body, .. } => {
                assert_eq!(status, 403);
                assert_eq!(body, "blocked");
            }
            _ => panic!("Expected ShortCircuit"),
        }
    }

    #[test]
    fn test_on_request_rejects_invalid_return_type() {
        let engine = engine_from_script(
            r#"
            function on_request(req)
                return 42
            end
            "#,
        );
        let headers = HeaderMap::new();

        let err = engine
            .on_request("GET", "http://example.com", &headers, b"")
            .unwrap_err()
            .to_string();

        assert!(err.contains("on_request must return a table or nil"));
    }

    #[test]
    fn test_on_request_rejects_invalid_header_value_type() {
        let engine = engine_from_script(
            r#"
            function on_request(req)
                req.headers["x-bad"] = 7
                return req
            end
            "#,
        );
        let headers = HeaderMap::new();

        let err = engine
            .on_request("GET", "http://example.com", &headers, b"")
            .unwrap_err()
            .to_string();

        assert!(err.contains("Header value for 'x-bad' must be a string or array of strings"));
    }

    #[test]
    fn test_on_response_modify() {
        let engine = engine_from_script(
            r#"
            function on_response(req, res)
                res.headers["x-proxy"] = "proxelar"
                res.status = 201
                return res
            end
            "#,
        );
        let headers = HeaderMap::new();
        let result = engine
            .on_response("GET", "http://example.com", 200, &headers, b"body")
            .unwrap();
        match result {
            ScriptResponseAction::Modified {
                status, headers, ..
            } => {
                assert_eq!(status, 201);
                assert_eq!(headers.get("x-proxy").unwrap(), "proxelar");
            }
            _ => panic!("Expected Modified"),
        }
    }

    #[test]
    fn test_on_response_passthrough() {
        let engine = engine_from_script("-- no on_response defined");
        let headers = HeaderMap::new();
        let result = engine
            .on_response("GET", "http://example.com", 200, &headers, b"body")
            .unwrap();
        assert!(matches!(result, ScriptResponseAction::PassThrough));
    }

    #[test]
    fn test_on_response_passthrough_nil() {
        let engine = engine_from_script(
            r#"
            function on_response(req, res)
                return nil
            end
            "#,
        );
        let headers = HeaderMap::new();
        let result = engine
            .on_response("GET", "http://example.com", 200, &headers, b"body")
            .unwrap();

        assert!(matches!(result, ScriptResponseAction::PassThrough));
    }

    #[test]
    fn test_on_response_rejects_invalid_return_type() {
        let engine = engine_from_script(
            r#"
            function on_response(req, res)
                return false
            end
            "#,
        );
        let headers = HeaderMap::new();

        let err = engine
            .on_response("GET", "http://example.com", 200, &headers, b"body")
            .unwrap_err()
            .to_string();

        assert!(err.contains("on_response must return a table or nil"));
    }

    #[test]
    fn test_on_response_rejects_invalid_header_value_type() {
        let engine = engine_from_script(
            r#"
            function on_response(req, res)
                res.headers["x-bad"] = true
                return res
            end
            "#,
        );
        let headers = HeaderMap::new();

        let err = engine
            .on_response("GET", "http://example.com", 200, &headers, b"body")
            .unwrap_err()
            .to_string();

        assert!(err.contains("Header value for 'x-bad' must be a string or array of strings"));
    }

    #[test]
    fn test_script_error_is_reported() {
        let engine = engine_from_script(
            r#"
            function on_request(req)
                error("intentional error")
            end
            "#,
        );
        let headers = HeaderMap::new();
        let result = engine.on_request("GET", "http://example.com", &headers, b"");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("intentional error"), "got: {err_msg}");
    }

    #[test]
    fn test_bad_script_file() {
        let result = ScriptEngine::new(Path::new("/nonexistent/script.lua"));
        assert!(result.is_err());
    }

    #[test]
    fn test_syntax_error_in_script() {
        let result = std::panic::catch_unwind(|| {
            engine_from_script("function on_request(req end") // missing closing paren
        });
        // This should result in an error during ScriptEngine::new, not a panic
        assert!(
            result.is_err() || {
                // If catch_unwind didn't catch a panic, check that it returned an error
                // Actually engine_from_script calls unwrap(), so a syntax error would panic
                // Let's test directly
                true
            }
        );

        // Test properly without unwrap
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"function on_request(req end").unwrap();
        f.flush().unwrap();
        let result = ScriptEngine::new(f.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_binary_body_roundtrip() {
        let engine = engine_from_script(
            r#"
            function on_request(req)
                return req
            end
            "#,
        );
        let headers = HeaderMap::new();
        let binary_body = &[0u8, 1, 2, 255, 254, 253];
        let result = engine
            .on_request("POST", "http://example.com", &headers, binary_body)
            .unwrap();
        match result {
            ScriptRequestAction::Forward { body, .. } => {
                assert_eq!(body.as_ref(), binary_body);
            }
            _ => panic!("Expected Forward"),
        }
    }

    #[test]
    fn test_request_fields_available_in_script() {
        let engine = engine_from_script(
            r#"
            function on_request(req)
                assert(req.method == "POST")
                assert(req.url == "http://example.com/api")
                assert(req.headers["content-type"] == "application/json")
                assert(req.body == '{"key":"value"}')
                return req
            end
            "#,
        );
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        let result = engine.on_request(
            "POST",
            "http://example.com/api",
            &headers,
            b"{\"key\":\"value\"}",
        );
        assert!(result.is_ok(), "Script assertions failed: {result:?}");
    }

    #[test]
    fn test_response_has_request_context() {
        let engine = engine_from_script(
            r#"
            function on_response(req, res)
                assert(req.method == "GET")
                assert(req.url == "http://example.com")
                res.headers["x-req-method"] = req.method
                return res
            end
            "#,
        );
        let headers = HeaderMap::new();
        let result = engine
            .on_response("GET", "http://example.com", 200, &headers, b"")
            .unwrap();
        match result {
            ScriptResponseAction::Modified { headers, .. } => {
                assert_eq!(headers.get("x-req-method").unwrap(), "GET");
            }
            _ => panic!("Expected Modified"),
        }
    }
}
