//! Lua scripting engine for request/response transformation.
//!
//! Users write Lua scripts defining `on_request` and/or `on_response` hooks.
//! The proxy calls these hooks for every request/response passing through.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

use bytes::Bytes;
use mlua::{
    AnyUserData, Lua, MetaMethod, MultiValue, Result as LuaResult, UserData, UserDataMethods, Value,
};
use proxyapi_models::HeaderBlock;

/// Action returned by the Lua `on_request` hook.
#[derive(Debug)]
pub enum ScriptRequestAction {
    /// Forward the (possibly modified) request to upstream.
    Forward {
        method: String,
        url: String,
        headers: HeaderBlock,
        body: Bytes,
    },
    /// Short-circuit: return this response directly without contacting upstream.
    ShortCircuit {
        status: u16,
        headers: HeaderBlock,
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
        headers: HeaderBlock,
        body: Bytes,
    },
    /// No script or script returned nil — pass through unchanged.
    PassThrough,
}

/// Action returned by the optional Lua `on_websocket_frame` hook.
#[derive(Debug)]
pub enum ScriptWebSocketAction {
    PassThrough,
    Forward(Bytes),
    Drop,
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
    state: Mutex<ScriptState>,
    script_path: PathBuf,
}

struct ScriptState {
    lua: Lua,
    signature: Option<(SystemTime, u64)>,
}

impl ScriptEngine {
    /// Create a new engine, in mlua's safe mode, from the given Lua script file.
    ///
    /// The script should define `on_request(request)` and/or `on_response(request, response)`.
    pub fn new(script_path: &Path) -> Result<Self, crate::Error> {
        Self::load(script_path)
    }

    fn load(script_path: &Path) -> Result<Self, crate::Error> {
        let script_path = resolve_script_path(script_path)?;
        let lua = Lua::new();
        load_script(&script_path, &lua)?;
        let signature = script_signature(&script_path).ok();
        Ok(Self {
            state: Mutex::new(ScriptState { lua, signature }),
            script_path,
        })
    }

    /// Reload the script after a file change. Invalid updates are logged and
    /// the last known-good VM remains active, so traffic continues to pass.
    fn lock_reloaded(&self) -> MutexGuard<'_, ScriptState> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let Ok(signature) = script_signature(&self.script_path) else {
            return state;
        };
        if state.signature == Some(signature) {
            return state;
        }

        let lua = Lua::new();
        match load_script(&self.script_path, &lua) {
            Ok(()) => {
                state.lua = lua;
                state.signature = Some(signature);
                tracing::info!("Reloaded Lua script: {}", self.script_path.display());
            }
            Err(error) => {
                // Remember this signature to avoid retrying the same broken
                // contents on every request. A subsequent edit retries.
                state.signature = Some(signature);
                tracing::warn!(
                    "Lua script reload failed; keeping last known-good version: {error}"
                );
            }
        }
        state
    }

    /// Force a reload now, retaining the current script when the new contents
    /// are invalid.
    pub fn reload(&self) -> Result<(), crate::Error> {
        let lua = Lua::new();
        load_script(&self.script_path, &lua)?;
        let signature = script_signature(&self.script_path).ok();
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.lua = lua;
        state.signature = signature;
        Ok(())
    }

    /// Path watched for script changes.
    pub fn script_path(&self) -> &Path {
        &self.script_path
    }

    /// Call the Lua `on_request` hook if it exists.
    pub fn on_request(
        &self,
        method: &str,
        url: &str,
        headers: &HeaderBlock,
        body: &[u8],
    ) -> Result<ScriptRequestAction, crate::Error> {
        let state = self.lock_reloaded();
        let lua = &state.lua;

        let globals = lua.globals();
        let func: mlua::Function = match globals.get("on_request") {
            Ok(f) => f,
            Err(_) => return Ok(ScriptRequestAction::PassThrough),
        };

        let req_table = request_to_lua_table(lua, method, url, headers, body)
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
                    let headers = lua_value_to_header_block(
                        lua,
                        t.get::<Value>("headers").unwrap_or(Value::Nil),
                    )
                    .map_err(|e| crate::Error::Script(format!("Invalid response headers: {e}")))?;
                    let body: Bytes = t
                        .get::<mlua::LuaString>("body")
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
                    let headers = lua_value_to_header_block(
                        lua,
                        t.get::<Value>("headers").unwrap_or(Value::Nil),
                    )
                    .map_err(|e| crate::Error::Script(format!("Invalid request headers: {e}")))?;
                    let body: Bytes = t
                        .get::<mlua::LuaString>("body")
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
        headers: &HeaderBlock,
        body: &[u8],
    ) -> Result<ScriptResponseAction, crate::Error> {
        let state = self.lock_reloaded();
        let lua = &state.lua;

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

        let res_table = response_to_lua_table(lua, status, headers, body)
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
                let headers =
                    lua_value_to_header_block(lua, t.get::<Value>("headers").unwrap_or(Value::Nil))
                        .map_err(|e| {
                            crate::Error::Script(format!("Invalid response headers: {e}"))
                        })?;
                let body: Bytes = t
                    .get::<mlua::LuaString>("body")
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

    /// Call `on_websocket_frame(frame)` when it exists. The hook may return
    /// `nil` to pass through, `false` to drop, or a string payload to replace.
    pub fn on_websocket_frame(
        &self,
        direction: &str,
        opcode: &str,
        payload: &[u8],
    ) -> Result<ScriptWebSocketAction, crate::Error> {
        let state = self.lock_reloaded();
        let lua = &state.lua;
        let globals = lua.globals();
        let function: mlua::Function = match globals.get("on_websocket_frame") {
            Ok(function) => function,
            Err(_) => return Ok(ScriptWebSocketAction::PassThrough),
        };
        let frame = lua
            .create_table()
            .and_then(|frame| {
                frame.set("direction", direction)?;
                frame.set("opcode", opcode)?;
                frame.set("payload", lua.create_string(payload)?)?;
                Ok(frame)
            })
            .map_err(|error| {
                crate::Error::Script(format!("Failed to build WebSocket frame table: {error}"))
            })?;
        match function
            .call::<Value>(frame)
            .map_err(|error| crate::Error::Script(format!("on_websocket_frame error: {error}")))?
        {
            Value::Nil => Ok(ScriptWebSocketAction::PassThrough),
            Value::Boolean(false) => Ok(ScriptWebSocketAction::Drop),
            Value::String(payload) => Ok(ScriptWebSocketAction::Forward(Bytes::copy_from_slice(
                &payload.as_bytes(),
            ))),
            other => Err(crate::Error::Script(format!(
                "on_websocket_frame must return a string, false, or nil, got: {other:?}"
            ))),
        }
    }
}

fn script_signature(script_path: &Path) -> Result<(SystemTime, u64), crate::Error> {
    let metadata = std::fs::metadata(script_path).map_err(|error| {
        crate::Error::Script(format!(
            "Failed to inspect script {}: {error}",
            script_path.display()
        ))
    })?;
    Ok((
        metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        metadata.len(),
    ))
}

fn load_script(script_path: &Path, lua: &Lua) -> Result<(), crate::Error> {
    if let Some(directory) = script_path.parent() {
        if let Ok(package) = lua.globals().get::<mlua::Table>("package") {
            let current = package.get::<String>("path").unwrap_or_default();
            let directory = directory.to_string_lossy();
            let path = format!("{directory}/?.lua;{directory}/?/init.lua;{current}");
            package.set("path", path).map_err(|error| {
                crate::Error::Script(format!("Failed to configure Lua module path: {error}"))
            })?;
        }
    }
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
    })
}

fn resolve_script_path(script_path: &Path) -> Result<PathBuf, crate::Error> {
    if !script_path.is_dir() {
        return Ok(script_path.to_owned());
    }

    let manifest_path = script_path.join(crate::addon::ADDON_MANIFEST_FILE);
    if !manifest_path.exists() {
        return Ok(script_path.join("init.lua"));
    }

    let package = crate::addon::AddonPackage::load(script_path)
        .map_err(|error| crate::Error::Script(format!("Invalid addon package: {error}")))?;
    if package.manifest().requires_native_modules {
        return Err(crate::Error::Script(format!(
            "Addon {} requires native Lua modules, which are prohibited by proxyapi's unsafe-code policy",
            package.manifest().name
        )));
    }
    Ok(package.entrypoint().to_owned())
}

#[derive(Clone, Debug)]
struct LuaHeaders(HeaderBlock);

impl UserData for LuaHeaders {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("get", |lua, headers, name: mlua::LuaString| {
            headers
                .0
                .get(name.as_bytes())
                .map(|value| lua.create_string(value))
                .transpose()
        });
        methods.add_method("get_all", |lua, headers, name: mlua::LuaString| {
            let values = lua.create_table()?;
            for (index, value) in headers.0.get_all(name.as_bytes()).enumerate() {
                values.set(index + 1, lua.create_string(value)?)?;
            }
            Ok(values)
        });
        methods.add_method_mut(
            "set",
            |_, headers, (name, value): (mlua::LuaString, mlua::LuaString)| {
                headers
                    .0
                    .set(name.as_bytes(), value.as_bytes())
                    .map_err(header_error)
            },
        );
        methods.add_method_mut(
            "add",
            |_, headers, (name, value): (mlua::LuaString, mlua::LuaString)| {
                headers
                    .0
                    .add(name.as_bytes(), value.as_bytes())
                    .map_err(header_error)
            },
        );
        methods.add_method_mut("remove", |_, headers, name: mlua::LuaString| {
            Ok(headers.0.remove(name.as_bytes()))
        });
        methods.add_method("iter", |lua, headers, ()| {
            ordered_header_iterator(lua, &headers.0)
        });

        // Compatibility for existing scripts: bracket reads return the first
        // value and assignments use `set`; assigning nil removes every value.
        methods.add_meta_method(MetaMethod::Index, |lua, headers, name: mlua::LuaString| {
            headers
                .0
                .get(name.as_bytes())
                .map(|value| lua.create_string(value))
                .transpose()
        });
        methods.add_meta_method_mut(
            MetaMethod::NewIndex,
            |_, headers, (name, value): (mlua::LuaString, Value)| {
                set_legacy_header_value(&mut headers.0, &name, value)
            },
        );
        methods.add_meta_method(MetaMethod::Len, |_, headers, ()| Ok(headers.0.len()));
        methods.add_meta_method(MetaMethod::Pairs, |lua, headers, ()| {
            Ok((
                ordered_header_iterator(lua, &headers.0)?,
                Value::Nil,
                Value::Nil,
            ))
        });
    }
}

fn header_error(error: proxyapi_models::HeaderFieldError) -> mlua::Error {
    mlua::Error::external(format!("Invalid header: {error}"))
}

fn ordered_header_iterator(lua: &Lua, headers: &HeaderBlock) -> LuaResult<mlua::Function> {
    let fields = headers
        .iter()
        .map(|field| (field.name().to_vec(), field.value().to_vec()))
        .collect::<Vec<_>>();
    let mut index = 0;
    lua.create_function_mut(move |lua, _: MultiValue| {
        let Some((name, value)) = fields.get(index) else {
            return Ok(MultiValue::new());
        };
        index += 1;
        Ok(MultiValue::from_vec(vec![
            Value::String(lua.create_string(name)?),
            Value::String(lua.create_string(value)?),
        ]))
    })
}

fn set_legacy_header_value(
    headers: &mut HeaderBlock,
    name: &mlua::LuaString,
    value: Value,
) -> LuaResult<()> {
    match value {
        Value::Nil => {
            headers.remove(name.as_bytes());
            Ok(())
        }
        Value::String(value) => headers
            .set(name.as_bytes(), value.as_bytes())
            .map_err(header_error),
        Value::Table(values) => {
            let mut values = values.sequence_values::<mlua::LuaString>();
            if let Some(value) = values.next() {
                headers
                    .set(name.as_bytes(), value?.as_bytes())
                    .map_err(header_error)?;
            } else {
                headers.remove(name.as_bytes());
            }
            for value in values {
                headers
                    .add(name.as_bytes(), value?.as_bytes())
                    .map_err(header_error)?;
            }
            Ok(())
        }
        other => Err(mlua::Error::external(format!(
            "Header value for '{}' must be a string, array of strings, or nil; got {}",
            name.to_string_lossy(),
            other.type_name()
        ))),
    }
}

fn lua_value_to_header_block(lua: &Lua, value: Value) -> LuaResult<HeaderBlock> {
    match value {
        Value::Nil => Ok(HeaderBlock::new()),
        Value::UserData(headers) => clone_lua_headers(&headers),
        Value::Table(table) => legacy_lua_table_to_header_block(lua, &table),
        other => Err(mlua::Error::external(format!(
            "headers must be a header object or table, got {}",
            other.type_name()
        ))),
    }
}

fn clone_lua_headers(headers: &AnyUserData) -> LuaResult<HeaderBlock> {
    Ok(headers.borrow::<LuaHeaders>()?.0.clone())
}

fn legacy_lua_table_to_header_block(_lua: &Lua, table: &mlua::Table) -> LuaResult<HeaderBlock> {
    let mut headers = HeaderBlock::new();
    for pair in table.clone().pairs::<mlua::LuaString, Value>() {
        let (name, value) = pair?;
        match value {
            Value::String(value) => headers
                .add(name.as_bytes(), value.as_bytes())
                .map_err(header_error)?,
            Value::Table(values) => {
                for value in values.sequence_values::<mlua::LuaString>() {
                    headers
                        .add(name.as_bytes(), value?.as_bytes())
                        .map_err(header_error)?;
                }
            }
            other => {
                return Err(mlua::Error::external(format!(
                    "Header value for '{}' must be a string or array of strings, got {}",
                    name.to_string_lossy(),
                    other.type_name()
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
    headers: &HeaderBlock,
    body: &[u8],
) -> LuaResult<mlua::Table> {
    let table = lua.create_table()?;
    table.set("method", method)?;
    table.set("url", url)?;
    table.set("headers", LuaHeaders(headers.clone()))?;
    table.set("body", lua.create_string(body)?)?;
    Ok(table)
}

/// Build a Lua response table from its parts.
fn response_to_lua_table(
    lua: &Lua,
    status: u16,
    headers: &HeaderBlock,
    body: &[u8],
) -> LuaResult<mlua::Table> {
    let table = lua.create_table()?;
    table.set("status", status)?;
    table.set("headers", LuaHeaders(headers.clone()))?;
    table.set("body", lua.create_string(body)?)?;
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{tempdir, NamedTempFile};

    fn engine_from_script(script: &str) -> ScriptEngine {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(script.as_bytes()).unwrap();
        f.flush().unwrap();
        ScriptEngine::new(f.path()).unwrap()
    }

    #[test]
    fn test_safe_mode_blocks_c_modules() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(br#"package.loadlib("whatever.so", "luaopen_whatever")"#)
            .unwrap();
        file.flush().unwrap();
        let err = match ScriptEngine::new(file.path()) {
            Ok(_) => panic!("native module loading should fail in safe mode"),
            Err(error) => error.to_string(),
        };
        assert!(err.contains("safe mode"), "got: {err}");
    }

    #[test]
    fn ordered_header_methods_preserve_duplicates_casing_binary_values_and_order() {
        let engine = engine_from_script(
            r#"
            function on_request(req)
                assert(req.headers:get("x-first") == "one")
                local duplicates = req.headers:get_all("X-DUP")
                assert(#duplicates == 2)
                assert(duplicates[1] == "alpha")
                assert(duplicates[2] == string.char(255, 128))

                local names = {}
                for name, _ in req.headers:iter() do
                    table.insert(names, name)
                end
                assert(table.concat(names, ",") == "X-First,X-Dup,X-Middle,x-dup")

                local pair_names = {}
                for name, _ in pairs(req.headers) do
                    table.insert(pair_names, name)
                end
                assert(table.concat(pair_names, ",") == "X-First,X-Dup,X-Middle,x-dup")

                req.headers:set("X-Dup", "replacement")
                req.headers:add("X-Dup", "tail")
                assert(req.headers:remove("x-first") == 1)
                return req
            end
            "#,
        );
        let mut headers = HeaderBlock::new();
        headers.add("X-First", "one").unwrap();
        headers.add("X-Dup", "alpha").unwrap();
        headers.add("X-Middle", "middle").unwrap();
        headers.add("x-dup", [0xff, 0x80]).unwrap();

        let action = engine
            .on_request("GET", "http://example.test", &headers, b"")
            .unwrap();
        let ScriptRequestAction::Forward { headers, .. } = action else {
            panic!("expected modified request");
        };
        let fields = headers
            .iter()
            .map(|field| (field.name(), field.value()))
            .collect::<Vec<_>>();
        assert_eq!(
            fields,
            vec![
                (b"X-Dup".as_slice(), b"replacement".as_slice()),
                (b"X-Middle".as_slice(), b"middle".as_slice()),
                (b"X-Dup".as_slice(), b"tail".as_slice()),
            ]
        );
    }

    #[test]
    fn bracket_assignment_remains_a_set_remove_compatibility_alias() {
        let engine = engine_from_script(
            r#"
            function on_request(req)
                assert(req.headers["x-test"] == "first")
                req.headers["x-test"] = "replacement"
                req.headers["x-remove"] = nil
                return req
            end
            "#,
        );
        let mut headers = HeaderBlock::new();
        headers.add("X-Test", "first").unwrap();
        headers.add("x-test", "second").unwrap();
        headers.add("X-Remove", "gone").unwrap();

        let action = engine
            .on_request("GET", "http://example.test", &headers, b"")
            .unwrap();
        let ScriptRequestAction::Forward { headers, .. } = action else {
            panic!("expected modified request");
        };
        assert_eq!(
            headers.get_all("x-test").collect::<Vec<_>>(),
            vec![b"replacement".as_slice()]
        );
        assert!(!headers.contains_key("x-remove"));
    }

    #[test]
    fn test_on_request_passthrough_no_function() {
        let engine = engine_from_script("-- empty script");
        let headers = HeaderBlock::new();
        let result = engine
            .on_request("GET", "http://example.com", &headers, b"")
            .unwrap();
        assert!(matches!(result, ScriptRequestAction::PassThrough));
    }

    #[test]
    fn test_on_request_passthrough_nil() {
        let engine = engine_from_script("function on_request(req) return nil end");
        let headers = HeaderBlock::new();
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
        let headers = HeaderBlock::new();
        let result = engine
            .on_request("GET", "http://example.com", &headers, b"")
            .unwrap();
        match result {
            ScriptRequestAction::Forward { headers, .. } => {
                assert_eq!(headers.get("x-added"), Some(b"yes".as_slice()));
            }
            _ => panic!("Expected Forward"),
        }
    }

    #[test]
    fn addon_directory_loads_init_and_relative_lua_modules() {
        let directory = tempdir().unwrap();
        std::fs::write(
            directory.path().join("addon.lua"),
            r#"return { value = "community-addon" }"#,
        )
        .unwrap();
        std::fs::write(
            directory.path().join("init.lua"),
            r#"
                local addon = require("addon")
                function on_request(req)
                    req.headers["x-addon"] = addon.value
                    return req
                end
            "#,
        )
        .unwrap();

        let engine = ScriptEngine::new(directory.path()).unwrap();
        let action = engine
            .on_request("GET", "http://example.test", &HeaderBlock::new(), b"")
            .unwrap();
        assert!(matches!(
            action,
            ScriptRequestAction::Forward { headers, .. }
                if headers.get("x-addon") == Some(b"community-addon".as_slice())
        ));
        assert_eq!(engine.script_path(), directory.path().join("init.lua"));
    }

    #[test]
    fn manifested_addon_uses_validated_entrypoint() {
        let directory = tempdir().unwrap();
        let script = br#"
            function on_request(req)
                req.headers["x-addon"] = "manifested"
                return req
            end
        "#;
        std::fs::write(directory.path().join("main.lua"), script).unwrap();
        let digest = {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(script);
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        std::fs::write(
            directory.path().join(crate::addon::ADDON_MANIFEST_FILE),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": 1,
                "name": "manifested-addon",
                "version": "1.0.0",
                "description": "test package",
                "entrypoint": "main.lua",
                "hooks": ["request"],
                "files": { "main.lua": digest }
            }))
            .unwrap(),
        )
        .unwrap();

        let engine = ScriptEngine::new(directory.path()).unwrap();
        let action = engine
            .on_request("GET", "http://example.test", &HeaderBlock::new(), b"")
            .unwrap();
        assert!(matches!(
            action,
            ScriptRequestAction::Forward { headers, .. }
                if headers.get("x-addon") == Some(b"manifested".as_slice())
        ));
        assert_eq!(
            engine.script_path(),
            directory.path().join("main.lua").canonicalize().unwrap()
        );
    }

    #[test]
    fn reloads_changed_script_and_keeps_last_good_version() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            br#"function on_request(req) req.headers["x-version"] = "one" return req end"#,
        )
        .unwrap();
        file.flush().unwrap();
        let engine = ScriptEngine::new(file.path()).unwrap();

        std::fs::write(
            file.path(),
            br#"function on_request(req) req.headers["x-version"] = "version-two" return req end"#,
        )
        .unwrap();
        let action = engine
            .on_request("GET", "http://example.test", &HeaderBlock::new(), b"")
            .unwrap();
        match action {
            ScriptRequestAction::Forward { headers, .. } => {
                assert_eq!(headers.get("x-version"), Some(b"version-two".as_slice()));
            }
            _ => panic!("expected modified request"),
        }

        std::fs::write(
            file.path(),
            b"this is invalid Lua and deliberately longer than before",
        )
        .unwrap();
        let action = engine
            .on_request("GET", "http://example.test", &HeaderBlock::new(), b"")
            .unwrap();
        match action {
            ScriptRequestAction::Forward { headers, .. } => {
                assert_eq!(headers.get("x-version"), Some(b"version-two".as_slice()));
            }
            _ => panic!("expected last known-good request hook"),
        }
    }

    #[test]
    fn websocket_hook_can_modify_drop_and_pass_frames() {
        let engine = engine_from_script(
            r#"
            function on_websocket_frame(frame)
                if frame.payload == "drop" then return false end
                if frame.direction == "client_to_server" then return "changed" end
                return nil
            end
            "#,
        );
        assert!(matches!(
            engine
                .on_websocket_frame("client_to_server", "text", b"hello")
                .unwrap(),
            ScriptWebSocketAction::Forward(payload) if payload == "changed"
        ));
        assert!(matches!(
            engine
                .on_websocket_frame("server_to_client", "text", b"drop")
                .unwrap(),
            ScriptWebSocketAction::Drop
        ));
        assert!(matches!(
            engine
                .on_websocket_frame("server_to_client", "text", b"hello")
                .unwrap(),
            ScriptWebSocketAction::PassThrough
        ));
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
        let headers = HeaderBlock::new();
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
        let headers = HeaderBlock::new();

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
        let headers = HeaderBlock::new();

        let err = engine
            .on_request("GET", "http://example.com", &headers, b"")
            .unwrap_err()
            .to_string();

        assert!(err.contains("Header value for 'x-bad' must be a string"));
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
        let headers = HeaderBlock::new();
        let result = engine
            .on_response("GET", "http://example.com", 200, &headers, b"body")
            .unwrap();
        match result {
            ScriptResponseAction::Modified {
                status, headers, ..
            } => {
                assert_eq!(status, 201);
                assert_eq!(headers.get("x-proxy"), Some(b"proxelar".as_slice()));
            }
            _ => panic!("Expected Modified"),
        }
    }

    #[test]
    fn test_on_response_passthrough() {
        let engine = engine_from_script("-- no on_response defined");
        let headers = HeaderBlock::new();
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
        let headers = HeaderBlock::new();
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
        let headers = HeaderBlock::new();

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
        let headers = HeaderBlock::new();

        let err = engine
            .on_response("GET", "http://example.com", 200, &headers, b"body")
            .unwrap_err()
            .to_string();

        assert!(err.contains("Header value for 'x-bad' must be a string"));
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
        let headers = HeaderBlock::new();
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
        let headers = HeaderBlock::new();
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
        let mut headers = HeaderBlock::new();
        headers.add("content-type", "application/json").unwrap();
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
        let headers = HeaderBlock::new();
        let result = engine
            .on_response("GET", "http://example.com", 200, &headers, b"")
            .unwrap();
        match result {
            ScriptResponseAction::Modified { headers, .. } => {
                assert_eq!(headers.get("x-req-method"), Some(b"GET".as_slice()));
            }
            _ => panic!("Expected Modified"),
        }
    }
}
