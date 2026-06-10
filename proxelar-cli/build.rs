fn main() {
    // Export the dynamic symbol table so Lua C modules loaded at runtime can
    // resolve the Lua C API from this executable; without `-rdynamic`, `require`
    // of a C module fails on Unix with `undefined symbol: lua_*`.
    let scripting = std::env::var_os("CARGO_FEATURE_SCRIPTING").is_some();
    let unix = std::env::var_os("CARGO_CFG_UNIX").is_some();
    if scripting && unix {
        println!("cargo::rustc-link-arg-bins=-rdynamic");
    }
}
