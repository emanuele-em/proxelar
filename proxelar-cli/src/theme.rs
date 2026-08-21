//! User-customizable TUI color theme.
//!
//! `Theme::default()` reproduces the original hardcoded palette from
//! `interface::tui::ui` exactly, so introducing this module is a no-op
//! until a user opts into a different theme.

use ratatui::style::{Color, Modifier, Style};
use serde::Deserialize;
use std::fmt;
use std::path::Path;

/// A theme color parsed from a TOML string: `"#rrggbb"` or a named ANSI
/// color (`"red"`, `"light_green"`, `"dark_gray"`, underscore optional).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThemeColor(pub Color);

impl From<ThemeColor> for Color {
    fn from(c: ThemeColor) -> Self {
        c.0
    }
}

fn parse_color(value: &str) -> Option<Color> {
    let normalized = value.trim().to_ascii_lowercase();
    if let Some(hex) = normalized.strip_prefix('#') {
        if hex.len() == 6 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            return Some(Color::Rgb(r, g, b));
        }
        return None;
    }
    Some(match normalized.replace('_', "").as_str() {
        "black" => Color::Black,
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" => Color::Magenta,
        "cyan" => Color::Cyan,
        "gray" | "grey" => Color::Gray,
        "darkgray" | "darkgrey" => Color::DarkGray,
        "lightred" => Color::LightRed,
        "lightgreen" => Color::LightGreen,
        "lightyellow" => Color::LightYellow,
        "lightblue" => Color::LightBlue,
        "lightmagenta" => Color::LightMagenta,
        "lightcyan" => Color::LightCyan,
        "white" => Color::White,
        _ => return None,
    })
}

impl<'de> Deserialize<'de> for ThemeColor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ColorVisitor;
        impl serde::de::Visitor<'_> for ColorVisitor {
            type Value = ThemeColor;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a hex color (\"#rrggbb\") or a named ANSI color (\"red\", \"light_green\", ...)")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                parse_color(v)
                    .map(ThemeColor)
                    .ok_or_else(|| E::custom(format!("invalid color '{v}'")))
            }
        }
        deserializer.deserialize_str(ColorVisitor)
    }
}

const SCHEMA_VERSION: u32 = 1;

/// Every colorable role in the TUI. Missing keys in a theme TOML file fall
/// back to [`Theme::default`] (see the container-level `#[serde(default)]`).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Theme {
    pub schema_version: u32,

    // Chrome
    pub table_header: ThemeColor,
    pub selection_bg: ThemeColor,
    pub status_bar_bg: ThemeColor,
    pub status_bar_fg: ThemeColor,
    pub border_focused: ThemeColor,

    // Row state
    pub row_pending: ThemeColor,
    pub row_error: ThemeColor,

    // Intercept
    pub intercept_badge_bg: ThemeColor,
    pub intercept_badge_fg: ThemeColor,
    pub intercept_pending_count: ThemeColor,
    pub intercept_border: ThemeColor,
    pub intercept_action_bg: ThemeColor,
    pub intercept_action_fg: ThemeColor,

    // HTTP method
    pub method_get: ThemeColor,
    pub method_post: ThemeColor,
    pub method_put: ThemeColor,
    pub method_delete: ThemeColor,
    pub method_patch: ThemeColor,
    pub method_head_options: ThemeColor,
    pub method_other: ThemeColor,

    // Protocol tag
    pub proto_https: ThemeColor,
    pub proto_wss: ThemeColor,
    pub proto_http: ThemeColor,
    pub proto_ws: ThemeColor,
    pub proto_tcp: ThemeColor,
    pub proto_udp: ThemeColor,
    pub proto_dns: ThemeColor,
    pub proto_other: ThemeColor,

    // Status code
    pub status_1xx: ThemeColor,
    pub status_2xx: ThemeColor,
    pub status_3xx: ThemeColor,
    pub status_4xx: ThemeColor,
    pub status_5xx: ThemeColor,
    pub status_other: ThemeColor,

    // Content type
    pub content_type_none: ThemeColor,
    pub content_type_json: ThemeColor,
    pub content_type_html: ThemeColor,
    pub content_type_script: ThemeColor,
    pub content_type_css: ThemeColor,
    pub content_type_text: ThemeColor,
    pub content_type_image: ThemeColor,
    pub content_type_font: ThemeColor,
    pub content_type_xml: ThemeColor,
    pub content_type_multipart: ThemeColor,
    pub content_type_binary: ThemeColor,
    pub content_type_other: ThemeColor,

    // Body size bucket
    pub size_zero: ThemeColor,
    pub size_small: ThemeColor,
    pub size_medium: ThemeColor,
    pub size_large: ThemeColor,
    pub size_xlarge: ThemeColor,
    pub size_huge: ThemeColor,

    // Duration bucket
    pub duration_unknown: ThemeColor,
    pub duration_fast: ThemeColor,
    pub duration_ok: ThemeColor,
    pub duration_slow: ThemeColor,
    pub duration_slower: ThemeColor,
    pub duration_slowest: ThemeColor,

    // WebSocket
    pub ws_frame_count: ThemeColor,
    pub ws_dir_up: ThemeColor,
    pub ws_dir_down: ThemeColor,
    pub ws_opcode: ThemeColor,
    pub ws_closed_banner: ThemeColor,
    pub ws_follow_indicator: ThemeColor,

    // TCP
    pub tcp_stream_label: ThemeColor,
    pub tcp_state_closed: ThemeColor,
    pub tcp_state_live: ThemeColor,
    pub binary_type_label: ThemeColor,

    // DNS
    pub dns_query_type: ThemeColor,
    pub dns_state_override: ThemeColor,
    pub dns_state_upstream: ThemeColor,

    // UDP
    pub udp_dgram_label: ThemeColor,
    pub udp_state_complete: ThemeColor,
    pub udp_state_no_response: ThemeColor,

    // Request/response detail pane
    pub detail_request_method: ThemeColor,
    pub detail_header_name: ThemeColor,
    pub detail_truncated: ThemeColor,
    pub detail_field_label: ThemeColor,

    // Inline editor
    pub editor_cursor_bg: ThemeColor,
    pub editor_cursor_fg: ThemeColor,
    pub editor_border_error: ThemeColor,
    pub editor_border_typing: ThemeColor,
    pub editor_border_ready: ThemeColor,

    // Help modal
    pub help_section: ThemeColor,
    pub help_key: ThemeColor,
    pub help_border: ThemeColor,
}

impl Default for Theme {
    fn default() -> Self {
        let c = |color: Color| ThemeColor(color);
        Self {
            schema_version: SCHEMA_VERSION,

            table_header: c(Color::Yellow),
            selection_bg: c(Color::DarkGray),
            status_bar_bg: c(Color::DarkGray),
            status_bar_fg: c(Color::White),
            border_focused: c(Color::Cyan),

            row_pending: c(Color::Yellow),
            row_error: c(Color::Red),

            intercept_badge_bg: c(Color::Red),
            intercept_badge_fg: c(Color::White),
            intercept_pending_count: c(Color::Yellow),
            intercept_border: c(Color::Yellow),
            intercept_action_bg: c(Color::Yellow),
            intercept_action_fg: c(Color::Black),

            method_get: c(Color::LightGreen),
            method_post: c(Color::Yellow),
            method_put: c(Color::LightBlue),
            method_delete: c(Color::LightRed),
            method_patch: c(Color::LightMagenta),
            method_head_options: c(Color::Gray),
            method_other: c(Color::White),

            proto_https: c(Color::LightGreen),
            proto_wss: c(Color::LightCyan),
            proto_http: c(Color::Yellow),
            proto_ws: c(Color::LightMagenta),
            proto_tcp: c(Color::LightBlue),
            proto_udp: c(Color::LightCyan),
            proto_dns: c(Color::LightMagenta),
            proto_other: c(Color::White),

            status_1xx: c(Color::Gray),
            status_2xx: c(Color::LightGreen),
            status_3xx: c(Color::LightBlue),
            status_4xx: c(Color::LightRed),
            status_5xx: c(Color::Red),
            status_other: c(Color::White),

            content_type_none: c(Color::DarkGray),
            content_type_json: c(Color::LightCyan),
            content_type_html: c(Color::LightYellow),
            content_type_script: c(Color::LightBlue),
            content_type_css: c(Color::LightMagenta),
            content_type_text: c(Color::Gray),
            content_type_image: c(Color::Magenta),
            content_type_font: c(Color::Blue),
            content_type_xml: c(Color::Cyan),
            content_type_multipart: c(Color::Yellow),
            content_type_binary: c(Color::DarkGray),
            content_type_other: c(Color::White),

            size_zero: c(Color::DarkGray),
            size_small: c(Color::Gray),
            size_medium: c(Color::White),
            size_large: c(Color::LightYellow),
            size_xlarge: c(Color::Yellow),
            size_huge: c(Color::LightRed),

            duration_unknown: c(Color::DarkGray),
            duration_fast: c(Color::LightGreen),
            duration_ok: c(Color::Green),
            duration_slow: c(Color::Yellow),
            duration_slower: c(Color::LightRed),
            duration_slowest: c(Color::Red),

            ws_frame_count: c(Color::LightCyan),
            ws_dir_up: c(Color::Yellow),
            ws_dir_down: c(Color::Cyan),
            ws_opcode: c(Color::DarkGray),
            ws_closed_banner: c(Color::Red),
            ws_follow_indicator: c(Color::DarkGray),

            tcp_stream_label: c(Color::LightMagenta),
            tcp_state_closed: c(Color::DarkGray),
            tcp_state_live: c(Color::LightGreen),
            binary_type_label: c(Color::DarkGray),

            dns_query_type: c(Color::LightBlue),
            dns_state_override: c(Color::Yellow),
            dns_state_upstream: c(Color::LightGreen),

            udp_dgram_label: c(Color::LightMagenta),
            udp_state_complete: c(Color::LightGreen),
            udp_state_no_response: c(Color::Yellow),

            detail_request_method: c(Color::Green),
            detail_header_name: c(Color::Cyan),
            detail_truncated: c(Color::Yellow),
            detail_field_label: c(Color::Cyan),

            editor_cursor_bg: c(Color::White),
            editor_cursor_fg: c(Color::Black),
            editor_border_error: c(Color::Red),
            editor_border_typing: c(Color::Cyan),
            editor_border_ready: c(Color::Yellow),

            help_section: c(Color::Yellow),
            help_key: c(Color::Cyan),
            help_border: c(Color::Cyan),
        }
    }
}

impl Theme {
    pub fn method_color(&self, method: &str) -> Color {
        match method {
            "GET" => self.method_get.0,
            "POST" => self.method_post.0,
            "PUT" => self.method_put.0,
            "DELETE" => self.method_delete.0,
            "PATCH" => self.method_patch.0,
            "HEAD" | "OPTIONS" => self.method_head_options.0,
            _ => self.method_other.0,
        }
    }

    pub fn proto_color(&self, proto: &str) -> Color {
        match proto {
            "HTTPS" => self.proto_https.0,
            "WSS" => self.proto_wss.0,
            "HTTP" => self.proto_http.0,
            "WS" => self.proto_ws.0,
            "TCP" => self.proto_tcp.0,
            "UDP" => self.proto_udp.0,
            "DNS" => self.proto_dns.0,
            _ => self.proto_other.0,
        }
    }

    pub fn status_style(&self, status: u16) -> Style {
        match status {
            100..=199 => Style::default().fg(self.status_1xx.0),
            200..=299 => Style::default().fg(self.status_2xx.0),
            300..=399 => Style::default().fg(self.status_3xx.0),
            400..=499 => Style::default().fg(self.status_4xx.0),
            500..=599 => Style::default()
                .fg(self.status_5xx.0)
                .add_modifier(Modifier::BOLD),
            _ => Style::default().fg(self.status_other.0),
        }
    }

    pub fn content_type_color(&self, ct: &str) -> Color {
        if ct == "[no content]" {
            return self.content_type_none.0;
        }
        let base = ct.split(';').next().unwrap_or(ct).trim();
        match base {
            t if t.contains("json") => self.content_type_json.0,
            t if t.starts_with("text/html") => self.content_type_html.0,
            t if t.contains("javascript") || t.contains("ecmascript") => self.content_type_script.0,
            t if t.starts_with("text/css") => self.content_type_css.0,
            t if t.starts_with("text/") => self.content_type_text.0,
            t if t.starts_with("image/") => self.content_type_image.0,
            t if t.starts_with("font/") => self.content_type_font.0,
            t if t.contains("xml") => self.content_type_xml.0,
            t if t.starts_with("multipart/") => self.content_type_multipart.0,
            t if t.starts_with("application/octet-stream") => self.content_type_binary.0,
            _ => self.content_type_other.0,
        }
    }

    pub fn size_color(&self, bytes: usize) -> Color {
        match bytes {
            0 => self.size_zero.0,
            1..=1_023 => self.size_small.0,
            1_024..=10_239 => self.size_medium.0,
            10_240..=102_399 => self.size_large.0,
            102_400..=1_048_575 => self.size_xlarge.0,
            _ => self.size_huge.0,
        }
    }

    pub fn duration_color(&self, ms: i64) -> Color {
        match ms {
            ms if ms < 0 => self.duration_unknown.0,
            0..=99 => self.duration_fast.0,
            100..=299 => self.duration_ok.0,
            300..=699 => self.duration_slow.0,
            700..=1_999 => self.duration_slower.0,
            _ => self.duration_slowest.0,
        }
    }
}

/// Name -> builtin theme TOML (embedded so a builtin and a user theme share
/// the same load path).
const BUILTIN_CYBERDREAM: &str = include_str!("themes/cyberdream.toml");
const BUILTIN_CYBERDREAM_LIGHT: &str = include_str!("themes/cyberdream-light.toml");
const BUILTIN_CYBERDREAM_MUTED: &str = include_str!("themes/cyberdream-muted.toml");
const BUILTIN_ROSE_PINE: &str = include_str!("themes/rose-pine.toml");
const BUILTIN_ROSE_PINE_DAWN: &str = include_str!("themes/rose-pine-dawn.toml");
const BUILTIN_TOKYONIGHT: &str = include_str!("themes/tokyonight.toml");
const BUILTIN_TOKYONIGHT_DAY: &str = include_str!("themes/tokyonight-day.toml");
const BUILTIN_DRACULA: &str = include_str!("themes/dracula.toml");
const BUILTIN_ALUCARD: &str = include_str!("themes/alucard.toml");
const BUILTIN_CATPPUCCIN_MOCHA: &str = include_str!("themes/catppuccin-mocha.toml");
const BUILTIN_CATPPUCCIN_LATTE: &str = include_str!("themes/catppuccin-latte.toml");

pub fn built_in_theme_names() -> &'static [&'static str] {
    &[
        "default",
        "dark",
        "light",
        "cyberdream",
        "cyberdream-light",
        "cyberdream-muted",
        "rose-pine",
        "rose-pine-dawn",
        "tokyonight",
        "tokyonight-day",
        "dracula",
        "alucard",
        "catppuccin-mocha",
        "catppuccin-latte",
    ]
}

fn built_in_theme_toml(name: &str) -> Option<&'static str> {
    match name {
        "cyberdream" => Some(BUILTIN_CYBERDREAM),
        "cyberdream-light" => Some(BUILTIN_CYBERDREAM_LIGHT),
        "cyberdream-muted" => Some(BUILTIN_CYBERDREAM_MUTED),
        "rose-pine" => Some(BUILTIN_ROSE_PINE),
        "rose-pine-dawn" => Some(BUILTIN_ROSE_PINE_DAWN),
        "tokyonight" => Some(BUILTIN_TOKYONIGHT),
        "tokyonight-day" => Some(BUILTIN_TOKYONIGHT_DAY),
        "dracula" => Some(BUILTIN_DRACULA),
        "alucard" => Some(BUILTIN_ALUCARD),
        "catppuccin-mocha" => Some(BUILTIN_CATPPUCCIN_MOCHA),
        "catppuccin-latte" => Some(BUILTIN_CATPPUCCIN_LATTE),
        _ => None,
    }
}

/// Parse a theme from TOML text. Unknown keys and invalid colors surface
/// as warnings; a value bad enough that no `Theme` can be built (currently:
/// never, since every field falls back to the default) would be an error.
fn parse_theme(source: &str, origin: &str) -> Result<(Theme, Vec<String>), String> {
    let mut warnings = Vec::new();

    let table: toml::Table =
        toml::from_str(source).map_err(|err| format!("Failed to parse theme '{origin}': {err}"))?;

    let theme: Theme = toml::Value::Table(table.clone())
        .try_into()
        .map_err(|err| {
            format!(
                "Failed to load theme '{origin}': {}",
                err.to_string().replace('\n', " ")
            )
        })?;

    // Unknown keys shouldn't refuse to start proxelar, just get flagged.
    let known_keys = known_theme_keys();
    for key in table.keys() {
        if !known_keys.contains(&key.as_str()) {
            warnings.push(format!(
                "Warning: unknown theme key '{key}' in '{origin}', ignoring"
            ));
        }
    }

    Ok((theme, warnings))
}

fn known_theme_keys() -> &'static [&'static str] {
    &[
        "schema_version",
        "table_header",
        "selection_bg",
        "status_bar_bg",
        "status_bar_fg",
        "border_focused",
        "row_pending",
        "row_error",
        "intercept_badge_bg",
        "intercept_badge_fg",
        "intercept_pending_count",
        "intercept_border",
        "intercept_action_bg",
        "intercept_action_fg",
        "method_get",
        "method_post",
        "method_put",
        "method_delete",
        "method_patch",
        "method_head_options",
        "method_other",
        "proto_https",
        "proto_wss",
        "proto_http",
        "proto_ws",
        "proto_tcp",
        "proto_udp",
        "proto_dns",
        "proto_other",
        "status_1xx",
        "status_2xx",
        "status_3xx",
        "status_4xx",
        "status_5xx",
        "status_other",
        "content_type_none",
        "content_type_json",
        "content_type_html",
        "content_type_script",
        "content_type_css",
        "content_type_text",
        "content_type_image",
        "content_type_font",
        "content_type_xml",
        "content_type_multipart",
        "content_type_binary",
        "content_type_other",
        "size_zero",
        "size_small",
        "size_medium",
        "size_large",
        "size_xlarge",
        "size_huge",
        "duration_unknown",
        "duration_fast",
        "duration_ok",
        "duration_slow",
        "duration_slower",
        "duration_slowest",
        "ws_frame_count",
        "ws_dir_up",
        "ws_dir_down",
        "ws_opcode",
        "ws_closed_banner",
        "ws_follow_indicator",
        "tcp_stream_label",
        "tcp_state_closed",
        "tcp_state_live",
        "binary_type_label",
        "dns_query_type",
        "dns_state_override",
        "dns_state_upstream",
        "udp_dgram_label",
        "udp_state_complete",
        "udp_state_no_response",
        "detail_request_method",
        "detail_header_name",
        "detail_truncated",
        "detail_field_label",
        "editor_cursor_bg",
        "editor_cursor_fg",
        "editor_border_error",
        "editor_border_typing",
        "editor_border_ready",
        "help_section",
        "help_key",
        "help_border",
    ]
}

/// Resolve a theme by name: a builtin name, or `<themes_dir>/<name>.toml`.
/// Returns `Ok(None)` if `name` matches neither, so the caller can decide
/// how to report "unknown theme".
pub fn resolve_theme_name(
    name: &str,
    themes_dir: &Path,
) -> Result<Option<(Theme, Vec<String>)>, String> {
    if name == "default" || name == "dark" || name == "light" {
        return Ok(Some((Theme::default(), Vec::new())));
    }
    if let Some(source) = built_in_theme_toml(name) {
        return parse_theme(source, name).map(Some);
    }

    let path = themes_dir.join(format!("{name}.toml"));
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&path)
        .map_err(|err| format!("Failed to read theme '{}': {err}", path.display()))?;
    parse_theme(&contents, &path.display().to_string()).map(Some)
}

pub fn built_in_theme_names_display() -> String {
    built_in_theme_names().join(", ")
}

/// Detect whether the terminal/OS is in dark mode, for `theme = "system"`.
///
/// Checked in order: `COLORFGBG` (set by many terminals per-session), then
/// macOS's OS-level appearance setting. Defaults to dark when neither signal
/// is available.
pub fn is_dark_mode() -> bool {
    if let Ok(val) = std::env::var("COLORFGBG") {
        if let Some(bg) = val.rsplit(';').next() {
            if let Ok(code) = bg.trim().parse::<u8>() {
                return !matches!(code, 7 | 15);
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("defaults")
            .args(["read", "-g", "AppleInterfaceStyle"])
            .output()
        {
            return output.status.success();
        }
    }
    true
}

/// Apply single-color overrides (e.g. from config.toml's `[colors]` table)
/// on top of an already-resolved theme. Unknown keys and invalid colors
/// warn and are skipped rather than failing startup.
pub fn apply_color_overrides(
    theme: &mut Theme,
    overrides: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for (key, value) in overrides {
        match parse_color(value) {
            Some(color) => {
                if !set_theme_field(theme, key, color) {
                    warnings.push(format!(
                        "Warning: unknown theme color key '{key}' in config.toml, ignoring"
                    ));
                }
            }
            None => warnings.push(format!(
                "Warning: invalid color '{value}' for '{key}' in config.toml, ignoring"
            )),
        }
    }
    warnings
}

fn set_theme_field(theme: &mut Theme, key: &str, color: Color) -> bool {
    let c = ThemeColor(color);
    match key {
        "table_header" => theme.table_header = c,
        "selection_bg" => theme.selection_bg = c,
        "status_bar_bg" => theme.status_bar_bg = c,
        "status_bar_fg" => theme.status_bar_fg = c,
        "border_focused" => theme.border_focused = c,
        "row_pending" => theme.row_pending = c,
        "row_error" => theme.row_error = c,
        "intercept_badge_bg" => theme.intercept_badge_bg = c,
        "intercept_badge_fg" => theme.intercept_badge_fg = c,
        "intercept_pending_count" => theme.intercept_pending_count = c,
        "intercept_border" => theme.intercept_border = c,
        "intercept_action_bg" => theme.intercept_action_bg = c,
        "intercept_action_fg" => theme.intercept_action_fg = c,
        "method_get" => theme.method_get = c,
        "method_post" => theme.method_post = c,
        "method_put" => theme.method_put = c,
        "method_delete" => theme.method_delete = c,
        "method_patch" => theme.method_patch = c,
        "method_head_options" => theme.method_head_options = c,
        "method_other" => theme.method_other = c,
        "proto_https" => theme.proto_https = c,
        "proto_wss" => theme.proto_wss = c,
        "proto_http" => theme.proto_http = c,
        "proto_ws" => theme.proto_ws = c,
        "proto_tcp" => theme.proto_tcp = c,
        "proto_udp" => theme.proto_udp = c,
        "proto_dns" => theme.proto_dns = c,
        "proto_other" => theme.proto_other = c,
        "status_1xx" => theme.status_1xx = c,
        "status_2xx" => theme.status_2xx = c,
        "status_3xx" => theme.status_3xx = c,
        "status_4xx" => theme.status_4xx = c,
        "status_5xx" => theme.status_5xx = c,
        "status_other" => theme.status_other = c,
        "content_type_none" => theme.content_type_none = c,
        "content_type_json" => theme.content_type_json = c,
        "content_type_html" => theme.content_type_html = c,
        "content_type_script" => theme.content_type_script = c,
        "content_type_css" => theme.content_type_css = c,
        "content_type_text" => theme.content_type_text = c,
        "content_type_image" => theme.content_type_image = c,
        "content_type_font" => theme.content_type_font = c,
        "content_type_xml" => theme.content_type_xml = c,
        "content_type_multipart" => theme.content_type_multipart = c,
        "content_type_binary" => theme.content_type_binary = c,
        "content_type_other" => theme.content_type_other = c,
        "size_zero" => theme.size_zero = c,
        "size_small" => theme.size_small = c,
        "size_medium" => theme.size_medium = c,
        "size_large" => theme.size_large = c,
        "size_xlarge" => theme.size_xlarge = c,
        "size_huge" => theme.size_huge = c,
        "duration_unknown" => theme.duration_unknown = c,
        "duration_fast" => theme.duration_fast = c,
        "duration_ok" => theme.duration_ok = c,
        "duration_slow" => theme.duration_slow = c,
        "duration_slower" => theme.duration_slower = c,
        "duration_slowest" => theme.duration_slowest = c,
        "ws_frame_count" => theme.ws_frame_count = c,
        "ws_dir_up" => theme.ws_dir_up = c,
        "ws_dir_down" => theme.ws_dir_down = c,
        "ws_opcode" => theme.ws_opcode = c,
        "ws_closed_banner" => theme.ws_closed_banner = c,
        "ws_follow_indicator" => theme.ws_follow_indicator = c,
        "tcp_stream_label" => theme.tcp_stream_label = c,
        "tcp_state_closed" => theme.tcp_state_closed = c,
        "tcp_state_live" => theme.tcp_state_live = c,
        "binary_type_label" => theme.binary_type_label = c,
        "dns_query_type" => theme.dns_query_type = c,
        "dns_state_override" => theme.dns_state_override = c,
        "dns_state_upstream" => theme.dns_state_upstream = c,
        "udp_dgram_label" => theme.udp_dgram_label = c,
        "udp_state_complete" => theme.udp_state_complete = c,
        "udp_state_no_response" => theme.udp_state_no_response = c,
        "detail_request_method" => theme.detail_request_method = c,
        "detail_header_name" => theme.detail_header_name = c,
        "detail_truncated" => theme.detail_truncated = c,
        "detail_field_label" => theme.detail_field_label = c,
        "editor_cursor_bg" => theme.editor_cursor_bg = c,
        "editor_cursor_fg" => theme.editor_cursor_fg = c,
        "editor_border_error" => theme.editor_border_error = c,
        "editor_border_typing" => theme.editor_border_typing = c,
        "editor_border_ready" => theme.editor_border_ready = c,
        "help_section" => theme.help_section = c,
        "help_key" => theme.help_key = c,
        "help_border" => theme.help_border = c,
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_theme_matches_original_hardcoded_palette() {
        let theme = Theme::default();
        assert_eq!(theme.proto_color("HTTPS"), Color::LightGreen);
        assert_eq!(theme.proto_color("OTHER"), Color::White);
        assert_eq!(theme.method_color("DELETE"), Color::LightRed);
        assert_eq!(theme.status_style(503).fg, Some(Color::Red));
        assert_eq!(theme.content_type_color("image/png"), Color::Magenta);
        assert_eq!(theme.size_color(2_000_000), Color::LightRed);
        assert_eq!(theme.duration_color(3_000), Color::Red);
    }

    #[test]
    fn parses_hex_and_named_colors() {
        assert_eq!(parse_color("#5ea1ff"), Some(Color::Rgb(0x5e, 0xa1, 0xff)));
        assert_eq!(parse_color("red"), Some(Color::Red));
        assert_eq!(parse_color("light_green"), Some(Color::LightGreen));
        assert_eq!(parse_color("lightgreen"), Some(Color::LightGreen));
        assert_eq!(parse_color("dark_gray"), Some(Color::DarkGray));
        assert_eq!(parse_color("not-a-color"), None);
        assert_eq!(parse_color("#zzzzzz"), None);
        assert_eq!(parse_color("#fff"), None);
    }

    #[test]
    fn partial_theme_falls_back_to_default_for_missing_keys() {
        let (theme, warnings) = parse_theme(r##"status_bar_bg = "#123456""##, "partial").unwrap();
        assert!(warnings.is_empty());
        assert_eq!(theme.status_bar_bg.0, Color::Rgb(0x12, 0x34, 0x56));
        // Everything else still matches the default.
        assert_eq!(theme.method_get.0, Color::LightGreen);
    }

    #[test]
    fn unknown_key_produces_a_warning_not_an_error() {
        let (_, warnings) = parse_theme(
            r##"
            status_bar_bg = "#123456"
            not_a_real_key = "red"
            "##,
            "with-typo",
        )
        .unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("not_a_real_key"));
    }

    #[test]
    fn invalid_color_value_is_a_load_error() {
        let result = parse_theme(r##"status_bar_bg = "not-a-color""##, "bad-color");
        assert!(result.is_err());
    }

    #[test]
    fn all_builtin_themes_parse() {
        for name in built_in_theme_names() {
            let themes_dir = Path::new("/nonexistent");
            let resolved = resolve_theme_name(name, themes_dir)
                .unwrap_or_else(|err| panic!("builtin theme '{name}' failed to load: {err}"));
            assert!(resolved.is_some(), "builtin theme '{name}' not found");
        }
    }

    #[test]
    fn set_theme_field_covers_every_known_key() {
        let mut theme = Theme::default();
        for key in known_theme_keys() {
            if *key == "schema_version" {
                continue;
            }
            assert!(
                set_theme_field(&mut theme, key, Color::Red),
                "known_theme_keys() lists '{key}' but set_theme_field doesn't handle it"
            );
        }
        assert!(!set_theme_field(&mut theme, "not_a_real_key", Color::Red));
    }

    #[test]
    fn apply_color_overrides_sets_known_keys_and_warns_on_unknown_or_bad() {
        let mut theme = Theme::default();
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("status_bar_bg".to_string(), "#112233".to_string());
        overrides.insert("not_a_real_key".to_string(), "red".to_string());
        overrides.insert("status_bar_fg".to_string(), "not-a-color".to_string());

        let warnings = apply_color_overrides(&mut theme, &overrides);
        assert_eq!(theme.status_bar_bg.0, Color::Rgb(0x11, 0x22, 0x33));
        assert_eq!(theme.status_bar_fg.0, Theme::default().status_bar_fg.0);
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn is_dark_mode_respects_colorfgbg() {
        std::env::set_var("COLORFGBG", "15;0");
        assert!(is_dark_mode());
        std::env::set_var("COLORFGBG", "0;15");
        assert!(!is_dark_mode());
        std::env::remove_var("COLORFGBG");
    }
}
