//! `~/.proxelar/config.toml` and theme resolution precedence.

use crate::theme::{
    apply_color_overrides, built_in_theme_names_display, is_dark_mode, resolve_theme_name, Theme,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    /// `"default"`/`"dark"`/`"light"`, `"system"`, or a custom theme name.
    pub theme: Option<String>,
    /// Theme to use when `theme = "system"` resolves to dark. Defaults to
    /// `"default"` when unset.
    pub theme_dark: Option<String>,
    /// Theme to use when `theme = "system"` resolves to light. Defaults to
    /// `"default"` when unset (plain ANSI colors already adapt to the
    /// terminal's own light/dark palette; only set this to something else
    /// if you want an explicit light-mode theme).
    pub theme_light: Option<String>,
    /// Single-color overrides layered on top of the resolved theme, e.g.
    /// `[colors]\nstatus_bar_bg = "#222222"`.
    pub colors: HashMap<String, String>,
}

/// Read `<ca_dir>/config.toml`. Missing file is not an error (empty config);
/// a malformed file produces a warning and an empty config, never a hard
/// failure — proxelar should still start.
pub fn load_config(ca_dir: &Path) -> (AppConfig, Vec<String>) {
    let path = ca_dir.join("config.toml");
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return (AppConfig::default(), Vec::new());
    };
    match toml::from_str(&contents) {
        Ok(config) => (config, Vec::new()),
        Err(err) => (
            AppConfig::default(),
            vec![format!(
                "Warning: Failed to parse '{}': {err}, using defaults",
                path.display()
            )],
        ),
    }
}

/// Resolve the active theme.
///
/// Precedence: `--theme` CLI flag > `theme` in config.toml > built-in
/// default. `theme = "system"` picks `theme_dark`/`theme_light` (both
/// default to `"default"` — plain ANSI colors already adapt to the
/// terminal's own light/dark palette) based on the detected terminal/OS
/// appearance. `[colors]` overrides in config.toml are applied last, on top
/// of whichever theme was resolved. An unresolvable name warns and falls
/// back rather than aborting startup.
pub fn resolve_theme(
    cli_theme: Option<&str>,
    config: &AppConfig,
    ca_dir: &Path,
) -> (Theme, Vec<String>) {
    let themes_dir = ca_dir.join("themes");
    let requested = cli_theme.or(config.theme.as_deref());

    let (mut theme, mut warnings) = match requested {
        None => (Theme::default(), Vec::new()),
        Some("system") => resolve_system_theme(config, &themes_dir),
        Some(name) => resolve_named_theme(name, &themes_dir),
    };

    warnings.extend(apply_color_overrides(&mut theme, &config.colors));
    (theme, warnings)
}

fn resolve_named_theme(name: &str, themes_dir: &Path) -> (Theme, Vec<String>) {
    match resolve_theme_name(name, themes_dir) {
        Ok(Some((theme, warnings))) => (theme, warnings),
        Ok(None) => (
            Theme::default(),
            vec![format!(
                "Warning: Unknown theme '{name}'. Bundled themes: {}, system. Local themes are loaded from {}",
                built_in_theme_names_display(),
                themes_dir.display()
            )],
        ),
        Err(err) => (Theme::default(), vec![format!("Warning: {err}, using default theme")]),
    }
}

fn resolve_system_theme(config: &AppConfig, themes_dir: &Path) -> (Theme, Vec<String>) {
    let name = if is_dark_mode() {
        config.theme_dark.as_deref().unwrap_or("default")
    } else {
        config.theme_light.as_deref().unwrap_or("default")
    };
    resolve_named_theme(name, themes_dir)
}

#[allow(dead_code)]
pub fn config_path(ca_dir: &Path) -> PathBuf {
    ca_dir.join("config.toml")
}

#[allow(dead_code)]
pub fn themes_dir(ca_dir: &Path) -> PathBuf {
    ca_dir.join("themes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_config_file_is_not_an_error() {
        let dir = std::env::temp_dir().join(format!("proxelar-test-{}", std::process::id()));
        let (config, warnings) = load_config(&dir);
        assert!(config.theme.is_none());
        assert!(warnings.is_empty());
    }

    #[test]
    fn malformed_config_file_warns_and_falls_back() {
        let dir = std::env::temp_dir().join(format!(
            "proxelar-test-malformed-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "this is not valid = = toml").unwrap();

        let (config, warnings) = load_config(&dir);
        assert!(config.theme.is_none());
        assert_eq!(warnings.len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cli_theme_wins_over_config_theme() {
        let dir = Path::new("/nonexistent");
        let config = AppConfig {
            theme: Some("cyberdream-light".to_string()),
            ..Default::default()
        };
        let (theme, warnings) = resolve_theme(Some("cyberdream"), &config, dir);
        assert!(warnings.is_empty());
        // cyberdream and cyberdream-light have different table_header colors.
        assert_ne!(
            theme.table_header.0,
            crate::theme::Theme::default().table_header.0
        );
    }

    #[test]
    fn unknown_cli_theme_warns_and_falls_back_to_default() {
        let dir = Path::new("/nonexistent");
        let config = AppConfig::default();
        let (theme, warnings) = resolve_theme(Some("not-a-theme"), &config, dir);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Unknown theme"));
        assert_eq!(
            theme.table_header.0,
            crate::theme::Theme::default().table_header.0
        );
    }

    #[test]
    fn no_theme_specified_uses_default() {
        let dir = Path::new("/nonexistent");
        let config = AppConfig::default();
        let (theme, warnings) = resolve_theme(None, &config, dir);
        assert!(warnings.is_empty());
        assert_eq!(
            theme.table_header.0,
            crate::theme::Theme::default().table_header.0
        );
    }

    #[test]
    fn dark_alias_matches_default() {
        let dir = Path::new("/nonexistent");
        let config = AppConfig::default();
        let (theme, warnings) = resolve_theme(Some("dark"), &config, dir);
        assert!(warnings.is_empty());
        assert_eq!(
            theme.table_header.0,
            crate::theme::Theme::default().table_header.0
        );
    }

    #[test]
    fn system_theme_uses_theme_dark_or_theme_light() {
        let _guard = crate::theme::test_support::ColorfgbgGuard::new();
        let dir = Path::new("/nonexistent");
        let config = AppConfig {
            theme: Some("system".to_string()),
            theme_dark: Some("cyberdream".to_string()),
            theme_light: Some("cyberdream-light".to_string()),
            ..Default::default()
        };

        std::env::set_var("COLORFGBG", "15;0"); // dark background
        let (dark_resolved, warnings) = resolve_theme(None, &config, dir);
        assert!(warnings.is_empty());

        std::env::set_var("COLORFGBG", "0;15"); // light background
        let (light_resolved, warnings) = resolve_theme(None, &config, dir);
        assert!(warnings.is_empty());

        // theme_dark and theme_light must resolve to their own distinct
        // named theme, not just "any non-default theme".
        let (cyberdream, _) = resolve_named_theme("cyberdream", &themes_dir(dir));
        let (cyberdream_light, _) = resolve_named_theme("cyberdream-light", &themes_dir(dir));
        assert_eq!(dark_resolved, cyberdream);
        assert_eq!(light_resolved, cyberdream_light);
        assert_ne!(dark_resolved, light_resolved);
    }

    /// `theme = "system"` without `theme_dark`/`theme_light` set must produce
    /// the exact same colors regardless of detected appearance: both branches
    /// fall back to plain ANSI-named colors, which the terminal itself
    /// resolves differently for light/dark — proxelar shouldn't also try to
    /// pick different colors on top of that.
    #[test]
    fn system_without_dark_light_config_is_appearance_independent() {
        let _guard = crate::theme::test_support::ColorfgbgGuard::new();
        let dir = Path::new("/nonexistent");
        let config = AppConfig {
            theme: Some("system".to_string()),
            ..Default::default()
        };

        std::env::set_var("COLORFGBG", "15;0"); // dark background
        let (dark_resolved, warnings) = resolve_theme(None, &config, dir);
        assert!(warnings.is_empty());

        std::env::set_var("COLORFGBG", "0;15"); // light background
        let (light_resolved, warnings) = resolve_theme(None, &config, dir);
        assert!(warnings.is_empty());

        assert_eq!(dark_resolved, light_resolved);
        assert_eq!(dark_resolved, crate::theme::Theme::default());
    }

    /// `theme_dark`/`theme_light` only need to override the colors that
    /// actually change; everything else still inherits `Theme::default()`.
    #[test]
    fn theme_dark_only_overrides_specified_colors() {
        let _guard = crate::theme::test_support::ColorfgbgGuard::new();
        let dir = std::env::temp_dir().join(format!(
            "proxelar-test-partial-dark-{}-{}",
            std::process::id(),
            line!()
        ));
        let themes_dir = dir.join("themes");
        std::fs::create_dir_all(&themes_dir).unwrap();
        std::fs::write(
            themes_dir.join("my-dark.toml"),
            r##"status_bar_bg = "#101010""##,
        )
        .unwrap();

        let config = AppConfig {
            theme: Some("system".to_string()),
            theme_dark: Some("my-dark".to_string()),
            ..Default::default()
        };
        std::env::set_var("COLORFGBG", "15;0"); // dark background
        let (theme, warnings) = resolve_theme(None, &config, &dir);

        assert!(warnings.is_empty());
        assert_eq!(
            theme.status_bar_bg.0,
            ratatui::style::Color::Rgb(0x10, 0x10, 0x10)
        );
        // Every other field still matches Theme::default().
        assert_eq!(
            theme.table_header.0,
            crate::theme::Theme::default().table_header.0
        );
        assert_eq!(
            theme.method_get.0,
            crate::theme::Theme::default().method_get.0
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn color_overrides_apply_on_top_of_resolved_theme() {
        let dir = Path::new("/nonexistent");
        let mut colors = HashMap::new();
        colors.insert("status_bar_bg".to_string(), "#334455".to_string());
        let config = AppConfig {
            colors,
            ..Default::default()
        };
        let (theme, warnings) = resolve_theme(None, &config, dir);
        assert!(warnings.is_empty());
        assert_eq!(
            theme.status_bar_bg.0,
            ratatui::style::Color::Rgb(0x33, 0x44, 0x55)
        );
        // Everything else is untouched.
        assert_eq!(
            theme.table_header.0,
            crate::theme::Theme::default().table_header.0
        );
    }
}
