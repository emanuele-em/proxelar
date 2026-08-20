//! Resolution of the directory holding CA certs, addons, and browser profile.

use std::path::{Path, PathBuf};

/// Which precedence rule produced the resolved directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    CliArg,
    XdgConfigHome,
    HomeDefault,
}

/// Resolve the CA/addons/browser-profile directory.
///
/// Precedence: `--ca-dir` CLI flag > `$XDG_CONFIG_HOME/proxelar` (when the
/// env var is set to a non-empty absolute path) > `~/.proxelar`.
pub fn resolve_ca_dir(cli_arg: Option<PathBuf>) -> PathBuf {
    let home = dirs::home_dir();
    let legacy = home.as_ref().map(|h| h.join(".proxelar"));
    let (dir, source) =
        resolve_ca_dir_from_parts(cli_arg, std::env::var_os("XDG_CONFIG_HOME"), home);

    if let Some(legacy) = legacy.as_deref() {
        if should_warn_relocation(&dir, source, Some(legacy), |p| p.exists()) {
            // Printed rather than logged: the default RUST_LOG filter hides warnings,
            // and silently regenerating the CA is exactly what needs explaining.
            eprintln!(
                "warning: using {} because XDG_CONFIG_HOME is set, but an existing proxelar \
                 directory was found at {}. Its CA certificate, addons, and WireGuard config \
                 are not used. Pass --ca-dir {} to keep using it.",
                dir.display(),
                legacy.display(),
                legacy.display(),
            );
        }
    }
    dir
}

fn resolve_ca_dir_from_parts(
    cli_arg: Option<PathBuf>,
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<PathBuf>,
) -> (PathBuf, Source) {
    if let Some(dir) = cli_arg {
        return (dir, Source::CliArg);
    }
    if let Some(xdg) = usable_xdg_config_home(xdg_config_home) {
        return (xdg.join("proxelar"), Source::XdgConfigHome);
    }
    let dir = home
        .unwrap_or_else(|| {
            tracing::warn!("Could not determine home directory, using current directory");
            PathBuf::from(".")
        })
        .join(".proxelar");
    (dir, Source::HomeDefault)
}

/// The XDG basedir spec requires `$XDG_CONFIG_HOME` to be an absolute path and
/// says relative values must be ignored, as must an empty one.
fn usable_xdg_config_home(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    let value = value.filter(|v| !v.is_empty())?;
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return Some(path);
    }
    // Printed rather than logged, for the same reason as the relocation notice above.
    eprintln!(
        "warning: ignoring XDG_CONFIG_HOME={}: the XDG base directory spec requires an \
         absolute path.",
        path.display()
    );
    None
}

/// True when `$XDG_CONFIG_HOME` silently moves us off an existing `~/.proxelar`.
///
/// State is never migrated, so without a warning the user just gets a fresh,
/// untrusted CA and an empty addon catalog with no explanation.
fn should_warn_relocation(
    resolved: &Path,
    source: Source,
    legacy: Option<&Path>,
    exists: impl Fn(&Path) -> bool,
) -> bool {
    source == Source::XdgConfigHome
        && legacy.is_some_and(|legacy| legacy != resolved && exists(legacy))
        && !exists(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_arg_wins_over_everything() {
        let (dir, source) = resolve_ca_dir_from_parts(
            Some(PathBuf::from("/explicit")),
            Some("/xdg".into()),
            Some(PathBuf::from("/home")),
        );
        assert_eq!(dir, PathBuf::from("/explicit"));
        assert_eq!(source, Source::CliArg);
    }

    #[test]
    fn uses_xdg_config_home_when_set() {
        let (dir, source) =
            resolve_ca_dir_from_parts(None, Some("/xdg".into()), Some(PathBuf::from("/home")));
        assert_eq!(dir, PathBuf::from("/xdg/proxelar"));
        assert_eq!(source, Source::XdgConfigHome);
    }

    #[test]
    fn ignores_empty_xdg_config_home() {
        let (dir, source) =
            resolve_ca_dir_from_parts(None, Some("".into()), Some(PathBuf::from("/home")));
        assert_eq!(dir, PathBuf::from("/home/.proxelar"));
        assert_eq!(source, Source::HomeDefault);
    }

    #[test]
    fn ignores_relative_xdg_config_home() {
        let (dir, source) = resolve_ca_dir_from_parts(
            None,
            Some("relative/config".into()),
            Some(PathBuf::from("/home")),
        );
        assert_eq!(dir, PathBuf::from("/home/.proxelar"));
        assert_eq!(source, Source::HomeDefault);
    }

    #[test]
    fn falls_back_to_home_proxelar_without_xdg() {
        let (dir, source) = resolve_ca_dir_from_parts(None, None, Some(PathBuf::from("/home")));
        assert_eq!(dir, PathBuf::from("/home/.proxelar"));
        assert_eq!(source, Source::HomeDefault);
    }

    /// Existence predicate that reports true only for the listed paths.
    fn existing(paths: &[&str]) -> impl Fn(&Path) -> bool + 'static {
        let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
        move |p| paths.iter().any(|e| e == p)
    }

    const XDG: &str = "/xdg/proxelar";
    const LEGACY: &str = "/home/.proxelar";

    #[test]
    fn warns_when_xdg_is_new_and_legacy_dir_exists() {
        assert!(should_warn_relocation(
            Path::new(XDG),
            Source::XdgConfigHome,
            Some(Path::new(LEGACY)),
            existing(&[LEGACY]),
        ));
    }

    #[test]
    fn silent_when_legacy_dir_absent() {
        assert!(!should_warn_relocation(
            Path::new(XDG),
            Source::XdgConfigHome,
            Some(Path::new(LEGACY)),
            existing(&[]),
        ));
    }

    #[test]
    fn silent_when_xdg_dir_already_exists() {
        assert!(!should_warn_relocation(
            Path::new(XDG),
            Source::XdgConfigHome,
            Some(Path::new(LEGACY)),
            existing(&[XDG, LEGACY]),
        ));
    }

    #[test]
    fn silent_when_cli_arg_given() {
        assert!(!should_warn_relocation(
            Path::new("/explicit"),
            Source::CliArg,
            Some(Path::new(LEGACY)),
            existing(&[LEGACY]),
        ));
    }

    #[test]
    fn silent_when_home_default() {
        assert!(!should_warn_relocation(
            Path::new(LEGACY),
            Source::HomeDefault,
            Some(Path::new(LEGACY)),
            existing(&[LEGACY]),
        ));
    }

    #[test]
    fn silent_when_home_dir_unknown() {
        assert!(!should_warn_relocation(
            Path::new(XDG),
            Source::XdgConfigHome,
            None,
            existing(&[LEGACY]),
        ));
    }

    /// `XDG_CONFIG_HOME=$HOME` resolves to the legacy path itself; not a relocation.
    #[test]
    fn silent_when_xdg_resolves_to_legacy_path() {
        assert!(!should_warn_relocation(
            Path::new(LEGACY),
            Source::XdgConfigHome,
            Some(Path::new(LEGACY)),
            existing(&[LEGACY]),
        ));
    }
}
