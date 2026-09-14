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
    let has_ca_pair =
        |dir: &Path| exists(&dir.join("proxelar-ca.pem")) && exists(&dir.join("proxelar-ca.key"));
    source == Source::XdgConfigHome
        && legacy.is_some_and(|legacy| {
            legacy != resolved
                && exists(legacy)
                && (!exists(resolved) || (has_ca_pair(legacy) && !has_ca_pair(resolved)))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn absolute_path(name: &str) -> PathBuf {
        let root = if cfg!(windows) { r"C:\" } else { "/" };
        Path::new(root).join(name)
    }

    #[test]
    fn cli_arg_wins_over_everything() {
        let (dir, source) = resolve_ca_dir_from_parts(
            Some(absolute_path("explicit")),
            Some(absolute_path("xdg").into_os_string()),
            Some(absolute_path("home")),
        );
        assert_eq!(dir, absolute_path("explicit"));
        assert_eq!(source, Source::CliArg);
    }

    #[test]
    fn uses_xdg_config_home_when_set() {
        let xdg = absolute_path("xdg");
        let (dir, source) = resolve_ca_dir_from_parts(
            None,
            Some(xdg.clone().into_os_string()),
            Some(absolute_path("home")),
        );
        assert_eq!(dir, xdg.join("proxelar"));
        assert_eq!(source, Source::XdgConfigHome);
    }

    #[test]
    fn ignores_empty_xdg_config_home() {
        let (dir, source) =
            resolve_ca_dir_from_parts(None, Some("".into()), Some(absolute_path("home")));
        assert_eq!(dir, absolute_path("home").join(".proxelar"));
        assert_eq!(source, Source::HomeDefault);
    }

    #[test]
    fn ignores_relative_xdg_config_home() {
        let (dir, source) = resolve_ca_dir_from_parts(
            None,
            Some("relative/config".into()),
            Some(absolute_path("home")),
        );
        assert_eq!(dir, absolute_path("home").join(".proxelar"));
        assert_eq!(source, Source::HomeDefault);
    }

    #[test]
    fn falls_back_to_home_proxelar_without_xdg() {
        let (dir, source) = resolve_ca_dir_from_parts(None, None, Some(absolute_path("home")));
        assert_eq!(dir, absolute_path("home").join(".proxelar"));
        assert_eq!(source, Source::HomeDefault);
    }

    /// Existence predicate that reports true only for the listed paths.
    fn existing(paths: Vec<PathBuf>) -> impl Fn(&Path) -> bool {
        move |p| paths.iter().any(|e| e == p)
    }

    #[test]
    fn warns_when_xdg_is_new_and_legacy_dir_exists() {
        let xdg = absolute_path("xdg").join("proxelar");
        let legacy = absolute_path("home").join(".proxelar");
        assert!(should_warn_relocation(
            &xdg,
            Source::XdgConfigHome,
            Some(&legacy),
            existing(vec![legacy.clone()]),
        ));
    }

    #[test]
    fn silent_when_legacy_dir_absent() {
        let xdg = absolute_path("xdg").join("proxelar");
        let legacy = absolute_path("home").join(".proxelar");
        assert!(!should_warn_relocation(
            &xdg,
            Source::XdgConfigHome,
            Some(&legacy),
            existing(vec![]),
        ));
    }

    #[test]
    fn silent_when_existing_directories_have_no_ca_pair() {
        let xdg = absolute_path("xdg").join("proxelar");
        let legacy = absolute_path("home").join(".proxelar");
        assert!(!should_warn_relocation(
            &xdg,
            Source::XdgConfigHome,
            Some(&legacy),
            existing(vec![xdg.clone(), legacy.clone()]),
        ));
    }

    #[test]
    fn warns_when_legacy_has_ca_pair_and_xdg_is_uninitialized() {
        let xdg = absolute_path("xdg").join("proxelar");
        let legacy = absolute_path("home").join(".proxelar");
        for destination_entry in [
            None,
            Some("addons"),
            Some("proxelar-ca.pem"),
            Some("proxelar-ca.key"),
        ] {
            let mut paths = vec![
                legacy.clone(),
                legacy.join("proxelar-ca.pem"),
                legacy.join("proxelar-ca.key"),
                xdg.clone(),
            ];
            if let Some(entry) = destination_entry {
                paths.push(xdg.join(entry));
            }
            assert!(
                should_warn_relocation(&xdg, Source::XdgConfigHome, Some(&legacy), existing(paths)),
                "destination entry: {destination_entry:?}",
            );
        }
    }

    #[test]
    fn silent_when_xdg_has_ca_pair() {
        let xdg = absolute_path("xdg").join("proxelar");
        let legacy = absolute_path("home").join(".proxelar");
        assert!(!should_warn_relocation(
            &xdg,
            Source::XdgConfigHome,
            Some(&legacy),
            existing(vec![
                legacy.clone(),
                legacy.join("proxelar-ca.pem"),
                legacy.join("proxelar-ca.key"),
                xdg.clone(),
                xdg.join("proxelar-ca.pem"),
                xdg.join("proxelar-ca.key"),
            ]),
        ));
    }

    #[test]
    fn silent_when_cli_arg_given() {
        let legacy = absolute_path("home").join(".proxelar");
        assert!(!should_warn_relocation(
            &absolute_path("explicit"),
            Source::CliArg,
            Some(&legacy),
            existing(vec![legacy.clone()]),
        ));
    }

    #[test]
    fn silent_when_home_default() {
        let legacy = absolute_path("home").join(".proxelar");
        assert!(!should_warn_relocation(
            &legacy,
            Source::HomeDefault,
            Some(&legacy),
            existing(vec![legacy.clone()]),
        ));
    }

    #[test]
    fn silent_when_home_dir_unknown() {
        let xdg = absolute_path("xdg").join("proxelar");
        let legacy = absolute_path("home").join(".proxelar");
        assert!(!should_warn_relocation(
            &xdg,
            Source::XdgConfigHome,
            None,
            existing(vec![legacy]),
        ));
    }

    /// `XDG_CONFIG_HOME=$HOME` resolves to the legacy path itself; not a relocation.
    #[test]
    fn silent_when_xdg_resolves_to_legacy_path() {
        let legacy = absolute_path("home").join(".proxelar");
        assert!(!should_warn_relocation(
            &legacy,
            Source::XdgConfigHome,
            Some(&legacy),
            existing(vec![legacy.clone()]),
        ));
    }
}
