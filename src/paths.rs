//! Picks the default key directory, using only the standard library.
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const APP: &str = "significant";

/// Resolves the directory from environment variables. `SIGNIFICANT_HOME` wins
/// everywhere. Unix uses `XDG_CONFIG_HOME` or `~/.config`, and Windows uses
/// `%APPDATA%`.
pub(crate) fn key_dir(env: impl Fn(&str) -> Option<OsString>, windows: bool) -> Option<PathBuf> {
    let var = |name: &str| env(name).filter(|value| !value.is_empty());
    if let Some(dir) = var("SIGNIFICANT_HOME") {
        return Some(dir.into());
    }
    if windows {
        return var("APPDATA")
            .map(|dir| PathBuf::from(dir).join(APP))
            .or_else(|| {
                let profile = PathBuf::from(var("USERPROFILE")?);
                Some(profile.join("AppData").join("Roaming").join(APP))
            });
    }
    // The XDG specification says to ignore relative paths.
    if let Some(dir) = var("XDG_CONFIG_HOME").filter(|dir| Path::new(dir).is_absolute()) {
        return Some(PathBuf::from(dir).join(APP));
    }
    Some(PathBuf::from(var("HOME")?).join(".config").join(APP))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(vars: &[(&str, &str)], windows: bool) -> Option<PathBuf> {
        let env = |name: &str| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        };
        key_dir(env, windows)
    }

    #[test]
    fn override_wins_on_every_platform() {
        let vars = [
            ("SIGNIFICANT_HOME", "/keys"),
            ("HOME", "/home/a"),
            ("XDG_CONFIG_HOME", "/xdg"),
            ("APPDATA", "/appdata"),
        ];
        assert_eq!(resolve(&vars, false), Some("/keys".into()));
        assert_eq!(resolve(&vars, true), Some("/keys".into()));
    }

    #[test]
    fn unix_prefers_xdg_then_home() {
        let both = [("HOME", "/home/a"), ("XDG_CONFIG_HOME", "/xdg")];
        assert_eq!(resolve(&both, false), Some("/xdg/significant".into()));
        let home = [("HOME", "/home/a")];
        assert_eq!(
            resolve(&home, false),
            Some("/home/a/.config/significant".into())
        );
    }

    #[test]
    fn unusable_xdg_values_are_ignored() {
        for value in ["", "relative/path"] {
            let vars = [("HOME", "/home/a"), ("XDG_CONFIG_HOME", value)];
            assert_eq!(
                resolve(&vars, false),
                Some("/home/a/.config/significant".into())
            );
        }
    }

    #[test]
    fn windows_uses_appdata_then_the_profile() {
        let vars = [("APPDATA", "/appdata"), ("USERPROFILE", "/users/a")];
        assert_eq!(resolve(&vars, true), Some("/appdata/significant".into()));
        let profile = [("USERPROFILE", "/users/a")];
        assert_eq!(
            resolve(&profile, true),
            Some("/users/a/AppData/Roaming/significant".into())
        );
    }

    #[test]
    fn windows_ignores_home() {
        assert_eq!(resolve(&[("HOME", "/home/a")], true), None);
    }

    #[test]
    fn no_usable_location_returns_none() {
        assert_eq!(resolve(&[], false), None);
        assert_eq!(resolve(&[("SIGNIFICANT_HOME", "")], true), None);
    }
}
