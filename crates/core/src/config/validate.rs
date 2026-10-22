//! Semantic validation of a loaded [`Config`]: one `validate` after deserialisation, never
//! inside serde. Used at startup (issues are logged) and by the profile editor on every change
//! (issues of the edited profile are shown inline and block Save).

use std::collections::{HashMap, HashSet};

use super::Config;
use crate::action::Action;
use crate::keychord::KeyChord;
use crate::profile::{Profile, ProfileId, ProfileKind};
use crate::scheme::ColorScheme;

/// One semantic problem found by [`validate`]. Syntax errors never reach this point (they fail
/// at [`load`](super::load) time instead).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigIssue {
    /// Two profiles share the same `id`.
    #[error("duplicate profile id {0:?}")]
    DuplicateProfileId(ProfileId),
    /// Another profile has the same name (reported for each of them).
    #[error("another profile is also named {name:?}")]
    DuplicateProfileName {
        /// One of the profiles sharing the name.
        profile: ProfileId,
        /// The shared name.
        name: String,
    },
    /// A profile's name is empty.
    #[error("the name is empty")]
    EmptyProfileName(ProfileId),
    /// An SSH profile has no host (neither its own nor from `profile_defaults.ssh`).
    #[error("the host is empty")]
    MissingHost(ProfileId),
    /// A port forward of an SSH profile can't start (see `PortForward::problem`).
    #[error("port forward {}: {reason}", .index + 1)]
    BadForward {
        /// The profile.
        profile: ProfileId,
        /// Index into its `forwarded_ports`.
        index: usize,
        /// What is wrong.
        reason: &'static str,
    },
    /// Algorithm names the SSH library doesn't know (`Algorithms::unknown`). Reported by the
    /// profile editor, which knows the library's lists; [`validate`] itself can't.
    #[error("unknown algorithms: {}", .names.join(", "))]
    UnknownAlgorithms {
        /// The profile.
        profile: ProfileId,
        /// The unknown names.
        names: Vec<String>,
    },
    /// Following `jump_host` from this profile comes back to it.
    #[error("jump host loop: {}", .chain.join(" → "))]
    JumpHostCycle {
        /// The profile whose jump chain loops.
        profile: ProfileId,
        /// The profile names along the loop, starting and ending with this one.
        chain: Vec<String>,
    },
    /// A profile's `group` does not match any entry in `groups`.
    #[error("profile {profile:?} references unknown group {group:?}")]
    UnknownGroup {
        /// The profile with the dangling reference.
        profile: ProfileId,
        /// The group id it references.
        group: String,
    },
    /// `appearance.color_scheme` does not match a built-in scheme.
    #[error("unknown colour scheme {0:?}")]
    UnknownColorScheme(String),
    /// The same chord is bound to more than one action.
    #[error("{chord} is bound to more than one action: {actions:?}")]
    AmbiguousChord {
        /// The shared chord.
        chord: KeyChord,
        /// The actions it is bound to.
        actions: Vec<Action>,
    },
}

impl ConfigIssue {
    /// The profile this issue is about, if it is about one.
    #[must_use]
    pub fn profile(&self) -> Option<&ProfileId> {
        match self {
            Self::DuplicateProfileId(id)
            | Self::EmptyProfileName(id)
            | Self::MissingHost(id)
            | Self::BadForward { profile: id, .. }
            | Self::UnknownAlgorithms { profile: id, .. }
            | Self::DuplicateProfileName { profile: id, .. }
            | Self::JumpHostCycle { profile: id, .. }
            | Self::UnknownGroup { profile: id, .. } => Some(id),
            Self::UnknownColorScheme(_) | Self::AmbiguousChord { .. } => None,
        }
    }
}

/// Checks `config` for problems that successful deserialisation cannot catch: duplicate ids and
/// names, empty names, SSH profiles without a host, jump-host loops, dangling group references,
/// an unknown colour scheme name, and chords bound to more than one action. Returns every issue
/// found (never panics, never fails to load the config).
#[must_use]
pub fn validate(config: &Config) -> Vec<ConfigIssue> {
    let mut issues = Vec::new();

    let mut seen_ids = HashSet::new();
    let group_ids: HashSet<&str> = config.groups.iter().map(|g| g.id.0.as_str()).collect();
    let mut names: HashMap<String, usize> = HashMap::new();
    for profile in &config.profiles {
        *names.entry(name_key(&profile.name)).or_default() += 1;
    }
    for profile in &config.profiles {
        let id = &profile.id;
        if !seen_ids.insert(id) {
            issues.push(ConfigIssue::DuplicateProfileId(id.clone()));
        }
        if profile.name.trim().is_empty() {
            issues.push(ConfigIssue::EmptyProfileName(id.clone()));
        } else if names.get(&name_key(&profile.name)).copied().unwrap_or(0) > 1 {
            issues.push(ConfigIssue::DuplicateProfileName {
                profile: id.clone(),
                name: profile.name.clone(),
            });
        }
        if let ProfileKind::Ssh(ssh) = &profile.kind {
            let host = ssh
                .host
                .as_ref()
                .or(config.profile_defaults.ssh.host.as_ref());
            if host.is_none_or(|h| h.trim().is_empty()) {
                issues.push(ConfigIssue::MissingHost(id.clone()));
            }
            for (index, forward) in ssh.forwarded_ports.iter().flatten().enumerate() {
                if let Some(reason) = forward.problem() {
                    issues.push(ConfigIssue::BadForward {
                        profile: id.clone(),
                        index,
                        reason,
                    });
                }
            }
        }
        if let Some(chain) = jump_cycle(config, profile) {
            issues.push(ConfigIssue::JumpHostCycle {
                profile: id.clone(),
                chain,
            });
        }
        if let Some(group) = &profile.group
            && !group_ids.contains(group.0.as_str())
        {
            issues.push(ConfigIssue::UnknownGroup {
                profile: id.clone(),
                group: group.0.clone(),
            });
        }
    }

    if ColorScheme::by_name(&config.appearance.color_scheme).is_none() {
        issues.push(ConfigIssue::UnknownColorScheme(
            config.appearance.color_scheme.clone(),
        ));
    }

    let mut by_chord: HashMap<KeyChord, Vec<Action>> = HashMap::new();
    for (&action, chords) in config.hotkeys.bindings() {
        for &chord in chords {
            by_chord.entry(chord).or_default().push(action);
        }
    }
    for (chord, actions) in by_chord {
        if actions.len() > 1 {
            issues.push(ConfigIssue::AmbiguousChord { chord, actions });
        }
    }

    issues
}

/// Names compare without case and surrounding blanks ("Work" and "work " are the same name).
fn name_key(name: &str) -> String {
    name.trim().to_lowercase()
}

/// The names along the jump chain when it comes back to `start` (`start`'s name first and
/// last); `None` when it ends (no jump host, or one that is not a stored profile such as an
/// `ssh-config:` host) or loops without passing through `start` (reported for those profiles).
fn jump_cycle(config: &Config, start: &Profile) -> Option<Vec<String>> {
    let jump_of = |p: &Profile| match &p.kind {
        ProfileKind::Ssh(ssh) => ssh
            .jump_host
            .clone()
            .or_else(|| config.profile_defaults.ssh.jump_host.clone()),
        ProfileKind::Local(_) => None,
    };
    let mut chain = vec![start.name.clone()];
    let mut seen = HashSet::from([&start.id]);
    let mut current = start;
    while let Some(next_id) = jump_of(current) {
        let next = config.profiles.iter().find(|p| p.id == next_id)?;
        chain.push(next.name.clone());
        if next.id == start.id {
            return Some(chain);
        }
        if !seen.insert(&next.id) {
            return None;
        }
        current = next;
    }
    None
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests")]

    use super::*;
    use crate::config::ssh_opts::SshOpts;
    use crate::profile::{Group, GroupId, LocalOpts};

    fn profile(id: &str) -> Profile {
        Profile {
            id: ProfileId(id.to_owned()),
            name: id.to_owned(),
            kind: ProfileKind::Local(LocalOpts::default()),
            ..Profile::default_shell()
        }
    }

    fn ssh(id: &str, jump: Option<&str>) -> Profile {
        Profile {
            kind: ProfileKind::Ssh(SshOpts {
                host: Some(format!("{id}.lan")),
                jump_host: jump.map(|j| ProfileId(j.to_owned())),
                ..SshOpts::default()
            }),
            ..profile(id)
        }
    }

    fn issues_of<'a>(issues: &'a [ConfigIssue], id: &str) -> Vec<&'a ConfigIssue> {
        issues
            .iter()
            .filter(|i| i.profile().is_some_and(|p| p.0 == id))
            .collect()
    }

    #[test]
    fn validate_catches_duplicate_profile_ids() {
        let config = Config {
            profiles: vec![profile("dup"), profile("dup")],
            ..Config::default()
        };
        let issues = validate(&config);
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, ConfigIssue::DuplicateProfileId(id) if id.0 == "dup")),
            "{issues:?}"
        );
    }

    #[test]
    fn validate_catches_unknown_group_and_scheme() {
        let mut p = profile("solo");
        p.group = Some(GroupId("nonexistent".to_owned()));
        let config = Config {
            profiles: vec![p],
            groups: vec![Group {
                id: GroupId("other".to_owned()),
                name: "Other".to_owned(),
            }],
            appearance: super::super::Appearance {
                color_scheme: "Not A Real Scheme".to_owned(),
                ..super::super::Appearance::default()
            },
            ..Config::default()
        };
        let issues = validate(&config);
        assert!(matches!(
            &issues[0],
            ConfigIssue::UnknownGroup { group, .. } if group == "nonexistent"
        ));
        assert!(
            issues.iter().any(
                |i| matches!(i, ConfigIssue::UnknownColorScheme(s) if s == "Not A Real Scheme")
            )
        );
    }

    #[test]
    fn validate_catches_ambiguous_chords() {
        use crate::action::Hotkeys;
        use std::collections::BTreeMap;
        let mut bindings = BTreeMap::new();
        let chord = KeyChord::parse("Ctrl-Shift-X").unwrap();
        bindings.insert(Action::Copy, vec![chord]);
        bindings.insert(Action::Paste, vec![chord]);
        let config = Config {
            hotkeys: Hotkeys::new(bindings),
            ..Config::default()
        };
        let issues = validate(&config);
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, ConfigIssue::AmbiguousChord { .. })),
            "{issues:?}"
        );
    }

    #[test]
    fn duplicate_names_are_reported_for_each_profile_ignoring_case() {
        let mut b = profile("b");
        b.name = " A ".to_owned();
        let config = Config {
            profiles: vec![profile("a"), b, profile("c")],
            ..Config::default()
        };
        let issues = validate(&config);
        for id in ["a", "b"] {
            assert!(
                matches!(
                    issues_of(&issues, id)[..],
                    [ConfigIssue::DuplicateProfileName { .. }]
                ),
                "{id}: {issues:?}"
            );
        }
        assert_eq!(issues_of(&issues, "c"), Vec::<&ConfigIssue>::new());
    }

    #[test]
    fn empty_name_and_missing_host_are_reported() {
        let mut nameless = profile("x");
        nameless.name = "  ".to_owned();
        let mut hostless = ssh("h", None);
        hostless.kind = ProfileKind::Ssh(SshOpts::default());
        let config = Config {
            profiles: vec![nameless, hostless.clone()],
            ..Config::default()
        };
        let issues = validate(&config);
        assert_eq!(
            issues_of(&issues, "x"),
            [&ConfigIssue::EmptyProfileName(ProfileId("x".into()))]
        );
        assert_eq!(
            issues_of(&issues, "h"),
            [&ConfigIssue::MissingHost(ProfileId("h".into()))]
        );
        // A host from profile_defaults.ssh counts.
        let mut config = Config {
            profiles: vec![hostless],
            ..Config::default()
        };
        config.profile_defaults.ssh.host = Some("default.lan".into());
        assert_eq!(validate(&config), Vec::new());
    }

    #[test]
    fn unusable_forwards_are_reported_with_their_index() {
        use crate::config::ssh_opts::{ForwardKind, PortForward};
        let mut p = ssh("f", None);
        if let ProfileKind::Ssh(opts) = &mut p.kind {
            let socks = PortForward {
                kind: ForwardKind::Dynamic,
                port: 1080,
                ..PortForward::default()
            };
            let no_target = PortForward {
                port: 8080,
                ..PortForward::default()
            };
            opts.forwarded_ports = Some(vec![socks, no_target]);
        }
        let config = Config {
            profiles: vec![p],
            ..Config::default()
        };
        let issues = validate(&config);
        assert_eq!(
            issues_of(&issues, "f"),
            [&ConfigIssue::BadForward {
                profile: ProfileId("f".into()),
                index: 1,
                reason: "the target address is empty",
            }]
        );
    }

    #[test]
    fn jump_host_cycles_are_rejected_and_chains_are_fine() {
        let config = Config {
            profiles: vec![
                ssh("a", Some("b")),
                ssh("b", Some("c")),
                ssh("c", Some("a")),
                ssh("d", Some("a")),
                ssh("e", Some("ssh-config:bastion")),
                ssh("f", Some("f")),
            ],
            ..Config::default()
        };
        let issues = validate(&config);
        let cycle = |id: &str| {
            issues_of(&issues, id).into_iter().find_map(|i| match i {
                ConfigIssue::JumpHostCycle { chain, .. } => Some(chain.join(">")),
                _ => None,
            })
        };
        assert_eq!(cycle("a").as_deref(), Some("a>b>c>a"));
        assert_eq!(cycle("b").as_deref(), Some("b>c>a>b"));
        assert_eq!(cycle("f").as_deref(), Some("f>f"));
        // `d` leads into a loop it is not part of; `e` jumps through a non-stored host.
        assert_eq!(cycle("d"), None);
        assert_eq!(cycle("e"), None);
        assert_eq!(
            ConfigIssue::JumpHostCycle {
                profile: ProfileId("a".into()),
                chain: vec!["a".into(), "b".into(), "a".into()]
            }
            .to_string(),
            "jump host loop: a → b → a"
        );
    }
}
