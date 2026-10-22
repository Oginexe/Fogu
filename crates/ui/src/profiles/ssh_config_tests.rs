#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]

use std::path::Path;
use std::sync::Arc;

use fogu_core::config::load;
use fogu_core::ssh_config::Env;
use fogu_core::{Action, EffectiveProfile, ProfileKind};

use super::super::tests::{app_in, id, send, tmp, tree};
use super::*;
use crate::message::Message;
use crate::profiles::{Origin, ProfilesMsg};

const SSH_CONFIG: &str = "\
Host storage
    HostName 10.0.0.9
    User admin
    IdentityFile ~/.ssh/id_nas
Host jumpy
    ProxyJump me@hop:2222
Match exec true
    User nobody
Host *
    StrictHostKeyChecking no
";

/// An app (see `app_in`) whose `~/.ssh/config` is `dir/home/.ssh/config`.
fn app_with_ssh_config(dir: &Path, text: &str) -> App {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(home.join(".ssh/config"), text).unwrap();
    let mut app = app_in(dir);
    let env = Env {
        home: home.clone(),
        user: "me".into(),
    };
    app.profiles.ssh_hosts = SshHosts::at(Some((env, home.join(".ssh/config"))));
    let _ = app.update(Message::Action(Action::ToggleProfiles));
    app
}

#[test]
fn hosts_show_in_their_own_section_and_connect_with_the_ignored_options_listed() {
    let t = tmp();
    let mut app = app_with_ssh_config(&t.0, SSH_CONFIG);
    let tree = tree(&app);
    let at = tree.iter().position(|l| l == "v SSH config (2)").unwrap();
    assert_eq!(tree[at + 1..at + 3], ["storage", "jumpy"]);
    assert_eq!(tree[at + 3], "v Built-ins (1)");
    // The picker (a flat list) says where the host comes from; "ssh config" is searchable.
    let (entries, rows) = crate::profile_picker::listing(&app);
    let i = entries
        .iter()
        .position(|e| e.profile.name == "storage")
        .unwrap();
    assert_eq!(rows[i].subtitle, "admin@10.0.0.9 · ssh config");
    send(&mut app, ProfilesMsg::Query("ssh config".into()));
    assert_eq!(super::super::tests::tree(&app), ["jumpy", "storage"]);
    send(&mut app, ProfilesMsg::Query(String::new()));
    // The Match line is reported once, with file:line.
    let toast = app.toasts.iter().last().unwrap();
    assert_eq!(toast.title, "~/.ssh/config");
    let config = Path::new("~").join(".ssh/config");
    assert_eq!(
        toast.detail,
        format!(
            "{}:7: Match blocks are not supported; block skipped",
            config.display()
        )
    );

    send(
        &mut app,
        ProfilesMsg::Open(id("ssh-config:storage"), crate::profiles::Launch::Tab),
    );
    let EffectiveProfile::Ssh(ssh) = app.stub_profiles.last().unwrap() else {
        panic!("ssh")
    };
    assert_eq!(
        (ssh.host.as_str(), ssh.user.as_str()),
        ("10.0.0.9", "admin")
    );
    assert!(
        ssh.verify_host_keys,
        "StrictHostKeyChecking no is not obeyed"
    );
    assert_eq!(
        ssh.unsupported(),
        ["StrictHostKeyChecking no (host keys are still verified)"]
    );
    send(
        &mut app,
        ProfilesMsg::Open(id("ssh-config:jumpy"), crate::profiles::Launch::Tab),
    );
    let EffectiveProfile::Ssh(ssh) = app.stub_profiles.last().unwrap() else {
        panic!("ssh")
    };
    // `ProxyJump me@hop:2222` resolves to a hop configured from the same file.
    let fogu_core::Jump::Via(hop) = &ssh.jump else {
        panic!("jump not resolved: {:?}", ssh.jump)
    };
    assert_eq!(
        (hop.user.as_str(), hop.host.as_str(), hop.port),
        ("me", "hop", 2222)
    );
    assert!(hop.verify_host_keys);
    assert_eq!(hop.jump, fogu_core::Jump::None);
    assert_eq!(ssh.route_problems(), Vec::<String>::new());
}

#[test]
fn rows_are_read_only_and_copy_to_my_profiles_saves_an_editable_one() {
    let t = tmp();
    let mut app = app_with_ssh_config(&t.0, SSH_CONFIG);
    send(&mut app, ProfilesMsg::Menu(id("ssh-config:storage"), 0));
    let menu = app.menu.as_ref().unwrap();
    let enabled = |label: &str| {
        menu.items
            .iter()
            .find(|i| i.label == label)
            .map(|i| i.enabled)
    };
    assert_eq!(enabled("Copy to my profiles"), Some(true));
    assert_eq!(enabled("Duplicate"), None);
    assert_eq!(enabled("Move to group ▸"), Some(false));
    assert_eq!(enabled("Delete"), Some(false));
    send(&mut app, ProfilesMsg::AskDelete(id("ssh-config:storage")));
    assert!(app.profiles.pending_delete.is_none());

    send(&mut app, ProfilesMsg::Duplicate(id("ssh-config:storage")));
    let (on_disk, _) = load(&t.0);
    let copy = on_disk.profiles.last().unwrap();
    assert_eq!(
        (copy.id.0.as_str(), copy.name.as_str()),
        ("storage", "storage")
    );
    let ProfileKind::Ssh(opts) = &copy.kind else {
        panic!("ssh")
    };
    assert_eq!(opts.host.as_deref(), Some("10.0.0.9"));
    assert_eq!(opts.ignored_ssh_config, Vec::<String>::new());
    assert_eq!(on_disk, *app.config);
    let toast = app.toasts.iter().last().unwrap();
    assert_eq!(toast.title, "Copied to my profiles");
    assert!(
        toast.detail.contains("StrictHostKeyChecking no"),
        "{}",
        toast.detail
    );
    // The ~/.ssh/config file itself is never written.
    let home_config = t.0.join("home/.ssh/config");
    assert_eq!(std::fs::read_to_string(home_config).unwrap(), SSH_CONFIG);
}

#[test]
fn changes_are_picked_up_when_the_sidebar_or_picker_opens() {
    let t = tmp();
    let mut app = app_with_ssh_config(&t.0, "Host one\n");
    assert!(tree(&app).contains(&"one".to_owned()));
    std::fs::write(t.0.join("home/.ssh/config"), "Host one two\n").unwrap();
    let _ = app.update(Message::Action(Action::ToggleProfiles)); // close: no re-read
    assert!(!tree(&app).contains(&"two".to_owned()));
    let _ = app.update(Message::Action(Action::OpenProfilePicker));
    assert!(tree(&app).contains(&"v SSH config (2)".to_owned()));
}

#[test]
fn read_ssh_config_false_hides_the_hosts() {
    let t = tmp();
    let mut app = app_with_ssh_config(&t.0, "Host one\n");
    Arc::make_mut(&mut app.config).ssh.read_ssh_config = false;
    let _ = app.update(Message::Action(Action::OpenProfilePicker));
    assert!(
        app.all_entries()
            .iter()
            .all(|e| e.origin != Origin::SshConfig)
    );
}
