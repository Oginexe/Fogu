#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::lex::{Directive, lex};
use super::*;
use crate::config::ssh_opts::{ForwardKind, PortForward, SshOpts};
use crate::profile::{ProfileId, ProfileKind};

/// A fresh temp `HOME` with `~/.ssh/` created.
fn home(name: &str) -> Env {
    let dir = std::env::temp_dir().join(format!("fogu-sshcfg-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".ssh")).unwrap();
    Env {
        home: dir,
        user: "me".to_owned(),
    }
}

fn write(env: &Env, rel: &str, text: &str) -> PathBuf {
    let path = env.home.join(".ssh").join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, text).unwrap();
    path
}

/// Loads `text` as `~/.ssh/config`.
fn load(env: &Env, text: &str) -> SshConfig {
    let path = write(env, "config", text);
    SshConfig::load(&path, env)
}

fn opts(config: &SshConfig, env: &Env, alias: &str) -> SshOpts {
    config.ssh_opts(alias, env)
}

fn messages(config: &SshConfig) -> Vec<String> {
    config.issues.iter().map(ToString::to_string).collect()
}

#[test]
fn lexes_like_openssh() {
    let d = |name: &str, args: &[&str], raw: &str| Directive {
        name: name.to_owned(),
        key: name.to_ascii_lowercase(),
        args: args.iter().map(|&a| a.to_owned()).collect(),
        raw: raw.to_owned(),
    };
    for (line, want) in [
        ("", None),
        ("   # comment", None),
        ("Host a b", Some(d("Host", &["a", "b"], "a b"))),
        ("HostName=x.org", Some(d("HostName", &["x.org"], "x.org"))),
        ("  Port = 2222  ", Some(d("Port", &["2222"], "2222"))),
        (
            "User me # trailing",
            Some(d("User", &["me"], "me # trailing")),
        ),
        (
            "IdentityFile \"~/my keys/id\" b",
            Some(d(
                "IdentityFile",
                &["~/my keys/id", "b"],
                "\"~/my keys/id\" b",
            )),
        ),
        (
            r"X a\ b 'c d'",
            Some(d("X", &["a b", "c d"], r"a\ b 'c d'")),
        ),
        ("X a#b", Some(d("X", &["a#b"], "a#b"))),
    ] {
        assert_eq!(lex(line).unwrap(), want, "{line}");
    }
    assert!(lex("User \"unterminated").is_err());
    assert!(lex("=x").is_err());
}

#[test]
fn glob_and_host_patterns_match_like_openssh() {
    for (pattern, text, want) in [
        ("*", "anything", true),
        ("a*c", "abbbc", true),
        ("a*c", "abbbd", false),
        ("a?c", "abc", true),
        ("a?c", "ac", false),
        ("*.example", "x.example", true),
        ("*.example", "example", false),
        ("[h]:22*", "[h]:2222", true),
        ("**a", "a", true),
    ] {
        assert_eq!(
            glob(pattern.as_bytes(), text.as_bytes()),
            want,
            "{pattern} {text}"
        );
    }
    for (patterns, host, want) in [
        (&["web*"][..], "web1", true),
        (&["web*", "!web2"][..], "web2", false),
        (&["!web2", "web*"][..], "web2", false),
        (&["!web2"][..], "web1", false),
        (&["WEB1"][..], "web1", true),
    ] {
        assert_eq!(
            host_matches(patterns.iter().copied(), host),
            want,
            "{patterns:?} {host}"
        );
    }
}

const FIXTURE: &str = "\
# my hosts
Host nas
    HostName 10.0.0.7
    User admin
    IdentityFile ~/.ssh/id_nas
    IdentitiesOnly yes

Host web1 web2 !web3 *.lan
    User deploy
    Port 2200

Host web2
    User ignored-because-first-match-wins
    Port 22

Host bastion
    HostName %h.example.org
    ServerAliveInterval 30
    ServerAliveCountMax 4
    ConnectTimeout 7

Host inner
    ProxyJump bastion
    LocalForward 8080 localhost:80
    LocalForward [::1]:9090 db:5432
    RemoteForward 0.0.0.0:2022 127.0.0.1:22
    DynamicForward 1080
    ForwardAgent yes

Host *
    User fallback
    IdentityFile %d/.ssh/id_%r_%h_%p
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    Compression yes
";

#[test]
fn fixture_round_trips_into_profiles() {
    let env = home("fixture");
    let config = load(&env, FIXTURE);
    assert!(config.issues.is_empty(), "{:?}", messages(&config));
    assert_eq!(
        config.aliases(),
        ["nas", "web1", "web2", "bastion", "inner"]
    );
    let profiles = config.profiles(&env);
    assert_eq!(profiles.len(), 5);
    assert_eq!(profiles[0].id, ProfileId("ssh-config:nas".to_owned()));
    assert_eq!(profiles[0].name, "nas");
    let ProfileKind::Ssh(nas) = &profiles[0].kind else {
        panic!("ssh profile expected");
    };
    assert_eq!(nas.host.as_deref(), Some("10.0.0.7"));
    assert_eq!(nas.user.as_deref(), Some("admin"));
    assert_eq!(nas.port, None);
    assert_eq!(nas.identities_only, Some(true));
    let home = env.home.display();
    assert_eq!(
        nas.private_keys.as_deref().unwrap(),
        [
            env.home.join(".ssh/id_nas"),
            PathBuf::from(format!("{home}/.ssh/id_admin_10.0.0.7_22")),
        ]
    );
    // The `Host *` defaults that apply are reported, never obeyed.
    assert_eq!(
        nas.ignored_ssh_config,
        [
            "StrictHostKeyChecking no (host keys are still verified)",
            "UserKnownHostsFile /dev/null (Fogu's known_hosts is used)",
            "Compression",
        ]
    );
}

#[test]
fn first_match_wins_per_keyword_and_wildcards_are_defaults() {
    let env = home("first");
    let config = load(&env, FIXTURE);
    let web2 = opts(&config, &env, "web2");
    assert_eq!(web2.user.as_deref(), Some("deploy"), "earlier block wins");
    assert_eq!(web2.port, Some(2200));
    assert_eq!(
        web2.host.as_deref(),
        Some("web2"),
        "HostName defaults to the alias"
    );
    // `!web3` negates the whole line: only `Host *` applies.
    let web3 = opts(&config, &env, "web3");
    assert_eq!(web3.user.as_deref(), Some("fallback"));
    assert_eq!(web3.port, None);
    let lan = opts(&config, &env, "nas.lan");
    assert_eq!(lan.user.as_deref(), Some("deploy"));
}

#[test]
fn every_mapped_keyword() {
    let env = home("mapped");
    let config = load(&env, FIXTURE);
    let bastion = opts(&config, &env, "bastion");
    assert_eq!(bastion.host.as_deref(), Some("bastion.example.org"));
    assert_eq!(bastion.keepalive_interval, Some(30_000));
    assert_eq!(bastion.keepalive_count_max, Some(4));
    assert_eq!(bastion.ready_timeout, Some(7_000));
    let inner = opts(&config, &env, "inner");
    assert_eq!(
        inner.jump_host,
        Some(ProfileId("ssh-config:bastion".to_owned()))
    );
    assert_eq!(inner.agent_forward, Some(true));
    let fwd = |kind, host: &str, port, to: &str, to_port| PortForward {
        kind,
        host: host.to_owned(),
        port,
        target_address: to.to_owned(),
        target_port: to_port,
        description: String::new(),
    };
    assert_eq!(
        inner.forwarded_ports.unwrap(),
        [
            fwd(ForwardKind::Local, "127.0.0.1", 8080, "localhost", 80),
            fwd(ForwardKind::Local, "::1", 9090, "db", 5432),
            fwd(ForwardKind::Remote, "0.0.0.0", 2022, "127.0.0.1", 22),
            fwd(ForwardKind::Dynamic, "127.0.0.1", 1080, "", 0),
        ]
    );
}

#[test]
fn unusable_values_are_reported_not_dropped() {
    let env = home("unusable");
    let config = load(
        &env,
        "Host a\n  Port nope\n  ProxyJump -oops\n  ProxyCommand nc %h %p\n  \
         LocalForward /tmp/sock host:1\n  ForwardAgent $SSH_AUTH_SOCK\n  IdentityFile ~/k_%C\n  \
         StrictHostKeyChecking ask\n  UserKnownHostsFile ~/.ssh/known_hosts\n",
    );
    let a = opts(&config, &env, "a");
    assert_eq!(a.port, None);
    assert_eq!(a.proxy_command.as_deref(), Some("nc %h %p"));
    assert_eq!(a.private_keys, None);
    assert_eq!(
        a.ignored_ssh_config,
        [
            "Port nope (invalid value)",
            "ProxyJump -oops (invalid value)",
            "LocalForward /tmp/sock host:1 (unsupported form)",
            "ForwardAgent $SSH_AUTH_SOCK (unsupported value)",
            "IdentityFile ~/k_%C (unsupported token %C)",
        ]
    );
    let effective = crate::config::ssh_opts::resolve_ssh(&a, &SshOpts::default());
    assert!(
        effective
            .unsupported()
            .contains(&"ProxyJump -oops (invalid value)".to_owned())
    );
    assert_eq!(
        effective.route_problems(),
        ["ProxyJump -oops (invalid value)"]
    );
}

#[test]
fn proxy_jump_hops_and_proxy_command_tokens_map() {
    let env = home("jumps");
    let config = load(
        &env,
        "Host multi\n  ProxyJump me@hop:2222,Bastion\n\
         Host uri\n  ProxyJump ssh://[::1]:2200\n\
         Host first-cmd\n  ProxyCommand nc %h %p\n  ProxyJump bastion\n\
         Host first-jump\n  ProxyJump bastion\n  ProxyCommand nc %h %p\n\
         Host token\n  ProxyCommand ssh -W %h:%p %n\n\
         Host bastion\n  HostName gw.example\n  User ops\n  ProxyJump none\n\
         Host *.lan\n  Port 2022\n",
    );
    let jump = |alias: &str| opts(&config, &env, alias).jump_host.map(|j| j.0);
    assert_eq!(
        jump("multi").as_deref(),
        Some("ssh-config:me@hop:2222,Bastion")
    );
    assert_eq!(jump("uri").as_deref(), Some("ssh-config:ssh://[::1]:2200"));
    assert_eq!(jump("first-jump").as_deref(), Some("ssh-config:bastion"));
    assert_eq!(opts(&config, &env, "first-jump").proxy_command, None);
    let cmd = opts(&config, &env, "first-cmd");
    assert_eq!(
        (cmd.jump_host, cmd.proxy_command.as_deref()),
        (None, Some("nc %h %p"))
    );
    let token = opts(&config, &env, "token");
    assert_eq!(token.proxy_command, None);
    assert_eq!(
        token.ignored_ssh_config,
        ["ProxyCommand ssh -W %h:%p %n (unsupported token %n)"]
    );

    // `multi` = hop.lan's options as me@:2222, through bastion (its own config).
    let last = config.jump_opts("me@hop:2222,Bastion", &env).unwrap();
    assert_eq!(last.host.as_deref(), Some("gw.example"));
    assert_eq!(last.user.as_deref(), Some("ops"));
    assert_eq!(
        last.jump_host.as_ref().map(|j| j.0.as_str()),
        Some("ssh-config:me@hop:2222")
    );
    let first = config.jump_opts("me@hop:2222", &env).unwrap();
    assert_eq!(
        (
            first.host.as_deref(),
            first.user.as_deref(),
            first.port,
            first.jump_host
        ),
        (Some("hop"), Some("me"), Some(2222), None)
    );
    let lan = config.jump_opts("box.lan", &env).unwrap();
    assert_eq!(
        (lan.host.as_deref(), lan.port),
        (Some("box.lan"), Some(2022))
    );
    let v6 = config.jump_opts("ssh://[::1]:2200", &env).unwrap();
    assert_eq!((v6.host.as_deref(), v6.port), (Some("::1"), Some(2200)));
    for bad in [
        "",
        "-oProxyCommand=x",
        "a b",
        "u@",
        "h:0",
        "h:x",
        "[::1",
        "a/b",
        "@h",
    ] {
        assert!(config.jump_opts(bad, &env).is_err(), "{bad:?}");
    }
}

#[test]
fn match_blocks_are_skipped_with_a_warning() {
    let env = home("match");
    let config = load(
        &env,
        "Host a\n  User one\nMatch host a exec \"true\"\n  User two\n  Include evil\nHost b\n  User three\n",
    );
    assert_eq!(opts(&config, &env, "a").user.as_deref(), Some("one"));
    assert_eq!(opts(&config, &env, "b").user.as_deref(), Some("three"));
    let path = env.home.join(".ssh").join("config");
    assert_eq!(
        messages(&config),
        [format!(
            "{}:3: Match blocks are not supported; block skipped",
            path.display()
        )]
    );
}

#[test]
fn bad_lines_are_issues_with_file_and_line_and_the_rest_loads() {
    let env = home("badline");
    let long = format!("User {}\n", "x".repeat(MAX_LINE));
    let config = load(
        &env,
        &format!("Host a\n  User \"oops\n{long}  Port 2\nHost\nHost b\n"),
    );
    assert_eq!(opts(&config, &env, "a").port, Some(2));
    assert_eq!(config.aliases(), ["a", "b"]);
    let lines: Vec<usize> = config.issues.iter().map(|i| i.line).collect();
    assert_eq!(lines, [2, 3, 5]);
}

#[test]
fn include_is_relative_to_dot_ssh_globbed_and_scoped_to_its_host_block() {
    let env = home("include");
    write(
        &env,
        "conf.d/10-work",
        "Host work\n  HostName work.example\n",
    );
    write(&env, "conf.d/20-home", "Host nas\n  User nas-user\n");
    write(&env, "conf.d/.hidden", "Host hidden\n");
    write(
        &env,
        "scoped",
        "User scoped-user\nHost other\n  User other-user\n",
    );
    let config = load(
        &env,
        "Include conf.d/*\nHost box\n  Include ~/.ssh/scoped\n  Port 2\nHost *\n  User dflt\n",
    );
    assert!(config.issues.is_empty(), "{:?}", messages(&config));
    assert_eq!(config.aliases(), ["work", "nas", "box", "other"]);
    assert_eq!(
        opts(&config, &env, "work").host.as_deref(),
        Some("work.example")
    );
    assert_eq!(opts(&config, &env, "nas").user.as_deref(), Some("nas-user"));
    let boxed = opts(&config, &env, "box");
    assert_eq!(boxed.user.as_deref(), Some("scoped-user"));
    assert_eq!(
        boxed.port,
        Some(2),
        "options after the Include still belong to the block"
    );
    // `Host other` inside an Include under `Host box` needs both to match: never for "other".
    assert_eq!(opts(&config, &env, "other").user.as_deref(), Some("dflt"));
}

#[test]
fn include_cycles_depth_and_non_regular_files_are_bounded() {
    let env = home("cycle");
    write(&env, "a", "Include b\nHost from-a\n");
    write(&env, "b", "Include a\nHost from-b\n");
    std::fs::create_dir_all(env.home.join(".ssh/dir")).unwrap();
    let config = load(&env, "Include a\nInclude dir\nInclude missing\nHost top\n");
    assert_eq!(config.aliases(), ["from-b", "from-a", "top"]);
    let found: Vec<String> = config.issues.iter().map(|i| i.message.clone()).collect();
    assert_eq!(
        found,
        ["Include cycle; ignored", "not a regular file; ignored"]
    );

    let deep = home("deep");
    for i in 0..20 {
        write(
            &deep,
            &format!("d{i}"),
            &format!("Include d{}\nHost h{i}\n", i + 1),
        );
    }
    let config = load(&deep, "Include d0\n");
    assert_eq!(config.aliases().len(), MAX_DEPTH);
    assert!(messages(&config)[0].ends_with("Include nested deeper than 16; ignored"));
}

#[test]
fn oversized_files_are_refused() {
    let env = home("big");
    let size = usize::try_from(MAX_FILE_BYTES).unwrap() + 1;
    write(&env, "big", &"#".repeat(size));
    let config = load(&env, "Include big\nHost ok\n");
    assert_eq!(config.aliases(), ["ok"]);
    assert_eq!(config.issues[0].message, "too large; ignored");
}

#[test]
fn missing_file_is_empty_and_changes_are_noticed() {
    let env = home("live");
    let path = env.home.join(".ssh/config");
    let config = SshConfig::load(&path, &env);
    assert!(config.aliases().is_empty() && config.issues.is_empty());
    assert!(!config.changed());
    std::fs::write(&path, "Include conf.d/*\nHost one\n").unwrap();
    assert!(config.changed(), "file created");

    std::fs::create_dir_all(env.home.join(".ssh/conf.d")).unwrap();
    let config = SshConfig::load(&path, &env);
    assert!(!config.changed());
    let old = SystemTime::now() - Duration::from_secs(60);
    let set_mtime = |p: &Path, at| {
        std::fs::File::options()
            .write(true)
            .open(p)
            .unwrap()
            .set_modified(at)
            .unwrap();
    };
    set_mtime(&path, old);
    assert!(config.changed(), "mtime changed");

    let config = SshConfig::load(&path, &env);
    write(&env, "conf.d/new", "Host two\n");
    assert!(config.changed(), "new file in a globbed directory");
    assert_eq!(SshConfig::load(&path, &env).aliases(), ["two", "one"]);
}

#[test]
fn host_key_alias_is_mapped_and_check_host_ip_no_is_quiet() {
    let env = home("hostkeyalias");
    let config = load(
        &env,
        "Host a\n  HostKeyAlias dev-a\n  CheckHostIP no\nHost b\n  CheckHostIP yes\n",
    );
    let a = opts(&config, &env, "a");
    assert_eq!(a.host_key_alias.as_deref(), Some("dev-a"));
    assert!(
        a.ignored_ssh_config.is_empty(),
        "{:?}",
        a.ignored_ssh_config
    );
    let b = opts(&config, &env, "b");
    assert_eq!(b.ignored_ssh_config, ["CheckHostIP"]);
}
