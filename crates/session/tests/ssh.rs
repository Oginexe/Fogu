//! SSH session tests that need no server: early failures and warnings. The sshd-backed suite
//! will reuse `support::prompter`.
#![cfg(feature = "ssh")]
#![expect(clippy::unwrap_used, clippy::panic, reason = "tests")]

mod support {
    pub mod prompter;
}

use std::time::Duration;

use fogu_core::{EffectiveSsh, Size};
use fogu_session::{
    PromptReply, SecretStore, SessionError, SessionOutput, SessionRuntime, SessionWarning,
    SshPaths, open_ssh,
};
use fogu_term::{TermHandle, WORD_SEPARATORS};
use support::prompter::Prompter;

const SIZE: Size = Size {
    cols: 80,
    rows: 24,
    px_w: 0,
    px_h: 0,
};

fn paths(name: &str) -> SshPaths {
    let dir = std::env::temp_dir().join(format!("fogu-ssh-test-{name}-{}", std::process::id()));
    SshPaths {
        known_hosts: dir.join("known_hosts"),
        system_known_hosts: None,
    }
}

/// Runs `ssh` until it reports an error or exits; returns that event, the warnings and the
/// terminal text.
fn run(ssh: &EffectiveSsh, name: &str) -> (SessionOutput, Vec<SessionWarning>, String) {
    let rt = SessionRuntime::with_store(SecretStore::Disabled("tests".into())).unwrap();
    let term = TermHandle::new(SIZE.cols, SIZE.rows, 100, WORD_SEPARATORS);
    let view = term.share();
    let mut session = open_ssh(
        rt.handle(),
        ssh,
        paths(name),
        rt.secrets().clone(),
        SIZE,
        term,
    );
    let mut prompter = Prompter::new(|_| PromptReply::Reject);
    let mut warnings = Vec::new();
    let end = rt.handle().block_on(prompter.run_until(
        &mut session,
        &view,
        Duration::from_secs(10),
        |event| match event {
            SessionOutput::Warning(w) => {
                warnings.push(w.clone());
                false
            }
            other => matches!(other, SessionOutput::Error(_) | SessionOutput::Exited(_)),
        },
    ));
    let end = end.unwrap_or_else(|| panic!("no end event; grid:\n{}", view.dump_grid()));
    assert!(prompter.asked.is_empty(), "{:?}", prompter.asked);
    (end, warnings, view.dump_grid())
}

#[test]
fn missing_host_fails_with_no_host_after_warning_unsupported_options() {
    let mut ssh = EffectiveSsh::new("");
    ssh.input_backspace = fogu_core::Backspace::CtrlH;
    let (end, warnings, grid) = run(&ssh, "nohost");
    assert!(
        matches!(end, SessionOutput::Error(SessionError::NoHost)),
        "{end:?}"
    );
    assert_eq!(
        warnings,
        [SessionWarning::Unsupported(vec![
            "input_backspace".to_owned()
        ])]
    );
    assert!(
        grid.contains("Not supported yet (ignored): input_backspace"),
        "{grid}"
    );
    assert!(grid.contains("Error: no host configured"), "{grid}");
}

#[test]
fn unresolved_or_ambiguous_routes_refuse_to_connect_directly() {
    // Port 1 would be refused if a connection were attempted: the error must come first.
    let mut ssh = EffectiveSsh::new("127.0.0.1");
    ssh.port = 1;
    ssh.jump_host = Some(fogu_core::ProfileId("bastion".into()));
    let (end, _warnings, grid) = run(&ssh, "unresolved");
    let SessionOutput::Error(SessionError::Route(what)) = end else {
        panic!("expected Route, got {end:?}");
    };
    assert_eq!(what, "jump_host bastion was not resolved");
    assert!(!grid.contains("Connecting to"), "{grid}");

    ssh.jump_host = None;
    ssh.proxy_command = Some("nc %h %p".into());
    ssh.http_proxy = Some(("127.0.0.1".into(), 1));
    let (end, _warnings, _grid) = run(&ssh, "ambiguous");
    let SessionOutput::Error(SessionError::Route(what)) = end else {
        panic!("expected Route, got {end:?}");
    };
    assert_eq!(what, "only one of proxy_command, http_proxy may be set");
}

#[test]
fn a_refused_proxy_port_is_a_clear_proxy_error() {
    let mut ssh = EffectiveSsh::new("example.invalid");
    ssh.socks_proxy = Some(("127.0.0.1".into(), 1));
    let (end, _warnings, grid) = run(&ssh, "socks-refused");
    let SessionOutput::Error(SessionError::Proxy(what)) = end else {
        panic!("expected Proxy, got {end:?}");
    };
    assert!(
        what.starts_with("SOCKS5 proxy 127.0.0.1:1: could not connect:"),
        "{what}"
    );
    assert!(
        grid.contains("Connecting to example.invalid:22 via proxy socks5://127.0.0.1:1"),
        "{grid}"
    );
}

#[cfg(unix)]
#[test]
fn a_failing_proxy_command_reports_its_last_stderr_line_sanitized() {
    let mut ssh = EffectiveSsh::new("127.0.0.1");
    ssh.proxy_command = Some("printf 'noise\\n\\033]0;pwned\\007bad %h\\n' >&2".into());
    let (end, _warnings, _grid) = run(&ssh, "proxy-fails");
    let SessionOutput::Error(SessionError::Proxy(what)) = end else {
        panic!("expected Proxy, got {end:?}");
    };
    assert_eq!(
        what,
        "the proxy command ended (exit status: 0): ]0;pwnedbad 127.0.0.1"
    );
}

#[test]
fn refused_port_reports_connect_error() {
    // Port 1 on loopback: nothing listens there in a test environment.
    let mut ssh = EffectiveSsh::new("127.0.0.1");
    ssh.port = 1;
    let (end, warnings, grid) = run(&ssh, "refused");
    let SessionOutput::Error(SessionError::Connect { target, .. }) = end else {
        panic!("expected a connect error, got {end:?}");
    };
    assert_eq!(target, "127.0.0.1:1");
    assert_eq!(warnings, []);
    assert!(grid.contains("Connecting to 127.0.0.1:1"), "{grid}");
}

#[test]
fn hostile_host_name_is_sanitized_in_service_lines() {
    let mut ssh = EffectiveSsh::new("bad\x1b]0;pwned\x07host.invalid");
    ssh.port = 1;
    let (_end, _warnings, grid) = run(&ssh, "hostile");
    assert!(grid.contains("bad]0;pwnedhost.invalid"), "{grid}");
}
