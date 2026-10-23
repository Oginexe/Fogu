//! Session reuse and agent forwarding through real OpenSSH: two tabs of one profile share
//! one connection (one host-key check, one set of forwards), closing one keeps the other, other
//! profiles or `reuse_session = false` never share; a forwarded agent answers `ssh-add -l`.

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fogu_core::{ForwardKind, PortForward};
use fogu_session::{
    ConnectionId, ForwardState, PromptKind, PromptReply, SecretStore, SessionOutput,
    SessionRuntime, SessionWarning,
};

use super::no_prompts;
use crate::support::client::Client;
use crate::support::sshd::{TestAgent, TestSshd};

type TestClient = Client<fn(&PromptKind) -> PromptReply>;

/// Accepts the unknown host key once (not saved: every new connection asks again).
fn accept_host(kind: &PromptKind) -> PromptReply {
    match kind {
        PromptKind::HostKeyUnknown { .. } => PromptReply::Accept,
        other => panic!("unexpected prompt: {other:?}"),
    }
}

fn connection(client: &mut TestClient) -> ConnectionId {
    match client.until(|e| matches!(e, SessionOutput::Connection(_))) {
        Some(SessionOutput::Connection(id)) => id,
        other => panic!("no connection id: {other:?}"),
    }
}

/// A TCP echo server on 127.0.0.1 (one connection at a time is enough here).
fn echo_server() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 256];
            while let Ok(n @ 1..) = stream.read(&mut buf) {
                if stream.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    });
    port
}

fn free_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.local_addr().unwrap().port()
}

fn echoes(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)) else {
        return false;
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = [0u8; 4];
    stream.write_all(b"ping").is_ok() && stream.read_exact(&mut buf).is_ok() && &buf == b"ping"
}

#[test]
fn two_tabs_of_one_profile_share_one_connection_and_its_forwards() {
    let Some(sshd) = TestSshd::start() else {
        return;
    };
    let target = echo_server();
    let port = free_port();
    let mut ssh = sshd.profile();
    ssh.reuse_linger = Duration::ZERO;
    ssh.forwarded_ports = vec![PortForward {
        kind: ForwardKind::Local,
        host: "127.0.0.1".into(),
        port,
        target_address: "127.0.0.1".into(),
        target_port: target,
        description: String::new(),
    }];
    let rt = Arc::new(SessionRuntime::with_store(SecretStore::Disabled("tests".into())).unwrap());
    let mut a: TestClient = Client::connect_shared(&rt, "lab", &ssh, sshd.paths(), accept_host);
    let first = connection(&mut a);
    let forward = a.until(
        |e| matches!(e, SessionOutput::ForwardStatus(s) if s.state == ForwardState::Listening),
    );
    let Some(SessionOutput::ForwardStatus(forward)) = forward else {
        panic!("forward never listened: {forward:?}");
    };
    a.wait_shell();
    assert_eq!(a.prompter.asked.len(), 1, "{:?}", a.prompter.asked);

    // The second tab: no host-key prompt (`no_prompts` panics), same connection, the
    // forward replayed with the same id rather than started again.
    // A split with `remember_cwd` starts in another directory: still the same connection.
    let mut split = ssh.clone();
    split.cwd = Some("/tmp".into());
    let mut b: TestClient = Client::connect_shared(&rt, "lab", &split, sshd.paths(), no_prompts);
    assert_eq!(connection(&mut b), first);
    let replayed = b.until(|e| matches!(e, SessionOutput::ForwardStatus(_)));
    assert!(
        matches!(&replayed, Some(SessionOutput::ForwardStatus(s)) if s.id == forward.id),
        "{replayed:?}"
    );
    b.wait_shell();
    assert!(echoes(port));

    // Closing the first tab keeps the connection, the forward and the other shell.
    a.close();
    assert!(matches!(a.end(), SessionOutput::Exited(_)));
    b.send("echo still-$((40+2))\r");
    b.expect_text("still-42");
    assert!(echoes(port));

    // The last tab closes the connection (linger 0): the forward stops.
    b.close();
    assert!(matches!(b.end(), SessionOutput::Exited(_)));
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok() {
        assert!(Instant::now() < deadline, "forward still listening");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn other_profiles_and_reuse_off_never_share() {
    let Some(sshd) = TestSshd::start() else {
        return;
    };
    let ssh = sshd.profile();
    let rt = Arc::new(SessionRuntime::with_store(SecretStore::Disabled("tests".into())).unwrap());
    let mut a: TestClient = Client::connect_shared(&rt, "one", &ssh, sshd.paths(), accept_host);
    let first = connection(&mut a);
    a.wait_shell();
    // Same settings, another profile id: its own connection and its own host-key check.
    let mut b: TestClient = Client::connect_shared(&rt, "two", &ssh, sshd.paths(), accept_host);
    assert_ne!(connection(&mut b), first);
    b.wait_shell();
    assert_eq!(b.prompter.asked.len(), 1);
    // Same profile id with another user: never the same connection.
    let mut other_user = ssh.clone();
    other_user.user = "nobody-else".into();
    other_user.auth = fogu_core::SshAuth::PublicKey;
    let mut c: TestClient =
        Client::connect_shared(&rt, "one", &other_user, sshd.paths(), accept_host);
    assert!(matches!(c.end(), SessionOutput::Error(_)));
    assert_eq!(c.prompter.asked.len(), 1);
    // reuse_session = false: a fresh connection even for the same profile.
    let mut off = ssh.clone();
    off.reuse_session = false;
    let mut d: TestClient = Client::connect_shared(&rt, "one", &off, sshd.paths(), accept_host);
    assert_ne!(connection(&mut d), first);
    d.wait_shell();
    assert_eq!(d.prompter.asked.len(), 1);
}

#[test]
fn a_forwarded_agent_answers_on_the_server() {
    let Some(sshd) = TestSshd::start() else {
        return;
    };
    let Some(agent) = TestAgent::start(&sshd.dir) else {
        return;
    };
    agent.add(&sshd.client_key);
    sshd.trust();
    let mut ssh = sshd.profile();
    ssh.agent_forward = true;
    ssh.agent_path = Some(agent.socket);
    let mut client: TestClient = Client::connect(&ssh, sshd.paths(), no_prompts);
    let warning = client.until(|e| matches!(e, SessionOutput::Warning(_)));
    assert!(
        matches!(
            warning,
            Some(SessionOutput::Warning(SessionWarning::AgentForwarded))
        ),
        "{warning:?}"
    );
    client.wait_shell();
    client.send("echo agent-keys-$(ssh-add -l | grep -c ED25519)\r");
    client.expect_text("agent-keys-1");
}

#[test]
fn without_agent_forwarding_the_server_has_no_agent() {
    let Some(sshd) = TestSshd::start() else {
        return;
    };
    sshd.trust();
    let mut client: TestClient = Client::connect(&sshd.profile(), sshd.paths(), no_prompts);
    client.wait_shell();
    // sshd names a forwarded agent socket `…/ssh-XXXX/agent.<pid>`. The login shell may set its
    // own SSH_AUTH_SOCK (e.g. a zsh plugin on a developer machine), so only sshd's counts.
    client.send("case \"${SSH_AUTH_SOCK:-}\" in */agent.*) echo fwd-yes;; *) echo fwd-no;; esac\r");
    client.expect_text("fwd-no");
}
