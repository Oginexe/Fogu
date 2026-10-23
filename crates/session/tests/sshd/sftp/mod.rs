//! SFTP engine against the real `sshd`'s `sftp-server`: listing, metadata operations,
//! streamed upload/download, symlink rules, cancel, resume, and the local symlink refusal. The
//! daemon runs on this machine, so "remote" paths are paths in the test's temp dir.

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fogu_session::sftp::{CmdId, EntryKind, OverwritePolicy, TransferReport};
use fogu_session::{SftpCmd, SftpEvent, SftpHandle, SftpRequest};

mod ops;
mod transfer;

use super::no_prompts;
use crate::support::client::Client;
use crate::support::sshd::TestSshd;

const EVENT_WAIT: Duration = Duration::from_secs(60);

type Answer = fn(&fogu_session::PromptKind) -> fogu_session::PromptReply;

/// A connected session plus its SFTP handle.
struct Sftp {
    client: Client<Answer>,
    handle: SftpHandle,
    next: u64,
    /// Every event seen so far (for assertions on progress/conflicts).
    seen: Vec<SftpEvent>,
    sshd: TestSshd,
}

impl Sftp {
    fn start() -> Option<Self> {
        let sshd = TestSshd::start()?;
        sshd.trust();
        let mut client = Client::connect(&sshd.profile(), sshd.paths(), no_prompts as Answer);
        client.wait_shell();
        let handle = client
            .session
            .sftp
            .take()
            .expect("SSH sessions have an SFTP handle");
        Some(Self {
            client,
            handle,
            next: 0,
            seen: Vec::new(),
            sshd,
        })
    }

    fn dir(&self) -> &Path {
        self.sshd.dir.path()
    }

    fn send(&mut self, cmd: SftpCmd) -> CmdId {
        self.next += 1;
        let id = CmdId(self.next);
        let request = SftpRequest { id, cmd };
        self.client
            .rt
            .handle()
            .block_on(self.handle.cmds.send(request))
            .expect("engine alive");
        id
    }

    /// Waits for the first event `done` accepts.
    fn wait(&mut self, mut done: impl FnMut(&SftpEvent) -> bool) -> SftpEvent {
        let events = &mut self.handle.events;
        let seen = &mut self.seen;
        self.client.rt.handle().block_on(async {
            loop {
                let event = tokio::time::timeout(EVENT_WAIT, events.recv())
                    .await
                    .expect("no SFTP event in time")
                    .expect("engine ended");
                seen.push(event.clone());
                if done(&event) {
                    return event;
                }
            }
        })
    }

    /// Sends `cmd` and waits for its final answer.
    fn request(&mut self, cmd: SftpCmd) -> SftpEvent {
        let id = self.send(cmd);
        self.wait(|e| answer_id(e) == Some(id))
    }

    fn ok(&mut self, cmd: SftpCmd) {
        match self.request(cmd) {
            SftpEvent::Done(_) => {}
            other => panic!("expected Done, got {other:?}"),
        }
    }

    /// Runs a transfer to its end and returns the final event.
    fn transfer(&mut self, cmd: SftpCmd) -> SftpEvent {
        self.request(cmd)
    }

    fn download(
        &mut self,
        remote: &[&Path],
        local: &Path,
        overwrite: OverwritePolicy,
        resume: bool,
    ) -> SftpEvent {
        self.transfer(SftpCmd::Download {
            remote: remote.iter().map(|p| p.display().to_string()).collect(),
            local_dir: local.to_owned(),
            overwrite,
            resume,
        })
    }
}

/// The command id a final event answers.
fn answer_id(event: &SftpEvent) -> Option<CmdId> {
    match event {
        SftpEvent::Listing { id, .. }
        | SftpEvent::StatResult { id, .. }
        | SftpEvent::Realpath { id, .. }
        | SftpEvent::Counted { id, .. }
        | SftpEvent::Error { id, .. }
        | SftpEvent::TransferDone { id, .. }
        | SftpEvent::TransferFailed { id, .. }
        | SftpEvent::TransferCancelled { id, .. }
        | SftpEvent::Done(id) => Some(*id),
        _ => None,
    }
}

fn done_report(event: SftpEvent) -> TransferReport {
    match event {
        SftpEvent::TransferDone { report, .. } => report,
        other => panic!("expected TransferDone, got {other:?}"),
    }
}

/// Deterministic pseudo-random bytes (xorshift).
#[expect(
    clippy::cast_possible_truncation,
    reason = "keeps the top byte of the xorshift state"
)]
fn random_bytes(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn mkdir(path: PathBuf) -> PathBuf {
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn sftp_lists_the_login_dir_and_a_directory() {
    let Some(mut s) = Sftp::start() else { return };
    let home = match s.request(SftpCmd::Realpath(".".into())) {
        SftpEvent::Realpath { path, .. } => path,
        other => panic!("{other:?}"),
    };
    assert!(home.starts_with('/'), "{home}");
    assert!(matches!(
        s.request(SftpCmd::List(home)),
        SftpEvent::Listing { .. }
    ));

    let dir = mkdir(s.dir().join("listing"));
    fs::write(dir.join("file.txt"), "12345").unwrap();
    fs::create_dir(dir.join("zdir")).unwrap();
    symlink("file.txt", dir.join("link")).unwrap();
    symlink("zdir", dir.join("dirlink")).unwrap();
    fs::write(dir.join("evil\x1b[31m"), "").unwrap();
    let SftpEvent::Listing {
        entries, truncated, ..
    } = s.request(SftpCmd::List(dir.display().to_string()))
    else {
        panic!("no listing")
    };
    assert!(!truncated);
    let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
    // Dirs (and links to dirs) first, then by name.
    assert_eq!(
        names,
        ["dirlink", "zdir", "evil\x1b[31m", "file.txt", "link"]
    );
    let file = &entries[3];
    assert_eq!(
        (file.kind, file.size, file.mode.map(|m| m & 0o777)),
        (EntryKind::File, Some(5), Some(0o644))
    );
    let link = &entries[4];
    assert_eq!(link.kind, EntryKind::Symlink);
    assert_eq!(link.link_target.as_deref(), Some("file.txt"));
    assert_eq!(link.link_kind, Some(EntryKind::File));
    assert_eq!(
        fogu_session::display_name(&entries[2].name),
        "evil\\x1b[31m"
    );

    let SftpEvent::StatResult { entry, .. } =
        s.request(SftpCmd::Stat(dir.join("dirlink").display().to_string()))
    else {
        panic!("no stat")
    };
    assert_eq!(
        (entry.name.as_str(), entry.kind, entry.link_kind),
        ("dirlink", EntryKind::Symlink, Some(EntryKind::Dir))
    );
    assert!(matches!(
        s.request(SftpCmd::List(dir.join("missing").display().to_string())),
        SftpEvent::Error { .. }
    ));
}

#[test]
fn sftp_mkdir_rename_chmod_remove_roundtrip() {
    let Some(mut s) = Sftp::start() else { return };
    let base = mkdir(s.dir().join("ops"));
    let p = |name: &str| base.join(name).display().to_string();
    s.ok(SftpCmd::Mkdir(p("a")));
    assert!(base.join("a").is_dir());
    s.ok(SftpCmd::Rename(p("a"), p("b")));
    assert!(!base.join("a").exists() && base.join("b").is_dir());
    s.ok(SftpCmd::Chmod(p("b"), 0o700));
    let mode = fs::metadata(base.join("b")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
    fs::write(base.join("c"), "x").unwrap();
    // SFTP v3 rename never replaces an existing target.
    assert!(matches!(
        s.request(SftpCmd::Rename(p("c"), p("b"))),
        SftpEvent::Error { .. }
    ));
    s.ok(SftpCmd::RemoveFile(p("c")));
    assert!(!base.join("c").exists());
    // A tree with a symlink pointing outside: the link is removed, its target is not.
    let outside = mkdir(s.dir().join("keep-me"));
    fs::write(outside.join("precious"), "x").unwrap();
    fs::create_dir_all(base.join("b/deep/er")).unwrap();
    fs::write(base.join("b/deep/er/f"), "x").unwrap();
    symlink(&outside, base.join("b/deep/out")).unwrap();
    // The root itself must not be a symlink.
    symlink(base.join("b"), base.join("blink")).unwrap();
    assert!(matches!(
        s.request(SftpCmd::RemoveDirRecursive(p("blink"))),
        SftpEvent::Error { .. }
    ));
    s.ok(SftpCmd::RemoveDirRecursive(p("b")));
    assert!(!base.join("b").exists());
    assert!(outside.join("precious").exists());
}
