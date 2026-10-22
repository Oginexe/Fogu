#![cfg(unix)]
//! SSH sessions against a real, throwaway OpenSSH `sshd` on 127.0.0.1, plus a tiny
//! in-process server for password / keyboard-interactive (see `support/fake_server.rs`).
//!
//! Hermetic: random port, everything in a temp dir, daemon killed on drop. Without `sshd` /
//! `ssh-keygen` the sshd-backed tests print a skip line and pass; `FOGU_REQUIRE_SSHD=1` (CI)
//! turns that into a failure.
#![cfg(feature = "ssh")]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unused_async_trait_impl,
    reason = "tests; the fake server implements async trait methods that need no await"
)]

#[path = "../support/mod.rs"]
mod support;

mod auth;
mod forward;
mod hostile;
mod hostkeys;
mod reuse;
mod route;
mod sftp;
mod shell;
mod stored;

use fogu_session::{PromptKind, PromptReply, SessionError, SessionOutput};
use secrecy::SecretString;

/// A prompt answerer that fails the test: no prompt is expected.
fn no_prompts(kind: &PromptKind) -> PromptReply {
    panic!("unexpected prompt: {kind:?}")
}

fn secret(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

/// The session ended with this error.
fn error_of(end: SessionOutput) -> SessionError {
    match end {
        SessionOutput::Error(err) => err,
        other => panic!("expected an error, got {other:?}"),
    }
}
