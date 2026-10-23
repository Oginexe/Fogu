//! Stored passwords and key passphrases in the editor: the "Password" row and one
//! "Passphrase" row per private key show whether the Secret Service holds a secret (existence
//! only, never the value) with Set… (the [`SecretDialog`]) and Clear. The status is looked up
//! when the editor opens and after every Set / Clear; it is keyed by the account / key it was
//! looked up for, so after editing the host, user, port or key list it reads "not checked"
//! until the next lookup instead of showing a stale answer.

use std::path::{Path, PathBuf};

use fogu_core::SecretKey;
use fogu_core::config::ssh_opts::resolve_ssh;
use fogu_core::{EffectiveSsh, ProfileKind};
use iced::Task;
use secrecy::SecretString;

use super::ProfileEditor;
use super::fields::FieldId;
#[cfg(feature = "ssh")]
use super::handlers::EditorMsg;
use super::view::Row;
use crate::app::App;
use crate::forms::{self, FieldValue};
use crate::message::Message;
use crate::notifications::{Level, Notification};
use crate::sftp::panel::Look;
use crate::tab::TabId;

/// What the Secret Service said about one secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stored {
    Yes,
    No,
    /// The store can't be used (sanitized reason).
    Unavailable(String),
}

/// One looked-up secret: the account password (`path` = `None`) or a key file's passphrase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEntry {
    pub path: Option<PathBuf>,
    pub key: SecretKey,
    pub state: Stored,
}

/// The name a key file's passphrase is stored under (`None` = unreadable).
#[cfg(feature = "ssh")]
fn fingerprint(path: &Path) -> Option<String> {
    fogu_session::key_fingerprint(path)
}

#[cfg(not(feature = "ssh"))]
fn fingerprint(_: &Path) -> Option<String> {
    None
}

const NOT_CHECKED: &str = "not checked";

fn status(entry: Option<&StoredEntry>) -> String {
    match entry.map(|e| &e.state) {
        Some(Stored::Yes) => "stored".to_owned(),
        Some(Stored::No) => "not stored".to_owned(),
        Some(Stored::Unavailable(why)) => format!("unavailable: {why}"),
        None => NOT_CHECKED.to_owned(),
    }
}

/// The key files of the draft, without empty rows.
fn key_paths(ed: &ProfileEditor) -> Vec<&Path> {
    match &ed.draft.kind {
        ProfileKind::Ssh(ssh) => ssh
            .private_keys
            .iter()
            .flatten()
            .map(PathBuf::as_path)
            .filter(|p| !p.as_os_str().is_empty())
            .collect(),
        ProfileKind::Local(_) => Vec::new(),
    }
}

/// The Authentication section's secret rows: the password, then a passphrase per private key.
pub(super) fn rows<'a>(ed: &ProfileEditor, eff: &EffectiveSsh, look: Look) -> Vec<Row<'a>> {
    let off = ed
        .read_only()
        .then_some("Copy the profile to your own first");
    let password = SecretKey::ssh_password(eff);
    let found = ed
        .stored
        .iter()
        .find(|e| e.path.is_none() && e.key == password);
    let mut rows = vec![forms::secret_hint(
        look,
        FieldId::Password,
        "Password",
        &status(found),
        off,
    )];
    for (i, path) in key_paths(ed).into_iter().enumerate() {
        let found = ed.stored.iter().find(|e| e.path.as_deref() == Some(path));
        let name = path.file_name().map_or_else(
            || path.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        rows.push(forms::secret_hint(
            look,
            FieldId::KeyPassphrase(i),
            &format!("Passphrase of {name}"),
            &status(found),
            off,
        ));
    }
    rows
}

impl ProfileEditor {
    /// The account whose password "Password" refers to, given the defaults.
    fn effective(&self, defaults: &fogu_core::SshOpts) -> Option<EffectiveSsh> {
        match &self.draft.kind {
            ProfileKind::Ssh(ssh) => Some(resolve_ssh(ssh, defaults)),
            ProfileKind::Local(_) => None,
        }
    }
}

impl App {
    /// What a Set… / Clear on `field` targets: its key and a sentence for the dialog; the
    /// error is the toast that says why not.
    fn secret_target(
        &mut self,
        tab: TabId,
        field: FieldId,
    ) -> Result<(SecretKey, String), Task<Message>> {
        let defaults = self.config.profile_defaults.ssh.clone();
        let target = self
            .tabs
            .iter()
            .find(|t| t.id == tab)
            .and_then(|t| t.editor.as_deref())
            .and_then(|editor| Some((editor.effective(&defaults)?, editor)))
            .and_then(|(eff, editor)| match field {
                FieldId::Password => Some(
                    (!eff.host.is_empty() && !eff.user.is_empty())
                        .then(|| {
                            let what = format!("password for {}@{}", eff.user, eff.host);
                            (SecretKey::ssh_password(&eff), what)
                        })
                        .ok_or("Set the host and the user first."),
                ),
                FieldId::KeyPassphrase(i) => {
                    let path = key_paths(editor).get(i).map(|p| p.to_path_buf())?;
                    let what = format!("passphrase of {}", path.display());
                    Some(
                        fingerprint(&path)
                            .map(|key_fingerprint| {
                                (SecretKey::KeyPassphrase { key_fingerprint }, what)
                            })
                            .ok_or("That key file can't be read."),
                    )
                }
                _ => None,
            });
        match target {
            Some(Ok(found)) => Ok(found),
            Some(Err(why)) => Err(self.notify_store(why)),
            None => Err(Task::none()),
        }
    }

    fn notify_store(&mut self, detail: &str) -> Task<Message> {
        self.notify(Notification::new(Level::Warn, "Stored secret").detail(detail))
    }

    /// Set… / Clear on a secret row of editor `tab`.
    pub(super) fn secret_field(
        &mut self,
        tab: TabId,
        field: FieldId,
        value: &FieldValue,
    ) -> Task<Message> {
        let (key, what) = match self.secret_target(tab, field) {
            Ok(target) => target,
            Err(task) => return task,
        };
        match value {
            FieldValue::SetSecret => {
                self.open_secret_dialog(crate::secret_dialog::SecretDialog::new(tab, key, &what))
            }
            FieldValue::ClearSecret => self.store_delete(tab, key),
            _ => Task::none(),
        }
    }

    /// Result of a Set / Clear: say why it failed, then look the statuses up again.
    pub(super) fn store_done(&mut self, tab: TabId, result: Result<(), String>) -> Task<Message> {
        let note = match result {
            Ok(()) => Task::none(),
            Err(why) => self.notify_store(&format!("Could not change it: {why}")),
        };
        Task::batch([note, self.store_query(tab)])
    }
}

#[cfg(feature = "ssh")]
impl App {
    /// Looks up the password and every key's passphrase of editor `tab`.
    pub(crate) fn store_query(&self, tab: TabId) -> Task<Message> {
        let defaults = self.config.profile_defaults.ssh.clone();
        let Some(editor) = self
            .tabs
            .iter()
            .find(|t| t.id == tab)
            .and_then(|t| t.editor.as_deref())
        else {
            return Task::none();
        };
        let Some(eff) = editor.effective(&defaults) else {
            return Task::none();
        };
        let keys: Vec<PathBuf> = key_paths(editor)
            .into_iter()
            .map(Path::to_path_buf)
            .collect();
        let secrets = self.runtime.secrets().clone();
        Task::perform(
            async move {
                let mut wanted = vec![(None, SecretKey::ssh_password(&eff))];
                wanted.extend(keys.into_iter().filter_map(|path| {
                    let key_fingerprint = fingerprint(&path)?;
                    Some((Some(path), SecretKey::KeyPassphrase { key_fingerprint }))
                }));
                let mut out = Vec::new();
                let mut unavailable = None;
                for (path, key) in wanted {
                    let state = match &unavailable {
                        Some(why) => Stored::Unavailable(String::clone(why)),
                        None => match secrets.exists(&key).await {
                            Ok(true) => Stored::Yes,
                            Ok(false) => Stored::No,
                            Err(err) => {
                                unavailable = Some(err.to_string());
                                Stored::Unavailable(err.to_string())
                            }
                        },
                    };
                    out.push(StoredEntry { path, key, state });
                }
                out
            },
            move |entries| Message::Editor(tab, EditorMsg::Stored(entries)),
        )
    }

    pub(crate) fn store_set(
        &self,
        tab: TabId,
        key: SecretKey,
        value: SecretString,
    ) -> Task<Message> {
        let secrets = self.runtime.secrets().clone();
        Task::perform(
            async move { secrets.set(&key, value).await.map_err(|e| e.to_string()) },
            move |result| Message::Editor(tab, EditorMsg::StoreDone(result)),
        )
    }

    fn store_delete(&self, tab: TabId, key: SecretKey) -> Task<Message> {
        let secrets = self.runtime.secrets().clone();
        Task::perform(
            async move { secrets.delete(&key).await.map_err(|e| e.to_string()) },
            move |result| Message::Editor(tab, EditorMsg::StoreDone(result)),
        )
    }
}

/// Without SSH there are no stored secrets.
#[cfg(not(feature = "ssh"))]
impl App {
    pub(crate) fn store_query(&mut self, _: TabId) -> Task<Message> {
        Task::none()
    }

    pub(crate) fn store_set(&self, _: TabId, _: SecretKey, _: SecretString) -> Task<Message> {
        Task::none()
    }

    fn store_delete(&self, _: TabId, _: SecretKey) -> Task<Message> {
        Task::none()
    }
}

#[cfg(test)]
mod tests {
    use fogu_core::{Profile, SshOpts};

    use super::*;
    use crate::profile_editor::Source;

    fn entry(state: Stored) -> StoredEntry {
        StoredEntry {
            path: None,
            key: SecretKey::KeyPassphrase {
                key_fingerprint: "x".into(),
            },
            state,
        }
    }

    #[test]
    fn status_words() {
        assert_eq!(status(Some(&entry(Stored::Yes))), "stored");
        assert_eq!(status(Some(&entry(Stored::No))), "not stored");
        assert_eq!(
            status(Some(&entry(Stored::Unavailable("no bus".into())))),
            "unavailable: no bus"
        );
        assert_eq!(status(None), "not checked");
    }

    #[test]
    fn rows_follow_the_key_list_and_skip_empty_rows() {
        let ssh = SshOpts {
            private_keys: Some(vec!["/k/a".into(), PathBuf::new(), "/k/b".into()]),
            ..SshOpts::default()
        };
        let draft = Profile {
            kind: ProfileKind::Ssh(ssh),
            ..Profile::default_shell()
        };
        let ed = ProfileEditor::new(draft, Source::New);
        let paths: Vec<_> = key_paths(&ed).into_iter().map(Path::to_path_buf).collect();
        assert_eq!(paths, [PathBuf::from("/k/a"), PathBuf::from("/k/b")]);
    }
}
