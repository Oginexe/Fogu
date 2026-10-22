//! Reducer tests for the SSH UI: prompt dialogs, host-key decisions, close confirmation,
//! reconnect, warnings and the profile picker, on a headless `App` with stub sessions.
#![expect(clippy::unwrap_used, clippy::panic, reason = "tests")]

use std::sync::Arc;

use fogu_core::{Action, Config, Profile, ProfileId, ProfileKind, SshOpts};
use fogu_session::{
    ExitInfo, KbdPrompt, PromptId, PromptKind, PromptReply, Remember, SessionInput, SessionOutput,
    SessionRuntime, SessionWarning,
};
use secrecy::ExposeSecret;

use super::{Choice, PromptMsg, PromptState, PromptText};
use crate::app::App;
use crate::message::Message;
use crate::metrics::{FontUnits, ResolvedFont};
use crate::profile_picker::PickerMsg;
use crate::tab::PaneId;

fn ssh_profile(warn_on_close: Option<bool>) -> Profile {
    Profile {
        id: ProfileId("box".to_owned()),
        name: "Box".to_owned(),
        kind: ProfileKind::Ssh(SshOpts {
            host: Some("box.lan".to_owned()),
            user: Some("alice".to_owned()),
            warn_on_close,
            ..SshOpts::default()
        }),
        ..Profile::default_shell()
    }
}

/// A headless app whose only tab is an SSH pane (stub session 0).
fn ssh_app(warn_on_close: Option<bool>) -> App {
    let runtime = Arc::new(SessionRuntime::new().unwrap());
    let resolved = ResolvedFont {
        font: iced::Font::MONOSPACE,
        units: FontUnits::FALLBACK,
    };
    let config = Config {
        profiles: vec![ssh_profile(warn_on_close)],
        ..Config::default()
    };
    let mut app = App::new(runtime, Arc::new(config), resolved);
    app.open_tab(&ssh_profile(warn_on_close), None);
    app
}

fn send(app: &mut App, message: Message) {
    let _task = app.update(message);
}

fn pane(app: &App) -> PaneId {
    app.active_pane().unwrap().id
}

fn ask(app: &mut App, id: u64, kind: PromptKind) {
    let pane = pane(app);
    send(
        app,
        Message::Session(pane, SessionOutput::Prompt(PromptId(id), kind, None)),
    );
}

/// Sends a prompt message built for the front pane.
fn act(app: &mut App, message: impl FnOnce(PaneId) -> PromptMsg) {
    let message = Message::Prompt(message(pane(app)));
    send(app, message);
}

/// What the UI sent to stub session `n`.
fn sent(app: &mut App, n: usize) -> Vec<SessionInput> {
    let rx = &mut app.stub_inputs[n];
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

/// The single prompt reply sent to stub session 0.
fn reply(app: &mut App) -> (PromptId, PromptReply) {
    let mut replies: Vec<_> = sent(app, 0)
        .into_iter()
        .filter_map(|input| match input {
            SessionInput::PromptReply(id, reply) => Some((id, reply)),
            _ => None,
        })
        .collect();
    assert_eq!(replies.len(), 1, "exactly one reply");
    replies.pop().unwrap()
}

fn changed_key() -> PromptKind {
    PromptKind::HostKeyChanged {
        host: "box.lan".into(),
        port: 22,
        key_type: "ssh-ed25519".into(),
        fingerprint: "SHA256:new".into(),
        old_fingerprint: "SHA256:old".into(),
        known_hosts_path: "/home/a/.config/fogu/known_hosts".into(),
        line: 3,
    }
}

fn unknown_key() -> PromptKind {
    PromptKind::HostKeyUnknown {
        host: "box.lan".into(),
        port: 22,
        key_type: "ssh-ed25519".into(),
        fingerprint: "SHA256:abc".into(),
    }
}

#[test]
fn password_submit_moves_the_buffer_into_the_reply() {
    let mut app = ssh_app(None);
    let password = PromptKind::Password {
        user: "alice".into(),
        host: "box.lan".into(),
        remember: Remember::Available,
    };
    ask(&mut app, 7, password);
    assert_eq!(
        app.active_pane().unwrap().prompt.as_ref().unwrap().fields(),
        1
    );
    let typed = |text: &str| PromptText::new(text.to_owned());
    act(&mut app, |p| PromptMsg::Input(p, 0, typed("hunter")));
    act(&mut app, |p| PromptMsg::Input(p, 0, typed("hunter2")));
    act(&mut app, PromptMsg::Submit);
    let (id, reply) = reply(&mut app);
    assert_eq!(id, PromptId(7));
    let PromptReply::Secret { value, remember } = reply else {
        panic!("expected a secret, got {reply:?}");
    };
    assert_eq!(value.expose_secret(), "hunter2");
    assert!(!remember, "Remember starts unticked");
    assert!(app.active_pane().unwrap().prompt.is_none(), "dialog closed");
}

#[test]
fn taking_the_answers_leaves_zero_buffers() {
    let kind = PromptKind::KeyboardInteractive {
        name: String::new(),
        instructions: String::new(),
        prompts: vec![
            KbdPrompt {
                text: "Code:".into(),
                echo: true,
            },
            KbdPrompt {
                text: "Password:".into(),
                echo: false,
            },
        ],
    };
    let mut state = PromptState::new(PromptId(1), kind, None);
    assert_eq!(state.fields(), 2);
    let Some(PromptReply::Secrets(answers)) = state.take_answers() else {
        panic!("expected secrets");
    };
    assert_eq!(answers.len(), 2);
    assert_eq!(state.fields(), 0, "no buffer left behind");
}

#[test]
fn keyboard_interactive_enter_walks_the_fields_then_submits() {
    let mut app = ssh_app(None);
    let kind = PromptKind::KeyboardInteractive {
        name: "otp".into(),
        instructions: "Two answers".into(),
        prompts: vec![
            KbdPrompt {
                text: "Code:".into(),
                echo: true,
            },
            KbdPrompt {
                text: "Password:".into(),
                echo: false,
            },
        ],
    };
    ask(&mut app, 1, kind);
    let typed = |text: &str| PromptText::new(text.to_owned());
    act(&mut app, |p| PromptMsg::Input(p, 0, typed("123456")));
    act(&mut app, |p| PromptMsg::FieldEnter(p, 0));
    assert!(
        sent(&mut app, 0).is_empty(),
        "Enter in the first field only moves on"
    );
    act(&mut app, |p| PromptMsg::Input(p, 1, typed("pw")));
    act(&mut app, |p| PromptMsg::FieldEnter(p, 1));
    let (_, reply) = reply(&mut app);
    let PromptReply::Secrets(answers) = reply else {
        panic!("expected secrets");
    };
    let answers: Vec<&str> = answers.iter().map(ExposeSecret::expose_secret).collect();
    assert_eq!(answers, ["123456", "pw"]);
}

#[test]
fn changed_key_cannot_be_accepted_with_enter_or_one_click() {
    let mut app = ssh_app(None);
    ask(&mut app, 2, changed_key());
    // Plain accept buttons and a lone second-step click do nothing.
    for choice in [Choice::AcceptOnce, Choice::AcceptAndSave, Choice::Replace] {
        act(&mut app, |p| PromptMsg::Choose(p, choice));
    }
    assert!(sent(&mut app, 0).is_empty());
    assert!(app.active_pane().unwrap().prompt.is_some());
    // Enter is Cancel.
    send(&mut app, Message::Enter);
    let (id, reply) = reply(&mut app);
    assert_eq!(id, PromptId(2));
    assert!(matches!(reply, PromptReply::Reject), "{reply:?}");
}

#[test]
fn changed_key_replace_needs_the_second_click() {
    let mut app = ssh_app(None);
    ask(&mut app, 3, changed_key());
    act(&mut app, |p| PromptMsg::Choose(p, Choice::ArmReplace));
    assert!(sent(&mut app, 0).is_empty(), "first click only asks again");
    send(&mut app, Message::Enter);
    assert!(
        matches!(reply(&mut app).1, PromptReply::Reject),
        "Enter still cancels"
    );

    ask(&mut app, 4, changed_key());
    act(&mut app, |p| PromptMsg::Choose(p, Choice::ArmReplace));
    act(&mut app, |p| PromptMsg::Choose(p, Choice::Replace));
    assert!(matches!(reply(&mut app).1, PromptReply::AcceptAndSave));
}

#[test]
fn unknown_key_buttons_and_keys() {
    let mut app = ssh_app(None);
    ask(&mut app, 5, unknown_key());
    send(&mut app, Message::Enter);
    assert!(sent(&mut app, 0).is_empty(), "Enter does not trust a key");
    act(&mut app, |p| PromptMsg::Choose(p, Choice::AcceptOnce));
    assert!(matches!(reply(&mut app).1, PromptReply::Accept));

    ask(&mut app, 6, unknown_key());
    act(&mut app, |p| PromptMsg::Choose(p, Choice::AcceptAndSave));
    assert!(matches!(reply(&mut app).1, PromptReply::AcceptAndSave));

    ask(&mut app, 7, unknown_key());
    send(&mut app, Message::Escape);
    assert!(matches!(reply(&mut app).1, PromptReply::Reject));
}

#[test]
fn a_new_prompt_declines_the_stale_one_and_an_exit_drops_it() {
    let mut app = ssh_app(None);
    ask(&mut app, 1, unknown_key());
    ask(&mut app, 2, unknown_key());
    let (id, reply) = reply(&mut app);
    assert_eq!(id, PromptId(1));
    assert!(matches!(reply, PromptReply::Reject));
    let exit = SessionOutput::Exited(ExitInfo {
        code: Some(255),
        signal: None,
    });
    let p = pane(&app);
    send(&mut app, Message::Session(p, exit));
    assert!(app.pane(p).unwrap().prompt.is_none());
}

#[test]
fn typed_secrets_never_show_in_message_debug() {
    let message = Message::Prompt(PromptMsg::Input(
        PaneId(1),
        0,
        PromptText::new("hunter2".to_owned()),
    ));
    let debug = format!("{message:?}");
    assert!(!debug.contains("hunter2"), "{debug}");
    let mut app = ssh_app(None);
    let kind = PromptKind::Password {
        user: "alice".into(),
        host: "box.lan".into(),
        remember: Remember::Available,
    };
    ask(&mut app, 1, kind);
    let typed = PromptText::new("hunter2".to_owned());
    act(&mut app, |p| PromptMsg::Input(p, 0, typed));
    let debug = format!("{:?}", app.active_pane().unwrap().prompt);
    assert!(!debug.contains("hunter2"), "{debug}");
}

#[test]
fn ssh_tab_is_titled_user_at_host_and_reconnects_fresh() {
    let mut app = ssh_app(None);
    // With "keep the profile name" off (it is on by default).
    let id = pane(&app);
    app.pane_mut(id).unwrap().profile.disable_dynamic_title = false;
    assert_eq!(app.title(), "alice@box.lan");
    let old = pane(&app);
    let exit = SessionOutput::Exited(ExitInfo {
        code: Some(0),
        signal: None,
    });
    // Default policy closes a clean exit; a dropped connection (non-zero) stays.
    let lost = SessionOutput::Exited(ExitInfo {
        code: Some(255),
        signal: None,
    });
    send(&mut app, Message::Session(old, lost));
    let status = app.pane(old).unwrap().status.clone().unwrap();
    assert!(
        status.starts_with("[Disconnected (exit code 255)]"),
        "{status}"
    );
    send(&mut app, Message::Action(Action::Reconnect));
    let new = pane(&app);
    assert_ne!(new, old, "a new session in a new pane");
    assert!(app.active_pane().unwrap().state.is_running());
    send(&mut app, Message::Session(new, exit));
    assert!(
        app.tabs.is_empty(),
        "clean exit closes under the default policy"
    );
}

#[test]
fn closing_a_live_ssh_tab_asks_first() {
    let mut app = ssh_app(None);
    send(&mut app, Message::Action(Action::CloseTab));
    assert!(app.pending_close.is_some());
    assert!(sent(&mut app, 0).is_empty(), "nothing closed yet");
    send(&mut app, Message::ConfirmClose(false));
    assert!(app.pending_close.is_none());
    assert!(sent(&mut app, 0).is_empty());
    send(&mut app, Message::Action(Action::CloseTab));
    send(&mut app, Message::ConfirmClose(true));
    assert!(matches!(sent(&mut app, 0)[..], [SessionInput::Close]));

    let mut quiet = ssh_app(Some(false));
    send(&mut quiet, Message::Action(Action::CloseTab));
    assert!(quiet.pending_close.is_none());
    assert!(matches!(sent(&mut quiet, 0)[..], [SessionInput::Close]));
}

#[test]
fn warnings_are_kept_once_per_pane_for_the_badge() {
    let mut app = ssh_app(None);
    let p = pane(&app);
    for _ in 0..2 {
        let warning = SessionOutput::Warning(SessionWarning::HostKeyNotVerified);
        send(&mut app, Message::Session(p, warning));
    }
    assert_eq!(app.tabs[0].warnings().count(), 1);
}

#[test]
fn picker_opens_the_filtered_profile_in_a_tab_or_a_split() {
    let mut app = ssh_app(Some(false));
    send(&mut app, Message::Action(Action::OpenProfilePicker));
    assert!(app.picker.is_some());
    send(
        &mut app,
        Message::Picker(PickerMsg::Filter("default".into())),
    );
    send(&mut app, Message::Picker(PickerMsg::Submit));
    assert!(app.picker.is_none());
    assert_eq!(app.tabs.len(), 2);
    assert_eq!(app.title(), "Default shell");

    send(&mut app, Message::Action(Action::OpenProfilePicker));
    // Entry 1 = the SSH profile, next to the focused (local) pane.
    send(
        &mut app,
        Message::Picker(PickerMsg::Open {
            index: 1,
            split: true,
        }),
    );
    assert_eq!(app.tabs.len(), 2);
    assert_eq!(app.active_tab().unwrap().panes.len(), 2);
    assert!(app.active_pane().unwrap().is_ssh());

    send(&mut app, Message::Action(Action::OpenProfilePicker));
    send(&mut app, Message::Escape);
    assert!(app.picker.is_none(), "Escape closes the picker");
}

fn password_prompt(remember: Remember) -> PromptKind {
    PromptKind::Password {
        user: "alice".into(),
        host: "box.lan".into(),
        remember,
    }
}

fn typed_reply(app: &mut App, remember: Remember, tick: Option<bool>) -> PromptReply {
    ask(app, 3, password_prompt(remember));
    let text = PromptText::new("hunter2".to_owned());
    act(app, |p| PromptMsg::Input(p, 0, text));
    if let Some(on) = tick {
        act(app, |p| PromptMsg::Remember(p, on));
    }
    act(app, PromptMsg::Submit);
    reply(app).1
}

#[test]
fn remember_is_sent_only_when_ticked_and_the_store_takes_it() {
    let mut app = ssh_app(None);
    let reply = typed_reply(&mut app, Remember::Available, Some(true));
    assert!(matches!(reply, PromptReply::Secret { remember: true, .. }));
    // A store that is unavailable never gets "remember", whatever the checkbox said.
    let unavailable = Remember::Unavailable("no keyring".into());
    let reply = typed_reply(&mut app, unavailable, Some(true));
    assert!(matches!(
        reply,
        PromptReply::Secret {
            remember: false,
            ..
        }
    ));
    // A rejected stored password starts as "replace it".
    let reply = typed_reply(&mut app, Remember::Rejected, None);
    assert!(matches!(reply, PromptReply::Secret { remember: true, .. }));
}

#[test]
fn forget_is_offered_only_for_a_rejected_stored_secret() {
    let mut app = ssh_app(None);
    ask(&mut app, 4, password_prompt(Remember::Available));
    act(&mut app, |p| PromptMsg::Choose(p, Choice::Forget));
    assert!(app.active_pane().unwrap().prompt.is_some(), "ignored");
    let mut app = ssh_app(None);
    ask(&mut app, 5, password_prompt(Remember::Rejected));
    act(&mut app, |p| PromptMsg::Choose(p, Choice::Forget));
    let (id, reply) = reply(&mut app);
    assert_eq!(id, PromptId(5));
    assert!(matches!(reply, PromptReply::Forget), "{reply:?}");
}
