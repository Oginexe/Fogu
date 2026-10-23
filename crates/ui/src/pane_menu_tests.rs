use std::sync::Arc;

use fogu_core::config::RightClickAction;
use fogu_core::{Config, Profile, ProfileId, ProfileKind, SshOpts};
use fogu_session::SessionRuntime;
use iced::Point;

use super::*;
use crate::context_menu::ContextMenu;
use crate::metrics::{FontUnits, ResolvedFont};

fn app_with(profile: Option<Profile>) -> App {
    let runtime = Arc::new(SessionRuntime::new().unwrap());
    let resolved = ResolvedFont {
        font: iced::Font::MONOSPACE,
        units: FontUnits::FALLBACK,
    };
    let mut app = App::new(runtime, Arc::new(Config::default()), resolved);
    let profile = profile.unwrap_or_else(|| app.default_profile());
    app.open_tab(&profile, None);
    app
}

fn enabled(items: &[MenuItem], label: &str) -> bool {
    items.iter().find(|i| i.label == label).unwrap().enabled
}

#[test]
fn right_click_modes() {
    let at = Point::new(3.0, 4.0);
    let menu = |m| matches!(m, Message::PaneMenu(p) if p == at);
    assert!(menu(right_click(RightClickAction::Menu, false, at)));
    assert!(matches!(
        right_click(RightClickAction::Paste, false, at),
        Message::Paste(PasteSource::Primary)
    ));
    assert!(matches!(
        right_click(RightClickAction::Clipboard, false, at),
        Message::Paste(PasteSource::Clipboard)
    ));
    assert!(
        menu(right_click(RightClickAction::Paste, true, at)),
        "Shift opens the menu"
    );
    assert!(menu(right_click(RightClickAction::Clipboard, true, at)));
}

#[test]
fn copy_needs_a_selection_and_select_all_provides_one() {
    let mut app = app_with(None);
    app.active_pane_mut().unwrap().term.feed(b"hello\r\n");
    let items = pane_items(app.active_pane().unwrap(), Vec::new());
    assert!(!enabled(&items, "Copy"));
    assert!(enabled(&items, "New tab here"));
    assert!(items.iter().any(|i| i.label == "Current process: shell"));
    let _ = app.update(Message::Action(Action::SelectAll));
    let items = pane_items(app.active_pane().unwrap(), Vec::new());
    assert!(enabled(&items, "Copy"));
}

#[test]
fn ssh_panes_offer_reconnect_and_no_local_only_items() {
    let ssh = Profile {
        id: ProfileId("box".to_owned()),
        name: "Box".to_owned(),
        kind: ProfileKind::Ssh(SshOpts {
            host: Some("box.lan".to_owned()),
            ..SshOpts::default()
        }),
        ..Profile::default_shell()
    };
    let app = app_with(Some(ssh));
    let items = pane_items(app.active_pane().unwrap(), Vec::new());
    assert!(!enabled(&items, "New tab here"));
    assert!(!enabled(&items, "Notify when done"));
    assert!(items.iter().any(|i| i.label == "Reconnect"));
}

#[test]
fn notify_toggles_check_and_tab_save_needs_a_stored_profile() {
    let mut app = app_with(None);
    let id = app.active_pane().unwrap().id;
    let _ = app.update(Message::PaneNotify(id, NotifyKind::Activity));
    let items = pane_items(app.active_pane().unwrap(), Vec::new());
    let activity = items
        .iter()
        .find(|i| i.label == "Notify on activity")
        .unwrap();
    assert_eq!(activity.checked, Some(true));
    let save = |stored| {
        ContextMenu::tab(Point::ORIGIN, false, stored)
            .items
            .into_iter()
            .find(|i| i.label == "Save to profile")
            .unwrap()
            .enabled
    };
    assert!(save(true) && !save(false));
}

#[test]
fn close_others_and_to_the_right() {
    let mut app = app_with(None);
    let profile = app.default_profile();
    app.open_tab(&profile, None);
    app.open_tab(&profile, None);
    let (first, second) = (app.tabs[0].id, app.tabs[1].id);
    app.activate(second);
    let _ = app.update(Message::Action(Action::CloseTabsRight));
    let ids: Vec<_> = app.tabs.iter().map(|t| t.id).collect();
    assert_eq!(ids, [first, second], "only the third tab closes");
    let _ = app.update(Message::Action(Action::CloseOtherTabs));
    let ids: Vec<_> = app.tabs.iter().map(|t| t.id).collect();
    assert_eq!(ids, [second]);
}

#[test]
fn a_right_click_on_a_link_puts_open_and_copy_first() {
    use fogu_term::links::{Link, LinkKind};
    let mut app = app_with(None);
    let id = app.active_pane().unwrap().id;
    let link = |uri: &str, kind| Link {
        uri: uri.to_owned(),
        kind,
        row: 0,
        start: 0,
        end: 4,
    };
    let _ = app.update(Message::LinkHover(
        id,
        Some(link("https://a.io", LinkKind::Url)),
    ));
    let items = pane_items(
        app.active_pane().unwrap(),
        link_items(app.active_pane().unwrap()),
    );
    assert_eq!(items[0].label, "Open link");
    assert_eq!(items[1].label, "Copy link");
    assert!(enabled(&items, "Open link"));
    // A blocked scheme can still be copied, not opened.
    let _ = app.update(Message::LinkHover(
        id,
        Some(link("javascript:x", LinkKind::Hyperlink)),
    ));
    let items = pane_items(
        app.active_pane().unwrap(),
        link_items(app.active_pane().unwrap()),
    );
    assert!(!enabled(&items, "Open link") && enabled(&items, "Copy link"));
    // No link: the usual menu.
    let _ = app.update(Message::LinkHover(id, None));
    let items = pane_items(
        app.active_pane().unwrap(),
        link_items(app.active_pane().unwrap()),
    );
    assert_eq!(items[0].label, "Copy");
}
