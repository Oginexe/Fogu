//! The terminal pane, divider and tab-bar context menus, all built on `context_menu`.

use std::path::PathBuf;

use fogu_core::config::RightClickAction;
use fogu_core::{Action, Profile, ProfileKind};
use fogu_session::SessionInput;
use iced::{Point, Task};

use crate::app::App;
use crate::context_menu::{ContextMenu, MenuAction, MenuItem};
use crate::message::{Message, PasteSource};
use crate::notifications::{Level, Notification};
use crate::profiles::{Launch, ProfilesMsg};
use crate::tab::{Pane, PaneId, TabId};

/// Pane-menu toggles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyKind {
    /// "Notify when done".
    Done,
    /// "Notify on activity".
    Activity,
}

/// What a right-click on a pane does under `terminal.right_click`; Shift always opens the menu.
pub(crate) fn right_click(mode: RightClickAction, shift: bool, at: Point) -> Message {
    match mode {
        _ if shift => Message::PaneMenu(at),
        RightClickAction::Menu => Message::PaneMenu(at),
        RightClickAction::Paste => Message::Paste(PasteSource::Primary),
        RightClickAction::Clipboard => Message::Paste(PasteSource::Clipboard),
    }
}

fn run(label: &str, action: Action) -> MenuItem {
    MenuItem::new(label, MenuAction::Run(action))
}

fn ui(label: impl Into<String>, message: Message) -> MenuItem {
    MenuItem::new(label, MenuAction::Ui(message))
}

/// The terminal pane menu for `pane`. `links` are items for a link under the pointer
/// and go first.
pub(crate) fn pane_items(pane: &Pane, links: Vec<MenuItem>) -> Vec<MenuItem> {
    let has_selection = pane.term.selection_text().is_some();
    let local = !pane.is_ssh();
    let running = pane.state.is_running();
    let process = match &pane.foreground {
        Some(name) => format!("Current process: {name}"),
        None => "Current process: shell".to_owned(),
    };
    let mut items = links;
    let copy = run("Copy", Action::Copy).enabled_if(
        has_selection,
        "Select text first (Shift+drag in programs that use the mouse, such as Claude Code)",
    );
    let copy = if items.is_empty() {
        copy
    } else {
        copy.after_separator()
    };
    items.extend([
        copy,
        run("Paste", Action::Paste),
        run("Paste selection", Action::PastePrimary),
        run("Select all", Action::SelectAll),
        run("Find…", Action::Find),
        ui("Split ▸", Message::MenuSplit).after_separator(),
        run("Close pane", Action::ClosePane),
        run("Copy current path", Action::CopyPath).after_separator(),
        run("New tab here", Action::NewTabHere).enabled_if(local, "Local shells only"),
        run("New terminal", Action::NewTab),
        ui("New terminal with ▸", Message::MenuNewWith),
        ui(
            "Notify when done",
            Message::PaneNotify(pane.id, NotifyKind::Done),
        )
        .checked(pane.notify.done)
        .enabled_if(local && running, "Local running shells only")
        .after_separator(),
        ui(
            "Notify on activity",
            Message::PaneNotify(pane.id, NotifyKind::Activity),
        )
        .checked(pane.notify.activity),
        ui(process, Message::CloseMenu).disabled(if local {
            "The program in front of the shell"
        } else {
            "Not known for SSH sessions"
        }),
        ui("Save as profile…", Message::PaneSaveAsProfile(pane.id)).after_separator(),
        ui("Export to file…", Message::PaneExport(pane.id)),
        run("Clear", Action::Clear).after_separator(),
    ]);
    items.push(if pane.is_ssh() || !running {
        run(
            if pane.is_ssh() {
                "Reconnect"
            } else {
                "Restart"
            },
            Action::Reconnect,
        )
    } else {
        run("Restart", Action::RestartTab)
    });
    items
}

/// "Open link" / "Copy link" when the right-click was on a link.
fn link_items(pane: &Pane) -> Vec<MenuItem> {
    let Some(link) = &pane.link else {
        return Vec::new();
    };
    let openable =
        crate::open_link::resolve(link, !pane.is_ssh(), pane.local_cwd.as_deref()).is_ok();
    vec![
        ui("Open link", Message::OpenLink(pane.id, link.clone())).enabled_if(
            openable,
            "Not opened from here: a remote path or a blocked scheme",
        ),
        ui("Copy link", Message::CopyLink(link.uri.clone())),
    ]
}

/// The plain text of a pane's scrollback and screen (wrapped rows joined, one `\n` per line).
fn export_text(pane: &Pane, max_lines: usize) -> String {
    let saved = pane.term.capture_history(max_lines, 0);
    let mut out = String::new();
    for row in &saved.rows {
        for run in &row.runs {
            out.push_str(&run.text);
        }
        if !row.wrapped {
            out.push('\n');
        }
    }
    out
}

impl App {
    /// The pane and tab menu messages (dispatched from `App::update`).
    pub(crate) fn on_menu_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::PaneMenu(at) => self.open_pane_menu(at),
            Message::MenuSplit | Message::MenuNewWith => {
                self.open_submenu(&message);
                Task::none()
            }
            Message::PaneNotify(pane, kind) => {
                self.toggle_pane_notify(pane, kind);
                Task::none()
            }
            Message::PaneSaveAsProfile(pane) => self.save_pane_as_profile(pane),
            Message::PaneExport(pane) => self.export_pane(pane),
            Message::PaneExportTo(pane, path) => self.export_pane_to(pane, path),
            Message::DividerMenu(tab, at) => {
                self.open_divider_menu(tab, at);
                Task::none()
            }
            Message::TabBarMenu => {
                self.open_tab_bar_menu(self.tab_bar_cursor);
                Task::none()
            }
            Message::TabSaveToProfile => self.save_tab_to_profile(),
            Message::ConfirmDiscard(yes) => match self.pending_discard.take() {
                Some(tab) if yes => self.remove_tab(tab),
                _ => Task::none(),
            },
            _ => Task::none(),
        }
    }

    /// Right-click on the focused pane (it was focused by the same press).
    pub(crate) fn open_pane_menu(&mut self, at: Point) -> Task<Message> {
        let Some(pane) = self.active_pane() else {
            return Task::none();
        };
        // Refresh "Current process" for next time (the reply updates the open menu too).
        if !pane.is_ssh() && pane.state.is_running() {
            let _sent = pane.control(SessionInput::QueryCwd);
        }
        let (items, id) = (pane_items(pane, link_items(pane)), pane.id);
        self.menu = Some(ContextMenu::new(at, items));
        self.pane_menu = Some(id);
        Task::none()
    }

    /// A `Foreground` reply while the pane's menu is open: rebuild it in place.
    pub(crate) fn refresh_pane_menu(&mut self, pane_id: PaneId) {
        if self.pane_menu != Some(pane_id) {
            return;
        }
        let (Some(menu), Some(pane)) = (&self.menu, self.pane(pane_id)) else {
            return;
        };
        let mut fresh = ContextMenu::new(menu.anchor, pane_items(pane, link_items(pane)));
        fresh.selected = menu.selected;
        self.menu = Some(fresh);
    }

    /// "Split ▸" / "New terminal with ▸" / "New tab ▸": the menu turns into its sub-items.
    pub(crate) fn open_submenu(&mut self, message: &Message) {
        let Some(anchor) = self.menu.as_ref().map(|m| m.anchor) else {
            return;
        };
        let items = match message {
            Message::MenuSplit => vec![
                run("Split right", Action::SplitRight),
                run("Split down", Action::SplitDown),
            ],
            _ => self.profile_items(),
        };
        self.menu = Some(ContextMenu::new(anchor, items));
        self.pane_menu = None;
    }

    /// Every profile of the picker as "open in a new tab" items.
    fn profile_items(&self) -> Vec<MenuItem> {
        let recent = None;
        crate::profiles::entries(
            &self.config,
            &self.profiles.builtins,
            &self.profiles.ssh_hosts.profiles,
            recent,
        )
        .into_iter()
        .map(|e| {
            ui(
                e.profile.name.clone(),
                Message::Profiles(ProfilesMsg::RowOpen(e.profile.id.clone(), Launch::Tab)),
            )
        })
        .collect()
    }

    /// Right-click on a split divider of tab `tab`.
    pub(crate) fn open_divider_menu(&mut self, tab: TabId, at: Point) {
        self.menu = Some(ContextMenu::new(
            at,
            vec![
                ui("Equalize", Message::Equalize(tab)),
                run("Swap panes", Action::SwapPanes),
            ],
        ));
    }

    /// Right-click on the tab bar's empty area.
    pub(crate) fn open_tab_bar_menu(&mut self, at: Point) {
        let ssh = self
            .active_pane()
            .is_some_and(|p| p.is_ssh() && p.state.is_running());
        let mut items = vec![
            ui("New tab ▸", Message::MenuNewWith),
            run("Profiles sidebar", Action::ToggleProfiles),
        ];
        if ssh {
            items.push(run("SFTP panel", Action::ToggleSftp));
        }
        self.menu = Some(ContextMenu::new(at, items));
    }

    /// "Discard changes?" while an editor tab with unsaved changes waits to close.
    pub(crate) fn discard_modal(&self) -> Option<crate::modal::Modal> {
        self.pending_discard?;
        Some(crate::modal::Modal {
            title: "Discard changes?",
            body: "The profile has unsaved changes.".to_owned(),
            buttons: vec![
                crate::modal::ModalButton {
                    label: "Discard",
                    on_press: Message::ConfirmDiscard(true),
                },
                crate::modal::ModalButton {
                    label: "Keep editing",
                    on_press: Message::ConfirmDiscard(false),
                },
            ],
        })
    }

    /// The pane menu's notification toggles.
    pub(crate) fn toggle_pane_notify(&mut self, pane_id: PaneId, kind: NotifyKind) {
        self.menu = None;
        let Some(pane) = self.pane_mut(pane_id) else {
            return;
        };
        match kind {
            NotifyKind::Done => {
                pane.notify.done = !pane.notify.done;
                let _sent = pane.control(SessionInput::WatchForeground(pane.notify.done));
            }
            NotifyKind::Activity => pane.notify.activity = !pane.notify.activity,
        }
    }

    /// "Save as profile…": the pane's profile and current directory in a new editor draft.
    pub(crate) fn save_pane_as_profile(&mut self, pane_id: PaneId) -> Task<Message> {
        self.menu = None;
        let Some(pane) = self.pane(pane_id) else {
            return Task::none();
        };
        let mut draft: Profile = pane.profile.clone();
        match &mut draft.kind {
            ProfileKind::Local(local) => {
                if let Some(cwd) = &pane.local_cwd {
                    local.cwd = Some(cwd.clone());
                }
            }
            ProfileKind::Ssh(ssh) => {
                if let Some(cwd) = &pane.remote_cwd {
                    ssh.cwd = Some(cwd.clone());
                }
            }
        }
        draft.name = format!("{} (copy)", draft.name);
        self.new_profile_from(draft)
    }

    /// "Export to file…": asks where, then writes the pane's text.
    pub(crate) fn export_pane(&mut self, pane_id: PaneId) -> Task<Message> {
        self.menu = None;
        let dialog = rfd::AsyncFileDialog::new()
            .set_title("Export terminal text")
            .set_file_name("terminal.txt");
        Task::perform(dialog.save_file(), move |file| {
            Message::PaneExportTo(pane_id, file.map(|f| f.path().to_path_buf()))
        })
    }

    /// Writes the export (the save dialog already asked before replacing a file).
    pub(crate) fn export_pane_to(
        &mut self,
        pane_id: PaneId,
        path: Option<PathBuf>,
    ) -> Task<Message> {
        let (Some(path), Some(pane)) = (path, self.pane(pane_id)) else {
            return Task::none();
        };
        let lines = self
            .config
            .terminal
            .scrollback_lines
            .saturating_add(pane.size().rows.into());
        let text = export_text(pane, lines);
        let note = match fogu_core::fsutil::write_private_atomic(&path, text.as_bytes()) {
            Ok(()) => Notification::new(Level::Info, "Exported").detail(path.display().to_string()),
            Err(err) => Notification::new(Level::Error, "Export failed")
                .detail(format!("{}: {err}", path.display())),
        };
        self.notify(note)
    }
}

#[cfg(test)]
#[path = "pane_menu_tests.rs"]
mod tests;
