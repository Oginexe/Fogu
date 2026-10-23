//! App wiring of the SFTP panel: toggling, panel input, engine events, file pickers, keys.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use fogu_core::{EffectiveProfile, ProfileKind, resolve};
use fogu_session::{SftpCmd, SftpEvent, SftpRequest};
use iced::Task;
use iced::widget::operation;
use tokio::sync::mpsc::Sender;

use super::breadcrumb::join;
use super::listing::{ClickMods, is_dir};
use super::panel::PATH_INPUT;
use super::transfers::{Direction, Origin};
use super::{
    PanelMsg, SftpMsg, SftpPanelState, download_cmd, download_dir, engine_options, transfer_label,
};
use crate::app::App;
use crate::message::Message;
use crate::notifications::{Level, Notification};
use crate::tab::{PaneId, Tab, TabId};

impl App {
    /// SFTP engine events and panel input.
    pub(crate) fn on_sftp(&mut self, message: SftpMsg) -> Task<Message> {
        match message {
            SftpMsg::Event(pane, event) => self.on_sftp_event(pane, *event),
            SftpMsg::Panel(tab, message) => {
                if message.is_command() {
                    self.menu = None;
                }
                self.on_panel(tab, message)
            }
        }
    }

    fn on_sftp_event(&mut self, pane: PaneId, event: SftpEvent) -> Task<Message> {
        let now = Instant::now();
        let Some((tab, panel, tx)) = self.panel_by_pane(pane) else {
            return Task::none();
        };
        let reaction = panel.on_event(event, &tx, now);
        let mut tasks: Vec<Task<Message>> = reaction
            .notes
            .into_iter()
            .map(|note| self.notify(note))
            .collect();
        if reaction.sweep {
            tasks.push(self.after(self.linger(), sweep(tab)));
        }
        if let Some(file) = reaction.open {
            tasks.push(self.open_local(file));
        }
        Task::batch(tasks)
    }

    /// The panel whose connection is pane `pane`, with its tab id and command sender.
    fn panel_by_pane(
        &mut self,
        pane: PaneId,
    ) -> Option<(TabId, &mut SftpPanelState, Sender<SftpRequest>)> {
        let tab = self
            .tabs
            .iter_mut()
            .find(|t| t.sftp.as_ref().is_some_and(|p| p.pane == pane))?;
        let tx = link(tab)?;
        let id = tab.id;
        Some((id, tab.sftp.as_mut()?, tx))
    }

    /// Tab `tab`'s panel and its command sender.
    pub(super) fn panel_of(
        &mut self,
        tab: TabId,
    ) -> Option<(&mut SftpPanelState, Sender<SftpRequest>)> {
        let tab = self.tabs.iter_mut().find(|t| t.id == tab)?;
        let tx = link(tab)?;
        Some((tab.sftp.as_mut()?, tx))
    }

    fn linger(&self) -> Duration {
        Duration::from_secs(self.config.sftp.transfer_linger_secs)
    }

    /// `ToggleSftp` / toolbar button: shows or hides the active tab's panel.
    pub(crate) fn toggle_sftp(&mut self) -> Task<Message> {
        let options = engine_options(&self.config.sftp);
        let cfg = self.config.sftp.clone();
        let defaults = self.config.profile_defaults.clone();
        let active = self.active;
        let Some(tab) = self.tabs.iter_mut().find(|t| t.id == active) else {
            return Task::none();
        };
        if tab.sftp.as_ref().is_some_and(|p| p.visible) {
            return self.close_panel(active);
        }
        // The panel's own pane if it still exists, else the focused SSH pane, else any.
        let pane = tab
            .sftp
            .as_ref()
            .map(|p| p.pane)
            .filter(|p| tab.panes.get(p).is_some_and(|p| p.sftp.is_some()))
            .or_else(|| {
                let focused = tab.focused_pane().filter(|p| p.sftp.is_some());
                focused
                    .or_else(|| tab.panes.values().find(|p| p.sftp.is_some()))
                    .map(|p| p.id)
            });
        let Some(pane) = pane else {
            let note = Notification::new(Level::Info, "SFTP")
                .detail("The SFTP panel is available in SSH tabs.");
            return self.notify(note);
        };
        let Some(pane_ref) = tab.panes.get(&pane) else {
            return Task::none();
        };
        let start = match (
            &pane_ref.profile.kind,
            resolve(&pane_ref.profile, &defaults),
        ) {
            (ProfileKind::Ssh(_), EffectiveProfile::Ssh(ssh)) => ssh.cwd,
            _ => None,
        };
        let Some(tx) = pane_ref.sftp.as_ref().map(|l| l.cmds.clone()) else {
            return Task::none();
        };
        let shell_cwd = pane_ref.remote_cwd.clone();
        let panel = tab
            .sftp
            .get_or_insert_with(|| SftpPanelState::new(pane, &cfg));
        if panel.pane != pane {
            panel.rebind(pane, Instant::now());
        }
        panel.shell_cwd = shell_cwd.filter(|p| p.starts_with('/'));
        let opened = match panel.open(&tx, options, start) {
            Ok(()) => Task::none(),
            Err(err) => self.notify(Notification::new(Level::Error, "SFTP").detail(err)),
        };
        Task::batch([opened, self.wayland_drop_hint()])
    }

    /// Hides tab `tab`'s panel; the engine closes its channel once no transfer runs.
    fn close_panel(&mut self, tab: TabId) -> Task<Message> {
        if let Some((panel, tx)) = self.panel_of(tab) {
            panel.visible = false;
            panel.focused = false;
            panel.editing = None;
            // Best effort: a full or closed channel just leaves the channel open a while.
            let _sent = panel.send(&tx, SftpCmd::Shutdown);
        }
        Task::none()
    }

    /// Input in tab `tab`'s panel.
    pub(super) fn on_panel(&mut self, tab: TabId, message: PanelMsg) -> Task<Message> {
        let mods = ClickMods {
            ctrl: self.modifiers.control(),
            shift: self.modifiers.shift(),
        };
        let default_width = self.config.sftp.panel_width;
        let Some((panel, tx)) = self.panel_of(tab) else {
            return Task::none();
        };
        let result = match message {
            PanelMsg::Close => return self.close_panel(tab),
            PanelMsg::Width(ratio) => {
                let ratio = ratio.unwrap_or(default_width);
                panel.width = ratio.clamp(super::MIN_WIDTH, super::MAX_WIDTH);
                Ok(())
            }
            PanelMsg::Hover(hovered) => {
                panel.hovered = hovered;
                Ok(())
            }
            PanelMsg::Go(path) => {
                panel.editing = None;
                panel.follow = false;
                panel.list(&tx, path, true)
            }
            PanelMsg::EditPath => {
                panel.focused = true;
                panel.editing = Some(panel.path.clone().unwrap_or_default());
                return Task::batch([
                    operation::focus(PATH_INPUT),
                    operation::select_all(PATH_INPUT),
                ]);
            }
            PanelMsg::PathInput(value) => {
                panel.editing = Some(value);
                Ok(())
            }
            PanelMsg::PathSubmit => match panel.editing.take() {
                Some(path) if !path.trim().is_empty() => {
                    panel.follow = false;
                    panel.resolve(&tx, Some(path.trim().to_owned()))
                }
                _ => Ok(()),
            },
            // Manual navigation stops following the terminal ("resume following" restarts).
            PanelMsg::Back => {
                panel.follow = false;
                panel.go_back(&tx)
            }
            PanelMsg::Up => {
                panel.follow = false;
                panel.go_up(&tx)
            }
            PanelMsg::Home => {
                panel.follow = false;
                panel.go_home(&tx)
            }
            PanelMsg::Refresh => match panel.path.clone() {
                Some(path) => panel.list(&tx, path, false),
                None => panel.resolve(&tx, None),
            },
            PanelMsg::ShowHidden(show) => {
                panel.listing.show_hidden = show;
                Ok(())
            }
            PanelMsg::Filter(filter) => {
                panel.focused = true;
                panel.listing.filter = filter;
                Ok(())
            }
            PanelMsg::Sort(key) => {
                panel.listing.sort_by(key);
                Ok(())
            }
            PanelMsg::Click(name) => {
                panel.focused = true;
                panel.listing.click(&name, mods);
                Ok(())
            }
            PanelMsg::Open(name) => return self.open_entry(tab, &name),
            PanelMsg::Scrolled(y, h) => {
                panel.scroll_y = y;
                panel.view_h = h;
                Ok(())
            }
            other => return self.on_panel_transfer(tab, other),
        };
        match result {
            Ok(()) => Task::none(),
            Err(err) => self.notify(Notification::new(Level::Error, "SFTP").detail(err)),
        }
    }

    /// Transfer and conflict input of tab `tab`'s panel.
    fn on_panel_transfer(&mut self, tab: TabId, message: PanelMsg) -> Task<Message> {
        let linger = self.linger();
        let Some((panel, tx)) = self.panel_of(tab) else {
            return Task::none();
        };
        let result = match message {
            PanelMsg::Upload if !super::desktop::picker_available() => {
                return self.notify(super::desktop::no_picker_note());
            }
            PanelMsg::Upload => return pick_upload(tab, panel.path.clone()),
            PanelMsg::Download => return self.pick_download(tab),
            PanelMsg::UploadPicked { remote_dir, local } => match local {
                Some(local) if !local.is_empty() => {
                    let cmd = SftpCmd::Upload {
                        local: local.clone(),
                        remote_dir: remote_dir.clone(),
                        overwrite: fogu_session::sftp::OverwritePolicy::Ask,
                        resume: false,
                    };
                    let label = transfer_label(&cmd);
                    let origin = Origin::Upload { local, remote_dir };
                    panel
                        .issue(&tx, cmd, Direction::Upload, label, origin)
                        .map(|_| ())
                }
                _ => Ok(()),
            },
            PanelMsg::DownloadPicked {
                remote_dir,
                remote,
                local_dir: Some(local_dir),
            } => {
                let cmd = download_cmd(remote, local_dir.clone());
                let label = transfer_label(&cmd);
                let origin = Origin::Download {
                    remote_dir,
                    local_dir,
                };
                panel
                    .issue(&tx, cmd, Direction::Download, label, origin)
                    .map(|_| ())
            }
            PanelMsg::Cancel(id) => panel.send(&tx, SftpCmd::Cancel(id)).map(|_| ()),
            PanelMsg::ClearTransfers => {
                panel.transfers.clear_finished(&panel.conflicts);
                Ok(())
            }
            PanelMsg::ToggleTransfers => {
                panel.transfers.collapsed = !panel.transfers.collapsed;
                Ok(())
            }
            PanelMsg::Sweep => {
                if panel
                    .transfers
                    .sweep(Instant::now(), linger, &panel.conflicts)
                {
                    return self.after(linger, sweep(tab));
                }
                Ok(())
            }
            PanelMsg::Conflict(choice) => {
                let notes = panel.answer_conflict(&tx, choice);
                let tasks: Vec<Task<Message>> = notes.into_iter().map(|n| self.notify(n)).collect();
                return Task::batch(tasks);
            }
            PanelMsg::ConflictApplyAll(all) => {
                panel.conflicts.apply_all = all;
                Ok(())
            }
            other => return self.on_panel_ops(tab, other),
        };
        match result {
            Ok(()) => Task::none(),
            Err(err) => self.notify(Notification::new(Level::Error, "SFTP").detail(err)),
        }
    }

    /// Double-click / Enter: a directory is entered (following stops), a file is downloaded
    /// to the download directory.
    fn open_entry(&mut self, tab: TabId, name: &str) -> Task<Message> {
        let Some((panel, tx)) = self.panel_of(tab) else {
            return Task::none();
        };
        let (Some(dir), Some(entry)) = (
            panel.path.clone(),
            panel.listing.entries.iter().find(|e| e.name == name),
        ) else {
            return Task::none();
        };
        if !is_dir(entry) {
            return self.download_entry(tab, name, false);
        }
        panel.follow = false;
        match panel.list(&tx, join(&dir, name), true) {
            Ok(()) => Task::none(),
            Err(err) => self.notify(Notification::new(Level::Error, "SFTP").detail(err)),
        }
    }

    /// `Download…`: the selection, then a folder picker.
    fn pick_download(&mut self, tab: TabId) -> Task<Message> {
        let start = download_dir(&self.config.sftp);
        let Some((panel, _)) = self.panel_of(tab) else {
            return Task::none();
        };
        let Some(remote_dir) = panel.path.clone() else {
            return Task::none();
        };
        let remote: Vec<String> = panel
            .listing
            .selected_entries()
            .iter()
            .map(|e| join(&remote_dir, &e.name))
            .collect();
        if remote.is_empty() {
            let note = Notification::new(Level::Info, "Download")
                .detail("Select one or more entries first.");
            return self.notify(note);
        }
        if !super::desktop::picker_available() {
            return self.notify(super::desktop::no_picker_note());
        }
        let mut dialog = rfd::AsyncFileDialog::new().set_title("Download to folder");
        if let Some(start) = start {
            dialog = dialog.set_directory(start);
        }
        Task::perform(dialog.pick_folder(), move |folder| {
            panel_msg(
                tab,
                PanelMsg::DownloadPicked {
                    remote_dir: remote_dir.clone(),
                    remote,
                    local_dir: folder.map(|f| f.path().to_path_buf()),
                },
            )
        })
    }

    /// Pane `old` was replaced by `new` (reconnect): the panel follows, its old work is gone.
    pub(crate) fn rebind_panel(&mut self, old: PaneId, new: PaneId) -> Task<Message> {
        let options = engine_options(&self.config.sftp);
        // The old pane is already gone from the tab, so find the panel by its stored pane.
        let Some(tab) = self
            .tabs
            .iter_mut()
            .find(|t| t.sftp.as_ref().is_some_and(|p| p.pane == old))
        else {
            return Task::none();
        };
        let Some(panel) = tab.sftp.as_mut() else {
            return Task::none();
        };
        panel.rebind(new, Instant::now());
        let (tab, visible) = (tab.id, panel.visible);
        let Some((panel, tx)) = self.panel_of(tab) else {
            return Task::none();
        };
        if !visible {
            return Task::none();
        }
        match panel.open(&tx, options, None) {
            Ok(()) => Task::none(),
            Err(err) => self.notify(Notification::new(Level::Error, "SFTP").detail(err)),
        }
    }
}

/// The command sender of the pane tab `tab`'s panel uses.
fn link(tab: &Tab) -> Option<Sender<SftpRequest>> {
    let pane = tab.sftp.as_ref()?.pane;
    tab.panes.get(&pane)?.sftp.as_ref().map(|l| l.cmds.clone())
}

fn panel_msg(tab: TabId, message: PanelMsg) -> Message {
    Message::Sftp(SftpMsg::Panel(tab, message))
}

fn sweep(tab: TabId) -> Message {
    panel_msg(tab, PanelMsg::Sweep)
}

/// `Upload…`: a multi-file picker; the answer targets the directory shown now.
fn pick_upload(tab: TabId, remote_dir: Option<String>) -> Task<Message> {
    let Some(remote_dir) = remote_dir else {
        return Task::none();
    };
    let dialog = rfd::AsyncFileDialog::new().set_title("Upload files");
    Task::perform(dialog.pick_files(), move |files| {
        let local: Option<Vec<PathBuf>> =
            files.map(|f| f.iter().map(|h| h.path().to_path_buf()).collect());
        panel_msg(tab, PanelMsg::UploadPicked { remote_dir, local })
    })
}
