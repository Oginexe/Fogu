//! Panic hook + crash log: a panic is logged through tracing and appended to
//! `$XDG_STATE_HOME/fogu/crash.log` (mode 0600) as location + message. No backtrace, no session
//! data. Session panics are contained by `supervise()`; a panic on the UI thread still ends the
//! process.

use std::panic::PanicHookInfo;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fogu_core::fsutil;

/// Longest panic message kept, in characters.
const MAX_MESSAGE_CHARS: usize = 300;

/// One crash-log line: `<unix seconds> <thread> <file:line:col> <message>`.
pub fn format_entry(
    unix_secs: u64,
    thread: &str,
    location: Option<(&str, u32, u32)>,
    message: &str,
) -> String {
    let location = location.map_or_else(
        || "<unknown>".to_owned(),
        |(file, line, col)| format!("{file}:{line}:{col}"),
    );
    let message: String = message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_MESSAGE_CHARS)
        .collect();
    format!("{unix_secs} [{thread}] {location} {message}\n")
}

/// Appends `entry` to `dir/crash.log`, creating it `0600`.
pub fn append_entry(dir: &Path, entry: &str) -> std::io::Result<()> {
    fsutil::append_private(&dir.join("crash.log"), entry.as_bytes())
}

fn message_of(info: &PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<non-string panic payload>".to_owned())
}

/// Installs the hook. `state_dir` is where `crash.log` goes (`None`: tracing only).
pub fn install(state_dir: Option<PathBuf>) {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let location = info.location().map(|l| (l.file(), l.line(), l.column()));
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let entry = format_entry(
            secs,
            thread.name().unwrap_or("<unnamed>"),
            location,
            &message_of(info),
        );
        tracing::error!(target: "fogu::panic", "{}", entry.trim_end());
        if let Some(dir) = &state_dir
            && let Err(err) = append_entry(dir, &entry)
        {
            tracing::error!(error = %err, "could not write crash.log");
        }
        default_hook(info);
    }));
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn entry_has_location_and_a_sanitized_capped_message() {
        let entry = format_entry(42, "main", Some(("src/a.rs", 7, 3)), "bad\x1b[31m\nthing");
        assert_eq!(entry, "42 [main] src/a.rs:7:3 bad [31m thing\n");
        let long = format_entry(1, "t", None, &"x".repeat(1000));
        assert!(long.contains("<unknown>"));
        assert!(long.trim_end().ends_with(&"x".repeat(MAX_MESSAGE_CHARS)));
        assert_eq!(long.matches('\n').count(), 1);
    }

    #[test]
    fn crash_log_is_created_0600_and_appended() {
        let dir = std::env::temp_dir().join(format!("fogu-crash-{}", std::process::id()));
        fsutil::create_private_dir(&dir).unwrap();
        append_entry(&dir, "one\n").unwrap();
        append_entry(&dir, "two\n").unwrap();
        let log = dir.join("crash.log");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "one\ntwo\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
