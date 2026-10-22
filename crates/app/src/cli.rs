//! Command-line flags.

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::Command;

use clap::Parser;

/// Environment variable iced's renderer selection reads (`tiny-skia` = CPU rendering).
const BACKEND_ENV: &str = "ICED_BACKEND";

/// Fogu: a native terminal emulator.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    /// Use this directory instead of `$XDG_CONFIG_HOME/fogu` for `config.toml`.
    #[arg(long, value_name = "PATH")]
    pub config_dir: Option<PathBuf>,
    /// Render on the CPU (tiny-skia) instead of the GPU; for broken drivers and VMs.
    #[arg(long)]
    pub software_render: bool,
    /// Exit right after the first presented frame (used by the benchmarks).
    #[arg(long, hide = true)]
    pub exit_after_first_frame: bool,
    /// Start with one new tab: don't restore the saved tabs and don't save this session.
    #[arg(long)]
    pub no_recovery: bool,
}

/// `--software-render` must reach iced as `ICED_BACKEND=tiny-skia` before it starts. Setting an
/// environment variable in-process is `unsafe` (and the workspace forbids `unsafe`), so the
/// process re-executes itself once with the variable set. Returns only if no re-exec was needed
/// (or it failed, which is logged and ignored: the GPU renderer then runs as usual).
pub fn reexec_for_software_render(cli: &Cli) {
    if !cli.software_render || std::env::var_os(BACKEND_ENV).is_some_and(|v| v == "tiny-skia") {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        eprintln!("fogu: --software-render: cannot find own executable; using the GPU");
        return;
    };
    let mut command = Command::new(exe);
    command
        .args(std::env::args_os().skip(1))
        .env(BACKEND_ENV, "tiny-skia");
    #[cfg(unix)]
    {
        let err = command.exec();
        eprintln!("fogu: --software-render: re-exec failed ({err}); using the GPU");
    }
    #[cfg(windows)]
    {
        // Windows has no `exec`: start the child (which sees the environment variable and
        // skips this branch), wait for it and relay its exit code.
        match command.spawn() {
            Ok(mut child) => match child.wait() {
                Ok(status) => std::process::exit(status.code().unwrap_or(1)),
                Err(err) => {
                    eprintln!(
                        "fogu: --software-render: cannot wait for the re-exec ({err}); using the GPU"
                    );
                }
            },
            Err(err) => {
                eprintln!("fogu: --software-render: re-exec failed ({err}); using the GPU");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests")]

    use super::*;

    #[test]
    fn flags_parse() {
        let cli = Cli::try_parse_from([
            "fogu",
            "--config-dir",
            "/tmp/x",
            "--software-render",
            "--exit-after-first-frame",
        ])
        .unwrap();
        assert_eq!(cli.config_dir, Some(PathBuf::from("/tmp/x")));
        assert!(cli.software_render && cli.exit_after_first_frame);
        let none = Cli::try_parse_from(["fogu"]).unwrap();
        assert!(none.config_dir.is_none() && !none.software_render);
    }

    #[test]
    fn unknown_flags_are_rejected() {
        assert!(Cli::try_parse_from(["fogu", "--bogus"]).is_err());
    }
}
