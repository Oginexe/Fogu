//! Command-line flags.

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::Command;

use std::ffi::OsString;

/// Environment variable iced's renderer selection reads (`tiny-skia` = CPU rendering).
const BACKEND_ENV: &str = "ICED_BACKEND";

const HELP: &str = "\
Fogu: a native terminal emulator

Usage: fogu [OPTIONS]

Options:
      --config-dir <PATH>  Use this directory instead of the platform one for config.toml
      --software-render    Render on the CPU instead of the GPU; for broken drivers and VMs
      --no-recovery        Start with one new tab: don't restore or save the open tabs
  -h, --help               Print help
  -V, --version            Print version
";

/// Command-line flags.
#[derive(Debug, Default)]
pub struct Cli {
    /// `--config-dir PATH`: use this directory instead of the platform one for `config.toml`.
    pub config_dir: Option<PathBuf>,
    /// `--software-render`: render on the CPU (tiny-skia) instead of the GPU.
    pub software_render: bool,
    /// `--exit-after-first-frame` (hidden): exit after the first frame (`scripts/metrics.sh`).
    pub exit_after_first_frame: bool,
    /// `--no-recovery`: start with one new tab; don't restore or save the session.
    pub no_recovery: bool,
}

/// Why parsing stopped before a [`Cli`].
#[derive(Debug, PartialEq, Eq)]
enum Stop {
    Help,
    Version,
    Error(String),
}

impl Cli {
    /// The process arguments. `--help`, `--version` and errors print and exit (0, 0, 2).
    #[expect(clippy::print_stdout, reason = "--help and --version go to stdout")]
    pub fn parse() -> Self {
        match Self::parse_from(std::env::args_os().skip(1)) {
            Ok(cli) => cli,
            Err(Stop::Help) => {
                print!("{HELP}");
                std::process::exit(0)
            }
            Err(Stop::Version) => {
                println!("fogu {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0)
            }
            Err(Stop::Error(why)) => {
                eprintln!("error: {why}\n\nFor more information, try '--help'.");
                std::process::exit(2)
            }
        }
    }

    fn parse_from(args: impl IntoIterator<Item = OsString>) -> Result<Self, Stop> {
        let mut cli = Self::default();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let text = arg.to_string_lossy();
            match text.as_ref() {
                "-h" | "--help" => return Err(Stop::Help),
                "-V" | "--version" => return Err(Stop::Version),
                "--software-render" => cli.software_render = true,
                "--exit-after-first-frame" => cli.exit_after_first_frame = true,
                "--no-recovery" => cli.no_recovery = true,
                "--config-dir" => {
                    let path = args.next().ok_or_else(|| {
                        Stop::Error("a value is required for '--config-dir <PATH>'".to_owned())
                    })?;
                    cli.config_dir = Some(PathBuf::from(path));
                }
                // `--config-dir=PATH` goes through text; `--config-dir PATH` keeps any OS path.
                other => match other.strip_prefix("--config-dir=") {
                    Some(path) => cli.config_dir = Some(PathBuf::from(path)),
                    None => return Err(Stop::Error(format!("unexpected argument '{other}'"))),
                },
            }
        }
        Ok(cli)
    }
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

    fn parse(args: &[&str]) -> Result<Cli, Stop> {
        Cli::parse_from(args.iter().map(OsString::from))
    }

    #[test]
    fn flags_parse() {
        let cli = parse(&[
            "--config-dir",
            "/tmp/x",
            "--software-render",
            "--exit-after-first-frame",
            "--no-recovery",
        ])
        .unwrap();
        assert_eq!(cli.config_dir, Some(PathBuf::from("/tmp/x")));
        assert!(cli.software_render && cli.exit_after_first_frame && cli.no_recovery);
        let eq = parse(&["--config-dir=/tmp/y"]).unwrap();
        assert_eq!(eq.config_dir, Some(PathBuf::from("/tmp/y")));
        let none = parse(&[]).unwrap();
        assert!(none.config_dir.is_none() && !none.software_render && !none.no_recovery);
    }

    #[test]
    fn help_version_and_errors_stop() {
        assert_eq!(parse(&["--help"]).unwrap_err(), Stop::Help);
        assert_eq!(parse(&["-V"]).unwrap_err(), Stop::Version);
        assert!(matches!(parse(&["--bogus"]), Err(Stop::Error(_))));
        assert!(matches!(parse(&["--config-dir"]), Err(Stop::Error(_))));
    }
}
