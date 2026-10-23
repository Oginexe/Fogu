use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::PathBuf;

use super::super::{NAME_MAX, file_mode, part_name};
use super::*;

struct Tmp(PathBuf);

impl Tmp {
    fn new(label: &str) -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fogu-localfs-{label}-{}-{n}", std::process::id()));
        let _stale = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _best_effort = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn part_names_respect_name_max() {
    assert_eq!(part_name("a").as_deref(), Some("a.part"));
    assert_eq!(
        part_name(&"a".repeat(NAME_MAX - 5)).map(|p| p.len()),
        Some(NAME_MAX)
    );
    assert_eq!(part_name(&"a".repeat(NAME_MAX - 4)), None);
}

#[test]
fn download_modes_never_carry_special_bits() {
    // Default: never executable, whatever the server says.
    for mode in [None, Some(0o600), Some(0o4755), Some(0o7001), Some(0o6644)] {
        assert_eq!(file_mode(mode, false).as_raw_mode(), 0o644, "{mode:?}");
    }
    // `keep_executable_bit`: x kept, special bits still dropped.
    assert_eq!(file_mode(None, true).as_raw_mode(), 0o644);
    assert_eq!(file_mode(Some(0o600), true).as_raw_mode(), 0o644);
    assert_eq!(file_mode(Some(0o4755), true).as_raw_mode(), 0o755);
    assert_eq!(file_mode(Some(0o7001), true).as_raw_mode(), 0o755);
    assert_eq!(file_mode(Some(0o6644), true).as_raw_mode(), 0o644);
}

#[test]
fn a_planted_symlink_is_never_written_through() {
    let tmp = Tmp::new("symlink");
    let dest = tmp.0.join("dest");
    std::fs::create_dir(&dest).unwrap();
    let outside = tmp.0.join("outside.txt");
    std::fs::write(&outside, "precious").unwrap();
    symlink(&outside, dest.join("report.txt")).unwrap();
    let dir = LocalDir::open(&dest).unwrap();
    let fd = dir.open_dir(&[]).unwrap();
    for truncate in [false, true] {
        let err = create_file(&fd, "report.txt", file_mode(None, false), truncate).unwrap_err();
        assert!(err.raw_os_error().is_some(), "{err}");
    }
    assert!(open_for_resume(&fd, "report.txt").is_err());
    assert_eq!(existing(&fd, "report.txt").unwrap(), Existing::Other);
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "precious");
}

#[test]
fn symlinked_directories_are_never_traversed_or_merged() {
    let tmp = Tmp::new("dirlink");
    let dest = tmp.0.join("dest");
    let outside = tmp.0.join("outside");
    std::fs::create_dir(&dest).unwrap();
    std::fs::create_dir(&outside).unwrap();
    symlink(&outside, dest.join("sub")).unwrap();
    let dir = LocalDir::open(&dest).unwrap();
    assert!(dir.open_dir(&["sub".into()]).is_err());
    assert!(dir.make_dir(&["sub".into()]).is_err());
    assert!(dir.make_dir(&["real".into()]).unwrap());
    assert!(!dir.make_dir(&["real".into()]).unwrap());
    assert!(dir.make_dir(&["real".into(), "deeper".into()]).unwrap());
    assert!(dest.join("real/deeper").is_dir());
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn create_is_exclusive_and_finish_never_replaces_unless_asked() {
    let tmp = Tmp::new("finish");
    let dir = LocalDir::open(&tmp.0).unwrap();
    let fd = dir.open_dir(&[]).unwrap();
    let mut part = create_file(&fd, "a.part", file_mode(Some(0o755), true), false).unwrap();
    part.write_all(b"new").unwrap();
    assert!(create_file(&fd, "a.part", file_mode(None, false), false).is_err());
    let mode = std::fs::metadata(tmp.0.join("a.part"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o7000, 0);
    std::fs::write(tmp.0.join("a"), "old").unwrap();
    let err = finish(&fd, "a.part", "a", false).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read_to_string(tmp.0.join("a")).unwrap(), "old");
    finish(&fd, "a.part", "a", true).unwrap();
    assert_eq!(std::fs::read_to_string(tmp.0.join("a")).unwrap(), "new");
    assert!(!tmp.0.join("a.part").exists());
    let (_, len) = {
        create_file(&fd, "b.part", file_mode(None, false), false)
            .unwrap()
            .write_all(b"12345")
            .unwrap();
        open_for_resume(&fd, "b.part").unwrap()
    };
    assert_eq!(len, 5);
    remove(&fd, "b.part").unwrap();
    assert!(!tmp.0.join("b.part").exists());
}
