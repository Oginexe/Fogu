#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;

use russh::keys::parse_public_key_base64;

use super::*;

const KEY_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
const KEY_B: &str = "AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF";

fn key(b64: &str) -> PublicKey {
    parse_public_key_base64(b64).unwrap()
}

/// A fresh temp dir per test.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fogu-hk-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn fingerprint_is_openssh_sha256_without_padding() {
    assert_eq!(
        fingerprint(&key(KEY_A)),
        "SHA256:T7SvZ2cslqpPj6nKzitCBHHlpVF3r3MvLwmFL0fk0IE"
    );
    assert_eq!(
        fingerprint(&key(KEY_B)),
        "SHA256:ogco5uzOZUBEcxTLMd4p6GnpvFvExJOxW6ui4kpIK0Q"
    );
}

#[test]
fn lookup_table() {
    let dir = temp_dir("lookup");
    let text = format!(
        "# comment\n\
         \n\
         garbage line\n\
         [localhost]:2222 ssh-ed25519 {KEY_A}\n\
         alpha.example,10.0.0.1  ssh-ed25519 {KEY_A} comment here\n\
         *.wild.example,!bad.wild.example ssh-ed25519 {KEY_A}\n\
         |1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak= ssh-ed25519 {KEY_B}\n\
         @revoked * ssh-ed25519 {KEY_B}\n\
         @cert-authority *.example ssh-ed25519 {KEY_B}\n"
    );
    let path = write(&dir, "known_hosts", &text);
    let files = [path.clone()];
    // (host, port, key, expected)
    let rows = [
        ("localhost", 2222, KEY_A, Lookup::Known),
        ("LOCALHOST", 2222, KEY_A, Lookup::Known),
        ("localhost", 22, KEY_A, Lookup::Unknown),
        ("localhost", 2223, KEY_A, Lookup::Unknown),
        ("alpha.example", 22, KEY_A, Lookup::Known),
        ("10.0.0.1", 22, KEY_A, Lookup::Known),
        ("x.wild.example", 22, KEY_A, Lookup::Known),
        ("bad.wild.example", 22, KEY_A, Lookup::Unknown),
        ("unknown.example", 22, KEY_A, Lookup::Unknown),
        // Hashed entry for example.com:22 holds KEY_B, which is also @revoked for every host.
        (
            "example.com",
            22,
            KEY_B,
            Lookup::Revoked {
                path: path.clone(),
                line: 8,
            },
        ),
        (
            "localhost",
            2222,
            KEY_B,
            Lookup::Revoked {
                path: path.clone(),
                line: 8,
            },
        ),
    ];
    for (host, port, k, want) in rows {
        assert_eq!(lookup(&files, host, port, &key(k)), want, "{host}:{port}");
    }
    // A different key for a known host: changed, with the recorded line (comments counted).
    let other = write(
        &dir,
        "other",
        &format!("[localhost]:2222 ssh-ed25519 {KEY_B}\n"),
    );
    let files_b = [other.clone()];
    assert_eq!(
        lookup(&files_b, "localhost", 2222, &key(KEY_A)),
        Lookup::Changed {
            path: other,
            line: 1,
            old: Box::new(key(KEY_B)),
        }
    );
    assert_eq!(
        lookup(&files, "alpha.example", 22, &key(KEY_A)),
        Lookup::Known
    );
    // Hashed match without the revocation: drop the @revoked line.
    let no_revoke = write(&dir, "hashed", &text.replace("@revoked", "#@revoked"));
    assert_eq!(
        lookup(
            std::slice::from_ref(&no_revoke),
            "example.com",
            22,
            &key(KEY_B)
        ),
        Lookup::Known
    );
    assert_eq!(
        lookup(
            std::slice::from_ref(&no_revoke),
            "example.com",
            22,
            &key(KEY_A)
        ),
        Lookup::Changed {
            path: no_revoke,
            line: 7,
            old: Box::new(key(KEY_B)),
        }
    );
    // Missing files are skipped; an equal key in any file wins over a conflict in another.
    let missing = dir.join("missing");
    assert_eq!(
        lookup(
            &[missing, files_b[0].clone(), path],
            "localhost",
            2222,
            &key(KEY_A)
        ),
        Lookup::Known
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn learn_writes_0600_openssh_lines_and_lookup_finds_them() {
    let dir = temp_dir("learn");
    let path = dir.join("sub/known_hosts");
    learn(&path, "host.example", 22, &key(KEY_A)).unwrap();
    learn(&path, "host.example", 2200, &key(KEY_B)).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let dir_mode = std::fs::metadata(path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        text,
        format!("host.example ssh-ed25519 {KEY_A}\n[host.example]:2200 ssh-ed25519 {KEY_B}\n")
    );
    let files = [path.clone()];
    assert_eq!(
        lookup(&files, "host.example", 22, &key(KEY_A)),
        Lookup::Known
    );
    assert_eq!(
        lookup(&files, "host.example", 2200, &key(KEY_B)),
        Lookup::Known
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_cert_authority_line_alone_never_makes_a_host_known() {
    let dir = temp_dir("ca");
    let path = write(
        &dir,
        "known_hosts",
        &format!("@cert-authority *.example ssh-ed25519 {KEY_B}\n"),
    );
    assert_eq!(
        lookup(&[path], "y.example", 22, &key(KEY_B)),
        Lookup::Unknown
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn hostile_host_names_are_written_hashed() {
    let dir = temp_dir("hostile");
    let path = dir.join("known_hosts");
    // Written plain, this would also trust KEY_A for every host.
    learn(&path, "evil.example,*", 22, &key(KEY_A)).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("|1|"), "{text}");
    let files = [path.clone()];
    assert_eq!(
        lookup(&files, "evil.example,*", 22, &key(KEY_A)),
        Lookup::Known
    );
    assert_eq!(
        lookup(&files, "other.example", 22, &key(KEY_A)),
        Lookup::Unknown
    );
    // Hashed `[host]:port`: the port is part of the hashed name.
    learn(&path, "odd host", 2222, &key(KEY_B)).unwrap();
    let files = [path.clone()];
    assert_eq!(lookup(&files, "odd host", 2222, &key(KEY_B)), Lookup::Known);
    assert_eq!(lookup(&files, "odd host", 22, &key(KEY_B)), Lookup::Unknown);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn replace_drops_old_records_of_that_host_only() {
    let dir = temp_dir("replace");
    let path = write(
        &dir,
        "known_hosts",
        &format!(
            "# keep me\nh.example ssh-ed25519 {KEY_A}\nother ssh-ed25519 {KEY_A}\n\
             @revoked h.example ssh-ed25519 {KEY_A}\nh.example,alias ssh-ed25519 {KEY_A}"
        ),
    );
    replace(&path, "h.example", 22, &key(KEY_B)).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        text,
        format!(
            "# keep me\nother ssh-ed25519 {KEY_A}\n@revoked h.example ssh-ed25519 {KEY_A}\n\
             h.example ssh-ed25519 {KEY_B}\n"
        )
    );
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(lookup(&[path], "h.example", 22, &key(KEY_B)), Lookup::Known);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn learn_appends_a_newline_first_when_the_file_lacks_one() {
    let dir = temp_dir("learn-nl");
    let path = write(&dir, "known_hosts", &format!("other ssh-ed25519 {KEY_A}"));
    learn(&path, "h.example", 22, &key(KEY_B)).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        text,
        format!("other ssh-ed25519 {KEY_A}\nh.example ssh-ed25519 {KEY_B}\n")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn replace_refuses_to_rewrite_an_oversized_file() {
    let dir = temp_dir("replace-big");
    let path = dir.join("known_hosts");
    let file = std::fs::File::create(&path).unwrap();
    // Sparse: no 16 MiB are actually written.
    file.set_len(MAX_FILE_BYTES + 1).unwrap();
    drop(file);
    assert!(replace(&path, "h.example", 22, &key(KEY_B)).is_err());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), MAX_FILE_BYTES + 1);
    assert_eq!(
        lookup(&[path], "h.example", 22, &key(KEY_B)),
        Lookup::Unknown
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
