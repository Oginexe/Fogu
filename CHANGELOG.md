# Changelog

## 0.1.6 (2026-10-23)

### Added
- Windows support (alpha): ConPTY shells, Credential Manager, the OpenSSH agent pipe and Windows
  SFTP paths, by [@Federicokalik](https://github.com/Federicokalik) in
  [#3](https://github.com/Revdep/Fogu/pull/3). Thank you!
- SSH tabs can keep their history after a restart (off by default, Settings → Tab recovery). It is
  saved only encrypted, with a key kept in your system's password vault.

### Security
- Windows: network (UNC) paths in links and in the working directory a program reports are never
  touched, so they can't leak your Windows password hash.
- Windows: Fogu's files get an access list for you and SYSTEM only; an SSH agent pipe created by
  another user is refused.
- Windows: SFTP downloads refuse every reserved device name; profiles whose user or host differ
  only in case no longer share a stored password (stored secrets move to the new names by
  themselves).
- Pasted text can't end a bracketed paste with an 8-bit control character.
- Tab titles drop bidirectional override characters, so a title can't read reversed.
- Passwords read from the macOS Keychain and Windows Credential Manager leave no unzeroed copy.
- Saving the config can no longer lose it on a crash, and a symlinked `config.toml` stays a link.
- Release archives carry every licence and a GitHub build attestation; build downloads are
  checked against their hashes.

### Changed
- The Linux binary is 34% smaller (29.3 → 19.4 MB), opens its first frame faster, uses about
  9% less memory and 21 fewer threads, with the same terminal throughput.
- One log file, `fogu.log`, rotated at start-up past 4 MB (it replaces the daily files).
- Clearer errors: failed saves name the file.
