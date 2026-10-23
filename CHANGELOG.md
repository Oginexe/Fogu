# Changelog

## Unreleased

### Security
- Windows: network (UNC) paths in links and in the working directory a program reports are never
  touched, so they can't leak your Windows password hash.
- Windows: Fogu's files get an access list for you and SYSTEM only; an SSH agent pipe created by
  another user is refused.
- Windows: SFTP downloads refuse every reserved device name; profiles whose user or host differ
  only in case no longer share a stored password (re-enter it once).
- Pasted text can't end a bracketed paste with an 8-bit control character.
- Tab titles drop bidirectional override characters, so a title can't read reversed.
- Passwords read from the macOS Keychain and Windows Credential Manager leave no unzeroed copy.
- Saving the config can no longer lose it on a crash, and a symlinked `config.toml` stays a link.
- Release archives carry every licence and a GitHub build attestation; build downloads are
  checked against their hashes.

### Changed
- The Linux binary is 34% smaller (29.3 → 19.4 MB) at the same speed.
- One log file, `fogu.log`, rotated at start-up past 4 MB (it replaces the daily files).
- Clearer errors: failed saves name the file.
