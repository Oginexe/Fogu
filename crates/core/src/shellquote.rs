//! Quoting for text typed into a shell (the SFTP panel's "cd terminal here", a profile's `cwd`)
//! and for the host and user substituted into a `ProxyCommand`.

/// The bytes that type a `cd` into a shell: `cd -- '<path>'` + Enter. Inside the single quotes a
/// `'` becomes `'\''` and a `\` becomes `'\\'` (outside the quotes), so the line means the
/// same in POSIX shells and fish (where `\\` and `\'` are escapes even inside quotes). Paths
/// with control characters (a newline would run a second command) are refused.
pub fn cd_command(path: &str) -> Result<Vec<u8>, &'static str> {
    if path.is_empty() {
        return Err("no directory");
    }
    if path.chars().any(char::is_control) {
        return Err("the path contains control characters");
    }
    let mut line = String::from("cd -- '");
    for c in path.chars() {
        match c {
            '\'' => line.push_str("'\\''"),
            '\\' => line.push_str("'\\\\'"),
            c => line.push(c),
        }
    }
    line.push_str("'\r");
    Ok(line.into_bytes())
}

/// How [`expand_proxy_command`] quotes host and user: `cmd.exe` keeps single quotes as part of
/// the argument, so Windows uses double quotes.
const PROXY_QUOTE: &str = if cfg!(windows) { "\"" } else { "'" };

/// `%h`, `%p`, `%r` and `%%` in a proxy command. Host and user are shell-quoted and limited to
/// characters that mean nothing to a shell, so a crafted host name can't inject commands.
pub fn expand_proxy_command(
    template: &str,
    host: &str,
    port: u16,
    user: &str,
) -> Result<String, String> {
    let safe = |s: &str| {
        !s.is_empty()
            && !s.starts_with('-')
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    };
    if !safe(host) {
        return Err("proxy_command: the host name has characters unsafe in a shell".to_owned());
    }
    let mut out = String::new();
    let mut chars = template.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => out.extend([PROXY_QUOTE, host, PROXY_QUOTE]),
            Some('p') => out.push_str(&port.to_string()),
            Some('r') if safe(user) => out.extend([PROXY_QUOTE, user, PROXY_QUOTE]),
            Some('r') => {
                return Err("proxy_command: the user name has characters unsafe in a shell".into());
            }
            Some('%') => out.push('%'),
            other => {
                let token = other.map_or_else(String::new, String::from);
                return Err(format!("proxy_command: unsupported token %{token}"));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{PROXY_QUOTE, cd_command, expand_proxy_command};

    #[test]
    fn cd_here_quoting_table() {
        let ok = [
            ("/tmp", "cd -- '/tmp'\r"),
            ("/home/me/my files", "cd -- '/home/me/my files'\r"),
            ("/a'b", "cd -- '/a'\\''b'\r"),
            ("/x\\y", "cd -- '/x'\\\\'y'\r"),
            ("/$(rm -rf ~)`id`", "cd -- '/$(rm -rf ~)`id`'\r"),
            ("/-n", "cd -- '/-n'\r"),
            ("/日本", "cd -- '/日本'\r"),
        ];
        for (path, want) in ok {
            assert_eq!(cd_command(path).as_deref(), Ok(want.as_bytes()), "{path}");
        }
        for bad in [
            "/a\nrm -rf ~",
            "/a\rb",
            "/esc\x1b[2J",
            "/del\x7f",
            "/c1\u{9b}",
            "",
        ] {
            assert!(cd_command(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn proxy_command_tokens_are_quoted_and_checked() {
        let expand = |t: &str, host: &str, user: &str| expand_proxy_command(t, host, 2222, user);
        let q = PROXY_QUOTE;
        assert_eq!(
            expand("ssh -W %h:%p -l %r gw 100%%", "box.lan", "me"),
            Ok(format!("ssh -W {q}box.lan{q}:2222 -l {q}me{q} gw 100%"))
        );
        assert_eq!(
            expand("nc %h %p", "::1", "x"),
            Ok(format!("nc {q}::1{q} 2222"))
        );
        assert!(expand("nc %h %p", "a;touch /tmp/x", "me").is_err());
        assert!(expand("nc %h %p", "$(id)", "me").is_err());
        assert!(expand("nc %h %p", "-oProxyCommand=x", "me").is_err());
        assert!(expand("nc %h %p", "a'b", "me").is_err());
        assert!(expand("ssh -l %r gw", "h", "me`id`").is_err());
        assert_eq!(expand("nc %h", "h", "me`id`"), Ok(format!("nc {q}h{q}")));
        assert_eq!(
            expand("nc %n", "h", "me"),
            Err("proxy_command: unsupported token %n".to_owned())
        );
        assert!(expand("nc %", "h", "me").is_err());
    }
}
