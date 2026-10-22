//! Fuzz target: `ProxyCommand` expansion (`fogu_core::shellquote::expand_proxy_command`). The
//! host and user come from profiles and ssh_config files someone else may have written: an
//! accepted expansion must give the shell exactly the metacharacters the template has, as if
//! host and user were plain words.

#![no_main]

use fogu_core::shellquote::expand_proxy_command;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut parts = text.splitn(3, '\n');
    let template = parts.next().unwrap_or_default();
    let host = parts.next().unwrap_or_default();
    let user = parts.next().unwrap_or_default();
    let Ok(out) = expand_proxy_command(template, host, 2222, user) else {
        return;
    };
    let plain = expand_proxy_command(template, "h", 2222, "u")
        .expect("a template that takes the fuzzed host and user takes plain ones");
    let meta = |s: &str| -> String {
        s.chars()
            .filter(|c| !c.is_ascii_alphanumeric() && !matches!(c, '.' | '-' | '_' | ':'))
            .collect()
    };
    assert_eq!(meta(&out), meta(&plain), "{out:?}");
    assert!(!host.starts_with('-'));
});
