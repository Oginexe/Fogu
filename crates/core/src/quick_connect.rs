//! `QuickConnect::parse`: the one parser for `user@host:port` strings, shared by the CLI and the
//! UI's quick-connect box. Serial's `/dev/ttyUSB0@115200` form is out of scope here (there are no
//! serial profiles).

use thiserror::Error;

/// A parsed `user@host:port` (or `host`, `host:port`) string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuickConnect {
    /// The `user@` part, if present.
    pub user: Option<String>,
    /// The host part (hostname or IPv4 literal; never empty).
    pub host: String,
    /// The `:port` part, if present.
    pub port: Option<u16>,
}

/// Why a quick-connect string failed to parse.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum QuickConnectError {
    /// Nothing to connect to.
    #[error("empty address")]
    Empty,
    /// The host part was empty (e.g. `"user@"` or `"@host"` with two `@`s).
    #[error("missing host in {0:?}")]
    MissingHost(String),
    /// The `:port` part was not a valid port number.
    #[error("invalid port in {0:?}")]
    InvalidPort(String),
}

impl QuickConnect {
    /// Parses `"user@host:port"`, `"host:port"` or `"host"`. At most one `@` and one `:` are
    /// allowed (IPv6 literals are out of scope).
    pub fn parse(s: &str) -> Result<Self, QuickConnectError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(QuickConnectError::Empty);
        }
        let (user, rest) = match s.split_once('@') {
            Some((user, rest)) => (Some(user).filter(|u| !u.is_empty()), rest),
            None => (None, s),
        };
        let (host, port) = match rest.split_once(':') {
            Some((host, port_str)) => {
                let port = port_str
                    .parse::<u16>()
                    .map_err(|_| QuickConnectError::InvalidPort(s.to_owned()))?;
                (host, Some(port))
            }
            None => (rest, None),
        };
        if host.is_empty() {
            return Err(QuickConnectError::MissingHost(s.to_owned()));
        }
        Ok(Self {
            user: user.map(str::to_owned),
            host: host.to_owned(),
            port,
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parses_the_three_forms() {
        assert_eq!(
            QuickConnect::parse("alice@example.com:2222").unwrap(),
            QuickConnect {
                user: Some("alice".to_owned()),
                host: "example.com".to_owned(),
                port: Some(2222),
            }
        );
        assert_eq!(
            QuickConnect::parse("example.com:22").unwrap(),
            QuickConnect {
                user: None,
                host: "example.com".to_owned(),
                port: Some(22),
            }
        );
        assert_eq!(
            QuickConnect::parse("example.com").unwrap(),
            QuickConnect {
                user: None,
                host: "example.com".to_owned(),
                port: None,
            }
        );
        assert_eq!(
            QuickConnect::parse("alice@example.com").unwrap(),
            QuickConnect {
                user: Some("alice".to_owned()),
                host: "example.com".to_owned(),
                port: None,
            }
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(QuickConnect::parse(""), Err(QuickConnectError::Empty));
        assert_eq!(QuickConnect::parse("   "), Err(QuickConnectError::Empty));
        assert!(matches!(
            QuickConnect::parse("alice@"),
            Err(QuickConnectError::MissingHost(_))
        ));
        assert!(matches!(
            QuickConnect::parse(":22"),
            Err(QuickConnectError::MissingHost(_))
        ));
        assert!(matches!(
            QuickConnect::parse("example.com:not-a-port"),
            Err(QuickConnectError::InvalidPort(_))
        ));
        assert!(matches!(
            QuickConnect::parse("example.com:99999"),
            Err(QuickConnectError::InvalidPort(_))
        ));
    }
}
