//! X11 forwarding is a Unix display feature. On Windows the profile option stays accepted but
//! forwarding is refused with a visible reason, never silently ignored.

use std::sync::Arc;

/// The `x11-req` cookie name; kept for source compatibility with the Unix module.
pub(crate) const MIT_COOKIE: &str = "MIT-MAGIC-COOKIE-1";

/// The subset of the Unix display identity used by the shell channel.
#[derive(Clone, Debug)]
pub(crate) struct Display {
    /// X screen number.
    pub(crate) screen: u32,
}

/// What the session would send with `x11-req`; never constructed on Windows.
#[derive(Clone, Debug)]
pub(crate) struct X11Fwd {
    pub(crate) display: Display,
    pub(crate) fake: [u8; 16],
}

impl X11Fwd {
    /// X11 forwarding is not available on Windows (no local X server socket).
    pub(crate) fn from_env() -> Result<Self, &'static str> {
        Err("X11 forwarding is not supported on Windows")
    }

    /// The fake cookie as hex text.
    pub(crate) fn fake_hex(&self) -> String {
        self.fake.iter().fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;

            let _infallible = write!(hex, "{byte:02x}");
            hex
        })
    }
}

/// Rejects an `x11` channel (the server should never see one because `x11-req` is not sent).
#[allow(clippy::unused_async, reason = "mirrors the Unix serve function")]
pub(crate) async fn serve<C>(_channel: C, _x11: &Arc<X11Fwd>) {}
