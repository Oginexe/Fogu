//! HTTP `CONNECT` client (no proxy authentication). The response is attacker-ish
//! input: it is read byte by byte up to the blank line (so no byte of the tunnel is consumed),
//! capped at [`MAX_RESPONSE`], and only a `2xx` status continues.

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// Longest response head (status line + headers) accepted, in bytes.
pub(crate) const MAX_RESPONSE: usize = 8 * 1024;

/// Sends `CONNECT host:port` on `stream` and checks the response; afterwards the stream
/// carries the target's bytes.
pub(crate) async fn connect<S>(stream: &mut S, host: &str, port: u16) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if host.is_empty() || host.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("invalid target host for HTTP CONNECT".to_owned());
    }
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    let io = |err: std::io::Error| format!("connection to the proxy failed: {err}");
    stream.write_all(request.as_bytes()).await.map_err(io)?;
    let mut head = Vec::with_capacity(256);
    while !head.ends_with(b"\r\n\r\n") && !head.ends_with(b"\n\n") {
        if head.len() == MAX_RESPONSE {
            return Err("proxy response too long".to_owned());
        }
        match stream.read_u8().await {
            Ok(byte) => head.push(byte),
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err("the proxy closed the connection".to_owned());
            }
            Err(err) => return Err(io(err)),
        }
    }
    let text = String::from_utf8_lossy(&head);
    let status = text.lines().next().unwrap_or_default();
    let mut parts = status.splitn(3, ' ');
    let (version, code, reason) = (parts.next(), parts.next(), parts.next());
    let code = code
        .filter(|c| c.len() == 3)
        .and_then(|c| c.parse::<u16>().ok());
    match (version, code) {
        (Some(v), Some(code)) if v.starts_with("HTTP/1.") => {
            if (200..300).contains(&code) {
                Ok(())
            } else {
                let reason = crate::sanitize_remote(reason.unwrap_or_default().trim(), 80, false);
                Err(format!("the proxy refused the connection: {code} {reason}"))
            }
        }
        _ => Err("not an HTTP proxy response".to_owned()),
    }
}

#[cfg(test)]
mod tests {

    use tokio::io::duplex;

    use super::*;

    /// `connect` against a proxy that expects `request` and answers `reply`; returns the result
    /// and the bytes the client reads afterwards.
    async fn run(
        host: &str,
        port: u16,
        request: &str,
        reply: Vec<u8>,
    ) -> (Result<(), String>, Vec<u8>) {
        let (mut client, mut server) = duplex(64 * 1024);
        let request = request.to_owned();
        let proxy = tokio::spawn(async move {
            let mut got = vec![0u8; request.len()];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(String::from_utf8(got).unwrap(), request);
            server.write_all(&reply).await.unwrap();
            // Dropped here: the client sees EOF after the reply.
        });
        let result = connect(&mut client, host, port).await;
        proxy.await.unwrap();
        let mut after = Vec::new();
        if result.is_ok() {
            client.read_to_end(&mut after).await.unwrap();
        }
        (result, after)
    }

    const REQ: &str = "CONNECT box.lan:22 HTTP/1.1\r\nHost: box.lan:22\r\n\r\n";

    #[tokio::test]
    async fn a_2xx_response_leaves_the_tunnel_bytes_unread() {
        let reply = b"HTTP/1.1 200 Connection established\r\nVia: x\r\n\r\nSSH-2.0-x".to_vec();
        let (result, after) = run("box.lan", 22, REQ, reply).await;
        assert_eq!(result, Ok(()));
        assert_eq!(after, b"SSH-2.0-x");
        let v6 = "CONNECT [::1]:2222 HTTP/1.1\r\nHost: [::1]:2222\r\n\r\n";
        let (result, _) = run("::1", 2222, v6, b"HTTP/1.0 200 OK\n\n".to_vec()).await;
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn refusals_garbage_and_floods_are_errors() {
        let refused = b"HTTP/1.1 403 Forbidden \x1b[31mred\r\n\r\n".to_vec();
        assert_eq!(
            run("box.lan", 22, REQ, refused).await.0,
            Err("the proxy refused the connection: 403 Forbidden [31mred".to_owned())
        );
        assert_eq!(
            run("box.lan", 22, REQ, b"SSH-2.0-OpenSSH\r\n\r\n".to_vec())
                .await
                .0,
            Err("not an HTTP proxy response".to_owned())
        );
        assert_eq!(
            run("box.lan", 22, REQ, b"HTTP/1.1 200".to_vec()).await.0,
            Err("the proxy closed the connection".to_owned())
        );
        let flood = [b"HTTP/1.1 200 OK\r\n".as_slice(), &[b'x'; MAX_RESPONSE]].concat();
        assert_eq!(
            run("box.lan", 22, REQ, flood).await.0,
            Err("proxy response too long".to_owned())
        );
    }

    #[tokio::test]
    async fn a_host_with_line_breaks_is_never_sent() {
        let (mut client, _server) = duplex(1024);
        let result = connect(&mut client, "evil\r\nX-Injected: 1", 22).await;
        assert_eq!(
            result,
            Err("invalid target host for HTTP CONNECT".to_owned())
        );
    }
}
