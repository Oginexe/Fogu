//! SOCKS5 `CONNECT` client (RFC 1928), "no authentication" only (profiles have no proxy
//! credentials). The proxy's replies are attacker-ish input: every field is checked, nothing is
//! read past the reply, and the bound address is read with its exact (≤ 255 byte) length.

use std::net::IpAddr;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

pub(super) const VERSION: u8 = 5;
pub(super) const NO_AUTH: u8 = 0;
pub(super) const NO_ACCEPTABLE: u8 = 0xFF;
pub(super) const CONNECT: u8 = 1;
pub(super) const ATYP_V4: u8 = 1;
pub(super) const ATYP_DOMAIN: u8 = 3;
pub(super) const ATYP_V6: u8 = 4;

/// Where the proxy should connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// A host name the proxy resolves (remote DNS).
    Name(String, u16),
    /// An address (an IP literal, or resolved here when remote DNS is off).
    Addr(IpAddr, u16),
}

/// Runs the greeting and `CONNECT` on `stream`; afterwards it carries the target's bytes.
pub(crate) async fn connect<S>(stream: &mut S, target: &Target) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let io = |err: std::io::Error| format!("connection to the proxy failed: {err}");
    stream.write_all(&[VERSION, 1, NO_AUTH]).await.map_err(io)?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await.map_err(io)?;
    match choice {
        [VERSION, NO_AUTH] => {}
        [VERSION, NO_ACCEPTABLE] => {
            return Err("the proxy requires authentication (not supported)".to_owned());
        }
        [VERSION, _] => return Err("the proxy chose an unsupported method".to_owned()),
        _ => return Err("not a SOCKS5 proxy".to_owned()),
    }
    stream.write_all(&request(target)?).await.map_err(io)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(io)?;
    let [version, reply, reserved, atyp] = head;
    if version != VERSION || reserved != 0 {
        return Err("malformed proxy reply".to_owned());
    }
    if reply != 0 {
        return Err(reply_text(reply).to_owned());
    }
    // The bound address: read exactly its length and drop it.
    let len = match atyp {
        ATYP_V4 => 4,
        ATYP_V6 => 16,
        ATYP_DOMAIN => usize::from(stream.read_u8().await.map_err(io)?),
        _ => return Err("malformed proxy reply (address type)".to_owned()),
    };
    let mut bound = [0u8; 255 + 2];
    let bound = bound
        .get_mut(..len + 2)
        .ok_or_else(|| "malformed proxy reply".to_owned())?;
    stream.read_exact(bound).await.map_err(io)?;
    Ok(())
}

fn request(target: &Target) -> Result<Vec<u8>, String> {
    let mut out = vec![VERSION, CONNECT, 0];
    let port = match target {
        Target::Name(host, port) => {
            let len = u8::try_from(host.len())
                .ok()
                .filter(|&n| n > 0)
                .ok_or_else(|| "host name too long for SOCKS5".to_owned())?;
            out.extend([ATYP_DOMAIN, len]);
            out.extend(host.as_bytes());
            port
        }
        Target::Addr(IpAddr::V4(ip), port) => {
            out.push(ATYP_V4);
            out.extend(ip.octets());
            port
        }
        Target::Addr(IpAddr::V6(ip), port) => {
            out.push(ATYP_V6);
            out.extend(ip.octets());
            port
        }
    };
    out.extend(port.to_be_bytes());
    Ok(out)
}

/// RFC 1928 § 6 reply codes.
fn reply_text(code: u8) -> &'static str {
    match code {
        1 => "general proxy failure",
        2 => "connection not allowed by the proxy's rules",
        3 => "network unreachable (from the proxy)",
        4 => "host unreachable (from the proxy)",
        5 => "connection refused by the target (from the proxy)",
        6 => "TTL expired",
        7 => "command not supported by the proxy",
        8 => "address type not supported by the proxy",
        _ => "the proxy refused the connection (unknown reply code)",
    }
}

#[cfg(test)]
mod tests {

    use std::net::Ipv6Addr;

    use tokio::io::duplex;

    use super::*;

    /// Runs `connect` against a scripted proxy: checks what the client sent, answers `script`.
    async fn run(target: Target, expect: &[u8], script: &[u8]) -> (Result<(), String>, Vec<u8>) {
        let (mut client, mut server) = duplex(1024);
        let expect = expect.to_vec();
        let script = script.to_vec();
        let proxy = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            server.write_all(script.get(..2).unwrap()).await.unwrap();
            if script.get(1) == Some(&0) && script.first() == Some(&5) {
                let mut req = vec![0u8; expect.len()];
                server.read_exact(&mut req).await.unwrap();
                assert_eq!(req, expect);
                server.write_all(script.get(2..).unwrap()).await.unwrap();
            }
            server.write_all(b"SSH-2.0-after").await.unwrap();
            server
        });
        let result = connect(&mut client, &target).await;
        let _server = proxy.await.unwrap();
        let mut rest = vec![0u8; 13];
        let after = if result.is_ok() {
            client.read_exact(&mut rest).await.unwrap();
            rest
        } else {
            Vec::new()
        };
        (result, after)
    }

    #[tokio::test]
    async fn connect_by_name_reads_exactly_the_reply() {
        let target = Target::Name("box.lan".into(), 22);
        let mut want = vec![5, 1, 0, 3, 7];
        want.extend(b"box.lan");
        want.extend([0, 22]);
        // Reply with a domain-type bound address; the bytes after it belong to SSH.
        let mut reply = vec![5, 0, 5, 0, 0, 3, 3];
        reply.extend(b"abc");
        reply.extend([0, 80]);
        let (result, after) = run(target, &want, &reply).await;
        assert_eq!(result, Ok(()));
        assert_eq!(after, b"SSH-2.0-after");
    }

    #[tokio::test]
    async fn connect_by_address_v4_and_v6() {
        let v4 = Target::Addr("10.0.0.1".parse().unwrap(), 2222);
        let ok_v4 = [5, 0, 5, 0, 0, 1, 1, 2, 3, 4, 0, 1];
        let (result, _) = run(v4, &[5, 1, 0, 1, 10, 0, 0, 1, 8, 174], &ok_v4).await;
        assert_eq!(result, Ok(()));
        let v6 = Target::Addr(IpAddr::V6(Ipv6Addr::LOCALHOST), 22);
        let mut want = vec![5, 1, 0, 4];
        want.extend(Ipv6Addr::LOCALHOST.octets());
        want.extend([0, 22]);
        let mut reply = vec![5, 0, 5, 0, 0, 4];
        reply.extend([0; 18]);
        assert_eq!(run(v6, &want, &reply).await.0, Ok(()));
    }

    #[tokio::test]
    async fn refusals_and_malformed_replies_are_errors() {
        let target = || Target::Name("h".into(), 22);
        let want = [5, 1, 0, 3, 1, b'h', 0, 22];
        for (script, err) in [
            (
                vec![5, 0xFF],
                "the proxy requires authentication (not supported)",
            ),
            (vec![4, 0], "not a SOCKS5 proxy"),
            (vec![5, 2], "the proxy chose an unsupported method"),
            (
                vec![5, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0],
                "connection refused by the target (from the proxy)",
            ),
            (
                vec![5, 0, 5, 0, 0, 9],
                "malformed proxy reply (address type)",
            ),
            (vec![5, 0, 4, 0, 0, 1], "malformed proxy reply"),
            (vec![5, 0, 5, 0, 1, 1], "malformed proxy reply"),
        ] {
            assert_eq!(run(target(), &want, &script).await.0, Err(err.to_owned()));
        }
    }

    #[test]
    fn an_overlong_name_is_refused_before_sending() {
        let long = Target::Name("a".repeat(256), 22);
        assert!(request(&long).is_err());
        assert!(request(&Target::Name(String::new(), 22)).is_err());
    }
}
