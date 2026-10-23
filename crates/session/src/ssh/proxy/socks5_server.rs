//! Local SOCKS5 server for dynamic forwards (RFC 1928): `CONNECT` only, "no authentication"
//! only, sharing the wire constants and [`Target`] with the client ([`super::socks5`]).
//!
//! Any local program (or user) can connect, so the handshake is untrusted input: every field
//! is checked, nothing past the request is read, names are at most 255 bytes of UTF-8, and the
//! caller bounds the whole handshake with a deadline.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::socks5::{
    ATYP_DOMAIN, ATYP_V4, ATYP_V6, CONNECT, NO_ACCEPTABLE, NO_AUTH, Target, VERSION,
};

/// RFC 1928 § 6 reply codes we send.
pub(crate) const SUCCEEDED: u8 = 0;
/// General failure (the SSH server refused the channel).
pub(crate) const GENERAL_FAILURE: u8 = 1;
const COMMAND_NOT_SUPPORTED: u8 = 7;
const ADDRESS_NOT_SUPPORTED: u8 = 8;

/// Runs the greeting and reads the `CONNECT` request; refusals are answered before the error is
/// returned. On success the caller must answer with [`reply`].
pub(crate) async fn accept<S>(stream: &mut S) -> Result<Target, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let io = |err: std::io::Error| format!("SOCKS5 client: {err}");
    let [version, count] = read_array(stream).await.map_err(io)?;
    if version != VERSION {
        return Err("not a SOCKS5 client".to_owned());
    }
    let mut methods = [0u8; 255];
    let methods = methods
        .get_mut(..usize::from(count))
        .ok_or_else(|| "malformed greeting".to_owned())?;
    stream.read_exact(methods).await.map_err(io)?;
    if !methods.contains(&NO_AUTH) {
        stream
            .write_all(&[VERSION, NO_ACCEPTABLE])
            .await
            .map_err(io)?;
        return Err("the client offers no unauthenticated method".to_owned());
    }
    stream.write_all(&[VERSION, NO_AUTH]).await.map_err(io)?;
    let [version, command, _reserved, atyp] = read_array(stream).await.map_err(io)?;
    if version != VERSION {
        return Err("malformed request".to_owned());
    }
    if command != CONNECT {
        let _gone = reply(stream, COMMAND_NOT_SUPPORTED).await;
        return Err(format!("SOCKS command {command} not supported"));
    }
    let target = match atyp {
        ATYP_V4 => {
            let ip: [u8; 4] = read_array(stream).await.map_err(io)?;
            Target::Addr(
                IpAddr::V4(Ipv4Addr::from(ip)),
                read_port(stream).await.map_err(io)?,
            )
        }
        ATYP_V6 => {
            let ip: [u8; 16] = read_array(stream).await.map_err(io)?;
            Target::Addr(
                IpAddr::V6(Ipv6Addr::from(ip)),
                read_port(stream).await.map_err(io)?,
            )
        }
        ATYP_DOMAIN => {
            let len = usize::from(stream.read_u8().await.map_err(io)?);
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name).await.map_err(io)?;
            let port = read_port(stream).await.map_err(io)?;
            match String::from_utf8(name) {
                Ok(name) if !name.is_empty() && !name.contains(char::is_control) => {
                    Target::Name(name, port)
                }
                _ => {
                    let _gone = reply(stream, ADDRESS_NOT_SUPPORTED).await;
                    return Err("invalid host name".to_owned());
                }
            }
        }
        _ => {
            let _gone = reply(stream, ADDRESS_NOT_SUPPORTED).await;
            return Err(format!("address type {atyp} not supported"));
        }
    };
    Ok(target)
}

/// Sends the reply to a `CONNECT` (bound address 0.0.0.0:0: the real one is on the server).
pub(crate) async fn reply<S>(stream: &mut S, code: u8) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, code, 0, ATYP_V4, 0, 0, 0, 0, 0, 0])
        .await
}

async fn read_array<S: AsyncRead + Unpin, const N: usize>(
    stream: &mut S,
) -> std::io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn read_port<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<u16> {
    Ok(u16::from_be_bytes(read_array(stream).await?))
}

#[cfg(test)]
mod tests {

    use tokio::io::duplex;

    use super::super::socks5;
    use super::*;

    /// The SOCKS5 client against this server; the server answers `code`.
    async fn client_vs_server(target: Target, code: u8) -> (Result<(), String>, Target) {
        let (mut client, mut server) = duplex(1024);
        let serve = tokio::spawn(async move {
            let got = accept(&mut server).await.unwrap();
            reply(&mut server, code).await.unwrap();
            server.write_all(b"tunnel").await.unwrap();
            got
        });
        let result = socks5::connect(&mut client, &target).await;
        if result.is_ok() {
            let mut rest = [0u8; 6];
            client.read_exact(&mut rest).await.unwrap();
            assert_eq!(&rest, b"tunnel");
        }
        (result, serve.await.unwrap())
    }

    #[tokio::test]
    async fn the_s29_client_connects_by_name_and_address() {
        for target in [
            Target::Name("web.lan".into(), 80),
            Target::Addr("10.1.2.3".parse().unwrap(), 443),
            Target::Addr("::1".parse().unwrap(), 22),
        ] {
            let (result, seen) = client_vs_server(target.clone(), SUCCEEDED).await;
            assert_eq!(result, Ok(()));
            assert_eq!(seen, target);
        }
        let (refused, _) = client_vs_server(Target::Name("x".into(), 1), GENERAL_FAILURE).await;
        assert_eq!(refused, Err("general proxy failure".to_owned()));
    }

    /// Sends `bytes`, returns the server's verdict and everything it wrote back.
    async fn raw(bytes: &[u8]) -> (Result<Target, String>, Vec<u8>) {
        let (mut client, mut server) = duplex(1024);
        client.write_all(bytes).await.unwrap();
        client.shutdown().await.unwrap();
        let result = accept(&mut server).await;
        drop(server);
        let mut back = Vec::new();
        client.read_to_end(&mut back).await.unwrap();
        (result, back)
    }

    #[tokio::test]
    async fn refusals_answer_before_closing() {
        // Only username/password offered.
        let (result, back) = raw(&[5, 1, 2]).await;
        assert!(result.is_err());
        assert_eq!(back, [5, 0xFF]);
        // BIND.
        let (result, back) = raw(&[5, 1, 0, 5, 2, 0, 1, 1, 2, 3, 4, 0, 80]).await;
        assert!(result.is_err());
        assert_eq!(back.get(2..4), Some(&[5, 7][..]));
        // Unknown address type, control character in a name.
        for request in [
            &[5, 1, 0, 5, 1, 0, 9][..],
            &[5, 1, 0, 5, 1, 0, 3, 2, b'a', 7, 0, 1],
        ] {
            let (result, back) = raw(request).await;
            assert!(result.is_err());
            assert_eq!(back.get(2..4), Some(&[5, 8][..]));
        }
        // SOCKS4 / truncated requests: no answer, just an error.
        assert!(raw(&[4, 1, 0, 80]).await.0.is_err());
        assert!(raw(&[5, 1, 0, 5, 1, 0, 3, 9, b'a']).await.0.is_err());
    }
}
