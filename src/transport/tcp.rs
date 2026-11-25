//! APDUs over TCP in Speculos's protocol.
//!
//! Talks to the Speculos emulator's APDU port, or to anything that speaks
//! the same protocol (for example `ledger_console`, which drives a bare
//! secure element and serves its USB this way):
//!
//! * request: APDU length (4 bytes, big endian), then the APDU;
//! * response: length of the data without the status word (4 bytes, big
//!   endian), then the data and the 2-byte status word.
//!
//! The I/O is blocking, like [`super::hid::HidTransport`]'s.
//!
//! [`serve`] is the other end: it answers a client speaking this protocol
//! with any [`Transport`], e.g. to put a real device on a TCP port the way
//! Speculos exposes its emulated one.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::transport::Transport;

/// A device behind a TCP socket.
pub struct TcpTransport {
    stream: Mutex<TcpStream>,
}

fn io_err(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::BrokenPipe => Error::Disconnected,
        _ => Error::Transport(e.to_string()),
    }
}

impl TcpTransport {
    /// Connects to `addr` (`host:port`; Speculos and `ledger_console` use
    /// port 9999).
    pub fn connect(addr: impl ToSocketAddrs) -> Result<Self> {
        let stream = TcpStream::connect(addr).map_err(|e| Error::Transport(e.to_string()))?;
        let _ = stream.set_nodelay(true);
        Ok(TcpTransport {
            stream: Mutex::new(stream),
        })
    }

    /// Sends one APDU and waits for its response (data and status word).
    pub fn exchange_blocking(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        let mut s = self
            .stream
            .lock()
            .map_err(|_| Error::Transport("poisoned lock".into()))?;
        let mut req = (apdu.len() as u32).to_be_bytes().to_vec();
        req.extend_from_slice(apdu);
        s.write_all(&req).map_err(io_err)?;
        let mut len = [0u8; 4];
        s.read_exact(&mut len).map_err(io_err)?;
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_FRAME {
            return Err(Error::Transport(format!(
                "response length {n} out of range"
            )));
        }
        let mut resp = vec![0u8; n + 2];
        s.read_exact(&mut resp).map_err(io_err)?;
        Ok(resp)
    }
}

impl Transport for TcpTransport {
    async fn exchange(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        self.exchange_blocking(apdu)
    }
}

/// Largest APDU or response accepted on the wire (well above any real one).
const MAX_FRAME: usize = 1 << 20;

/// Serves one client connection: reads Speculos-framed APDUs from `stream`,
/// hands each to `exchange` (which returns the raw response, status word
/// included) and writes the framed response back, until the client closes
/// the connection (`Ok`) or something fails (`Err`, the connection is then
/// dropped since the protocol has no way to report errors).
///
/// [`Transport::exchange`] fits as `exchange`; taking a closure lets the
/// caller log, or reopen a device that re-enumerated, between exchanges.
pub async fn serve<S: Read + Write>(
    mut stream: S,
    mut exchange: impl AsyncFnMut(&[u8]) -> Result<Vec<u8>>,
) -> Result<()> {
    loop {
        let mut len = [0u8; 4];
        match stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(io_err(e)),
        }
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_FRAME {
            return Err(Error::Transport(format!("APDU length {n} out of range")));
        }
        let mut apdu = vec![0u8; n];
        stream.read_exact(&mut apdu).map_err(io_err)?;
        let resp = exchange(&apdu).await?;
        if resp.len() < 2 {
            return Err(Error::InvalidResponse(format!(
                "{}-byte response has no status word",
                resp.len()
            )));
        }
        let mut out = ((resp.len() - 2) as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&resp);
        stream.write_all(&out).map_err(io_err)?;
        stream.flush().map_err(io_err)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn speculos_framing() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut len = [0u8; 4];
            c.read_exact(&mut len).unwrap();
            let mut apdu = vec![0u8; u32::from_be_bytes(len) as usize];
            c.read_exact(&mut apdu).unwrap();
            assert_eq!(apdu, [0xe0, 0x01, 0x00, 0x00, 0x00]);
            c.write_all(&[0, 0, 0, 3, 0xaa, 0xbb, 0xcc, 0x90, 0x00])
                .unwrap();
        });
        let t = TcpTransport::connect(addr).unwrap();
        assert_eq!(
            t.exchange_blocking(&[0xe0, 0x01, 0x00, 0x00, 0x00])
                .unwrap(),
            [0xaa, 0xbb, 0xcc, 0x90, 0x00]
        );
        server.join().unwrap();
        assert!(matches!(
            t.exchange_blocking(&[0xe0, 0x01, 0x00, 0x00, 0x00]),
            Err(Error::Disconnected)
        ));
    }

    /// `serve` on one end, `TcpTransport` on the other.
    #[test]
    fn serve_round_trip() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (c, _) = l.accept().unwrap();
            let mut seen = Vec::new();
            let r = block_on(serve(c, async |apdu: &[u8]| {
                seen.push(apdu.to_vec());
                let mut r = apdu.iter().rev().copied().collect::<Vec<_>>();
                r.extend_from_slice(&[0x90, 0x00]);
                Ok(r)
            }));
            (r, seen)
        });
        let t = TcpTransport::connect(addr).unwrap();
        assert_eq!(
            t.exchange_blocking(&[1, 2, 3]).unwrap(),
            [3, 2, 1, 0x90, 0x00]
        );
        assert_eq!(t.exchange_blocking(&[]).unwrap(), [0x90, 0x00]);
        drop(t);
        let (r, seen) = server.join().unwrap();
        r.unwrap();
        assert_eq!(seen, [vec![1, 2, 3], vec![]]);
    }

    /// Polls a future that never really waits (the I/O is blocking).
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        let mut f = std::pin::pin!(f);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }
}
