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
        if n > 1 << 20 {
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
}
