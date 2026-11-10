//! HID framing used by the devices over USB.
//!
//! Every APDU is split in 64-byte HID reports:
//!
//! ```text
//! first packet : channel(2) tag(1)=0x05 seq(2)=0 len(2) data...
//! next packets : channel(2) tag(1)=0x05 seq(2)=n data...
//! ```
//! Reports are zero padded to 64 bytes. Responses use the same format.

use crate::error::{Error, Result};

/// Size of an HID report (without the report id).
pub const PACKET_SIZE: usize = 64;
/// Tag identifying an APDU frame.
pub const TAG_APDU: u8 = 0x05;
/// Default channel.
pub const DEFAULT_CHANNEL: u16 = 0x0101;

/// Split an APDU into HID packets of `packet_size` bytes.
pub fn encode(channel: u16, apdu: &[u8], packet_size: usize) -> Vec<Vec<u8>> {
    assert!(packet_size > 7, "packet size too small");
    let mut packets = Vec::new();
    let mut seq: u16 = 0;
    let mut offset = 0;
    loop {
        let mut p = Vec::with_capacity(packet_size);
        p.extend_from_slice(&channel.to_be_bytes());
        p.push(TAG_APDU);
        p.extend_from_slice(&seq.to_be_bytes());
        if seq == 0 {
            p.extend_from_slice(&(apdu.len() as u16).to_be_bytes());
        }
        let take = (packet_size - p.len()).min(apdu.len() - offset);
        p.extend_from_slice(&apdu[offset..offset + take]);
        offset += take;
        p.resize(packet_size, 0);
        packets.push(p);
        seq = seq.wrapping_add(1);
        if offset >= apdu.len() {
            break;
        }
    }
    packets
}

/// Incremental decoder of response packets.
#[derive(Debug)]
pub struct Decoder {
    channel: u16,
    expected_len: Option<usize>,
    seq: u16,
    data: Vec<u8>,
}

impl Decoder {
    pub fn new(channel: u16) -> Self {
        Self {
            channel,
            expected_len: None,
            seq: 0,
            data: Vec::new(),
        }
    }

    /// Feed one HID report. Returns `Some(response)` once complete.
    pub fn push(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        if packet.len() < 5 {
            return Err(Error::Framing("packet too short".into()));
        }
        let channel = u16::from_be_bytes([packet[0], packet[1]]);
        if channel != self.channel {
            return Err(Error::Framing(format!(
                "unexpected channel 0x{channel:04x}"
            )));
        }
        if packet[2] != TAG_APDU {
            return Err(Error::Framing(format!(
                "unexpected tag 0x{:02x}",
                packet[2]
            )));
        }
        let seq = u16::from_be_bytes([packet[3], packet[4]]);
        if seq != self.seq {
            return Err(Error::Framing(format!(
                "unexpected sequence {seq}, wanted {}",
                self.seq
            )));
        }
        let mut payload = &packet[5..];
        if seq == 0 {
            if payload.len() < 2 {
                return Err(Error::Framing("first packet too short".into()));
            }
            self.expected_len = Some(u16::from_be_bytes([payload[0], payload[1]]) as usize);
            payload = &payload[2..];
        }
        let expected = self.expected_len.unwrap_or(0);
        let take = (expected - self.data.len()).min(payload.len());
        self.data.extend_from_slice(&payload[..take]);
        self.seq = self.seq.wrapping_add(1);
        if self.data.len() >= expected {
            Ok(Some(core::mem::take(&mut self.data)))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for len in [0usize, 1, 57, 58, 59, 100, 200, 260, 1000] {
            let apdu: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let packets = encode(DEFAULT_CHANNEL, &apdu, PACKET_SIZE);
            assert!(packets.iter().all(|p| p.len() == PACKET_SIZE));
            let mut d = Decoder::new(DEFAULT_CHANNEL);
            let mut out = None;
            for (i, p) in packets.iter().enumerate() {
                let r = d.push(p).unwrap();
                if i + 1 < packets.len() {
                    assert!(r.is_none());
                } else {
                    out = r;
                }
            }
            assert_eq!(out.unwrap(), apdu);
        }
    }

    #[test]
    fn first_packet_layout() {
        let p = encode(0x0101, &[0xe0, 0x01, 0, 0, 0], 64);
        assert_eq!(p.len(), 1);
        assert_eq!(&p[0][..12], &[1, 1, 5, 0, 0, 0, 5, 0xe0, 1, 0, 0, 0]);
    }
}
