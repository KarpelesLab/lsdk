//! APDU command and response types.

use core::fmt;

use crate::error::{Error, Result};

/// Maximum data length of a short APDU.
pub const MAX_DATA_LEN: usize = 255;

/// An APDU command (`CLA INS P1 P2 Lc data`).
#[derive(Clone, PartialEq, Eq)]
pub struct Apdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
}

impl Apdu {
    /// Build an APDU without data.
    pub const fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self { cla, ins, p1, p2, data: Vec::new() }
    }

    /// Build an APDU with data.
    pub fn with_data(cla: u8, ins: u8, p1: u8, p2: u8, data: impl Into<Vec<u8>>) -> Self {
        Self { cla, ins, p1, p2, data: data.into() }
    }

    /// Serialize to raw bytes. Fails if data exceeds 255 bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.data.len() > MAX_DATA_LEN {
            return Err(Error::InvalidInput(format!(
                "APDU data too long ({} > {MAX_DATA_LEN})",
                self.data.len()
            )));
        }
        let mut out = Vec::with_capacity(5 + self.data.len());
        out.extend_from_slice(&[self.cla, self.ins, self.p1, self.p2, self.data.len() as u8]);
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    /// Parse raw APDU bytes (as found in HSM messages).
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() < 4 {
            return Err(Error::InvalidInput("APDU shorter than 4 bytes".into()));
        }
        let data = if raw.len() > 5 { raw[5..].to_vec() } else { Vec::new() };
        Ok(Self { cla: raw[0], ins: raw[1], p1: raw[2], p2: raw[3], data })
    }
}

impl fmt::Debug for Apdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Apdu({:02x} {:02x} {:02x} {:02x} [{}])",
            self.cla,
            self.ins,
            self.p1,
            self.p2,
            hex::encode(&self.data)
        )
    }
}

/// A 16-bit status word.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StatusWord(pub u16);

impl StatusWord {
    pub const OK: Self = Self(0x9000);
    pub const LOCKED_DEVICE: Self = Self(0x5515);
    pub const USER_REFUSED: Self = Self(0x5501);
    pub const CONDITIONS_NOT_SATISFIED: Self = Self(0x6985);
    pub const WRONG_LENGTH: Self = Self(0x6700);
    pub const INCORRECT_DATA: Self = Self(0x6a80);
    pub const NOT_ENOUGH_MEMORY: Self = Self(0x6a84);
    pub const REFERENCED_DATA_NOT_FOUND: Self = Self(0x6a88);
    pub const FILE_ALREADY_EXISTS: Self = Self(0x6a89);
    pub const INCORRECT_P1_P2: Self = Self(0x6b00);
    pub const INS_NOT_SUPPORTED: Self = Self(0x6d00);
    pub const CLA_NOT_SUPPORTED: Self = Self(0x6e00);
    pub const CLA_NOT_SUPPORTED_BOOTLOADER: Self = Self(0x6e01);
    pub const UNKNOWN_APDU: Self = Self(0x6d02);
    pub const DEVICE_NOT_ONBOARDED: Self = Self(0x6d07);
    pub const DEVICE_NOT_ONBOARDED_2: Self = Self(0x6d06);
    pub const APP_NOT_FOUND: Self = Self(0x6807);
    pub const SECURITY_STATUS_NOT_SATISFIED: Self = Self(0x6982);
    pub const HALTED: Self = Self(0x6faa);
    pub const INVALID_STATE: Self = Self(0x6624);
    pub const OUT_OF_MEMORY: Self = Self(0x5102);
    pub const MANAGER_DEP_MISSING: Self = Self(0x6a83);

    /// `true` for `0x9000`.
    pub fn is_ok(self) -> bool {
        self == Self::OK
    }

    /// `true` when the user rejected the action on the device.
    pub fn is_refused(self) -> bool {
        self == Self::USER_REFUSED || self == Self::CONDITIONS_NOT_SATISFIED
    }

    /// Human readable description of well known status words.
    pub fn description(self) -> &'static str {
        match self.0 {
            0x9000 => "success",
            0x5515 => "device locked",
            0x5501 => "user refused on device",
            0x6985 => "conditions of use not satisfied (denied by user?)",
            0x6700 => "incorrect length",
            0x6a80 => "invalid data",
            0x6a84 | 0x5102 => "not enough memory",
            0x6a83 => "app dependency missing",
            0x6a88 => "referenced data not found",
            0x6a89 => "already exists",
            0x6b00 => "incorrect parameter P1 or P2",
            0x6d00 | 0x6d02 => "instruction not supported (wrong app open?)",
            0x6e00 | 0x6e01 => "class not supported (wrong app open?)",
            0x6d06 | 0x6d07 => "device not onboarded",
            0x6807 => "app not installed",
            0x6982 => "security status not satisfied",
            0x6faa => "device halted",
            0x6624 => "invalid state",
            0x6a82 => "file not found",
            _ => "unknown status",
        }
    }
}

impl fmt::Display for StatusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04x} ({})", self.0, self.description())
    }
}

impl fmt::Debug for StatusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StatusWord(0x{:04x})", self.0)
    }
}

/// A device response: payload + status word.
#[derive(Clone, PartialEq, Eq)]
pub struct Response {
    pub data: Vec<u8>,
    pub sw: StatusWord,
}

impl Response {
    /// Parse a raw response (`data || sw1 sw2`).
    pub fn from_raw(mut raw: Vec<u8>) -> Result<Self> {
        if raw.len() < 2 {
            return Err(Error::InvalidResponse("response shorter than 2 bytes".into()));
        }
        let n = raw.len();
        let sw = StatusWord(u16::from_be_bytes([raw[n - 2], raw[n - 1]]));
        raw.truncate(n - 2);
        Ok(Self { data: raw, sw })
    }

    /// Return the data if the status is `0x9000`, otherwise an error.
    pub fn ok(self) -> Result<Vec<u8>> {
        if self.sw.is_ok() { Ok(self.data) } else { Err(self.sw.into()) }
    }

    /// Re-serialize to `data || sw`.
    pub fn to_raw(&self) -> Vec<u8> {
        let mut v = self.data.clone();
        v.extend_from_slice(&self.sw.0.to_be_bytes());
        v
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Response([{}] {:?})", hex::encode(&self.data), self.sw)
    }
}

/// Small cursor-based reader to parse response payloads.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let r = &self.buf[self.pos..];
        self.pos = self.buf.len();
        r
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::InvalidResponse(format!(
                "truncated response: wanted {n} bytes at offset {}, have {}",
                self.pos,
                self.remaining()
            )));
        }
        let r = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(r)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a length-prefixed (1 byte) field.
    pub fn lv(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.bytes(n)
    }

    /// Read a length-prefixed field, `None` if nothing is left.
    pub fn opt_lv(&mut self) -> Result<Option<&'a [u8]>> {
        if self.is_empty() { Ok(None) } else { self.lv().map(Some) }
    }

    /// Read a length-prefixed string (lossy UTF-8).
    pub fn lv_string(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.lv()?).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode() {
        let a = Apdu::with_data(0xe0, 0xd8, 0, 0, b"Bitcoin".to_vec());
        let raw = a.encode().unwrap();
        assert_eq!(hex::encode(&raw), "e0d8000007426974636f696e");
        assert_eq!(Apdu::decode(&raw).unwrap(), a);
        assert!(Apdu::with_data(0, 0, 0, 0, vec![0; 256]).encode().is_err());
    }

    #[test]
    fn response() {
        let r = Response::from_raw(vec![1, 2, 0x90, 0x00]).unwrap();
        assert_eq!(r.data, vec![1, 2]);
        assert!(r.sw.is_ok());
        let r = Response::from_raw(vec![0x55, 0x15]).unwrap();
        assert!(matches!(r.ok(), Err(Error::Locked)));
    }
}
