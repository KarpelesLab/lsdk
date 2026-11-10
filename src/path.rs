//! BIP-32 derivation paths.

use core::fmt;
use core::str::FromStr;

use crate::error::{Error, Result};

/// Hardened bit.
pub const HARDENED: u32 = 0x8000_0000;

/// A BIP-32 derivation path like `m/44'/60'/0'/0/0`.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct DerivationPath(pub Vec<u32>);

impl DerivationPath {
    /// Components of the path.
    pub fn components(&self) -> &[u32] {
        &self.0
    }

    /// Encode as `count(1) || u32be...`, the format used by most apps.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 4 * self.0.len());
        v.push(self.0.len() as u8);
        for c in &self.0 {
            v.extend_from_slice(&c.to_be_bytes());
        }
        v
    }

    /// Encode as `u32be...` without the count prefix.
    pub fn encode_raw(&self) -> Vec<u8> {
        self.0.iter().flat_map(|c| c.to_be_bytes()).collect()
    }
}

impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        let s = s.strip_prefix("m/").or_else(|| s.strip_prefix("m")).unwrap_or(s);
        if s.is_empty() {
            return Ok(Self(Vec::new()));
        }
        let mut out = Vec::new();
        for part in s.split('/') {
            let (num, hardened) = match part.strip_suffix(['\'', 'h', 'H']) {
                Some(n) => (n, true),
                None => (part, false),
            };
            let n: u32 = num
                .parse()
                .map_err(|_| Error::InvalidInput(format!("invalid path component {part:?}")))?;
            if n >= HARDENED {
                return Err(Error::InvalidInput(format!("path component {part:?} out of range")));
            }
            out.push(if hardened { n | HARDENED } else { n });
        }
        if out.len() > 10 {
            return Err(Error::InvalidInput("derivation path too long (max 10)".into()));
        }
        Ok(Self(out))
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for c in &self.0 {
            if c & HARDENED != 0 {
                write!(f, "/{}'", c & !HARDENED)?;
            } else {
                write!(f, "/{c}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DerivationPath({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let p: DerivationPath = "m/44'/60'/0'/0/0".parse().unwrap();
        assert_eq!(p.0, vec![44 | HARDENED, 60 | HARDENED, HARDENED, 0, 0]);
        assert_eq!(p.to_string(), "m/44'/60'/0'/0/0");
        assert_eq!(hex::encode(p.encode()), "058000002c8000003c800000000000000000000000");
        let q: DerivationPath = "44h/501h/0h".parse().unwrap();
        assert_eq!(q.0.len(), 3);
        assert!("m/abc".parse::<DerivationPath>().is_err());
    }
}
