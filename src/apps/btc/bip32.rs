//! Minimal BIP-32 extended public keys: decode, encode and non-hardened derivation.

use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use purecrypto::hash::{Hmac, Sha512, ripemd160, sha256};

use crate::error::{Error, Result};

/// An extended public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xpub {
    pub version: [u8; 4],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    /// Compressed public key.
    pub public_key: [u8; 33],
}

fn dsha256(d: &[u8]) -> [u8; 32] {
    sha256(&sha256(d))
}

/// HASH160 of data.
pub fn hash160(d: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(d))
}

impl Xpub {
    /// Parse a base58check `xpub`/`tpub` string.
    pub fn parse(s: &str) -> Result<Self> {
        let raw = outscript::base58::decode(s).map_err(|e| Error::InvalidInput(format!("xpub: {e:?}")))?;
        if raw.len() != 82 {
            return Err(Error::InvalidInput("xpub: bad length".into()));
        }
        let (body, check) = raw.split_at(78);
        if dsha256(body)[..4] != *check {
            return Err(Error::InvalidInput("xpub: bad checksum".into()));
        }
        let x = Xpub {
            version: body[0..4].try_into().unwrap(),
            depth: body[4],
            parent_fingerprint: body[5..9].try_into().unwrap(),
            child_number: u32::from_be_bytes(body[9..13].try_into().unwrap()),
            chain_code: body[13..45].try_into().unwrap(),
            public_key: body[45..78].try_into().unwrap(),
        };
        AffinePoint::from_sec1(&x.public_key).map_err(|_| Error::InvalidInput("xpub: invalid key".into()))?;
        Ok(x)
    }

    /// Encode as base58check.
    pub fn encode(&self) -> String {
        let mut body = Vec::with_capacity(82);
        body.extend_from_slice(&self.version);
        body.push(self.depth);
        body.extend_from_slice(&self.parent_fingerprint);
        body.extend_from_slice(&self.child_number.to_be_bytes());
        body.extend_from_slice(&self.chain_code);
        body.extend_from_slice(&self.public_key);
        let check = dsha256(&body);
        body.extend_from_slice(&check[..4]);
        outscript::base58::encode(&body)
    }

    /// Fingerprint of this key (first 4 bytes of HASH160(pubkey)).
    pub fn fingerprint(&self) -> [u8; 4] {
        hash160(&self.public_key)[..4].try_into().unwrap()
    }

    /// Derive a non-hardened child.
    pub fn derive_child(&self, index: u32) -> Result<Self> {
        if index & 0x8000_0000 != 0 {
            return Err(Error::InvalidInput("cannot derive hardened child from xpub".into()));
        }
        let mut mac = Hmac::<Sha512>::new(&self.chain_code);
        mac.update(&self.public_key);
        mac.update(&index.to_be_bytes());
        let i = mac.finalize();
        let i = i.as_ref();
        let il: [u8; 32] = i[..32].try_into().unwrap();
        let tweak = Scalar::from_bytes_be(&il).map_err(|_| Error::App("invalid child (IL >= n)".into()))?;
        let parent = AffinePoint::from_sec1(&self.public_key)
            .map_err(|_| Error::InvalidInput("invalid public key".into()))?
            .to_projective();
        let child: ProjectivePoint = ProjectivePoint::mul_generator(&tweak).add(&parent);
        let child = child.to_affine().ok_or_else(|| Error::App("invalid child (point at infinity)".into()))?;
        Ok(Xpub {
            version: self.version,
            depth: self.depth.wrapping_add(1),
            parent_fingerprint: self.fingerprint(),
            child_number: index,
            chain_code: i[32..].try_into().unwrap(),
            public_key: child.to_sec1_compressed(),
        })
    }

    /// Derive along a list of non-hardened indexes.
    pub fn derive_path(&self, path: &[u32]) -> Result<Self> {
        let mut k = self.clone();
        for i in path {
            k = k.derive_child(*i)?;
        }
        Ok(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-32 test vector 1.
    const M: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const M_0H_1: &str = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";
    const M_0H_1_2H_2: &str = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV";
    const M_0H_1_2H_2_1B: &str = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy";

    #[test]
    fn roundtrip_and_derive() {
        let m = Xpub::parse(M).unwrap();
        assert_eq!(m.encode(), M);
        let a = Xpub::parse(M_0H_1).unwrap();
        assert_eq!(a.encode(), M_0H_1);
        let b = Xpub::parse(M_0H_1_2H_2).unwrap();
        let c = b.derive_child(1_000_000_000).unwrap();
        assert_eq!(c.encode(), M_0H_1_2H_2_1B);
        assert!(m.derive_child(0x8000_0000).is_err());
    }
}
