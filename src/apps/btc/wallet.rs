//! Wallet policies (BIP-388) as understood by the Bitcoin app.

use purecrypto::hash::sha256;

use super::merkle::{MerkleTree, leaf_hash};
use super::varint;
use crate::error::{Error, Result};
use crate::path::DerivationPath;

/// Single-signature account types usable without registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum AddressType {
    /// BIP-44 `pkh(@0/**)`
    Legacy,
    /// BIP-49 `sh(wpkh(@0/**))`
    NestedSegwit,
    /// BIP-84 `wpkh(@0/**)`
    NativeSegwit,
    /// BIP-86 `tr(@0/**)`
    Taproot,
}

impl AddressType {
    /// BIP-43 purpose.
    pub fn purpose(self) -> u32 {
        match self {
            AddressType::Legacy => 44,
            AddressType::NestedSegwit => 49,
            AddressType::NativeSegwit => 84,
            AddressType::Taproot => 86,
        }
    }

    /// Descriptor template.
    pub fn template(self) -> &'static str {
        match self {
            AddressType::Legacy => "pkh(@0/**)",
            AddressType::NestedSegwit => "sh(wpkh(@0/**))",
            AddressType::NativeSegwit => "wpkh(@0/**)",
            AddressType::Taproot => "tr(@0/**)",
        }
    }

    /// outscript script format name.
    pub fn script_format(self) -> &'static str {
        match self {
            AddressType::Legacy => "p2pkh",
            AddressType::NestedSegwit => "p2sh:p2wpkh",
            AddressType::NativeSegwit => "p2wpkh",
            AddressType::Taproot => "p2tr",
        }
    }

    /// Account derivation path `m/purpose'/coin'/account'`.
    pub fn account_path(self, testnet: bool, account: u32) -> DerivationPath {
        use crate::path::HARDENED;
        DerivationPath(vec![
            self.purpose() | HARDENED,
            (testnet as u32) | HARDENED,
            account | HARDENED,
        ])
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "legacy" | "pkh" | "p2pkh" | "44" => AddressType::Legacy,
            "nested" | "nested-segwit" | "sh-wpkh" | "p2sh-p2wpkh" | "49" => {
                AddressType::NestedSegwit
            }
            "segwit" | "native-segwit" | "wpkh" | "p2wpkh" | "84" => AddressType::NativeSegwit,
            "taproot" | "tr" | "p2tr" | "86" => AddressType::Taproot,
            _ => return Err(Error::InvalidInput(format!("unknown address type {s:?}"))),
        })
    }
}

/// A key information string: `[fingerprint/path]xpub` (key origin optional).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    pub fingerprint: Option<[u8; 4]>,
    pub path: DerivationPath,
    pub xpub: String,
}

impl KeyInfo {
    pub fn new(fingerprint: [u8; 4], path: DerivationPath, xpub: String) -> Self {
        Self {
            fingerprint: Some(fingerprint),
            path,
            xpub,
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        let Some(rest) = s.strip_prefix('[') else {
            return Ok(Self {
                fingerprint: None,
                path: DerivationPath::default(),
                xpub: s.to_string(),
            });
        };
        let (origin, xpub) = rest
            .split_once(']')
            .ok_or_else(|| Error::InvalidInput("bad key origin".into()))?;
        let (fpr, path) = origin.split_once('/').unwrap_or((origin, ""));
        let fpr = hex::decode(fpr).map_err(|_| Error::InvalidInput("bad fingerprint".into()))?;
        let fpr: [u8; 4] = fpr
            .try_into()
            .map_err(|_| Error::InvalidInput("bad fingerprint".into()))?;
        Ok(Self {
            fingerprint: Some(fpr),
            path: path.parse()?,
            xpub: xpub.to_string(),
        })
    }
}

impl core::fmt::Display for KeyInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.fingerprint {
            None => f.write_str(&self.xpub),
            Some(fpr) => {
                let path = self.path.to_string();
                write!(
                    f,
                    "[{}{}]{}",
                    hex::encode(fpr),
                    path.strip_prefix('m').unwrap_or(&path),
                    self.xpub
                )
            }
        }
    }
}

/// A wallet policy (version 2 of the app protocol).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletPolicy {
    /// Empty for default (unregistered) single-sig policies.
    pub name: String,
    pub descriptor_template: String,
    pub keys: Vec<KeyInfo>,
}

impl WalletPolicy {
    pub fn new(
        name: impl Into<String>,
        descriptor_template: impl Into<String>,
        keys: Vec<KeyInfo>,
    ) -> Self {
        Self {
            name: name.into(),
            descriptor_template: descriptor_template.into(),
            keys,
        }
    }

    /// Default single-sig policy for an account key.
    pub fn default_single_sig(kind: AddressType, key: KeyInfo) -> Self {
        Self::new("", kind.template(), vec![key])
    }

    pub(crate) fn key_strings(&self) -> Vec<String> {
        self.keys.iter().map(|k| k.to_string()).collect()
    }

    /// Serialization sent to the device.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = vec![2u8];
        out.push(self.name.len() as u8);
        out.extend_from_slice(self.name.as_bytes());
        out.extend(varint::encode(self.descriptor_template.len() as u64));
        out.extend_from_slice(&sha256(self.descriptor_template.as_bytes()));
        out.extend(varint::encode(self.keys.len() as u64));
        let leaves = self
            .key_strings()
            .iter()
            .map(|k| leaf_hash(k.as_bytes()))
            .collect();
        out.extend_from_slice(MerkleTree::new(leaves).root());
        out
    }

    /// Policy id (sha256 of the serialization).
    pub fn id(&self) -> [u8; 32] {
        sha256(&self.serialize())
    }

    /// Descriptor with keys substituted (for display / external wallets).
    pub fn descriptor(&self, change: bool) -> String {
        let mut d = self.descriptor_template.clone();
        for (i, k) in self.keys.iter().enumerate().rev() {
            d = d.replace(&format!("@{i}"), &k.to_string());
        }
        d.replace("/**", if change { "/1/*" } else { "/0/*" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_info() {
        let s = "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P";
        let k = KeyInfo::parse(s).unwrap();
        assert_eq!(k.to_string(), s);
    }
}
