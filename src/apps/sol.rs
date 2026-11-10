//! Solana app client.
//!
//! Transactions are built with outscript ([`new_solana_tx`],
//! [`transfer_instruction`], ...); the device signs the serialized message.

use crate::apdu::{Apdu, StatusWord};
use crate::device::Device;
use crate::error::{Error, Result};
use crate::path::{DerivationPath, HARDENED};
use crate::transport::Transport;

pub use outscript::solana::{
    SolanaInstruction, SolanaKey, SolanaTx, new_solana_tx, set_compute_unit_limit,
    set_compute_unit_price, spl_transfer_instruction, transfer_instruction,
};

const CLA: u8 = 0xe0;
const INS_GET_CONFIG: u8 = 0x04;
const INS_GET_PUBKEY: u8 = 0x05;
const INS_SIGN: u8 = 0x06;
const INS_SIGN_OFFCHAIN: u8 = 0x07;
const P2_EXTEND: u8 = 0x01;
const P2_MORE: u8 = 0x02;
const MAX_CHUNK: usize = 255;

/// Default derivation path for the first account.
pub const DEFAULT_PATH: &str = "m/44'/501'/0'";

/// App configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct SolConfig {
    pub blind_signing_enabled: bool,
    pub pubkey_display_short: bool,
    pub version: String,
}

/// Solana app client.
pub struct SolApp<'d, T: Transport> {
    device: &'d Device<T>,
}

/// The app only accepts hardened components.
fn hardened(path: &DerivationPath) -> DerivationPath {
    DerivationPath(path.0.iter().map(|c| c | HARDENED).collect())
}

/// Bytes signed by the device for a transaction (its message).
pub fn message_bytes(tx: &SolanaTx) -> Result<Vec<u8>> {
    if let Some(m) = &tx.message_v1 {
        m.to_bytes()
            .map_err(|e| Error::InvalidInput(format!("{e:?}")))
    } else if let Some(m) = &tx.message_v0 {
        Ok(m.to_bytes())
    } else {
        Ok(tx.message.to_bytes())
    }
}

fn map_err(sw: StatusWord) -> Error {
    match sw.0 {
        0x6985 | 0x5501 => Error::UserRefused,
        0x6808 => Error::App("blind signing must be enabled in the Solana app settings".into()),
        0x6d00 | 0x6e00 | 0x6e01 => Error::App("the Solana app is not open".into()),
        _ => sw.into(),
    }
}

impl<'d, T: Transport> SolApp<'d, T> {
    pub fn new(device: &'d Device<T>) -> Self {
        Self { device }
    }

    async fn send_chunked(&self, ins: u8, p1: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let mut p2 = 0u8;
        let chunks: Vec<&[u8]> = payload.chunks(MAX_CHUNK).collect();
        let n = chunks.len().max(1);
        let mut last = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let more = if i + 1 < n { P2_MORE } else { 0 };
            let r = self
                .device
                .exchange(&Apdu::with_data(CLA, ins, p1, p2 | more, chunk.to_vec()))
                .await?;
            if !r.sw.is_ok() {
                return Err(map_err(r.sw));
            }
            last = r.data;
            p2 |= P2_EXTEND;
        }
        Ok(last)
    }

    /// App configuration.
    pub async fn get_configuration(&self) -> Result<SolConfig> {
        let r = self
            .device
            .exchange(&Apdu::new(CLA, INS_GET_CONFIG, 0, 0))
            .await?;
        if !r.sw.is_ok() {
            return Err(map_err(r.sw));
        }
        let d = r.data;
        if d.len() < 5 {
            return Err(Error::InvalidResponse("configuration too short".into()));
        }
        Ok(SolConfig {
            blind_signing_enabled: d[0] != 0,
            pubkey_display_short: d[1] != 0,
            version: format!("{}.{}.{}", d[2], d[3], d[4]),
        })
    }

    /// Public key (base58 address) for a path.
    pub async fn get_address(&self, path: &DerivationPath, display: bool) -> Result<String> {
        let d = self
            .send_chunked(INS_GET_PUBKEY, display as u8, &hardened(path).encode())
            .await?;
        if d.len() != 32 {
            return Err(Error::InvalidResponse("bad public key length".into()));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&d);
        Ok(SolanaKey(k).to_base58())
    }

    /// Sign a serialized message, returns the 64-byte signature.
    pub async fn sign_message_bytes(
        &self,
        path: &DerivationPath,
        message: &[u8],
    ) -> Result<[u8; 64]> {
        let mut payload = vec![1u8];
        payload.extend_from_slice(&hardened(path).encode());
        payload.extend_from_slice(message);
        let d = self.send_chunked(INS_SIGN, 0x01, &payload).await?;
        d.as_slice()
            .try_into()
            .map_err(|_| Error::InvalidResponse("bad signature length".into()))
    }

    /// Sign a transaction in place (the device key must be one of its signers).
    pub async fn sign_tx(&self, path: &DerivationPath, tx: &mut SolanaTx) -> Result<[u8; 64]> {
        let pubkey = SolanaKey::parse(&self.get_address(path, false).await?)
            .map_err(|e| Error::InvalidResponse(format!("{e:?}")))?;
        let (keys, header) = match (&tx.message_v1, &tx.message_v0) {
            (Some(m), _) => (m.account_keys.clone(), m.header.num_required_signatures),
            (None, Some(m)) => (m.account_keys.clone(), m.header.num_required_signatures),
            (None, None) => (
                tx.message.account_keys.clone(),
                tx.message.header.num_required_signatures,
            ),
        };
        let n = header as usize;
        let idx = keys
            .iter()
            .take(n)
            .position(|k| *k == pubkey)
            .ok_or_else(|| {
                Error::InvalidInput("device key is not a signer of this transaction".into())
            })?;
        let sig = self.sign_message_bytes(path, &message_bytes(tx)?).await?;
        if tx.signatures.len() < n {
            tx.signatures.resize(n, Vec::new());
        }
        tx.signatures[idx] = sig.to_vec();
        Ok(sig)
    }

    /// Sign an off-chain message (already serialized in the off-chain format).
    pub async fn sign_offchain_message(
        &self,
        path: &DerivationPath,
        message: &[u8],
    ) -> Result<[u8; 64]> {
        let mut payload = vec![1u8];
        payload.extend_from_slice(&hardened(path).encode());
        payload.extend_from_slice(message);
        let d = self.send_chunked(INS_SIGN_OFFCHAIN, 0x01, &payload).await?;
        d.as_slice()
            .try_into()
            .map_err(|_| Error::InvalidResponse("bad signature length".into()))
    }
}

/// Build an unsigned SOL transfer.
pub fn build_transfer(
    from: &str,
    to: &str,
    lamports: u64,
    recent_blockhash: &str,
) -> Result<SolanaTx> {
    let parse =
        |s: &str| SolanaKey::parse(s).map_err(|e| Error::InvalidInput(format!("{s:?}: {e:?}")));
    let from = parse(from)?;
    let ix = transfer_instruction(from, parse(to)?, lamports);
    new_solana_tx(from, parse(recent_blockhash)?, &[ix])
        .map_err(|e| Error::InvalidInput(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer() {
        let a = "83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri";
        let b = "11111111111111111111111111111112";
        let tx =
            build_transfer(a, b, 1000, "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N").unwrap();
        let m = message_bytes(&tx).unwrap();
        assert_eq!(m[0], 1); // one required signature
    }
}
