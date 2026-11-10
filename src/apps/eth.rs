//! Ethereum app client.
//!
//! Transactions are built with [`outscript::EvmTx`] (re-exported as
//! [`EvmTx`]); the device signs [`EvmTx::sign_bytes`] and
//! [`EthApp::sign_tx`] writes the signature back into the transaction, ready
//! to be serialized with [`EvmTx::to_bytes`] and broadcast.

use num_bigint::{BigInt, Sign};

use crate::apdu::{Apdu, Reader, StatusWord};
use crate::device::Device;
use crate::error::{Error, Result};
use crate::path::DerivationPath;
use crate::transport::Transport;

pub use outscript::evmabi::AbiValue;
pub use outscript::evmtx::{EvmTx, EvmTxType};

const CLA: u8 = 0xe0;
const INS_GET_PUBLIC_KEY: u8 = 0x02;
const INS_SIGN: u8 = 0x04;
const INS_GET_CONFIGURATION: u8 = 0x06;
const INS_SIGN_PERSONAL_MESSAGE: u8 = 0x08;
const INS_SIGN_EIP712_HASHED: u8 = 0x0c;
const MAX_CHUNK: usize = 255;

/// Default derivation path for the first account.
pub const DEFAULT_PATH: &str = "m/44'/60'/0'/0/0";

/// Result of `GET_PUBLIC_KEY`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct EthAddress {
    /// Uncompressed public key (hex, 65 bytes).
    pub public_key: String,
    /// EIP-55 checksummed address.
    pub address: String,
    /// Chain code (hex), when requested.
    pub chain_code: Option<String>,
}

/// App configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct EthConfig {
    /// Blind signing ("contract data") allowed.
    pub blind_signing_enabled: bool,
    pub erc20_provisioning_necessary: bool,
    pub stark_enabled: bool,
    pub stark_v2_supported: bool,
    pub version: String,
}

/// An ECDSA signature as returned by the app.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EthSignature {
    /// Full `v` value (EIP-155 applied for legacy transactions, parity for typed ones).
    pub v: u64,
    #[cfg_attr(feature = "serde", serde(with = "hex32"))]
    pub r: [u8; 32],
    #[cfg_attr(feature = "serde", serde(with = "hex32"))]
    pub s: [u8; 32],
}

#[cfg(feature = "serde")]
mod hex32 {
    pub fn serialize<S: serde::Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
}

impl EthSignature {
    /// `r || s || v` (65 bytes, `v` as one byte), the usual message signature encoding.
    pub fn to_rsv(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&self.r);
        out.extend_from_slice(&self.s);
        out.push(self.v as u8);
        out
    }
}

/// Ethereum app client.
pub struct EthApp<'d, T: Transport> {
    device: &'d Device<T>,
}

fn map_sign_err(sw: StatusWord) -> Error {
    match sw.0 {
        0x6985 | 0x5501 => Error::UserRefused,
        0x6a80 => Error::App(
            "blind signing must be enabled in the Ethereum app settings (or invalid data)".into(),
        ),
        0x6d00 | 0x6e00 | 0x6e01 => Error::App("the Ethereum app is not open".into()),
        _ => sw.into(),
    }
}

impl<'d, T: Transport> EthApp<'d, T> {
    pub fn new(device: &'d Device<T>) -> Self {
        Self { device }
    }

    async fn send(&self, apdu: Apdu) -> Result<Vec<u8>> {
        let r = self.device.exchange(&apdu).await?;
        if r.sw.is_ok() {
            Ok(r.data)
        } else {
            Err(map_sign_err(r.sw))
        }
    }

    /// App configuration and version.
    pub async fn get_configuration(&self) -> Result<EthConfig> {
        let d = self
            .send(Apdu::new(CLA, INS_GET_CONFIGURATION, 0, 0))
            .await?;
        if d.len() < 4 {
            return Err(Error::InvalidResponse("configuration too short".into()));
        }
        Ok(EthConfig {
            blind_signing_enabled: d[0] & 0x01 != 0,
            erc20_provisioning_necessary: d[0] & 0x02 != 0,
            stark_enabled: d[0] & 0x04 != 0,
            stark_v2_supported: d[0] & 0x08 != 0,
            version: format!("{}.{}.{}", d[1], d[2], d[3]),
        })
    }

    /// Derive an address. With `display`, the user must confirm it on screen.
    pub async fn get_address(
        &self,
        path: &DerivationPath,
        display: bool,
        chain_code: bool,
    ) -> Result<EthAddress> {
        let d = self
            .send(Apdu::with_data(
                CLA,
                INS_GET_PUBLIC_KEY,
                display as u8,
                chain_code as u8,
                path.encode(),
            ))
            .await?;
        let mut r = Reader::new(&d);
        let public_key = hex::encode(r.lv()?);
        let addr_ascii = String::from_utf8_lossy(r.lv()?).into_owned();
        let raw = hex::decode(addr_ascii.trim_start_matches("0x"))
            .map_err(|e| Error::InvalidResponse(format!("address: {e}")))?;
        let chain_code = if chain_code {
            Some(hex::encode(r.bytes(32)?))
        } else {
            None
        };
        Ok(EthAddress {
            public_key,
            address: outscript::address::eip55(&raw),
            chain_code,
        })
    }

    /// Sign raw unsigned transaction bytes (as produced by [`EvmTx::sign_bytes`]).
    pub async fn sign_transaction(
        &self,
        path: &DerivationPath,
        unsigned_tx: &[u8],
    ) -> Result<EthSignature> {
        let (chain_id, typed) = unsigned_tx_info(unsigned_tx)?;
        let mut payload = path.encode();
        payload.extend_from_slice(unsigned_tx);
        let chunks = safe_chunks(&payload, if typed { None } else { Some(chain_id) });
        let mut resp = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let p1 = if i == 0 { 0x00 } else { 0x80 };
            resp = self
                .send(Apdu::with_data(CLA, INS_SIGN, p1, 0x00, chunk.to_vec()))
                .await?;
        }
        parse_signature(&resp, Some((chain_id, typed)))
    }

    /// Sign an [`EvmTx`] and store the signature in it.
    pub async fn sign_tx(&self, path: &DerivationPath, tx: &mut EvmTx) -> Result<EthSignature> {
        tx.signed = false;
        let unsigned = tx
            .sign_bytes()
            .map_err(|e| Error::InvalidInput(format!("{e:?}")))?;
        let sig = self.sign_transaction(path, &unsigned).await?;
        tx.signed = true;
        tx.y = BigInt::from(sig.v);
        tx.r = BigInt::from_bytes_be(Sign::Plus, &sig.r);
        tx.s = BigInt::from_bytes_be(Sign::Plus, &sig.s);
        Ok(sig)
    }

    /// `personal_sign` (EIP-191) a message.
    pub async fn sign_personal_message(
        &self,
        path: &DerivationPath,
        message: &[u8],
    ) -> Result<EthSignature> {
        let mut payload = path.encode();
        payload.extend_from_slice(&(message.len() as u32).to_be_bytes());
        payload.extend_from_slice(message);
        let mut resp = Vec::new();
        for (i, chunk) in payload.chunks(MAX_CHUNK).enumerate() {
            let p1 = if i == 0 { 0x00 } else { 0x80 };
            resp = self
                .send(Apdu::with_data(
                    CLA,
                    INS_SIGN_PERSONAL_MESSAGE,
                    p1,
                    0x00,
                    chunk.to_vec(),
                ))
                .await?;
        }
        parse_signature(&resp, None)
    }

    /// Sign EIP-712 typed data given its domain separator and message hashes
    /// (blind signing of the hashes).
    pub async fn sign_eip712_hashed(
        &self,
        path: &DerivationPath,
        domain_separator: &[u8; 32],
        message_hash: &[u8; 32],
    ) -> Result<EthSignature> {
        let mut payload = path.encode();
        payload.extend_from_slice(domain_separator);
        payload.extend_from_slice(message_hash);
        let resp = self
            .send(Apdu::with_data(
                CLA,
                INS_SIGN_EIP712_HASHED,
                0x00,
                0x00,
                payload,
            ))
            .await?;
        parse_signature(&resp, None)
    }
}

/// Build the signed encoding of an unsigned transaction and its signature.
pub fn assemble_signed(unsigned: &[u8], sig: &EthSignature) -> Result<Vec<u8>> {
    use outscript::rlp::{RlpItem, decode_one, encode_list};
    let (_, typed) = unsigned_tx_info(unsigned)?;
    let trim = |b: &[u8]| -> Vec<u8> { b.iter().skip_while(|x| **x == 0).copied().collect() };
    if typed {
        let mut tx = EvmTx::parse_transaction(unsigned)
            .map_err(|e| Error::InvalidInput(format!("{e:?}")))?;
        tx.signed = true;
        tx.y = BigInt::from(sig.v);
        tx.r = BigInt::from_bytes_be(Sign::Plus, &sig.r);
        tx.s = BigInt::from_bytes_be(Sign::Plus, &sig.s);
        return tx
            .to_bytes()
            .map_err(|e| Error::InvalidInput(format!("{e:?}")));
    }
    let (item, _) = decode_one(unsigned).map_err(|e| Error::InvalidInput(format!("{e:?}")))?;
    let mut fields = item
        .as_list()
        .ok_or_else(|| Error::InvalidInput("not a list".into()))?[..6]
        .to_vec();
    fields.push(RlpItem::uint(sig.v));
    fields.push(RlpItem::Bytes(trim(&sig.r)));
    fields.push(RlpItem::Bytes(trim(&sig.s)));
    Ok(encode_list(&fields))
}

/// Chain id and "typed" flag of an unsigned transaction encoding.
///
/// Unsigned legacy transactions end with the EIP-155 `(chain_id, 0, 0)`
/// trailer (or nothing for pre-EIP-155), which must not be read as `v, r, s`.
fn unsigned_tx_info(unsigned: &[u8]) -> Result<(u64, bool)> {
    let bad = |e: String| Error::InvalidInput(format!("invalid transaction: {e}"));
    match unsigned.first() {
        Some(&b) if b >= 0xc0 => {
            let (item, rest) =
                outscript::rlp::decode_one(unsigned).map_err(|e| bad(format!("{e:?}")))?;
            if !rest.is_empty() {
                return Err(bad("trailing data".into()));
            }
            let fields = item.as_list().ok_or_else(|| bad("not a list".into()))?;
            match fields.len() {
                6 => Ok((0, false)),
                9 => {
                    let cid = fields[6]
                        .as_bytes()
                        .ok_or_else(|| bad("bad chain id".into()))?;
                    let cid = outscript::rlp::decode_uint64_checked(cid)
                        .map_err(|e| bad(format!("{e:?}")))?;
                    Ok((cid, false))
                }
                n => Err(bad(format!("unexpected legacy field count {n}"))),
            }
        }
        Some(&t) if t < 0x80 => {
            let tx = EvmTx::parse_transaction(unsigned).map_err(|e| bad(format!("{e:?}")))?;
            if tx.signed {
                return Err(bad("transaction is already signed".into()));
            }
            Ok((tx.chain_id, true))
        }
        _ => Err(bad("empty or malformed".into())),
    }
}

/// Parse `v(1) r(32) s(32)`. `tx` = `(chain_id, typed)` to reconstruct `v`.
fn parse_signature(resp: &[u8], tx: Option<(u64, bool)>) -> Result<EthSignature> {
    if resp.len() < 65 {
        return Err(Error::InvalidResponse("signature too short".into()));
    }
    let v_dev = resp[0];
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&resp[1..33]);
    s.copy_from_slice(&resp[33..65]);
    let v = match tx {
        None => v_dev as u64,
        Some((_, true)) => (v_dev & 1) as u64,
        Some((0, false)) => v_dev as u64,
        Some((chain_id, false)) => {
            // The app only returns one byte: chain_id (truncated to its 4 most
            // significant bytes) * 2 + 35 + parity, modulo 256.
            let bytes = chain_id.to_be_bytes();
            let first = bytes.iter().position(|b| *b != 0).unwrap_or(7);
            let trunc = &bytes[first..(first + 4).min(8)];
            let cid32 = trunc.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
            let base = (cid32 * 2 + 35) % 256;
            let parity = if base == v_dev as u64 {
                0
            } else if (base + 1) % 256 == v_dev as u64 {
                1
            } else {
                return Err(Error::InvalidResponse(format!(
                    "unexpected v value {v_dev}"
                )));
            };
            chain_id
                .checked_mul(2)
                .and_then(|x| x.checked_add(35 + parity))
                .ok_or_else(|| Error::InvalidInput("chain id too large".into()))?
        }
    };
    Ok(EthSignature { v, r, s })
}

/// Split `path || rlp` in 255 byte chunks. For legacy transactions, avoid a
/// chunk boundary that would let the app believe the RLP ends before the
/// EIP-155 `(chain_id, 0, 0)` trailer.
fn safe_chunks(payload: &[u8], legacy_chain_id: Option<u64>) -> Vec<&[u8]> {
    if payload.len() <= MAX_CHUNK {
        return vec![payload];
    }
    let mut size = MAX_CHUNK;
    if let Some(chain_id) = legacy_chain_id {
        let cid_len = if chain_id < 0x80 {
            1
        } else {
            1 + (8 - chain_id.leading_zeros() as usize / 8)
        };
        let vrs_len = cid_len + 2;
        let ok = |sz: usize| {
            let last = payload.len() % sz;
            last == 0 || last > vrs_len
        };
        if !ok(size) {
            size = (1..MAX_CHUNK)
                .map(|i| MAX_CHUNK - i)
                .find(|sz| ok(*sz))
                .unwrap_or(MAX_CHUNK);
        }
    }
    payload.chunks(size).collect()
}

/// Parse a decimal amount (`"1.5"`) into base units with `decimals` digits.
pub fn parse_units(amount: &str, decimals: u32) -> Result<BigInt> {
    let amount = amount.trim();
    let (int, frac) = amount.split_once('.').unwrap_or((amount, ""));
    if frac.len() > decimals as usize {
        return Err(Error::InvalidInput(format!(
            "too many decimals in {amount:?}"
        )));
    }
    if int.is_empty() && frac.is_empty() {
        return Err(Error::InvalidInput("empty amount".into()));
    }
    let digits = format!("{int}{frac:0<width$}", width = decimals as usize);
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidInput(format!("invalid amount {amount:?}")));
    }
    BigInt::parse_bytes(
        if digits.is_empty() {
            b"0"
        } else {
            digits.as_bytes()
        },
        10,
    )
    .ok_or_else(|| Error::InvalidInput(format!("invalid amount {amount:?}")))
}

/// Build the calldata of an ERC-20 `transfer(to, amount)`.
pub fn erc20_transfer_data(to: &str, amount: &BigInt) -> Result<Vec<u8>> {
    let to = outscript::address::parse_evm_address(to)
        .map_err(|e| Error::InvalidInput(format!("{e:?}")))?;
    let mut tx = EvmTx::default();
    tx.call(
        "transfer(address,uint256)",
        &[AbiValue::Out(to), AbiValue::Uint(amount.clone())],
    )
    .map_err(|e| Error::InvalidInput(format!("{e:?}")))?;
    Ok(tx.data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v_reconstruction() {
        // chain id 1: v = 37/38
        let mut resp = vec![37u8];
        resp.extend_from_slice(&[0; 64]);
        assert_eq!(parse_signature(&resp, Some((1, false))).unwrap().v, 37);
        // large chain id 137 (polygon): 137*2+35 = 309 -> 309 % 256 = 53
        resp[0] = 54;
        assert_eq!(parse_signature(&resp, Some((137, false))).unwrap().v, 310);
        resp[0] = 1;
        assert_eq!(parse_signature(&resp, Some((1, true))).unwrap().v, 1);
    }

    #[test]
    fn unsigned_info() {
        for (ty, cid) in [
            (EvmTxType::Legacy, 137u64),
            (EvmTxType::Legacy, 1),
            (EvmTxType::Eip1559, 8453),
        ] {
            let tx = EvmTx {
                tx_type: ty,
                chain_id: cid,
                nonce: 1,
                gas: 21000,
                gas_fee_cap: BigInt::from(1),
                to: "0x0000000000000000000000000000000000000001".into(),
                ..Default::default()
            };
            let b = tx.sign_bytes().unwrap();
            assert_eq!(
                unsigned_tx_info(&b).unwrap(),
                (cid, ty != EvmTxType::Legacy)
            );
        }
    }

    #[test]
    fn assemble_matches_evmtx() {
        let mut tx = EvmTx {
            tx_type: EvmTxType::Legacy,
            chain_id: 137,
            nonce: 3,
            gas: 21000,
            gas_fee_cap: BigInt::from(30_000_000_000u64),
            to: "0x0000000000000000000000000000000000000001".into(),
            value: BigInt::from(5),
            ..Default::default()
        };
        let unsigned = tx.sign_bytes().unwrap();
        let sig = EthSignature {
            v: 310,
            r: [1; 32],
            s: [2; 32],
        };
        tx.signed = true;
        tx.y = BigInt::from(310);
        tx.r = BigInt::from_bytes_be(Sign::Plus, &[1; 32]);
        tx.s = BigInt::from_bytes_be(Sign::Plus, &[2; 32]);
        assert_eq!(
            assemble_signed(&unsigned, &sig).unwrap(),
            tx.to_bytes().unwrap()
        );
    }

    #[test]
    fn units() {
        assert_eq!(
            parse_units("1.5", 18).unwrap().to_string(),
            "1500000000000000000"
        );
        assert_eq!(parse_units("0.000001", 6).unwrap().to_string(), "1");
        assert!(parse_units("1.0000001", 6).is_err());
    }

    #[test]
    fn erc20() {
        let d = erc20_transfer_data(
            "0x0000000000000000000000000000000000000001",
            &BigInt::from(5),
        )
        .unwrap();
        assert_eq!(&d[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(d.len(), 4 + 64);
    }

    #[test]
    fn chunks() {
        let p = vec![0u8; 600];
        let c = safe_chunks(&p, Some(1));
        assert!(c.iter().all(|c| c.len() <= 255));
        assert!(c.last().unwrap().len() > 3);
    }
}
