//! Bitcoin app client (app version 2.1+).
//!
//! The app works with wallet policies and PSBTs. PSBTs are parsed, built
//! and finalized with outscript ([`psbt::build_psbt`],
//! [`psbt::finalize_and_extract`]); this module drives the device side,
//! including the merkleized "client command" protocol ([`merkle`]).
//!
//! Address check: the app derives addresses itself and can display them for
//! verification. For default single-sig policies the client also checks the
//! returned address against one derived locally from the account xpub
//! ([`BtcApp::get_wallet_address_checked`]).

pub mod bip32;
pub mod merkle;
pub mod psbt;
pub mod wallet;

use crate::apdu::{Apdu, StatusWord};
use crate::device::Device;
use crate::error::{Error, Result};
use crate::path::DerivationPath;
use crate::transport::Transport;

pub use bip32::Xpub;
pub use psbt::{PartialSignature, Payment, Utxo};
pub use wallet::{AddressType, KeyInfo, WalletPolicy};

use merkle::{Interpreter, map_commitment};

const CLA: u8 = 0xe1;
const CLA_FRAMEWORK: u8 = 0xf8;
const P2_PROTOCOL: u8 = 0x01;
const INS_GET_EXTENDED_PUBKEY: u8 = 0x00;
const INS_REGISTER_WALLET: u8 = 0x02;
const INS_GET_WALLET_ADDRESS: u8 = 0x03;
const INS_SIGN_PSBT: u8 = 0x04;
const INS_GET_MASTER_FINGERPRINT: u8 = 0x05;
const INS_SIGN_MESSAGE: u8 = 0x10;
const INS_CONTINUE: u8 = 0x01;
const SW_INTERRUPTED: u16 = 0xe000;

/// Bitcoin compact size integers.
pub mod varint {
    pub fn encode(n: u64) -> Vec<u8> {
        match n {
            0..=0xfc => vec![n as u8],
            0xfd..=0xffff => {
                let mut v = vec![0xfd];
                v.extend_from_slice(&(n as u16).to_le_bytes());
                v
            }
            0x1_0000..=0xffff_ffff => {
                let mut v = vec![0xfe];
                v.extend_from_slice(&(n as u32).to_le_bytes());
                v
            }
            _ => {
                let mut v = vec![0xff];
                v.extend_from_slice(&n.to_le_bytes());
                v
            }
        }
    }

    /// Decode, returning the value and the number of bytes read.
    pub fn decode(d: &[u8]) -> Option<(u64, usize)> {
        let first = *d.first()?;
        Some(match first {
            0xfd => (u16::from_le_bytes(d.get(1..3)?.try_into().ok()?) as u64, 3),
            0xfe => (u32::from_le_bytes(d.get(1..5)?.try_into().ok()?) as u64, 5),
            0xff => (u64::from_le_bytes(d.get(1..9)?.try_into().ok()?), 9),
            n => (n as u64, 1),
        })
    }
}

fn map_sw(sw: StatusWord) -> Error {
    match sw.0 {
        0x6985 | 0x5501 => Error::UserRefused,
        0x6d00 | 0x6e00 | 0x6e01 => Error::App("the Bitcoin app is not open".into()),
        0xb007 => Error::App("bad state (wallet policy not registered or invalid PSBT)".into()),
        0xb008 => Error::App("signature failed".into()),
        0x6a80 => Error::App("incorrect data (check the PSBT / wallet policy)".into()),
        0x6a82 => Error::App("not supported by this app version".into()),
        _ => sw.into(),
    }
}

/// Bitcoin app client.
pub struct BtcApp<'d, T: Transport> {
    device: &'d Device<T>,
}

impl<'d, T: Transport> BtcApp<'d, T> {
    pub fn new(device: &'d Device<T>) -> Self {
        Self { device }
    }

    async fn request(
        &self,
        ins: u8,
        data: Vec<u8>,
        mut interp: Option<&mut Interpreter>,
    ) -> Result<Vec<u8>> {
        let mut r = self
            .device
            .exchange(&Apdu::with_data(CLA, ins, 0x00, P2_PROTOCOL, data))
            .await?;
        while r.sw.0 == SW_INTERRUPTED {
            let it = interp
                .as_deref_mut()
                .ok_or_else(|| Error::App("unexpected client command from the app".into()))?;
            let reply = it.execute(&r.data)?;
            r = self
                .device
                .exchange(&Apdu::with_data(
                    CLA_FRAMEWORK,
                    INS_CONTINUE,
                    0x00,
                    P2_PROTOCOL,
                    reply,
                ))
                .await?;
        }
        if r.sw.is_ok() {
            Ok(r.data)
        } else {
            Err(map_sw(r.sw))
        }
    }

    fn interpreter_for(policy: &WalletPolicy) -> Interpreter {
        let mut it = Interpreter::new();
        it.add_preimage(policy.serialize());
        it.add_list(&policy.key_strings());
        it.add_preimage(policy.descriptor_template.as_bytes().to_vec());
        it
    }

    /// Master key fingerprint.
    pub async fn get_master_fingerprint(&self) -> Result<[u8; 4]> {
        let d = self
            .request(INS_GET_MASTER_FINGERPRINT, Vec::new(), None)
            .await?;
        d.get(..4)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| Error::InvalidResponse("fingerprint".into()))
    }

    /// Extended public key at `path` (base58 string). With `display`, shown on screen.
    pub async fn get_extended_pubkey(
        &self,
        path: &DerivationPath,
        display: bool,
    ) -> Result<String> {
        let mut data = vec![display as u8];
        data.extend(path.encode());
        let d = self.request(INS_GET_EXTENDED_PUBKEY, data, None).await?;
        Ok(String::from_utf8_lossy(&d).into_owned())
    }

    /// Key information (`[fpr/path]xpub`) of an account, to build a policy.
    pub async fn get_account_key(
        &self,
        kind: AddressType,
        testnet: bool,
        account: u32,
    ) -> Result<KeyInfo> {
        let fpr = self.get_master_fingerprint().await?;
        let path = kind.account_path(testnet, account);
        let xpub = self.get_extended_pubkey(&path, false).await?;
        Ok(KeyInfo::new(fpr, path, xpub))
    }

    /// Default single-sig policy for an account.
    pub async fn default_policy(
        &self,
        kind: AddressType,
        testnet: bool,
        account: u32,
    ) -> Result<WalletPolicy> {
        Ok(WalletPolicy::default_single_sig(
            kind,
            self.get_account_key(kind, testnet, account).await?,
        ))
    }

    /// Register a (non-default) wallet policy. Returns `(policy id, hmac)`.
    pub async fn register_wallet(&self, policy: &WalletPolicy) -> Result<([u8; 32], [u8; 32])> {
        let ser = policy.serialize();
        let mut data = varint::encode(ser.len() as u64);
        data.extend(ser);
        let mut it = Self::interpreter_for(policy);
        let d = self
            .request(INS_REGISTER_WALLET, data, Some(&mut it))
            .await?;
        if d.len() < 64 {
            return Err(Error::InvalidResponse("register_wallet".into()));
        }
        Ok((d[..32].try_into().unwrap(), d[32..64].try_into().unwrap()))
    }

    /// Address of a policy at `change/index`.
    pub async fn get_wallet_address(
        &self,
        policy: &WalletPolicy,
        hmac: Option<&[u8; 32]>,
        change: bool,
        index: u32,
        display: bool,
    ) -> Result<String> {
        let mut data = vec![display as u8];
        data.extend_from_slice(&policy.id());
        data.extend_from_slice(hmac.unwrap_or(&[0u8; 32]));
        data.push(change as u8);
        data.extend_from_slice(&index.to_be_bytes());
        let mut it = Self::interpreter_for(policy);
        let d = self
            .request(INS_GET_WALLET_ADDRESS, data, Some(&mut it))
            .await?;
        Ok(String::from_utf8_lossy(&d).into_owned())
    }

    /// Like [`BtcApp::get_wallet_address`] for a default single-sig policy,
    /// also checking the address against a local derivation.
    pub async fn get_wallet_address_checked(
        &self,
        kind: AddressType,
        testnet: bool,
        key: &KeyInfo,
        change: bool,
        index: u32,
        display: bool,
    ) -> Result<String> {
        let policy = WalletPolicy::default_single_sig(kind, key.clone());
        let addr = self
            .get_wallet_address(&policy, None, change, index, display)
            .await?;
        let xpub = Xpub::parse(&key.xpub)?;
        let (_, local, _) = psbt::derive_script(&xpub, kind, testnet, change as u32, index)?;
        if local != addr {
            return Err(Error::App(format!(
                "address mismatch: device {addr}, local {local}"
            )));
        }
        Ok(addr)
    }

    /// Sign a PSBT (v0 or v2 bytes). Returns the signatures the app produced;
    /// use [`psbt::insert_signatures`] then [`psbt::finalize_and_extract`].
    pub async fn sign_psbt(
        &self,
        psbt_bytes: &[u8],
        policy: &WalletPolicy,
        hmac: Option<&[u8; 32]>,
    ) -> Result<Vec<PartialSignature>> {
        let maps = psbt::v2_maps(psbt_bytes)?;
        let mut it = Self::interpreter_for(policy);
        it.add_map(&maps.global);
        let global_commitment = map_commitment(&maps.global);
        let mut input_commitments = Vec::with_capacity(maps.inputs.len());
        for m in &maps.inputs {
            it.add_map(m);
            input_commitments.push(map_commitment(m));
        }
        let inputs_root = it.add_list(&input_commitments);
        let mut output_commitments = Vec::with_capacity(maps.outputs.len());
        for m in &maps.outputs {
            it.add_map(m);
            output_commitments.push(map_commitment(m));
        }
        let outputs_root = it.add_list(&output_commitments);

        let mut data = global_commitment;
        data.extend(varint::encode(maps.inputs.len() as u64));
        data.extend_from_slice(&inputs_root);
        data.extend(varint::encode(maps.outputs.len() as u64));
        data.extend_from_slice(&outputs_root);
        data.extend_from_slice(&policy.id());
        data.extend_from_slice(hmac.unwrap_or(&[0u8; 32]));
        self.request(INS_SIGN_PSBT, data, Some(&mut it)).await?;
        it.into_yielded()
            .iter()
            .map(|y| psbt::parse_yielded(y))
            .collect()
    }

    /// Sign a PSBT and insert the signatures, returning the updated PSBT.
    pub async fn sign_psbt_into(
        &self,
        psbt_bytes: &[u8],
        policy: &WalletPolicy,
        hmac: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>> {
        let sigs = self.sign_psbt(psbt_bytes, policy, hmac).await?;
        psbt::insert_signatures(psbt_bytes, &sigs)
    }

    /// Sign a message (BIP-137 style). Returns the 65-byte signature
    /// (`header || r || s`); base64 it for the usual text form.
    pub async fn sign_message(&self, path: &DerivationPath, message: &[u8]) -> Result<[u8; 65]> {
        let chunks: Vec<&[u8]> = message.chunks(64).collect();
        let mut it = Interpreter::new();
        let root = it.add_list(&chunks);
        let mut data = path.encode();
        data.extend(varint::encode(message.len() as u64));
        data.extend_from_slice(&root);
        let d = self.request(INS_SIGN_MESSAGE, data, Some(&mut it)).await?;
        d.as_slice()
            .try_into()
            .map_err(|_| Error::InvalidResponse("bad message signature length".into()))
    }
}
