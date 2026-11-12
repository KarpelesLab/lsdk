//! Legacy BTChip family: Ledger HW.1 and the original Nano (USB vendor
//! [`crate::LEGACY_VENDOR_ID`]).
//!
//! These devices predate the dashboard: a single Bitcoin applet speaking the
//! BTChip protocol (`CLA E0`, "Ledger Wallet 1.0" technical specification).
//! They have no screen: an operation needing approval (message or
//! transaction) is confirmed by power cycling the dongle, which then **types**
//! a summary and a one-time code as a USB keyboard; the host sends that code
//! back to finish. The pending operation survives the power cycles.
//!
//! * [`BtchipWallet::firmware`], [`BtchipWallet::operation_mode`],
//!   [`BtchipWallet::pin_attempts`], [`BtchipWallet::attestation`]: info.
//! * [`BtchipWallet::setup`]: first setup of a new or wiped dongle (PIN and,
//!   optionally, a seed restored from a BIP-39 phrase: [`bip39_seed`]).
//! * [`BtchipWallet::verify_pin`]: unlock; **3 wrong PINs erase the dongle**,
//!   and it must be replugged after each wrong PIN.
//! * [`BtchipWallet::wallet_public_key`]: public key and (legacy, Base58)
//!   address of a BIP32 path.
//! * Message signing ([`BtchipWallet::sign_message_prepare`]) and P2PKH
//!   transaction signing ([`TxSigner`]).

use purecrypto::hash::{HmacSha512, ripemd160, sha256};

use crate::apdu::{Apdu, StatusWord};
use crate::device::Device;
use crate::error::{Error, Result};
use crate::path::DerivationPath;
use crate::transport::Transport;

const CLA: u8 = 0xe0;
const INS_SETUP: u8 = 0x20;
const INS_VERIFY_PIN: u8 = 0x22;
const INS_GET_OPERATION_MODE: u8 = 0x24;
const INS_SET_KEYBOARD: u8 = 0x28;
const INS_GET_WALLET_PUBLIC_KEY: u8 = 0x40;
const INS_GET_TRUSTED_INPUT: u8 = 0x42;
const INS_HASH_INPUT_START: u8 = 0x44;
const INS_HASH_INPUT_FINALIZE: u8 = 0x46;
const INS_HASH_SIGN: u8 = 0x48;
const INS_SIGN_MESSAGE: u8 = 0x4e;
const INS_GET_ATTESTATION: u8 = 0xc2;
const INS_GET_FIRMWARE_VERSION: u8 = 0xc4;

/// Status of most commands before setup (and of PIN-protected ones before
/// the PIN is entered).
const SW_CONDITIONS: StatusWord = StatusWord(0x6985);

/// Operation modes (bitflags, for [`Setup::modes`] and
/// [`BtchipWallet::operation_mode`]).
pub mod mode {
    pub const WALLET: u8 = 0x01;
    pub const RELAXED_WALLET: u8 = 0x02;
    pub const SERVER: u8 = 0x04;
    pub const DEVELOPER: u8 = 0x08;
}

/// Setup features (bitflags, for [`Setup::features`]).
pub mod feature {
    pub const UNCOMPRESSED_KEYS: u8 = 0x01;
    pub const RFC6979: u8 = 0x02;
    pub const FREE_SIGHASH: u8 = 0x04;
    pub const NO_2FA_P2SH: u8 = 0x08;
}

/// Default QWERTY keymap (spec "KeymapEncoding"), used to type confirmations.
pub const QWERTY_KEYMAP: [u8; 119] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x76, 0x0f, 0x00, 0xd4, 0xff, 0xff, 0xff, 0xc7, 0x00, 0x00,
    0x00, 0x78, 0x2c, 0x1e, 0x34, 0x20, 0x21, 0x22, 0x24, 0x34, 0x26, 0x27, 0x25, 0x2e, 0x36, 0x2d,
    0x37, 0x38, 0x27, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x33, 0x33, 0x36, 0x2e,
    0x37, 0x38, 0x1f, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x2f, 0x31, 0x30,
    0x23, 0x2d, 0x35, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x2f, 0x31, 0x30,
    0x35,
];

/// `GET FIRMWARE VERSION`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct FirmwareInfo {
    /// `x.y.z`.
    pub version: String,
    /// Public keys and addresses are compressed.
    pub compressed_keys: bool,
    /// Raw features flag (0x02/0x04 screen, 0x08 NFC, 0x10 BLE, 0x20 TEE).
    pub features: u8,
    /// Architecture byte (since Ledger Wallet 1.0).
    pub architecture: u8,
    /// Loader version `x.y`, when reported.
    pub loader: Option<String>,
}

/// `GET DEVICE ATTESTATION`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Attestation {
    pub batch_id: u32,
    pub derivation_index: u32,
    pub architecture: u8,
    pub firmware: String,
    pub loader: String,
    /// Supported operation modes (0 before setup).
    pub supported_modes: u8,
    /// Current operation mode (0xff before setup).
    pub current_mode: u8,
    /// The 8-byte challenge that was signed with the 8 info bytes before it.
    #[cfg_attr(feature = "serde", serde(serialize_with = "ser_hex"))]
    pub blob: Vec<u8>,
    /// DER signature by the batch attestation key.
    #[cfg_attr(feature = "serde", serde(serialize_with = "ser_hex"))]
    pub signature: Vec<u8>,
}

/// `GET WALLET PUBLIC KEY`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct WalletPublicKey {
    /// Uncompressed public key (65 bytes), as returned.
    #[cfg_attr(feature = "serde", serde(serialize_with = "ser_hex"))]
    pub public_key: Vec<u8>,
    /// Base58 address (compressed or not, as set up).
    pub address: String,
    #[cfg_attr(feature = "serde", serde(serialize_with = "ser_hex"))]
    pub chain_code: Vec<u8>,
}

#[cfg(feature = "serde")]
fn ser_hex<S: serde::Serializer>(v: &[u8], s: S) -> core::result::Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(v))
}

/// First setup parameters. [`Setup::new`] has the defaults Ledger's own setup
/// used: standard wallet mode, RFC 6979 signatures, Bitcoin mainnet.
#[derive(Clone, Debug)]
pub struct Setup {
    /// Allowed operation modes ([`mode`]).
    pub modes: u8,
    /// [`feature`] flags.
    pub features: u8,
    /// Address version byte (0 = Bitcoin mainnet, 111 = testnet).
    pub key_version: u8,
    /// P2SH version byte (5 = Bitcoin mainnet, 196 = testnet), 0 to disable.
    pub p2sh_version: u8,
    /// User PIN, 4 to 32 bytes.
    pub pin: String,
    /// Optional secondary PIN (up to 4 bytes) opening a random decoy wallet.
    pub secondary_pin: Option<String>,
    /// BIP32 seed to restore (32 to 64 bytes); `None` lets the dongle
    /// generate one, which it then **types** on later power-ups until the PIN
    /// is entered.
    pub seed: Option<Vec<u8>>,
}

impl Setup {
    pub fn new(pin: impl Into<String>, seed: Option<Vec<u8>>) -> Self {
        Self {
            modes: mode::WALLET,
            features: feature::RFC6979,
            key_version: 0x00,
            p2sh_version: 0x05,
            pin: pin.into(),
            secondary_pin: None,
            seed,
        }
    }
}

/// Outcome of a step needing the user's confirmation code.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Confirmation {
    /// 0x01 keyboard (power cycle, then the dongle types a code), 0x02 security
    /// card, 0x03 secure screen.
    pub kind: u8,
    /// Extra data for card / screen validation (card indexes...).
    #[cfg_attr(feature = "serde", serde(serialize_with = "ser_hex"))]
    pub data: Vec<u8>,
}

/// Client for a BTChip-family dongle.
pub struct BtchipWallet<'d, T: Transport> {
    device: &'d Device<T>,
}

fn path_bytes(path: &DerivationPath) -> Result<Vec<u8>> {
    if path.components().len() > 10 {
        return Err(Error::InvalidInput("at most 10 derivation levels".into()));
    }
    Ok(path.encode())
}

fn lv(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > 255 {
        return Err(Error::InvalidInput("field too long".into()));
    }
    let mut v = vec![data.len() as u8];
    v.extend_from_slice(data);
    Ok(v)
}

fn pin_error(sw: StatusWord) -> Error {
    if sw.0 & 0xfff0 == 0x63c0 {
        Error::App(format!(
            "wrong PIN, {} attempt(s) left before the dongle erases itself; unplug and replug it before trying again",
            sw.0 & 0x0f
        ))
    } else {
        sw.into()
    }
}

impl<'d, T: Transport> BtchipWallet<'d, T> {
    pub fn new(device: &'d Device<T>) -> Self {
        Self { device }
    }

    async fn send(&self, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Result<Vec<u8>> {
        let r = self
            .device
            .exchange(&Apdu::with_data(CLA, ins, p1, p2, data))
            .await?;
        match r.sw {
            StatusWord::OK => Ok(r.data),
            sw => Err(sw.into()),
        }
    }

    /// Firmware version and features (always available).
    pub async fn firmware(&self) -> Result<FirmwareInfo> {
        let r = self.send(INS_GET_FIRMWARE_VERSION, 0, 0, vec![]).await?;
        if r.len() < 5 {
            return Err(Error::InvalidResponse("short firmware version".into()));
        }
        Ok(FirmwareInfo {
            version: format!("{}.{}.{}", r[2], r[3], r[4]),
            compressed_keys: r[0] & 0x01 != 0,
            features: r[0],
            architecture: r[1],
            loader: (r.len() >= 7).then(|| format!("{}.{}", r[5], r[6])),
        })
    }

    /// Current operation mode ([`mode`] flags; 0x80 set while a forward setup
    /// seed is unredeemed), `None` when the dongle is not set up yet.
    pub async fn operation_mode(&self) -> Result<Option<u8>> {
        match self.send(INS_GET_OPERATION_MODE, 0, 0, vec![]).await {
            Ok(r) => Ok(r.first().copied()),
            Err(Error::Status(SW_CONDITIONS)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Second factor in use: 0x11 keyboard, 0x12 security card, 0x13 card and
    /// secure screen.
    pub async fn second_factor(&self) -> Result<u8> {
        let r = self.send(INS_GET_OPERATION_MODE, 1, 0, vec![]).await?;
        r.first()
            .copied()
            .ok_or_else(|| Error::InvalidResponse("empty second factor".into()))
    }

    /// Remaining PIN attempts, `None` when the dongle is not set up.
    pub async fn pin_attempts(&self) -> Result<Option<u8>> {
        match self.send(INS_VERIFY_PIN, 0x80, 0, b"0".to_vec()).await {
            Ok(_) => Ok(None),
            Err(Error::Status(sw)) if sw.0 & 0xfff0 == 0x63c0 => Ok(Some((sw.0 & 0x0f) as u8)),
            Err(Error::Status(SW_CONDITIONS)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Unlock with the PIN. **After 3 wrong PINs in a row the dongle erases
    /// itself**, and it must be replugged after each wrong one. Returns the PIN
    /// validation flags (0x01: forward setup, power cycle to read the seed).
    pub async fn verify_pin(&self, pin: &str) -> Result<u8> {
        let r = self
            .device
            .exchange(&Apdu::with_data(
                CLA,
                INS_VERIFY_PIN,
                0,
                0,
                pin.as_bytes().to_vec(),
            ))
            .await?;
        match r.sw {
            StatusWord::OK => Ok(r.data.first().copied().unwrap_or(0)),
            sw => Err(pin_error(sw)),
        }
    }

    /// Attestation of the firmware: the dongle signs its version info followed
    /// by `blob` with its batch attestation key.
    pub async fn attestation(&self, blob: [u8; 8]) -> Result<Attestation> {
        let r = self.send(INS_GET_ATTESTATION, 0, 0, blob.to_vec()).await?;
        if r.len() < 15 {
            return Err(Error::InvalidResponse("short attestation".into()));
        }
        // Observed on firmware 1.0.1 (differs from the spec text): batch id,
        // derivation index, then the 6 version bytes of GET FIRMWARE VERSION
        // (architecture, x.y.z, loader x.y), supported and current modes, then
        // the DER signature.
        if r.len() < 17 {
            return Err(Error::InvalidResponse("short attestation".into()));
        }
        let u32be = |o: usize| u32::from_be_bytes(r[o..o + 4].try_into().unwrap());
        Ok(Attestation {
            batch_id: u32be(0),
            derivation_index: u32be(4),
            architecture: r[8],
            firmware: format!("{}.{}.{}", r[9], r[10], r[11]),
            loader: format!("{}.{}", r[12], r[13]),
            supported_modes: r[14],
            current_mode: r[15],
            blob: blob.to_vec(),
            signature: r[16..].to_vec(),
        })
    }

    /// First setup of a new or wiped dongle, then the QWERTY keymap and
    /// Ledger's typing speed. Returns whether the dongle will type a generated
    /// seed. **The PIN and seed travel in clear over USB.**
    pub async fn setup(&self, s: &Setup) -> Result<bool> {
        if !(4..=32).contains(&s.pin.len()) {
            return Err(Error::InvalidInput(
                "the PIN must be 4 to 32 characters".into(),
            ));
        }
        let mut d = vec![s.modes, s.features, s.key_version, s.p2sh_version];
        d.extend(lv(s.pin.as_bytes())?);
        let second = s.secondary_pin.as_deref().unwrap_or("");
        if second.len() > 4 {
            return Err(Error::InvalidInput(
                "the secondary PIN is at most 4 characters".into(),
            ));
        }
        d.extend(lv(second.as_bytes())?);
        match &s.seed {
            Some(seed) if !(32..=64).contains(&seed.len()) => {
                return Err(Error::InvalidInput(
                    "the seed must be 32 to 64 bytes".into(),
                ));
            }
            Some(seed) => d.extend(lv(seed)?),
            None => d.push(0),
        }
        d.push(0); // developer key: generate
        let r = self.send(INS_SETUP, 0, 0, d).await?;
        self.send(INS_SET_KEYBOARD, 0, 0, QWERTY_KEYMAP.to_vec())
            .await?;
        let mut typing = Vec::new();
        for v in [0xffu32, 0xff, 0xff, 0x10] {
            typing.extend(v.to_be_bytes());
        }
        // Older firmware doesn't have the typing behaviour (0x6700).
        match self.send(INS_SET_KEYBOARD, 1, 0, typing).await {
            Ok(_) | Err(Error::Status(StatusWord(0x6700))) => {}
            Err(e) => return Err(e),
        }
        Ok(r.first().copied() == Some(0x01))
    }

    /// Public key, Base58 address and chain code of `path` (needs the PIN).
    pub async fn wallet_public_key(&self, path: &DerivationPath) -> Result<WalletPublicKey> {
        let r = self
            .send(INS_GET_WALLET_PUBLIC_KEY, 0, 0, path_bytes(path)?)
            .await?;
        let mut o = 0;
        let mut take = |n: usize| -> Result<Vec<u8>> {
            let v = r
                .get(o..o + n)
                .ok_or_else(|| Error::InvalidResponse("short public key response".into()))?
                .to_vec();
            o += n;
            Ok(v)
        };
        let n = take(1)?[0] as usize;
        let public_key = take(n)?;
        let n = take(1)?[0] as usize;
        let address = String::from_utf8(take(n)?)
            .map_err(|_| Error::InvalidResponse("address is not text".into()))?;
        let chain_code = take(32)?;
        Ok(WalletPublicKey {
            public_key,
            address,
            chain_code,
        })
    }

    /// Start signing a message (ASCII printable, at most 140 bytes) with the
    /// key of `path`. Returns the confirmation needed, if any: then power cycle
    /// the dongle, read the code it types, and call
    /// [`Self::sign_message_finish`] with it.
    pub async fn sign_message_prepare(
        &self,
        path: &DerivationPath,
        message: &[u8],
    ) -> Result<Option<Confirmation>> {
        if message.len() > 140 || message.iter().any(|b| !(0x20..=0x7e).contains(b)) {
            return Err(Error::InvalidInput(
                "the message must be ASCII printable, at most 140 characters".into(),
            ));
        }
        let mut d = path_bytes(path)?;
        d.extend(lv(message)?);
        let r = self.send(INS_SIGN_MESSAGE, 0x00, 0x00, d).await?;
        Ok(match r.first().copied().unwrap_or(0) {
            0 => None,
            kind => Some(Confirmation {
                kind,
                data: r[1..].to_vec(),
            }),
        })
    }

    /// Finish a message signature with the confirmation code (empty if none
    /// was asked). Returns the DER signature with the Y parity in its first
    /// byte; see [`message_signature_base64`].
    pub async fn sign_message_finish(&self, code: &str) -> Result<Vec<u8>> {
        self.send(INS_SIGN_MESSAGE, 0x80, 0x00, lv(code.as_bytes())?)
            .await
    }
}

// ------------------------------------------------------------ messages --

fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `(r, s)` of a DER ECDSA signature, 32 bytes each.
fn der_rs(der: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let bad = || Error::InvalidResponse("bad DER signature".into());
    let mut o = 2;
    let mut int = || -> Result<[u8; 32]> {
        if der.get(o) != Some(&0x02) {
            return Err(bad());
        }
        let n = *der.get(o + 1).ok_or_else(bad)? as usize;
        let mut v = der.get(o + 2..o + 2 + n).ok_or_else(bad)?;
        o += 2 + n;
        while v.len() > 32 && v[0] == 0 {
            v = &v[1..];
        }
        if v.len() > 32 {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        out[32 - v.len()..].copy_from_slice(v);
        Ok(out)
    };
    Ok((int()?, int()?))
}

/// Bitcoin-QT message signature (Base64 of `header || r || s`) from the
/// dongle's DER signature with Y parity in its first byte.
pub fn message_signature_base64(der: &[u8], compressed: bool) -> Result<String> {
    let parity = der.first().copied().unwrap_or(0) & 0x01;
    let (r, s) = der_rs(der)?;
    let mut out = vec![27 + parity + if compressed { 4 } else { 0 }];
    out.extend(r);
    out.extend(s);
    Ok(base64(&out))
}

// --------------------------------------------------------------- BIP 39 --

const BIP39_ENGLISH: &str = include_str!("bip39_english.txt");

/// BIP32 seed (64 bytes) of a BIP-39 English phrase, after checking its words
/// and checksum. For [`Setup::seed`].
pub fn bip39_seed(phrase: &str, passphrase: &str) -> Result<[u8; 64]> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if ![12, 15, 18, 21, 24].contains(&words.len()) {
        return Err(Error::InvalidInput(
            "a recovery phrase has 12, 15, 18, 21 or 24 words".into(),
        ));
    }
    let list: Vec<&str> = BIP39_ENGLISH.lines().collect();
    let mut bits = Vec::with_capacity(words.len() * 11);
    for w in &words {
        let i = list
            .iter()
            .position(|x| x == w)
            .ok_or_else(|| Error::InvalidInput(format!("\"{w}\" is not a BIP-39 word")))?;
        bits.extend((0..11).rev().map(|b| (i >> b) & 1 == 1));
    }
    let ent_bits = bits.len() * 32 / 33;
    let entropy: Vec<u8> = bits[..ent_bits]
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | b as u8))
        .collect();
    let hash = sha256(&entropy);
    let checksum_ok = bits[ent_bits..]
        .iter()
        .enumerate()
        .all(|(i, &b)| ((hash[i / 8] >> (7 - i % 8)) & 1 == 1) == b);
    if !checksum_ok {
        return Err(Error::InvalidInput(
            "invalid recovery phrase checksum (check the words)".into(),
        ));
    }
    // PBKDF2-HMAC-SHA512, 2048 iterations, one 64-byte block.
    let password = words.join(" ");
    let salt = format!("mnemonic{passphrase}");
    let mut block_input = salt.into_bytes();
    block_input.extend_from_slice(&1u32.to_be_bytes());
    let mut u: [u8; 64] = hmac512(password.as_bytes(), &block_input);
    let mut out = u;
    for _ in 1..2048 {
        u = hmac512(password.as_bytes(), &u);
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    Ok(out)
}

fn hmac512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut m = HmacSha512::new(key);
    m.update(data);
    let r = m.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(r.as_ref());
    out
}

// ---------------------------------------------------------- transactions --

/// A Bitcoin transaction (witness data is parsed and dropped).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    /// Previous txid (internal byte order) then output index (LE).
    pub prevout: [u8; 36],
    pub script: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script: Vec<u8>,
}

fn varint(n: usize) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => {
            let mut v = vec![0xfd];
            v.extend((n as u16).to_le_bytes());
            v
        }
        _ => {
            let mut v = vec![0xfe];
            v.extend((n as u32).to_le_bytes());
            v
        }
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    o: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let v = self
            .b
            .get(self.o..self.o + n)
            .ok_or_else(|| Error::InvalidInput("truncated transaction".into()))?;
        self.o += n;
        Ok(v)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn varint(&mut self) -> Result<usize> {
        Ok(match self.u8()? {
            0xfd => u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as usize,
            0xfe => self.u32()? as usize,
            0xff => {
                let v = self.u64()?;
                usize::try_from(v).map_err(|_| Error::InvalidInput("varint too large".into()))?
            }
            n => n as usize,
        })
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.varint()?;
        Ok(self.take(n)?.to_vec())
    }
}

impl Tx {
    /// Parse a raw transaction (legacy or segwit serialization).
    pub fn parse(raw: &[u8]) -> Result<Tx> {
        let mut c = Cursor { b: raw, o: 0 };
        let version = c.u32()?;
        let mut n_in = c.varint()?;
        let segwit = n_in == 0;
        if segwit {
            if c.u8()? != 1 {
                return Err(Error::InvalidInput("bad segwit flag".into()));
            }
            n_in = c.varint()?;
        }
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            let prevout: [u8; 36] = c.take(36)?.try_into().unwrap();
            let script = c.bytes()?;
            let sequence = c.u32()?;
            inputs.push(TxIn {
                prevout,
                script,
                sequence,
            });
        }
        let n_out = c.varint()?;
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            let value = c.u64()?;
            let script = c.bytes()?;
            outputs.push(TxOut { value, script });
        }
        if segwit {
            for _ in 0..n_in {
                for _ in 0..c.varint()? {
                    c.bytes()?;
                }
            }
        }
        let lock_time = c.u32()?;
        if c.o != raw.len() {
            return Err(Error::InvalidInput(
                "trailing data after transaction".into(),
            ));
        }
        Ok(Tx {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    /// Legacy serialization (no witness).
    pub fn serialize(&self) -> Vec<u8> {
        let mut v = self.version.to_le_bytes().to_vec();
        v.extend(varint(self.inputs.len()));
        for i in &self.inputs {
            v.extend(i.prevout);
            v.extend(varint(i.script.len()));
            v.extend(&i.script);
            v.extend(i.sequence.to_le_bytes());
        }
        v.extend(varint(self.outputs.len()));
        for o in &self.outputs {
            v.extend(o.value.to_le_bytes());
            v.extend(varint(o.script.len()));
            v.extend(&o.script);
        }
        v.extend(self.lock_time.to_le_bytes());
        v
    }

    /// Transaction id, in internal byte order (reverse it for display).
    pub fn txid(&self) -> [u8; 32] {
        sha256(&sha256(&self.serialize()))
    }
}

/// Compressed form of a 65-byte uncompressed public key.
pub fn compress_public_key(pk: &[u8]) -> Result<Vec<u8>> {
    if pk.len() != 65 || pk[0] != 0x04 {
        return Err(Error::InvalidResponse(
            "expected an uncompressed public key".into(),
        ));
    }
    let mut v = vec![0x02 | (pk[64] & 1)];
    v.extend_from_slice(&pk[1..33]);
    Ok(v)
}

/// P2PKH output script of a public key.
pub fn p2pkh_script(public_key: &[u8]) -> Vec<u8> {
    let h = ripemd160(&sha256(public_key));
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&h);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// One input to spend: output `vout` of `prev_tx`, paid to the P2PKH address
/// of `path`.
#[derive(Clone, Debug)]
pub struct SpendInput {
    pub prev_tx: Tx,
    pub vout: u32,
    pub path: DerivationPath,
}

/// Where the money goes: one destination plus the change, computed by the
/// dongle from the inputs (`inputs - amount - fee`) and sent to `change_path`.
#[derive(Clone, Debug)]
pub struct Payment {
    /// Base58 address.
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub change_path: DerivationPath,
}

/// What a [`TxSigner::step`] call produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxStep {
    /// The user must confirm: for keyboard confirmation, unplug and replug the
    /// dongle (it types a summary and a code into the focused window), plug it
    /// back, set the code with [`TxSigner::set_code`] and call `step` again,
    /// on a reopened device.
    NeedsConfirmation(Confirmation),
    /// Signed transaction, ready to broadcast.
    Done(Vec<u8>),
}

/// Legacy P2PKH transaction signing, resumable across the confirmation power
/// cycles (keep it, reopen the device, call [`TxSigner::step`] again).
#[derive(Clone, Debug)]
pub struct TxSigner {
    inputs: Vec<SpendInput>,
    payment: Payment,
    lock_time: u32,
    /// Per input: public key in the address form, trusted input.
    keys: Vec<Vec<u8>>,
    trusted: Vec<Vec<u8>>,
    scripts: Vec<Vec<u8>>,
    outputs: Option<Vec<u8>>,
    signatures: Vec<Vec<u8>>,
    first: bool,
    code: Option<String>,
}

impl TxSigner {
    pub fn new(inputs: Vec<SpendInput>, payment: Payment) -> Result<Self> {
        if inputs.is_empty() {
            return Err(Error::InvalidInput("no input to spend".into()));
        }
        let total: u64 = inputs
            .iter()
            .map(|i| {
                i.prev_tx
                    .outputs
                    .get(i.vout as usize)
                    .map(|o| o.value)
                    .ok_or_else(|| Error::InvalidInput(format!("output {} does not exist", i.vout)))
            })
            .sum::<Result<u64>>()?;
        if payment.amount.saturating_add(payment.fee) > total {
            return Err(Error::InvalidInput(format!(
                "amount + fee ({}) exceed the inputs ({total})",
                payment.amount + payment.fee
            )));
        }
        Ok(Self {
            inputs,
            payment,
            lock_time: 0,
            keys: Vec::new(),
            trusted: Vec::new(),
            scripts: Vec::new(),
            outputs: None,
            signatures: Vec::new(),
            first: true,
            code: None,
        })
    }

    /// Confirmation code typed by the dongle.
    pub fn set_code(&mut self, code: impl Into<String>) {
        self.code = Some(code.into());
    }

    /// Change and total input value, in satoshis.
    pub fn summary(&self) -> (u64, u64) {
        let total: u64 = self
            .inputs
            .iter()
            .map(|i| i.prev_tx.outputs[i.vout as usize].value)
            .sum();
        (total - self.payment.amount - self.payment.fee, total)
    }

    /// Run until the next confirmation or the end. The PIN must have been
    /// verified on this power-up; after a confirmation power cycle, if this
    /// fails with 0x6982, verify the PIN and call it again.
    pub async fn step<T: Transport>(&mut self, w: &BtchipWallet<'_, T>) -> Result<TxStep> {
        if self.trusted.is_empty() {
            for i in &self.inputs {
                let pk = w.wallet_public_key(&i.path).await?;
                let compressed = w.firmware().await?.compressed_keys;
                let key = if compressed {
                    compress_public_key(&pk.public_key)?
                } else {
                    pk.public_key.clone()
                };
                let script = &i.prev_tx.outputs[i.vout as usize].script;
                if *script != p2pkh_script(&key) {
                    return Err(Error::InvalidInput(format!(
                        "output {} of {} is not paid to {} ({})",
                        i.vout,
                        hex::encode(i.prev_tx.txid().iter().rev().copied().collect::<Vec<_>>()),
                        i.path,
                        pk.address
                    )));
                }
                self.trusted
                    .push(trusted_input(w, &i.prev_tx, i.vout).await?);
                self.scripts.push(script.clone());
                self.keys.push(key);
            }
        }
        while self.signatures.len() < self.inputs.len() {
            let idx = self.signatures.len();
            self.hash_inputs(w, idx).await?;
            let (outputs, confirm) = self.finalize(w).await?;
            self.outputs = Some(outputs);
            self.first = false;
            if let Some(c) = confirm
                && self.code.is_none()
            {
                return Ok(TxStep::NeedsConfirmation(c));
            }
            let mut d = path_bytes(&self.inputs[idx].path)?;
            d.extend(lv(self.code.as_deref().unwrap_or("").as_bytes())?);
            d.extend(self.lock_time.to_be_bytes());
            d.push(0x01); // SIGHASH_ALL
            let mut sig = w.send(INS_HASH_SIGN, 0, 0, d).await?;
            if let Some(b) = sig.first_mut() {
                *b = 0x30;
            }
            self.signatures.push(sig);
        }
        Ok(TxStep::Done(self.assemble()?))
    }

    async fn hash_inputs<T: Transport>(&self, w: &BtchipWallet<'_, T>, idx: usize) -> Result<()> {
        let mut d = 1u32.to_le_bytes().to_vec();
        d.extend(varint(self.inputs.len()));
        let p2 = if self.first { 0x00 } else { 0x80 };
        w.send(INS_HASH_INPUT_START, 0x00, p2, d).await?;
        for (i, t) in self.trusted.iter().enumerate() {
            let script: &[u8] = if i == idx { &self.scripts[i] } else { &[] };
            let mut d = vec![0x01];
            d.extend(lv(t)?);
            d.extend(varint(script.len()));
            w.send(INS_HASH_INPUT_START, 0x80, 0x00, d).await?;
            let seq = 0xffff_ffffu32.to_le_bytes();
            if script.is_empty() {
                w.send(INS_HASH_INPUT_START, 0x80, 0x00, seq.to_vec())
                    .await?;
            } else {
                let chunks: Vec<&[u8]> = script.chunks(251).collect();
                for (k, c) in chunks.iter().enumerate() {
                    let mut d = c.to_vec();
                    if k + 1 == chunks.len() {
                        d.extend(seq);
                    }
                    w.send(INS_HASH_INPUT_START, 0x80, 0x00, d).await?;
                }
            }
        }
        Ok(())
    }

    async fn finalize<T: Transport>(
        &self,
        w: &BtchipWallet<'_, T>,
    ) -> Result<(Vec<u8>, Option<Confirmation>)> {
        let mut d = lv(self.payment.to.as_bytes())?;
        d.extend(self.payment.amount.to_be_bytes());
        d.extend(self.payment.fee.to_be_bytes());
        d.extend(path_bytes(&self.payment.change_path)?);
        let r = w.send(INS_HASH_INPUT_FINALIZE, 0x02, 0x00, d).await?;
        let n = *r
            .first()
            .ok_or_else(|| Error::InvalidResponse("empty finalize response".into()))?
            as usize;
        let outputs = r
            .get(1..1 + n)
            .ok_or_else(|| Error::InvalidResponse("short finalize response".into()))?
            .to_vec();
        let kind = r.get(1 + n).copied().unwrap_or(0);
        let confirm = (kind != 0).then(|| Confirmation {
            kind,
            data: r.get(2 + n..).unwrap_or(&[]).to_vec(),
        });
        Ok((outputs, confirm))
    }

    fn assemble(&self) -> Result<Vec<u8>> {
        let outputs = self
            .outputs
            .as_ref()
            .ok_or_else(|| Error::App("no outputs from the dongle".into()))?;
        let mut v = 1u32.to_le_bytes().to_vec();
        v.extend(varint(self.inputs.len()));
        for (k, i) in self.inputs.iter().enumerate() {
            v.extend(i.prev_tx.txid());
            v.extend(i.vout.to_le_bytes());
            let mut script = lv(&self.signatures[k])?;
            script.extend(lv(&self.keys[k])?);
            v.extend(varint(script.len()));
            v.extend(script);
            v.extend(0xffff_ffffu32.to_le_bytes());
        }
        v.extend(outputs);
        v.extend(self.lock_time.to_le_bytes());
        Ok(v)
    }
}

/// `GET TRUSTED INPUT` for output `vout` of `tx`, sent element by element
/// (the dongle rejects elements split across APDUs).
async fn trusted_input<T: Transport>(
    w: &BtchipWallet<'_, T>,
    tx: &Tx,
    vout: u32,
) -> Result<Vec<u8>> {
    let mut d = vout.to_be_bytes().to_vec();
    d.extend(tx.version.to_le_bytes());
    d.extend(varint(tx.inputs.len()));
    w.send(INS_GET_TRUSTED_INPUT, 0x00, 0x00, d).await?;
    for i in &tx.inputs {
        let mut d = i.prevout.to_vec();
        d.extend(varint(i.script.len()));
        w.send(INS_GET_TRUSTED_INPUT, 0x80, 0x00, d).await?;
        let chunks: Vec<&[u8]> = i.script.chunks(251).collect();
        if chunks.is_empty() {
            w.send(
                INS_GET_TRUSTED_INPUT,
                0x80,
                0x00,
                i.sequence.to_le_bytes().to_vec(),
            )
            .await?;
        }
        for (k, c) in chunks.iter().enumerate() {
            let mut d = c.to_vec();
            if k + 1 == chunks.len() {
                d.extend(i.sequence.to_le_bytes());
            }
            w.send(INS_GET_TRUSTED_INPUT, 0x80, 0x00, d).await?;
        }
    }
    w.send(INS_GET_TRUSTED_INPUT, 0x80, 0x00, varint(tx.outputs.len()))
        .await?;
    for o in &tx.outputs {
        let mut d = o.value.to_le_bytes().to_vec();
        d.extend(varint(o.script.len()));
        w.send(INS_GET_TRUSTED_INPUT, 0x80, 0x00, d).await?;
        for c in o.script.chunks(255) {
            w.send(INS_GET_TRUSTED_INPUT, 0x80, 0x00, c.to_vec())
                .await?;
        }
    }
    w.send(
        INS_GET_TRUSTED_INPUT,
        0x80,
        0x00,
        tx.lock_time.to_le_bytes().to_vec(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip39_vector() {
        // BIP-39 test vector (passphrase "TREZOR").
        let s = bip39_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "TREZOR",
        )
        .unwrap();
        assert_eq!(
            hex::encode(s),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
        assert!(bip39_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", "").is_err());
        assert!(bip39_seed("abandon zzz", "").is_err());
    }

    #[test]
    fn base64_and_der() {
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
        let mut der = vec![0x31, 0x44, 0x02, 0x20];
        der.extend([1u8; 32]);
        der.extend([0x02, 0x20]);
        der.extend([2u8; 32]);
        let sig = message_signature_base64(&der, true).unwrap();
        assert!(sig.starts_with('I')); // header 32 = 27 + 1 + 4
    }

    #[test]
    fn tx_roundtrip() {
        // A legacy transaction: 1 input, 1 output.
        let raw = hex::decode(concat!(
            "01000000",
            "01",
            "0000000000000000000000000000000000000000000000000000000000000000ffffffff",
            "00",
            "ffffffff",
            "01",
            "0100000000000000",
            "19",
            "76a914000000000000000000000000000000000000000088ac",
            "00000000"
        ))
        .unwrap();
        let tx = Tx::parse(&raw).unwrap();
        assert_eq!(tx.serialize(), raw);
        assert_eq!(tx.outputs[0].value, 1);
        assert_eq!(p2pkh_script(&[2u8; 33]).len(), 25);
    }
}
