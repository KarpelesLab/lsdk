//! Dashboard secure channel (SCP) and the secure commands it carries.
//!
//! The host authenticates with a secp256k1 *root key*:
//!
//! * a random or personal key: the device asks the user to allow an
//!   *insecure (foreign) manager*; most commands work, but the device
//!   refuses to install apps;
//! * the private key of the **custom CA** installed on the device (see
//!   [`SecureChannel::setup_custom_ca`]): the device asks to allow the
//!   named manager, and app installation (sideloading) is permitted.
//!
//! Handshake: `VALIDATE_TARGET_ID`, `INITIALIZE_AUTHENTICATION` (nonces),
//! `VALIDATE_CERTIFICATE` (host root, self-signed, then a host ephemeral key
//! signed over both nonces), `GET_CERTIFICATE` (device certificate then
//! device ephemeral key signed over both nonces), `MUTUAL_AUTHENTICATE`.
//! The session secret is `sha256(compressed(ECDH(host_eph, device_eph)))`;
//! encryption and MAC keys derive from it, and every secure APDU is
//! `E0 00 00 00 Lc AES-CBC(pad(ins || data)) || CBC-MAC[-14..]`, with the
//! IVs chained across the session in both directions.

use purecrypto::cipher::{Aes128, Aes256, AesSiv, BlockCipher};
use purecrypto::ec::Secp256k1EcdsaPublicKey;
use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use purecrypto::hash::sha256;

use crate::apdu::{Apdu, Reader, StatusWord};
use crate::attestation::{host_certificate, rand_bytes, random_key, verify};
use crate::device::Device;
use crate::error::{Error, Result};
use crate::os::OsVersion;
use crate::transport::Transport;

const MAC_LEN: usize = 14;

/// Secure instruction codes (first plaintext byte of `INS_SECURE_COMMAND`).
pub mod ins {
    pub const SET_LOAD_OFFSET: u8 = 0x05;
    pub const LOAD: u8 = 0x06;
    pub const FLUSH: u8 = 0x07;
    pub const CRC: u8 = 0x08;
    pub const COMMIT: u8 = 0x09;
    pub const CREATE_APP: u8 = 0x0b;
    pub const DELETE_APP: u8 = 0x0c;
    pub const LIST_APPS: u8 = 0x0e;
    pub const LIST_APPS_CONTINUE: u8 = 0x0f;
    pub const GET_VERSION: u8 = 0x10;
    pub const GET_MEMORY_INFORMATION: u8 = 0x11;
    pub const SETUP_CUSTOM_CERTIFICATE: u8 = 0x12;
    pub const RESET_CUSTOM_CERTIFICATE: u8 = 0x13;
    pub const DELETE_ALL_APPS: u8 = 0x14;
    pub const DELETE_APP_BY_HASH: u8 = 0x15;
    pub const RESET_ENDORSEMENT: u8 = 0x16;
    pub const HASH_FIRMWARE: u8 = 0x17;
    pub const MCU_BOOTLOADER: u8 = 0xb0;
    /// Recover channel only.
    pub const RECOVER_SET_CA: u8 = 0xd2;
    /// Recover channel only.
    pub const RECOVER_DELETE_CA: u8 = 0xd3;

    /// Symbolic name of a secure instruction, `None` if unknown.
    pub fn name(ins: u8) -> Option<&'static str> {
        Some(match ins {
            SET_LOAD_OFFSET => "SET_LOAD_OFFSET",
            LOAD => "LOAD",
            FLUSH => "FLUSH",
            CRC => "CRC",
            COMMIT => "COMMIT",
            CREATE_APP => "CREATE_APP",
            DELETE_APP => "DELETE_APP",
            LIST_APPS => "LIST_APPS",
            LIST_APPS_CONTINUE => "LIST_APPS_CONTINUE",
            GET_VERSION => "GET_VERSION",
            GET_MEMORY_INFORMATION => "GET_MEMORY_INFORMATION",
            SETUP_CUSTOM_CERTIFICATE => "SETUP_CUSTOM_CERTIFICATE",
            RESET_CUSTOM_CERTIFICATE => "RESET_CUSTOM_CERTIFICATE",
            DELETE_ALL_APPS => "DELETE_ALL_APPS",
            DELETE_APP_BY_HASH => "DELETE_APP_BY_HASH",
            RESET_ENDORSEMENT => "RESET_ENDORSEMENT",
            HASH_FIRMWARE => "HASH_FIRMWARE",
            MCU_BOOTLOADER => "MCU_BOOTLOADER",
            RECOVER_SET_CA => "RECOVER_SET_CA",
            RECOVER_DELETE_CA => "RECOVER_DELETE_CA",
            _ => return None,
        })
    }
}

pub use crate::attestation::RootKey;

/// Render secure commands as the `.fw` text stream: one command per line, in
/// stream order, as `NAME <arguments as hex>` (`NAME` alone when it has no
/// arguments; `CMD_xx` for an unknown instruction), e.g.
/// `SET_LOAD_OFFSET 0000ec00`, `LOAD 0000<data>` (2-byte BE in-region
/// offset, then the bytes).
pub fn format_stream(cmds: &[(u8, Vec<u8>)]) -> String {
    let mut out = String::new();
    for (ins, args) in cmds {
        match ins::name(*ins) {
            Some(n) => out.push_str(n),
            None => out.push_str(&format!("CMD_{ins:02X}")),
        }
        if !args.is_empty() {
            out.push(' ');
            out.push_str(&hex::encode(args));
        }
        out.push('\n');
    }
    out
}

/// Extract the decrypted secure commands from a session log written by the
/// emulated device (`firmware download --device-key`): its `  cmd <ins>
/// <args hex>` lines, in order. Other lines are ignored.
pub fn parse_decrypted_log(text: &str) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut cmds = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let Some(rest) = line.trim().strip_prefix("cmd ") else {
            continue;
        };
        let bad = |what: &str| Error::InvalidInput(format!("log line {}: {what}", n + 1));
        let mut it = rest.split_whitespace();
        let ins = it.next().ok_or_else(|| bad("missing instruction"))?;
        let ins = u8::from_str_radix(ins, 16).map_err(|_| bad("bad instruction"))?;
        let args = match it.next() {
            Some(h) => hex::decode(h).map_err(|_| bad("bad argument hex"))?,
            None => Vec::new(),
        };
        if it.next().is_some() {
            return Err(bad("trailing data"));
        }
        cmds.push((ins, args));
    }
    Ok(cmds)
}

/// Owner certificate for an endorsement key: DER signature by `owner` over
/// `sha256(0xFE || endorsement_public_key)`.
pub fn endorsement_certificate(owner: &RootKey, endorsement_public_key: &[u8]) -> Result<Vec<u8>> {
    let mut d = vec![0xfe];
    d.extend_from_slice(endorsement_public_key);
    owner.sign(&d)
}

/// Check the device signature of a new endorsement key: by the device
/// attestation key over `sha256(0xFF || endorsement_public_key)`.
pub fn verify_endorsement_key(
    device_public_key: &[u8],
    endorsement_public_key: &[u8],
    device_signature: &[u8],
) -> bool {
    let mut d = vec![0xff];
    d.extend_from_slice(endorsement_public_key);
    verify(device_public_key, &d, device_signature)
}

/// Events during the handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(
        tag = "type",
        rename_all = "camelCase",
        rename_all_fields = "camelCase"
    )
)]
pub enum ScpEvent {
    /// The device asks the user to allow this manager key (or the custom CA).
    PermissionRequested {
        host_public_key: String,
    },
    PermissionGranted,
    /// Mutual authentication done, the channel is open.
    Opened,
}

/// Memory usage, from `GET_MEMORY_INFORMATION`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct MemoryInfo {
    pub system_size: u32,
    pub applications_size: u32,
    pub free_size: u32,
    pub used_app_slots: u32,
    pub total_app_slots: u32,
}

/// An app as listed over the secure channel.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct SecureAppEntry {
    pub name: String,
    /// App flags (`APPLICATION_FLAG_*`). Before 1.4 the low half of the
    /// registry word; from 1.4 the raw 4 bytes the dashboard sends.
    pub flags: u32,
    pub hash_code_data: String,
    pub hash: String,
}

/// An open secure channel.
pub struct SecureChannel<'d, T: Transport> {
    device: &'d Device<T>,
    session: Session,
    /// Device attestation public key (from its factory certificate).
    pub device_public_key: Vec<u8>,
    /// Device ephemeral public key of this session.
    pub device_ephemeral_key: Vec<u8>,
    /// Firmware information read before the handshake.
    pub version: OsVersion,
}

/// How the host authenticates.
#[derive(Clone, Copy, Debug)]
pub enum HostAuth<'k> {
    /// A self-signed root key (custom CA private key, or any key).
    Root(&'k RootKey),
    /// Recover orchestrator: `orchestrator` certified by the custom `ca`.
    Orchestrator {
        ca: &'k RootKey,
        orchestrator: &'k RootKey,
    },
}

/// Secure channel flavor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum ScpMode {
    /// Regular manager channel (AES-CBC + CBC-MAC).
    Default,
    /// Recover channel (AES-SIV): custom CA management in recovery mode.
    Recover,
}

pub(crate) enum Session {
    Default {
        enc: Aes128,
        mac: Aes128,
        enc_iv: [u8; 16],
        mac_iv: [u8; 16],
    },
    Recover {
        siv: AesSiv,
    },
    /// Pre-1.4 firmware (target ids ending in 2, e.g. Nano S 1.3.x): the
    /// key is the ECDH secret's first 16 bytes, one CBC chain for both
    /// directions and no MAC.
    V2 {
        enc: Aes128,
        iv: [u8; 16],
    },
}

/// Whether a target id uses the pre-1.4 channel and app layout.
pub fn is_pre_1_4(target_id: u32) -> bool {
    target_id & 0xf == 0x2
}

/// Recover-style AES-SIV key between a host private key and a device public
/// key: `secret = sha256(x || 00000001)`, key = `AES256(secret, 0x01*16) ||
/// AES256(secret, 0x02*16)`.
pub fn recover_siv_key(host: &RootKey, device_public: &[u8]) -> Result<[u8; 32]> {
    let scalar =
        Scalar::from_bytes_be(&host.to_bytes()).map_err(|_| Error::App("bad key".into()))?;
    Ok(siv_key_from_x(&ecdh_x(
        &RootKeyScalar(scalar),
        device_public,
    )?))
}

fn siv_key_from_x(x: &[u8; 32]) -> [u8; 32] {
    let mut buf = x.to_vec();
    buf.extend_from_slice(&[0, 0, 0, 1]);
    let secret = sha256(&buf);
    let aes = Aes256::new(&secret);
    let mut key = [0u8; 32];
    let (mut b1, mut b2) = ([1u8; 16], [2u8; 16]);
    aes.encrypt_block(&mut b1);
    aes.encrypt_block(&mut b2);
    key[..16].copy_from_slice(&b1);
    key[16..].copy_from_slice(&b2);
    key
}

fn ecdh_x(private: &RootKeyScalar, public: &[u8]) -> Result<[u8; 32]> {
    let p = AffinePoint::from_sec1(public)
        .map_err(|_| Error::InvalidResponse("bad device ephemeral key".into()))?;
    let q = p
        .to_projective()
        .mul(&private.0)
        .to_affine()
        .ok_or_else(|| Error::App("ECDH failed".into()))?;
    Ok(q.x_bytes())
}

fn ecdh_secret(private: &RootKeyScalar, public: &[u8]) -> Result<[u8; 32]> {
    let p = AffinePoint::from_sec1(public)
        .map_err(|_| Error::InvalidResponse("bad device ephemeral key".into()))?;
    let q = p
        .to_projective()
        .mul(&private.0)
        .to_affine()
        .ok_or_else(|| Error::App("ECDH failed".into()))?;
    Ok(sha256(&q.to_sec1_compressed()))
}

struct RootKeyScalar(Scalar);

/// `di = sha256(be32(index) || retry || secret)` until a valid scalar, then
/// `ki = sha256(uncompressed(di * G))[..16]`.
fn derive_key(secret: &[u8; 32], index: u32) -> Result<[u8; 16]> {
    for retry in 0u8..=255 {
        let mut buf = Vec::with_capacity(37);
        buf.extend_from_slice(&index.to_be_bytes());
        buf.push(retry);
        buf.extend_from_slice(secret);
        let d = sha256(&buf);
        if let Ok(s) = Scalar::from_bytes_be(&d) {
            if bool::from(s.is_zero()) {
                continue;
            }
            let p = ProjectivePoint::mul_generator(&s)
                .to_affine()
                .ok_or_else(|| Error::App("derive".into()))?;
            let k = sha256(&p.to_sec1_uncompressed());
            return Ok(k[..16].try_into().unwrap());
        }
    }
    Err(Error::App("key derivation failed".into()))
}

/// ISO 7816-4 padding then AES-CBC, chaining `iv`.
fn cbc_encrypt(enc: &Aes128, iv: &mut [u8; 16], plain: &[u8]) -> Vec<u8> {
    let mut data = plain.to_vec();
    data.push(0x80);
    while !data.len().is_multiple_of(16) {
        data.push(0);
    }
    for chunk in data.chunks_mut(16) {
        let mut block: [u8; 16] = chunk.try_into().unwrap();
        xor16(&mut block, iv);
        enc.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        *iv = block;
    }
    data
}

/// AES-CBC decrypt chaining `iv`, then strip ISO 7816-4 padding.
fn cbc_decrypt(enc: &Aes128, iv: &mut [u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(16) {
        return Err(Error::InvalidResponse("bad secure response length".into()));
    }
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let c: [u8; 16] = chunk.try_into().unwrap();
        let mut block = c;
        enc.decrypt_block(&mut block);
        xor16(&mut block, iv);
        *iv = c;
        out.extend_from_slice(&block);
    }
    let end = out
        .iter()
        .rposition(|b| *b == 0x80)
        .ok_or_else(|| Error::InvalidResponse("bad padding".into()))?;
    out.truncate(end);
    Ok(out)
}

fn xor16(a: &mut [u8; 16], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

impl Session {
    /// Encrypt (and MAC) a plaintext for the channel, advancing the IV chain.
    /// Host and device share one continuous chain, so this is used by both
    /// ends: the host to wrap a command, the emulated device to wrap a reply.
    pub(crate) fn seal(&mut self, plain: &[u8]) -> Vec<u8> {
        let (enc, mac, enc_iv, mac_iv) = match self {
            Session::Recover { siv } => return siv.seal(&[], plain),
            Session::V2 { enc, iv } => return cbc_encrypt(enc, iv, plain),
            Session::Default {
                enc,
                mac,
                enc_iv,
                mac_iv,
            } => (enc, mac, enc_iv, mac_iv),
        };
        let mut data = plain.to_vec();
        data.push(0x80);
        while !data.len().is_multiple_of(16) {
            data.push(0);
        }
        // CBC encrypt, chaining enc_iv.
        for chunk in data.chunks_mut(16) {
            let mut block: [u8; 16] = chunk.try_into().unwrap();
            xor16(&mut block, enc_iv);
            enc.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);
            *enc_iv = block;
        }
        // CBC-MAC over the ciphertext, chaining mac_iv.
        for chunk in data.chunks(16) {
            let mut block = *mac_iv;
            xor16(&mut block, chunk);
            mac.encrypt_block(&mut block);
            *mac_iv = block;
        }
        data.extend_from_slice(&mac_iv[16 - MAC_LEN..]);
        data
    }

    /// Verify and decrypt a channel message, advancing the IV chain.
    pub(crate) fn open(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let (enc, mac, enc_iv, mac_iv) = match self {
            Session::V2 { enc, iv } => return cbc_decrypt(enc, iv, data),
            Session::Recover { siv } => {
                return siv
                    .open(&[], data)
                    .map_err(|_| Error::InvalidResponse("secure channel tag mismatch".into()));
            }
            Session::Default {
                enc,
                mac,
                enc_iv,
                mac_iv,
            } => (enc, mac, enc_iv, mac_iv),
        };
        if data.len() < MAC_LEN + 16 || !(data.len() - MAC_LEN).is_multiple_of(16) {
            return Err(Error::InvalidResponse("bad secure response length".into()));
        }
        let (body, tag) = data.split_at(data.len() - MAC_LEN);
        for chunk in body.chunks(16) {
            let mut block = *mac_iv;
            xor16(&mut block, chunk);
            mac.encrypt_block(&mut block);
            *mac_iv = block;
        }
        if mac_iv[16 - MAC_LEN..] != *tag {
            return Err(Error::InvalidResponse("secure channel MAC mismatch".into()));
        }
        let mut out = Vec::with_capacity(body.len());
        for chunk in body.chunks(16) {
            let c: [u8; 16] = chunk.try_into().unwrap();
            let mut block = c;
            enc.decrypt_block(&mut block);
            xor16(&mut block, enc_iv);
            *enc_iv = c;
            out.extend_from_slice(&block);
        }
        let end = out
            .iter()
            .rposition(|b| *b == 0x80)
            .ok_or_else(|| Error::InvalidResponse("bad padding".into()))?;
        if out[end + 1..].iter().any(|b| *b != 0) {
            return Err(Error::InvalidResponse("bad padding".into()));
        }
        out.truncate(end);
        Ok(out)
    }
}

/// Build the session keys from the *device* side of the handshake: the device
/// ephemeral private scalar and the host ephemeral public key (mirror of what
/// the host computes in [`SecureChannel::open_with`]). Used by the key-file
/// virtual device; Recover mode is not needed there.
// Only the key-file virtual device uses this, and that transport is native-only.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn device_session(
    device_eph_secret: &[u8; 32],
    host_eph_pub: &[u8],
    target_id: u32,
) -> Result<Session> {
    let scalar = Scalar::from_bytes_be(device_eph_secret)
        .map_err(|_| Error::App("bad ephemeral key".into()))?;
    let secret = ecdh_secret(&RootKeyScalar(scalar), host_eph_pub)?;
    if is_pre_1_4(target_id) {
        let key: [u8; 16] = secret[..16].try_into().unwrap();
        Ok(Session::V2 {
            enc: Aes128::new(&key),
            iv: [0; 16],
        })
    } else {
        Ok(Session::Default {
            enc: Aes128::new(&derive_key(&secret, 0)?),
            mac: Aes128::new(&derive_key(&secret, 1)?),
            enc_iv: [0; 16],
            mac_iv: [0; 16],
        })
    }
}

impl<'d, T: Transport> SecureChannel<'d, T> {
    /// Open a default channel with `root` as the host authority.
    pub async fn open(
        device: &'d Device<T>,
        root: &RootKey,
        on_event: &mut dyn FnMut(ScpEvent),
    ) -> Result<Self> {
        Self::open_mode(device, root, ScpMode::Default, on_event).await
    }

    /// Open a channel of the given mode.
    pub async fn open_mode(
        device: &'d Device<T>,
        root: &RootKey,
        mode: ScpMode,
        on_event: &mut dyn FnMut(ScpEvent),
    ) -> Result<Self> {
        Self::open_with(device, HostAuth::Root(root), mode, on_event).await
    }

    /// Open a channel with any host authentication.
    pub async fn open_with(
        device: &'d Device<T>,
        auth: HostAuth<'_>,
        mode: ScpMode,
        on_event: &mut dyn FnMut(ScpEvent),
    ) -> Result<Self> {
        let (root, ca, role, eph_role, cert_id) = match auth {
            HostAuth::Root(r) => (r, None, 0x01u8, 0x11u8, 0x00u8),
            HostAuth::Orchestrator { ca, orchestrator } => {
                (orchestrator, Some(ca), 0x05, 0x15, 0x01)
            }
        };
        if !device.is_on_dashboard().await? {
            return Err(Error::DashboardExpected);
        }
        let version = device.get_version().await?;
        if version.is_bootloader {
            return Err(Error::App("device is in bootloader mode".into()));
        }
        let refused = |sw: StatusWord| {
            if sw.is_refused() {
                Error::UserRefused
            } else {
                sw.into()
            }
        };
        let recover = mode == ScpMode::Recover;

        device
            .send(&Apdu::with_data(
                0xe0,
                0x04,
                if recover { 0x02 } else { 0x00 },
                0x00,
                version.target_id.to_be_bytes().to_vec(),
            ))
            .await?;

        let mut host_nonce = [0u8; 8];
        rand_bytes(&mut host_nonce)?;
        let info = device
            .send(&Apdu::with_data(
                0xe0,
                0x50,
                0x00,
                0x00,
                host_nonce.to_vec(),
            ))
            .await?;
        if info.len() < 12 {
            return Err(Error::InvalidResponse(
                "short INITIALIZE_AUTHENTICATION response".into(),
            ));
        }
        let device_nonce: [u8; 8] = info[4..12].try_into().unwrap();

        // Host root certificate (self-signed, or by the CA for an orchestrator).
        let root_pub = root.public_key();
        let mut data = vec![role];
        data.extend_from_slice(&root_pub);
        let sig = ca.unwrap_or(root).sign(&data)?;
        on_event(ScpEvent::PermissionRequested {
            host_public_key: hex::encode(root_pub),
        });
        let r = device
            .exchange(&Apdu::with_data(
                0xe0,
                0x51,
                0x00,
                cert_id,
                host_certificate(&root_pub, &sig),
            ))
            .await?;
        if !r.sw.is_ok() {
            return Err(refused(r.sw));
        }
        on_event(ScpEvent::PermissionGranted);

        // Host ephemeral key.
        let eph = random_key()?;
        let eph_pub = eph.public_key().to_sec1();
        let mut data = vec![eph_role];
        data.extend_from_slice(&host_nonce);
        data.extend_from_slice(&device_nonce);
        data.extend_from_slice(&eph_pub);
        let sig = root.sign(&data)?;
        device
            .send(&Apdu::with_data(
                0xe0,
                0x51,
                0x80,
                cert_id,
                host_certificate(&eph_pub, &sig),
            ))
            .await?;

        // Device certificates.
        let static_cert = device.send(&Apdu::new(0xe0, 0x52, 0x00, 0x00)).await?;
        let eph_cert = device.send(&Apdu::new(0xe0, 0x52, 0x80, 0x00)).await?;
        let mut rd = Reader::new(&eph_cert);
        let _h = rd.lv()?;
        let dev_eph = rd.lv()?.to_vec();
        let mut dev_eph_sig = rd.lv()?.to_vec();
        Secp256k1EcdsaPublicKey::from_sec1(&dev_eph)
            .map_err(|_| Error::InvalidResponse("bad device key".into()))?;
        let scalar = Scalar::from_bytes_be(&eph.to_bytes())
            .map_err(|_| Error::App("bad ephemeral key".into()))?;

        let (session, static_cert) = if recover {
            // secret = sha256(x || 00000001); SIV key from AES-256-ECB blocks.
            let key = siv_key_from_x(&ecdh_x(&RootKeyScalar(scalar), &dev_eph)?);
            let siv = AesSiv::new(&key);
            let open = |c: &[u8]| {
                siv.open(&[], c)
                    .map_err(|_| Error::InvalidResponse("cannot decrypt device certificate".into()))
            };
            let static_cert = open(&static_cert)?;
            dev_eph_sig = open(&dev_eph_sig)?;
            (Session::Recover { siv }, static_cert)
        } else if is_pre_1_4(version.target_id) {
            let secret = ecdh_secret(&RootKeyScalar(scalar), &dev_eph)?;
            let key: [u8; 16] = secret[..16].try_into().unwrap();
            (
                Session::V2 {
                    enc: Aes128::new(&key),
                    iv: [0; 16],
                },
                static_cert,
            )
        } else {
            let secret = ecdh_secret(&RootKeyScalar(scalar), &dev_eph)?;
            let enc = Aes128::new(&derive_key(&secret, 0)?);
            let mac = Aes128::new(&derive_key(&secret, 1)?);
            (
                Session::Default {
                    enc,
                    mac,
                    enc_iv: [0; 16],
                    mac_iv: [0; 16],
                },
                static_cert,
            )
        };

        let mut rd = Reader::new(&static_cert);
        let _header = rd.lv()?;
        let device_public_key = rd.lv()?.to_vec();
        let mut signed = vec![0x12];
        signed.extend_from_slice(&device_nonce);
        signed.extend_from_slice(&host_nonce);
        signed.extend_from_slice(&dev_eph);
        if !verify(&device_public_key, &signed, &dev_eph_sig) {
            return Err(Error::App(
                "device ephemeral key signature is invalid".into(),
            ));
        }

        device.send(&Apdu::new(0xe0, 0x53, 0x00, 0x00)).await?;
        on_event(ScpEvent::Opened);
        Ok(Self {
            device,
            session,
            device_public_key,
            device_ephemeral_key: dev_eph,
            version,
        })
    }

    /// Channel flavor.
    pub fn mode(&self) -> ScpMode {
        match self.session {
            Session::Default { .. } | Session::V2 { .. } => ScpMode::Default,
            Session::Recover { .. } => ScpMode::Recover,
        }
    }

    fn wrap(&mut self, plain: &[u8]) -> Vec<u8> {
        self.session.seal(plain)
    }

    fn unwrap(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.session.open(data)
    }

    /// Send a secure command (`ins` + `data`), returning the decrypted response.
    pub async fn exchange(&mut self, ins: u8, data: &[u8]) -> Result<Vec<u8>> {
        let mut plain = vec![ins];
        plain.extend_from_slice(data);
        if plain.len() > 239 {
            return Err(Error::InvalidInput("secure command too long".into()));
        }
        if std::env::var_os("LSDK_DEBUG").is_some() {
            eprintln!(
                "> sec e000 {:02x} len={}: {}",
                ins,
                data.len(),
                hex::encode(&data[..data.len().min(40)])
            );
        }
        let wrapped = self.wrap(&plain);
        let r = self
            .device
            .exchange(&Apdu::with_data(0xe0, 0x00, 0x00, 0x00, wrapped))
            .await?;
        if !r.sw.is_ok() {
            return Err(match r.sw {
                sw if sw.is_refused() => Error::UserRefused,
                sw => sw.into(),
            });
        }
        let out = self.unwrap(&r.data)?;
        if std::env::var_os("LSDK_DEBUG").is_some() {
            eprintln!("< sec {}", hex::encode(&out));
        }
        Ok(out)
    }

    /// The underlying device.
    pub fn device(&self) -> &'d Device<T> {
        self.device
    }

    /// Firmware version, through the channel.
    pub async fn get_version(&mut self) -> Result<OsVersion> {
        OsVersion::parse(&self.exchange(ins::GET_VERSION, &[]).await?)
    }

    /// Memory usage.
    pub async fn get_memory_info(&mut self) -> Result<MemoryInfo> {
        let d = self.exchange(ins::GET_MEMORY_INFORMATION, &[]).await?;
        let mut r = Reader::new(&d);
        Ok(MemoryInfo {
            system_size: r.u32()?,
            applications_size: r.u32()?,
            free_size: r.u32()?,
            used_app_slots: r.u32()?,
            total_app_slots: r.u32()?,
        })
    }

    /// Installed apps (no extra consent: the channel is authenticated).
    pub async fn list_apps(&mut self) -> Result<Vec<SecureAppEntry>> {
        let mut out = Vec::new();
        let old = matches!(self.session, Session::V2 { .. });
        // Before 1.4 the list has no end marker, so take the app count (and
        // slot count) from the memory info and read until that many apps.
        // Without it, the first erased slot ends the list.
        let slots = if old {
            self.get_memory_info()
                .await
                .ok()
                .map(|m| (m.used_app_slots as usize, m.total_app_slots as usize))
        } else {
            None
        };
        if slots.is_some_and(|(used, _)| used == 0) {
            return Ok(out);
        }
        let mut seen = 0usize;
        let mut d = self.exchange(ins::LIST_APPS, &[]).await?;
        while !d.is_empty() {
            let mut r = Reader::new(&d);
            if old {
                // Before 1.4: entries of size(1, counting itself), name LV,
                // flags(4), hash(32). The flags are the registry word:
                // `!flags << 16 | flags` (APPLICATION_FLAG_NEG_MASK). The list
                // has no end marker (1.3.1): it walks every slot, returning
                // erased ones (all 0xff, failing that check), and asking past
                // the last slot crashes the device. So stop at the app count,
                // skipping erased slots on the way, and never go past the slot
                // count; without the counts, stop at the first erased slot.
                while !r.is_empty() {
                    let size = r.u8()? as usize;
                    let entry = r.bytes(size.saturating_sub(1))?;
                    seen += 1;
                    let app = Self::old_entry(entry);
                    let valid = app.is_some();
                    out.extend(app);
                    match slots {
                        Some((used, total)) if out.len() >= used || seen >= total => {
                            return Ok(out);
                        }
                        None if !valid => return Ok(out),
                        _ => {}
                    }
                }
                d = self.exchange(ins::LIST_APPS_CONTINUE, &[]).await?;
                continue;
            }
            if r.u8()? != 1 {
                return Err(Error::InvalidResponse("unknown list format".into()));
            }
            while !r.is_empty() {
                let _entry_size = r.u8()?;
                let flags = r.u32()?;
                let hash_code_data = hex::encode(r.bytes(32)?);
                let hash = hex::encode(r.bytes(32)?);
                let name = r.lv_string()?;
                out.push(SecureAppEntry {
                    name,
                    flags,
                    hash_code_data,
                    hash,
                });
            }
            d = self.exchange(ins::LIST_APPS_CONTINUE, &[]).await?;
        }
        Ok(out)
    }

    /// One pre-1.4 list entry (after its size byte), `None` for an erased
    /// slot or anything that doesn't parse as an app.
    fn old_entry(entry: &[u8]) -> Option<SecureAppEntry> {
        let mut e = Reader::new(entry);
        let raw = e.lv().ok()?;
        let word = e.u32().ok()?;
        if raw.is_empty() || raw.contains(&0xff) || (word >> 16) != (!word & 0xffff) {
            return None;
        }
        Some(SecureAppEntry {
            name: String::from_utf8_lossy(raw).into_owned(),
            flags: word & 0xffff,
            hash_code_data: String::new(),
            hash: hex::encode(e.bytes(32).ok()?),
        })
    }

    /// Delete an app by name.
    pub async fn delete_app(&mut self, name: &str) -> Result<()> {
        let mut d = vec![name.len() as u8];
        d.extend_from_slice(name.as_bytes());
        self.exchange(ins::DELETE_APP, &d).await.map(|_| ())
    }

    /// Delete an app by its full hash (32 bytes).
    pub async fn delete_app_by_hash(&mut self, hash: &[u8; 32]) -> Result<()> {
        self.exchange(ins::DELETE_APP_BY_HASH, hash)
            .await
            .map(|_| ())
    }

    /// Delete every app (the device asks for confirmation).
    pub async fn delete_all_apps(&mut self) -> Result<()> {
        self.exchange(ins::DELETE_ALL_APPS, &[]).await.map(|_| ())
    }

    /// Firmware integrity hash over `[address, address + length)`.
    /// **Vendor HSM sessions only**: the dashboard refuses it on channels
    /// authenticated with a custom CA or a foreign key.
    pub async fn hash_firmware(&mut self, address: u32, length: u32) -> Result<Vec<u8>> {
        let mut d = address.to_be_bytes().to_vec();
        d.extend_from_slice(&length.to_be_bytes());
        d.resize(24, 0);
        self.exchange(ins::HASH_FIRMWARE, &d)
            .await
            .map_err(|e| match e {
                Error::Status(sw) if (sw.0 >> 8) == 0x66 || (sw.0 >> 8) == 0x6d => {
                    Error::App(format!(
                        "firmware hash is reserved to vendor HSM sessions (device answered {sw})"
                    ))
                }
                e => e,
            })
    }

    /// Install a custom CA over the default channel (recovery mode; the
    /// device asks for confirmation). See also [`Self::recover_set_ca`].
    /// Its private key can then open channels allowed to install apps.
    pub async fn setup_custom_ca(&mut self, name: &str, public_key: &[u8]) -> Result<()> {
        let d = Self::name_key(name, public_key)?;
        self.exchange(ins::SETUP_CUSTOM_CERTIFICATE, &d)
            .await
            .map(|_| ())
    }

    /// Remove the custom CA (the device asks for confirmation).
    pub async fn reset_custom_ca(&mut self) -> Result<()> {
        self.exchange(ins::RESET_CUSTOM_CERTIFICATE, &[])
            .await
            .map(|_| ())
    }

    fn name_key(name: &str, public_key: &[u8]) -> Result<Vec<u8>> {
        if name.is_empty() || name.len() > 32 {
            return Err(Error::InvalidInput("CA name must be 1..=32 bytes".into()));
        }
        if public_key.len() != 65 || public_key[0] != 0x04 {
            return Err(Error::InvalidInput(
                "CA public key must be 65 bytes uncompressed (04...)".into(),
            ));
        }
        let mut d = vec![name.len() as u8];
        d.extend_from_slice(name.as_bytes());
        d.push(public_key.len() as u8);
        d.extend_from_slice(public_key);
        Ok(d)
    }

    /// Install a custom CA through the Recover channel (recovery mode).
    pub async fn recover_set_ca(&mut self, name: &str, public_key: &[u8]) -> Result<()> {
        let d = Self::name_key(name, public_key)?;
        self.exchange(ins::RECOVER_SET_CA, &d).await.map(|_| ())
    }

    /// Delete the custom CA through the Recover channel (recovery mode).
    pub async fn recover_delete_ca(&mut self, name: &str, public_key: &[u8]) -> Result<()> {
        let d = Self::name_key(name, public_key)?;
        self.exchange(ins::RECOVER_DELETE_CA, &d).await.map(|_| ())
    }

    /// Remove the user endorsement certificates.
    pub async fn reset_endorsement(&mut self) -> Result<()> {
        self.exchange(ins::RESET_ENDORSEMENT, &[]).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn stream_format_and_log_parse() {
        let log = "> e0000000ee00\n  cmd 05 0000ec00\n  rsp \n< 9000\n  cmd 06 0010aabb\n  cmd 07 \n  cmd 42 01\n";
        let cmds = parse_decrypted_log(log).unwrap();
        assert_eq!(
            cmds,
            vec![
                (ins::SET_LOAD_OFFSET, vec![0, 0, 0xec, 0]),
                (ins::LOAD, vec![0, 0x10, 0xaa, 0xbb]),
                (ins::FLUSH, vec![]),
                (0x42, vec![1]),
            ]
        );
        assert_eq!(
            format_stream(&cmds),
            "SET_LOAD_OFFSET 0000ec00\nLOAD 0010aabb\nFLUSH\nCMD_42 01\n"
        );
    }

    use super::*;

    #[test]
    fn aes_siv_rfc5297() {
        // RFC 5297 A.1, to pin the SIV conventions used by the Recover channel.
        let key = hex::decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
            .unwrap();
        let ad = hex::decode("101112131415161718191a1b1c1d1e1f2021222324252627").unwrap();
        let pt = hex::decode("112233445566778899aabbccddee").unwrap();
        let out = AesSiv::new(&key).seal(&[&ad], &pt);
        assert_eq!(
            hex::encode(out),
            "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c"
        );
    }

    #[test]
    fn old_list_entry() {
        // Nano S 1.3.1 pages: one app, then an erased slot.
        let app = hex::decode("300a466c617368205363616e780b87f450da980d1c4bb4b4292facea596e747a9aec5324a1418c1ef0a002e41346192c").unwrap();
        let e = SecureChannel::<crate::transport::tcp::TcpTransport>::old_entry(&app[1..]).unwrap();
        assert_eq!(e.name, "Flash Scan");
        assert_eq!(e.flags, 0x87f4);
        assert_eq!(&e.hash[..8], "50da980d");
        let mut erased = vec![0xb6, 0x90];
        erased.resize(0xb6, 0xff);
        assert!(
            SecureChannel::<crate::transport::tcp::TcpTransport>::old_entry(&erased[1..]).is_none()
        );
        // A name running past the entry is not an app either.
        assert!(
            SecureChannel::<crate::transport::tcp::TcpTransport>::old_entry(&[0x40, b'a'])
                .is_none()
        );
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        // Two channel ends sharing keys: what one wraps the other unwraps,
        // with chained IVs over several messages.
        let secret = [7u8; 32];
        let k0 = derive_key(&secret, 0).unwrap();
        let k1 = derive_key(&secret, 1).unwrap();
        assert_ne!(k0, k1);
        struct End {
            enc: Aes128,
            mac: Aes128,
            enc_iv: [u8; 16],
            mac_iv: [u8; 16],
        }
        let mk = || End {
            enc: Aes128::new(&k0),
            mac: Aes128::new(&k1),
            enc_iv: [0; 16],
            mac_iv: [0; 16],
        };
        // Reuse the channel code through a fake channel with no device.
        fn wrap(e: &mut End, plain: &[u8]) -> Vec<u8> {
            let mut data = plain.to_vec();
            data.push(0x80);
            while !data.len().is_multiple_of(16) {
                data.push(0);
            }
            for chunk in data.chunks_mut(16) {
                let mut b: [u8; 16] = chunk.try_into().unwrap();
                xor16(&mut b, &e.enc_iv);
                e.enc.encrypt_block(&mut b);
                chunk.copy_from_slice(&b);
                e.enc_iv = b;
            }
            for chunk in data.chunks(16) {
                let mut b = e.mac_iv;
                xor16(&mut b, chunk);
                e.mac.encrypt_block(&mut b);
                e.mac_iv = b;
            }
            data.extend_from_slice(&e.mac_iv[16 - MAC_LEN..]);
            data
        }
        let mut a = mk();
        let mut b = mk();
        for msg in [&b"hello"[..], &[0u8; 16], &[1u8; 100]] {
            let w = wrap(&mut a, msg);
            // unwrap on b mirrors SecureChannel::unwrap
            let (body, tag) = w.split_at(w.len() - MAC_LEN);
            for chunk in body.chunks(16) {
                let mut blk = b.mac_iv;
                xor16(&mut blk, chunk);
                b.mac.encrypt_block(&mut blk);
                b.mac_iv = blk;
            }
            assert_eq!(&b.mac_iv[16 - MAC_LEN..], tag);
            let mut out = Vec::new();
            for chunk in body.chunks(16) {
                let c: [u8; 16] = chunk.try_into().unwrap();
                let mut blk = c;
                b.enc.decrypt_block(&mut blk);
                xor16(&mut blk, &b.enc_iv);
                b.enc_iv = c;
                out.extend_from_slice(&blk);
            }
            let end = out.iter().rposition(|x| *x == 0x80).unwrap();
            out.truncate(end);
            assert_eq!(out, msg);
        }
    }
}
