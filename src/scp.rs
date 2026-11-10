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
use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use purecrypto::ec::{Secp256k1EcdsaPrivateKey, Secp256k1EcdsaPublicKey};
use purecrypto::hash::{Sha256, sha256};

use crate::apdu::{Apdu, Reader, StatusWord};
use crate::attestation::{der_encode, host_certificate, rand_bytes, random_key, verify};
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
}

/// A host root key (secp256k1). Use the custom CA private key to be allowed
/// to install apps.
#[derive(Clone)]
pub struct RootKey(Secp256k1EcdsaPrivateKey);

impl RootKey {
    /// Generate a new random key.
    pub fn generate() -> Result<Self> {
        random_key().map(Self)
    }

    /// From a 32-byte secret.
    pub fn from_bytes(secret: &[u8]) -> Result<Self> {
        let s: [u8; 32] = secret
            .try_into()
            .map_err(|_| Error::InvalidInput("private key must be 32 bytes".into()))?;
        Secp256k1EcdsaPrivateKey::from_bytes(&s)
            .map(Self)
            .map_err(|_| Error::InvalidInput("invalid private key".into()))
    }

    /// From a hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let b = hex::decode(s.trim().trim_start_matches("0x"))
            .map_err(|e| Error::InvalidInput(format!("private key hex: {e}")))?;
        Self::from_bytes(&b)
    }

    /// Secret (32 bytes). Keep it safe.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Uncompressed public key (65 bytes).
    pub fn public_key(&self) -> [u8; 65] {
        self.0.public_key().to_sec1()
    }

    /// DER ECDSA signature of a 32-byte digest (no extra hashing).
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let sig = self
            .0
            .sign_prehash::<Sha256>(digest)
            .map_err(|e| Error::App(format!("sign: {e:?}")))?;
        Ok(der_encode(&sig))
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let sig = self
            .0
            .sign::<Sha256>(data)
            .map_err(|e| Error::App(format!("sign: {e:?}")))?;
        Ok(der_encode(&sig))
    }
}

impl core::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RootKey({})", hex::encode(self.public_key()))
    }
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
    /// Firmware information read before the handshake.
    pub version: OsVersion,
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

enum Session {
    Default {
        enc: Aes128,
        mac: Aes128,
        enc_iv: [u8; 16],
        mac_iv: [u8; 16],
    },
    Recover {
        siv: AesSiv,
    },
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

fn xor16(a: &mut [u8; 16], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
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

        // Host root certificate (self-signed).
        let root_pub = root.public_key();
        let mut data = vec![0x01];
        data.extend_from_slice(&root_pub);
        let sig = root.sign(&data)?;
        on_event(ScpEvent::PermissionRequested {
            host_public_key: hex::encode(root_pub),
        });
        let r = device
            .exchange(&Apdu::with_data(
                0xe0,
                0x51,
                0x00,
                0x00,
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
        let mut data = vec![0x11];
        data.extend_from_slice(&host_nonce);
        data.extend_from_slice(&device_nonce);
        data.extend_from_slice(&eph_pub);
        let sig = root.sign(&data)?;
        device
            .send(&Apdu::with_data(
                0xe0,
                0x51,
                0x80,
                0x00,
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
            let x = ecdh_x(&RootKeyScalar(scalar), &dev_eph)?;
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
            let siv = AesSiv::new(&key);
            let open = |c: &[u8]| {
                siv.open(&[], c)
                    .map_err(|_| Error::InvalidResponse("cannot decrypt device certificate".into()))
            };
            let static_cert = open(&static_cert)?;
            dev_eph_sig = open(&dev_eph_sig)?;
            (Session::Recover { siv }, static_cert)
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
            version,
        })
    }

    /// Channel flavor.
    pub fn mode(&self) -> ScpMode {
        match self.session {
            Session::Default { .. } => ScpMode::Default,
            Session::Recover { .. } => ScpMode::Recover,
        }
    }

    fn wrap(&mut self, plain: &[u8]) -> Vec<u8> {
        let (enc, mac, enc_iv, mac_iv) = match &mut self.session {
            Session::Recover { siv } => return siv.seal(&[], plain),
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

    fn unwrap(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let (enc, mac, enc_iv, mac_iv) = match &mut self.session {
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

    /// Send a secure command (`ins` + `data`), returning the decrypted response.
    pub async fn exchange(&mut self, ins: u8, data: &[u8]) -> Result<Vec<u8>> {
        let mut plain = vec![ins];
        plain.extend_from_slice(data);
        if plain.len() > 239 {
            return Err(Error::InvalidInput("secure command too long".into()));
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
        self.unwrap(&r.data)
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
        let mut d = self.exchange(ins::LIST_APPS, &[]).await?;
        while !d.is_empty() {
            let mut r = Reader::new(&d);
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
