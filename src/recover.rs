//! Seed backup through the Recover protocol, with your own CA as the backup
//! service.
//!
//! The dashboard can split the seed into 3 shares (threshold 2, Pedersen VSS
//! on secp384r1) and hand each one, encrypted, to a *backup provider*. Every
//! party is certified by the custom CA installed through the Recover
//! channel ([`crate::scp::SecureChannel::recover_set_ca`], recovery mode):
//!
//! * an **orchestrator** opens a Recover secure channel (its key certified by
//!   the CA);
//! * each **provider** presents a CA-signed certificate and an ephemeral key,
//!   which yields an AES-SIV key shared with the device;
//! * the user confirms the backup identity on the device (name, birth date...);
//! * backup: the device exports each share with the commitments, which the
//!   provider verifies; restore (on a device being onboarded with "restore
//!   from backup"): providers send their share back; delete: the device
//!   proves the deletion with the share's delete key.
//!
//! [`RecoverConfig`] and [`ShareBackup`] use the JSON formats of the vendor's
//! legacy tooling (`conf.json`, `Backup_N.json`, `DeleteBackup_N.json`).
//!
//! **While a custom CA is installed, app installs from the vendor fail**:
//! remove the CA once done.

use std::collections::BTreeMap;

use num_bigint::{BigInt, Sign};
use purecrypto::cipher::AesSiv;
use purecrypto::hash::sha256;
use serde::{Deserialize, Serialize};

use crate::device::Device;
use crate::error::{Error, Result};
use crate::scp::{HostAuth, RootKey, ScpEvent, ScpMode, SecureChannel, recover_siv_key};
use crate::transport::Transport;

const CERT_FORMAT_VERSION: u8 = 0x01;
const ROLE_PROVIDER: u8 = 0x04;
const ROLE_PROVIDER_EPHEMERAL: u8 = 0x14;
const INS_CONFIRM_ID: u8 = 0xd4;
const INS_VALIDATE_CERTIFICATE: u8 = 0xd5;
const INS_MUTUAL_AUTH: u8 = 0xd6;
const INS_VALIDATE_HASH: u8 = 0xd7;
const INS_GET_SHARE: u8 = 0xd8;
const INS_VALIDATE_COMMIT: u8 = 0xd9;
const INS_RESTORE_SEED: u8 = 0xda;
const INS_DELETE_BACKUP: u8 = 0xdb;
/// Shares produced per backup, and needed to restore.
pub const SHARES: usize = 3;
pub const THRESHOLD: usize = 2;

// ---------------------------------------------------------------- P-384 --

/// Minimal affine arithmetic on secp384r1 (public data only: verification of
/// the VSS commitments).
mod p384 {
    use super::*;

    pub const LEN: usize = 48;

    fn hex(s: &str) -> BigInt {
        BigInt::parse_bytes(s.as_bytes(), 16).unwrap()
    }

    pub struct Curve {
        pub p: BigInt,
        pub a: BigInt,
        pub b: BigInt,
        pub n: BigInt,
        pub g: Point,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Point {
        Infinity,
        Affine(BigInt, BigInt),
    }

    pub fn curve() -> Curve {
        let p = hex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        );
        Curve {
            a: &p - 3,
            b: hex(
                "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
            ),
            n: hex(
                "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            ),
            g: Point::Affine(
                hex(
                    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
                ),
                hex(
                    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
                ),
            ),
            p,
        }
    }

    impl Curve {
        fn m(&self, v: BigInt) -> BigInt {
            let r = v % &self.p;
            if r.sign() == Sign::Minus {
                r + &self.p
            } else {
                r
            }
        }

        fn inv(&self, v: &BigInt) -> BigInt {
            v.modpow(&(&self.p - 2), &self.p)
        }

        pub fn on_curve(&self, pt: &Point) -> bool {
            match pt {
                Point::Infinity => true,
                Point::Affine(x, y) => self.m(y * y) == self.m(x * x * x + &self.a * x + &self.b),
            }
        }

        pub fn add(&self, p1: &Point, p2: &Point) -> Point {
            let (x1, y1, x2, y2) = match (p1, p2) {
                (Point::Infinity, q) | (q, Point::Infinity) => return q.clone(),
                (Point::Affine(x1, y1), Point::Affine(x2, y2)) => (x1, y1, x2, y2),
            };
            let l = if x1 == x2 {
                if self.m(y1 + y2) == BigInt::from(0) {
                    return Point::Infinity;
                }
                self.m((x1 * x1 * 3 + &self.a) * self.inv(&self.m(y1 * 2)))
            } else {
                self.m((y2 - y1) * self.inv(&self.m(x2 - x1)))
            };
            let x3 = self.m(&l * &l - x1 - x2);
            let y3 = self.m(&l * (x1 - &x3) - y1);
            Point::Affine(x3, y3)
        }

        pub fn mul(&self, k: &BigInt, pt: &Point) -> Point {
            let k = {
                let r = k % &self.n;
                if r.sign() == Sign::Minus {
                    r + &self.n
                } else {
                    r
                }
            };
            let mut acc = Point::Infinity;
            for byte in k.to_bytes_be().1 {
                for bit in (0..8).rev() {
                    acc = self.add(&acc, &acc);
                    if (byte >> bit) & 1 == 1 {
                        acc = self.add(&acc, pt);
                    }
                }
            }
            acc
        }

        /// Parse `x || y` (48 bytes each).
        pub fn point(&self, b: &[u8]) -> Result<Point> {
            if b.len() != 2 * LEN {
                return Err(Error::InvalidResponse(
                    "P-384 point must be 96 bytes".into(),
                ));
            }
            let pt = Point::Affine(
                BigInt::from_bytes_be(Sign::Plus, &b[..LEN]),
                BigInt::from_bytes_be(Sign::Plus, &b[LEN..]),
            );
            if !self.on_curve(&pt) {
                return Err(Error::InvalidResponse("point not on P-384".into()));
            }
            Ok(pt)
        }

        pub fn encode(&self, pt: &Point) -> Vec<u8> {
            let pad = |v: &BigInt| {
                let b = v.to_bytes_be().1;
                let mut out = vec![0u8; LEN - b.len()];
                out.extend(b);
                out
            };
            match pt {
                Point::Infinity => vec![0; 2 * LEN],
                Point::Affine(x, y) => [pad(x), pad(y)].concat(),
            }
        }
    }
}

/// Pedersen commitment of a share `(a || b)`: `a*G + b*Q`.
pub fn share_commit(point_q: &[u8], share: &[u8]) -> Result<Vec<u8>> {
    let c = p384::curve();
    if share.len() != 2 * p384::LEN {
        return Err(Error::InvalidInput("share must be 96 bytes".into()));
    }
    let q = c.point(point_q)?;
    let a = BigInt::from_bytes_be(Sign::Plus, &share[..p384::LEN]);
    let b = BigInt::from_bytes_be(Sign::Plus, &share[p384::LEN..]);
    let s = c.add(&c.mul(&a, &c.g), &c.mul(&b, &q));
    Ok(c.encode(&s))
}

/// Verify a share against the VSS commitments: `commit(share) == sum C_i * index^i`.
/// Returns the share commitment.
pub fn verify_share(
    point_q: &[u8],
    share: &[u8],
    index: u32,
    commitments: &[u8],
) -> Result<Vec<u8>> {
    let c = p384::curve();
    let s = share_commit(point_q, share)?;
    let n = 2 * p384::LEN;
    if commitments.is_empty() || !commitments.len().is_multiple_of(n) {
        return Err(Error::InvalidResponse("bad commitments length".into()));
    }
    let mut r = p384::Point::Infinity;
    for (i, chunk) in commitments.chunks(n).enumerate() {
        let ci = c.point(chunk)?;
        let e = BigInt::from(index).pow(i as u32);
        r = c.add(&r, &c.mul(&e, &ci));
    }
    if c.encode(&r) != s {
        return Err(Error::App("share does not match its commitments".into()));
    }
    Ok(s)
}

// -------------------------------------------------------------- combine --

/// BIP-39 English word list (sha256 2f5eed53…3b24dbda).
const BIP39_ENGLISH: &str = include_str!("bip39_english.txt");

/// BIP-39 English phrase of `entropy` (16, 20, 24, 28 or 32 bytes).
pub fn bip39_phrase(entropy: &[u8]) -> Result<String> {
    if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
        return Err(Error::InvalidInput(format!(
            "BIP-39 entropy must be 16 to 32 bytes, got {}",
            entropy.len()
        )));
    }
    let words: Vec<&str> = BIP39_ENGLISH.lines().collect();
    let checksum_bits = entropy.len() / 4;
    let hash = sha256(entropy);
    let bit = |i: usize| {
        let byte = if i < entropy.len() * 8 {
            entropy[i / 8]
        } else {
            hash[(i - entropy.len() * 8) / 8]
        };
        (byte >> (7 - i % 8)) & 1
    };
    let total = entropy.len() * 8 + checksum_bits;
    Ok((0..total / 11)
        .map(|w| {
            let idx = (0..11).fold(0usize, |acc, b| (acc << 1) | bit(w * 11 + b) as usize);
            words[idx]
        })
        .collect::<Vec<_>>()
        .join(" "))
}

/// Rebuild the seed entropy from at least [`THRESHOLD`] share files
/// (`Backup_N.json` entries), **without a device**: Lagrange interpolation at
/// 0 of the first half of each share (`s_i = f(i)`, `f(x) = entropy + a·x mod
/// N` on secp384r1, per the Recover white paper). Every share is checked
/// against its commitments first. Returns the entropy; [`bip39_phrase`] turns
/// it into the recovery phrase.
pub fn combine(shares: &[ShareBackup]) -> Result<Vec<u8>> {
    if shares.len() < THRESHOLD {
        return Err(Error::InvalidInput(format!(
            "at least {THRESHOLD} shares are needed"
        )));
    }
    let dec =
        |h: &str| hex::decode(h).map_err(|e| Error::InvalidInput(format!("backup file: {e}")));
    let n = p384::curve().n;
    let mut points: Vec<(BigInt, BigInt)> = Vec::new();
    let first = &shares[0];
    for b in shares {
        if b.commitments != first.commitments || b.words_number != first.words_number {
            return Err(Error::InvalidInput(
                "the shares come from different backups".into(),
            ));
        }
        let share = dec(&b.share)?;
        let index_bytes: [u8; 4] = dec(&b.index)?
            .try_into()
            .map_err(|_| Error::InvalidInput("backup file: index must be 4 bytes".into()))?;
        let index = u32::from_le_bytes(index_bytes);
        verify_share(&dec(&b.point)?, &share, index, &dec(&b.commitments)?)?;
        let x = BigInt::from(index);
        if points.iter().any(|(px, _)| *px == x) {
            return Err(Error::InvalidInput("the same share was given twice".into()));
        }
        points.push((x, BigInt::from_bytes_be(Sign::Plus, &share[..p384::LEN])));
    }
    // f(0) = sum y_i * prod_{j != i} x_j / (x_j - x_i)   (mod N)
    let modn = |v: BigInt| ((v % &n) + &n) % &n;
    let mut secret = BigInt::from(0);
    for (i, (xi, yi)) in points.iter().enumerate() {
        let (mut num, mut den) = (BigInt::from(1), BigInt::from(1));
        for (j, (xj, _)) in points.iter().enumerate() {
            if i != j {
                num = modn(num * xj);
                den = modn(den * (xj - xi));
            }
        }
        let inv = den
            .modinv(&n)
            .ok_or_else(|| Error::InvalidInput("degenerate share indexes".into()))?;
        secret = modn(secret + yi * num * inv);
    }
    let len = match first.words_number {
        12 => 16,
        18 => 24,
        _ => 32,
    };
    let bytes = secret.to_bytes_be().1;
    if bytes.len() > len {
        return Err(Error::App(format!(
            "the rebuilt secret is {} bytes, more than the {len} bytes of a {}-word phrase",
            bytes.len(),
            len * 3 / 4
        )));
    }
    let mut out = vec![0u8; len - bytes.len()];
    out.extend(bytes);
    Ok(out)
}

// --------------------------------------------------------------- config --

/// Identity shown on the device during backup / restore.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub first_name: String,
    pub last_name: String,
    pub birth: String,
    pub city: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupInfo {
    /// 16 bytes (a UUID v4 without dashes), hex.
    pub backup_id: String,
    pub backup_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyEntry {
    #[serde(default)]
    pub name: String,
    /// secp256k1 private key, hex.
    pub key: String,
}

/// Recover configuration (`conf.json` of the legacy tooling).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoverConfig {
    pub user_info: UserInfo,
    pub backup_info: BackupInfo,
    pub orchestrator: KeyEntry,
    pub providers: Vec<KeyEntry>,
}

impl RecoverConfig {
    /// A new configuration with fresh orchestrator / provider keys and a
    /// random backup id.
    pub fn generate(user: UserInfo, backup_name: &str) -> Result<Self> {
        let mut id = [0u8; 16];
        crate::attestation::rand_bytes(&mut id)?;
        id[6] = (id[6] & 0x0f) | 0x40; // UUID v4
        id[8] = (id[8] & 0x3f) | 0x80;
        let key = || RootKey::generate().map(|k| hex::encode(k.to_bytes()));
        Ok(Self {
            user_info: user,
            backup_info: BackupInfo {
                backup_id: hex::encode(id),
                backup_name: backup_name.into(),
            },
            orchestrator: KeyEntry {
                name: String::new(),
                key: key()?,
            },
            providers: (1..=SHARES)
                .map(|i| {
                    Ok(KeyEntry {
                        name: format!("Backup_{i}"),
                        key: key()?,
                    })
                })
                .collect::<Result<_>>()?,
        })
    }

    fn backup_id(&self) -> Result<Vec<u8>> {
        let id = hex::decode(&self.backup_info.backup_id)
            .map_err(|e| Error::InvalidInput(format!("backup_id: {e}")))?;
        if id.len() != 16 {
            return Err(Error::InvalidInput(
                "backup_id must be 16 bytes (UUID without dashes)".into(),
            ));
        }
        Ok(id)
    }

    /// Identity payload (`backup_id || LV(name) || tagged LV fields || flow`).
    fn idv(&self, delete: bool) -> Result<Vec<u8>> {
        let u = &self.user_info;
        let mut d = self.backup_id()?;
        let mut lv = |tag: Option<u8>, v: &str| -> Result<()> {
            if v.len() > 255 {
                return Err(Error::InvalidInput("identity field too long".into()));
            }
            if let Some(t) = tag {
                d.push(t);
            }
            d.push(v.len() as u8);
            d.extend_from_slice(v.as_bytes());
            Ok(())
        };
        lv(None, &self.backup_info.backup_name)?;
        lv(Some(0x20), &u.first_name)?;
        lv(Some(0x21), &u.last_name)?;
        lv(Some(0x22), &u.birth)?;
        lv(Some(0x23), &u.city)?;
        d.push(delete as u8);
        Ok(d)
    }

    /// `sha256(provider_ephemeral_pub || backup_id || sha256(name || identity))`.
    fn data_hash(&self, provider_ephemeral: &[u8]) -> Result<[u8; 32]> {
        let u = &self.user_info;
        let inner = sha256(
            format!(
                "{}{}{}{}{}",
                self.backup_info.backup_name, u.first_name, u.last_name, u.birth, u.city
            )
            .as_bytes(),
        );
        let mut d = provider_ephemeral.to_vec();
        d.extend(self.backup_id()?);
        d.extend_from_slice(&inner);
        Ok(sha256(&d))
    }

    fn provider(&self, name: &str) -> Result<(String, RootKey)> {
        let p = self
            .providers
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| {
                Error::NotFound(format!("provider {name:?} not in the configuration"))
            })?;
        Ok((p.name.clone(), RootKey::from_hex(&p.key)?))
    }
}

/// One share as kept by a provider (`Backup_N.json` entry).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareBackup {
    pub share: String,
    /// Share index, u32 little endian, hex.
    pub index: String,
    pub commitments: String,
    pub share_commit: String,
    pub hash: String,
    pub point: String,
    pub words_number: u8,
}

/// Result of a backup, per provider.
#[derive(Clone, Debug, Serialize)]
pub struct ProviderBackup {
    pub provider: String,
    pub backup: ShareBackup,
    /// Public key proving a later deletion (`DeleteBackup_N.json`).
    pub delete_public_key: String,
}

impl ProviderBackup {
    /// `Backup_N.json` content.
    pub fn backup_json(&self) -> serde_json::Value {
        serde_json::json!({ &self.provider: &self.backup })
    }

    /// `DeleteBackup_N.json` content.
    pub fn delete_json(&self) -> serde_json::Value {
        serde_json::json!({ &self.provider: { "public_key": &self.delete_public_key } })
    }
}

/// Events of the Recover flows.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(
        tag = "type",
        rename_all = "camelCase",
        rename_all_fields = "camelCase"
    )
)]
pub enum RecoverEvent {
    /// Secure channel handshake (allow the orchestrator).
    Channel { event: ScpEvent },
    /// Working with this provider.
    Provider { name: String },
    /// The device asks to confirm the identity (or shows a code).
    ConfirmOnDevice,
    /// A share was received and verified.
    ShareVerified { name: String },
}

// ----------------------------------------------------------------- flows --

struct Session<'d, T: Transport> {
    chan: SecureChannel<'d, T>,
    confirmed: bool,
}

fn siv_seal(key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    AesSiv::new(key).seal(&[], plain)
}

fn siv_open(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    AesSiv::new(key)
        .open(&[], data)
        .map_err(|_| Error::InvalidResponse("provider payload tag mismatch".into()))
}

fn lv(data: &[u8]) -> Vec<u8> {
    let mut v = vec![data.len() as u8];
    v.extend_from_slice(data);
    v
}

impl<'d, T: Transport> Session<'d, T> {
    async fn open(
        device: &'d Device<T>,
        ca: &RootKey,
        conf: &RecoverConfig,
        on_event: &mut dyn FnMut(RecoverEvent),
    ) -> Result<Self> {
        let orchestrator = RootKey::from_hex(&conf.orchestrator.key)?;
        let chan = SecureChannel::open_with(
            device,
            HostAuth::Orchestrator {
                ca,
                orchestrator: &orchestrator,
            },
            ScpMode::Recover,
            &mut |event| on_event(RecoverEvent::Channel { event }),
        )
        .await?;
        Ok(Self {
            chan,
            confirmed: false,
        })
    }

    /// Certificates, mutual auth, identity (once) and data hash for one
    /// provider. Returns the provider key and the device's hash answer.
    async fn provider(
        &mut self,
        ca: &RootKey,
        conf: &RecoverConfig,
        name: &str,
        provider: &RootKey,
        delete: bool,
        on_event: &mut dyn FnMut(RecoverEvent),
    ) -> Result<([u8; 32], Vec<u8>)> {
        on_event(RecoverEvent::Provider { name: name.into() });
        let cert = |role: u8, key: &[u8], signer: &RootKey| -> Result<Vec<u8>> {
            let mut signed = vec![CERT_FORMAT_VERSION, role];
            signed.extend(lv(name.as_bytes()));
            signed.extend(lv(key));
            let sig = signer.sign(&signed)?;
            let mut d = signed;
            d.extend(lv(&sig));
            Ok(d)
        };
        // Static certificate, signed by the CA.
        let mut d = vec![0x00];
        d.extend(cert(ROLE_PROVIDER, &provider.public_key(), ca)?);
        self.chan.exchange(INS_VALIDATE_CERTIFICATE, &d).await?;
        // Ephemeral certificate, signed by the provider.
        let eph = RootKey::generate()?;
        let eph_pub = eph.public_key();
        let mut d = vec![0x80];
        d.extend(cert(ROLE_PROVIDER_EPHEMERAL, &eph_pub, provider)?);
        self.chan.exchange(INS_VALIDATE_CERTIFICATE, &d).await?;
        self.chan.exchange(INS_MUTUAL_AUTH, &[]).await?;
        let key = recover_siv_key(&eph, &self.chan.device_ephemeral_key)?;
        if !self.confirmed {
            on_event(RecoverEvent::ConfirmOnDevice);
            self.chan
                .exchange(INS_CONFIRM_ID, &lv(&siv_seal(&key, &conf.idv(delete)?)))
                .await?;
            self.confirmed = true;
        }
        let hash = conf.data_hash(&eph_pub)?;
        let resp = self
            .chan
            .exchange(INS_VALIDATE_HASH, &lv(&siv_seal(&key, &hash)))
            .await?;
        Ok((key, resp))
    }
}

/// Back up the seed: one share per provider of the configuration (3).
/// The device must be onboarded, on the dashboard, with the CA installed
/// through the Recover channel.
pub async fn backup<T: Transport>(
    device: &Device<T>,
    ca: &RootKey,
    conf: &RecoverConfig,
    on_event: &mut dyn FnMut(RecoverEvent),
) -> Result<Vec<ProviderBackup>> {
    if conf.providers.len() != SHARES {
        return Err(Error::InvalidInput(format!(
            "the configuration needs {SHARES} providers"
        )));
    }
    let mut s = Session::open(device, ca, conf, on_event).await?;
    let mut out = Vec::new();
    for p in &conf.providers {
        let provider = RootKey::from_hex(&p.key)?;
        let (key, _) = s
            .provider(ca, conf, &p.name, &provider, false, on_event)
            .await?;
        let resp = s.chan.exchange(INS_GET_SHARE, &[0x00]).await?;
        let (enc, words) = resp.split_at(resp.len().saturating_sub(1));
        let plain = siv_open(&key, enc)?;
        if plain.len() < 96 + 4 + 65 + 32 {
            return Err(Error::InvalidResponse("short share".into()));
        }
        let share = &plain[..96];
        let index = u32::from_le_bytes(plain[96..100].try_into().unwrap());
        let delete_key = &plain[100..165];
        let commit_hash = &plain[165..];
        let commitments = s.chan.exchange(INS_GET_SHARE, &[0x01]).await?;
        let point = s.chan.exchange(INS_GET_SHARE, &[0x10]).await?;
        if sha256(&commitments)[..] != *commit_hash {
            return Err(Error::App("commitments do not match their hash".into()));
        }
        let commit = verify_share(&point, share, index, &commitments)?;
        // Acknowledge the share commitment.
        let mut d = vec![0x04];
        d.extend(lv(&commit));
        s.chan.exchange(INS_VALIDATE_COMMIT, &d).await?;
        let mut d = vec![0x03];
        d.extend(lv(&siv_seal(&key, &sha256(&commit))));
        s.chan.exchange(INS_VALIDATE_COMMIT, &d).await?;
        on_event(RecoverEvent::ShareVerified {
            name: p.name.clone(),
        });
        out.push(ProviderBackup {
            provider: p.name.clone(),
            backup: ShareBackup {
                share: hex::encode(share),
                index: hex::encode(index.to_le_bytes()),
                commitments: hex::encode(&commitments),
                share_commit: hex::encode(&commit),
                hash: hex::encode(commit_hash),
                point: hex::encode(&point),
                words_number: words.first().copied().unwrap_or(24),
            },
            delete_public_key: hex::encode(delete_key),
        });
    }
    Ok(out)
}

/// Restore the seed from at least [`THRESHOLD`] shares, on a device being
/// onboarded with "restore from a backup".
pub async fn restore<T: Transport>(
    device: &Device<T>,
    ca: &RootKey,
    conf: &RecoverConfig,
    shares: &BTreeMap<String, ShareBackup>,
    on_event: &mut dyn FnMut(RecoverEvent),
) -> Result<()> {
    if shares.len() < THRESHOLD {
        return Err(Error::InvalidInput(format!(
            "at least {THRESHOLD} shares are needed"
        )));
    }
    let mut s = Session::open(device, ca, conf, on_event).await?;
    for (name, b) in shares {
        let (name, provider) = conf.provider(name)?;
        let (key, resp) = s
            .provider(ca, conf, &name, &provider, false, on_event)
            .await?;
        if siv_open(&key, &resp)? != b"Confirm restore" {
            return Err(Error::App("the device is not waiting for a restore".into()));
        }
        let dec =
            |h: &str| hex::decode(h).map_err(|e| Error::InvalidInput(format!("backup file: {e}")));
        let (share, index, commitments, point) = (
            dec(&b.share)?,
            dec(&b.index)?,
            dec(&b.commitments)?,
            dec(&b.point)?,
        );
        let commit = share_commit(&point, &share)?;
        let mut d = vec![0x02];
        d.extend(lv(&commitments));
        s.chan.exchange(INS_VALIDATE_COMMIT, &d).await?;
        let mut d = vec![0x04];
        d.extend(lv(&commit));
        s.chan.exchange(INS_VALIDATE_COMMIT, &d).await?;
        let mut d = vec![0x03];
        d.extend(lv(&siv_seal(
            &key,
            &sha256(&[commitments.as_slice(), commit.as_slice()].concat()),
        )));
        s.chan.exchange(INS_VALIDATE_COMMIT, &d).await?;
        let p1 = match b.words_number {
            12 => 0x0c,
            18 => 0x12,
            _ => 0x00,
        };
        let mut d = vec![p1];
        d.extend(lv(&siv_seal(
            &key,
            &[share.as_slice(), index.as_slice()].concat(),
        )));
        s.chan.exchange(INS_RESTORE_SEED, &d).await?;
        on_event(RecoverEvent::ShareVerified { name });
    }
    Ok(())
}

/// Delete backups: the device signs a fresh nonce with each share's delete
/// key, verified against the provider's `DeleteBackup_N.json` public key.
pub async fn delete<T: Transport>(
    device: &Device<T>,
    ca: &RootKey,
    conf: &RecoverConfig,
    delete_keys: &BTreeMap<String, String>,
    on_event: &mut dyn FnMut(RecoverEvent),
) -> Result<()> {
    let mut s = Session::open(device, ca, conf, on_event).await?;
    for (name, public_key) in delete_keys {
        let (name, provider) = conf.provider(name)?;
        let (key, _) = s
            .provider(ca, conf, &name, &provider, true, on_event)
            .await?;
        let mut nonce = [0u8; 16];
        crate::attestation::rand_bytes(&mut nonce)?;
        let resp = s
            .chan
            .exchange(INS_DELETE_BACKUP, &lv(&siv_seal(&key, &nonce)))
            .await?;
        let sig = siv_open(&key, &resp)?;
        let pk =
            hex::decode(public_key).map_err(|e| Error::InvalidInput(format!("delete key: {e}")))?;
        if !crate::attestation::verify(&pk, &nonce, &sig) {
            return Err(Error::App(format!(
                "{name}: deletion proof does not verify"
            )));
        }
        on_event(RecoverEvent::ShareVerified { name });
    }
    Ok(())
}

#[cfg(test)]
mod combine_tests {
    use super::*;

    #[test]
    fn bip39_vectors() {
        let z = |n: usize| vec![0u8; n];
        assert_eq!(
            bip39_phrase(&z(16)).unwrap(),
            format!("{}about", "abandon ".repeat(11))
        );
        assert_eq!(
            bip39_phrase(&z(32)).unwrap(),
            format!("{}art", "abandon ".repeat(23))
        );
        assert_eq!(
            bip39_phrase(&[0x7f; 16]).unwrap(),
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        );
        assert_eq!(
            bip39_phrase(&[0xff; 32]).unwrap(),
            format!("{}vote", "zoo ".repeat(23))
        );
        assert!(bip39_phrase(&z(15)).is_err());
    }

    /// White paper Q point ("Ledger Recover Auxiliary VSS Point seed").
    const Q: &str = "fbfc7b98c353a92621854e13d1efbcf1385601a5ce14f5b64eb722ddc52b5690f302663f904679847fc5114dcc7d94ed3b59569d2791c3a8e1bc8c32b5c0e537d1a4a95f0c3b16c493e5d69fec29ead4c95f7ed6b9c561a856a7b83d980f1cd8";

    /// A 2-of-3 Pedersen sharing of `entropy`, as the device would produce it.
    fn share(entropy: &[u8], words: u8) -> Vec<ShareBackup> {
        let c = p384::curve();
        let q_bytes = hex::decode(Q).unwrap();
        let q = c.point(&q_bytes).unwrap();
        let big = |h: &str| BigInt::parse_bytes(h.as_bytes(), 16).unwrap();
        let (e, a) = (
            BigInt::from_bytes_be(Sign::Plus, entropy),
            big("1234567890abcdef1234"),
        );
        let (t, b) = (big("fedcba9876543210"), big("0badc0ffee"));
        let commit = |x: &BigInt, y: &BigInt| c.encode(&c.add(&c.mul(x, &c.g), &c.mul(y, &q)));
        let commitments = [commit(&e, &t), commit(&a, &b)].concat();
        let pad = |v: BigInt| {
            let v = ((v % &c.n) + &c.n) % &c.n;
            let bytes = v.to_bytes_be().1;
            [vec![0u8; p384::LEN - bytes.len()], bytes].concat()
        };
        let base: u32 = 0x1234_5678;
        (0..3)
            .map(|k| {
                let i = BigInt::from(base + k);
                let s = [pad(&e + &a * &i), pad(&t + &b * &i)].concat();
                ShareBackup {
                    share: hex::encode(&s),
                    index: hex::encode((base + k).to_le_bytes()),
                    commitments: hex::encode(&commitments),
                    share_commit: String::new(),
                    hash: String::new(),
                    point: Q.into(),
                    words_number: words,
                }
            })
            .collect()
    }

    #[test]
    fn combine_any_two_shares() {
        let entropy: Vec<u8> = (1..=32).collect();
        let s = share(&entropy, 24);
        for pair in [[0, 1], [0, 2], [2, 1]] {
            let two = [s[pair[0]].clone(), s[pair[1]].clone()];
            assert_eq!(combine(&two).unwrap(), entropy);
        }
        assert_eq!(combine(&s).unwrap(), entropy);
        // Null seed, 24 words.
        let s = share(&[0u8; 32], 24);
        let phrase = bip39_phrase(&combine(&s[..2]).unwrap()).unwrap();
        assert_eq!(phrase, format!("{}art", "abandon ".repeat(23)));
    }

    #[test]
    fn combine_rejects_bad_input() {
        let s = share(&[7u8; 32], 24);
        assert!(combine(&s[..1]).is_err());
        assert!(combine(&[s[0].clone(), s[0].clone()]).is_err());
        let mut bad = s[1].clone();
        bad.share
            .replace_range(..2, if &bad.share[..2] == "00" { "01" } else { "00" });
        assert!(combine(&[s[0].clone(), bad]).is_err());
        let other = share(&[8u8; 32], 24);
        assert!(combine(&[s[0].clone(), other[1].clone()]).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p384_arithmetic() {
        let c = p384::curve();
        assert!(c.on_curve(&c.g));
        // n * G = infinity, (n + 1) * G = G
        assert_eq!(c.mul(&c.n, &c.g), p384::Point::Infinity);
        let two = c.add(&c.g, &c.g);
        assert!(c.on_curve(&two));
        assert_eq!(c.mul(&BigInt::from(2), &c.g), two);
        // (a + b) G = aG + bG
        let (a, b) = (BigInt::from(123456789u64), BigInt::from(987654321u64));
        assert_eq!(
            c.mul(&(&a + &b), &c.g),
            c.add(&c.mul(&a, &c.g), &c.mul(&b, &c.g))
        );
        // 2G known value
        let enc = c.encode(&two);
        assert_eq!(
            hex::encode(&enc[..48]),
            "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61"
        );
    }

    #[test]
    fn vss_roundtrip() {
        // Dealer side: secret polynomial f(x) = a0 + a1 x, blinding g(x) = b0 + b1 x,
        // commitments C_i = a_i G + b_i Q; share i = (f(i), g(i)).
        let c = p384::curve();
        let q = c.mul(&BigInt::from(77u32), &c.g);
        let qb = c.encode(&q);
        let (a0, a1, b0, b1) = (
            BigInt::from(11u32),
            BigInt::from(22u32),
            BigInt::from(33u32),
            BigInt::from(44u32),
        );
        let commit = |a: &BigInt, b: &BigInt| c.encode(&c.add(&c.mul(a, &c.g), &c.mul(b, &q)));
        let commitments = [commit(&a0, &b0), commit(&a1, &b1)].concat();
        let idx = 5u32;
        let pad = |v: BigInt| {
            let b = v.to_bytes_be().1;
            let mut out = vec![0u8; 48 - b.len()];
            out.extend(b);
            out
        };
        let share = [pad(&a0 + &a1 * idx), pad(&b0 + &b1 * idx)].concat();
        assert!(verify_share(&qb, &share, idx, &commitments).is_ok());
        assert!(verify_share(&qb, &share, idx + 1, &commitments).is_err());
    }

    #[test]
    fn config_roundtrip() {
        let conf = RecoverConfig::generate(
            UserInfo {
                first_name: "John".into(),
                last_name: "Doe".into(),
                birth: "1 Jan 1980".into(),
                city: "".into(),
            },
            "test",
        )
        .unwrap();
        let json = serde_json::to_string(&conf).unwrap();
        let back: RecoverConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.providers.len(), 3);
        let idv = back.idv(false).unwrap();
        assert_eq!(
            &idv[..16],
            &hex::decode(&back.backup_info.backup_id).unwrap()[..]
        );
        assert_eq!(*idv.last().unwrap(), 0);
    }
}
