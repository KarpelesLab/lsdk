//! Offline genuine check: device attestation without contacting the vendor.
//!
//! The host opens the dashboard's secure channel handshake with its own,
//! self-signed key (so the device asks the user to allow an *insecure /
//! foreign manager connection*), then asks the device for:
//!
//! 1. its factory certificate: the device public key signed by the vendor
//!    issuer key, over `sha256(0x02 || header || device_pubkey)`;
//! 2. a fresh ephemeral key signed by that device key, over
//!    `sha256(0x12 || device_nonce || host_nonce || ephemeral_pubkey)`.
//!
//! (1) checked against a pinned issuer public key shows the device key was
//! certified at manufacturing; (2) shows the device holds that key right now
//! (the host nonce makes it non-replayable). Nothing leaves the machine.
//!
//! The handshake is not completed (no secure channel is opened), so this
//! cannot change anything on the device. As a side effect, the next online
//! manager operation asks again to allow the secure connection.

use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use purecrypto::ec::{Secp256k1EcdsaPrivateKey, Secp256k1EcdsaPublicKey, Secp256k1EcdsaSignature};
use purecrypto::hash::{Sha256, sha256};

use crate::apdu::{Apdu, Reader, StatusWord};
use crate::device::Device;
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Issuer public keys the device certificate is checked against.
///
/// The first one is the issuer key published with the vendor's legacy Python
/// loader (`checkGenuine.py`).
pub const KNOWN_ISSUER_KEYS: &[(&str, &str)] = &[(
    "vendor issuer key #1",
    "0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609",
)];

/// Events reported during the check.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "camelCase"))]
pub enum AttestationEvent {
    /// The device asks the user to allow the (insecure) connection.
    PermissionRequested,
    /// The user allowed it.
    PermissionGranted,
    /// The device is signing its ephemeral key (takes a few seconds).
    Attesting,
}

/// Outcome of the offline check.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Attestation {
    /// Device certificate signed by a known issuer key, and live proof of
    /// possession of the certified device key.
    pub genuine: bool,
    /// Name of the issuer key that signed the device certificate.
    pub issuer: Option<String>,
    /// The device signed the fresh ephemeral key with its certified key.
    pub proof_of_possession: bool,
    pub target_id: u32,
    /// Batch signer serial reported by the device (hex).
    pub signer_serial: String,
    /// Device attestation public key (hex, uncompressed).
    pub device_public_key: String,
    /// Certificate header (hex).
    pub certificate_header: String,
    /// Issuer certificate signature (hex DER).
    pub certificate_signature: String,
    /// Public keys that could have produced the device certificate signature
    /// (recovered from it). One of them is the actual issuer key: useful to
    /// identify and pin the issuer of a model not in [`KNOWN_ISSUER_KEYS`].
    pub issuer_candidates: Vec<String>,
}

fn rand_bytes(buf: &mut [u8]) -> Result<()> {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast;
        let crypto = js_sys::Reflect::get(&js_sys::global(), &"crypto".into())
            .map_err(|_| Error::App("no crypto.getRandomValues".into()))?;
        let f: js_sys::Function = js_sys::Reflect::get(&crypto, &"getRandomValues".into())
            .ok()
            .and_then(|f| f.dyn_into().ok())
            .ok_or_else(|| Error::App("no crypto.getRandomValues".into()))?;
        let arr = js_sys::Uint8Array::new_with_length(buf.len() as u32);
        f.call1(&crypto, &arr)
            .map_err(|_| Error::App("getRandomValues failed".into()))?;
        arr.copy_to(buf);
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use purecrypto::rng::{OsRng, RngCore};
        OsRng.fill_bytes(buf);
        Ok(())
    }
}

fn random_key() -> Result<Secp256k1EcdsaPrivateKey> {
    loop {
        let mut k = [0u8; 32];
        rand_bytes(&mut k)?;
        if let Ok(key) = Secp256k1EcdsaPrivateKey::from_bytes(&k) {
            return Ok(key);
        }
    }
}

/// DER-encode an ECDSA signature.
fn der_encode(sig: &Secp256k1EcdsaSignature) -> Vec<u8> {
    fn int(v: &[u8; 32]) -> Vec<u8> {
        let mut b: Vec<u8> = v.iter().copied().skip_while(|x| *x == 0).collect();
        if b.is_empty() || b[0] & 0x80 != 0 {
            b.insert(0, 0);
        }
        let mut out = vec![0x02, b.len() as u8];
        out.extend(b);
        out
    }
    let mut body = int(&sig.r_bytes());
    body.extend(int(&sig.s_bytes()));
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

/// Decode a DER ECDSA signature into `(r, s)`.
fn der_decode(der: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let bad = || Error::InvalidResponse("bad DER signature".into());
    let mut r = Reader::new(der);
    if r.u8()? != 0x30 {
        return Err(bad());
    }
    let body = r.lv()?;
    let mut r = Reader::new(body);
    let mut read_int = || -> Result<[u8; 32]> {
        if r.u8()? != 0x02 {
            return Err(bad());
        }
        let v = r.lv()?;
        let v: Vec<u8> = v.iter().copied().skip_while(|x| *x == 0).collect();
        if v.len() > 32 {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        out[32 - v.len()..].copy_from_slice(&v);
        Ok(out)
    };
    let a = read_int()?;
    let b = read_int()?;
    Ok((a, b))
}

fn verify(pubkey: &[u8], msg: &[u8], der_sig: &[u8]) -> bool {
    let Ok(pk) = Secp256k1EcdsaPublicKey::from_sec1(pubkey) else {
        return false;
    };
    let Ok((r, s)) = der_decode(der_sig) else {
        return false;
    };
    pk.verify::<Sha256>(msg, &Secp256k1EcdsaSignature::from_components(&r, &s))
        .is_ok()
}

/// Public keys `Q` for which `(r, s)` is a valid signature of `msg`.
fn recover_candidates(msg: &[u8], der_sig: &[u8]) -> Vec<String> {
    let Ok((r, s)) = der_decode(der_sig) else {
        return Vec::new();
    };
    let (Ok(rs), Ok(ss)) = (Scalar::from_bytes_be(&r), Scalar::from_bytes_be(&s)) else {
        return Vec::new();
    };
    let z = Scalar::from_bytes_be_reduce(&sha256(msg));
    let r_inv = rs.invert();
    let mut out = Vec::new();
    for parity in [0x02u8, 0x03] {
        let mut enc = [0u8; 33];
        enc[0] = parity;
        enc[1..].copy_from_slice(&r);
        let Ok(big_r) = AffinePoint::from_sec1(&enc) else {
            continue;
        };
        // Q = r^-1 (s R - z G)
        let q: ProjectivePoint = big_r
            .to_projective()
            .mul(&ss)
            .add(&ProjectivePoint::mul_generator(&z).negate())
            .mul(&r_inv);
        if let Some(q) = q.to_affine() {
            out.push(hex::encode(q.to_sec1_uncompressed()));
        }
    }
    out
}

/// A host certificate: `len(pub) || pub || len(sig) || sig`.
fn host_certificate(pubkey: &[u8; 65], sig: &[u8]) -> Vec<u8> {
    let mut c = vec![pubkey.len() as u8];
    c.extend_from_slice(pubkey);
    c.push(sig.len() as u8);
    c.extend_from_slice(sig);
    c
}

/// Run the offline genuine check. `extra_issuers` are additional trusted
/// issuer public keys (uncompressed SEC1), checked after [`KNOWN_ISSUER_KEYS`].
pub async fn offline_genuine_check<T: Transport>(
    device: &Device<T>,
    extra_issuers: &[(String, Vec<u8>)],
    on_event: &mut dyn FnMut(AttestationEvent),
) -> Result<Attestation> {
    if !device.is_on_dashboard().await? {
        return Err(Error::DashboardExpected);
    }
    let os = device.get_version().await?;
    if os.is_bootloader {
        return Err(Error::App(
            "finish the firmware update first (device in bootloader mode)".into(),
        ));
    }
    let target_id = os.target_id;

    let refused = |sw: StatusWord| {
        if sw.is_refused() {
            Error::UserRefused
        } else {
            sw.into()
        }
    };

    // Validate target id (P1 = default secure channel).
    device
        .send(&Apdu::with_data(
            0xe0,
            0x04,
            0x00,
            0x00,
            target_id.to_be_bytes().to_vec(),
        ))
        .await?;

    // Exchange nonces.
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
    let signer_serial = hex::encode(&info[..4]);
    let device_nonce: [u8; 8] = info[4..12].try_into().unwrap();

    // Self-signed host root key: the device asks to allow a foreign manager.
    let root = random_key()?;
    let root_pub = root.public_key().to_sec1();
    let mut data = vec![0x01];
    data.extend_from_slice(&root_pub);
    let sig = root
        .sign::<Sha256>(&data)
        .map_err(|e| Error::App(format!("sign: {e:?}")))?;
    on_event(AttestationEvent::PermissionRequested);
    let r = device
        .exchange(&Apdu::with_data(
            0xe0,
            0x51,
            0x00,
            0x00,
            host_certificate(&root_pub, &der_encode(&sig)),
        ))
        .await?;
    if !r.sw.is_ok() {
        return Err(refused(r.sw));
    }
    on_event(AttestationEvent::PermissionGranted);

    // Host ephemeral key, certified by the root over both nonces.
    let eph = random_key()?;
    let eph_pub = eph.public_key().to_sec1();
    let mut data = vec![0x11];
    data.extend_from_slice(&host_nonce);
    data.extend_from_slice(&device_nonce);
    data.extend_from_slice(&eph_pub);
    let sig = root
        .sign::<Sha256>(&data)
        .map_err(|e| Error::App(format!("sign: {e:?}")))?;
    device
        .send(&Apdu::with_data(
            0xe0,
            0x51,
            0x80,
            0x00,
            host_certificate(&eph_pub, &der_encode(&sig)),
        ))
        .await?;

    // Device factory certificate.
    let cert = device.send(&Apdu::new(0xe0, 0x52, 0x00, 0x00)).await?;
    let mut rd = Reader::new(&cert);
    let header = rd.lv()?.to_vec();
    let device_pub = rd.lv()?.to_vec();
    let cert_sig = rd.lv()?.to_vec();
    let mut signed = vec![0x02];
    signed.extend_from_slice(&header);
    signed.extend_from_slice(&device_pub);

    let mut issuer = None;
    for (name, key) in KNOWN_ISSUER_KEYS {
        let key = hex::decode(key).expect("valid pinned key");
        if verify(&key, &signed, &cert_sig) {
            issuer = Some(name.to_string());
            break;
        }
    }
    if issuer.is_none() {
        issuer = extra_issuers
            .iter()
            .find(|(_, k)| verify(k, &signed, &cert_sig))
            .map(|(n, _)| n.clone());
    }

    // Device ephemeral key signed by the device key (live proof).
    on_event(AttestationEvent::Attesting);
    let eph_cert = device.send(&Apdu::new(0xe0, 0x52, 0x80, 0x00)).await?;
    let mut rd = Reader::new(&eph_cert);
    let _eph_header = rd.lv()?;
    let dev_eph_pub = rd.lv()?.to_vec();
    let dev_eph_sig = rd.lv()?.to_vec();
    let mut signed_eph = vec![0x12];
    signed_eph.extend_from_slice(&device_nonce);
    signed_eph.extend_from_slice(&host_nonce);
    signed_eph.extend_from_slice(&dev_eph_pub);
    let proof_of_possession = verify(&device_pub, &signed_eph, &dev_eph_sig);

    Ok(Attestation {
        genuine: issuer.is_some() && proof_of_possession,
        issuer,
        proof_of_possession,
        target_id,
        signer_serial,
        device_public_key: hex::encode(&device_pub),
        certificate_header: hex::encode(&header),
        certificate_signature: hex::encode(&cert_sig),
        issuer_candidates: recover_candidates(&signed, &cert_sig),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_roundtrip_and_recovery() {
        let key = Secp256k1EcdsaPrivateKey::from_bytes(&[7u8; 32]).unwrap();
        let msg = b"\x02header-and-key";
        let sig = key.sign::<Sha256>(msg).unwrap();
        let der = der_encode(&sig);
        let pubkey = key.public_key().to_sec1();
        assert!(verify(&pubkey, msg, &der));
        assert!(!verify(&pubkey, b"other", &der));
        let candidates = recover_candidates(msg, &der);
        assert!(candidates.contains(&hex::encode(pubkey)));
    }

    #[test]
    fn pinned_keys_parse() {
        for (_, k) in KNOWN_ISSUER_KEYS {
            let k = hex::decode(k).unwrap();
            assert!(Secp256k1EcdsaPublicKey::from_sec1(&k).is_ok());
        }
    }
}
