//! A virtual device backed by a dumped secure-element attestation key.
//!
//! [`KeyFileTransport`] answers the handful of APDUs the offline genuine
//! check sends ([`crate::attestation::offline_genuine_check`]) from a local
//! key file, so the check can run with no hardware plugged in. It is only as
//! trustworthy as the file: anyone holding the device attestation private key
//! can make this "device" pass, so a pass here proves the *file* is a genuine
//! dump, not that any particular hardware is genuine.
//!
//! The file is an INI describing a dump of the SE `os_perso` region:
//!
//! ```ini
//! [device_key]                 ; the per-device attestation key
//! d = <32-byte hex secret>     ; PRIVATE — the file must be kept safe
//!
//! [certificate]                ; the factory device certificate
//! header = <hex>               ; the certificate header the device returns
//!
//! [signature]
//! der = <hex DER>              ; issuer signature over 0x02 || header || pub
//!
//! [device]                     ; optional
//! target_id  = 0x31100004      ; defaults to a Nano S target id
//! se_version = 1.6.0           ; reported by GET_VERSION
//! ```
//!
//! The device public key is derived from `device_key.d`; the signed
//! certificate is `len(header) header len(pubkey) pubkey len(sig) sig`, and
//! the genuine check verifies `der` against the pinned issuer keys over
//! `0x02 || header || pubkey`, exactly as against real hardware.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

use crate::apdu::StatusWord;
use crate::attestation::{RootKey, rand_bytes, random_key};
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Default target id reported when the file does not specify one (Nano S).
const DEFAULT_TARGET_ID: u32 = 0x3110_0004;
const DEFAULT_SE_VERSION: &str = "1.6.0";

/// A virtual device reconstructed from a dumped SE attestation key.
pub struct KeyFileTransport {
    /// Device attestation key (its public key is what the certificate certifies).
    device: RootKey,
    /// Device public key (uncompressed SEC1), cached.
    device_pub: [u8; 65],
    /// Certificate header, as the real device returns it.
    cert_header: Vec<u8>,
    /// Issuer signature over the device certificate (DER).
    cert_sig: Vec<u8>,
    /// Batch signer serial reported by `INITIALIZE_AUTHENTICATION` (4 bytes).
    signer_serial: [u8; 4],
    target_id: u32,
    se_version: String,
    /// Per-session nonces, set during the handshake.
    state: RefCell<State>,
}

#[derive(Default)]
struct State {
    host_nonce: [u8; 8],
    device_nonce: [u8; 8],
}

impl KeyFileTransport {
    /// Load a key file from disk.
    pub fn open(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::InvalidInput(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }

    /// Parse a key file from its INI text.
    pub fn parse(text: &str) -> Result<Self> {
        let ini = parse_ini(text);
        let get = |sec: &str, key: &str| ini.get(&(sec.to_string(), key.to_string()));
        let hex_of = |sec: &str, key: &str| -> Result<Vec<u8>> {
            let v = get(sec, key).ok_or_else(|| {
                Error::InvalidInput(format!("key file: missing [{sec}] {key}"))
            })?;
            hex::decode(v.trim_start_matches("0x"))
                .map_err(|e| Error::InvalidInput(format!("key file [{sec}] {key}: {e}")))
        };

        let d = hex_of("device_key", "d")?;
        let device = RootKey::from_bytes(&d)
            .map_err(|_| Error::InvalidInput("key file: device_key.d is not a valid key".into()))?;
        let device_pub = device.public_key();

        // The certificate header: the bytes the device returns and the issuer
        // signed over. Accept it under [certificate] header (preferred) or the
        // older [header] cert spelling.
        let cert_header = match get("certificate", "header").or_else(|| get("header", "cert")) {
            Some(v) => hex::decode(v.trim_start_matches("0x")).map_err(|e| {
                Error::InvalidInput(format!("key file: certificate.header: {e}"))
            })?,
            None => {
                return Err(Error::InvalidInput(
                    "key file: missing [certificate] header (the device certificate header; \
                     the SE dump stores it just before the signature)"
                        .into(),
                ));
            }
        };

        let cert_sig = hex_of("signature", "der")?;

        let target_id = match get("device", "target_id") {
            Some(v) => u32::from_str_radix(v.trim_start_matches("0x"), 16)
                .map_err(|e| Error::InvalidInput(format!("key file: device.target_id: {e}")))?,
            None => DEFAULT_TARGET_ID,
        };
        let se_version = get("device", "se_version")
            .cloned()
            .unwrap_or_else(|| DEFAULT_SE_VERSION.to_string());

        // The real signer serial is not in the dump; derive a stable value so
        // the reported attestation is reproducible.
        let mut signer_serial = [0u8; 4];
        signer_serial.copy_from_slice(&device_pub[1..5]);

        Ok(Self {
            device,
            device_pub,
            cert_header,
            cert_sig,
            signer_serial,
            target_id,
            se_version,
            state: RefCell::new(State::default()),
        })
    }

    /// The device attestation public key (uncompressed SEC1).
    pub fn device_public_key(&self) -> [u8; 65] {
        self.device_pub
    }

    fn reply(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        if apdu.len() < 4 {
            return Err(Error::Transport("short APDU".into()));
        }
        let (cla, ins, p1) = (apdu[0], apdu[1], apdu[2]);
        let data = apdu.get(5..).unwrap_or(&[]);
        match (cla, ins, p1) {
            // GET_APP_AND_VERSION: report the dashboard so is_on_dashboard() is true.
            (0xb0, 0x01, _) => Ok(tlv_app_version("BOLOS", &self.se_version)),
            // GET_VERSION.
            (0xe0, 0x01, _) => Ok(self.get_version()),
            // VALIDATE_TARGET_ID.
            (0xe0, 0x04, _) => Ok(ok(vec![])),
            // INITIALIZE_AUTHENTICATION: take the host nonce, pick a device nonce.
            (0xe0, 0x50, _) => {
                let mut st = self.state.borrow_mut();
                st.host_nonce = data.get(..8).unwrap_or(&[0u8; 8]).try_into().unwrap_or([0; 8]);
                rand_bytes(&mut st.device_nonce)?;
                let mut out = self.signer_serial.to_vec();
                out.extend_from_slice(&st.device_nonce);
                Ok(ok(out))
            }
            // MUTUAL_AUTHENTICATE host certificates: accepted (no channel is opened).
            (0xe0, 0x51, _) => Ok(ok(vec![])),
            // GET_CERTIFICATE.
            (0xe0, 0x52, 0x00) => {
                // Device factory certificate: header || device pubkey || issuer signature.
                let mut cert = lv(&self.cert_header);
                cert.extend(lv(&self.device_pub));
                cert.extend(lv(&self.cert_sig));
                Ok(ok(cert))
            }
            (0xe0, 0x52, 0x80) => {
                // Ephemeral key certified by the device key (live proof of possession).
                let st = self.state.borrow();
                let eph = random_key()?;
                let eph_pub = eph.public_key().to_sec1();
                let mut signed = vec![0x12u8];
                signed.extend_from_slice(&st.device_nonce);
                signed.extend_from_slice(&st.host_nonce);
                signed.extend_from_slice(&eph_pub);
                let sig = self.device.sign(&signed)?;
                let mut cert = lv(&[]); // empty header
                cert.extend(lv(&eph_pub));
                cert.extend(lv(&sig));
                Ok(ok(cert))
            }
            _ => Ok(sw(StatusWord::INS_NOT_SUPPORTED)),
        }
    }

    fn get_version(&self) -> Vec<u8> {
        let mut out = self.target_id.to_be_bytes().to_vec();
        out.extend(lv(self.se_version.as_bytes()));
        out.extend(lv(&[0u8; 4])); // seFlags
        ok(out)
    }
}

impl Transport for KeyFileTransport {
    async fn exchange(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        self.reply(apdu)
    }
}

/// A length-prefixed (1 byte) value.
fn lv(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() + 1);
    out.push(v.len() as u8);
    out.extend_from_slice(v);
    out
}

/// Append a `0x9000` status word to a response payload.
fn ok(mut data: Vec<u8>) -> Vec<u8> {
    data.extend_from_slice(&[0x90, 0x00]);
    data
}

/// A response that is just a status word.
fn sw(s: StatusWord) -> Vec<u8> {
    s.0.to_be_bytes().to_vec()
}

/// `GET_APP_AND_VERSION` payload: format 1, name, version.
fn tlv_app_version(name: &str, version: &str) -> Vec<u8> {
    let mut out = vec![0x01];
    out.extend(lv(name.as_bytes()));
    out.extend(lv(version.as_bytes()));
    ok(out)
}

/// Parse a minimal INI into a `(section, key) -> value` map. Values have
/// trailing `; ...` comments and inline annotations like `(secp256k1)`
/// stripped (only the first whitespace-separated token is kept).
fn parse_ini(text: &str) -> BTreeMap<(String, String), String> {
    let mut map = BTreeMap::new();
    let mut section = String::new();
    for line in text.lines() {
        let line = line.split(';').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_string();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.split_whitespace().next().unwrap_or("").to_string();
            map.insert((section.clone(), k.trim().to_string()), v);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::offline_genuine_check;
    use crate::device::Device;

    fn block_on<F: core::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// Build a self-consistent key file (synthetic issuer + device key) and
    /// check it passes the full offline genuine check through the transport.
    #[test]
    fn emulated_device_is_genuine() {
        let device = RootKey::from_bytes(&[7u8; 32]).unwrap();
        let issuer = RootKey::from_bytes(&[9u8; 32]).unwrap();
        let header = [0xe0u8, 0xb0, 0x20, 0x80];
        // issuer certifies the device: sign 0x02 || header || device_pubkey.
        let mut signed = vec![0x02u8];
        signed.extend_from_slice(&header);
        signed.extend_from_slice(&device.public_key());
        let cert_sig = issuer.sign(&signed).unwrap();

        let ini = format!(
            "[device_key]\nd = {}\n[certificate]\nheader = {}\n[signature]\nder = {}\n[device]\ntarget_id = 0x31100004\n",
            hex::encode(device.to_bytes()),
            hex::encode(header),
            hex::encode(&cert_sig),
        );
        let kf = KeyFileTransport::parse(&ini).unwrap();
        assert_eq!(kf.device_public_key(), device.public_key());

        let issuers = vec![("test issuer".to_string(), issuer.public_key().to_vec())];
        let host = RootKey::from_bytes(&[3u8; 32]).unwrap();
        let att = block_on(offline_genuine_check(
            &Device::new(kf),
            &host,
            &issuers,
            &mut |_| {},
        ))
        .unwrap();

        assert!(att.genuine);
        assert!(att.proof_of_possession);
        assert_eq!(att.issuer.as_deref(), Some("test issuer"));
        assert_eq!(att.target_id, 0x3110_0004);
        assert_eq!(att.device_public_key, hex::encode(device.public_key()));
        assert_eq!(att.certificate_header, hex::encode(header));
    }

    /// A wrong issuer (not in the trust list) is reported as not genuine, but
    /// proof of possession still holds.
    #[test]
    fn unknown_issuer_is_not_genuine() {
        let device = RootKey::from_bytes(&[7u8; 32]).unwrap();
        let issuer = RootKey::from_bytes(&[9u8; 32]).unwrap();
        let header = [0x01u8];
        let mut signed = vec![0x02u8];
        signed.extend_from_slice(&header);
        signed.extend_from_slice(&device.public_key());
        let cert_sig = issuer.sign(&signed).unwrap();
        let ini = format!(
            "[device_key]\nd = {}\n[certificate]\nheader = {}\n[signature]\nder = {}\n",
            hex::encode(device.to_bytes()),
            hex::encode(header),
            hex::encode(&cert_sig),
        );
        let kf = KeyFileTransport::parse(&ini).unwrap();
        // Trust a different, unrelated issuer.
        let other = RootKey::from_bytes(&[11u8; 32]).unwrap();
        let issuers = vec![("other".to_string(), other.public_key().to_vec())];
        let host = RootKey::from_bytes(&[3u8; 32]).unwrap();
        let att = block_on(offline_genuine_check(
            &Device::new(kf),
            &host,
            &issuers,
            &mut |_| {},
        ))
        .unwrap();
        assert!(!att.genuine);
        assert!(att.issuer.is_none());
        assert!(att.proof_of_possession);
    }

    #[test]
    fn missing_header_is_rejected() {
        let device = RootKey::from_bytes(&[7u8; 32]).unwrap();
        let ini = format!(
            "[device_key]\nd = {}\n[signature]\nder = 3045\n",
            hex::encode(device.to_bytes()),
        );
        assert!(KeyFileTransport::parse(&ini).is_err());
    }
}
