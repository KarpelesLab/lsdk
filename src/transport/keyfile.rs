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
    /// Verbatim `GET_VERSION` response payload (without status word), when the
    /// file carries one. The HSM parses this, so for the online check it must
    /// match what the real device returns; capture it with `lsdk info` /
    /// `GET_VERSION` and store it as `[device] get_version = <hex>`.
    get_version: Option<Vec<u8>>,
    /// Per-session nonces, set during the handshake.
    state: RefCell<State>,
    /// Session trace: every wire APDU (`>`/`<`, encrypted), the decrypted
    /// secure commands (`cmd`/`rsp`), and the session's ephemeral key and
    /// nonces (`#`), so the encrypted wire can be re-derived/verified offline.
    trace: RefCell<Vec<String>>,
}

#[derive(Default)]
struct State {
    host_nonce: [u8; 8],
    device_nonce: [u8; 8],
    /// Host ephemeral public key, from the host's `E051 80` certificate.
    host_eph_pub: Vec<u8>,
    /// This session's device ephemeral private scalar, kept so the secure
    /// channel's ECDH can be completed at `E053` (online / HSM path).
    device_eph_secret: [u8; 32],
    /// The opened secure channel, after `E053` (scp feature only).
    #[cfg(feature = "scp")]
    session: Option<crate::scp::Session>,
    /// Every decrypted secure command of the session (online
    /// install/download), in stream order, as (instruction, arguments).
    /// Kept verbatim so the load stream (SET_LOAD_OFFSET switches, LOAD
    /// chunks, CRCs, ...) can be written out exactly.
    fw_cmds: Vec<(u8, Vec<u8>)>,
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
            let v = get(sec, key)
                .ok_or_else(|| Error::InvalidInput(format!("key file: missing [{sec}] {key}")))?;
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
            Some(v) => hex::decode(v.trim_start_matches("0x"))
                .map_err(|e| Error::InvalidInput(format!("key file: certificate.header: {e}")))?,
            None => {
                return Err(Error::InvalidInput(
                    "key file: missing [certificate] header (the device certificate header; \
                     the SE dump stores it just before the signature)"
                        .into(),
                ));
            }
        };

        let cert_sig = hex_of("signature", "der")?;

        let get_version =
            match get("device", "get_version") {
                Some(v) => Some(hex::decode(v.trim_start_matches("0x")).map_err(|e| {
                    Error::InvalidInput(format!("key file: device.get_version: {e}"))
                })?),
                None => None,
            };

        let target_id = match get("device", "target_id") {
            Some(v) => u32::from_str_radix(v.trim_start_matches("0x"), 16)
                .map_err(|e| Error::InvalidInput(format!("key file: device.target_id: {e}")))?,
            // Fall back to the target id embedded in the captured GET_VERSION.
            None => match get_version.as_deref() {
                Some([a, b, c, d, ..]) => u32::from_be_bytes([*a, *b, *c, *d]),
                _ => DEFAULT_TARGET_ID,
            },
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
            get_version,
            state: RefCell::new(State::default()),
            trace: RefCell::new(Vec::new()),
        })
    }

    /// The device attestation public key (uncompressed SEC1).
    pub fn device_public_key(&self) -> [u8; 65] {
        self.device_pub
    }

    /// Override the reported `GET_VERSION` payload (without status word), and
    /// take the target id from its first 4 bytes. Used to present a different
    /// device state (e.g. the post-OSU "1.4.2-osu" updater) for a later step.
    pub fn set_get_version(&mut self, raw: Vec<u8>) {
        if let Some(b) = raw.get(..4) {
            self.target_id = u32::from_be_bytes(b.try_into().unwrap());
        }
        self.get_version = Some(raw);
    }

    fn log(&self, line: String) {
        self.trace.borrow_mut().push(line);
    }

    /// Process one APDU, logging the wire request and response (both
    /// directions, encrypted as sent); secure commands log their decrypted
    /// form, and the handshake logs the ephemeral key, in between.
    fn reply(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        self.log(format!("> {}", hex::encode(apdu)));
        let r = self.reply_inner(apdu);
        match &r {
            Ok(resp) => self.log(format!("< {}", hex::encode(resp))),
            Err(e) => self.log(format!("! {e}")),
        }
        r
    }

    fn reply_inner(&self, apdu: &[u8]) -> Result<Vec<u8>> {
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
                st.host_nonce = data
                    .get(..8)
                    .unwrap_or(&[0u8; 8])
                    .try_into()
                    .unwrap_or([0; 8]);
                rand_bytes(&mut st.device_nonce)?;
                let mut out = self.signer_serial.to_vec();
                out.extend_from_slice(&st.device_nonce);
                Ok(ok(out))
            }
            // Host root certificate: accepted (we do not verify the manager).
            (0xe0, 0x51, 0x00) => Ok(ok(vec![])),
            // Host ephemeral certificate: capture the host ephemeral public key
            // (needed to complete the secure channel's ECDH).
            (0xe0, 0x51, 0x80) => {
                // host_certificate = len(pub) || pub || len(sig) || sig.
                if let Some(pk) = data.first().and_then(|&len| data.get(1..1 + len as usize)) {
                    self.log(format!("# host_ephemeral_pub {}", hex::encode(pk)));
                    self.state.borrow_mut().host_eph_pub = pk.to_vec();
                }
                Ok(ok(vec![]))
            }
            // GET_CERTIFICATE.
            (0xe0, 0x52, 0x00) => {
                // Device factory certificate: header || device pubkey || issuer signature.
                let mut cert = lv(&self.cert_header);
                cert.extend(lv(&self.device_pub));
                cert.extend(lv(&self.cert_sig));
                Ok(ok(cert))
            }
            (0xe0, 0x52, 0x80) => {
                // Ephemeral key certified by the device key (live proof of
                // possession). Keep its private scalar for the channel ECDH.
                let eph = random_key()?;
                let eph_pub = eph.public_key().to_sec1();
                let (device_nonce, host_nonce) = {
                    let mut st = self.state.borrow_mut();
                    st.device_eph_secret = eph.to_bytes();
                    (st.device_nonce, st.host_nonce)
                };
                // Log the session's ephemeral key + nonces so the encrypted
                // wire trace can be re-derived / decrypted offline.
                self.log(format!(
                    "# device_ephemeral_priv {} device_ephemeral_pub {}",
                    hex::encode(eph.to_bytes()),
                    hex::encode(eph_pub)
                ));
                self.log(format!(
                    "# device_nonce {} host_nonce {}",
                    hex::encode(device_nonce),
                    hex::encode(host_nonce)
                ));
                let mut signed = vec![0x12u8];
                signed.extend_from_slice(&device_nonce);
                signed.extend_from_slice(&host_nonce);
                signed.extend_from_slice(&eph_pub);
                let sig = self.device.sign(&signed)?;
                let mut cert = lv(&[]); // empty header
                cert.extend(lv(&eph_pub));
                cert.extend(lv(&sig));
                Ok(ok(cert))
            }
            // OPEN_SECURE_CHANNEL: commit the ECDH channel (online / HSM path).
            #[cfg(feature = "scp")]
            (0xe0, 0x53, _) => {
                let mut st = self.state.borrow_mut();
                let secret = st.device_eph_secret;
                let host_eph = st.host_eph_pub.clone();
                st.session = Some(crate::scp::device_session(
                    &secret,
                    &host_eph,
                    self.target_id,
                )?);
                Ok(ok(vec![]))
            }
            // Secure command: decrypt, run, re-encrypt (online / HSM path).
            #[cfg(feature = "scp")]
            (0xe0, 0x00, _) => self.secure_command(data),
            _ => Ok(sw(StatusWord::INS_NOT_SUPPORTED)),
        }
    }

    fn get_version(&self) -> Vec<u8> {
        ok(self.version_payload())
    }

    /// `GET_VERSION` payload (without the status word). Prefers a verbatim
    /// response captured from the real device; otherwise synthesizes a minimal
    /// one (enough for the offline check, but not necessarily for the HSM).
    fn version_payload(&self) -> Vec<u8> {
        if let Some(raw) = &self.get_version {
            return raw.clone();
        }
        let mut out = self.target_id.to_be_bytes().to_vec();
        out.extend(lv(self.se_version.as_bytes()));
        out.extend(lv(&[0u8; 4])); // seFlags
        out
    }

    /// Handle a secure-channel command (`E000`): decrypt it, run it, and
    /// return the encrypted response. Only the commands the HSM genuine check
    /// needs are implemented; anything else returns an empty response so the
    /// unexpected instruction is visible in the logs rather than silently
    /// faked.
    #[cfg(feature = "scp")]
    fn secure_command(&self, data: &[u8]) -> Result<Vec<u8>> {
        use crate::scp::ins;
        let mut st = self.state.borrow_mut();
        // Decrypt the command (borrows the session only for this call).
        let plain = st
            .session
            .as_mut()
            .ok_or_else(|| Error::Transport("secure command before the channel is open".into()))?
            .open(data)?;
        let cmd = plain.first().copied().unwrap_or(0);
        let args = &plain[1.min(plain.len())..];
        self.log(format!("  cmd {cmd:02x} {}", hex::encode(args)));
        st.fw_cmds.push((cmd, args.to_vec()));
        let reply = match cmd {
            ins::GET_VERSION => self.version_payload(),
            // No apps installed: every slot reads back erased (all 0xff). The
            // manager walks the slots via LIST_APPS / LIST_APPS_CONTINUE and
            // stops at the model's slot count, so return an erased slot each
            // time it asks.
            ins::LIST_APPS | ins::LIST_APPS_CONTINUE => vec![0xff; 64],
            _ => Vec::new(),
        };
        self.log(format!("  rsp {}", hex::encode(&reply)));
        // Commands that carry no payload (LOAD, CREATE_APP, CRC, COMMIT, ...)
        // answer with a bare 9000 and no secure body: their response must NOT
        // advance the shared CBC-IV chain, or the next command (especially in
        // the fire-and-forget bulk load phase, where the HSM never reads these
        // responses) decrypts against the wrong IV. Only data-bearing commands
        // seal a body.
        if reply.is_empty() {
            Ok(ok(vec![]))
        } else {
            let sealed = st.session.as_mut().unwrap().seal(&reply);
            Ok(ok(sealed))
        }
    }

    /// Take the secure command stream captured so far as text, clearing it
    /// for the next component: one command per line, in stream order, as
    /// `NAME <arguments as hex>` (`NAME` alone when it has no arguments;
    /// `CMD_xx` for an unknown instruction). E.g. `SET_LOAD_OFFSET 0000ec00`,
    /// `LOAD 0000<data>` (2-byte BE in-region offset, then the bytes).
    /// `None` if no secure command was sent.
    #[cfg(feature = "scp")]
    pub fn take_firmware_stream(&self) -> Option<String> {
        let cmds = std::mem::take(&mut self.state.borrow_mut().fw_cmds);
        if cmds.is_empty() {
            return None;
        }
        Some(crate::scp::format_stream(&cmds))
    }

    /// Take the session trace (wire APDUs, decrypted secure commands, and the
    /// ephemeral key / nonces), clearing it for the next component. `None` if
    /// nothing was traced.
    pub fn take_trace(&self) -> Option<String> {
        let lines = std::mem::take(&mut *self.trace.borrow_mut());
        if lines.is_empty() {
            None
        } else {
            Some(lines.join("\n") + "\n")
        }
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

    /// The emulated device completes a full SCP secure channel (the online /
    /// HSM path): a host SecureChannel opens against it and a secure command
    /// round-trips, which exercises the ECDH and the wrap/unwrap mirror.
    #[cfg(feature = "scp")]
    #[test]
    fn opens_secure_channel() {
        use crate::scp::SecureChannel;

        let device = RootKey::from_bytes(&[7u8; 32]).unwrap();
        let issuer = RootKey::from_bytes(&[9u8; 32]).unwrap();
        let header = [0x01u8, 0x02];
        let mut signed = vec![0x02u8];
        signed.extend_from_slice(&header);
        signed.extend_from_slice(&device.public_key());
        let cert_sig = issuer.sign(&signed).unwrap();
        let ini = format!(
            "[device_key]\nd = {}\n[certificate]\nheader = {}\n[signature]\nder = {}\n[device]\ntarget_id = 0x31100004\nse_version = 1.6.1\n",
            hex::encode(device.to_bytes()),
            hex::encode(header),
            hex::encode(&cert_sig),
        );
        let dev = Device::new(KeyFileTransport::parse(&ini).unwrap());
        let host = RootKey::from_bytes(&[3u8; 32]).unwrap();

        let version = block_on(async {
            let mut ch = SecureChannel::open(&dev, &host, &mut |_| {}).await?;
            ch.get_version().await
        })
        .unwrap();
        assert_eq!(version.target_id, 0x3110_0004);
        assert_eq!(version.raw_version, "1.6.1");
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
