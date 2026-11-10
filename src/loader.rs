//! App images and sideloading over the secure channel.
//!
//! An [`AppImage`] is built from the app ELF produced by the C or Rust SDK:
//! the loadable segments give the memory image, the `ledger.*` sections the
//! metadata (name, version, flags, API level, target id) and the linker
//! symbols the NVRAM data and install parameters sizes. Intel HEX files are
//! supported too, with the metadata given explicitly.
//!
//! [`install_app`] then streams it over a [`SecureChannel`] opened with the
//! custom CA key: `CREATE_APP`, then per segment `SET_LOAD_OFFSET`, `LOAD`
//! chunks, `FLUSH`, `CRC`, and finally `COMMIT`.

use crate::error::{Error, Result};
use crate::scp::{SecureChannel, ins};
use crate::transport::Transport;

/// A contiguous memory area of the image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Area {
    pub address: u32,
    pub data: Vec<u8>,
}

/// An app ready to be installed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AppImage {
    pub name: String,
    pub version: Option<String>,
    /// API level (sent with `CREATE_APP` when known).
    pub api_level: Option<u8>,
    pub flags: u32,
    /// Target id the app was built for.
    pub target_id: Option<u32>,
    /// NVRAM data size, at the end of the image.
    pub data_size: u32,
    /// Install parameters size (embedded TLVs), after the code.
    pub install_params_size: u32,
    /// Entry point (absolute address).
    pub entry: u32,
    #[cfg_attr(feature = "serde", serde(skip))]
    pub areas: Vec<Area>,
}

fn rd16(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2)
        .map(|x| u16::from_le_bytes([x[0], x[1]]))
        .ok_or_else(|| Error::InvalidInput("truncated ELF".into()))
}
fn rd32(b: &[u8], o: usize) -> Result<u32> {
    b.get(o..o + 4)
        .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
        .ok_or_else(|| Error::InvalidInput("truncated ELF".into()))
}
fn cstr(b: &[u8], o: usize) -> String {
    let s = b.get(o..).unwrap_or_default();
    let end = s.iter().position(|c| *c == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).into_owned()
}

fn parse_num(s: &str) -> Option<u32> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Merge segments into contiguous areas, sorted by address.
fn merge(mut segs: Vec<Area>) -> Vec<Area> {
    segs.sort_by_key(|a| a.address);
    let mut out: Vec<Area> = Vec::new();
    for s in segs.into_iter().filter(|s| !s.data.is_empty()) {
        if let Some(last) = out.last_mut()
            && last.address as u64 + last.data.len() as u64 == s.address as u64
        {
            last.data.extend(s.data);
            continue;
        }
        out.push(s);
    }
    out
}

impl AppImage {
    /// Parse an app ELF (32-bit little endian, as built by the SDKs).
    pub fn from_elf(elf: &[u8]) -> Result<Self> {
        if elf.len() < 52 || &elf[..4] != b"\x7fELF" {
            return Err(Error::InvalidInput("not an ELF file".into()));
        }
        if elf[4] != 1 || elf[5] != 1 {
            return Err(Error::InvalidInput(
                "only 32-bit little-endian ELF is supported".into(),
            ));
        }
        let entry = rd32(elf, 0x18)?;
        let phoff = rd32(elf, 0x1c)? as usize;
        let shoff = rd32(elf, 0x20)? as usize;
        let phentsize = rd16(elf, 0x2a)? as usize;
        let phnum = rd16(elf, 0x2c)? as usize;
        let shentsize = rd16(elf, 0x2e)? as usize;
        let shnum = rd16(elf, 0x30)? as usize;
        let shstrndx = rd16(elf, 0x32)? as usize;

        // Loadable segments, at their physical (load) address, as objcopy does.
        let mut segs = Vec::new();
        for i in 0..phnum {
            let o = phoff + i * phentsize;
            if rd32(elf, o)? != 1 {
                continue; // PT_LOAD
            }
            let offset = rd32(elf, o + 4)? as usize;
            let paddr = rd32(elf, o + 12)?;
            let filesz = rd32(elf, o + 16)? as usize;
            if filesz == 0 {
                continue;
            }
            let data = elf
                .get(offset..offset + filesz)
                .ok_or_else(|| Error::InvalidInput("ELF segment out of bounds".into()))?;
            segs.push(Area {
                address: paddr,
                data: data.to_vec(),
            });
        }

        // Sections: metadata and symbols.
        let sh = |i: usize| -> Result<(u32, u32, u32, u32, u32)> {
            let o = shoff + i * shentsize;
            Ok((
                rd32(elf, o)?,
                rd32(elf, o + 4)?,
                rd32(elf, o + 16)?,
                rd32(elf, o + 20)?,
                rd32(elf, o + 24)?,
            ))
        };
        let shstr_off = if shnum > shstrndx {
            sh(shstrndx)?.2 as usize
        } else {
            0
        };
        let mut meta = std::collections::HashMap::new();
        let mut symbols = std::collections::HashMap::new();
        for i in 0..shnum {
            let (name_off, kind, offset, size, link) = sh(i)?;
            let name = cstr(elf, shstr_off + name_off as usize);
            let content = elf
                .get(offset as usize..(offset + size) as usize)
                .unwrap_or_default();
            if let Some(field) = name
                .strip_prefix("ledger.")
                .or_else(|| name.strip_prefix(".ledger."))
            {
                let v = String::from_utf8_lossy(content);
                let v = v
                    .split(['\n', '\0'])
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                meta.insert(field.to_string(), v);
            }
            if kind == 2 {
                // SHT_SYMTAB
                let (_, _, str_off, _, _) = sh(link as usize)?;
                for k in 0..(size as usize / 16) {
                    let so = offset as usize + k * 16;
                    let sname = cstr(elf, str_off as usize + rd32(elf, so)? as usize);
                    symbols.insert(sname, rd32(elf, so + 4)?);
                }
            }
        }
        let sym_diff = |a: &str, b: &str| match (symbols.get(a), symbols.get(b)) {
            (Some(s), Some(e)) => e.saturating_sub(*s),
            _ => 0,
        };
        let name = meta
            .get("app_name")
            .cloned()
            .filter(|n| !n.is_empty())
            .ok_or_else(|| {
                Error::InvalidInput(
                    "ELF has no ledger.app_name section (build it with a recent SDK)".into(),
                )
            })?;
        Ok(Self {
            name,
            version: meta.get("app_version").cloned().filter(|v| !v.is_empty()),
            api_level: meta.get("api_level").and_then(|v| v.parse().ok()),
            flags: meta
                .get("app_flags")
                .and_then(|v| parse_num(v))
                .unwrap_or(0),
            target_id: meta.get("target_id").and_then(|v| parse_num(v)),
            data_size: sym_diff("_nvram_data", "_envram_data"),
            install_params_size: sym_diff("_install_parameters", "_einstall_parameters"),
            entry,
            areas: merge(segs),
        })
    }

    /// Parse an Intel HEX file; metadata must then be set by the caller
    /// (`name`, `flags`, `api_level`, `data_size`, `install_params_size`).
    pub fn from_ihex(text: &str, name: &str) -> Result<Self> {
        let mut segs = Vec::new();
        let mut base: u32 = 0;
        let mut entry = None;
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let raw = hex::decode(
                line.strip_prefix(':')
                    .ok_or_else(|| Error::InvalidInput(format!("hex line {}", n + 1)))?,
            )
            .map_err(|e| Error::InvalidInput(format!("hex line {}: {e}", n + 1)))?;
            if raw.len() < 5 || raw.len() != 5 + raw[0] as usize {
                return Err(Error::InvalidInput(format!(
                    "hex line {}: bad length",
                    n + 1
                )));
            }
            if raw.iter().fold(0u8, |a, b| a.wrapping_add(*b)) != 0 {
                return Err(Error::InvalidInput(format!(
                    "hex line {}: bad checksum",
                    n + 1
                )));
            }
            let len = raw[0] as usize;
            let addr = u16::from_be_bytes([raw[1], raw[2]]) as u32;
            let data = &raw[4..4 + len];
            match raw[3] {
                0x00 => segs.push(Area {
                    address: base + addr,
                    data: data.to_vec(),
                }),
                0x01 => break,
                0x02 => base = (u16::from_be_bytes([data[0], data[1]]) as u32) << 4,
                0x04 => base = (u16::from_be_bytes([data[0], data[1]]) as u32) << 16,
                0x05 => entry = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]])),
                _ => {}
            }
        }
        let areas = merge(segs);
        let min = areas.first().map(|a| a.address).unwrap_or(0);
        Ok(Self {
            name: name.to_string(),
            version: None,
            api_level: None,
            flags: 0,
            target_id: None,
            data_size: 0,
            install_params_size: 0,
            entry: entry.unwrap_or(min),
            areas,
        })
    }

    /// Lowest address of the image.
    pub fn min_address(&self) -> u32 {
        self.areas.first().map(|a| a.address).unwrap_or(0)
    }

    /// Size of the whole image (code + install params + data).
    pub fn image_size(&self) -> u32 {
        self.areas
            .last()
            .map(|a| a.address + a.data.len() as u32)
            .unwrap_or(0)
            - self.min_address()
    }

    /// Code length declared to the device.
    pub fn code_length(&self) -> Result<u32> {
        self.image_size()
            .checked_sub(self.data_size + self.install_params_size)
            .ok_or_else(|| {
                Error::InvalidInput("image smaller than its data + install params".into())
            })
    }

    /// `CREATE_APP` payload.
    pub fn create_app_params(&self) -> Result<Vec<u8>> {
        let mut d = Vec::new();
        if let Some(l) = self.api_level {
            d.push(l);
        }
        d.extend_from_slice(&self.code_length()?.to_be_bytes());
        d.extend_from_slice(&self.data_size.to_be_bytes());
        d.extend_from_slice(&self.install_params_size.to_be_bytes());
        d.extend_from_slice(&self.flags.to_be_bytes());
        d.extend_from_slice(&((self.entry.wrapping_sub(self.min_address())) | 1).to_be_bytes());
        Ok(d)
    }
}

impl AppImage {
    /// The image as loaded: `min_address..end`, gaps zero-filled.
    pub fn flat_image(&self) -> Vec<u8> {
        let min = self.min_address();
        let mut out = vec![0u8; self.image_size() as usize];
        for a in &self.areas {
            let o = (a.address - min) as usize;
            out[o..o + a.data.len()].copy_from_slice(&a.data);
        }
        out
    }

    /// Application hash, as computed by the device and reported by app
    /// listings: `sha256(target_id || CREATE_APP params || image)`.
    pub fn app_hash(&self, target_id: u32) -> Result<[u8; 32]> {
        let mut d = target_id.to_be_bytes().to_vec();
        d.extend(self.create_app_params()?);
        d.extend(self.flat_image());
        Ok(purecrypto::hash::sha256(&d))
    }
}

/// CRC-16/CCITT-FALSE, as checked by `SECUREINS_CRC`.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    for b in data {
        crc ^= (*b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Bytes per `LOAD` command (keeps the wrapped APDU within 255 bytes).
const LOAD_CHUNK: usize = 208;
/// The `LOAD` offset is 16 bits: segments are sent in 64 KiB windows.
const WINDOW: usize = 0x10000;

/// Install options.
#[derive(Default)]
pub struct InstallOptions<'a> {
    /// Delete an app with the same name first.
    pub replace: bool,
    /// Sign the app hash with this key (sent with `COMMIT`).
    pub signer: Option<&'a crate::scp::RootKey>,
}

/// Install an app. See [`install_app_with`] for signing.
/// `on_progress(sent, total)` reports loaded bytes.
pub async fn install_app<T: Transport>(
    chan: &mut SecureChannel<'_, T>,
    image: &AppImage,
    replace: bool,
    on_progress: &mut dyn FnMut(usize, usize),
) -> Result<()> {
    install_app_with(
        chan,
        image,
        &InstallOptions {
            replace,
            signer: None,
        },
        on_progress,
    )
    .await
}

/// Install an app with options (replace, signature).
pub async fn install_app_with<T: Transport>(
    chan: &mut SecureChannel<'_, T>,
    image: &AppImage,
    opts: &InstallOptions<'_>,
    on_progress: &mut dyn FnMut(usize, usize),
) -> Result<()> {
    let replace = opts.replace;
    if let Some(t) = image.target_id
        && t != chan.version.target_id
    {
        return Err(Error::InvalidInput(format!(
            "app built for target 0x{t:08x}, device is 0x{:08x}",
            chan.version.target_id
        )));
    }
    if replace {
        match chan.delete_app(&image.name).await {
            Ok(()) | Err(Error::Status(_)) => {} // not installed
            Err(e) => return Err(e),
        }
    }
    chan.exchange(ins::CREATE_APP, &image.create_app_params()?)
        .await?;
    let total: usize = image.areas.iter().map(|a| a.data.len()).sum();
    let mut sent = 0;
    let min = image.min_address();
    for area in &image.areas {
        for (w, window) in area.data.chunks(WINDOW).enumerate() {
            let base = area.address - min + (w * WINDOW) as u32;
            chan.exchange(ins::SET_LOAD_OFFSET, &base.to_be_bytes())
                .await?;
            for (c, chunk) in window.chunks(LOAD_CHUNK).enumerate() {
                let mut d = ((c * LOAD_CHUNK) as u16).to_be_bytes().to_vec();
                d.extend_from_slice(chunk);
                chan.exchange(ins::LOAD, &d).await?;
                sent += chunk.len();
                on_progress(sent, total);
            }
            chan.exchange(ins::FLUSH, &[]).await?;
            let mut crc = vec![0, 0];
            crc.extend_from_slice(&(window.len() as u32).to_be_bytes());
            crc.extend_from_slice(&crc16(window).to_be_bytes());
            chan.exchange(ins::CRC, &crc).await?;
        }
    }
    let commit = match opts.signer {
        Some(key) => {
            let sig = key.sign_digest(&image.app_hash(chan.version.target_id)?)?;
            let mut d = vec![sig.len() as u8];
            d.extend(sig);
            d
        }
        None => Vec::new(),
    };
    chan.exchange(ins::COMMIT, &commit).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc() {
        assert_eq!(crc16(b"123456789"), 0x29b1); // CRC-16/CCITT-FALSE check value
    }

    #[test]
    fn ihex() {
        let h = ":020000040004F6\n:10000000000102030405060708090A0B0C0D0E0F78\n:0400000500041235AC\n:00000001FF\n";
        let img = AppImage::from_ihex(h, "x").unwrap();
        assert_eq!(img.min_address(), 0x40000);
        assert_eq!(img.areas[0].data.len(), 16);
        assert_eq!(img.entry, 0x41235);
    }

    #[test]
    fn create_params() {
        let img = AppImage {
            name: "x".into(),
            version: None,
            api_level: Some(22),
            flags: 0x200,
            target_id: None,
            data_size: 64,
            install_params_size: 64,
            entry: 0xc0de0101,
            areas: vec![Area {
                address: 0xc0de0000,
                data: vec![0; 1024],
            }],
        };
        let p = img.create_app_params().unwrap();
        assert_eq!(p[0], 22);
        assert_eq!(&p[1..5], &(1024u32 - 128).to_be_bytes());
        assert_eq!(&p[17..21], &0x101u32.to_be_bytes());
    }
}
