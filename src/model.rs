//! Device models.

use core::fmt;

/// Known device models.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[non_exhaustive]
pub enum DeviceModel {
    NanoS,
    NanoSPlus,
    NanoX,
    Stax,
    Flex,
    /// "Nano Gen5" (apex)
    NanoGen5,
}

impl DeviceModel {
    pub const ALL: [DeviceModel; 6] = [
        DeviceModel::NanoS,
        DeviceModel::NanoSPlus,
        DeviceModel::NanoX,
        DeviceModel::Stax,
        DeviceModel::Flex,
        DeviceModel::NanoGen5,
    ];

    /// Product name.
    pub fn name(self) -> &'static str {
        match self {
            DeviceModel::NanoS => "Nano S",
            DeviceModel::NanoSPlus => "Nano S Plus",
            DeviceModel::NanoX => "Nano X",
            DeviceModel::Stax => "Stax",
            DeviceModel::Flex => "Flex",
            DeviceModel::NanoGen5 => "Nano Gen5",
        }
    }

    /// Short identifier, compatible with the identifiers used by the manager API.
    pub fn id(self) -> &'static str {
        match self {
            DeviceModel::NanoS => "nanoS",
            DeviceModel::NanoSPlus => "nanoSP",
            DeviceModel::NanoX => "nanoX",
            DeviceModel::Stax => "stax",
            DeviceModel::Flex => "flex",
            DeviceModel::NanoGen5 => "apexp",
        }
    }

    /// High byte of the USB product id when running the OS.
    pub fn usb_product_id(self) -> u8 {
        match self {
            DeviceModel::NanoS => 0x10,
            DeviceModel::NanoX => 0x40,
            DeviceModel::NanoSPlus => 0x50,
            DeviceModel::Stax => 0x60,
            DeviceModel::Flex => 0x70,
            DeviceModel::NanoGen5 => 0x80,
        }
    }

    /// Full USB product id when the device is in bootloader mode.
    pub fn bootloader_product_id(self) -> u16 {
        match self {
            DeviceModel::NanoS => 0x0001,
            DeviceModel::NanoX => 0x0004,
            DeviceModel::NanoSPlus => 0x0005,
            DeviceModel::Stax => 0x0006,
            DeviceModel::Flex => 0x0007,
            DeviceModel::NanoGen5 => 0x0008,
        }
    }

    /// Target id mask (`target_id & 0xffff0000`).
    pub fn target_id_mask(self) -> u32 {
        match self {
            DeviceModel::NanoS => 0x3110_0000,
            DeviceModel::NanoX => 0x3300_0000,
            DeviceModel::NanoSPlus => 0x3310_0000,
            DeviceModel::Stax => 0x3320_0000,
            DeviceModel::Flex => 0x3330_0000,
            DeviceModel::NanoGen5 => 0x3340_0000,
        }
    }

    /// Flash memory available for apps, in bytes.
    pub fn memory_size(self) -> u32 {
        match self {
            DeviceModel::NanoS => 320 * 1024,
            DeviceModel::NanoX => 2 * 1024 * 1024,
            _ => 1533 * 1024,
        }
    }

    /// Flash block size, given the firmware version (only matters for the Nano S).
    pub fn block_size(self, firmware_version: &str) -> u32 {
        match self {
            DeviceModel::NanoS => {
                if version_lt(firmware_version, (2, 0, 0)) {
                    4096
                } else {
                    2048
                }
            }
            DeviceModel::NanoX => 4096,
            _ => 512,
        }
    }

    /// Whether the model has a touch screen.
    pub fn has_touch_screen(self) -> bool {
        matches!(
            self,
            DeviceModel::Stax | DeviceModel::Flex | DeviceModel::NanoGen5
        )
    }

    /// Whether the model has a battery.
    pub fn has_battery(self) -> bool {
        !matches!(self, DeviceModel::NanoS | DeviceModel::NanoSPlus)
    }

    /// Identify the model from a USB product id (OS or bootloader).
    pub fn from_product_id(pid: u16) -> Option<Self> {
        // Bootloader product ids are not reliable to identify the model (a Nano
        // S Plus bootloader can enumerate as 0x0001): use the target id instead.
        let hi = (pid >> 8) as u8;
        if hi == 0 {
            return None;
        }
        Self::ALL.into_iter().find(|m| m.usb_product_id() == hi)
    }

    /// Identify the model from a target id.
    pub fn from_target_id(target_id: u32) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|m| target_id & 0xffff_0000 == m.target_id_mask())
    }

    /// Whether the given product id corresponds to bootloader mode.
    pub fn is_bootloader_product_id(pid: u16) -> bool {
        pid >> 8 == 0 && Self::ALL.iter().any(|m| m.bootloader_product_id() == pid)
    }
}

impl fmt::Display for DeviceModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Parse the leading `major.minor.patch` of a version string.
pub fn parse_version(v: &str) -> (u32, u32, u32) {
    let mut it = v
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// `v < (maj, min, patch)`
pub fn version_lt(v: &str, target: (u32, u32, u32)) -> bool {
    parse_version(v) < target
}

/// `v >= (maj, min, patch)`
pub fn version_gte(v: &str, target: (u32, u32, u32)) -> bool {
    !version_lt(v, target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect() {
        assert_eq!(
            DeviceModel::from_product_id(0x5011),
            Some(DeviceModel::NanoSPlus)
        );
        assert_eq!(
            DeviceModel::from_product_id(0x4015),
            Some(DeviceModel::NanoX)
        );
        assert_eq!(DeviceModel::from_product_id(0x0005), None);
        assert_eq!(DeviceModel::from_product_id(0x0001), None);
        assert!(DeviceModel::is_bootloader_product_id(0x0001));
        assert_eq!(
            DeviceModel::from_target_id(0x33100004),
            Some(DeviceModel::NanoSPlus)
        );
        assert_eq!(
            DeviceModel::from_target_id(0x31100004),
            Some(DeviceModel::NanoS)
        );
        assert!(version_lt("1.6.1", (2, 0, 0)));
        assert!(version_gte("2.2.3-rc1", (2, 2, 3)));
    }
}
