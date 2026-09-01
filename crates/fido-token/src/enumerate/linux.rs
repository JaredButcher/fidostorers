//! Linux enumeration via sysfs.
//!
//! Walks `/sys/class/hidraw`, reads each device's HID report descriptor, and keeps
//! the ones whose top-level collection is the FIDO usage page. No external crates
//! and no `unsafe`: everything needed is exposed as plain files.
//!
//! Note that finding a device here says nothing about whether it can be *opened*.
//! `/dev/hidraw*` is root-only by default on most distributions; the udev rule that
//! grants a normal user access is a packaging concern documented in
//! docs/M1-MANUAL-TESTING.md.

use std::fs;
use std::path::Path;

use crate::enumerate::{FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID};
use crate::{DeviceInfo, TokenError};

const HIDRAW_CLASS: &str = "/sys/class/hidraw";

pub(super) fn list_devices() -> Result<Vec<DeviceInfo>, TokenError> {
    let entries = match fs::read_dir(HIDRAW_CLASS) {
        Ok(entries) => entries,
        // No hidraw class at all (no HID devices, or a kernel without hidraw) is an
        // empty list, not a failure.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            log::debug!("{HIDRAW_CLASS} does not exist; no HID devices to enumerate");
            return Ok(Vec::new());
        }
        Err(err) => {
            return Err(TokenError::Transport(format!(
                "reading {HIDRAW_CLASS}: {err}"
            )))
        }
    };

    let mut devices = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                log::warn!("skipping unreadable {HIDRAW_CLASS} entry: {err}");
                continue;
            }
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        match inspect(&entry.path(), &name) {
            Ok(Some(device)) => devices.push(device),
            Ok(None) => log::trace!("{name}: not a FIDO device, skipping"),
            // One unreadable device must not sink the whole listing.
            Err(err) => log::debug!("{name}: skipping, {err}"),
        }
    }

    devices.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(devices)
}

/// Returns `Ok(None)` for a HID device that isn't a FIDO authenticator.
fn inspect(sysfs_dir: &Path, name: &str) -> Result<Option<DeviceInfo>, String> {
    let device_dir = sysfs_dir.join("device");

    let descriptor = fs::read(device_dir.join("report_descriptor"))
        .map_err(|err| format!("reading report_descriptor: {err}"))?;
    if !descriptor_is_fido(&descriptor) {
        return Ok(None);
    }

    let uevent = fs::read_to_string(device_dir.join("uevent"))
        .map_err(|err| format!("reading uevent: {err}"))?;
    let (vendor_id, product_id) = parse_hid_id(&uevent);

    Ok(Some(DeviceInfo {
        path: format!("/dev/{name}"),
        product: parse_uevent_field(&uevent, "HID_NAME"),
        // sysfs exposes a combined "vendor product" string in HID_NAME rather than
        // separate fields, so there is nothing more specific to report here.
        manufacturer: None,
        vendor_id,
        product_id,
        supports_hmac_secret: None,
        supports_client_pin: None,
    }))
}

/// Does this HID report descriptor declare the FIDO usage page?
///
/// Looks for the two-byte Usage Page item (`0x06 lo hi`) naming [`FIDO_USAGE_PAGE`]
/// followed by a one-byte Usage item (`0x09 0x01`). Both appear at the very start of
/// the top-level collection in every CTAP HID descriptor.
fn descriptor_is_fido(descriptor: &[u8]) -> bool {
    let page_lo = (FIDO_USAGE_PAGE & 0xFF) as u8;
    let page_hi = (FIDO_USAGE_PAGE >> 8) as u8;
    let usage = FIDO_USAGE_U2FHID as u8;

    descriptor
        .windows(5)
        .any(|w| w == [0x06, page_lo, page_hi, 0x09, usage])
}

fn parse_uevent_field(uevent: &str, key: &str) -> Option<String> {
    uevent.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

/// `HID_ID` looks like `0003:00001050:00000407` — bus:vendor:product, hex, and the
/// vendor/product halves are 32-bit even though the real values are 16-bit.
fn parse_hid_id(uevent: &str) -> (Option<u16>, Option<u16>) {
    let Some(value) = parse_uevent_field(uevent, "HID_ID") else {
        return (None, None);
    };
    let mut parts = value.split(':').skip(1);
    let vendor = parts
        .next()
        .and_then(|p| u32::from_str_radix(p, 16).ok())
        .and_then(|v| u16::try_from(v).ok());
    let product = parts
        .next()
        .and_then(|p| u32::from_str_radix(p, 16).ok())
        .and_then(|v| u16::try_from(v).ok());
    (vendor, product)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The opening bytes of a YubiKey's CTAP HID report descriptor.
    const FIDO_DESCRIPTOR: &[u8] = &[
        0x06, 0xD0, 0xF1, // Usage Page (0xF1D0, FIDO alliance)
        0x09, 0x01, // Usage (0x01, U2FHID)
        0xA1, 0x01, // Collection (Application)
        0x09, 0x20, 0x15, 0x00,
    ];

    /// A generic keyboard: usage page 0x01 (generic desktop), usage 0x06.
    const KEYBOARD_DESCRIPTOR: &[u8] = &[0x05, 0x01, 0x09, 0x06, 0xA1, 0x01];

    #[test]
    fn recognizes_a_fido_report_descriptor() {
        assert!(descriptor_is_fido(FIDO_DESCRIPTOR));
    }

    #[test]
    fn rejects_a_non_fido_report_descriptor() {
        assert!(!descriptor_is_fido(KEYBOARD_DESCRIPTOR));
        assert!(!descriptor_is_fido(&[]));
    }

    #[test]
    fn rejects_a_truncated_fido_descriptor() {
        // The usage page is there but the usage item is cut off.
        assert!(!descriptor_is_fido(&[0x06, 0xD0, 0xF1, 0x09]));
    }

    #[test]
    fn does_not_match_fido_bytes_that_are_not_a_usage_page_item() {
        // Same bytes, but introduced by 0x05 (one-byte Usage Page) rather than
        // 0x06, so this is not a FIDO usage page declaration.
        assert!(!descriptor_is_fido(&[0x05, 0xD0, 0xF1, 0x09, 0x01]));
    }

    #[test]
    fn parses_uevent_fields() {
        let uevent = "DRIVER=hid-generic\nHID_ID=0003:00001050:00000407\nHID_NAME=Yubico YubiKey OTP+FIDO+CCID\nHID_PHYS=usb-0000:00:14.0-3/input0\n";
        assert_eq!(
            parse_uevent_field(uevent, "HID_NAME").as_deref(),
            Some("Yubico YubiKey OTP+FIDO+CCID")
        );
        assert_eq!(parse_hid_id(uevent), (Some(0x1050), Some(0x0407)));
    }

    #[test]
    fn missing_uevent_fields_are_none_not_errors() {
        assert_eq!(parse_uevent_field("DRIVER=x\n", "HID_NAME"), None);
        assert_eq!(parse_hid_id("DRIVER=x\n"), (None, None));
    }

    #[test]
    fn malformed_hid_id_does_not_panic() {
        assert_eq!(parse_hid_id("HID_ID=nonsense\n"), (None, None));
        assert_eq!(parse_hid_id("HID_ID=0003\n"), (None, None));
        // Values too large for u16 are dropped rather than truncated.
        assert_eq!(
            parse_hid_id("HID_ID=0003:FFFFFFFF:00000407\n"),
            (None, Some(0x0407))
        );
    }

    #[test]
    fn does_not_match_a_key_that_is_a_prefix_of_another() {
        // `HID_NAME` must not be satisfied by `HID_NAMESPACE`.
        assert_eq!(parse_uevent_field("HID_NAMESPACE=x\n", "HID_NAME"), None);
    }
}
